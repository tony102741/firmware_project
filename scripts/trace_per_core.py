"""
Deep-dive into the PER decode core:
1. Find all allocator symbol names used in the binary (malloc/rtxMem*)
2. Disassemble asn1PD_ULP_PDU      @ 0x82eaf4   (top-level PDU entry)
3. Disassemble asn1PD_UlpMessage   @ 0x82e620   (ULP message body)
4. Disassemble ASN1C_ULP_PDU::DecodeFrom @ 0x808160 (main decode iface)
5. Find all functions that call any allocator AND have a bit-decode call
6. Scan for the "read_length → multiply → alloc" pattern
   (look for: mul/lsl immediately before an alloc call)
"""

import re, os
BINARY      = os.environ.get("GPSD_BINARY",      "/workspace/data/rootfs/vendor/bin/hw/gpsd")
PROJECT_DIR = os.environ.get("GHIDRA_PROJECT_DIR", "/workspace/ghidra_projects")
PROJECT_NAME = "gpsd_analysis"

import pyghidra

def get_call_name(flat_api, instr_addr):
    refs = list(flat_api.currentProgram.referenceManager
                .getReferencesFrom(instr_addr))
    for r in refs:
        if r.referenceType.isCall():
            s = flat_api.getSymbolAt(r.toAddress)
            return (str(s.name) if s else str(r.toAddress)), r.toAddress.offset
    return "?", 0

def disasm_func_full(flat_api, addr_int, label="", max_insns=800):
    func = flat_api.getFunctionAt(flat_api.toAddr(addr_int))
    if not func:
        print(f"  [!] No function at {hex(addr_int)}")
        return
    body = func.body
    end_a = body.maxAddress
    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(body.minAddress)
    print(f"\n{'='*72}")
    print(f"FUNCTION: {func.name}  ({label})")
    print(f"  {body.minAddress} – {end_a}  ({body.numAddresses}B)")
    print(f"{'='*72}")
    n = 0
    while instr and instr.address <= end_a and n < max_insns:
        mnem = instr.mnemonicString
        ops  = [instr.getDefaultOperandRepresentation(i)
                for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)
        line = f"  {instr.address}:  {mnem:<10} {op_str}"
        if mnem in ("bl","blr","br"):
            tname, _ = get_call_name(flat_api, instr.address)
            line += f"  --> {tname}"
        if mnem in ("rev","rev16","rev32","rev64"):
            line += "  [NTOH]"
        if mnem in ("mul","umulh","umull","smull","madd","msub","lsl"):
            line += "  [ARITH]"
        if mnem in ("ldrh","ldrsh","ldrb","ldrsb") and len(ops)>=2:
            line += "  [hword/byte]"
        if mnem == "sub" and len(ops)>=3 and ops[0]=="sp" and ops[1]=="sp":
            line += f"  [FRAME {ops[2]}]"
        print(line)
        n += 1
        instr = instr.next
    if n >= max_insns:
        print(f"  ... (truncated at {max_insns} insns)")
    print(f"\n  [{n} instructions, {body.numAddresses}B]")

def find_all_allocators(flat_api):
    """Find every symbol that looks like a memory allocator."""
    ALLOC_NAMES = re.compile(
        r'(malloc|calloc|realloc|rtxMem|osrtMem|_Znwm|_Znam|'
        r'operator.new|MemAlloc|memAlloc|rtxMemHeap)', re.I)
    prog = flat_api.currentProgram
    results = {}
    for sym in prog.symbolTable.getAllSymbols(True):
        name = sym.name
        if ALLOC_NAMES.search(name):
            results[name] = sym.address.offset
    return results

def find_bitdecode_fns(flat_api):
    """Find rtxDecBits / rtxReadBytes / rtxDecUnconsLength etc."""
    BIT_NAMES = re.compile(
        r'(rtxDec|rtxRead|perDec|pd_[A-Z]|pu_get|rtxBitDec|'
        r'DecodeConLen|DecodeSemi|DecodeUncons)', re.I)
    prog = flat_api.currentProgram
    results = {}
    for sym in prog.symbolTable.getAllSymbols(True):
        name = sym.name
        if BIT_NAMES.search(name):
            results[name] = sym.address.offset
    return results

def scan_mul_before_alloc(flat_api, alloc_addrs, addr_lo=0x00800000, addr_hi=0x00990000):
    """
    For every function in range: look for a mul/lsl/add within 15 instructions
    before an allocator call where x0 (the size arg) comes from a multiply.
    """
    prog = flat_api.currentProgram
    hits = []
    for func in prog.functionManager.getFunctions(True):
        off = func.entryPoint.offset
        if not (addr_lo <= off <= addr_hi):
            continue
        body = func.body
        end_a = body.maxAddress
        listing = prog.listing
        instr = listing.getInstructionAt(body.minAddress)
        window = []  # rolling (addr, mnem, ops, line)
        while instr and instr.address <= end_a:
            mnem = instr.mnemonicString
            ops = [instr.getDefaultOperandRepresentation(i)
                   for i in range(instr.numOperands)]
            op_str = ", ".join(str(o) for o in ops)
            line = f"  {instr.address}:  {mnem:<10} {op_str}"
            is_alloc = False
            tname = ""
            if mnem in ("bl","blr","br"):
                tname, toff = get_call_name(flat_api, instr.address)
                if toff in alloc_addrs.values():
                    is_alloc = True
            if is_alloc:
                # check if any of the last 15 instructions is a multiply
                has_mul = any(r[1] in ("mul","umulh","umull","smull","madd","msub","lsl","add","sub")
                              and "x0" in r[2] or "w0" in r[2]
                              for r in window[-15:])
                # check if x0 was loaded from network-derived data (not a constant)
                # Look for mov x0, #constant pattern just before alloc
                ctx = list(window[-12:])
                # check if the size is a literal constant (safe) or register (potentially attacker-controlled)
                size_is_const = False
                for r in reversed(ctx):
                    # mov w0, #N  or  mov x0, #N
                    if re.match(r'.*:.*\b(mov|movz)\s+(w|x)0\s*,\s*#0x[0-9a-f]+', r[3].lower()):
                        size_is_const = True
                        break
                    if re.match(r'.*:.*\b(mov|movz)\s+(w|x)0\s*,\s*#\d+', r[3].lower()):
                        size_is_const = True
                        break
                    if r[1] in ("bl","blr") and not size_is_const:
                        # a call was made → x0 may be return value
                        break
                if not size_is_const:
                    hits.append({
                        "func": func.name,
                        "addr": off,
                        "size": func.body.numAddresses,
                        "alloc": tname,
                        "context": ctx,
                        "call_line": line + f"  --> {tname}  !!!ALLOC!!!"
                    })
            window.append((str(instr.address), mnem, op_str, line))
            if len(window) > 16: window.pop(0)
            instr = instr.next
    return hits

def main():
    print(f"[*] Loading {BINARY}")
    with pyghidra.open_program(BINARY,
                               project_location=PROJECT_DIR,
                               project_name=PROJECT_NAME,
                               analyze=False) as flat_api:
        prog = flat_api.currentProgram
        print(f"[*] {prog.name}  lang={prog.languageID}")

        # Step 1: find allocator symbols
        print("\n[*] Step 1: Memory allocator symbols")
        allocs = find_all_allocators(flat_api)
        for name, addr in sorted(allocs.items()):
            print(f"  {hex(addr)}  {name}")

        # Step 2: find bit-decode runtime symbols
        print("\n[*] Step 2: PER bit-decode runtime symbols")
        bitdec = find_bitdecode_fns(flat_api)
        for name, addr in sorted(bitdec.items()):
            print(f"  {hex(addr)}  {name}")

        # Step 3: disassemble key entry points
        for addr, label in [
            (0x82eaf4, "asn1PD_ULP_PDU"),
            (0x82e620, "asn1PD_UlpMessage"),
            (0x808160, "ASN1C_ULP_PDU::DecodeFrom"),
        ]:
            disasm_func_full(flat_api, addr, label)

        # Step 4: scan for non-constant size before alloc
        print(f"\n[*] Step 4: Scanning 0x008-0x009 range for variable-size alloc calls")
        alloc_addrs = allocs
        hits = scan_mul_before_alloc(flat_api, alloc_addrs)
        print(f"  Found {len(hits)} potential variable-size allocation sites")
        for h in hits[:30]:
            print(f"\n  ── {h['func']} @ {hex(h['addr'])} ({h['size']}B) ──")
            for c in h['context']:
                print(f"    {c[3]}")
            print(f"  >>>> {h['call_line']}")

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
