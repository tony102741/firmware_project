"""
Targeted analysis of:
1. rtxMemAllocArray2 @ 0x871c14  -- integer overflow in size computation?
2. pd_Length64       @ 0x874a6c  -- how length is read from bitstream
3. pd_OpenType       @ 0x876520  -- open type decoder (unconstrained bytes)
4. pd_SmallNonNegWholeNumber @ 0x87496c
5. rtxDecBits        @ 0x86f2c8  -- bit reader

Then scan ALL asn1PD_* SEQUENCE OF decoders for:
   rtxDecUnconsLength / pd_Length / count-read → mul/lsl → rtxMemHeapAlloc pattern
"""

import re, os
BINARY = "/home/user/firmware_project/rootfs/vendor/bin/hw/gpsd"
PROJECT_DIR = "/home/user/ghidra_projects"
PROJECT_NAME = "gpsd_analysis"

import pyghidra

def get_call_name_and_addr(flat_api, instr_addr):
    refs = list(flat_api.currentProgram.referenceManager
                .getReferencesFrom(instr_addr))
    for r in refs:
        if r.referenceType.isCall():
            s = flat_api.getSymbolAt(r.toAddress)
            return (str(s.name) if s else str(r.toAddress)), r.toAddress.offset
    return "?", 0

def disasm(flat_api, addr_int, label="", max_insns=300):
    func = flat_api.getFunctionAt(flat_api.toAddr(addr_int))
    if not func:
        print(f"\n  [!] No function at {hex(addr_int)}")
        return
    body = func.body
    end_a = body.maxAddress
    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(body.minAddress)
    print(f"\n{'='*72}")
    print(f"  {func.name}  ({label})")
    print(f"  {body.minAddress} – {end_a}  ({body.numAddresses}B)")
    print(f"{'='*72}")
    n = 0
    while instr and instr.address <= end_a and n < max_insns:
        mnem = instr.mnemonicString
        ops  = [instr.getDefaultOperandRepresentation(i)
                for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)
        line = f"  {instr.address}:  {mnem:<10} {op_str}"
        annot = ""
        if mnem in ("bl","blr","br"):
            tname, _ = get_call_name_and_addr(flat_api, instr.address)
            annot = f"  --> {tname}"
        if mnem in ("mul","umulh","umull","smull","madd","msub"):
            annot += "  [MUL]"
        if mnem == "lsl" and len(ops) >= 3:
            annot += "  [LSL - potential size*n]"
        if mnem in ("rev","rev16"):
            annot += "  [NTOH]"
        if mnem in ("ldrh","ldrsh","ldrb","ldrsb") and len(ops)>=2:
            annot += "  [byte/hword]"
        if mnem == "sub" and len(ops)>=3 and ops[0]=="sp" and ops[1]=="sp":
            annot += f"  [FRAME {ops[2]}]"
        print(line + annot)
        n += 1
        instr = instr.next

def find_seqof_decoders_with_alloc(flat_api, rtxMemHeapAlloc_addr, rtxDecBits_addr):
    """
    Scan asn1PD_* functions. Flag any where:
      - there is a call to rtxDecBits / pd_Length / pd_UnconsLength (count from network)
      - within 30 instructions, there is a call to rtxMemHeapAlloc
      - and x1 (the size arg to alloc) is not a literal constant
    """
    ALLOC_FNS  = {rtxMemHeapAlloc_addr, 0x871ba8}  # HeapAlloc + HeapAllocZ
    LENGTH_FNS_NAMES = re.compile(
        r'rtxDecBits|pd_Length|UnconsLength|SemiConsLength|'
        r'SmallNonNeg|DecUInt|DecNonNeg|DecConLen|pu_getMsgLen', re.I)

    prog = flat_api.currentProgram
    hits = []

    for func in prog.functionManager.getFunctions(True):
        off = func.entryPoint.offset
        if not (0x00800000 <= off <= 0x00900000):
            continue
        if 'asn1PD_' not in func.name and 'asn1PD' not in func.name:
            continue

        body = func.body
        end_a = body.maxAddress
        listing = prog.listing
        instr = listing.getInstructionAt(body.minAddress)
        window = []   # (addr, mnem, op_str, tname, is_alloc, is_length)

        while instr and instr.address <= end_a:
            mnem = instr.mnemonicString
            ops  = [instr.getDefaultOperandRepresentation(i)
                    for i in range(instr.numOperands)]
            op_str = ", ".join(str(o) for o in ops)
            tname = ""
            is_alloc = False
            is_length = False
            if mnem in ("bl","blr","br"):
                tname, taddr = get_call_name_and_addr(flat_api, instr.address)
                is_alloc  = taddr in ALLOC_FNS
                is_length = bool(LENGTH_FNS_NAMES.search(tname))

            # If we see an alloc, look back in window for a length call
            if is_alloc:
                for back in window[-30:]:
                    if back[5]:  # is_length
                        # Also check x1 is not a literal constant (size argument)
                        # Look for  mov w1, #constant  or mov x1, #constant
                        # in the last 5 instructions before alloc
                        size_is_const = False
                        for rb in window[-8:]:
                            if re.match(r'mov\s+(w1|x1)\s*,\s*#', rb[2]):
                                size_is_const = True
                                break
                        ctx = [f"    {r[0]}:  {r[1]:<10} {r[2]}" +
                               (f"  --> {r[3]}" if r[3] else "") +
                               ("  [LENGTH_READ]" if r[5] else "") +
                               ("  [ALLOC]" if r[4] else "")
                               for r in window[-20:]]
                        ctx.append(f"    {instr.address}:  {mnem:<10} {op_str}"
                                   f"  --> {tname}  [ALLOC]")
                        hits.append({
                            "func": func.name,
                            "addr": off,
                            "size_bytes": body.numAddresses,
                            "context": ctx,
                            "size_is_const": size_is_const,
                        })
                        break

            window.append((str(instr.address), mnem, op_str, tname,
                           is_alloc, is_length))
            if len(window) > 32: window.pop(0)
            instr = instr.next

    return hits

def main():
    print(f"[*] Loading {BINARY}")
    with pyghidra.open_program(BINARY,
                               project_location=PROJECT_DIR,
                               project_name=PROJECT_NAME,
                               analyze=False) as flat_api:
        prog = flat_api.currentProgram
        print(f"[*] {prog.name}")

        # 1. Key primitive functions
        print("\n[*] Key PER runtime primitives:")
        for addr, label in [
            (0x871c14, "rtxMemAllocArray2"),
            (0x874a6c, "pd_Length64"),
            (0x876520, "pd_OpenType"),
            (0x87496c, "pd_SmallNonNegWholeNumber"),
            (0x86f2c8, "rtxDecBits"),
            (0x874148, "ASN1PERMessageBuffer::C2"),
            (0x871da8, "rtxMemHeapAlloc"),
        ]:
            disasm(flat_api, addr, label)

        # 2. Scan for length-read → alloc patterns in asn1PD_* functions
        print(f"\n\n{'='*72}")
        print("SCANNING asn1PD_* FOR: length-read → variable-size alloc")
        print(f"{'='*72}")
        hits = find_seqof_decoders_with_alloc(flat_api, 0x871da8, 0x86f2c8)
        print(f"\nFound {len(hits)} asn1PD_* functions with length-read → alloc pattern")

        # Show only non-constant-size ones first
        variable = [h for h in hits if not h["size_is_const"]]
        const    = [h for h in hits if h["size_is_const"]]
        print(f"  Variable-size (potentially attacker-controlled): {len(variable)}")
        print(f"  Constant-size (safe):                           {len(const)}")

        for h in variable[:15]:
            print(f"\n  ── {h['func']} @ {hex(h['addr'])} ({h['size_bytes']}B) ──")
            for line in h["context"]:
                print(line)

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
