"""
ASN.1 decoder internals analysis.
1. Disassemble ASN1CType::Decode @ 0x00873854
2. Find all asn1D_* functions in 0x008xxxxx range
3. For each: flag malloc/new, memcpy, length reads (ldrh/ldrb + rev patterns),
   integer arithmetic on network-derived values, missing bounds checks.
"""

import os, re
BINARY = "/home/user/firmware_project/rootfs/vendor/bin/hw/gpsd"
PROJECT_DIR = "/home/user/ghidra_projects"
PROJECT_NAME = "gpsd_analysis"

import pyghidra

# Functions to disassemble in full
TARGETS = [
    ("ASN1CType::Decode",          0x00873854),
]

# Pattern for dangerous operations
ALLOC_RE  = re.compile(r'\b(malloc|calloc|realloc|osrtMemAlloc|osrtMemAllocZ|'
                        r'rtxMemAlloc|rtxMemAllocZ|operator new|_Znwm|_Znam)\b')
COPY_RE   = re.compile(r'\b(memcpy|__memcpy_chk|memmove|memset|strcpy|'
                        r'__strcpy_chk|strncpy|sprintf|__sprintf_chk)\b')
DANGER_RE = re.compile(r'\b(memcpy|__memcpy_chk|memmove|strcpy|__strcpy_chk|'
                        r'strncpy|sprintf|__sprintf_chk|malloc|calloc|realloc|'
                        r'osrtMemAlloc|osrtMemAllocZ|rtxMemAlloc|rtxMemAllocZ|'
                        r'_Znwm|_Znam|SSL_read|recv|read)\b')

def get_called_symbol(flat_api, call_addr):
    refs = list(flat_api.currentProgram.referenceManager.getReferencesFrom(call_addr))
    for r in refs:
        if r.referenceType.isCall():
            sym = flat_api.getSymbolAt(r.toAddress)
            if sym:
                return str(sym.name)
            return str(r.toAddress)
    return "?"

def disassemble(flat_api, func, max_insns=800, show_all=True):
    body   = func.body
    end_a  = body.maxAddress
    start_a= body.minAddress
    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(start_a)
    lines = []
    count = 0
    while instr is not None and instr.address <= end_a and count < max_insns:
        addr = instr.address
        mnem = instr.mnemonicString
        ops  = [instr.getDefaultOperandRepresentation(i)
                for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)

        annot = ""
        target_sym = None
        if mnem in ("bl", "blr", "br"):
            target_sym = get_called_symbol(flat_api, addr)
            annot = f"  --> {target_sym}"
            if DANGER_RE.search(target_sym):
                annot += "  !!!"

        if mnem in ("rev", "rev16", "rev32", "rev64"):
            annot += "  [ntoh]"
        if mnem == "sub" and len(ops) >= 3 and ops[0] == "sp" and ops[1] == "sp":
            annot += f"  [frame {ops[2]}]"
        if mnem in ("ldrh", "ldrb", "ldrsh", "ldrsb") and len(ops) >= 2:
            annot += "  [byte/hword load - potential length]"
        if mnem in ("umulh", "umull", "smull"):
            annot += "  [wide-mul - potential overflow check]"
        if mnem == "madd" or mnem == "msub":
            annot += "  [mul-add]"

        line = f"  {addr}:  {mnem:<10} {op_str}{annot}"

        if show_all or annot:
            lines.append(line)
        count += 1
        instr = instr.next

    return lines, count

def analyze_targets(flat_api):
    for name, addr_int in TARGETS:
        func = flat_api.getFunctionAt(flat_api.toAddr(addr_int))
        if func is None:
            print(f"\n[!] No function at {hex(addr_int)}")
            continue
        body = func.body
        print(f"\n{'='*72}")
        print(f"FUNCTION: {func.name}  ({name})")
        print(f"  {body.minAddress} – {body.maxAddress}  ({body.numAddresses} bytes)")
        print(f"{'='*72}")
        lines, count = disassemble(flat_api, func)
        for l in lines:
            print(l)
        print(f"\n  [{count} instructions]")

def find_asn1d_functions(flat_api):
    """Find all asn1D_* or asn1_* generated decode functions in 0x008xxxxx range."""
    prog = flat_api.currentProgram
    fm = prog.functionManager
    funcs = []
    for func in fm.getFunctions(True):
        name = func.name
        addr = func.entryPoint.offset
        # asn1D_ / asn1d_ / Decode patterns; address in 0x00800000–0x008fffff
        if 0x00800000 <= addr <= 0x00900000:
            n = name.lower()
            if ('asn1d' in n or 'asn1_' in n or 'decode' in n.lower()
                    or 'perd' in n or 'berd' in n):
                funcs.append((addr, name, func.body.numAddresses))
    funcs.sort()
    return funcs

def analyze_asn1d_functions(flat_api, funcs, max_funcs=80):
    """
    For each asn1D_* function: fast-scan for dangerous patterns.
    Print: function name, any allocation/copy calls with context.
    """
    print(f"\n{'='*72}")
    print(f"ASN1 GENERATED DECODE FUNCTIONS ({len(funcs)} found, showing top {max_funcs})")
    print(f"{'='*72}")

    # Show summary list
    for addr, name, sz in funcs[:max_funcs]:
        print(f"  {hex(addr)}  {sz:5d}B  {name}")

    print(f"\n{'='*72}")
    print("DANGEROUS OPERATION SCAN (alloc + copy sites in asn1D_* functions)")
    print(f"{'='*72}")

    for addr, name, sz in funcs[:max_funcs]:
        func = flat_api.getFunctionAt(flat_api.toAddr(addr))
        if func is None:
            continue
        body = func.body
        end_a = body.maxAddress
        listing = flat_api.currentProgram.listing
        instr = listing.getInstructionAt(body.minAddress)
        hits = []
        prev_lines = []  # rolling window of last 6 instructions for context
        while instr is not None and instr.address <= end_a:
            mnem = instr.mnemonicString
            ops  = [instr.getDefaultOperandRepresentation(i)
                    for i in range(instr.numOperands)]
            op_str = ", ".join(str(o) for o in ops)
            cur_line = f"    {instr.address}:  {mnem:<10} {op_str}"

            if mnem in ("bl", "blr", "br"):
                target = get_called_symbol(flat_api, instr.address)
                cur_line += f"  --> {target}"
                if ALLOC_RE.search(target) or COPY_RE.search(target):
                    hits.append(("CALL", list(prev_lines[-6:]), cur_line, target))
            elif mnem in ("rev", "rev16", "rev32", "rev64"):
                hits.append(("NTOH", list(prev_lines[-3:]), cur_line + "  [ntoh]", ""))
            elif mnem in ("ldrh", "ldrsh") and len(ops) >= 2:
                # halfword load — often a length field
                hits.append(("HWORD_LOAD", list(prev_lines[-2:]), cur_line + "  [halfword - length?]", ""))

            prev_lines.append(cur_line)
            if len(prev_lines) > 8:
                prev_lines.pop(0)
            instr = instr.next

        if hits:
            print(f"\n  ── {name} @ {hex(addr)} ({sz}B) ──")
            for kind, ctx, line, sym in hits:
                print(f"    [{kind}]")
                for c in ctx:
                    print(f"    {'':2}{c}")
                print(f"  >>> {line}")
                print()

def main():
    print(f"[*] Loading {BINARY}")
    with pyghidra.open_program(BINARY,
                               project_location=PROJECT_DIR,
                               project_name=PROJECT_NAME,
                               analyze=False) as flat_api:
        prog = flat_api.currentProgram
        print(f"[*] {prog.name}  lang={prog.languageID}")

        # 1. Disassemble ASN1CType::Decode
        analyze_targets(flat_api)

        # 2. Find and scan asn1D_* functions
        funcs = find_asn1d_functions(flat_api)
        print(f"\n[*] Found {len(funcs)} ASN.1 decode functions in 0x008xxxxx range")
        analyze_asn1d_functions(flat_api, funcs)

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
