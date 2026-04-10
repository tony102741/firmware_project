"""
Targeted ASN.1 PER decode analysis:
1. Find the actual PER decoder function called by ASN1CType::Decode vtable dispatch
2. Find all asn1PD_* / pd_* / ASN1C_*Decode functions
3. Deep-scan for: osrtMemAlloc/rtxMemAlloc with network-derived size args,
   memcpy with network-derived length, rev (ntohl), ldrh/ldrb length reads
"""

import os, re
BINARY      = os.environ.get("GPSD_BINARY",      "/workspace/data/rootfs/vendor/bin/hw/gpsd")
PROJECT_DIR = os.environ.get("GHIDRA_PROJECT_DIR", "/workspace/ghidra_projects")
PROJECT_NAME = "gpsd_analysis"

import pyghidra

ALLOC_RE = re.compile(r'\b(osrtMemAlloc|osrtMemAllocZ|osrtMemRealloc|'
                       r'rtxMemAlloc|rtxMemAllocZ|rtxMemReallocArray|'
                       r'malloc|calloc|realloc|_Znwm|_Znam|operator.new)\b', re.I)
COPY_RE  = re.compile(r'\b(memcpy|__memcpy_chk|memmove|memset|'
                       r'strcpy|__strcpy_chk|strncpy|__strncpy_chk)\b', re.I)

def sym(flat_api, addr):
    s = flat_api.getSymbolAt(addr)
    return str(s.name) if s else str(addr)

def get_call_target(flat_api, instr_addr):
    refs = list(flat_api.currentProgram.referenceManager
                .getReferencesFrom(instr_addr))
    for r in refs:
        if r.referenceType.isCall():
            return r.toAddress
    return None

def get_call_name(flat_api, instr_addr):
    t = get_call_target(flat_api, instr_addr)
    if t is None:
        return "?"
    return sym(flat_api, t)

def disasm_func(flat_api, func_or_addr, max_insns=1000, highlight=True):
    """Return list of (addr_str, mnem, op_str, annot) tuples."""
    if isinstance(func_or_addr, int):
        func = flat_api.getFunctionAt(flat_api.toAddr(func_or_addr))
        if func is None:
            return [], 0
    else:
        func = func_or_addr
    body = func.body
    end_a = body.maxAddress
    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(body.minAddress)
    rows = []
    n = 0
    while instr is not None and instr.address <= end_a and n < max_insns:
        mnem = instr.mnemonicString
        ops = [instr.getDefaultOperandRepresentation(i)
               for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)
        annot = ""
        if mnem in ("bl","blr","br"):
            tname = get_call_name(flat_api, instr.address)
            annot = f" --> {tname}"
            if ALLOC_RE.search(tname): annot += "  !!!ALLOC!!!"
            if COPY_RE.search(tname):  annot += "  !!!COPY!!!"
        if mnem in ("rev","rev16","rev32","rev64"):
            annot += "  [NTOH]"
        if mnem in ("ldrh","ldrsh","ldrb","ldrsb") and len(ops)>=2:
            annot += "  [hword/byte]"
        if mnem == "sub" and len(ops)>=3 and ops[0]=="sp" and ops[1]=="sp":
            annot += f"  [FRAME {ops[2]}]"
        rows.append((str(instr.address), mnem, op_str, annot))
        n += 1
        instr = instr.next
    return rows, n

def print_func(name, rows, show_all=True):
    for addr, mnem, op_str, annot in rows:
        if show_all or annot:
            print(f"  {addr}:  {mnem:<10} {op_str}{annot}")

def find_funcs_by_pattern(flat_api, patterns, addr_lo=0x00800000, addr_hi=0x00980000):
    """Find functions whose demangled/raw name matches any of the regex patterns."""
    prog = flat_api.currentProgram
    results = []
    for func in prog.functionManager.getFunctions(True):
        off = func.entryPoint.offset
        if not (addr_lo <= off <= addr_hi):
            continue
        name = func.name
        if any(re.search(p, name, re.I) for p in patterns):
            results.append((off, name, func.body.numAddresses, func))
    results.sort()
    return results

def deep_scan_for_alloc_copy(flat_api, func, func_name):
    """
    Walk the function body. For each alloc or copy call, capture the
    10 preceding instructions (to see where x0/x1/x2 came from).
    Return a list of (kind, context_rows, call_row) tuples.
    """
    body = func.body
    end_a = body.maxAddress
    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(body.minAddress)
    window = []   # rolling window of last 10 rows
    hits = []
    while instr is not None and instr.address <= end_a:
        mnem = instr.mnemonicString
        ops = [instr.getDefaultOperandRepresentation(i)
               for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)
        cur = f"  {instr.address}:  {mnem:<10} {op_str}"
        annot = ""
        kind = None
        if mnem in ("bl","blr","br"):
            tname = get_call_name(flat_api, instr.address)
            cur += f"  --> {tname}"
            if ALLOC_RE.search(tname):
                kind = f"ALLOC ({tname})"
                annot = "  !!!ALLOC!!!"
            elif COPY_RE.search(tname):
                kind = f"COPY ({tname})"
                annot = "  !!!COPY!!!"
        if mnem in ("rev","rev16","rev32","rev64"):
            kind = "NTOH"
            cur += "  [NTOH]"
        if kind:
            hits.append((kind, list(window[-10:]), cur + annot))
        window.append(cur)
        if len(window) > 12:
            window.pop(0)
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

        # ── Step 1: trace the vtable dispatch from ASN1CType::Decode ──────────
        # ASN1CType::Decode @ 0x00873854 does: ldr x8,[x20]; ldr x8,[x8,#0x28]; blr x8
        # The concrete object passed from GlSupl10Mgr::Decode is ASN1C_ULP_PDU
        # We need to find ASN1C_ULP_PDU's vtable and slot 5 (offset 0x28)
        print("\n[*] Step 1: Finding ASN1C_ULP_PDU concrete Decode function")
        # Search for functions related to ULP_PDU decode
        ulp_decoders = find_funcs_by_pattern(flat_api,
            [r'ULP_PDU.*[Dd]ecode', r'[Dd]ecode.*ULP_PDU',
             r'asn1PD_ULP', r'asn1C_ULP', r'ASN1C_ULP'])
        print(f"  Found {len(ulp_decoders)} ULP_PDU decode-related functions:")
        for off, name, sz, _ in ulp_decoders:
            print(f"    {hex(off)}  {sz:5d}B  {name}")

        # ── Step 2: find all PER decode functions ──────────────────────────────
        print("\n[*] Step 2: Finding all PER decode functions")
        per_decoders = find_funcs_by_pattern(flat_api,
            [r'asn1PD_', r'^pd_', r'PERDecod', r'per_decode',
             r'ASN1C.*6Decode', r'asn1D_'])
        print(f"  Found {len(per_decoders)} PER decoder functions:")
        for off, name, sz, _ in per_decoders[:60]:
            print(f"    {hex(off)}  {sz:5d}B  {name}")

        # ── Step 3: deep scan ALL PER decoders for alloc+copy patterns ────────
        print(f"\n[*] Step 3: Deep scan of PER decoders for ALLOC/COPY/NTOH")
        all_decode = per_decoders + [f for f in ulp_decoders
                                     if f not in per_decoders]
        # also add any function with 'Decode' in name in range
        decode_funcs = find_funcs_by_pattern(flat_api,
            [r'[Dd]ecod', r'asn1PD', r'pu_get', r'rtxRead',
             r'rtxDecode', r'rtPerDec'])
        print(f"  Total decode-pattern functions: {len(decode_funcs)}")

        # scan them all
        reported = 0
        for off, name, sz, func in decode_funcs:
            hits = deep_scan_for_alloc_copy(flat_api, func, name)
            if not hits:
                continue
            reported += 1
            print(f"\n{'─'*68}")
            print(f"  FUNCTION: {name}")
            print(f"  Address : {hex(off)}  Size: {sz}B")
            print(f"{'─'*68}")
            for kind, ctx, call_line in hits:
                print(f"  [{kind}]  context:")
                for c in ctx:
                    print(f"    {c}")
                print(f"  >>>> {call_line}")
                print()

        print(f"\n[*] Reported {reported} functions with ALLOC/COPY/NTOH hits")

        # ── Step 4: specifically look for rtxMemAlloc / osrtMemAlloc patterns ─
        # across the entire 0x008-0x009 range (not just named decode funcs)
        print(f"\n[*] Step 4: Searching ALL 0x008xxxxx functions for alloc+ntoh co-occurrence")
        co_hits = []
        for func in prog.functionManager.getFunctions(True):
            off = func.entryPoint.offset
            if not (0x00800000 <= off <= 0x00980000):
                continue
            body = func.body
            end_a = body.maxAddress
            listing = prog.listing
            instr = listing.getInstructionAt(body.minAddress)
            has_alloc = False
            has_ntoh  = False
            alloc_ctx = []
            window = []
            while instr and instr.address <= end_a:
                mnem = instr.mnemonicString
                ops = [instr.getDefaultOperandRepresentation(i)
                       for i in range(instr.numOperands)]
                op_str = ", ".join(str(o) for o in ops)
                cur = f"  {instr.address}:  {mnem:<10} {op_str}"
                if mnem in ("bl","blr","br"):
                    tname = get_call_name(flat_api, instr.address)
                    if ALLOC_RE.search(tname):
                        has_alloc = True
                        alloc_ctx.append((list(window[-8:]),
                                          cur + f"  --> {tname}  !!!ALLOC!!!"))
                if mnem in ("rev","rev16","rev32","rev64"):
                    has_ntoh = True
                window.append(cur)
                if len(window) > 10: window.pop(0)
                instr = instr.next
            if has_alloc and has_ntoh:
                co_hits.append((off, func.name, func.body.numAddresses, alloc_ctx))

        print(f"  Functions with BOTH alloc AND ntoh: {len(co_hits)}")
        for off, name, sz, alloc_ctx_list in co_hits[:20]:
            print(f"\n  ══ {name} @ {hex(off)} ({sz}B) ══")
            for ctx, call_line in alloc_ctx_list:
                print(f"  [ALLOC site]")
                for c in ctx:
                    print(f"    {c}")
                print(f"  >>>> {call_line}")

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
