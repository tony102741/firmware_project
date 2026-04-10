"""
Disassemble the OnData/OnDataReceived functions that receive SSL data via Connection::Read.
Priority order:
  1. GlLtoDownloader::OnData       @ 0x004b415c
  2. GlSuplHalPlatform::OnDataReceived @ 0x004c9514
  3. GlSuplEngineImpl::OnDataReceived  @ 0x008cf094
  4. GlSupl10Mgr::OnDataReceived       @ 0x008b7bf8
  5. BrcmGpsHalDownload::OnData        @ 0x004c2a68
  6. BrcmGpsHalNtrip::OnData           @ 0x004bae74  (bonus)

For each: print the full disassembly and flag any:
  - memcpy / __memcpy_chk / strcpy / __strcpy_chk / sprintf calls
  - length field reads (ntohl/rev/ldr w patterns)
  - blr/bl calls (potential Connection::Read vtable dispatch)
  - large stack allocations (sub sp, sp, #N)
"""

import os, sys, re

BINARY      = os.environ.get("GPSD_BINARY",      "/workspace/data/rootfs/vendor/bin/hw/gpsd")
PROJECT_DIR = os.environ.get("GHIDRA_PROJECT_DIR", "/workspace/ghidra_projects")
PROJECT_NAME = "gpsd_analysis"

TARGETS = [
    ("GlLtoDownloader::OnData",          0x004b415c),
    ("GlSuplHalPlatform::OnDataReceived",0x004c9514),
    ("GlSuplEngineImpl::OnDataReceived", 0x008cf094),
    ("GlSupl10Mgr::OnDataReceived",      0x008b7bf8),
    ("BrcmGpsHalDownload::OnData",       0x004c2a68),
    ("BrcmGpsHalNtrip::OnData",          0x004bae74),
]

DANGER_RE = re.compile(
    r'\b(memcpy|__memcpy_chk|strcpy|__strcpy_chk|strncpy|__strncpy_chk|'
    r'sprintf|__sprintf_chk|snprintf|__snprintf_chk|gets|system|popen|'
    r'SSL_read|recv|read|fgets)\b'
)

import pyghidra

def addr_of(flat_api, addr_int):
    return flat_api.toAddr(addr_int)

def disassemble_range(flat_api, start_addr, end_addr):
    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(start_addr)
    lines = []
    while instr is not None and instr.address <= end_addr:
        addr = instr.address
        mnem = instr.mnemonicString
        ops  = instr.defaultOperandRepresentationList
        op_str = ", ".join(str(o) for o in ops)
        line = f"  {addr}:  {mnem:<12} {op_str}"
        # flag dangerous calls
        if DANGER_RE.search(op_str) or (mnem in ("bl","blr") and DANGER_RE.search(op_str)):
            line += "   <<<< SINK"
        lines.append(line)
        instr = instr.next
    return lines

def get_called_symbol(flat_api, call_addr):
    """Try to resolve what a bl/blr at call_addr calls."""
    refs = list(flat_api.currentProgram.referenceManager.getReferencesFrom(call_addr))
    for r in refs:
        if r.referenceType.isCall():
            sym = flat_api.getSymbolAt(r.toAddress)
            if sym:
                return str(sym.name)
            return str(r.toAddress)
    return "?"

def analyze_function(flat_api, name, start_int):
    func = flat_api.getFunctionAt(flat_api.toAddr(start_int))
    if func is None:
        print(f"  [!] No function found at {hex(start_int)}")
        return

    body   = func.body
    end_a  = body.maxAddress
    start_a= body.minAddress

    print(f"\n{'='*72}")
    print(f"FUNCTION: {func.name}  ({name})")
    print(f"  Range : {start_a} – {end_a}  ({body.numAddresses} bytes)")
    print(f"{'='*72}")

    listing = flat_api.currentProgram.listing
    instr = listing.getInstructionAt(start_a)

    # track: first sub sp (stack frame size)
    frame_found = False
    call_count  = 0

    while instr is not None and instr.address <= end_a:
        addr = instr.address
        mnem = instr.mnemonicString
        ops  = [instr.getDefaultOperandRepresentation(i)
                for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)
        line = f"  {addr}:  {mnem:<10} {op_str}"

        # stack frame
        if not frame_found and mnem == "sub" and "sp" in ops[0] and "sp" in ops[1]:
            frame_found = True
            line += f"   # stack frame size: {ops[2] if len(ops)>2 else '?'}"

        # calls
        if mnem in ("bl", "blr", "br"):
            target = get_called_symbol(flat_api, addr)
            line += f"   --> {target}"
            call_count += 1
            # flag danger
            if DANGER_RE.search(target):
                line += "   <<<< DANGER"

        # length / byte-swap ops (network-order field reads)
        if mnem in ("rev", "rev16", "rev32", "rev64"):
            line += "   # byte-swap (ntoh)"

        # ldr of word from pointer + small offset (potential protocol field)
        if mnem in ("ldr", "ldrb", "ldrh", "ldrsw") and len(ops) >= 2:
            if re.search(r'\[x\d+\]$|\[x\d+,\s*#0x[0-9a-f]+\]', op_str):
                pass  # too noisy; skip generic loads

        print(line)
        instr = instr.next

    print(f"\n  [summary] {call_count} calls in {func.name}")


def main():
    print(f"[*] PyGhidra: loading {BINARY}")
    with pyghidra.open_program(BINARY,
                               project_location=PROJECT_DIR,
                               project_name=PROJECT_NAME,
                               analyze=False) as flat_api:
        prog = flat_api.currentProgram
        print(f"[*] Loaded: {prog.name}  lang={prog.languageID}")

        for name, addr in TARGETS:
            try:
                analyze_function(flat_api, name, addr)
            except Exception as e:
                print(f"\n[!] Error analyzing {name}: {e}")
                import traceback; traceback.print_exc()

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
