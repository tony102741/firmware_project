"""
Disassemble:
  1. GlSupl10Mgr::Decode @ 0x008b8acc  -- ASN.1 SUPL parser receiving raw SSL bytes
  2. Connection::Read    @ 0x004a383c  -- actual SSL_read wrapper
  3. BrcmGpsHalNtrip thunk vtable[0x10] @ 0x004baf74 callee (NTRIP data callback)
  4. BrcmGpsHalDownload listener vtable[0x10] callee (the downstream that gets content-length)

Flag: rev/rev16 (ntohl), ldr w (length field reads), memcpy/strcpy, stack alloc
"""

import os, sys, re
BINARY = "/home/user/firmware_project/rootfs/vendor/bin/hw/gpsd"
PROJECT_DIR = "/home/user/ghidra_projects"
PROJECT_NAME = "gpsd_analysis"

TARGETS = [
    ("Connection::Read",       0x004a383c),
    ("GlSupl10Mgr::Decode",   0x008b8acc),
]

DANGER_RE = re.compile(
    r'\b(memcpy|__memcpy_chk|strcpy|__strcpy_chk|strncpy|'
    r'sprintf|__sprintf_chk|snprintf|__snprintf_chk|gets|system|popen|'
    r'SSL_read|recv|read)\b'
)

import pyghidra

def get_called_symbol(flat_api, call_addr):
    refs = list(flat_api.currentProgram.referenceManager.getReferencesFrom(call_addr))
    for r in refs:
        if r.referenceType.isCall():
            sym = flat_api.getSymbolAt(r.toAddress)
            if sym:
                return str(sym.name)
            return str(r.toAddress)
    return "?"

def analyze_function(flat_api, name, start_int, max_insns=600):
    func = flat_api.getFunctionAt(flat_api.toAddr(start_int))
    if func is None:
        print(f"  [!] No function at {hex(start_int)}")
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
    count = 0
    while instr is not None and instr.address <= end_a and count < max_insns:
        addr = instr.address
        mnem = instr.mnemonicString
        ops  = [instr.getDefaultOperandRepresentation(i)
                for i in range(instr.numOperands)]
        op_str = ", ".join(str(o) for o in ops)
        line = f"  {addr}:  {mnem:<10} {op_str}"

        # flag dangerous calls
        if mnem in ("bl", "blr", "br"):
            target = get_called_symbol(flat_api, addr)
            line += f"   --> {target}"
            if DANGER_RE.search(target):
                line += "  !!DANGER!!"

        # byte-swap = network-order field
        if mnem in ("rev", "rev16", "rev32", "rev64"):
            line += "   ### ntoh()"

        # stack frame
        if mnem == "sub" and len(ops) >= 3 and ops[0] == "sp" and ops[1] == "sp":
            line += f"   ### stack alloc {ops[2]}"

        # lsl used with a byte count register (common pattern for length multiply)
        if mnem == "lsl" and len(ops) >= 3:
            line += "   ### shift"

        print(line)
        instr = instr.next
        count += 1

    if count >= max_insns:
        print(f"  ... (truncated at {max_insns} instructions) ...")
    print(f"\n  [summary] {count} instructions, function body size={body.numAddresses} bytes")


def main():
    print(f"[*] PyGhidra loading {BINARY}")
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
                print(f"\n[!] Error: {e}")
                import traceback; traceback.print_exc()

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
