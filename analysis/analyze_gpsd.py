"""
Headless Ghidra analysis of gpsd binary.
Goals:
  1. Find all call sites of execv
  2. Decompile every function that calls execv
  3. Trace argument construction back to input sources (recv/read/fgets/SSL_read)
"""

import pyghidra
import sys
import os

BINARY = "/home/user/firmware_project/rootfs/vendor/bin/hw/gpsd"
PROJECT_DIR = "/home/user/ghidra_projects"
PROJECT_NAME = "gpsd_analysis"

os.makedirs(PROJECT_DIR, exist_ok=True)

def find_import_address(flat_api, name):
    """Return the address of an imported function by name."""
    for sym in flat_api.currentProgram.symbolTable.getAllSymbols(True):
        if sym.name == name and sym.externalEntryPoint:
            return sym.address
    # fallback: search all symbols
    from ghidra.program.model.symbol import SymbolType
    st = flat_api.currentProgram.symbolTable
    syms = list(st.getSymbols(name, None))
    for s in syms:
        return s.address
    return None

def get_thunk_or_stub_address(flat_api, import_name):
    """
    Find the PLT stub / thunk that wraps an external import.
    Returns a list of addresses (there may be multiple thunks).
    """
    from ghidra.app.util.query import TableService
    results = []
    sym_iter = flat_api.currentProgram.symbolTable.getSymbols(import_name, None)
    for sym in sym_iter:
        addr = sym.address
        results.append(addr)
    return results

def get_callers(flat_api, func):
    """Return list of (caller_function, call_address) for all calls to func."""
    from ghidra.program.model.symbol import RefType
    callers = []
    refs = flat_api.currentProgram.referenceManager.getReferencesTo(func.entryPoint)
    for ref in refs:
        if ref.referenceType.isCall():
            caller_func = flat_api.getFunctionContaining(ref.fromAddress)
            if caller_func:
                callers.append((caller_func, ref.fromAddress))
    return callers

def decompile_function(decompiler, func):
    """Return decompiled C pseudo-code string for func."""
    result = decompiler.decompileFunction(func, 60, None)
    if result and result.decompileCompleted():
        return result.decompiledFunction.getC()
    return f"[decompile failed for {func.name}]"

def main():
    print(f"[*] Loading {BINARY} into Ghidra headless...")

    with pyghidra.open_program(BINARY, project_location=PROJECT_DIR,
                                project_name=PROJECT_NAME, analyze=True) as flat_api:
        prog = flat_api.currentProgram
        print(f"[*] Program: {prog.name}  Lang: {prog.languageID}")

        # Setup decompiler
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        decomp = DecompInterface()
        opts = DecompileOptions()
        decomp.setOptions(opts)
        decomp.toggleCCode(True)
        decomp.toggleSyntaxTree(True)
        decomp.openProgram(prog)

        # ── Step 1: locate exec-family functions in the import/symbol table ─────
        from ghidra.program.model.symbol import SymbolType

        EXEC_NAMES = ["execv", "execve", "execvp", "execvpe",
                      "execl", "execle", "execlp", "system", "popen"]

        all_targets = []
        for exec_name in EXEC_NAMES:
            syms = list(prog.symbolTable.getSymbols(exec_name, None))
            if syms:
                print(f"\n[*] '{exec_name}' symbol(s) found: {[str(s.address) for s in syms]}")
            for sym in syms:
                all_targets.append(sym.address)

        # Also look for thunks (PLT stubs that call the external symbol)
        thunk_addrs = []
        for addr in list(all_targets):
            refs = list(prog.referenceManager.getReferencesTo(addr))
            for ref in refs:
                thunk_func = flat_api.getFunctionContaining(ref.fromAddress)
                if thunk_func and thunk_func.isThunk():
                    if thunk_func.entryPoint not in thunk_addrs:
                        thunk_addrs.append(thunk_func.entryPoint)
                        print(f"  [thunk] {thunk_func.name} @ {thunk_func.entryPoint}")

        all_targets = list(all_targets) + thunk_addrs

        # ── Step 2: find all callers of execv (direct + via thunk) ───────────
        callers_seen = {}  # func.entryPoint -> (func, [call_addr])
        for target_addr in all_targets:
            refs = list(prog.referenceManager.getReferencesTo(target_addr))
            for ref in refs:
                if not ref.referenceType.isCall():
                    continue
                caller_func = flat_api.getFunctionContaining(ref.fromAddress)
                if caller_func is None:
                    continue
                ep = str(caller_func.entryPoint)
                if ep not in callers_seen:
                    callers_seen[ep] = (caller_func, [])
                callers_seen[ep][1].append(ref.fromAddress)

        print(f"\n[*] Functions calling execv: {len(callers_seen)}")
        for ep, (func, call_addrs) in callers_seen.items():
            print(f"  {func.name} @ {ep}  (call sites: {[str(a) for a in call_addrs]})")

        # ── Step 3: decompile each execv caller ───────────────────────────────
        print("\n" + "="*80)
        print("DECOMPILED EXECV CALLERS")
        print("="*80)
        for ep, (func, call_addrs) in callers_seen.items():
            print(f"\n{'─'*60}")
            print(f"FUNCTION: {func.name}  @  {ep}")
            print(f"Call sites: {[str(a) for a in call_addrs]}")
            print(f"{'─'*60}")
            c_code = decompile_function(decomp, func)
            print(c_code)

        # ── Step 4: also decompile callers-of-callers (one level up) ─────────
        # to trace where execv arguments come from
        print("\n" + "="*80)
        print("CALLERS OF EXECV CALLERS (argument source tracing)")
        print("="*80)
        for ep, (func, _) in callers_seen.items():
            up_refs = list(prog.referenceManager.getReferencesTo(func.entryPoint))
            call_up = [(flat_api.getFunctionContaining(r.fromAddress), r.fromAddress)
                       for r in up_refs if r.referenceType.isCall()]
            call_up = [(f, a) for f, a in call_up if f is not None]
            if not call_up:
                print(f"\n  [no callers found for {func.name}]")
                continue
            for parent_func, call_addr in call_up[:3]:  # limit to 3 parents
                print(f"\n{'─'*60}")
                print(f"PARENT: {parent_func.name} @ {parent_func.entryPoint}  calls {func.name} @ {call_addr}")
                print(f"{'─'*60}")
                c_code = decompile_function(decomp, parent_func)
                print(c_code)

        # ── Step 5: find input sources (SSL_read / read / fgets / recv) ───────
        INPUT_FUNCS = ["SSL_read", "read", "fgets", "recv", "recvfrom", "recvmsg", "__read_chk"]
        print("\n" + "="*80)
        print("INPUT SOURCE FUNCTIONS REFERENCED IN EXECV-CALLER SUBTREE")
        print("="*80)
        for ifunc in INPUT_FUNCS:
            syms = list(prog.symbolTable.getSymbols(ifunc, None))
            for sym in syms:
                refs = list(prog.referenceManager.getReferencesTo(sym.address))
                callers_of_input = set()
                for ref in refs:
                    if not ref.referenceType.isCall():
                        continue
                    f = flat_api.getFunctionContaining(ref.fromAddress)
                    if f:
                        callers_of_input.add(f.name)
                if callers_of_input:
                    print(f"  {ifunc} called from: {sorted(callers_of_input)}")

        decomp.closeProgram()
        print("\n[*] Done.")

if __name__ == "__main__":
    main()
