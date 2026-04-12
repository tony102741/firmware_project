import os
import sys
import argparse

# Ensure src/core/ is on sys.path so that 'from parser.init_parser import ...'
# resolves to src/core/parser/init_parser.py regardless of how this script is
# invoked (directly, via pipeline.py subprocess, or with a manual PYTHONPATH).
_CORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core")
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from parser.init_parser import parse_init_services
from analyzer.risk import analyze_services
from scanner.scan_setuid import scan_setuid
from scanner.scan_perm import scan_world_writable
from scanner.scan_su import scan_su
from scanner.scan_web import scan_web_surface
from analyzer.verify_flow import verify_exploitable_flows
from analyzer.reach_check import analyze_reachability


_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ROOTFS_DIR  = os.path.join(_PROJECT_ROOT, "data/rootfs")
SYSTEM_PATH = os.path.join(ROOTFS_DIR, "system")
VENDOR_PATH = os.path.join(ROOTFS_DIR, "vendor")

_W = 65   # output width — matches pipeline.py


# ── Output helpers ─────────────────────────────────────────────────────────────

def _sec(title):
    """
    Section header — same visual style as pipeline.py's _stage().
    Always flushed so it appears before any subprocess output that follows.
    """
    label = f"  {title}  "
    pad = max(0, _W - len(label) - 3)
    print(f"\n{'─' * 3}{label}{'─' * pad}", flush=True)


# ── Result display ────────────────────────────────────────────────────────────

def print_section(title, data):
    """
    Print a result section with full detail for each target.

    Fields displayed:
      - risk level, service name, score, dataflow confidence
      - input type, privilege, dataflow pattern, source partition
      - binary path (relative to project root)
      - all dangerous functions found
      - detected attack surface (sockets, config files, IPC interfaces)
      - fuzzing hints
    """
    _sec(f"{title}  ({len(data)})")

    if not data:
        print("  (none)", flush=True)
        return

    for r in data:
        flow    = r.get("flow_type") or "none"
        conf    = r.get("confidence", "WEAK")
        src     = r.get("source", "system")
        ctrl    = r.get("controllability", "?")
        mem     = r.get("memory_impact", "?")
        vp      = r.get("validation_penalty", 0.0)
        tc      = r.get("taint_confidence", 0.0)

        print(f"\n  ▸ {r['name']}", flush=True)
        print(f"    score={r['score']}  level={r['level']}  "
              f"ctrl={ctrl}  mem_impact={mem}", flush=True)
        print(f"    input={r['input_type']}  priv={r['priv']}  "
              f"flow={flow}  conf={conf}  taint={tc:.2f}  "
              f"val_penalty={vp:.2f}  source={src}", flush=True)

        bp = r.get("binary_path", r["exec"])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        print(f"    path:  {bp}", flush=True)

        all_sinks = r.get("all_sinks") or r.get("sinks") or []
        if all_sinks:
            print(f"    sinks: {', '.join(all_sinks)}", flush=True)

        surface = r.get("attack_surface", {})
        if surface.get("sockets"):
            print(f"    sockets:      {', '.join(surface['sockets'][:4])}", flush=True)
        if surface.get("config_files"):
            print(f"    config files: {', '.join(surface['config_files'][:3])}", flush=True)
        if surface.get("ipc"):
            print(f"    ipc:          {', '.join(surface['ipc'][:3])}", flush=True)

        hints = r.get("fuzzing_hints", [])
        if hints:
            for hint in hints:
                print(f"    → {hint}", flush=True)


def print_attack_surface_map(results):
    """
    Print a compact [input] → [service] → [binary] attack surface map
    for HIGH and MEDIUM targets.
    """
    visible = [r for r in results if r["level"] in ("HIGH", "MEDIUM")]
    if not visible:
        return

    _sec("ATTACK SURFACE MAP  ([input] → [service] → [binary])")

    for r in visible:
        itype   = r["input_type"]
        surface = r.get("attack_surface", {})
        sockets = surface.get("sockets", [])
        configs = surface.get("config_files", [])

        if sockets:
            surface_str = sockets[0]
        elif configs:
            surface_str = configs[0]
        else:
            surface_str = itype

        conf = r.get("confidence", "WEAK")
        ctrl = r.get("controllability", "?")
        mem  = r.get("memory_impact", "?")
        print(f"  [{itype}: {surface_str}]"
              f" → [{r['name']}]"
              f" → [{r['exec']}]"
              f"  ctrl={ctrl}  mem={mem}  ({conf})", flush=True)


# ── Filesystem cross-reference ────────────────────────────────────────────────

def _exec_key(path):
    """Convert a scanner path (data/rootfs/system/bin/foo) to /system/bin/foo."""
    return "/" + os.path.relpath(path, ROOTFS_DIR)


def _annotate(path, exec_map, flag_fn):
    """
    Return an annotation string for a scanned path.
    Looks up the path in exec_map and applies flag_fn to detect high-risk combos.
    """
    svc = exec_map.get(_exec_key(path))
    if svc is None:
        return ""
    tag = f"  → {svc['name']} [{svc['level']}]"
    flag = flag_fn(svc)
    return tag + (f"  !! {flag}" if flag else "")


def run_filesystem_checks(results):
    roots = [p for p in [SYSTEM_PATH, VENDOR_PATH] if os.path.exists(p)]
    if not roots:
        print("\n[*] Filesystem checks: no rootfs paths found, skipping", flush=True)
        return

    total_files = sum(
        sum(len(files) for _, _, files in os.walk(root))
        for root in roots
    )
    print(f"\n[*] Filesystem checks: {total_files} files across {len(roots)} partition(s)",
          flush=True)

    exec_map = {svc["exec"]: svc for svc in results}

    def collect(fn):
        paths = []
        for root in roots:
            paths.extend(fn(root))
        return paths

    def flag_setuid(svc):
        if svc["input_type"] in ("socket", "binder", "netlink"):
            return "setuid + network-exposed"
        return None

    def flag_writable(_svc):
        return "world-writable + executed binary"

    def flag_none(_svc):
        return None

    checks = [
        ("Setuid binaries",        collect(scan_setuid),         flag_setuid),
        ("World-writable files",   collect(scan_world_writable), flag_writable),
        ("su / busybox binaries",  collect(scan_su),             flag_none),
    ]

    printed_header = False
    for label, paths, flag_fn in checks:
        if not paths:
            continue
        if not printed_header:
            _sec("FILESYSTEM CHECKS")
            printed_header = True
        print(f"\n  {label}:", flush=True)
        for path in paths:
            print(f"    {path}{_annotate(path, exec_map, flag_fn)}", flush=True)


# ── IoT firmware detection and analysis ──────────────────────────────────────

def _is_iot_firmware(system_path):
    """
    Return True if the rootfs contains no Android .rc files.
    Android firmware always has init.rc and *.rc service definitions;
    IoT/Linux firmware does not.
    """
    for _, _, files in os.walk(system_path):
        if any(f.endswith(".rc") for f in files):
            return False
    return True


def _collect_iot_services(system_path, web_bins):
    """
    Synthesize service entries for ELF executables in standard IoT binary
    directories.  Web-exposed binaries get a world-accessible socket marker
    so the controllability classifier assigns them HIGH priority.
    """
    _BIN_DIRS = [
        "bin", "sbin",
        os.path.join("usr", "bin"),
        os.path.join("usr", "sbin"),
    ]
    web_set  = {os.path.normpath(p) for p in web_bins}
    services = []
    seen     = set()

    for bin_dir in _BIN_DIRS:
        abs_dir = os.path.join(system_path, bin_dir)
        if not os.path.isdir(abs_dir):
            continue
        for f in sorted(os.listdir(abs_dir)):
            fpath = os.path.normpath(os.path.join(abs_dir, f))
            if not os.path.isfile(fpath):
                continue
            exec_path = "/" + os.path.relpath(fpath, system_path)
            if exec_path in seen:
                continue
            seen.add(exec_path)
            is_web = fpath in web_set
            services.append({
                "name":   f,
                "exec":   exec_path,
                "user":   "root",
                "socket": [{"perm": "666"}] if is_web else [],
                "source": "vendor",
            })

    # Web-exposed binaries outside standard dirs (e.g. CGI executables in /www)
    for wb in sorted(web_bins):
        fpath = os.path.normpath(wb)
        if not os.path.isfile(fpath):
            continue
        exec_path = "/" + os.path.relpath(fpath, system_path)
        if exec_path in seen:
            continue
        seen.add(exec_path)
        services.append({
            "name":   os.path.basename(wb),
            "exec":   exec_path,
            "user":   "root",
            "socket": [{"perm": "666"}],
            "source": "vendor",
        })

    return services


def _relevel(score, confidence):
    """Re-classify level after a score adjustment."""
    flow_for_high   = confidence in ("HIGH", "MEDIUM")   # proxy for flow_score ≥ 6
    flow_for_medium = confidence != "WEAK"               # proxy for flow_score ≥ 3
    if score >= 15 and flow_for_high:
        return "HIGH"
    if score >= 8 and flow_for_medium:
        return "MEDIUM"
    if score >= 2:
        return "LOW"
    return "LOW"


def _print_iot_entry(r):
    flow = r.get("flow_type") or "none"
    conf = r.get("confidence", "WEAK")
    ctrl = r.get("controllability", "?")
    mem  = r.get("memory_impact", "?")
    tc   = r.get("taint_confidence", 0.0)
    tag  = "[WEB]" if r.get("web_exposed") else f"[{r['level']}]"

    print(f"\n  {tag} {r['name']}", flush=True)
    print(f"    score={r['score']}  level={r['level']}  ctrl={ctrl}  mem_impact={mem}",
          flush=True)
    print(f"    input={r['input_type']}  priv={r['priv']}  "
          f"flow={flow}  conf={conf}  taint={tc:.2f}", flush=True)

    bp = r.get("binary_path", r["exec"])
    try:
        bp = os.path.relpath(bp, _PROJECT_ROOT)
    except ValueError:
        pass
    print(f"    path:  {bp}", flush=True)

    all_sinks = r.get("all_sinks") or r.get("sinks") or []
    if all_sinks:
        print(f"    sinks: {', '.join(all_sinks)}", flush=True)

    for hint in r.get("fuzzing_hints", []):
        print(f"    → {hint}", flush=True)


def _run_deep_verification(results, top_n=10):
    """
    Run verify_exploitable_flows() on the top-N HIGH/WEB candidates.
    Attaches a 'verified_flows' list to each result dict.
    Operates on at most top_n results to keep runtime bounded.
    """
    from analyzer.elf_analyzer import build_call_graph
    from analyzer.strings_analyzer import extract_strings

    candidates = [r for r in results
                  if r.get("web_exposed") or r["level"] in ("HIGH", "MEDIUM")][:top_n]

    for r in candidates:
        bp = r.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            r["verified_flows"] = []
            continue

        try:
            cg      = build_call_graph(bp)
            imports = r.get("_imports")      # set by risk.py if available
            strings = extract_strings(bp) if not imports else None
            flows   = verify_exploitable_flows(bp, cg or {},
                                               imports=imports,
                                               strings=strings)
            r["verified_flows"] = flows
        except Exception:
            r["verified_flows"] = []


def _print_verified_flows(results):
    """
    Print the CONFIRMED / LIKELY flows found by deep verification.
    Skips FALSE_POSITIVE results entirely.
    Returns True if any actionable flows were printed.
    """
    _VERDICT_LABEL = {
        'CONFIRMED': '!! CONFIRMED',
        'LIKELY':    '?  LIKELY   ',
        'UNCERTAIN': '~  UNCERTAIN',
    }
    printed_any = False

    for r in results:
        flows = r.get("verified_flows", [])
        actionable = [f for f in flows if f['verdict'] != 'FALSE_POSITIVE']
        if not actionable:
            continue

        tag = "[WEB]" if r.get("web_exposed") else f"[{r['level']}]"
        print(f"\n  {tag} {r['name']}  (score={r['score']})", flush=True)

        bp = r.get("binary_path", r["exec"])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        print(f"    path: {bp}", flush=True)

        for f in actionable:
            label  = _VERDICT_LABEL.get(f['verdict'], f['verdict'])
            fsym   = f.get('func_sym') or hex(f['func_va']) if f.get('func_va') else '(heuristic)'
            sink   = f['sink_sym']
            flow   = f['flow_str']
            reason = f['reason']
            print(f"    [{label}]  func={fsym}  sink={sink}", flush=True)
            print(f"      flow:   {flow}", flush=True)
            print(f"      reason: {reason}", flush=True)
        printed_any = True

    return printed_any


def _print_exploit_candidates(candidates):
    """
    Print the final list of remotely reachable, exploitable flows.

    Format per candidate:
      endpoint   — URL or port
      binary + function
      parameter  — HTTP param → env var → sink
      scenario   — 1–2 line exploit description
    """
    if not candidates:
        return False

    _AUTH_LABEL = {
        True:  'AUTHENTICATED',
        False: 'UNAUTHENTICATED',
        None:  'AUTH-UNKNOWN',
    }
    _VERDICT_MARK = {
        'CONFIRMED': '!! ',
        'LIKELY':    '?  ',
        'UNCERTAIN': '~  ',
    }

    for idx, entry in enumerate(candidates, 1):
        r      = entry['result']
        flow   = entry['flow']
        reach  = entry['reach']

        verdict  = flow['verdict']
        mark     = _VERDICT_MARK.get(verdict, '   ')
        auth_req = reach['auth_required']
        auth_lbl = _AUTH_LABEL.get(auth_req, 'AUTH-UNKNOWN')
        unauth   = '  ★' if auth_req is False else ''

        print(f"\n  ── Exploit #{idx}  [{mark}{verdict}]  [{auth_lbl}]{unauth}",
              flush=True)

        # Endpoint
        ep = reach.get('endpoint') or '(unknown endpoint)'
        print(f"    endpoint:  {ep}", flush=True)

        # Handler script
        handler = reach.get('handler')
        if handler:
            print(f"    handler:   {handler}", flush=True)

        # Binary + function
        bp = r.get('binary_path', r['exec'])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        fsym = flow.get('func_sym') or '(unknown)'
        sink = flow.get('sink_sym', '?')
        print(f"    binary:    {bp}", flush=True)
        print(f"    function:  {fsym}  →  {sink}()", flush=True)

        # Input parameter chain
        param  = reach.get('input_param', '?')
        method = reach.get('input_method', '?')
        origin = flow.get('flow_str', flow.get('origin', '?'))
        print(f"    input:     {method} param '{param}'  →  {origin}", flush=True)

        # Auth evidence
        if reach.get('auth_evidence'):
            print(f"    auth:      {reach['auth_evidence']}", flush=True)

        # Exploit scenario
        scenario = reach.get('exploit_scenario')
        if scenario:
            print(f"    scenario:", flush=True)
            for line in scenario.splitlines():
                print(f"      {line}", flush=True)

        # Other invoking handlers (if multiple)
        others = (reach.get('all_invokers') or [])[1:3]
        if others:
            print(f"    also via:", flush=True)
            for rel, url in others:
                print(f"      {rel}  ({url})", flush=True)

    return True


def run_iot_analysis(show_all=False):
    """
    IoT-specific analysis path.

    1. Scan web roots to identify web-exposed binaries and their CGI scripts.
    2. Synthesize service entries for all ELF executables in standard dirs,
       marking web-exposed ones as world-accessible.
    3. Run the standard analyze_services() pipeline.
    4. Apply a 1.5× score boost to web-exposed results, re-level.
    5. Output web-exposed + HIGH + MEDIUM candidates only.
    """
    _sec("IoT Firmware — Web Surface Scan")

    web_bins, cgi_files = scan_web_surface(SYSTEM_PATH)
    print(f"    web server / CGI binaries : {len(web_bins)}", flush=True)
    print(f"    scripts scanned           : {len(cgi_files)}", flush=True)

    if cgi_files:
        print("    scripts:", flush=True)
        for cf in cgi_files[:8]:
            print(f"      {os.path.relpath(cf, _PROJECT_ROOT)}", flush=True)
        if len(cgi_files) > 8:
            print(f"      … and {len(cgi_files) - 8} more", flush=True)

    services = _collect_iot_services(SYSTEM_PATH, web_bins)
    print(f"\n    {len(services)} service candidates", flush=True)
    print(f"[START] Vulnerability analysis", flush=True)
    sys.stdout.flush()

    results = analyze_services(services, SYSTEM_PATH)

    # ── Apply web-exposure score boost (1.5×) and re-level ───────────────────
    web_norm = {os.path.normpath(p) for p in web_bins}
    for r in results:
        bp = os.path.normpath(r.get("binary_path", ""))
        r["web_exposed"] = bp in web_norm
        if r["web_exposed"]:
            r["score"] = int(round(r["score"] * 1.5))
            r["level"] = _relevel(r["score"], r["confidence"])

    results.sort(key=lambda x: x["score"], reverse=True)

    # ── Partition results ─────────────────────────────────────────────────────
    web_results   = [r for r in results if r.get("web_exposed")]
    high_results  = [r for r in results if not r.get("web_exposed") and r["level"] == "HIGH"]
    med_results   = [r for r in results if not r.get("web_exposed") and r["level"] == "MEDIUM"]
    low_results   = [r for r in results if not r.get("web_exposed") and r["level"] == "LOW"]

    total_shown = len(web_results) + len(high_results) + len(med_results)
    print(f"[DONE]  {len(results)} candidate(s)  "
          f"(web={len(web_results)}  HIGH={len(high_results)}"
          f"  MEDIUM={len(med_results)}  LOW={len(low_results)})",
          flush=True)

    _sec(f"IoT HIGH-PRIORITY TARGETS  ({total_shown})")

    if web_results:
        print("\n  ── Web-exposed ──────────────────────────────────────────", flush=True)
        for r in web_results:
            _print_iot_entry(r)

    if high_results:
        print("\n  ── HIGH (not directly web-exposed) ──────────────────────", flush=True)
        for r in high_results:
            _print_iot_entry(r)

    if med_results:
        print("\n  ── MEDIUM ───────────────────────────────────────────────", flush=True)
        for r in med_results:
            _print_iot_entry(r)

    if show_all and low_results:
        print("\n  ── LOW ──────────────────────────────────────────────────", flush=True)
        for r in low_results:
            _print_iot_entry(r)

    if not (web_results or high_results or med_results):
        print("  (none — the firmware may use stripped binaries or an unsupported format)",
              flush=True)

    # ── Deep flow verification ─────────────────────────���─────────────────────���
    # Run only on top candidates to keep runtime bounded.
    priority_results = web_results + high_results + med_results
    if priority_results:
        _sec("VERIFIED EXPLOITABLE FLOWS  (top candidates only)")
        print("    Running deep argument-taint analysis ...", flush=True)
        sys.stdout.flush()
        _run_deep_verification(priority_results, top_n=10)
        had_flows = _print_verified_flows(priority_results)
        if not had_flows:
            print("  (no confirmed flows — binaries may be stripped or use indirect dispatch)",
                  flush=True)

    # ── Reachability and exploit scenario generation ──────────────────────────
    # Only runs on candidates that have verified CONFIRMED/LIKELY flows.
    if priority_results:
        _sec("REMOTELY EXPLOITABLE FLOWS")
        print("    Checking HTTP reachability and authentication ...", flush=True)
        sys.stdout.flush()
        exploit_candidates = analyze_reachability(
            priority_results, cgi_files, SYSTEM_PATH)
        had_exploits = _print_exploit_candidates(exploit_candidates)
        if not had_exploits:
            print("  (no remotely reachable flows confirmed — check verified flows above)",
                  flush=True)

        # Summary count
        unauth_count = sum(1 for e in exploit_candidates
                           if e['reach']['auth_required'] is False)
        if exploit_candidates:
            print(f"\n  Total exploit candidates : {len(exploit_candidates)}", flush=True)
            print(f"  Unauthenticated          : {unauth_count}", flush=True)

    # ── Summary ───────────────────────────────────────────────────────────────
    _sec("SUMMARY")
    print(f"  Candidates analyzed : {len(results)}", flush=True)
    print(f"  Web-exposed         : {len(web_results)}", flush=True)
    print(f"  HIGH                : {len(high_results)}", flush=True)
    print(f"  MEDIUM              : {len(med_results)}", flush=True)
    print(f"  LOW                 : {len(low_results)}", flush=True)

    if web_results:
        print(f"\n  Top web-exposed targets:", flush=True)
        for r in web_results[:5]:
            print(f"    ▸ {r['name']:<30}  score={r['score']}  "
                  f"flow={r.get('flow_type') or 'none'}  "
                  f"sinks={','.join((r.get('all_sinks') or [])[:2])}",
                  flush=True)

    print(f"\n{'─' * _W}", flush=True)


# ── Main analysis entry point ─────────────────────────────────────────────────

def run_analysis(show_all=False):
    if not os.path.exists(SYSTEM_PATH):
        print("[!] data/rootfs/system not found — was the extraction step successful?",
              flush=True)
        print(f"    Expected: {SYSTEM_PATH}", flush=True)
        print("    Tip: run without --skip to re-extract, or check data/extracted/",
              flush=True)
        return

    # IoT firmware has no Android .rc files — use web-surface-aware analysis.
    if _is_iot_firmware(SYSTEM_PATH):
        run_iot_analysis(show_all=show_all)
        return

    services = parse_init_services(SYSTEM_PATH)
    if os.path.exists(VENDOR_PATH):
        services += parse_init_services(VENDOR_PATH)

    print(f"    {len(services)} services detected", flush=True)
    print(f"[START] Vulnerability analysis", flush=True)
    sys.stdout.flush()

    results = analyze_services(services, SYSTEM_PATH)

    high   = [r for r in results if r["level"] == "HIGH"]
    medium = [r for r in results if r["level"] == "MEDIUM"]
    low    = [r for r in results if r["level"] == "LOW"]

    print(f"[DONE]  Analysis complete — {len(results)} candidate(s) found"
          f"  (HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})",
          flush=True)

    print_section("HIGH RISK TARGETS", high)
    print_section("MEDIUM RISK TARGETS", medium)

    if show_all:
        print_section("LOW RISK TARGETS", low)

    print_attack_surface_map(results)

    run_filesystem_checks(results)

    # ── Final summary ─────────────────────────────────────────────────────────
    _sec("SUMMARY")
    print(f"  Services parsed:   {len(services)}", flush=True)
    print(f"  Candidates found:  {len(results)}"
          f"  (HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})",
          flush=True)

    if high:
        print(f"\n  Top targets:", flush=True)
        for r in high[:5]:
            ctrl = r.get("controllability", "?")
            mem  = r.get("memory_impact", "?")
            print(f"    ▸ {r['name']:<30}  score={r['score']}  "
                  f"ctrl={ctrl}  mem={mem}  priv={r['priv']}", flush=True)
    elif medium:
        print(f"\n  No HIGH targets. Top MEDIUM:", flush=True)
        for r in medium[:3]:
            print(f"    ▸ {r['name']:<30}  score={r['score']}  priv={r['priv']}",
                  flush=True)
    else:
        print("\n  No HIGH or MEDIUM candidates found.", flush=True)
        print("  Run with --all to inspect LOW-scored services.", flush=True)

    print(f"\n{'─' * _W}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="show LOW results too")
    args = parser.parse_args()

    run_analysis(show_all=args.all)
