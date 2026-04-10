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


_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ROOTFS_DIR  = os.path.join(_PROJECT_ROOT, "data/rootfs")
SYSTEM_PATH = os.path.join(ROOTFS_DIR, "system")
VENDOR_PATH = os.path.join(ROOTFS_DIR, "vendor")

_W = 65   # output width


def _sec(title):
    """Consistent section header — same style as pipeline stage headers."""
    label = f"  {title}  "
    pad = max(0, _W - len(label) - 3)
    print(f"\n{'─' * 3}{label}{'─' * pad}")


# ── Result display ────────────────────────────────────────────────────────────

def print_section(title, data):
    """
    Print a result section with full detail for each target.

    Fields displayed:
      - risk level, service name, score, dataflow confidence
      - input type, privilege, dataflow pattern, source partition
      - binary path (absolute host path)
      - all dangerous functions found
      - detected attack surface (sockets, config files, IPC interfaces)
      - evidence strings
      - fuzzing hints
    """
    _sec(f"{title}  ({len(data)})")

    if not data:
        print("  (none)")
        return

    for r in data:
        flow = r.get("flow_type") or "none"
        conf = r.get("confidence", "WEAK")
        src  = r.get("source", "system")

        # ── Entry header ──────────────────────────────────────────────────────
        print(f"\n  ▸ {r['name']}")
        print(f"    score={r['score']}  confidence={conf}  input={r['input_type']}"
              f"  priv={r['priv']}  flow={flow}  source={src}")

        # ── Binary path (relative) ────────────────────────────────────────────
        bp = r.get("binary_path", r["exec"])
        try:
            bp = os.path.relpath(bp, _PROJECT_ROOT)
        except ValueError:
            pass
        print(f"    path:  {bp}")

        # ── Dangerous functions ───────────────────────────────────────────────
        all_sinks = r.get("all_sinks") or r.get("sinks") or []
        if all_sinks:
            print(f"    sinks: {', '.join(all_sinks)}")

        # ── Attack surface ────────────────────────────────────────────────────
        surface = r.get("attack_surface", {})
        if surface.get("sockets"):
            print(f"    sockets:      {', '.join(surface['sockets'][:4])}")
        if surface.get("config_files"):
            print(f"    config files: {', '.join(surface['config_files'][:3])}")
        if surface.get("ipc"):
            print(f"    ipc:          {', '.join(surface['ipc'][:3])}")

        # ── Fuzzing hints ─────────────────────────────────────────────────────
        hints = r.get("fuzzing_hints", [])
        if hints:
            for hint in hints:
                print(f"    → {hint}")


def print_attack_surface_map(results):
    """
    Print a compact [input] → [service] → [binary] attack surface map
    for HIGH and MEDIUM targets.
    """
    visible = [r for r in results if r["level"] in ("HIGH", "MEDIUM")]
    if not visible:
        return

    print(f"\n{'=' * 64}")
    print("  ATTACK SURFACE MAP  ([input] → [service] → [binary])")
    print(f"{'=' * 64}")

    for r in visible:
        itype   = r["input_type"]
        surface = r.get("attack_surface", {})
        sockets = surface.get("sockets", [])
        configs = surface.get("config_files", [])

        # Pick the most informative surface descriptor
        if sockets:
            surface_str = sockets[0]
        elif configs:
            surface_str = configs[0]
        else:
            surface_str = itype

        conf = r.get("confidence", "WEAK")
        print(f"  [{itype}: {surface_str}]"
              f" → [{r['name']}]"
              f" → [{r['exec']}]"
              f"  ({conf} confidence)")


# ── Filesystem cross-reference ────────────────────────────────────────────────

def _exec_key(path):
    """Convert a scanner path (rootfs/system/bin/foo) to an exec-style path (/system/bin/foo)."""
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
        print("[*] Filesystem checks: no rootfs paths found, skipping")
        return

    total_files = sum(
        sum(len(files) for _, _, files in os.walk(root))
        for root in roots
    )
    print(f"\n[*] Filesystem checks: {total_files} files across {len(roots)} partition(s)")

    exec_map = {svc["exec"]: svc for svc in results}

    def collect(fn, label):
        paths = []
        for root in roots:
            paths.extend(fn(root))
        print(f"[dbg] {label}: {len(paths)} result(s)")
        return paths

    def flag_setuid(svc):
        if svc["input_type"] in ("socket", "binder", "netlink"):
            return "setuid + network-exposed"
        return None

    def flag_writable(svc):
        return "world-writable + executed binary"

    def flag_none(_svc):
        return None

    checks = [
        ("setuid binaries",       collect(scan_setuid,         "scan_setuid"),         flag_setuid),
        ("world-writable files",  collect(scan_world_writable, "scan_world_writable"), flag_writable),
        ("su / busybox binaries", collect(scan_su,             "scan_su"),             flag_none),
    ]

    printed_header = False
    for label, paths, flag_fn in checks:
        if not paths:
            continue
        if not printed_header:
            print("\n=== FILESYSTEM CHECKS ===")
            printed_header = True
        print(f"\n[{label}]")
        for path in paths:
            print(f"  {path}{_annotate(path, exec_map, flag_fn)}")


# ── Main analysis entry point ─────────────────────────────────────────────────

def run_analysis(show_all=False):
    if not os.path.exists(SYSTEM_PATH):
        print("[!] rootfs/system not found — was the extraction step successful?")
        print(f"    Expected: {SYSTEM_PATH}")
        print("    Tip: run without --skip to re-extract, or check data/extracted/")
        return

    services = parse_init_services(SYSTEM_PATH)
    if os.path.exists(VENDOR_PATH):
        services += parse_init_services(VENDOR_PATH)

    print(f"[*] Parsed {len(services)} services from init scripts")
    print("[*] Scanning binaries...")

    results = analyze_services(services, SYSTEM_PATH)

    high   = [r for r in results if r["level"] == "HIGH"]
    medium = [r for r in results if r["level"] == "MEDIUM"]
    low    = [r for r in results if r["level"] == "LOW"]

    print_section("HIGH RISK TARGETS", high)
    print_section("MEDIUM RISK TARGETS", medium)

    if show_all:
        print_section("LOW RISK TARGETS", low)

    # Attack surface map: compact [input] → [service] → [binary] overview
    print_attack_surface_map(results)

    run_filesystem_checks(results)

    # ── Final summary ─────────────────────────────────────────────────────────
    total = len(results)
    print(f"\n{'═' * 60}")
    print(f"  SUMMARY")
    print(f"{'═' * 60}")
    print(f"  Services parsed:     {len(services)}")
    print(f"  Candidates found:    {total}  "
          f"(HIGH: {len(high)}  MEDIUM: {len(medium)}  LOW: {len(low)})")
    if high:
        print(f"\n  Top targets:")
        for r in high[:5]:
            print(f"    • {r['name']:<30}  score={r['score']}  "
                  f"flow={r.get('flow_type','?')}  priv={r['priv']}")
    elif medium:
        print(f"\n  No HIGH targets. Top MEDIUM targets:")
        for r in medium[:3]:
            print(f"    • {r['name']:<30}  score={r['score']}  priv={r['priv']}")
    else:
        print("\n  No HIGH or MEDIUM candidates found.")
        print("  Consider running with --all to inspect LOW-scored services.")
    print(f"{'═' * 60}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="show LOW results too")
    args = parser.parse_args()

    run_analysis(show_all=args.all)
