import os
import argparse

from parser.init_parser import parse_init_services
from analyzer.risk import analyze_services
from scanner.scan_setuid import scan_setuid
from scanner.scan_perm import scan_world_writable
from scanner.scan_su import scan_su


ROOTFS_DIR = "rootfs"
SYSTEM_PATH = os.path.join(ROOTFS_DIR, "system")
VENDOR_PATH = os.path.join(ROOTFS_DIR, "vendor")


def print_section(title, data):
    print(f"\n=== {title} ===")
    for r in data:
        flow = r.get("flow_type") or "unknown"
        print(f"\n[{r['level']}] {r['name']}  score={r['score']}")
        print(f"  input={r['input_type']}  priv={r['priv']}  flow={flow}")
        print(f"  exec: {r['exec']}")
        if r.get("sinks"):
            print(f"  sinks: {', '.join(r['sinks'])}")
        if r.get("evidence"):
            print(f"  evidence: {r['evidence'][0]}")


def run_analysis(show_all=False):
    if not os.path.exists(SYSTEM_PATH):
        print("[!] rootfs/system not found")
        return

    services = parse_init_services(SYSTEM_PATH)
    if os.path.exists(VENDOR_PATH):
        services += parse_init_services(VENDOR_PATH)

    results = analyze_services(services, SYSTEM_PATH)

    high   = [r for r in results if r["level"] == "HIGH"]
    medium = [r for r in results if r["level"] == "MEDIUM"]
    low    = [r for r in results if r["level"] == "LOW"]

    print_section("HIGH RISK TARGETS", high)
    print_section("MEDIUM RISK TARGETS", medium)

    if show_all:
        print_section("LOW RISK TARGETS", low)

    print(f"\n[*] {len(high)} HIGH  {len(medium)} MEDIUM  {len(low)} LOW")

    run_filesystem_checks(results)


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
        print("[dbg] filesystem checks: no rootfs paths found, skipping")
        return

    print(f"\n[dbg] filesystem checks: scanning {len(roots)} root(s)")
    total_files = 0
    for root in roots:
        count = sum(len(files) for _, _, files in os.walk(root))
        total_files += count
        print(f"[dbg]   {root}  ({count} files)")
    print(f"[dbg]   total: {total_files} files")

    exec_map = {svc["exec"]: svc for svc in results}

    def collect(fn, label):
        paths = []
        for root in roots:
            paths.extend(fn(root))
        print(f"[dbg] {label}: {len(paths)} result(s)")
        return paths

    def flag_setuid(svc):
        if svc["input_type"] in ("socket", "binder"):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="show LOW results too")
    args = parser.parse_args()

    run_analysis(show_all=args.all)
