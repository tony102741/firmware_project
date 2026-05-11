#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path


SERVICE_START_RE = re.compile(r"service_start\s+([^\s;&]+)")
SERVICE_STOP_RE = re.compile(r"service_stop\s+([^\s;&]+)")
EXEC_RE = re.compile(r"(?:(?:^|\s))(\/(?:usr\/)?s?bin\/[^\s;&]+|\/bin\/[^\s;&]+)")


def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def parse_init_script(path: Path) -> dict[str, object]:
    text = read_text(path)
    start = None
    stop = None
    starts: list[str] = []
    stops: list[str] = []
    execs: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("START="):
            start = stripped.split("=", 1)[1]
        if stripped.startswith("STOP="):
            stop = stripped.split("=", 1)[1]
        starts.extend(SERVICE_START_RE.findall(stripped))
        stops.extend(SERVICE_STOP_RE.findall(stripped))
        execs.extend(EXEC_RE.findall(stripped))
    return {
        "path": str(path),
        "start": start,
        "stop": stop,
        "service_start_targets": sorted(dict.fromkeys(starts)),
        "service_stop_targets": sorted(dict.fromkeys(stops)),
        "exec_targets": sorted(dict.fromkeys(execs)),
    }


def parse_rc_links(rootfs: Path) -> list[dict[str, str]]:
    rc_dir = rootfs / "etc/rc.d"
    if not rc_dir.exists():
        return []
    rows = []
    for path in sorted(rc_dir.iterdir()):
        if not path.is_symlink():
            continue
        rows.append(
            {
                "entry": str(path.relative_to(rootfs)),
                "target": str(path.resolve().relative_to(rootfs)) if path.resolve().is_absolute() and str(path.resolve()).startswith(str(rootfs)) else path.readlink().as_posix() if hasattr(path, "readlink") else "",
            }
        )
    return rows


def parse_hotplug_scripts(rootfs: Path) -> list[dict[str, object]]:
    hotplug_dir = rootfs / "etc/hotplug.d"
    if not hotplug_dir.exists():
        return []
    rows = []
    for path in sorted(hotplug_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(rootfs)
        text = read_text(path)
        execs = sorted(dict.fromkeys(EXEC_RE.findall(text)))
        rows.append(
            {
                "path": str(rel),
                "subsystem": rel.parts[2] if len(rel.parts) > 2 else "",
                "exec_targets": execs,
                "touches_service_logic": bool(execs or "service_" in text or "ubus" in text or "uci" in text),
            }
        )
    return rows


def extract_service_topology(rootfs: Path) -> dict[str, object]:
    init_dir = rootfs / "etc/init.d"
    init_scripts = []
    if init_dir.exists():
        for path in sorted(init_dir.iterdir()):
            if path.is_file():
                init_scripts.append(parse_init_script(path))
    rc_links = parse_rc_links(rootfs)
    hotplug = parse_hotplug_scripts(rootfs)
    return {
        "rootfs": str(rootfs),
        "init_scripts": init_scripts,
        "rc_links": rc_links,
        "hotplug_scripts": hotplug,
    }


def markdown_service_topology(topology: dict[str, object], focus_bins: set[str] | None = None) -> str:
    if focus_bins is None:
        focus_bins = set()
    lines = [
        "# Service Topology",
        "",
        "## init.d",
        "",
        "| Script | START | STOP | service_start | exec targets |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    for item in topology["init_scripts"]:
        starts = ", ".join(item["service_start_targets"]) or "-"
        execs = ", ".join(item["exec_targets"]) or "-"
        lines.append(
            f"| `{Path(item['path']).name}` | `{item['start'] or '-'}` | `{item['stop'] or '-'}` | `{starts}` | `{execs}` |"
        )
    lines += [
        "",
        "## rc.d links",
        "",
        "| Entry | Target |",
        "| --- | --- |",
    ]
    for item in topology["rc_links"]:
        lines.append(f"| `{item['entry']}` | `{item['target']}` |")
    lines += [
        "",
        "## hotplug scripts with service/control-plane relevance",
        "",
        "| Script | Subsystem | Exec targets |",
        "| --- | --- | --- |",
    ]
    for item in topology["hotplug_scripts"]:
        if not item["touches_service_logic"]:
            continue
        execs = ", ".join(item["exec_targets"]) or "-"
        lines.append(f"| `{item['path']}` | `{item['subsystem']}` | `{execs}` |")
    if focus_bins:
        lines += [
            "",
            "## Focus Components",
            "",
        ]
        for item in topology["init_scripts"]:
            hit = focus_bins & set(item["service_start_targets"]) | focus_bins & set(item["exec_targets"])
            if hit:
                lines.append(f"- `{Path(item['path']).name}` touches `{', '.join(sorted(hit))}`")
    return "\n".join(lines) + "\n"


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Extract init/rc.d/hotplug service topology from a preserved rootfs.")
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--md-out")
    args = ap.parse_args()

    topology = extract_service_topology(Path(args.rootfs))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(topology, indent=2), encoding="utf-8")
    if args.md_out:
        Path(args.md_out).write_text(markdown_service_topology(topology), encoding="utf-8")
    if not args.json_out and not args.md_out:
        print(json.dumps(topology, indent=2))


if __name__ == "__main__":
    main()
