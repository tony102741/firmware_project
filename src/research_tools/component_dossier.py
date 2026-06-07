#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

try:
    from .paths import relative_to_project
    from .service_topology import extract_service_topology, markdown_service_topology
except ImportError:
    from paths import relative_to_project
    from service_topology import extract_service_topology, markdown_service_topology

STRING_PATTERNS = [
    "127.0.0.1",
    "20002",
    "/tmp/",
    "tmp",
    "tdp",
    "ubus",
    "uci",
    "token",
    "session",
    "cloud",
    "account",
    "bind",
    "login",
    "auth",
    "ssl",
    "tls",
    "mqtt",
    "https",
]

LOOPBACK_PATTERNS = ["127.0.0.1", "20002", "tmp", "tdp", "token", "session"]
AUTH_PATTERNS = ["token", "session", "account", "bind", "login", "auth", "cloud"]


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def file_desc(path: Path) -> str:
    return run(["file", str(path)]).strip()


def elf_metadata(path: Path) -> dict[str, object]:
    desc = file_desc(path)
    if "ELF" not in desc:
        return {"file": desc, "class": "non-ELF", "machine": "script/text", "needed": []}
    readelf_h = run(["readelf", "-h", str(path)])
    readelf_d = run(["readelf", "-d", str(path)])
    elf_class = ""
    machine = ""
    for line in readelf_h.splitlines():
        if "Class:" in line:
            elf_class = line.split(":", 1)[1].strip()
        if "Machine:" in line:
            machine = line.split(":", 1)[1].strip()
    needed = []
    for line in readelf_d.splitlines():
        if "(NEEDED)" in line:
            needed.append(line.split("[", 1)[1].split("]", 1)[0])
    return {"file": desc, "class": elf_class, "machine": machine, "needed": needed}


def triage_strings(path: Path, patterns: list[str] | None = None) -> dict[str, list[str]]:
    if patterns is None:
        patterns = STRING_PATTERNS
    text = run(["strings", "-a", str(path)])
    lines = text.splitlines()
    out: dict[str, list[str]] = {}
    for pat in patterns:
        matches: list[str] = []
        low_pat = pat.lower()
        for line in lines:
            if low_pat in line.lower():
                matches.append(line)
            if len(matches) >= 10:
                break
        out[pat] = matches
    return out


def copy_item(rootfs: Path, workspace: Path, relpath: str) -> dict[str, str]:
    src = rootfs / relpath
    dst = workspace / "rootfs" / relpath
    ensure_parent(dst)
    if src.is_symlink():
        target = os.readlink(src)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        os.symlink(target, dst)
        kind = "symlink"
    else:
        shutil.copy2(src, dst)
        kind = "file"
    return {"relative": relpath, "original": str(src), "workspace": str(dst), "kind": kind}


def read_init_meta(rootfs: Path, relpath: str) -> dict[str, object]:
    path = rootfs / relpath
    start = None
    stop = None
    actions = []
    text = path.read_text(errors="ignore")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("START="):
            start = stripped.split("=", 1)[1]
        if stripped.startswith("STOP="):
            stop = stripped.split("=", 1)[1]
        if "service_start " in stripped or "service_stop " in stripped:
            actions.append(stripped)
    return {"start": start, "stop": stop, "actions": actions}


def score_patterns(strings: dict[str, list[str]], patterns: list[str]) -> int:
    score = 0
    for pat in patterns:
        if strings.get(pat):
            score += 1
    return score


def classify_candidate(strings: dict[str, list[str]], init_meta: dict[str, object] | None) -> dict[str, object]:
    loopback_score = score_patterns(strings, LOOPBACK_PATTERNS)
    auth_score = score_patterns(strings, AUTH_PATTERNS)
    service_score = 1 if init_meta and init_meta.get("start") else 0
    tags = []
    if loopback_score >= 3:
        tags.append("loopback-relay-candidate")
    if auth_score >= 3:
        tags.append("auth-boundary-candidate")
    if service_score:
        tags.append("auto-start-service")
    if strings.get("ssl") or strings.get("tls") or strings.get("https"):
        tags.append("cloud-transport-candidate")
    return {
        "loopback_score": loopback_score,
        "auth_score": auth_score,
        "service_score": service_score,
        "tags": tags,
    }


def short_path(path: str) -> str:
    return relative_to_project(path)


def write(path: Path, text: str) -> None:
    ensure_parent(path)
    path.write_text(text, encoding="utf-8")


def generate_reports(
    workspace: Path,
    rootfs: Path,
    target_name: str,
    components: list[str],
    context: list[str],
    init_files: list[str],
    records: dict[str, dict[str, object]],
    copied: list[dict[str, str]],
) -> None:
    inv = [
        f"# {target_name} Component Dossier",
        "",
        f"- rootfs: `{rootfs}`",
        f"- workspace: `{workspace}`",
        "",
        "## Primary Components",
        "",
        "| Component | Workspace path | SHA256 | ELF | Arch | Size | Loopback | Auth | Tags |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for rel in components:
        rec = records[rel]
        clf = rec["classification"]
        inv.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} | `{}` |".format(
                rel,
                short_path(rec["workspace"]),
                rec["sha256"],
                rec["elf"]["class"],
                rec["elf"]["machine"],
                rec["size"],
                clf["loopback_score"],
                clf["auth_score"],
                ", ".join(clf["tags"]) or "-",
            )
        )
    write(workspace / "target_inventory.md", "\n".join(inv) + "\n")

    summary = [
        "# Component Summary",
        "",
        "## Included Files",
        "",
    ]
    for item in copied:
        summary.append(f"- `{short_path(item['workspace'])}`")
    summary += [
        "",
        "## Highest-Signal Candidates",
        "",
    ]
    ranked = sorted(
        ((rel, records[rel]["classification"]) for rel in components),
        key=lambda item: (item[1]["auth_score"], item[1]["loopback_score"], item[1]["service_score"]),
        reverse=True,
    )
    for rel, clf in ranked[:5]:
        summary.append(
            f"- `{rel}`: auth `{clf['auth_score']}`, loopback `{clf['loopback_score']}`, tags `{', '.join(clf['tags']) or '-'}`"
        )
    write(workspace / "component_summary.md", "\n".join(summary) + "\n")

    init_lines = [
        "# Init Relationships",
        "",
        "| Init Script | START | STOP | Actions |",
        "| --- | ---: | ---: | --- |",
    ]
    for rel in init_files:
        meta = records[rel]["init"]
        init_lines.append(
            f"| `{rel}` | `{meta['start'] or '-'}` | `{meta['stop'] or '-'}` | `{' ; '.join(meta['actions']) or '-'}` |"
        )
    write(workspace / "init_relationships.md", "\n".join(init_lines) + "\n")

    triage = [
        "# Initial String Triage",
        "",
    ]
    for rel in components:
        rec = records[rel]
        triage.append(f"## `{rel}`")
        triage.append("")
        for pat in STRING_PATTERNS:
            matches = rec["strings"].get(pat, [])
            if matches:
                triage.append(f"- `{pat}`")
                for line in matches[:5]:
                    triage.append(f"  - `{line}`")
        triage.append("")
    write(workspace / "initial_string_triage.md", "\n".join(triage) + "\n")

    evidence = {
        "target_name": target_name,
        "rootfs": str(rootfs),
        "components": components,
        "context": context,
        "init_files": init_files,
        "records": records,
    }
    write(workspace / "dossier_meta.json", json.dumps(evidence, indent=2) + "\n")


def build_dossier(
    rootfs: Path,
    workspace: Path,
    target_name: str,
    components: list[str],
    context: list[str],
    init_files: list[str],
) -> None:
    if workspace.exists():
        shutil.rmtree(workspace)
    (workspace / "rootfs").mkdir(parents=True, exist_ok=True)

    copied = []
    records: dict[str, dict[str, object]] = {}

    for rel in components + context + init_files:
        src = rootfs / rel
        if not src.exists() and not src.is_symlink():
            continue
        copied.append(copy_item(rootfs, workspace, rel))

    for rel in components:
        path = rootfs / rel
        init_meta = None
        base_name = Path(rel).name
        matched_init = next((item for item in init_files if base_name in item or base_name.replace("-", "_") in item), None)
        if matched_init and (rootfs / matched_init).exists():
            init_meta = read_init_meta(rootfs, matched_init)
        strings = triage_strings(path)
        records[rel] = {
            "original": str(path),
            "workspace": str(workspace / "rootfs" / rel),
            "sha256": sha256(path),
            "size": path.stat().st_size,
            "elf": elf_metadata(path),
            "strings": strings,
            "classification": classify_candidate(strings, init_meta),
        }

    for rel in init_files:
        path = rootfs / rel
        if path.exists():
            records[rel] = {"init": read_init_meta(rootfs, rel)}

    generate_reports(workspace, rootfs, target_name, components, context, init_files, records, copied)
    topology = extract_service_topology(rootfs)
    focus_bins = {f"/{rel}" if not rel.startswith("/") else rel for rel in components}
    write(workspace / "service_topology.json", json.dumps(topology, indent=2) + "\n")
    write(workspace / "service_topology.md", markdown_service_topology(topology, focus_bins=focus_bins))


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a reproducible component dossier from a preserved firmware rootfs.")
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--target-name", required=True)
    ap.add_argument("--component", action="append", default=[])
    ap.add_argument("--context", action="append", default=[])
    ap.add_argument("--init", dest="init_files", action="append", default=[])
    args = ap.parse_args()

    build_dossier(
        rootfs=Path(args.rootfs),
        workspace=Path(args.workspace),
        target_name=args.target_name,
        components=args.component,
        context=args.context,
        init_files=args.init_files,
    )


if __name__ == "__main__":
    main()
