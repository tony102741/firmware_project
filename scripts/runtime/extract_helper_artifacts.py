#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


HELPER_NAMES = {
    "/lib/sync-server/scripts/request",
    "/lib/sync-server/scripts/request_clients",
    "/lib/sync-server/scripts/sync_wifi",
    "/lib/sync-server/scripts/trans_main_wcfg",
    "/lib/sync-server/scripts/trans_backup_wcfg",
}


EXECVE_RE = re.compile(r'execve\("([^"]+)", \[(.*?)\],', re.DOTALL)
ARGV_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
OPEN_PATH_RE = re.compile(r'openat\([^,]+, "([^"]+)"')


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Extract helper invocations/artifacts from an MR90X observation directory.")
    ap.add_argument("observation_dir", help="Path under research/.../runtime_observation/<timestamp>")
    return ap.parse_args()


def unescape_c_string(s: str) -> str:
    return bytes(s, "utf-8").decode("unicode_escape")


def collect_strace_files(obs: Path) -> list[Path]:
    out = []
    for pat in ("sync_server_strace*", "meshd_strace*"):
        out.extend(sorted(p for p in obs.glob(pat) if p.is_file() and not p.name.endswith(".stderr")))
    return out


def parse_execves(text: str, source: str) -> list[dict[str, Any]]:
    invocations: list[dict[str, Any]] = []
    for m in EXECVE_RE.finditer(text):
      path = m.group(1)
      argv_blob = m.group(2)
      if path not in HELPER_NAMES:
        continue
      argv = [unescape_c_string(x) for x in ARGV_ITEM_RE.findall(argv_blob)]
      entry: dict[str, Any] = {
          "source_file": source,
          "helper_path": path,
          "helper_name": os.path.basename(path),
          "argv": argv,
      }
      if len(argv) > 1:
          entry["arg_infile"] = argv[1]
      if len(argv) > 2:
          entry["arg_outfile"] = argv[2]
      if len(argv) > 3:
          entry["arg_opcode"] = argv[3]
      if len(argv) > 4:
          entry["extra_args"] = argv[4:]
      invocations.append(entry)
    return invocations


def classify_json_file(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False
    sample = data.lstrip()
    if not sample:
        return False
    if sample[:1] not in (b"{", b"["):
        return False
    try:
        json.loads(data.decode("utf-8"))
    except Exception:
        return False
    return True


def relative_to_obs(path: Path, obs: Path) -> str:
    try:
        return str(path.relative_to(obs))
    except ValueError:
        return str(path)


def main() -> int:
    ns = parse_args()
    obs = Path(ns.observation_dir).resolve()
    if not obs.is_dir():
        raise SystemExit(f"observation dir not found: {obs}")

    strace_files = collect_strace_files(obs)
    invocations: list[dict[str, Any]] = []
    opened_paths: set[str] = set()
    for sf in strace_files:
        try:
            text = sf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        invocations.extend(parse_execves(text, sf.name))
        for m in OPEN_PATH_RE.finditer(text):
            opened_paths.add(m.group(1))

    snapshot_files = sorted(p for p in obs.glob("snapshots/**/*") if p.is_file())
    tmp_files = sorted(p for p in obs.glob("tmp_sync_server/**/*") if p.is_file())
    captured_files = snapshot_files + tmp_files

    candidate_json = []
    for p in captured_files:
        if classify_json_file(p):
            candidate_json.append({
                "path": relative_to_obs(p, obs),
                "size": p.stat().st_size,
            })

    summary = {
        "observation_dir": str(obs),
        "strace_files": [p.name for p in strace_files],
        "helper_invocation_count": len(invocations),
        "helper_invocations": invocations,
        "opened_paths": sorted(opened_paths),
        "captured_tmp_files": [relative_to_obs(p, obs) for p in captured_files],
        "candidate_json_files": candidate_json,
    }

    (obs / "helper_invocations.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Helper Artifact Summary",
        "",
        f"- Observation dir: `{obs}`",
        f"- Strace files parsed: `{len(strace_files)}`",
        f"- Helper invocations found: `{len(invocations)}`",
        f"- Captured `/tmp` files: `{len(captured_files)}`",
        f"- Candidate JSON files: `{len(candidate_json)}`",
        "",
        "## Helper Invocations",
        "",
    ]
    if invocations:
        for item in invocations:
            lines.append(f"- `{item['helper_path']}` from `{item['source_file']}`")
            if item.get("argv"):
                lines.append(f"  argv: `{item['argv']}`")
            if item.get("arg_infile"):
                lines.append(f"  infile: `{item['arg_infile']}`")
            if item.get("arg_outfile"):
                lines.append(f"  outfile: `{item['arg_outfile']}`")
            if item.get("arg_opcode"):
                lines.append(f"  opcode: `{item['arg_opcode']}`")
    else:
        lines.append("- no helper execve lines found")

    lines.extend(["", "## Candidate JSON Files", ""])
    if candidate_json:
        for item in candidate_json:
            lines.append(f"- `{item['path']}` ({item['size']} bytes)")
    else:
        lines.append("- none detected")

    lines.extend(["", "## Opened Paths From Strace", ""])
    if opened_paths:
        for path in sorted(opened_paths):
            lines.append(f"- `{path}`")
    else:
        lines.append("- none parsed")

    (obs / "helper_artifact_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
