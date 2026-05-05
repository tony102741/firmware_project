"""
Build a conservative memory-corruption hunting queue from reviewed packets.

The goal is not to prove exploitability. The goal is to surface the small
set of samples where the current evidence is strongest for parser / copy /
overflow-style work, while suppressing command-only noise.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


MEMORY_SINK_HINTS = (
    "memcpy",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "sscanf",
    "scanf",
    "fscanf",
    "gets",
)

MEMORY_SUMMARY_HINTS = (
    "overflow",
    "buffer overflow",
    "stack buffer",
    "heap overflow",
    "format string",
    "memory corruption",
)


def load_jsonl(path: str | Path) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_labels(paths: list[str | Path]) -> dict[str, dict]:
    labels: dict[str, dict] = {}
    for path in paths:
        p = Path(path)
        if not p.is_file():
            continue
        for row in load_jsonl(p):
            rid = str(row.get("review_id") or "").strip()
            if rid:
                labels[rid] = row
    return labels


def is_memory_candidate(candidate: dict) -> bool:
    sinks = [str(s).lower() for s in (candidate.get("all_sinks") or [])]
    summary = str(candidate.get("vuln_summary") or "").lower()
    return any(h in sink for sink in sinks for h in MEMORY_SINK_HINTS) or any(
        h in summary for h in MEMORY_SUMMARY_HINTS
    )


def score_candidate(packet: dict, label_row: dict | None, candidate: dict) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    manual_family = ((label_row or {}).get("manual_labels") or {}).get("top_risk_family")
    if manual_family == "memory-corruption":
        score += 50
        reasons.append("reviewed-memory-corruption")

    sinks = [str(s).lower() for s in (candidate.get("all_sinks") or [])]
    summary = str(candidate.get("vuln_summary") or "")
    summary_l = summary.lower()

    if any(h in summary_l for h in MEMORY_SUMMARY_HINTS):
        score += 18
        reasons.append("overflow-summary")

    sink_hits = sorted({hint for hint in MEMORY_SINK_HINTS for sink in sinks if hint in sink})
    if sink_hits:
        score += min(18, 5 + 3 * len(sink_hits))
        reasons.append(f"memory-sinks:{','.join(sink_hits[:4])}")

    if candidate.get("web_exposed"):
        score += 12
        reasons.append("web-exposed")
    if candidate.get("handler_surface"):
        score += 8
        reasons.append("handler-surface")

    auth = str(candidate.get("auth_bypass") or "").lower()
    if auth == "confirmed":
        score += 12
        reasons.append("pre-auth")
    elif auth == "bypassable":
        score += 8
        reasons.append("auth-bypassable")
    elif auth == "required":
        score -= 3
        reasons.append("post-auth")

    conf = str(candidate.get("confidence") or "").upper()
    if conf == "HIGH":
        score += 8
        reasons.append("high-confidence")
    elif conf == "MEDIUM":
        score += 4
        reasons.append("medium-confidence")

    triage = int(candidate.get("triage_score") or 0)
    score += min(12, triage // 4)
    if triage:
        reasons.append(f"triage:{triage}")

    missing = set(candidate.get("missing_links") or [])
    if "exact_input_unknown" in missing:
        score -= 8
        reasons.append("missing:exact-input")
    if "auth_boundary_unknown" in missing:
        score -= 4
        reasons.append("missing:auth-boundary")
    if "chain_gap_unknown" in missing:
        score -= 4
        reasons.append("missing:chain-gap")

    if not candidate.get("web_exposed") and not candidate.get("handler_surface"):
        score -= 6
        reasons.append("weak-surface")

    return score, reasons


def collect_rows(packet_paths: list[str | Path], label_paths: list[str | Path]) -> list[dict]:
    labels = load_labels(label_paths)
    dedup: dict[tuple[str, str], dict] = {}
    for path in packet_paths:
        p = Path(path)
        if not p.is_file():
            continue
        for packet in load_jsonl(p):
            rid = str(packet.get("review_id") or "").strip()
            label_row = labels.get(rid)
            manual_family = ((label_row or {}).get("manual_labels") or {}).get("top_risk_family")
            cands = ((packet.get("evidence") or {}).get("top_candidates") or [])
            for cand in cands:
                if not is_memory_candidate(cand):
                    continue
                summary_l = str(cand.get("vuln_summary") or "").lower()
                flow_type = str(cand.get("flow_type") or "").lower()
                is_memory_flow = flow_type in {"buffer_overflow", "heap_overflow", "format_string"}
                has_memory_summary = any(
                    hint in summary_l for hint in MEMORY_SUMMARY_HINTS
                )
                if not has_memory_summary and not is_memory_flow:
                    continue
                if manual_family != "memory-corruption" and not has_memory_summary and not is_memory_flow:
                    continue
                score, reasons = score_candidate(packet, label_row, cand)
                row = {
                    "review_id": rid,
                    "firmware": packet.get("firmware") or {},
                    "candidate": cand,
                    "manual_top_risk_family": manual_family,
                    "queue_score": score,
                    "queue_reasons": reasons,
                }
                key = (rid.strip().lower(), str(cand.get("name") or "").strip().lower())
                prev = dedup.get(key)
                if prev is None or int(row["queue_score"]) > int(prev["queue_score"]):
                    dedup[key] = row
    rows = list(dedup.values())
    rows.sort(key=lambda r: (-int(r["queue_score"]), r["review_id"], str(r["candidate"].get("name") or "")))
    return rows


def write_markdown(rows: list[dict], path: str | Path, top: int) -> None:
    lines = ["# Memory Hunt Queue", ""]
    if not rows:
        lines.append("(no memory-corruption candidates passed the conservative packet filter)")
    for idx, row in enumerate(rows[:top], 1):
        fw = row["firmware"]
        cand = row["candidate"]
        lines.extend([
            f"## Rank {idx}",
            f"- firmware: `{fw.get('vendor') or '?'} {fw.get('model') or '?'} {fw.get('version') or ''}`",
            f"- review_id: `{row['review_id']}`",
            f"- binary/script: `{cand.get('name') or '?'}`",
            f"- summary: `{cand.get('vuln_summary') or 'n/a'}`",
            f"- sinks: `{', '.join(cand.get('all_sinks') or []) or 'none'}`",
            f"- endpoints: `{', '.join(cand.get('endpoints') or []) or 'none'}`",
            f"- confidence: `{cand.get('confidence') or 'unknown'}`",
            f"- auth: `{cand.get('auth_bypass') or 'unknown'}`",
            f"- missing_links: `{', '.join(cand.get('missing_links') or []) or 'none'}`",
            f"- reviewed_family: `{row.get('manual_top_risk_family') or 'unlabeled'}`",
            f"- queue_score: `{row['queue_score']}`",
            f"- reasons: `{', '.join(row['queue_reasons'])}`",
            "",
        ])
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", nargs="+", required=True)
    ap.add_argument("--labels", nargs="*", default=[])
    ap.add_argument("--markdown-out", required=True)
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    rows = collect_rows(args.packets, args.labels)
    write_markdown(rows, args.markdown_out, args.top)
    Path(args.json_out).write_text(json.dumps(rows[: args.top], indent=2), encoding="utf-8")
    print(json.dumps({
        "packet_files": len(args.packets),
        "label_files": len(args.labels),
        "candidate_rows": len(rows),
        "emitted": min(len(rows), args.top),
    }, indent=2))


if __name__ == "__main__":
    main()
