"""
Build a prioritized direct-review queue from corpus review packets.

The goal is to spend manual review time where it most improves engine judgment:

- opaque blob/container families first
- weak rootfs cases with low-confidence top candidates next
- already reviewed items last

Usage:
  python3 src/review/manual_review_queue.py \
      --packets research/review/llm/llm_review_packets.jsonl \
      --manual research/review/manual/manual_review_labels.jsonl \
      --json-out research/review/manual/manual_review_queue.json \
      --jsonl-out research/review/manual/manual_review_queue.jsonl \
      --markdown-out research/review/manual/manual_review_queue.md
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def load_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for idx, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: line {idx}: invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: str, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")


def _manual_map(path: str | None) -> dict[str, dict]:
    if not path or not Path(path).is_file():
        return {}
    out = {}
    for row in load_jsonl(path):
        review_id = row.get("review_id")
        if review_id:
            out[review_id] = row
    return out


def _confidence_penalty(candidates: list[dict]) -> int:
    if not candidates:
        return 15
    top = candidates[0]
    conf = str(top.get("confidence") or "").upper()
    if conf == "LOW":
        return 10
    if conf == "MEDIUM":
        return 4
    return 0


def _missing_links_penalty(candidates: list[dict]) -> int:
    if not candidates:
        return 0
    top = candidates[0]
    return min(8, len(top.get("missing_links") or []) * 2)


def score_packet(packet: dict, manual_row: dict | None) -> tuple[int, list[str]]:
    engine = packet.get("engine_state") or {}
    evidence = packet.get("evidence") or {}
    top_candidates = evidence.get("top_candidates") or []

    success_quality = engine.get("success_quality") or "unknown"
    probe_readiness = engine.get("probe_readiness") or "unknown"
    blob_family = engine.get("blob_family") or "none"
    analysis_mode = engine.get("analysis_mode") or "unknown"
    web_surface = bool(engine.get("web_surface_detected"))

    score = 0
    reasons: list[str] = []

    if probe_readiness == "bundle-probe-ready":
        score += 100
        reasons.append("bundle-probe-ready")
    elif probe_readiness == "decrypt-probe-ready":
        score += 95
        reasons.append("decrypt-probe-ready")
    elif probe_readiness == "scan-probe-ready":
        score += 90
        reasons.append("scan-probe-ready")
    elif success_quality == "blob-success":
        score += 80
        reasons.append("blob-success")

    if blob_family != "none":
        score += 8
        reasons.append(f"blob-family:{blob_family}")

    if success_quality == "rootfs-success":
        conf_penalty = _confidence_penalty(top_candidates)
        if conf_penalty:
            score += conf_penalty
            reasons.append("weak-top-candidate")
        link_penalty = _missing_links_penalty(top_candidates)
        if link_penalty:
            score += link_penalty
            reasons.append("missing-links")
        if top_candidates:
            top = top_candidates[0]
            if not top.get("handler_surface"):
                score += 4
                reasons.append("no-handler-surface")
            if not top.get("web_exposed") and web_surface:
                score += 4
                reasons.append("web-surface-gap")

    if analysis_mode == "general":
        score += 6
        reasons.append("general-mode")

    status = str((manual_row or {}).get("review_status") or "PENDING").upper()
    if status == "REVIEWED":
        score -= 1000
        reasons.append("already-reviewed")
    elif status == "PENDING":
        score += 5
        reasons.append("pending-review")

    return score, reasons


def build_queue(packets: list[dict], manual_rows: dict[str, dict]) -> list[dict]:
    queue = []
    for packet in packets:
        review_id = packet.get("review_id")
        manual_row = manual_rows.get(review_id)
        score, reasons = score_packet(packet, manual_row)
        firmware = packet.get("firmware") or {}
        engine = packet.get("engine_state") or {}
        candidates = (packet.get("evidence") or {}).get("top_candidates") or []
        top = candidates[0] if candidates else {}

        queue.append({
            "review_id": review_id,
            "priority_score": score,
            "priority_reasons": reasons,
            "review_status": str((manual_row or {}).get("review_status") or "PENDING").upper(),
            "vendor": firmware.get("vendor"),
            "model": firmware.get("model"),
            "version": firmware.get("version"),
            "local_filename": firmware.get("local_filename"),
            "run_id": firmware.get("run_id"),
            "success_quality": engine.get("success_quality"),
            "probe_readiness": engine.get("probe_readiness"),
            "blob_family": engine.get("blob_family") or "none",
            "analysis_mode": engine.get("analysis_mode"),
            "web_surface_detected": engine.get("web_surface_detected"),
            "top_candidate_name": top.get("name"),
            "top_candidate_confidence": top.get("confidence"),
            "top_candidate_summary": top.get("vuln_summary"),
            "top_candidate_missing_links": top.get("missing_links") or [],
        })
    queue.sort(
        key=lambda row: (
            -int(row.get("priority_score") or 0),
            str(row.get("vendor") or ""),
            str(row.get("model") or ""),
            str(row.get("version") or ""),
        )
    )
    return queue


def render_markdown(queue: list[dict]) -> str:
    lines = [
        "# Manual Review Queue",
        "",
        f"- queue size: {len(queue)}",
        "",
    ]
    for idx, row in enumerate(queue[:20], 1):
        label = " / ".join(str(x) for x in [row.get("vendor"), row.get("model"), row.get("version")] if x)
        lines.append(f"## {idx}. {label}")
        lines.append("")
        lines.append(f"- `review_id`: `{row.get('review_id')}`")
        lines.append(f"- `priority_score`: `{row.get('priority_score')}`")
        lines.append(f"- `review_status`: `{row.get('review_status')}`")
        lines.append(f"- `success_quality`: `{row.get('success_quality')}`")
        lines.append(f"- `probe_readiness`: `{row.get('probe_readiness')}`")
        lines.append(f"- `blob_family`: `{row.get('blob_family')}`")
        lines.append(f"- `priority_reasons`: {', '.join(row.get('priority_reasons') or [])}")
        if row.get("top_candidate_name"):
            lines.append(f"- top candidate: `{row.get('top_candidate_name')}` ({row.get('top_candidate_confidence')})")
        if row.get("top_candidate_summary"):
            lines.append(f"- summary: {row.get('top_candidate_summary')}")
        if row.get("top_candidate_missing_links"):
            lines.append(f"- missing links: {', '.join(row.get('top_candidate_missing_links') or [])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", required=True)
    ap.add_argument("--manual", help="Optional manual review labels JSONL.")
    ap.add_argument("--limit", type=int, default=0, help="Only emit the top N rows.")
    ap.add_argument("--json-out")
    ap.add_argument("--jsonl-out")
    ap.add_argument("--markdown-out")
    args = ap.parse_args()

    packets = load_jsonl(args.packets)
    queue = build_queue(packets, _manual_map(args.manual))
    if args.limit:
        queue = queue[: args.limit]

    payload = {
        "queue_size": len(queue),
        "review_status_counts": dict(sorted(Counter(row.get("review_status") for row in queue).items())),
        "rows": queue,
    }

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    if args.jsonl_out:
        write_jsonl(args.jsonl_out, queue)
    if args.markdown_out:
        with open(args.markdown_out, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(queue))

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
