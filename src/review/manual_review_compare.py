"""
Compare engine-derived review labels against manually corrected review labels.

This lets you run the pipeline, inspect a firmware yourself, then measure where
the tool's current judgment diverges from the manual review.

Typical workflow:
  python3 src/review/manual_review_compare.py \
      --packets research/review/llm/llm_review_packets.jsonl \
      --write-stubs research/review/manual/manual_review_labels.jsonl

  # edit `manual_labels` by hand for reviewed rows

  python3 src/review/manual_review_compare.py \
      --packets research/review/llm/llm_review_packets.jsonl \
      --manual research/review/manual/manual_review_labels.jsonl \
      --json-out research/review/manual/manual_review_diff.json \
      --markdown-out research/review/manual/manual_review_diff.md
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from review.llm_review import build_gold_stub, load_json, load_jsonl


FIELDS = (
    "has_rootfs",
    "has_web_ui",
    "artifact_kind",
    "probe_readiness",
    "blob_family",
    "encrypted_container",
    "best_next_action",
    "top_risk_family",
)


def write_jsonl(path: str | Path, rows: Iterable[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")


def _read_packets(path: str) -> list[dict]:
    p = Path(path)
    if p.suffix == ".json":
        return [load_json(path)]
    return load_jsonl(path)


def _read_manual_rows(path: str) -> dict[str, dict]:
    rows = {}
    for row in load_jsonl(path):
        review_id = row.get("review_id")
        if not review_id:
            raise ValueError(f"{path}: every row must contain review_id")
        rows[review_id] = row
    return rows


def _manual_labels(row: dict) -> dict:
    labels = row.get("manual_labels")
    if labels is None:
        labels = row.get("labels")
    if labels is None:
        labels = {}
    return labels


def _mismatch_kind(field: str, predicted, expected) -> str:
    if field in {"has_rootfs", "artifact_kind"}:
        return "rootfs_state_mismatch"
    if field == "has_web_ui":
        return "web_surface_mismatch"
    if field == "probe_readiness":
        return "probe_strategy_mismatch"
    if field == "blob_family":
        return "blob_family_mismatch"
    if field == "encrypted_container":
        return "container_state_mismatch"
    if field == "best_next_action":
        if predicted in {"review-artifacts", "expand-binary-signals"} and expected not in {predicted, None, ""}:
            return "next_action_too_generic"
        return "next_action_mismatch"
    if field == "top_risk_family":
        return "risk_family_mismatch"
    return "label_mismatch"


def _row_status(row: dict) -> str:
    return str(row.get("review_status") or "PENDING").upper()


def build_stub(packet: dict) -> dict:
    engine = build_gold_stub(packet)
    return {
        "review_id": packet.get("review_id"),
        "firmware": packet.get("firmware"),
        "review_status": "PENDING",
        "engine_labels": engine.get("labels") or {},
        "manual_labels": engine.get("labels") or {},
        "review_notes": "Correct manual_labels after direct review. Keep fields you agree with.",
        "mismatch_focus": [],
    }


def compare_packets_to_manual(packets: list[dict], manual_rows: dict[str, dict]) -> dict:
    totals = Counter()
    matches = Counter()
    mismatch_kinds = Counter()
    review_statuses = Counter()
    per_review = []
    missing_manual = []

    for packet in packets:
        review_id = packet.get("review_id")
        engine_stub = build_gold_stub(packet)
        predicted = engine_stub.get("labels") or {}
        manual_row = manual_rows.get(review_id)
        if not manual_row:
            missing_manual.append(review_id)
            continue

        review_statuses[_row_status(manual_row)] += 1
        expected = _manual_labels(manual_row)
        field_mismatches = []

        for field in FIELDS:
            if field not in expected:
                continue
            totals[field] += 1
            if predicted.get(field) == expected.get(field):
                matches[field] += 1
                continue
            kind = _mismatch_kind(field, predicted.get(field), expected.get(field))
            mismatch_kinds[kind] += 1
            field_mismatches.append({
                "field": field,
                "kind": kind,
                "predicted": predicted.get(field),
                "expected": expected.get(field),
            })

        per_review.append({
            "review_id": review_id,
            "firmware": packet.get("firmware") or {},
            "review_status": _row_status(manual_row),
            "engine_labels": predicted,
            "manual_labels": expected,
            "mismatches": field_mismatches,
            "review_notes": manual_row.get("review_notes") or "",
        })

    return {
        "packet_rows": len(packets),
        "manual_rows": len(manual_rows),
        "review_status_counts": dict(sorted(review_statuses.items())),
        "field_accuracy": {
            field: {
                "correct": matches[field],
                "total": totals[field],
                "accuracy": round(matches[field] / totals[field], 4) if totals[field] else None,
            }
            for field in FIELDS
        },
        "mismatch_kind_counts": dict(sorted(mismatch_kinds.items())),
        "missing_manual_reviews": missing_manual,
        "per_review": per_review,
    }


def render_markdown(payload: dict) -> str:
    lines = [
        "# Manual Review Diff",
        "",
        f"- packets: {payload.get('packet_rows', 0)}",
        f"- manual rows: {payload.get('manual_rows', 0)}",
        f"- review statuses: {payload.get('review_status_counts', {})}",
        f"- mismatch kinds: {payload.get('mismatch_kind_counts', {})}",
        "",
        "## Field Accuracy",
        "",
    ]
    for field, stats in payload.get("field_accuracy", {}).items():
        lines.append(
            f"- `{field}`: {stats['correct']}/{stats['total']} "
            + (f"({stats['accuracy']:.4f})" if stats["accuracy"] is not None else "(n/a)")
        )

    if payload.get("missing_manual_reviews"):
        lines.extend([
            "",
            "## Missing Manual Reviews",
            "",
        ])
        for review_id in payload["missing_manual_reviews"]:
            lines.append(f"- `{review_id}`")

    mismatched = [row for row in payload.get("per_review", []) if row.get("mismatches")]
    if mismatched:
        lines.extend([
            "",
            "## Review Mismatches",
            "",
        ])
        for row in mismatched:
            fw = row.get("firmware") or {}
            label = " / ".join(
                str(x) for x in [fw.get("vendor"), fw.get("model"), fw.get("version")] if x
            ) or row.get("review_id")
            lines.append(f"### {label}")
            lines.append("")
            lines.append(f"- `review_id`: `{row.get('review_id')}`")
            for item in row.get("mismatches") or []:
                lines.append(
                    f"- `{item['field']}`: predicted `{item['predicted']}` vs manual `{item['expected']}` "
                    f"({item['kind']})"
                )
            if row.get("review_notes"):
                lines.append(f"- notes: {row['review_notes']}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", required=True, help="Packet JSON or JSONL from src/review/llm_review.py")
    ap.add_argument("--manual", help="Manual review labels JSONL.")
    ap.add_argument("--write-stubs", help="Write editable manual-review stubs JSONL.")
    ap.add_argument("--json-out", help="Write comparison summary JSON.")
    ap.add_argument("--markdown-out", help="Write comparison summary Markdown.")
    args = ap.parse_args()

    packets = _read_packets(args.packets)
    if not packets:
        raise SystemExit("no packets loaded")

    if args.write_stubs:
        stubs = [build_stub(packet) for packet in packets]
        write_jsonl(args.write_stubs, stubs)
        print(json.dumps({
            "stub_rows_written": len(stubs),
            "stub_path": args.write_stubs,
        }, ensure_ascii=False, indent=2))
        return 0

    if not args.manual:
        raise SystemExit("--manual is required unless --write-stubs is used")

    payload = compare_packets_to_manual(packets, _read_manual_rows(args.manual))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    if args.markdown_out:
        with open(args.markdown_out, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(payload))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
