"""
Evaluate LLM review predictions against a gold-label JSONL file.

Prediction rows should contain either:
  - {"review_id": "...", "labels": {...}}
  - {"review_id": "...", "predictions": {...}}

Gold rows should contain:
  - {"review_id": "...", "labels": {...}}
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gold", required=True)
    ap.add_argument("--predictions", required=True)
    args = ap.parse_args()

    gold = {}
    for row in load_jsonl(args.gold):
        gold[row["review_id"]] = (
            row.get("labels")
            or row.get("manual_labels")
            or {}
        )
    preds = {}
    for row in load_jsonl(args.predictions):
        preds[row["review_id"]] = row.get("labels") or row.get("predictions") or {}

    totals = Counter()
    matches = Counter()
    mismatches = defaultdict(list)

    for review_id, labels in gold.items():
        pred = preds.get(review_id) or {}
        for field in FIELDS:
            if field not in labels:
                continue
            totals[field] += 1
            if pred.get(field) == labels.get(field):
                matches[field] += 1
            else:
                mismatches[field].append({
                    "review_id": review_id,
                    "expected": labels.get(field),
                    "predicted": pred.get(field),
                })

    payload = {
        "gold_rows": len(gold),
        "prediction_rows": len(preds),
        "field_accuracy": {
            field: {
                "correct": matches[field],
                "total": totals[field],
                "accuracy": round(matches[field] / totals[field], 4) if totals[field] else None,
            }
            for field in FIELDS
        },
        "mismatches": {field: rows[:10] for field, rows in mismatches.items() if rows},
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
