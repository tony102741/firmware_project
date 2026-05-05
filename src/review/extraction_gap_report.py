"""
Summarize current extraction bottlenecks from firmware_corpus.jsonl.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_jsonl(path: str | Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def classify_priority(row: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    sq = row.get("success_quality")
    pr = row.get("probe_readiness")
    bf = row.get("blob_family")
    if sq is None:
        score += 15
        reasons.append("metadata-or-regression-backfill")
    elif sq == "blob-success":
        score += 60
        reasons.append("blob-success")
    elif sq == "fallback-success":
        score += 70
        reasons.append("fallback-success")
    if pr in {"bundle-probe-ready", "decrypt-probe-ready", "scan-probe-ready"}:
        score += 18
        reasons.append(f"probe:{pr}")
    if bf:
        score += 10
        reasons.append(f"blob-family:{bf}")
    if not row.get("web_surface_detected") and row.get("web_ui_expected"):
        score += 8
        reasons.append("expected-web-ui-not-surfaced")
    return score, reasons


def build_rows(corpus_rows: list[dict]) -> list[dict]:
    out = []
    for row in corpus_rows:
        score, reasons = classify_priority(row)
        if score <= 0:
            continue
        out.append({
            "corpus_id": row.get("corpus_id"),
            "vendor": row.get("vendor"),
            "model": row.get("model"),
            "version": row.get("version"),
            "success_quality": row.get("success_quality"),
            "probe_readiness": row.get("probe_readiness"),
            "blob_family": row.get("blob_family"),
            "local_path": row.get("local_path"),
            "priority_score": score,
            "priority_reasons": reasons,
        })
    out.sort(key=lambda r: (-int(r["priority_score"]), r["vendor"] or "", r["model"] or "", r["version"] or ""))
    return out


def write_markdown(corpus_rows: list[dict], priority_rows: list[dict], path: str | Path, top: int) -> None:
    sq = Counter(r.get("success_quality") or "missing" for r in corpus_rows)
    pr = Counter(r.get("probe_readiness") or "missing" for r in corpus_rows)
    bf = Counter(r.get("blob_family") or "none" for r in corpus_rows)

    lines = [
        "# Extraction Gap Report",
        "",
        "## Current Counts",
        f"- success_quality: `{dict(sq)}`",
        f"- probe_readiness: `{dict(pr)}`",
        f"- blob_family: `{dict(bf)}`",
        "",
        "## Top Extraction Priorities",
        "",
    ]
    for idx, row in enumerate(priority_rows[:top], 1):
        lines.extend([
            f"### Rank {idx}",
            f"- corpus_id: `{row['corpus_id']}`",
            f"- firmware: `{row['vendor']} {row['model']} {row['version']}`",
            f"- success_quality: `{row['success_quality']}`",
            f"- probe_readiness: `{row['probe_readiness']}`",
            f"- blob_family: `{row['blob_family']}`",
            f"- local_path: `{row['local_path']}`",
            f"- priority_score: `{row['priority_score']}`",
            f"- reasons: `{', '.join(row['priority_reasons'])}`",
            "",
        ])
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--markdown-out", required=True)
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    rows = load_jsonl(args.corpus)
    priority_rows = build_rows(rows)
    write_markdown(rows, priority_rows, args.markdown_out, args.top)
    Path(args.json_out).write_text(json.dumps(priority_rows[: args.top], indent=2), encoding="utf-8")
    print(json.dumps({
        "corpus_rows": len(rows),
        "priority_rows": len(priority_rows),
        "emitted": min(len(priority_rows), args.top),
    }, indent=2))


if __name__ == "__main__":
    main()
