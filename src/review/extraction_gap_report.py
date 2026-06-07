"""
Summarize current extraction bottlenecks from firmware_corpus.jsonl.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def classify_fix_lane(row: dict) -> tuple[str, str]:
    """Group extraction gaps by the next engineering fix they need."""
    sq = row.get("success_quality")
    pr = row.get("probe_readiness")
    bf = row.get("blob_family")
    vendor = str(row.get("vendor") or "").lower()
    model = str(row.get("model") or "").lower()

    if sq == "rootfs-success":
        return "rootfs-candidate-quality", "rootfs recovered; improve entrypoint/candidate evidence"
    if bf == "tenda-openssl-container" or pr == "decrypt-probe-ready":
        return "encrypted-container-decrypt", "decrypt or key-derivation probe needs improvement"
    if bf == "dlink-shrs-container":
        return "dlink-shrs-container", "D-Link SHRS payload is encrypted or obfuscated; identify decrypt/unpack path"
    if bf == "tp-link-segmented-bundle" or pr == "bundle-probe-ready":
        return "segmented-bundle-extract", "segmented/chunked bundle extractor needs improvement"
    if bf == "mercusys-cloud-container":
        return "cloud-container-extract", "cloud container extraction needs deeper payload recovery"
    if pr == "scan-probe-ready" and "d-link" in vendor:
        return "dlink-container-scan", "D-Link generic container scan should be turned into rootfs recovery"
    if pr == "scan-probe-ready":
        return "generic-container-scan", "generic container scan should identify a filesystem payload"
    if sq == "fallback-success" and ("netgear" in vendor or "synology" in vendor):
        return "vendor-fallback-extract", "vendor-specific fallback extractor is missing or incomplete"
    if sq == "fallback-success":
        return "fallback-extract", "fallback analysis needs a format-specific extractor"
    if sq == "blob-success":
        return "opaque-blob-triage", "blob-level evidence exists but no rootfs recovery path is known"
    return "metadata-backfill", "metadata or regression status needs backfill"


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
        fix_lane, fix_reason = classify_fix_lane(row)
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
            "fix_lane": fix_lane,
            "fix_reason": fix_reason,
        })
    out.sort(key=lambda r: (-int(r["priority_score"]), r["fix_lane"], r["vendor"] or "", r["model"] or "", r["version"] or ""))
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
        "## Fix Lanes",
        "",
    ]

    by_lane: dict[str, list[dict]] = defaultdict(list)
    for row in priority_rows:
        by_lane[row["fix_lane"]].append(row)
    lane_rows = sorted(
        by_lane.items(),
        key=lambda item: (-len(item[1]), -max(int(row["priority_score"]) for row in item[1]), item[0]),
    )
    for lane, rows in lane_rows:
        first = rows[0]
        lines.extend([
            f"### {lane}",
            f"- targets: `{len(rows)}`",
            f"- max_priority: `{max(int(row['priority_score']) for row in rows)}`",
            f"- reason: `{first['fix_reason']}`",
            f"- first_target: `{first['vendor']} {first['model']} {first['version']}`",
            f"- first_path: `{first['local_path']}`",
            "",
        ])

    lines.extend([
        "## Top Extraction Priorities",
        "",
    ])
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
            f"- fix_lane: `{row['fix_lane']}`",
            f"- fix_reason: `{row['fix_reason']}`",
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
