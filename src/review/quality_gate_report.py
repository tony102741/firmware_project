"""
Generate extraction and candidate quality gates from batch results.

The goal is to make FP/FN pressure visible after every regression run:
- extraction false negatives: web-capable/rootfs-looking runs classified too low
- candidate false negatives: rootfs/web runs with no actionable candidate
- FP pressure: high-scoring candidates blocked by evidence gaps or FP risks
- suppressed FP pressure: raw high score retained but evidence-adjusted below gate
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from core.analyzer.evidence_profile import evidence_adjusted_score


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def resolve_path(pathish: str | None) -> Path | None:
    if not pathish:
        return None
    path = Path(pathish)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def load_bundle(row: dict) -> dict:
    path = resolve_path(row.get("results_json"))
    if path and path.is_file():
        return load_json(path)
    return {}


def _candidate_review_state(candidate: dict) -> str:
    profile = candidate.get("evidence_profile") or {}
    return profile.get("review_state") or "unknown"


def _candidate_raw_score(candidate: dict) -> int:
    try:
        return int(candidate.get("triage_score") or candidate.get("score") or 0)
    except (TypeError, ValueError):
        return 0


def _candidate_adjusted_score(candidate: dict) -> int:
    value = candidate.get("evidence_adjusted_score")
    raw_score = _candidate_raw_score(candidate)
    if value is None:
        return evidence_adjusted_score(candidate, raw_score=raw_score)
    try:
        adjusted = int(value)
    except (TypeError, ValueError):
        return evidence_adjusted_score(candidate, raw_score=raw_score)
    if adjusted == 0 and raw_score > 0:
        return evidence_adjusted_score(candidate, raw_score=raw_score)
    return adjusted


def _normalized_success_quality(row: dict) -> str:
    mode = row.get("analysis_mode")
    system_path = str(row.get("analysis_system_path") or "").lower()
    if (
        "/squashfs-root" in system_path
        or "/rootfs" in system_path
        or "/system" in system_path
        or "/_ubi_extract/" in system_path
        or "/_raw_fs" in system_path
        or "/_raw" in system_path
        or "/.cache/rootfs/" in system_path
    ):
        return "rootfs-success"
    return str(row.get("success_quality") or "missing")


def _is_candidate_fn(row: dict, bundle: dict) -> bool:
    analysis = bundle.get("analysis") or {}
    summary = bundle.get("summary") or {}
    if analysis.get("mode") not in {"iot_web", "android"}:
        return False
    if int(summary.get("web_exposed") or 0) > 0:
        return False
    if bundle.get("cve_candidates"):
        return False
    return len(bundle.get("candidates") or []) == 0


def _extraction_fn_reason(row: dict) -> str | None:
    system_path = str(row.get("analysis_system_path") or "").lower()
    mode = row.get("analysis_mode")
    quality = _normalized_success_quality(row)
    if mode in {"iot_web", "android"} and quality != "rootfs-success":
        return "web-analysis-not-rootfs-classified"
    if "/_raw" in system_path and quality != "rootfs-success":
        return "raw-rootfs-path-not-rootfs-classified"
    return None


def build_report(summary: dict) -> dict:
    rows = summary.get("results") or []
    quality_counts = Counter()
    probe_counts = Counter()
    blob_counts = Counter()
    review_states = Counter()
    missing_links = Counter()
    fp_risks = Counter()
    extraction_fns = []
    candidate_fns = []
    fp_pressure = []
    suppressed_fp_pressure = []

    for row in rows:
        quality = _normalized_success_quality(row)
        quality_counts[quality] += 1
        probe_counts[str(row.get("probe_readiness") or "missing")] += 1
        blob_counts[str(row.get("blob_family") or "none")] += 1

        reason = _extraction_fn_reason(row)
        if reason:
            extraction_fns.append({
                "sample": row.get("sample"),
                "corpus_id": row.get("corpus_id"),
                "reason": reason,
                "analysis_mode": row.get("analysis_mode"),
                "success_quality": quality,
                "system_path": row.get("analysis_system_path"),
            })

        bundle = load_bundle(row)
        if _is_candidate_fn(row, bundle):
            candidate_fns.append({
                "sample": row.get("sample"),
                "corpus_id": row.get("corpus_id"),
                "reason": "web/rootfs analysis produced no candidates",
            })

        for cand in bundle.get("candidates") or []:
            state = _candidate_review_state(cand)
            review_states[state] += 1
            for link in cand.get("missing_links") or []:
                missing_links[str(link)] += 1
            for risk in cand.get("false_positive_risks") or []:
                fp_risks[str(risk)] += 1
            raw_score = _candidate_raw_score(cand)
            adjusted_score = _candidate_adjusted_score(cand)
            if raw_score >= 40 and state in {"reject-risk", "needs-evidence"}:
                row_data = {
                    "sample": row.get("sample"),
                    "candidate": cand.get("name"),
                    "score": raw_score,
                    "evidence_adjusted_score": adjusted_score,
                    "review_state": state,
                    "missing_links": cand.get("missing_links") or [],
                    "false_positive_risks": cand.get("false_positive_risks") or [],
                }
                if adjusted_score >= 40:
                    fp_pressure.append(row_data)
                else:
                    suppressed_fp_pressure.append(row_data)

    return {
        "total": len(rows),
        "success_quality_counts": dict(quality_counts),
        "probe_readiness_counts": dict(probe_counts),
        "blob_family_counts": dict(blob_counts),
        "candidate_review_state_counts": dict(review_states),
        "top_missing_links": missing_links.most_common(12),
        "top_false_positive_risks": fp_risks.most_common(12),
        "extraction_false_negatives": extraction_fns,
        "candidate_false_negatives": candidate_fns,
        "fp_pressure": fp_pressure[:50],
        "suppressed_fp_pressure": suppressed_fp_pressure[:50],
        "gate_status": {
            "extraction_fn_count": len(extraction_fns),
            "candidate_fn_count": len(candidate_fns),
            "fp_pressure_count": len(fp_pressure),
            "suppressed_fp_pressure_count": len(suppressed_fp_pressure),
        },
    }


def write_markdown(report: dict, path: str | Path) -> None:
    lines = [
        "# Quality Gate Report",
        "",
        "## Counts",
        f"- total: `{report['total']}`",
        f"- success_quality: `{report['success_quality_counts']}`",
        f"- probe_readiness: `{report['probe_readiness_counts']}`",
        f"- blob_family: `{report['blob_family_counts']}`",
        f"- candidate_review_state: `{report['candidate_review_state_counts']}`",
        "",
        "## Gates",
        f"- extraction false negatives: `{report['gate_status']['extraction_fn_count']}`",
        f"- candidate false negatives: `{report['gate_status']['candidate_fn_count']}`",
        f"- FP pressure candidates: `{report['gate_status']['fp_pressure_count']}`",
        f"- suppressed FP pressure candidates: `{report['gate_status']['suppressed_fp_pressure_count']}`",
        "",
        "## Top Missing Links",
        *[f"- `{name}`: `{count}`" for name, count in report["top_missing_links"]],
        "",
        "## Top False Positive Risks",
        *[f"- `{name}`: `{count}`" for name, count in report["top_false_positive_risks"]],
        "",
        "## Extraction False Negatives",
    ]
    if not report["extraction_false_negatives"]:
        lines.append("(none)")
    for row in report["extraction_false_negatives"][:20]:
        lines.append(f"- `{row['sample']}`: `{row['reason']}` / `{row['success_quality']}`")

    lines.extend(["", "## Candidate False Negatives"])
    if not report["candidate_false_negatives"]:
        lines.append("(none)")
    for row in report["candidate_false_negatives"][:20]:
        lines.append(f"- `{row['sample']}`: `{row['reason']}`")

    lines.extend(["", "## FP Pressure"])
    if not report["fp_pressure"]:
        lines.append("(none)")
    for row in report["fp_pressure"][:20]:
        lines.append(
            f"- `{row['sample']} / {row['candidate']}`: "
            f"score=`{row['score']}`, adjusted=`{row['evidence_adjusted_score']}`, "
            f"state=`{row['review_state']}`"
        )

    lines.extend(["", "## Suppressed FP Pressure"])
    if not report["suppressed_fp_pressure"]:
        lines.append("(none)")
    for row in report["suppressed_fp_pressure"][:20]:
        lines.append(
            f"- `{row['sample']} / {row['candidate']}`: "
            f"score=`{row['score']}`, adjusted=`{row['evidence_adjusted_score']}`, "
            f"state=`{row['review_state']}`"
        )

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-summary", required=True)
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--markdown-out", required=True)
    args = ap.parse_args()

    report = build_report(load_json(args.batch_summary))
    Path(args.json_out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(report, args.markdown_out)
    print(json.dumps(report["gate_status"], indent=2))


if __name__ == "__main__":
    main()
