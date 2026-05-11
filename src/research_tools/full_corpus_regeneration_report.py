"""
Generate reproducibility-oriented reports for a fresh full-corpus regeneration.

Usage:
  python3 src/research_tools/full_corpus_regeneration_report.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --batch-summary research/regeneration/full_corpus_20260508/batch_regression_summary.json \
      --workspace-root research/regeneration/full_corpus_20260508
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_ARTIFACT_FIELDS = [
    "target_metadata",
    "architecture_profile",
    "management_inventory",
    "service_topology",
    "config_backend",
    "helper_script_inventory",
    "filesystem_inventory",
    "command_materialization_features",
    "execution_wrapper_features",
    "extraction_quality_flags",
    "extraction_evidence",
]


def load_json(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str | Path):
    p = Path(path)
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_md(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def iter_results(root: Path):
    for path in sorted((root / "runs").glob("**/results.json")):
        try:
            yield path, load_json(path)
        except Exception:
            continue


def load_fresh_index(workspace_root: Path) -> dict[str, dict]:
    out = {}
    for path, bundle in iter_results(workspace_root):
        corpus_id = str((bundle.get("target_metadata") or {}).get("corpus_id") or "").strip()
        if corpus_id:
            out[corpus_id] = {"path": path, "bundle": bundle}
    return out


def load_legacy_index(exclude_root: Path | None = None) -> dict[str, list[dict]]:
    out = defaultdict(list)
    for path in sorted((PROJECT_ROOT / "runs").glob("**/results.json")):
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path
        if exclude_root and exclude_root.resolve() in resolved.parents:
            continue
        try:
            bundle = load_json(path)
        except Exception:
            continue
        corpus_id = str((bundle.get("target_metadata") or {}).get("corpus_id") or "").strip()
        if corpus_id:
            out[corpus_id].append({"path": path, "bundle": bundle})
    return out


def _artifact_completeness(bundle: dict) -> tuple[int, list[str]]:
    present = []
    for field in REQUIRED_ARTIFACT_FIELDS:
        if bundle.get(field):
            present.append(field)
    return len(present), present


def _rootfs_retained(bundle: dict) -> bool:
    flags = bundle.get("extraction_quality_flags") or {}
    return bool(flags.get("rootfs_recovered"))


def _arch_profile(bundle: dict) -> dict:
    return bundle.get("architecture_profile") or {}


def _target(bundle: dict) -> dict:
    return bundle.get("target_metadata") or {}


def _firmware_label(bundle: dict) -> str:
    target = _target(bundle)
    return f"{target.get('vendor') or '?'} {target.get('model') or '?'} {target.get('version') or '?'}"


def _status_row(batch_summary: dict) -> dict[str, dict]:
    by_id = {}
    for row in batch_summary.get("results") or []:
        corpus_id = str(row.get("corpus_id") or "").strip()
        if corpus_id:
            by_id[corpus_id] = row
    return by_id


def _subset_class(bundle: dict, batch_row: dict | None) -> str:
    target = _target(bundle)
    profile = _arch_profile(bundle)
    completeness_count, _ = _artifact_completeness(bundle)
    if not target or not batch_row or batch_row.get("status") != "SUCCESS":
        return "unstable-excluded"
    if (
        completeness_count == len(REQUIRED_ARTIFACT_FIELDS)
        and _rootfs_retained(bundle)
        and profile.get("architecture_family") not in {"opaque-or-partial", ""}
        and target.get("vendor") not in {"UNKNOWN", ""}
    ):
        return "reproducible-high-confidence"
    if completeness_count >= 7 and batch_row.get("status") == "SUCCESS":
        return "partial-confidence"
    return "unstable-excluded"


def _cluster_rows(fresh_index: dict[str, dict]) -> dict[str, list[dict]]:
    by_fp = defaultdict(list)
    for corpus_id, row in fresh_index.items():
        bundle = row["bundle"]
        fp = str(_arch_profile(bundle).get("architecture_fingerprint") or "")
        by_fp[fp].append(row)
    return by_fp


def build_reports(corpus_rows: list[dict], batch_summary: dict, workspace_root: Path) -> dict[str, list[str]]:
    fresh_index = load_fresh_index(workspace_root)
    legacy_index = load_legacy_index(exclude_root=workspace_root)
    batch_by_id = _status_row(batch_summary)
    fresh_bundle_count = sum(1 for _ in iter_results(workspace_root))
    duplicate_unique_gap = fresh_bundle_count - len(fresh_index)

    subset_counts = Counter()
    completeness = Counter()
    family_counts = Counter()
    rootfs_retained = 0
    emitted_complete = 0
    drift_rows = []
    degraded_legacy = []
    excluded = []

    for corpus_id, row in fresh_index.items():
        bundle = row["bundle"]
        batch_row = batch_by_id.get(corpus_id)
        subset = _subset_class(bundle, batch_row)
        subset_counts[subset] += 1
        complete_count, present_fields = _artifact_completeness(bundle)
        completeness[complete_count] += 1
        profile = _arch_profile(bundle)
        family_counts[str(profile.get("architecture_family") or "unknown")] += 1
        if _rootfs_retained(bundle):
            rootfs_retained += 1
        if complete_count == len(REQUIRED_ARTIFACT_FIELDS):
            emitted_complete += 1

        legacy_rows = legacy_index.get(corpus_id) or []
        if legacy_rows:
            legacy = sorted(legacy_rows, key=lambda x: str(x["path"]))[-1]["bundle"]
            fresh_fp = str(profile.get("architecture_fingerprint") or "")
            legacy_fp = str((_arch_profile(legacy)).get("architecture_fingerprint") or "")
            fresh_family = str(profile.get("architecture_family") or "")
            legacy_family = str((_arch_profile(legacy)).get("architecture_family") or "")
            legacy_rootfs = _rootfs_retained(legacy)
            if not legacy_rootfs:
                degraded_legacy.append({
                    "firmware": _firmware_label(bundle),
                    "corpus_id": corpus_id,
                    "fresh_family": fresh_family,
                    "legacy_family": legacy_family,
                    "fresh_fp": fresh_fp,
                    "legacy_fp": legacy_fp,
                })
            elif fresh_fp != legacy_fp or fresh_family != legacy_family:
                drift_rows.append({
                    "firmware": _firmware_label(bundle),
                    "corpus_id": corpus_id,
                    "fresh_family": fresh_family,
                    "legacy_family": legacy_family,
                    "fresh_fp": fresh_fp,
                    "legacy_fp": legacy_fp,
                })
        if subset == "unstable-excluded":
            excluded.append({
                "firmware": _firmware_label(bundle),
                "corpus_id": corpus_id,
                "family": profile.get("architecture_family") or "unknown",
                "batch_status": (batch_row or {}).get("status"),
                "quality": (batch_row or {}).get("success_quality"),
            })

    fresh_cluster_rows = _cluster_rows(fresh_index)
    unstable_clusters = []
    for fp, rows in fresh_cluster_rows.items():
        families = {str(_arch_profile(x["bundle"]).get("architecture_family") or "unknown") for x in rows}
        if len(families) > 1:
            unstable_clusters.append({"fingerprint": fp, "families": sorted(families), "count": len(rows)})

    batch_results = batch_summary.get("results") or []
    success_counts = Counter(str(row.get("success_quality") or "missing") for row in batch_results)
    status_counts = Counter(str(row.get("status") or "missing") for row in batch_results)
    drift_lines = [
        f"- `{row['firmware']}` / fresh=`{row['fresh_family']}` `{row['fresh_fp']}` / legacy=`{row['legacy_family']}` `{row['legacy_fp']}`"
        for row in drift_rows[:50]
    ] or ["- `(none)`"]
    degraded_lines = [
        f"- `{row['firmware']}` / fresh=`{row['fresh_family']}` / legacy=`{row['legacy_family']}`"
        for row in degraded_legacy[:50]
    ] or ["- `(none)`"]
    excluded_lines = [
        f"- `{row['firmware']}` / status=`{row['batch_status']}` / quality=`{row['quality']}` / family=`{row['family']}`"
        for row in excluded[:50]
    ] or ["- `(none)`"]

    reports = {}
    reports["full_corpus_regeneration_report.md"] = [
        "# Full Corpus Regeneration Report",
        "",
        f"- corpus rows targeted: `{len(corpus_rows)}`",
        f"- batch rows completed: `{len(batch_results)}`",
        f"- fresh results bundles discovered: `{fresh_bundle_count}`",
        f"- unique corpus_ids in fresh rerun: `{len(fresh_index)}`",
        f"- duplicate bundle gap (same corpus_id repeated): `{duplicate_unique_gap}`",
        f"- status counts: `{dict(status_counts)}`",
        f"- success quality counts: `{dict(success_counts)}`",
        f"- architecture families in fresh rerun: `{dict(family_counts)}`",
        f"- emitted-complete bundles: `{emitted_complete}`",
        f"- rootfs-retained fresh bundles: `{rootfs_retained}`",
    ]
    reports["rerun_stability_validation.md"] = [
        "# Rerun Stability Validation",
        "",
        f"- fresh bundles compared against legacy corpus: `{len(fresh_index)}`",
        f"- fingerprint drift rows: `{len(drift_rows)}`",
        f"- degraded legacy bundles: `{len(degraded_legacy)}`",
        "- Fingerprint drift is counted only when both fresh and legacy bundles preserve rootfs-observable state.",
        "",
        "## Drift Rows",
        *drift_lines,
    ]
    reports["architecture_cluster_consistency.md"] = [
        "# Architecture Cluster Consistency",
        "",
        f"- fresh architecture fingerprints: `{len(fresh_cluster_rows)}`",
        f"- unstable fingerprint groups: `{len(unstable_clusters)}`",
        "",
        "## Largest Fresh Clusters",
        *[
            f"- `{fp}`: `count={len(rows)}` family=`{_arch_profile(rows[0]['bundle']).get('architecture_family')}`"
            for fp, rows in sorted(fresh_cluster_rows.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:20]
        ],
    ]
    reports["rootfs_retention_impact.md"] = [
        "# Rootfs Retention Impact",
        "",
        f"- fresh rootfs-retained bundles: `{rootfs_retained}/{len(fresh_index)}`",
        f"- degraded legacy bundles lacking preserved rootfs: `{len(degraded_legacy)}`",
        "- Degraded legacy bundles are excluded from prevalence or lineage claims even if they carry migrated architecture fields.",
        "",
        "## Degraded Legacy Bundles",
        *degraded_lines,
    ]
    reports["paper_grade_subset_definition.md"] = [
        "# Paper Grade Subset Definition",
        "",
        f"- subset counts: `{dict(subset_counts)}`",
        "",
        "## Reproducible High-Confidence",
        "- requires SUCCESS batch status",
        "- requires all required emitted artifact fields",
        "- requires preserved rootfs visibility",
        "- excludes `opaque-or-partial` families",
        "- excludes `UNKNOWN` normalized vendors",
        "",
        "## Partial-Confidence",
        "- emitted artifact coverage is substantial but rootfs visibility or family specificity is weaker",
        "",
        "## Unstable / Excluded",
        "- failed or blocked reruns",
        "- degraded or incomplete emitted artifact coverage",
        "- architecture families or fingerprints not supportable without preserved evidence",
        "",
        "## Excluded Targets",
        *excluded_lines,
    ]
    return reports


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--batch-summary", required=True)
    ap.add_argument("--workspace-root", required=True)
    args = ap.parse_args()

    corpus_rows = load_jsonl(args.corpus)
    batch_summary = load_json(args.batch_summary)
    workspace_root = Path(args.workspace_root)

    reports = build_reports(corpus_rows, batch_summary, workspace_root)
    for name, lines in reports.items():
        write_md(workspace_root / name, lines)
    print(json.dumps({"reports_written": sorted(reports), "workspace_root": str(workspace_root)}, indent=2))


if __name__ == "__main__":
    main()
