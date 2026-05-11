"""
Backfill first-class architecture metadata into existing results.json bundles.

Usage:
  python3 src/research_tools/backfill_architecture_artifacts.py --batch-summary runs/regression/batch_regression_summary_may7.json
  python3 src/research_tools/backfill_architecture_artifacts.py --results runs/.../results.json /tmp/.../results.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from architecture_metadata import (
    SCHEMA_VERSION,
    collect_architecture_artifacts,
    normalize_target_metadata,
)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def resolve_analysis_path(results_path: Path, raw_path: str | None) -> str:
    if not raw_path:
        return ""
    raw = Path(str(raw_path))
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.append((results_path.parent / raw).resolve())
        candidates.append((Path.cwd() / raw).resolve())
        candidates.append((Path("/") / raw).resolve())
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0]) if candidates else ""


def iter_results_paths(args) -> list[Path]:
    paths = []
    for raw in args.results or []:
        p = Path(raw)
        if p.is_file():
            paths.append(p)
    if args.batch_summary:
        batch = load_json(Path(args.batch_summary))
        for row in batch.get("results") or []:
            raw = row.get("results_json")
            if raw:
                p = Path(raw)
                if p.is_file():
                    paths.append(p)
    runs_root = Path(args.runs_root)
    if runs_root.exists():
        paths.extend(sorted(runs_root.rglob("results.json")))
    deduped = []
    seen = set()
    for path in paths:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-summary")
    ap.add_argument("--results", nargs="*")
    ap.add_argument("--runs-root", default="runs")
    args = ap.parse_args()

    results_paths = iter_results_paths(args)
    updated = 0
    for path in results_paths:
        bundle = load_json(path)
        input_obj = bundle.get("input") or {}
        original_path = ((input_obj.get("original") or {}).get("path")) or ""
        resolved_path = ((input_obj.get("resolved") or {}).get("path")) or ""
        analysis = bundle.get("analysis") or {}
        system_path = resolve_analysis_path(path, analysis.get("system_path"))
        vendor_path = resolve_analysis_path(path, analysis.get("vendor_path"))
        target_metadata = normalize_target_metadata(
            resolved_path or original_path,
            original_input_path=original_path or None,
            input_type=((input_obj.get("resolved") or {}).get("type")) or ((input_obj.get("original") or {}).get("type")),
            run_id=bundle.get("run_id"),
        )
        artifacts = collect_architecture_artifacts(
            system_path,
            vendor_path=vendor_path,
            candidates=bundle.get("candidates") or [],
            analysis_reason=analysis.get("reason"),
            target_metadata=target_metadata,
        )
        bundle["artifact_schema_version"] = SCHEMA_VERSION
        for key, value in artifacts.items():
            bundle[key] = value
        save_json(path, bundle)
        updated += 1
    print(json.dumps({"updated_results": updated, "schema_version": SCHEMA_VERSION}, indent=2))


if __name__ == "__main__":
    main()
