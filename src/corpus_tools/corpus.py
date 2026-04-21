"""
Helper for validating and summarizing firmware corpus inventory files.

Usage:
  python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl
  python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl --pretty
"""

import argparse
import json
import os
import sys
from collections import Counter


REQUIRED_FIELDS = {
    "corpus_id",
    "vendor",
    "model",
    "version",
    "local_filename",
    "local_path",
    "input_type",
    "product_class",
    "web_ui_expected",
    "extraction_status",
    "analysis_status",
}

EXTRACTION_STATUSES = {"PENDING", "SUCCESS", "PARTIAL", "FAILED"}
ANALYSIS_STATUSES = {"PENDING", "COMPLETED", "REVIEWED", "BLOCKED"}
REGRESSION_STATUSES = {"SUCCESS", "PARTIAL", "BLOCKED", "BUG", "SKIPPED"}
SUCCESS_QUALITIES = {"rootfs-success", "fallback-success", "blob-success"}
PROBE_READINESS = {
    "rootfs-ready",
    "fallback-ready",
    "blob-ready",
    "bundle-probe-ready",
    "decrypt-probe-ready",
    "scan-probe-ready",
}
BLOB_FAMILIES = {
    "tp-link-segmented-bundle",
    "mercusys-cloud-container",
    "tenda-openssl-container",
    "generic-container",
    "generic-blob-signal",
}


def _missing(required, obj):
    return sorted(k for k in required if k not in obj)


def validate_entry(entry, line_no):
    errors = []

    missing = _missing(REQUIRED_FIELDS, entry)
    if missing:
        errors.append(f"line {line_no}: missing fields: {', '.join(missing)}")
        return errors

    extraction_status = entry.get("extraction_status")
    analysis_status = entry.get("analysis_status")

    if extraction_status not in EXTRACTION_STATUSES:
        errors.append(
            f"line {line_no}: invalid extraction_status: {extraction_status!r}"
        )
    if analysis_status not in ANALYSIS_STATUSES:
        errors.append(
            f"line {line_no}: invalid analysis_status: {analysis_status!r}"
        )

    regression_status = entry.get("regression_status")
    if regression_status is not None and regression_status not in REGRESSION_STATUSES:
        errors.append(
            f"line {line_no}: invalid regression_status: {regression_status!r}"
        )

    success_quality = entry.get("success_quality")
    if success_quality is not None and success_quality not in SUCCESS_QUALITIES:
        errors.append(
            f"line {line_no}: invalid success_quality: {success_quality!r}"
        )
    probe_readiness = entry.get("probe_readiness")
    if probe_readiness is not None and probe_readiness not in PROBE_READINESS:
        errors.append(
            f"line {line_no}: invalid probe_readiness: {probe_readiness!r}"
        )
    blob_family = entry.get("blob_family")
    if blob_family is not None and blob_family not in BLOB_FAMILIES:
        errors.append(
            f"line {line_no}: invalid blob_family: {blob_family!r}"
        )

    local_path = entry.get("local_path")
    if local_path and not isinstance(local_path, str):
        errors.append(f"line {line_no}: local_path must be a string")

    suspected_stack = entry.get("suspected_stack")
    if suspected_stack is not None and not isinstance(suspected_stack, list):
        errors.append(f"line {line_no}: suspected_stack must be a list")

    web_surface_detected = entry.get("web_surface_detected")
    if web_surface_detected not in (True, False, None):
        errors.append(f"line {line_no}: web_surface_detected must be true, false, or null")

    if extraction_status == "SUCCESS" and analysis_status == "PENDING":
        errors.append(
            f"line {line_no}: analysis_status should not remain PENDING after successful extraction if the sample has already been run"
        )

    return errors


def load_jsonl(path):
    entries = []
    errors = []
    with open(path, "r", encoding="utf-8") as fh:
        for idx, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                errors.append(f"line {idx}: invalid JSON: {exc}")
                continue
            entries.append(entry)
            errors.extend(validate_entry(entry, idx))
    return entries, errors


def print_summary(entries):
    vendors = Counter(e.get("vendor", "?") for e in entries)
    input_types = Counter(e.get("input_type", "?") for e in entries)
    product_classes = Counter(e.get("product_class", "?") for e in entries)
    extraction_statuses = Counter(e.get("extraction_status", "?") for e in entries)
    analysis_statuses = Counter(e.get("analysis_status", "?") for e in entries)
    web_expected = Counter(str(e.get("web_ui_expected", "?")).lower() for e in entries)
    web_detected = Counter(str(e.get("web_surface_detected", "?")).lower() for e in entries)
    success_qualities = Counter(str(e.get("success_quality", "?")).lower() for e in entries)
    probe_readiness = Counter(str(e.get("probe_readiness", "?")).lower() for e in entries)
    blob_families = Counter(str(e.get("blob_family", "?")).lower() for e in entries)

    print(f"entries: {len(entries)}")
    print(f"vendors: {dict(sorted(vendors.items()))}")
    print(f"input_types: {dict(sorted(input_types.items()))}")
    print(f"product_classes: {dict(sorted(product_classes.items()))}")
    print(f"extraction_statuses: {dict(sorted(extraction_statuses.items()))}")
    print(f"analysis_statuses: {dict(sorted(analysis_statuses.items()))}")
    print(f"success_qualities: {dict(sorted(success_qualities.items()))}")
    print(f"probe_readiness: {dict(sorted(probe_readiness.items()))}")
    print(f"blob_families: {dict(sorted(blob_families.items()))}")
    print(f"web_ui_expected: {dict(sorted(web_expected.items()))}")
    print(f"web_surface_detected: {dict(sorted(web_detected.items()))}")


def print_pretty(entries):
    for idx, entry in enumerate(entries, 1):
        if idx > 1:
            print()
        print(f"entry {idx}:")
        print(json.dumps(entry, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(
        description="Validate, summarize, or pretty-print firmware corpus inventory files."
    )
    parser.add_argument("path", help="Path to the corpus inventory file (JSONL).")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print each corpus entry after the summary.",
    )
    args = parser.parse_args()

    path = args.path
    if not os.path.isfile(path):
        print(f"not found: {path}", file=sys.stderr)
        sys.exit(1)

    entries, errors = load_jsonl(path)
    print_summary(entries)
    if args.pretty and entries:
        print()
        print_pretty(entries)
    if errors:
        print("\nvalidation errors:")
        for err in errors:
            print(f"- {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
