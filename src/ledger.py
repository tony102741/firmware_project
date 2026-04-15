"""
Helper for validating and summarizing firmware candidate ledger files.

Usage:
  python3 src/ledger.py research/my_ledger.jsonl
  python3 src/ledger.py research/my_ledger.jsonl --pretty
"""

import argparse
import json
import os
import sys
from collections import Counter


REQUIRED_TOP = {"entry_id", "firmware", "candidate", "review", "pattern"}
REQUIRED_FIRMWARE = {"vendor", "model", "version"}
REQUIRED_CANDIDATE = {"name", "entry_point", "input", "processing_chain", "sink"}
REQUIRED_REVIEW = {"verdict", "confidence", "cve_potential"}
REQUIRED_PATTERN = {"primary"}


def _missing(required, obj):
    return sorted(k for k in required if k not in obj)


def validate_entry(entry, line_no):
    errors = []
    top_missing = _missing(REQUIRED_TOP, entry)
    if top_missing:
        errors.append(f"line {line_no}: missing top-level fields: {', '.join(top_missing)}")
        return errors

    fw = entry.get("firmware", {})
    cand = entry.get("candidate", {})
    rev = entry.get("review", {})
    pat = entry.get("pattern", {})

    for label, required, obj in (
        ("firmware", REQUIRED_FIRMWARE, fw),
        ("candidate", REQUIRED_CANDIDATE, cand),
        ("review", REQUIRED_REVIEW, rev),
        ("pattern", REQUIRED_PATTERN, pat),
    ):
        missing = _missing(required, obj)
        if missing:
            errors.append(f"line {line_no}: missing {label} fields: {', '.join(missing)}")

    chain = cand.get("processing_chain")
    if chain is not None and not isinstance(chain, list):
        errors.append(f"line {line_no}: candidate.processing_chain must be a list")

    verdict = rev.get("verdict")
    if verdict == "REJECTED" and not rev.get("reject_reason"):
        errors.append(f"line {line_no}: rejected entry should include review.reject_reason")
    if verdict in ("CONFIRMED", "LIKELY") and not rev.get("accept_reason"):
        errors.append(f"line {line_no}: accepted entry should include review.accept_reason")
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
    verdicts = Counter(e.get("review", {}).get("verdict", "?") for e in entries)
    confidences = Counter(e.get("review", {}).get("confidence", "?") for e in entries)
    patterns = Counter(e.get("pattern", {}).get("primary", "?") for e in entries)
    vendors = Counter(e.get("firmware", {}).get("vendor", "?") for e in entries)

    print(f"entries: {len(entries)}")
    print(f"verdicts: {dict(sorted(verdicts.items()))}")
    print(f"confidences: {dict(sorted(confidences.items()))}")
    print(f"patterns: {dict(sorted(patterns.items()))}")
    print(f"vendors: {dict(sorted(vendors.items()))}")


def print_pretty(entries):
    for idx, entry in enumerate(entries, 1):
        if idx > 1:
            print()
        print(f"entry {idx}:")
        print(json.dumps(entry, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(
        description="Validate, summarize, or pretty-print firmware candidate ledger files."
    )
    parser.add_argument("path", help="Path to the ledger file (JSONL).")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print each ledger entry after the summary.",
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
