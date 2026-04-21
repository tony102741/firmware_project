"""
Generate a compact research progress report from the corpus inventory and a
candidate ledger set.

Usage:
  python3 src/research_tools/research_report.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --ledger research/ledgers/totolink_a3002ru_initial.jsonl.json

  python3 src/research_tools/research_report.py \
      --corpus research/corpus/firmware_corpus.jsonl \
      --ledger research/vendor_a.jsonl \
      --ledger research/vendor_b.jsonl

  python3 src/research_tools/research_report.py --corpus research/corpus/firmware_corpus.jsonl
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_jsonl(path):
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for idx, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entries.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: line {idx}: invalid JSON: {exc}") from exc
    return entries


def discover_ledgers(corpus_path):
    research_dir = Path(corpus_path).resolve().parent
    discovered = []
    for path in sorted(research_dir.iterdir()):
        if not path.is_file():
            continue
        if path.name in {
            "candidate_ledger.template.jsonl",
            "firmware_corpus.jsonl",
            "firmware_corpus.template.jsonl",
        }:
            continue
        if not any(
            path.name.endswith(ext) for ext in (".jsonl", ".jsonl.json")
        ):
            continue
        discovered.append(str(path))
    return discovered


def _sorted_counter(counter_obj):
    return dict(sorted(counter_obj.items()))


def _print_mapping(title, mapping):
    print(f"{title}: {dict(sorted(mapping.items()))}")


def summarize_corpus(corpus_entries):
    vendors = Counter()
    extraction_statuses = Counter()
    analysis_statuses = Counter()
    product_classes = Counter()
    by_vendor = defaultdict(lambda: {
        "samples": 0,
        "extraction_success": 0,
        "analysis_completed": 0,
    })

    for entry in corpus_entries:
        vendor = entry.get("vendor", "?")
        vendors[vendor] += 1
        extraction_status = entry.get("extraction_status", "?")
        analysis_status = entry.get("analysis_status", "?")
        product_class = entry.get("product_class", "?")

        extraction_statuses[extraction_status] += 1
        analysis_statuses[analysis_status] += 1
        product_classes[product_class] += 1

        by_vendor[vendor]["samples"] += 1
        if extraction_status == "SUCCESS":
            by_vendor[vendor]["extraction_success"] += 1
        if analysis_status in ("COMPLETED", "REVIEWED"):
            by_vendor[vendor]["analysis_completed"] += 1

    return {
        "entries": len(corpus_entries),
        "vendors": vendors,
        "extraction_statuses": extraction_statuses,
        "analysis_statuses": analysis_statuses,
        "product_classes": product_classes,
        "by_vendor": by_vendor,
    }


def summarize_ledger(ledger_entries):
    verdicts = Counter()
    confidences = Counter()
    patterns = Counter()
    ledger_sources = Counter()
    by_vendor = defaultdict(lambda: {
        "candidates": 0,
        "confirmed": 0,
        "likely": 0,
        "needs_more_work": 0,
        "rejected": 0,
    })
    by_model = defaultdict(lambda: {
        "vendor": "?",
        "candidates": 0,
        "confirmed": 0,
        "likely": 0,
        "needs_more_work": 0,
        "rejected": 0,
    })

    for entry in ledger_entries:
        firmware = entry.get("firmware", {})
        review = entry.get("review", {})
        pattern = entry.get("pattern", {})

        vendor = firmware.get("vendor", "?")
        model = firmware.get("model", "?")
        verdict = review.get("verdict", "?")
        confidence = review.get("confidence", "?")
        primary = pattern.get("primary", "?")
        source_path = entry.get("_source_path", "?")
        model_key = f"{vendor} :: {model}"

        verdicts[verdict] += 1
        confidences[confidence] += 1
        patterns[primary] += 1
        ledger_sources[source_path] += 1

        by_vendor[vendor]["candidates"] += 1
        by_model[model_key]["vendor"] = vendor
        by_model[model_key]["candidates"] += 1
        if verdict == "CONFIRMED":
            by_vendor[vendor]["confirmed"] += 1
            by_model[model_key]["confirmed"] += 1
        elif verdict == "LIKELY":
            by_vendor[vendor]["likely"] += 1
            by_model[model_key]["likely"] += 1
        elif verdict == "NEEDS_MORE_WORK":
            by_vendor[vendor]["needs_more_work"] += 1
            by_model[model_key]["needs_more_work"] += 1
        elif verdict == "REJECTED":
            by_vendor[vendor]["rejected"] += 1
            by_model[model_key]["rejected"] += 1

    return {
        "entries": len(ledger_entries),
        "verdicts": verdicts,
        "confidences": confidences,
        "patterns": patterns,
        "ledger_sources": ledger_sources,
        "by_vendor": by_vendor,
        "by_model": by_model,
    }


def print_report(corpus_summary, ledger_summary, ledger_paths):
    print("== Corpus Summary ==")
    print(f"entries: {corpus_summary['entries']}")
    print(f"vendors: {_sorted_counter(corpus_summary['vendors'])}")
    print(f"product_classes: {_sorted_counter(corpus_summary['product_classes'])}")
    print(f"extraction_statuses: {_sorted_counter(corpus_summary['extraction_statuses'])}")
    print(f"analysis_statuses: {_sorted_counter(corpus_summary['analysis_statuses'])}")
    print()

    print("== Ledger Summary ==")
    print(f"entries: {ledger_summary['entries']}")
    print(f"ledger_files: {len(ledger_paths)}")
    print(f"verdicts: {_sorted_counter(ledger_summary['verdicts'])}")
    print(f"confidences: {_sorted_counter(ledger_summary['confidences'])}")
    print(f"patterns: {_sorted_counter(ledger_summary['patterns'])}")
    print(f"ledger_sources: {_sorted_counter(ledger_summary['ledger_sources'])}")
    print()

    print("== Vendor Progress ==")
    vendor_names = sorted(
        set(corpus_summary["by_vendor"].keys()) | set(ledger_summary["by_vendor"].keys())
    )
    for vendor in vendor_names:
        corpus = corpus_summary["by_vendor"].get(vendor, {})
        ledger = ledger_summary["by_vendor"].get(vendor, {})
        print(
            f"{vendor}: "
            f"samples={corpus.get('samples', 0)} "
            f"extract_ok={corpus.get('extraction_success', 0)} "
            f"analyzed={corpus.get('analysis_completed', 0)} "
            f"candidates={ledger.get('candidates', 0)} "
            f"confirmed={ledger.get('confirmed', 0)} "
            f"likely={ledger.get('likely', 0)} "
            f"needs_more_work={ledger.get('needs_more_work', 0)} "
            f"rejected={ledger.get('rejected', 0)}"
        )

    print()
    print("== Model Progress ==")
    for model_key in sorted(ledger_summary["by_model"].keys()):
        row = ledger_summary["by_model"][model_key]
        print(
            f"{model_key}: "
            f"candidates={row.get('candidates', 0)} "
            f"confirmed={row.get('confirmed', 0)} "
            f"likely={row.get('likely', 0)} "
            f"needs_more_work={row.get('needs_more_work', 0)} "
            f"rejected={row.get('rejected', 0)}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Generate a compact research progress report from corpus and ledger files."
    )
    parser.add_argument(
        "--corpus",
        required=True,
        help="Path to the firmware corpus inventory JSONL file.",
    )
    parser.add_argument(
        "--ledger",
        action="append",
        default=[],
        help="Path to a candidate ledger JSONL file. Can be repeated. If omitted, ledger files are auto-discovered under the corpus directory.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.corpus):
        print(f"not found: {args.corpus}", file=sys.stderr)
        sys.exit(1)
    ledger_paths = args.ledger or discover_ledgers(args.corpus)
    if not ledger_paths:
        print("no ledger files found", file=sys.stderr)
        sys.exit(1)
    for ledger_path in ledger_paths:
        if not os.path.isfile(ledger_path):
            print(f"not found: {ledger_path}", file=sys.stderr)
            sys.exit(1)

    try:
        corpus_entries = load_jsonl(args.corpus)
        ledger_entries = []
        for ledger_path in ledger_paths:
            for entry in load_jsonl(ledger_path):
                entry["_source_path"] = ledger_path
                ledger_entries.append(entry)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    corpus_summary = summarize_corpus(corpus_entries)
    ledger_summary = summarize_ledger(ledger_entries)
    print_report(corpus_summary, ledger_summary, ledger_paths)


if __name__ == "__main__":
    main()
