# Firmware Corpus Metadata Fields

Use `firmware_corpus.template.jsonl` as the tracking file for collected firmware images.
Use `firmware_corpus.jsonl` as the live inventory file.

This file is not for vulnerability candidates.
It is for corpus-level benchmark management.

## Recommended Workflow

1. Add one JSON object per collected firmware image.
2. Fill basic collection metadata when you download the file.
3. Update extraction and analysis status after each pipeline run.
4. Keep failed samples too.
5. Do not remove old versions when you add newer ones.

## Field Guide

- `corpus_id`
  Stable identifier for the firmware sample.
  Recommended format: `vendor-model-version`.

- `vendor`
  Vendor name, normalized consistently across the corpus.

- `model`
  Product model name.

- `version`
  Firmware version string as published by the vendor.

- `release_date`
  Optional vendor release date in `YYYY-MM-DD` format when known.

- `local_filename`
  Original local filename kept under `inputs/`.

- `local_path`
  Local repository-relative path to the input file.

- `source_url`
  Direct download URL if you have it.

- `source_page`
  Download center or support page URL when the direct URL is unstable.

- `input_type`
  Expected pipeline input type such as `zip`, `rar`, `img`, `iot`, or `unknown`.

- `product_class`
  Broad device category such as `router`, `mesh`, `repeater`, `camera`, or `iot`.

- `web_ui_expected`
  Set to `true` if the product is expected to expose a web management interface.

- `extraction_status`
  One of:
  - `PENDING`
  - `SUCCESS`
  - `PARTIAL`
  - `FAILED`

- `analysis_status`
  One of:
  - `PENDING`
  - `COMPLETED`
  - `REVIEWED`
  - `BLOCKED`

- `run_id`
  Most relevant pipeline run id for this firmware.

- `web_surface_detected`
  `true`, `false`, or `null` if not checked yet.

- `suspected_stack`
  Array of important web stack markers or handler hints, such as:
  - `boa`
  - `goform`
  - `boafrm`
  - `luci`
  - `uhttpd`
  - `lighttpd`

- `arch`
  Architecture string if known, such as `mips`, `arm`, or `aarch64`.

- `notes`
  Free-form notes about extraction quirks, failed stages, or why the sample matters.

## Why Keep This File

This file lets you answer:

- how many samples you actually collected
- which vendors and versions are represented
- which samples extract successfully
- which samples are pending review
- which formats waste the most time

That makes it useful for both:

- day-to-day benchmarking
- paper methodology and experiment description

## Tooling

Validate and summarize the live corpus file with:

```bash
python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl
python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl --pretty
```

Append newly downloaded files from `inputs/` into the live corpus with
best-effort filename inference:

```bash
python3 src/corpus_tools/corpus_sync.py
python3 src/corpus_tools/corpus_sync.py --write
```

Combine corpus and candidate-ledger progress with:

```bash
python3 src/research_tools/research_report.py --corpus research/corpus/firmware_corpus.jsonl

python3 src/research_tools/research_report.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --ledger research/ledgers/totolink_a3002ru_initial.jsonl.json
```

If `--ledger` is omitted, the tool auto-discovers ledger-like files under `research/`.
