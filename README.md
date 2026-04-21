# Firmware Vulnerability Analysis Pipeline

A static analysis pipeline for identifying **potentially exploitable vulnerabilities** in firmware images.

---

## Overview

Traditional static analysis often produces many candidates that are not practically exploitable.

This project focuses on reducing false positives by analyzing:

* Web-exposed components
* Data flow from user input to sensitive functions
* Realistic reachability from external interfaces

---

## Features

### 1. Firmware Extraction

* Android OTA (`.zip`)
* IoT firmware (`.bin`)
* Uses `payload-dumper-go` and `binwalk`

---

### 2. Web Surface Identification

* Detects web entry points:

  * `/www`
  * `/cgi-bin`
* Maps HTTP requests to underlying binaries

---

### 3. Data Flow Analysis

Tracks flow from user input to sensitive functions:

* `system`
* `exec`
* `popen`

---

### 4. Flow Verification

Filters out:

* constant execution
* non-controllable inputs

Keeps only flows where user input reaches a sink.

---

### 5. Reachability Check

Determines:

* whether the path is remotely accessible
* whether authentication is required
* how input is controlled

---

### 6. PoC Generation

Outputs simple request examples when applicable:

```bash
curl "http://target/cgi-bin/xxx?cmd=id"
```

---

## Pipeline

```
Firmware
 → Extraction
 → Web surface analysis
 → Data flow tracking
 → Flow verification
 → Reachability check
 → Candidate output
```

---

## Requirements

```bash
python3
git
go
binwalk
unzip
p7zip
```

## GitHub / WSL Setup

This repository is intended to track code and docs only. Large firmware inputs, extraction outputs, and run artifacts are ignored.

Clone on WSL and initialize your environment like this:

```bash
git clone <your-repo-url>
cd firmware_project

sudo apt update
sudo apt install -y python3 python3-pip git unzip p7zip-full binwalk golang

python3 src/pipeline.py --dry-run
```

Notes:

* `tools/payload-dumper-go/` is intentionally not committed. If missing, the pipeline will try to `git clone` and `go build` it automatically.
* `tools/run-ghidra-mcp.sh` is a local machine helper and is intentionally ignored.
* Keep firmware samples under `inputs/` locally; do not commit them.

---

## Usage

```bash
python3 src/pipeline.py --input <firmware>
python3 src/pipeline.py --dry-run
python3 src/pipeline.py --status
python3 src/pipeline.py --cleanup build rootfs
python3 src/pipeline.py --retain-runs 5 --retain-extracted 2
```

Workspace layout:

* `inputs/` — firmware files grouped by product, e.g. `inputs/RT-AX58U/...`
* `runs/` — run logs, manifests, JSON results, dossiers grouped as `runs/<product>/<input-stem>/run_*`
* `.cache/` — internal extraction, rootfs, and build intermediates
* `research/` — exploitability checklist, pattern taxonomy, candidate ledger schema

If you bulk-drop files into `inputs/` and want them cleaned up into product
folders, run:

```bash
python3 src/corpus_tools/organize_inputs.py --write-corpus
```

This removes stray `:Zone.Identifier` sidecar files, groups firmware under
`inputs/<product>/`, and rewrites corpus `local_path` fields to match the new
layout.

## Run Artifacts

Each run now writes a dedicated artifact directory under `runs/`:

* `run.log` — full pipeline + analysis console log
* `manifest.json` — input hash, paths, status, summary
* `results.json` — structured candidate output
* `dossiers/` — per-candidate review notes for manual follow-up

If `--output` is omitted, `results.json` is written to the run directory automatically.

## Research Loop

Use the repository like this when you are collecting real vulnerability patterns across many firmware images:

1. Put firmware into `inputs/`.
2. Run the pipeline and inspect `runs/<product>/<input-stem>/run_*/results.json` plus `dossiers/`.
3. Review only strong candidates against `research/review/framework/review_checklist.md`.
4. Record every investigated candidate in your own JSONL ledger using `research/review/framework/candidate_ledger.schema.json`.
5. Reuse the primary pattern classes from `research/review/framework/pattern_taxonomy.md`.
6. Build and expand the benchmark corpus intentionally using `research/corpus/firmware_corpus_plan.md`.

You can validate and summarize a ledger file with:

```bash
python3 src/research_tools/ledger.py research/my_ledger.jsonl
python3 src/research_tools/ledger.py research/my_ledger.jsonl --pretty
```

`--pretty` keeps the summary output and also prints each JSONL entry as formatted JSON for manual review.

You can also validate and summarize the benchmark corpus inventory with:

```bash
python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl
python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl --pretty
```

And you can run a stability-focused batch regression pass across the corpus with:

```bash
python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl --limit 10
python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl --only-blocked
python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl \
  --write-corpus \
  --json-output runs/regression/batch_regression_summary.json
```

`batch_regression.py` classifies each sample as `SUCCESS`, `PARTIAL`,
`BLOCKED`, or `BUG` so you can separate unsupported formats from real pipeline
regressions.
Successful runs are also tagged as `rootfs-success`, `fallback-success`, or
`blob-success` so you can distinguish full rootfs extraction from weaker
bundle/blob analysis.
Probe-readiness is also tracked as `rootfs-ready`, `decrypt-probe-ready`,
`scan-probe-ready`, or `bundle-probe-ready` so opaque firmware families still
land in a concrete next-action bucket instead of a generic blob bucket.

And you can generate LLM-ready review packets plus evaluation stubs with:

```bash
python3 src/review/llm_review.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --batch-summary runs/regression/batch_regression_summary.json \
  --emit-corpus-packets research/review/llm/llm_review_packets.jsonl

python3 src/review/llm_review.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --batch-summary runs/regression/batch_regression_summary.json \
  --emit-corpus-packets-compact research/review/llm/llm_review_packets_compact.jsonl

python3 src/review/llm_review.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --batch-summary runs/regression/batch_regression_summary.json \
  --write-gold-stubs research/review/llm/llm_review_gold.jsonl

python3 src/review/llm_review_infer.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --provider heuristic \
  --output research/review/llm/llm_review_predictions.jsonl

python3 src/review/llm_review_infer.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --provider hybrid \
  --model gpt-5.2 \
  --preflight \
  --output research/review/llm/llm_review_predictions_hybrid.jsonl

python3 src/review/llm_review_infer.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --provider openai \
  --model gpt-5.2 \
  --output research/review/llm/llm_review_predictions.jsonl

python3 src/review/llm_review_eval.py \
  --gold research/review/llm/llm_review_gold.jsonl \
  --predictions research/review/llm/llm_review_predictions.jsonl
```

If you want to improve the tool without paying for API calls, keep the same
packet format and compare the engine's current labels against your own direct
review:

```bash
python3 src/review/manual_review_compare.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --write-stubs research/review/manual/manual_review_labels.jsonl

python3 src/review/manual_review_compare.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --manual research/review/manual/manual_review_labels.jsonl \
  --json-out research/review/manual/manual_review_diff.json \
  --markdown-out research/review/manual/manual_review_diff.md
```

This gives you a concrete mismatch queue such as rootfs-state mistakes,
container-family mistakes, and next-action mistakes so you can tighten the
heuristics directly.

`llm_review.py` turns each run into a stable evidence packet for classification,
planning, triage, and report writing. `llm_review_infer.py` turns those packets
into prediction rows using either a deterministic baseline or the OpenAI API.
`heuristic` is now the safe default. Use `--llm-provider hybrid` only when you
intentionally want API-backed judgment for opaque or ambiguous samples.
With `--preflight`, the runner checks `OPENAI_API_KEY` and OpenAI reachability
first, then falls back to `heuristic` automatically unless you set
`--fallback-provider fail`.
For project-local always-on setup, copy `.env.local.example` to `.env.local`
once and set `OPENAI_API_KEY=...`. The runner will auto-load it on every run,
so you do not need to export the key manually each time.
You can also keep `ANTHROPIC_API_KEY=...` there, or store each key separately
under `.secrets/openai_api_key` and `.secrets/anthropic_api_key`.
`llm_review_eval.py` then measures how well model predictions match your
reviewed gold labels.

And you can generate a compact combined research report with:

```bash
python3 src/research_tools/research_report.py --corpus research/corpus/firmware_corpus.jsonl

python3 src/research_tools/research_report.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --ledger research/my_ledger.jsonl
```

The `research/` folder can also hold real investigation snapshots, for example:

* `research/ledgers/totolink_a3002ru_initial.jsonl.json` — initial TOTOLINK A3002RU research leads captured from one pipeline run

---

## Output Example

```
endpoint: /cgi-bin/example.cgi
param: cmd
flow: QUERY_STRING → system()
```

---

## Limitations

* Some vendor firmware may require custom extraction
* Encrypted firmware is not supported
* No dynamic execution validation

---

## License

MIT License
