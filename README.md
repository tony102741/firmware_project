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

* `inputs/` — firmware files you drop in manually
* `runs/` — run logs, manifests, JSON results, dossiers
* `.cache/` — internal extraction, rootfs, and build intermediates
* `research/` — exploitability checklist, pattern taxonomy, candidate ledger schema

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
2. Run the pipeline and inspect `runs/<run>/results.json` plus `dossiers/`.
3. Review only strong candidates against `research/review_checklist.md`.
4. Record every investigated candidate in your own JSONL ledger using `research/candidate_ledger.schema.json`.
5. Reuse the primary pattern classes from `research/pattern_taxonomy.md`.

You can validate and summarize a ledger file with:

```bash
python3 src/ledger.py research/my_ledger.jsonl
```

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
