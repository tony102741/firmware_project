# Runtime Observation Toolkit

This directory is for passive runtime-ground-truth collection from an MR90X router.

## Components

- `scripts/runtime/observe_mr90x_sync.sh`
  - starts passive observers only
  - does **not** send packets
  - does **not** modify runtime files
  - saves logs, strace output, and `/tmp/sync-server` snapshots under:
    - `research/regeneration/full_corpus_20260508/runtime_observation/<timestamp>/`

- `scripts/runtime/extract_helper_artifacts.py`
  - parses one observation directory
  - extracts helper `execve(...)` lines
  - summarizes candidate helper `infile` / `outfile` paths
  - lists captured `/tmp/sync-server` files
  - detects likely JSON artifacts

## Recommended workflow

On the router:

```bash
bash scripts/runtime/observe_mr90x_sync.sh
```

Optional `meshd` tracing:

```bash
bash scripts/runtime/observe_mr90x_sync.sh --include-meshd
```

Stop with `Ctrl-C`.

Then parse the captured directory on the analysis workstation:

```bash
python3 scripts/runtime/extract_helper_artifacts.py \
  research/regeneration/full_corpus_20260508/runtime_observation/<timestamp>
```

## Safety notes

- passive observation only
- no exploit payloads
- no helper injection
- no firmware update / restore / reset paths
- no deletion of runtime state
- no automatic execution against a live router from this repository
