# Portable Environment Workflow

This document is a portability guide, not the canonical WSL operating procedure.
The primary analysis environment remains the desktop WSL workspace.

The goal is to continue the same firmware work on a desktop and a MacBook with minimal friction.

Git carries the shared working state:

- source code
- research notes
- final reports
- Ghidra target notes and JSON summaries
- setup scripts and docs

Each machine keeps its own heavy local state:

- firmware samples in `inputs/`
- extraction cache in `.cache/`
- run artifacts in `runs/`
- downloaded or built tools in `tools/`
- Python virtualenv in `.venv/`
- machine-specific MCP config in `.mcp.json`

## WSL Desktop Baseline

On the main WSL machine, keep the heavy local analysis state in place and do not try to reconstruct it from Git alone.

Use:

```bash
cd firmware_project
. scripts/env.sh
scripts/check-env-wsl.sh
```

The WSL workspace is expected to hold the real local analysis data, including:

- `research/regeneration/full_corpus_20260508/`
- `ghidra_targets/`
- copied firmware samples in `inputs/`
- older run bundles in `runs/`
- local tools under `tools/`

## First Setup On Each Mac

```bash
cd firmware_project
scripts/bootstrap-macos.sh
. scripts/env.sh
scripts/check-env.sh
```

Install missing system tools with Homebrew:

```bash
brew install git go binwalk p7zip
```

`scripts/check-env.sh` is the generic compatibility check before starting serious work on a Mac.

## Starting Work

```bash
cd firmware_project
git pull --ff-only
. scripts/env.sh
python3 src/pipeline.py --status
```

If a firmware file exists only on the other machine, copy just that product folder into `inputs/`.

## Ending Work

```bash
git status
git add README.md .gitignore requirements.txt docs scripts src
git add 'ghidra_targets/**/*.md' 'ghidra_targets/**/*.json'
git commit -m "Save firmware research progress"
git push
```

Then, on the other machine, pull and continue.

## Local-Only Files

Do not try to make these identical through Git:

- `inputs/`
- `runs/`
- `.cache/`
- `tools/`
- `.venv/`
- `.mcp.json`
- `research/regeneration/full_corpus_20260508/`
- `research/**/*.jsonl`
- `research/**/*.md`
- `ghidra_targets/**/rootfs/`

Move them manually only when the next task needs them.

If a local machine has irreplaceable analysis outputs, protect them first and treat Git as code/document sync only.
