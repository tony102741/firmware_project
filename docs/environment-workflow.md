# Portable Environment Workflow

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

`scripts/check-env.sh` is the quick compatibility check before starting serious work.

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
git add README.md CLAUDE.md .gitignore requirements.txt docs scripts src research report
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
- `ghidra_targets/**/rootfs/`

Move them manually only when the next task needs them.
