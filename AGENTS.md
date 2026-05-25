# AGENTS.md

This file provides guidance for AI agents (OpenAI Codex CLI and equivalents) working in this repository.

---

## Language Convention

**Research documents must be written in Korean.**

This applies to all files under:

- `research/management_plane/`
- `research/topics/`
- `research/pipeline_architecture/`
- `research/corpus/`
- `docs/strategy/`
- `docs/`

When creating or editing any `.md` file in these directories, write all prose in Korean.

### What to keep in English

The following must remain in English regardless of context:

- Code blocks (everything inside ` ``` ` fences)
- Binary and daemon names: `meshd`, `sync-server`, `client_mgmt`, `tdpServer`, `tmpsvr`, `connmode`, `pfclient`, `ubus`, `saveconfig`, `firmware.lua`, etc.
- Function names, file paths, variable names, command names
- Technical identifiers: `system()`, `uci commit`, JSON keys, UCI section names
- Evidence class labels: `E1_function_level_confirmed`, `E2_xref_confirmed`, `E3_converging_static_evidence`
- `CONFIRMED` / `HYPOTHETICAL` status markers in flow diagrams
- Markdown table structure (translate cell contents, not the structure)

### Writing style

- Technical document style, plain declarative sentences (평서형)
- No honorifics (존댓말 사용 금지)
- Concise and high-signal — match the existing translated documents in `research/management_plane/`

---

## Project Context

This repository studies orchestration-heavy firmware management planes.

The core research focus is how trust, state, validation, helper output, and persistence are distributed across:

- entry handlers
- helper scripts
- native daemons (`meshd`, `sync-server`, `client_mgmt`, `tdpServer`, `tmpsvr`)
- staging layers
- orchestration amplifiers
- downstream mutation sinks

Main ecosystems: TP-Link OneMesh, GL.iNet GL-X3000.

---

## Claim Discipline

Follow the evidence discipline strictly:

- `E1_function_level_confirmed` — direct function-level confirmation
- `E2_xref_confirmed` — confirmed through xrefs or direct call relationships
- `E3_converging_static_evidence` — multiple static cues, not yet direct closure

Do not claim exploitability unless directly proven. Do not silently promote weaker evidence into stronger claims. If a result is incomplete, say so plainly.

---

## Directory Structure

```
src/                  # source code (Python pipeline, analysis tools)
tests/                # tests
docs/                 # workflow and strategy documents (Korean)
research/
  corpus/             # corpus metadata and planning (Korean)
  management_plane/   # firmware management plane analysis notes (Korean)
  topics/             # topic-specific research notes (Korean)
  pipeline_architecture/  # pipeline design documents (Korean)
  review/             # review results, triage, reports
  regeneration/       # generated corpus analysis data
  reports/            # per-firmware analysis summaries
paper/                # paper writing workspace
```

---

## What Not To Do

- Do not write research documents in English (use Korean prose)
- Do not overclaim: no CVE status without a real disclosure workflow, no exploitability without direct proof
- Do not treat graph outputs as final truth
- Do not add features or abstractions beyond what the task requires
