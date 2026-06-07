# Firmware Orchestration Analysis

### Analyst-assisted tooling for reverse engineering orchestration-heavy embedded firmware

![Status](https://img.shields.io/badge/status-active%20research-0a7ea4)
![Focus](https://img.shields.io/badge/focus-embedded%20firmware%20orchestration-2f6f3e)
![Method](https://img.shields.io/badge/method-analyst--assisted%20RE-6b4fa1)
![Release](https://img.shields.io/badge/release-src--focused-444)

This repository contains source code for an analyst-assisted workflow that reconstructs orchestration structure in embedded firmware management planes.

The focus is not exploit generation. The focus is recovering how requests, helper scripts, native components, staging boundaries, orchestration fan-out, and downstream mutation paths fit together in real firmware.

## Why this exists

Many firmware workflows stop at obvious sinks such as `system()`, `uci commit`, or shell command strings.

That is often too shallow for orchestration-heavy systems.

In practice, management actions may cross several boundaries before persistence or activation occurs:

- entry handlers
- helper scripts
- native staging logic
- ubus or RPC fan-out
- downstream mutation and save paths

This project exists to help analysts recover that larger structure in a reproducible way.

## What this project emphasizes

| Area | Focus |
|---|---|
| Analysis style | architecture-first reverse engineering |
| Main lens | trust-boundary reconstruction |
| Cross-target logic | semantic recurrence, not naive clone matching |
| Tool design | conservative, evidence-tagged, analyst-assisted |
| Primary use case | orchestration-heavy embedded firmware |

## Core ideas

- **Six-layer orchestration model**  
  Entry, helper mediation, staging, amplification, downstream normalization, and persistence are treated as distinct analytical roles.

- **Validation displacement**  
  Stronger validation often appears late, near a sink, even though trust was distributed earlier.

- **Function-scoped evidence**  
  Structured function-level notes are preferred over vague narrative summaries whenever possible.

- **Semantic recurrence**  
  Similarity is judged by architectural role and trust-boundary behavior, not only by shared strings or cloned code.

## Current tooling

The current public codebase centers on orchestration-graph assistance and structured reverse-analysis support.

Key modules:

- `src/research_tools/orchestration_graph_mvp.py`
- `src/research_tools/orchestration_note_drafter.py`
- `src/research_tools/orch_graph_normalization.py`

Current capabilities:

- orchestration-relevant signal extraction from firmware binaries
- analyst-note ingestion and refinement
- markdown-to-note drafting support
- helper, staging, replay, projection, and sink-aware normalization
- conservative graph generation with evidence and warning preservation
- lightweight regression testing for graph-typing behavior

## Repository structure

This public repository is intentionally source-focused.

```text
src/
  research_tools/   Orchestration graph tooling and research helpers
  core/             Supporting analysis components
  batch/            Batch execution helpers
  corpus_tools/     Corpus and input organization utilities
  review/           Review and triage support code
  tests/            Lightweight regression tests
```

Large local corpora, Ghidra workspaces, extracted firmware targets, and private research artifacts are not required for understanding the released source tree and may not be included in a public upload.

## Public release scope

The public-facing repository is intended to prioritize reusable source code over private or bulky research state.

That typically means:

- keeping `src/` as the primary release surface
- keeping lightweight tests when they clarify expected behavior
- excluding local firmware corpora, extracted root filesystems, Ghidra workspaces, and working research archives

If a directory is absent from a public upload, that should usually be interpreted as a release-scope decision rather than as missing methodology context.

## Research framing

This project is motivated by case studies in orchestration-heavy firmware ecosystems, including work on:

- TP-Link OneMesh components such as `meshd`, `sync-server`, and `client_mgmt`
- GL.iNet GL-X3000 components such as `modem.so` and `gl_modem`

Those studies inform the tooling design, but this repository should be read primarily as a methodology and tooling release rather than as a public dump of all underlying research assets.

## What this repository is not

This is **not**:

- an exploit repository
- a mass-CVE harvesting tool
- a benchmark claiming automatic vulnerability discovery
- a final graph generator that replaces analyst judgment

It does **not** claim:

- universal exploitability
- complete runtime reconstruction from static evidence alone
- exact architectural equivalence across all firmware families
- automatic recurrence decisions without review

## Methodology philosophy

The safest default here is conservative interpretation.

That means:

- preserve original evidence
- separate confirmed findings from inference
- allow warnings instead of forcing conclusions
- avoid promoting weak signals into strong architecture claims

The goal is not to automate reverse engineering away. The goal is to make orchestration-aware reverse engineering more structured, more reproducible, and less sink-myopic.

## Future directions

Planned directions include:

- better function-scoped note export workflows
- stronger support for staging-heavy and sink-heavy component classes
- improved cross-family recurrence comparison
- cleaner public evaluation artifacts for future research publication

## For first-time visitors

If you are starting from the public code release:

1. inspect `src/research_tools/orchestration_graph_mvp.py`
2. read the note drafting and normalization modules beside it
3. run the regression tests under `src/tests/research_tools/`
4. treat the tooling as analyst support, not as a push-button answer engine
