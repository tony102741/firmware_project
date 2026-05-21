# Orchestration Graph Tooling Status Report

## Current Capabilities

The current tooling stack supports:

- strings/imports-based provisional orchestration graph extraction
- analyst-note ingestion and evidence promotion
- markdown-to-note draft generation
- helper/restart/replay normalization
- staging-aware note drafting
- semantic node-type reconciliation
- projection/activation-aware raw node typing

The tooling is designed for analyst assistance, not autonomous orchestration reconstruction.

## Tested Cases

Regression-tested cases currently include:

- helper command normalization
  - `/usr/bin/switch_sim_slot %s timing start` -> `/usr/bin/switch_sim_slot`
- helper lifecycle normalization
  - `kill -15 $(pgrep -f dual_sim_failover)` -> `dual_sim_failover`
- restart normalization
  - `kmwan restart` -> `kmwan`
- projection phrase typing
  - `Sync configuration to network...` -> downstream/projection-like node
- activation phrase typing
  - `Start_dial` -> activation endpoint
- persistence preservation
  - `glmodem.network_sim%d` remains persistence-related
  - `network.%s.iccid` remains persistence/context-related
- `gl_modem` drafted-note refinement
  - no hard node-type conflict warnings

## What the Tool Does Well

- gathers orchestration-relevant static signals quickly
- preserves original evidence even after normalization
- reduces helper-command fragmentation
- supports note-based evidence promotion
- keeps conservative warning behavior for unresolved cases

## Known Limitations

- graph output is still provisional and can be noisy
- note drafter remains prose-sensitive
- compatibility overlays are useful, but they are not full semantic resolution
- no function-level decompilation recovery
- no exact ordering inference
- no automatic recurrence judgment

## What Should Remain Manual

- xref confirmation
- function-level interpretation
- exact ordering reconstruction
- final graph cleanup for publication use
- exact vs semantic recurrence decisions
- architecture-level significance judgments

## What Should Not Be Claimed

The tooling should not be described as:

- an exploitability detector
- a vulnerability detector
- a final graph generator
- a runtime reconstruction engine
- an automatic cross-family recurrence engine

## Current Safe Interpretation

The safest current claim is:

The tooling provides conservative, evidence-preserving analyst assistance for orchestration-heavy firmware reverse engineering, especially around helper relationships, replay boundaries, persistence state, downstream projection, and activation paths.

## Next Safe Improvement

The next safe improvement is:

- function-scoped analyst-note export / ingestion

Reason:

- it increases grounded `E1` / `E2` evidence
- it reduces prose-driven drafting ambiguity
- it improves graph quality without adding unsupported automation
