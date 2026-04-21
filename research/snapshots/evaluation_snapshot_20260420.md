# Evaluation Snapshot (2026-04-20)

This note captures the current tool-evaluation numbers so they can be reused
later in a paper, slide deck, or summary without recomputing the state by hand.

Source commands:

- `python3 src/research_tools/research_report.py --corpus research/corpus/firmware_corpus.jsonl`
- `python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl`
- `python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl`

---

## 1. Corpus Summary

Current corpus size:

- total samples: `21`
- vendors: `4`
  - `TOTOLINK`: `6`
  - `ipTIME`: `6`
  - `TP-Link`: `5`
  - `Cudy`: `4`
- product classes:
  - `router`: `19`
  - `mesh`: `2`

Extraction / analysis status:

- extraction success: `21 / 21` (`100%`)
- extraction failed: `0 / 21` (`0%`)
- analysis completed: `21 / 21` (`100%`)
- blocked: `0 / 21` (`0%`)

Previously blocked cases now removed by tooling changes:

- `TP-Link Archer C80` now completes via segmented-bundle fallback analysis
- old `TOTOLINK X6000R` RAR images now complete via `unar` fallback extraction

Interpretation:

- the tool now handles the entire current corpus end-to-end
- some samples still complete through weaker fallback modes rather than ideal
  rootfs extraction, but they no longer terminate the pipeline

---

## 2. Ledger Snapshot

Current structured review ledger summary:

- ledger entries: `10`
- ledger files: `2`
- verdicts:
  - `CONFIRMED`: `6`
  - `NEEDS_MORE_WORK`: `3`
  - `REJECTED`: `1`
- confidence:
  - `HIGH`: `6`
  - `MEDIUM`: `4`

Pattern distribution in the current ledger:

- `cmd-injection`: `8`
- `config-injection`: `1`
- `rule-injection`: `1`

Important note:

- the ledger now includes the manually confirmed `A3002RU` recurrence cases
- it also preserves one rejected `AX3000M` heuristic entry so that automated
  triage provenance is not confused with final confirmed findings

So the ledger numbers can now be interpreted as:

- **structured triage + review outcome**

with a visible distinction between:

- confirmed findings
- unresolved leads
- heuristics later rejected during manual review

---

## 3. Vendor Progress

From `research_report.py`:

- `Cudy`
  - samples: `4`
  - extract_ok: `4`
  - analyzed: `4`
  - candidates: `1`
  - confirmed: `0`
  - needs_more_work: `1`

- `TOTOLINK`
  - samples: `6`
  - extract_ok: `6`
  - analyzed: `6`
  - candidates: `7`
  - confirmed: `5`
  - needs_more_work: `2`

- `TP-Link`
  - samples: `5`
  - extract_ok: `5`
  - analyzed: `5`
  - candidates: `0`

- `ipTIME`
  - samples: `6`
  - extract_ok: `6`
  - analyzed: `6`
  - candidates: `2`
  - confirmed: `1`
  - rejected: `1`

Interpretation:

- `ipTIME` and `TOTOLINK` are currently the strongest families for
  security-relevant findings
- `Cudy` is useful as a secondary family but not yet as strong for a fresh
  command-execution claim
- `TP-Link` currently contributes more to benchmark / extraction robustness than
  to confirmed case studies

---

## 4. Current Best Case Studies

### A. `ipTIME AX3000M`

Current status:

- strongest likely-new case
- hidden diagnostic CGI pattern manually confirmed
- version-diff story:
  - `14.234`
  - `15.024`
  - `15.330`

Why it matters:

- hidden authenticated diagnostic interface
- `cmd -> popen()` chain confirmed at function level
- later version appears to remove or significantly restrict the path

Best role in evaluation:

- flagship deep-dive case study

### B. `TOTOLINK A3002RU`

Current status:

- strongest recurrence / repeated-pattern case
- three command-injection reports already exist
- same design anti-pattern persists across feature areas

Why it matters:

- not just one bug
- repeated shell command construction from user-controlled data

Best role in evaluation:

- vendor-level recurrence case study

### C. `TOTOLINK X6000R`

Current status:

- strong code-level sink evidence
- but high overlap risk with already public disclosures

Why it matters:

- demonstrates the tool can surface real issues
- also demonstrates the need for overlap filtering before claiming novelty

Best role in evaluation:

- known-issue / overlap-filtering case study

### D. `Cudy WR3000E / WR1300 V4`

Current status:

- repeated shell-execution patterns exist
- strongest current `WR3000E` case is QoS / `nft-qos` rule manipulation
- direct web-input-to-shell claim remains weaker than `AX3000M`

Best role in evaluation:

- secondary family / supporting case

---

## 5. Practical Research Framing

If this snapshot is used later in a paper, the current material already supports
the following evaluation claims:

1. the tool processes a non-trivial multi-vendor corpus successfully
2. the hardened pipeline now completes all current corpus entries
3. the tool surfaces command-execution-oriented leads at useful density
4. manual review can separate:
   - likely-new cases
   - recurrence cases
   - overlap / known-issue cases
   - weaker supporting cases
   - rejected heuristics

That framing is stronger than simply saying:

- "the tool found bugs"

because it shows:

- extraction coverage
- triage utility
- review prioritization value
- overlap filtering value

---

## 6. Immediate Next Data-Hygiene Tasks

To make the evaluation section cleaner later:

1. keep blocked extraction cases documented rather than removing them
2. preserve the distinction between:
   - automated triage counts
   - manually confirmed case-study counts
3. if needed later, add a dedicated ledger field for `superseded_by` so rejected
   heuristics can point directly to the final confirmed case

---

## 7. Bottom Line

As of `2026-04-20`, the tool has completed end-to-end extraction and analysis on
`17 / 21` firmware samples across `4` vendors, produced a compact review ledger
with multiple confirmed command-injection-style candidates, and already supports
three distinct case-study roles:

- likely-new finding: `AX3000M`
- recurrence finding: `A3002RU`
- overlap-filtering finding: `X6000R`
