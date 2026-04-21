# Tool Pipeline Overview (2026-04-20)

This note summarizes the current firmware-analysis toolchain from a paper-facing
point of view. It is meant to support future writing about:

- what the tool does
- how the pipeline is structured
- what kinds of signals it promotes
- where the current limits still are

It is not a full implementation manual.

---

## 1. High-Level Goal

The tool is designed to triage firmware images for security-relevant web-facing
attack paths, with emphasis on:

- extraction reliability across mixed firmware formats
- web-surface discovery
- exploitability-aware prioritization
- compact ledger-based manual review

The practical target is not “find every sink,” but:

- make multi-vendor firmware review repeatable
- push strong web-to-privileged-execution cases toward the top
- preserve enough metadata to compare pipeline revisions over time

---

## 2. Pipeline Structure

At a high level, the workflow is:

1. input normalization
2. extraction
3. rootfs selection
4. analysis mode detection
5. scanner / analyzer pass
6. candidate triage
7. dossier / ledger output
8. corpus-level progress reporting

### Stage 1. Input Normalization

Implemented in:

- `src/pipeline.py`

Current input families handled by the pipeline include:

- archive-style OTA packages such as `.zip`
- raw firmware blobs such as `.bin`
- partition / image style inputs such as `.img`
- vendor-specific IoT-style archive blobs such as `.web`
- some `.rar`-wrapped cases when the extractor can decode them

The pipeline tries to classify the input automatically before extraction.

### Stage 2. Extraction

Implemented primarily in:

- `src/pipeline.py`

Extraction behavior includes support for:

- nested archive handling
- nested blob following
- early squashfs-root selection
- Android-style payload handling where applicable

This is one of the key engineering contributions because many firmware-analysis
pipelines fail before reaching any security logic.

### Stage 3. Root Filesystem Selection

The pipeline does not stop at “archive extracted.”
It also tries to identify the correct analysis root so later scanners operate on
the actual system partition rather than arbitrary unpacked debris.

This matters especially for:

- nested `.bin` or `.img` payloads
- vendor bundles with multiple internal components
- images where the first extracted filesystem is not the real runtime root

### Stage 4. Analysis Mode Detection

Implemented in:

- `src/main.py`

The current tool distinguishes at least:

- `iot_web`
- `android`
- `general`

For the firmware in the present corpus, the important case is `iot_web`, which
is triggered by evidence such as:

- `www`
- `cgi-bin`
- `luci`
- web-server binaries like `boa`, `uhttpd`, `lighttpd`, `httpd`

This allows the later triage to focus on web-reachable attack surfaces instead
of treating all binaries equally.

### Stage 5. Scanner / Analyzer Pass

Implemented in:

- `src/main.py`

Current imported analysis modules include:

- init / service parsing
- web-surface scanning
- reachability analysis
- exploit-flow verification
- strings extraction
- CVE / exploitability triage
- crypto material scanning
- upgrade-script scanning
- setuid / permission / `su` checks

In practice, the most important paper-facing behavior is that the tool combines:

- web exposure clues
- runtime sink clues
- privilege context
- attack-surface hints

rather than reporting only raw sink strings.

### Stage 6. Candidate Triage

Implemented in:

- `src/main.py`
- `research/review/framework/pattern_taxonomy.md`

The pipeline promotes candidates into pattern classes such as:

- `cmd-injection`
- `config-injection`
- `rule-injection`
- `file-write -> later execution`
- `privilege-boundary crossing`

The taxonomy is designed to help the reviewer distinguish:

- direct command-execution candidates
- state / policy manipulation cases
- persistence-oriented configuration abuse

This is important because not every dangerous string should be treated as the
same kind of vulnerability.

### Stage 7. Dossier / Ledger Output

Implemented in:

- `src/pipeline.py`
- `src/research_tools/ledger.py`
- `research/review/manual/review_queue_20260420.jsonl`

The pipeline preserves outputs in two useful forms:

- per-run artifacts under `runs/`
- compact JSONL review ledgers under `research/`

The ledger structure captures:

- firmware identity
- entry point
- input type
- processing chain
- sink
- review verdict
- confidence
- CVE potential

This makes it possible to compare:

- automated surfacing
- manual confirmation
- rejected heuristics

without losing provenance.

### Stage 8. Corpus-Level Reporting

Implemented in:

- `src/corpus_tools/corpus.py`
- `src/research_tools/research_report.py`

These scripts convert local firmware work into evaluation metrics such as:

- extraction success rate
- analyzed sample count
- per-vendor progress
- verdict distribution
- confirmed / unresolved / rejected counts

This is what makes the project usable as a paper evaluation rather than only a
set of ad hoc reversing notes.

---

## 3. Why The Current Triage Is Useful

The current pipeline is not just an unpacker plus grep.
Its value comes from the combination of:

- format-aware extraction
- web-surface detection
- sink-aware candidate ranking
- ledger-backed manual review

This is visible in the current corpus through three distinct outcomes:

- likely-new case:
  - `ipTIME AX3000M`
- recurrence / anti-pattern case:
  - `TOTOLINK A3002RU`
- overlap / known-issue filtering case:
  - `TOTOLINK X6000R`

That spread is useful because it shows the tool supports not only “finding,” but
also:

- prioritizing
- downgrading
- classifying

real firmware cases.

---

## 4. Current Evaluation Snapshot

From the current corpus and ledger state:

- corpus size: `21`
- extraction success: `17 / 21`
- analysis completed: `17 / 21`
- current ledger entries: `10`
- current verdict distribution:
  - `CONFIRMED`: `6`
  - `NEEDS_MORE_WORK`: `3`
  - `REJECTED`: `1`

These numbers matter because they show that the pipeline is already stable
enough to support repeated benchmarking across multiple vendors rather than only
single-target experiments.

See also:

- `research/snapshots/evaluation_snapshot_20260420.md`
- `research/snapshots/case_study_matrix_20260420.md`

---

## 5. Current Failure / Limitation Types

The remaining blocked cases are not random.
They currently cluster into a few extraction-oriented categories.

### A. Rootfs Selection Failures

Example:

- `TP-Link Archer C80`

Current issue:

- nested image layout is unpacked, but the current rootfs locator still misses
  the correct runtime filesystem

Why it matters:

- this is a pipeline-coverage limitation, not a target-specific security claim

### B. Archive Decoder Limits

Example:

- older `TOTOLINK X6000R` RAR samples

Current issue:

- present `7z` environment can list the archive but cannot reliably decode the
  member compression method for some samples

Why it matters:

- this blocks ingestion before any security analysis can begin

### C. Heuristic Overstatement

Example:

- early `AX3000M /config -> popen` heuristic
- `Cudy WR3000E system.lua -> /bin/sh` heuristic

Current issue:

- raw sink proximity can overstate exploitability before manual chain
  confirmation

Why it matters:

- this is exactly why the ledger keeps:
  - `CONFIRMED`
  - `NEEDS_MORE_WORK`
  - `REJECTED`

separate.

---

## 6. Practical Strengths

At the current stage, the strongest practical aspects of the tool are:

- it processes a mixed, real-world firmware corpus with non-trivial success
- it preserves run artifacts and review provenance
- it is good at surfacing web-management-adjacent command-execution patterns
- it supports cross-version and cross-vendor comparison

This makes it suitable for a methodology section that emphasizes:

- repeatability
- analyst efficiency
- exploitability-aware prioritization

not just raw sink discovery.

---

## 7. Practical Weaknesses

Current weak points are:

- extraction coverage for some vendor-specific layouts
- incomplete alignment between report docs and compact JSONL ledgers unless
  maintained actively
- some heuristics still depend on manual reversing to distinguish:
  - direct command execution
  - fixed-template administration helpers
  - configuration / rule manipulation only

These are not fatal weaknesses, but they should be described honestly in any
future paper.

---

## 8. Bottom Line

The current toolchain should be described as:

- a **firmware extraction + web-surface security triage pipeline**
- with **ledger-backed manual validation**
- evaluated on a **multi-vendor benchmark corpus**

Its most defensible contribution is not “full automation of vulnerability
discovery,” but:

- reliable corpus processing
- exploitability-aware candidate surfacing
- and structured separation of confirmed findings, weak leads, and rejected
  heuristics
