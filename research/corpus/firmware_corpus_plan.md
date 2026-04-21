# Firmware Corpus Plan

This document defines how to collect a research corpus for evaluating the firmware analysis pipeline.

The goal is not to download as many firmware files as possible.
The goal is to build a corpus that supports:

- repeated pipeline runs
- cross-version comparison
- cross-vendor pattern comparison
- measurable tool improvement over time

## Collection Principles

- Prefer web-managed routers and IoT devices with a clear HTTP or CGI surface.
- Prefer vendors and models with multiple public firmware versions.
- Prefer formats that extract reliably with the current pipeline.
- Prefer diversity across vendors, but consistency within each model line.
- Avoid spending early effort on encrypted or heavily customized formats unless they are a deliberate extraction target.

## What To Optimize For

Use the corpus to answer these questions:

- Does the pipeline extract the firmware successfully?
- Does it identify the web surface correctly?
- Does it rank plausible exploit chains near the top?
- Does the same pattern recur across versions or vendors?
- Does a scoring or analysis change improve precision without exploding review cost?

## Recommended Initial Corpus Size

Start with 20 to 30 firmware images.

This is large enough to:

- compare vendors
- compare versions within the same model
- measure candidate quality changes after code edits

This is still small enough to:

- inspect outputs manually
- maintain a ledger
- avoid turning the corpus into an unmanaged archive

## Sampling Strategy

Use a two-axis sampling plan:

1. Vendor diversity
2. Version depth per model

Recommended structure:

- 5 to 8 vendors
- 1 to 3 models per vendor
- 2 to 4 versions per model

This gives you both:

- horizontal comparison across vendors
- vertical comparison across versions and patch history

## Priority Tiers

### Tier 1: Immediate Benchmark Targets

Collect these first:

- consumer routers with a web admin interface
- firmware distributed as `.zip`, `.rar`, `.bin`, `.img`, `.trx`, or other archive-like blobs
- models with at least two public versions
- vendors already known to expose CGI, LuCI, Boa, GoAhead, `boafrm`, `goform`, `cgi-bin`, or config-restore workflows

These samples are best for:

- quick extraction feedback
- web-surface evaluation
- command injection and rule-injection triage

### Tier 2: Expansion Targets

Collect these after the first benchmark set is stable:

- additional models from the same vendors
- mesh products, repeaters, and APs that share code families
- firmware with more unusual layouts that still unpack without major reverse engineering

These samples are best for:

- pattern generalization
- cross-product code reuse studies
- testing scorer robustness

### Tier 3: Extraction Stress Targets

Collect these only when you explicitly want to improve extraction coverage:

- encrypted firmware
- vendor-specific package formats
- nested blobs that require custom unpacking
- images that currently fail in the pipeline

These samples are useful, but they should not dominate the early benchmark corpus.

## Recommended Vendor Shortlist

Good early candidates:

- TOTOLINK
- TP-Link
- D-Link
- Netgear
- ASUS
- Tenda
- ipTIME
- Xiaomi

Selection criteria:

- public download center is easy to crawl manually
- multiple firmware revisions are available
- embedded web stack is likely present
- the vendor is common enough to make the results legible in a paper

## Per-Model Selection Rule

For each chosen model, try to collect:

- one older version
- one middle version
- one newer version

If available, also note:

- security advisory dates
- release note keywords such as `security`, `bug fix`, `command injection`, `authentication`, `web`, or `upgrade`

This helps with:

- n-day variant hunting
- regression analysis
- patch-diff case studies

## Avoid These Early

- firmware with no obvious web management component
- samples with only a single version available
- extremely large archives that cost time but add little diversity
- mobile-app-only ecosystems unless they clearly ship local web handlers or CGI equivalents

## Tracking Metadata

For each collected firmware, record at least:

- vendor
- model
- version
- release date if known
- local filename
- source URL or download page
- input type
- extraction result
- web surface detected or not
- notes on unusual layout

Store this in a simple CSV, JSONL, or ledger-style file.

This repository now includes:

- `firmware_corpus.template.jsonl` for sample entries
- `firmware_corpus_fields.md` for field definitions

## Proposed Initial Benchmark Set

Phase 1 target:

- TOTOLINK: 2 models x 3 versions
- TP-Link: 2 models x 3 versions
- ipTIME: 1 or 2 models x 2 to 3 versions
- D-Link: 1 or 2 models x 2 to 3 versions
- Netgear or Tenda: 1 or 2 models x 2 versions

This should land near 20 to 25 images.

That is a good first benchmark size for:

- manual review
- precision tracking
- score tuning
- paper figures

## How To Use The Corpus

For each pipeline revision:

1. Run the same benchmark corpus.
2. Keep the raw run artifacts.
3. Review a fixed top-N candidate budget per firmware.
4. Record verdicts in the ledger.
5. Compare changes in:
   - extraction success rate
   - candidate count
   - precision at top-N
   - number of repeated high-value patterns
   - analyst review time

## Minimum Metrics To Track

- extraction success rate
- web-surface detection success rate
- average candidate count per firmware
- top-10 precision
- number of `CONFIRMED` and `LIKELY` leads
- ratio of reusable pattern classes across vendors

## Practical Recommendation

If you are about to start downloading firmware now, do this:

1. Pick 5 vendors.
2. Pick 1 to 2 models per vendor.
3. Download 2 to 3 versions per model.
4. Stop at about 20 images.
5. Run the pipeline on all of them before collecting more.

Only expand the corpus after you can say:

- which vendors extract well
- which formats fail
- which rule sets produce useful candidates
- where manual review time is being wasted
