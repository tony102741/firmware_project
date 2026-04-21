# Blocked Extraction Matrix (2026-04-20)

This note started as a blocked-case summary. As of the latest tooling pass on
`2026-04-20`, the previously blocked samples below now complete analysis, so it
also records how each blockage was removed.

---

## Matrix

| Vendor | Model | Version | Input type | Status | Failure class | Short reason |
|---|---|---|---|---|---|---|
| `TP-Link` | `Archer C80` | `V2.2_230609` | `zip` | `UNBLOCKED` | segmented bundle fallback | classic rootfs is absent, but the image now completes through segmented-bundle analysis without crashing |
| `TP-Link` | `Archer C80` | `V2.2_240617` | `zip` | `UNBLOCKED` | segmented bundle fallback | non-classic TP-Link layout now falls back to generic bundle analysis instead of failing rootfs selection |
| `TOTOLINK` | `X6000R` | `V9.4.0cu.1360_B20241207_ALL` | `rar` | `UNBLOCKED` | archive decoder fallback added | `unar` fallback support allows ingestion of old/unsupported RAR members instead of failing at `7z` |
| `TOTOLINK` | `X6000R` | `V9.4.0cu.652_B20230116` | `rar` | `UNBLOCKED` | archive decoder fallback added | legacy RAR now resolves to the internal `.web` image and proceeds into normal extraction/analysis |

---

## Grouped By Failure Class

### 1. Non-classic Nested Layout

Affected samples:

- `TP-Link Archer C80 V2.2_230609`
- `TP-Link Archer C80 V2.2_240617`

Observed behavior:

- archive unpacking now progresses without the previous nested-blob crash
- extraction workspaces are isolated per firmware, so cross-run contamination is removed
- when no classic rootfs exists, the pipeline now falls back to segmented-bundle analysis

Why it matters:

- this is no longer a hard extraction failure
- the tool now degrades into bundle-level analysis instead of aborting

Paper value:

- demonstrates that the benchmark includes honest extraction failures
- highlights a concrete future engineering improvement target

### 2. Archive Decoder Limitation

Affected samples:

- `TOTOLINK X6000R V9.4.0cu.652_B20230116`
- `TOTOLINK X6000R V9.4.0cu.1360_B20241207_ALL`  (historical issue, now mitigated)

Observed behavior:

- the archive can be recognized
- plain `7z` was not enough for some legacy RAR members
- after adding `unar` fallback support, ingestion proceeds instead of failing at the archive stage

Why it matters:

- this used to block the pipeline before filesystem analysis could start
- it is now largely mitigated by extractor fallback support rather than remaining a hard block

Paper value:

- useful for separating format-support limitations from security-triage quality

---

## Quantitative Summary

Hard-blocked total:

- `0 / 21` after the latest fallback and validation pass

By failure class:

- non-classic nested layout still requires fallback analysis: `2`
- archive decoder limitation still hard-blocked: `0`

Interpretation:

- no sample remains hard-blocked in the current validation set
- the old RAR ingestion problem is now removed with extractor fallback support
- the TP-Link C80 pair still highlights a weaker outcome: completed bundle analysis with zero candidates rather than classic rootfs-based analysis

---

## Bottom Line

The present residual extraction complexities fall into two narrow engineering categories:

- **runtime analysis-root selection for non-classic TP-Link layouts**
- **RAR decoding support**  (mitigated by fallback tooling)

This is useful because it shows the pipeline now handles the full current
sample set end-to-end, while still making clear that some images complete via
weaker fallback modes rather than ideal rootfs extraction. The biggest recent
changes were:

- legacy TOTOLINK RAR ingestion is no longer a hard blocker once fallback
  extractors are available
- TP-Link C80 images now complete through segmented-bundle fallback instead of
  terminating at rootfs-selection time
