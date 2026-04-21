# Session Notes (2026-04-20)

This file is the shortest handoff note for restarting the same research session
in a future Codex run.

## Project State

- working directory:
  - `/home/user/firmware_project`
- corpus status:
  - `21` samples total
  - `21` analyzed successfully in the latest isolated batch regression
  - `0` hard-blocked
- current report command:
  - `python3 src/research_tools/research_report.py --corpus research/corpus/firmware_corpus.jsonl`

## Most Important Files

- corpus:
  - `research/corpus/firmware_corpus.jsonl`
- case-study summary:
  - `research/snapshots/paper_case_studies_20260420.md`
- evaluation snapshot:
  - `research/snapshots/evaluation_snapshot_20260420.md`
- case-study matrix:
  - `research/snapshots/case_study_matrix_20260420.md`
- tool pipeline overview:
  - `research/notes/tool_pipeline_overview_20260420.md`
- blocked extraction matrix:
  - `research/snapshots/blocked_extraction_matrix_20260420.md`
- review outcome matrix:
  - `research/snapshots/review_outcome_matrix_20260420.md`
- vendor finding type matrix:
  - `research/snapshots/vendor_finding_type_matrix_20260420.md`
- review queue:
  - `research/review/manual/review_queue_20260420.jsonl`
- X6000R confirmed review:
  - `research/notes/x6000r_mtkwifi_confirmed_review.md`
- X6000R overlap assessment:
  - `research/notes/x6000r_cve_overlap_assessment_20260420.md`

## Current Conclusions

### 1. Tooling / corpus work

- pipeline and corpus tooling were extended to support:
  - corpus tracking
  - research reporting
  - better RAR failure handling
  - nested `.7z` / LZMA blob following
  - early squashfs-root selection
  - per-firmware IoT extraction workspace isolation
  - forced `zip` / `rar` runs still resolving nested firmware blobs before analysis
  - fallback root selection avoiding stale `.cache/extracted` reuse when the
    current run never performed payload extraction
  - shortlist label normalization from generic binaries to handler-like names
    such as `boa/formUploadFile` and `mtkwifi.lua/submit_dpp_uri`
- result:
  - `21 / 21` firmware samples now complete successfully in isolated regression
  - legacy `X6000R` RAR ingestion is no longer blocked once `unar` is installed
  - `TP-Link Archer C80` no longer crashes during nested extraction, but still
    needs a better layout-specific analysis-root selector
  - latest validation pass removed the four historical hard blocks:
    - `X6000R 652` and `1360` now ingest and analyze normally via RAR fallback
    - `Archer C80 2023` and `2024` now complete via segmented-bundle fallback
      analysis instead of failing in extraction

### 2. X6000R findings

Confirmed code-level command-injection-style paths exist in:

- `apcli_cfg()` -> `apcli_connect()`
- `submit_dpp_uri()`

These were documented as confirmed review notes in:

- `research/notes/x6000r_mtkwifi_confirmed_review.md`

### 3. X6000R CVE decision

Do **not** assume the X6000R findings are new CVEs.

Current safest interpretation:

- likely overlap with already public `TOTOLINK X6000R` disclosure family
- especially because `CVE-2026-1723` already affects:
  - `through V9.4.0cu.1498_B20250826`
- and `1498` still contains:
  - `/cgi-bin/cstecgi.cgi`
  - `topicurl`
  - `setEasyMeshAgentCfg`
  - `setWizardCfg`

This is documented in:

- `research/notes/x6000r_cve_overlap_assessment_20260420.md`

## Ghidra Setup Used

The following binaries were the main reverse-engineering targets:

- `.../usr/sbin/shttpd`
- `.../usr/bin/wappctrl`
- `.../usr/bin/cs`

Main useful result:

- `shttpd` contains the public API family for:
  - `setEasyMeshAgentCfg`
  - `setWizardCfg`

## Best Next Step

Do **not** spend the next session trying to claim a new X6000R CVE first.

Recommended priority:

1. move to a likely-new target
   - `AX3000M`
   - `WR1300V4`
   - `WR3000E`
2. use the existing review queue to select a stronger new finding
3. keep `X6000R` as:
   - paper case study
   - known-issue overlap / variant-analysis example

### Follow-up update

Latest manual continuation note:

- `research/notes/ax3000m_cudy_followup_20260420.md`

Main new takeaway:

- `AX3000M` is now a better next target than `Cudy`
- `14.234` and `15.024` expose a hidden diagnostic CGI pattern involving:
  - `fname`
  - `cmd`
  - `aaksjdkfj`
  - `popen`
- `15.330` no longer exposes that same visible path, which makes it a good
  version-diff case
- `Cudy WR1300V4` still shows fixed shell-execution templates, but not yet a
  clean attacker-controlled shell argument
- `Cudy WR3000E` re-check points the same way:
  - visible `system.lua` / `autoupgrade.lua` shell paths are mostly fixed
    `fork_exec()` templates
  - better treated as paper/supporting material than a fresh command-exec lead
- `AX2004M` completed runs do not currently show the same saved hidden
  diagnostic `d.cgi` / `timepro.cgi` / `aaksjdkfj` pattern seen in `AX3000M`

## Restart Checklist

Run:

```bash
cd /home/user/firmware_project
python3 src/corpus_tools/corpus.py research/corpus/firmware_corpus.jsonl
python3 src/research_tools/research_report.py --corpus research/corpus/firmware_corpus.jsonl
git status --short
```

## Latest Tooling Follow-up

- `src/pipeline.py` was updated to:
  - add RAR extractor fallbacks: `unrar`, `unar`, `bsdtar`
  - isolate IoT extraction output per firmware blob under `.cache/build`
  - avoid the previous nested extraction `FileNotFoundError` on TP-Link C80
  - widen rootfs candidate scoring for small wrapper roots
  - recognize segmented TP-Link-style LZMA bundles and fall back to generic
    bundle analysis when no classic rootfs exists
- validated result:
  - `inputs/X6000R_V9.4.0cu.652_B20230116.rar` now resolves and analyzes
  - `inputs/V9.4.0cu.1360_B20241207_ALL.rar` now resolves and analyzes
  - `inputs/Archer C80(US)_V2.2_240617.zip` completes via segmented-bundle
    fallback with `40` blob candidates scanned and `0` findings
  - `inputs/Archer C80(US)_V2.2_230609.zip` completes via segmented-bundle
    fallback with `40` blob candidates scanned and `0` findings
- remaining gap:
  - C80 still does not expose a classic extracted rootfs; it now completes in
    fallback mode rather than ideal web-root mode
  - latest full-corpus regression command:
    - `python3 src/batch/batch_regression.py research/corpus/firmware_corpus.jsonl`
  - latest full-corpus regression result:
    - `21 / 21 OK`

## Candidate Alignment Follow-up

- Added `src/batch/candidate_alignment.py` to compare:
  - pipeline `results.json` candidates and `cve_candidates`
  - against reviewed ledger entries in `research/review/manual/review_queue_20260420.jsonl`
- Current snapshot:
  - markdown: `research/snapshots/candidate_alignment_snapshot_20260420.md`
  - json: `research/snapshots/candidate_alignment_snapshot_20260420.json`
- Current reviewed-family alignment numbers:
  - reviewed entries: `8`
  - matched by any pipeline candidate: `8 / 8` (`100%`)
  - matched by top shortlist candidate: `8 / 8` (`100%`)
  - ranking misses: `0`
  - semantic misses: `0`
- Most useful interpretation:
  - `WR3000E` already aligns well with the current shortlist
  - `A3002RU` was the clearest current gap, but endpoint extraction changes now
    let the pipeline top shortlist line up with all three reviewed handler-level
    cases: `formWsc`, `formWlSiteSurvey`, and `formUploadFile`
  - `X6000R` is no longer the residual ranking gap after adding LuCI route
    extraction and richer script `handler_symbols`; both reviewed
    `mtkwifi.lua` cases now align with the top shortlist:
    `apcli_connect` and `submit_dpp_uri`
  - latest reruns also improved presentation quality:
    - forced ZIP analysis now resolves the embedded `.web` firmware instead of
      falling back to stale cache directories
    - top shortlist labels are closer to reviewed findings, e.g.
      `boa/formUploadFile` and `mtkwifi.lua/submit_dpp_uri`
- Best next tooling direction if continuing:
  - keep `candidate_alignment.py` as the main regression metric after each
    heuristic change, not just raw candidate count
  - shift effort from basic coverage toward reducing unmatched shortlist items
    and false-positive-looking generic candidates in reviewed families
  - keep improving candidate normalization so shortlist labels look more like
    reviewed handler-level findings and less like raw binary-level summaries
  - recent shortlist-only false-positive reductions were intentionally narrow:
    - shebang/declarative `/bin/sh` sinks no longer count as real exec sinks
    - pseudo sinks such as `system(Flash)` no longer count as command-exec
      evidence
    - source-artifact endpoints like `/configparser.y` are now heavily
      deprioritised / discarded unless stronger handler evidence exists
    - generic firmware/config-only artifact paths such as `/firmware.bin` are
      penalised when they are not tied to a concrete web handler
  - latest practical effect:
    - `WR3000E` kept the reviewed `system.lua administration` case but lost the
      old `uhttpd` shebang noise
    - `AX2004M` reruns no longer promote the old `arp_protection system(Flash)`
      heuristic into the CVE shortlist
    - `AX3000M 15.024` keeps `d.cgi` in the shortlist while dropping the old
      `lighttpd/configparser.y` artifact; `AX3000M 14.234` now has no CVE
      shortlist item under the stricter triage rules

If using Ghidra again:

1. check `research/notes/ghidra_mcp_wsl_windows_setup_20260420.md`
2. ensure the Windows Ghidra HTTP bridge is listening on `0.0.0.0:8080`
3. from Windows PowerShell, run:
   - `tools/ghidra_11.3.2_PUBLIC/check_ghidra_bridge.ps1`
4. from WSL, confirm one of these responds:
   - `http://127.0.0.1:8080/`
   - `http://<nameserver>:8080/`
   - `http://<default-gateway>:8080/`
5. then open the current AX3000M targets:
   - `/home/user/firmware_project/work/ax3000m/15_024/d.cgi`
   - `/home/user/firmware_project/work/ax3000m/14_234/timepro.cgi`
   - `/home/user/firmware_project/work/ax3000m/15_330/ftm.cgi`

## Good First Prompt For Next Session

Use this:

`지난번 firmware_project 이어서 해줘. research/notes/SESSION_NOTES_20260420.md, research/notes/x6000r_cve_overlap_assessment_20260420.md, research/snapshots/paper_case_studies_20260420.md 먼저 읽고 이어가줘. X6000R는 overlap 가능성이 높고, 다음은 AX3000M이나 Cudy 쪽 새 제보 후보를 파는 방향이었어.`
