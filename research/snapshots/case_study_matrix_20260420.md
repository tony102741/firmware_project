# Case Study Matrix (2026-04-20)

This note compresses the current best findings into a single matrix for later
paper/thesis writing. The goal is not to replace the detailed reports, but to
make the role of each case study obvious at a glance.

---

## Matrix

| Case | Firmware set | Tool surfaced | Manual review result | Security interpretation | Best paper role |
|---|---|---|---|---|---|
| `ipTIME AX3000M` | `14.234`, `15.024`, `15.330` | hidden CGI + `popen` + version recurrence hints | confirmed hidden diagnostic `cmd -> popen()` in `14.234/15.024`; restricted/removed in `15.330` | hidden authenticated diagnostic/debug interface | flagship deep-dive / version-diff case |
| `TOTOLINK A3002RU` | multiple V3 builds including `2021-03-02` recheck | repeated Boa/`system()` command-construction patterns | three confirmed command-injection paths across different features | product-level recurrence of insecure shell command construction | recurrence / vendor-pattern case |
| `TOTOLINK X6000R` | `V9.4.0cu.1498_B20250826_ALL` | clean web-management-to-`os.execute()` leads | code-level sink evidence is strong, but public-issue overlap risk is high | real vulnerability pattern, but likely not safe to claim as novel | overlap-filtering / known-issue handling case |
| `Cudy WR3000E / WR1300 V4` | `WR3000E`, `WR1300V4 2.3.8`, `2.4.22` | repeated shell-execution and upgrade/admin helpers | mostly fixed command templates; no equally strong new web-input-to-shell proof yet | supporting pattern family, weaker than primary cases | secondary / supporting case |

---

## Case Summaries

### 1. `ipTIME AX3000M`

Why it is strong:

- same-model multi-version set exists
- hidden diagnostic CGI path was not just heuristic; it was confirmed in Ghidra
- `14.234` and `15.024` retain the old command-capable path
- `15.330` appears to remove or meaningfully restrict it

What the tool contributed:

- triage surfaced `d.cgi` / `popen` relevance quickly
- versioned corpus made recurrence / removal analysis easy
- manual reversing then turned the heuristic into a confirmed case

Why it matters in the paper:

- shows that the pipeline can do more than one-off bug spotting
- supports a strong story about exploitability-aware triage plus version diffing

Key references:

- `report/ipTIME AX3000M/hidden_diagnostic_dcgi_command_execution_analysis.md`
- `research/notes/ax3000m_cudy_followup_20260420.md`

### 2. `TOTOLINK A3002RU`

Why it is strong:

- not a single isolated issue
- three distinct handlers/features show the same insecure shell construction
- recurrence survives later build re-check

What the tool contributed:

- helped surface multiple sink-adjacent handlers in the same product family
- made it easier to compare whether different features reuse the same risky
  command-execution style

Why it matters in the paper:

- this is the best vendor-pattern / recurrence case in the current corpus
- useful for arguing that the tool finds implementation anti-patterns, not just
  isolated bugs

Key references:

- `report/TOTOLINK A3002RU V3/command_injection_recurrence_summary.md`
- `report/TOTOLINK A3002RU V3/formWsc_peerRptPin_command_injection_analysis.md`
- `report/TOTOLINK A3002RU V3/repeater_ssid_command_injection_analysis.md`
- `report/TOTOLINK A3002RU V3/formUploadFile_filename_command_injection_analysis.md`

### 3. `TOTOLINK X6000R`

Why it is strong:

- the surfaced sinks are real and code-level evidence is clean
- the management-plane path into shell execution is easy to explain

Why it is not the best novelty case:

- public overlap risk is high
- the responsible interpretation is to treat it as a known-issue / overlap case
  unless novelty is proven carefully

Why it matters in the paper:

- shows that the workflow does not blindly overclaim novelty
- demonstrates the value of post-triage overlap review

Key references:

- `research/notes/x6000r_mtkwifi_confirmed_review.md`
- `research/notes/x6000r_cve_overlap_assessment_20260420.md`

### 4. `Cudy WR3000E / WR1300 V4`

Why it is weaker:

- visible shell execution exists, but much of it currently looks like fixed
  template execution
- strongest current `WR3000E` case is rule / policy manipulation rather than a
  clean command-execution chain

Why it still matters:

- useful supporting family
- helps show that the tool can surface repeated shell-heavy management logic
  even when manual review later downgrades the exploitability claim

Key references:

- `report/Cudy WR3000E/qos_nftables_rule_injection_analysis.md`
- `research/notes/ax3000m_cudy_followup_20260420.md`

---

## Recommended Paper Ordering

If these are later turned into a paper section, the cleanest order is:

1. `AX3000M`
   - best likely-new deep-dive
2. `A3002RU`
   - best recurrence / repeated anti-pattern case
3. `X6000R`
   - best overlap-filtering case
4. `Cudy`
   - supporting family, not headline case

---

## Bottom Line

The current corpus already supports three distinct and complementary case-study
roles:

- **new-like finding candidate**: `AX3000M`
- **recurrence / anti-pattern case**: `A3002RU`
- **overlap / non-novelty filtering case**: `X6000R`

That combination is stronger than relying on only one “best bug,” because it
shows that the tool contributes to:

- finding
- triaging
- validating
- and correctly classifying firmware security cases
