# Paper Case Studies (2026-04-20)

This note turns the current corpus into a small set of case studies that are
worth manual review, write-up work, and thesis/paper framing.

## Current Snapshot

- corpus: `21` samples
- analyzed successfully: `17`
- blocked: `4`
- reviewed candidates in ledger: `5`
- strongest current vendors:
  - `TOTOLINK`: best single candidate quality
  - `ipTIME`: best same-model version set for recurrence analysis
  - `Cudy`: best secondary command-injection family

## Case Study A: TOTOLINK X6000R

- sample:
  - `inputs/TOTOLINK_C8380R_X6000R_IP04499_MT7981_SPI_16M256M_V9.4.0cu.1498_B20250826_ALL.zip`
- run:
  - `run_20260420_0253_totolink-c8380r-x6000r`
- current status:
  - `LIKELY`
  - confidence `HIGH`
  - cve potential `STRONG`
- why it matters:
  - highest current triage score in the corpus (`85`)
  - script-level web input to `os.execute()` heuristic
  - clean “web management -> shell execution” story
- primary review targets:
  - `usr/lib/lua/luci/controller/mtkwifi.lua`
  - `usr/lib/lua/luci/controller/ipsec.lua`
- concrete next checks:
  - map exact LuCI handler path
  - list form fields read by `http.formvalue()`
  - identify whether any field reaches shell command construction without strict allowlisting
  - decide whether auth is required and whether CSRF can matter
- paper value:
  - strongest standalone write-up candidate
  - useful headline example for “exploitability-aware firmware triage”

## Case Study B: ipTIME AX3000M

- samples:
  - `inputs/ax3000m_ml_14_234.bin`
  - `inputs/ax3000m_ml_15_024.bin`
  - `inputs/ax3000m_ml_15_330.bin`
- focus run:
  - `run_20260420_0241_ax3000m_ml_15_024`
- current status:
  - `NEEDS_MORE_WORK`
  - confidence `MEDIUM`
- why it matters:
  - best same-model version family currently in the corpus
  - good for “pattern recurrence across versions” even if the sink later downgrades
- primary review targets:
  - `home/httpd/192.168.0.1/cgi/d.cgi`
  - `sbin/lighttpd`
- concrete next checks:
  - diff the hidden diagnostic CGI path across `14.234`, `15.024`, `15.330`
  - verify whether `fname` / `cmd` reach the `popen` sink
  - determine whether the `aaksjdkfj` gate is static, derivable, or auth-bound
- paper value:
  - version-comparison figure or table
  - stronger methodology evidence than a single isolated finding

### Current manual note

- `14.234`
  - `timepro.cgi` still contains a hidden diagnostic form with:
    - `fname`
    - `cmd`
    - `aaksjdkfj`
  - the same binary also contains `popen`
- `15.024`
  - dedicated `home/httpd/cgi/d.cgi` exists
  - strings show:
    - `assistance/config`
    - `fname`
    - `cmd`
    - `aaksjdkfj`
    - `popen`
- `15.330`
  - `d.cgi` is absent from the extracted CGI set
  - `ftm.cgi` exposes `_run_cmd` and `get_value_from_query_string`, but the old hidden diagnostic form strings are absent

Interpretation:

- this is now the best same-model recurrence story in the corpus
- the hidden diagnostic path is present in `14.234` and `15.024`
- `15.330` may represent removal or refactoring, which is useful for a version-diff case study
- novelty is still unproven until the `cmd` / `fname` inputs are tied to the `popen` call in code

## Case Study C: Cudy WR3000E / WR1300 V4

- samples:
  - `inputs/WR3000E-R53-2.2.7-20240910-160305-sysupgrade.zip`
  - `inputs/WR1300V4-R98-2.3.8-20250124-115930-flash.zip`
  - `inputs/WR1300V4-R98-2.4.22-20251126-095302-flash.zip`
- focus runs:
  - `run_20260420_0236_wr3000e-r53-2-2-7`
  - `run_20260420_0220_wr1300v4-r98-2-3-8`
  - `run_20260420_0234_wr1300v4-r98-2-4-22`
- current status:
  - `NEEDS_MORE_WORK`
  - confidence `MEDIUM`
- why it matters:
  - repeated administration / upgrade shell-execution pattern
  - two related models make it easier to argue pattern-family recurrence
- primary review targets:
  - `usr/lib/lua/luci/controller/system.lua`
  - `usr/lib/lua/luci/controller/autoupgrade.lua`
- concrete next checks:
  - identify which administration endpoints call `/bin/sh`
  - trace request parameters into command templates
  - compare whether the same helper paths survive across WR1300 versions
- paper value:
  - strong secondary family
  - useful when arguing that the pipeline surfaces repeated vendor patterns, not just isolated bugs

### Current manual note

- `WR1300V4` `2.3.8` and `2.4.22` both still contain:
  - `luci.controller.system`
  - `luci.apprpc.system`
  - `luci.controller.autoupgrade`
- however, the currently visible shell executions are mostly fixed command templates such as:
  - `sleep 1; /etc/init.d/uhttpd stop; /sbin/autoupgrade upgrade`
  - `sleep 1; firstboot && reboot >/dev/null 2>&1`
  - `/usr/lib/diag/%s.sh`
- these are useful for pattern-family discussion, but not yet a clean new web-input-to-shell claim

Interpretation:

- keep Cudy as the secondary family for now
- do not prioritize it over `AX3000M` until a direct attacker-controlled shell argument is confirmed

## What To Ignore For Now

- `Archer C80`
  - extraction is still blocked by rootfs selection issues
- old `TOTOLINK X6000R` RARs
  - blocked by current `7z` RAR decoder support
- `XE75`
  - useful benchmark coverage, but weak current case-study value
- `AX2004M`
  - stable corpus coverage, but lower triage value than `AX3000M`

## Immediate Review Order

1. Confirm whether `AX3000M` `fname` / `cmd` in the hidden diagnostic path reach the `popen` sink.
2. Compare `14.234`, `15.024`, and `15.330` to determine whether the path was removed or merely renamed.
3. Keep `X6000R` as overlap-aware paper material, not an immediate CVE target.
4. Revisit `Cudy` only after a direct attacker-controlled shell argument is found.

## Thesis / Paper Angle

The current corpus already supports a defensible paper narrative:

- broad benchmark:
  - `21` recent consumer-router firmware images across `4` vendors
- engineering contribution:
  - archive handling, nested extraction, and rootfs selection improvements
- security contribution:
  - exploitability-aware triage that promotes web-exposed, sink-relevant cases
- evaluation story:
  - high analysis completion rate (`17 / 21`)
  - repeated command-injection style patterns across multiple vendors and versions
