# AX3000M / Cudy Follow-up (2026-04-20)

This note continues the 2026-04-20 session after deciding that `TOTOLINK X6000R`
should be treated as likely-overlapping paper material rather than an immediate
new-CVE claim.

## Short Answer

- best next manual target: `ipTIME AX3000M`
- best current hypothesis:
  - hidden diagnostic CGI path present in `14.234` and `15.024`
  - likely changed or removed in `15.330`
- Cudy status:
  - still useful as a repeated shell-execution family
  - not yet a strong new-report candidate because the currently visible shell
    commands are mostly fixed templates

## AX3000M Findings

### Samples checked

- `inputs/ax3000m_ml_14_234.bin`
- `inputs/ax3000m_ml_15_024.bin`
- `inputs/ax3000m_ml_15_330.bin`

### `14.234`

Extracted CGI set includes:

- `/tmp/fw_ax3000m/root14x/cgibin/timepro.cgi`
- `/tmp/fw_ax3000m/root14x/cgibin/m.cgi`
- `/tmp/fw_ax3000m/root14x/cgibin/upgrade.cgi`

Relevant strings in `timepro.cgi`:

- `popen`
- `sysconf_misc_configmgmt_submit`
- `sysconf_misc_configmgmt_restore`
- hidden form fields:
  - `fname`
  - `cmd`
  - `aaksjdkfj`

The binary embeds a diagnostic/debug-style form:

- `<form method=get action="d.cgi" name="dform">`
- `File Name : <input type=text name="fname" ...>`
- `Command Name : <input type=text name="cmd" ...>`
- `<input type=text name="aaksjdkfj" value="%s" ...>`

Interpretation:

- the older firmware still contains the hidden diagnostic interface inside
  `timepro.cgi`
- this is more specific than the earlier generic `/config -> popen` heuristic

### `15.024`

Extracted CGI set includes:

- `/tmp/fw_ax3000m/root15_024x/home/httpd/cgi/d.cgi`

Relevant strings in `d.cgi`:

- `popen`
- `assistance/config`
- `fname`
- `cmd`
- `aaksjdkfj`
- same hidden HTML form fields as above

Interpretation:

- by `15.024`, the diagnostic functionality appears to have been moved into a
  standalone CGI binary
- this is currently the cleanest `AX3000M` lead
- code-level chain confirmed:
  - `call_service_bool("assistance/config", 0)`
  - `check_default_pass()`
  - `check_csrf_attack()`
  - `httpcon_auth(1, 0)`
  - `get_value(..., "aaksjdkfj", ...)`
  - literal compare against `!@dnjsrurelqjrm*&`
  - `get_value(..., "cmd", ...)`
  - append `" 2>&1"`
  - `popen(cmd, "r")`
- `fname` is a secondary file-read path, but the main issue is authenticated
  direct command execution through `cmd`

### `15.330`

Extracted CGI set includes:

- `/tmp/fw_ax3000m/root15_330x/home/httpd/cgi/ftm.cgi`
- `/tmp/fw_ax3000m/root15_330x/home/httpd/cgi/upload.cgi`
- `/tmp/fw_ax3000m/root15_330x/home/httpd/cgi/download.cgi`

Relevant strings in `ftm.cgi`:

- `_run_cmd`
- `get_value_from_query_string`

Notably absent:

- `d.cgi`
- `fname`
- `cmd`
- `aaksjdkfj`
- visible hidden diagnostic form strings

Interpretation:

- there is a real version delta here
- the old hidden diagnostic path may have been removed, renamed, or folded into
  another CGI
- this makes `AX3000M` a good recurrence/diff case study with a confirmed sink
  in `15.024` and a near-identical older path in `14.234`
- `ftm.cgi` is not an obvious drop-in replacement for the old backdoor-like
  path:
  - it only exposes `get_value_from_query_string` and `_run_cmd`
  - disassembly shows no visible `cmd` / `aaksjdkfj` / `popen` style interface
  - current best interpretation is removal or major redesign, not simple rename

## Cudy WR1300V4 Findings

### Samples checked

- `inputs/WR1300V4-R98-2.3.8-20250124-115930-flash.zip`
- `inputs/WR1300V4-R98-2.4.22-20251126-095302-flash.zip`

### Present in both versions

- `usr/lib/lua/luci/controller/system.lua`
- `usr/lib/lua/luci/apprpc/system.lua`
- `usr/lib/lua/luci/controller/autoupgrade.lua`

Visible shell-command strings include:

- `sleep 1; /etc/init.d/uhttpd stop; /sbin/autoupgrade upgrade`
- `sleep 1; firstboot && reboot >/dev/null 2>&1`
- `sleep 1; /etc/init.d/uhttpd stop; reboot`
- `/usr/lib/diag/%s.sh`

### Current interpretation

- there is definitely shell execution in the management stack
- however, the currently visible commands are mostly fixed templates or appear
  to be driven by internal route selection rather than a clearly attacker-
  controlled shell fragment
- this is still useful for a cross-version vendor-family discussion, but it is
  weaker than the current `AX3000M` lead

## Recommended Next Step

Do next:

1. reverse the `AX3000M` `d.cgi` / `timepro.cgi` diagnostic handler at the
   function level
2. confirm whether `fname` and `cmd` flow into the `popen` call
3. determine whether `aaksjdkfj` is:
   - static
   - derived from device state
   - auth/session gated
4. compare that handler with `15.330` `ftm.cgi` to see whether the path was
   actually removed or just renamed

Do not do next:

- do not spend another session trying to upgrade `X6000R` into a new CVE claim
- do not prioritize `Cudy` over `AX3000M` until a direct user-input-to-shell
  edge is confirmed

## Additional Follow-up

### Cudy WR3000E re-check

Relevant files from the completed run:

- `runs/run_20260420_0236_wr3000e-r53-2-2-7/ghidra_targets/system.lua`
- `runs/run_20260420_0236_wr3000e-r53-2-2-7/ghidra_targets/autoupgrade.lua`

Observed shell-related strings:

- `reboot >/dev/null 2>&1`
- `sleep 1; firstboot && reboot >/dev/null 2>&1`
- `/etc/init.d/led reload`
- `/etc/init.d/system reload`
- `/sbin/autoupgrade check`
- `sleep 1; /etc/init.d/uhttpd stop; /sbin/autoupgrade upgrade`

Current interpretation:

- the earlier `/administration -> /bin/sh` triage claim looks overstated
- the visible execution paths are mostly fixed `fork_exec()` command templates
- this still supports a paper case about repeated shell execution in the
  management stack
- it is not currently a strong new command-execution report candidate

The stronger `WR3000E` case remains the already-documented QoS / `nft-qos`
rule-manipulation path, but that is a configuration-injection / policy-tamper
story rather than a clean web-input-to-shell RCE case.

### ipTIME AX2004M quick comparison

Corpus entries exist for:

- `inputs/ax2004m_ml_14_234.bin`
- `inputs/ax2004m_ml_15_028.bin`
- `inputs/ax2004m_ml_15_330.bin`

Quick review of the completed run outputs shows:

- no obvious `timepro.cgi`
- no obvious standalone `d.cgi`
- no visible `aaksjdkfj` / hidden diagnostic gate strings
- no immediate replay of the `AX3000M` hidden diagnostic CGI pattern in the
  saved run artifacts

Current interpretation:

- `AX2004M` is not yet a same-family recurrence win on the evidence currently
  preserved in the run outputs
- unless fresh extraction shows hidden CGI binaries that were missed by the
  saved triage targets, `AX3000M` remains the stronger ipTIME case
