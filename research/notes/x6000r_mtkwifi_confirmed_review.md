# X6000R `mtkwifi.lua` Confirmed Review

Sample:
- `inputs/TOTOLINK_C8380R_X6000R_IP04499_MT7981_SPI_16M256M_V9.4.0cu.1498_B20250826_ALL.zip`

Run:
- `run_20260420_0253_totolink-c8380r-x6000r`

## Confirmed Finding 1: `apcli_cfg` -> `apcli_connect`

Relevant code paths:
- `luci.controller.mtkwifi.index()`
  - registers `admin/mtk/wifi/apcli_cfg`
  - registers `admin/mtk/wifi/apcli_connect`
- `apcli_cfg(dev, vif)`
  - copies form keys into `cfgs` with:
    - `for k,v in pairs(http.formvalue()) do`
    - `cfgs[k] = v`
- `apcli_connect(dev, vif)`
  - loads the saved profile and executes:
    - `os.execute("iwpriv "..vifname.." set ApCliWPAPSK=\""..mtkwifi.__handleSpecialChars(cfgs.ApCliWPAPSK).."\"")`
    - `os.execute("iwpriv "..vifname.." set ApCliSsid=\""..mtkwifi.__handleSpecialChars(cfgs.ApCliSsid).."\"")`

Escaping helper:
- `mtkwifi.__handleSpecialChars(s)`
  - escapes only:
    - `\\`
    - `"`

Why this is still injectable:
- `os.execute()` runs through `/bin/sh -c`
- shell command substitution using `` `...` `` or `$(...)` still happens inside double quotes
- the helper does not escape:
  - `$`
  - backticks
  - shell metacharacters in a shell-safe way

Impact:
- authenticated admin user can place command-substitution payloads into Wi-Fi client values
- command runs as root when `apcli_connect()` applies the configuration

Example payload idea:
- `ApCliSsid=$(touch /tmp/pwned)`

## Confirmed Finding 2: `submit_dpp_uri()`

Relevant code path:
- `luci.controller.mtkwifi.index()`
  - registers `admin/mtk/multi_ap/submit_dpp_uri`
- `submit_dpp_uri()`
  - `uri = http.formvalue("uri")`
  - `os.execute("wappctrl ra0 dpp dpp_qr_code ".."\""..uri.."\"")`

Why this is confirmed:
- user-controlled `uri` is concatenated directly into an `os.execute()` string
- there is no escaping, allowlist, or validation before shell execution

Impact:
- authenticated admin user can inject shell syntax through the EasyMesh DPP URI flow
- command runs as root

Example payload idea:
- `uri=$(touch /tmp/dpp_pwned)`

## Assessment

This firmware now has at least two code-confirmed authenticated command-injection
paths inside the same LuCI controller:

1. Wi-Fi client configuration apply flow
2. EasyMesh DPP URI submission flow

That makes `X6000R` the strongest current case study in the corpus.
