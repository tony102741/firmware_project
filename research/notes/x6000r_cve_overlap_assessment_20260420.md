# X6000R CVE Overlap Assessment (2026-04-20)

This note answers a specific question:

- are the `X6000R` findings in this repo likely new CVEs?
- or do they overlap with already published `X6000R` disclosures?

## Short Answer

They are **probably not safe to claim as new CVEs yet**.

The strongest reason is that `CVE-2026-1723` already exists for
`TOTOLINK X6000R` **through `V9.4.0cu.1498_B20250826`**, which is the same
firmware version we analyzed locally.

## Public CVEs Relevant To This Firmware Family

Older public disclosures from Unit 42 / Palo Alto Networks:

- `CVE-2025-52905`
  - `V9.4.0cu.1360_B20241207` and earlier
  - argument injection / DoS
- `CVE-2025-52906`
  - `V9.4.0cu.1360_B20241207` and earlier
  - unauthenticated command injection in `setEasyMeshAgentCfg`
- `CVE-2025-52907`
  - `V9.4.0cu.1360_B20241207` and earlier
  - security bypass / file manipulation via `setWizardCfg`

Newer public disclosure:

- `CVE-2026-1723`
  - affects `X6000R` through `V9.4.0cu.1498_B20250826`
  - generic published description: OS command injection

## What We Verified Locally

Firmware analyzed:

- `TOTOLINK_C8380R_X6000R_IP04499_MT7981_SPI_16M256M_V9.4.0cu.1498_B20250826_ALL.zip`

Confirmed local findings:

1. `apcli_cfg()` -> `apcli_connect()`
   - attacker-controlled values are copied from `http.formvalue()`
   - saved into profile data
   - later concatenated into `os.execute("iwpriv ...")`
   - escaping is incomplete

2. `submit_dpp_uri()`
   - `uri = http.formvalue("uri")`
   - directly concatenated into `os.execute("wappctrl ra0 dpp dpp_qr_code ...")`

These are documented in:

- `research/notes/x6000r_mtkwifi_confirmed_review.md`

## Why This Looks Like Overlap Rather Than A Clean New CVE

### 1. Same affected version family

The firmware we analyzed is exactly the version family named in
`CVE-2026-1723`:

- local sample: `1498`
- public CVE: affects through `1498`

That alone makes “new CVE” a weak claim unless we can prove the public CVE is
about a different function and a different root cause.

### 2. Publicly disclosed API still exists in `1498`

Inside `web/static/js/topicurl.js`, the UI still exposes:

- `setEasyMeshAgentCfg`
- `setWizardCfg`
- requests routed to `/cgi-bin/cstecgi.cgi`

That matches the public Unit 42 write-up pattern:

- `/cgi-bin/cstecgi.cgi`
- `topicurl`
- `setEasyMeshAgentCfg`
- `setWizardCfg`

### 3. Our findings are in a different code path, but same vulnerability class

Our local confirmed paths live in `luci.controller.mtkwifi.lua`, not in the
published `cstecgi.cgi` write-up.

So the most conservative interpretation is:

- same product
- same affected version family
- same broad class (`OS command injection`)
- likely same disclosure family or adjacent variants

That is enough overlap that a fresh CVE claim would be premature.

## What We Could Not Yet Verify

- we could not extract `V9.4.0cu.1360_B20241207_ALL.rar` in this environment
  because the current `7z` build can list it but cannot decode the member
  compression method
- we therefore could not do a direct local file diff of `1360` vs `1498`
- we also did not inspect the exact `cstecgi.cgi` dispatcher implementation in
  a disassembler yet

## Practical Conclusion

Current recommendation:

- treat the `1498` findings as **likely overlapping with already published
  public research**, especially `CVE-2026-1723`
- do **not** pitch these two `mtkwifi.lua` paths as confidently “new CVEs”
  right now
- do use them as:
  - strong paper case-study material
  - evidence that command-injection risk remains easy to surface in this
    product line
  - a basis for deeper variant analysis

## Best Next Step

If we want to separate “known issue” from “new variant,” the next step is not
another broad scan. It is targeted reverse engineering:

1. inspect the `cstecgi.cgi` handling path in the web server / dispatcher
2. determine what exact function PANW likely used for `CVE-2026-1723`
3. compare that root cause with:
   - `apcli_cfg` -> `apcli_connect`
   - `submit_dpp_uri`

If the vulnerable functions and reachable attack paths are materially distinct,
then the `mtkwifi.lua` findings may still support a **variant** report. But
today, the safer conclusion is “overlap likely.”
