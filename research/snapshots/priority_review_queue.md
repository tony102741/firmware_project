# Priority Review Queue

This file is the immediate triage queue for turning pipeline output into
paper-grade case studies.

## Tier 1

- `TOTOLINK X6000R`
  - sample: `TOTOLINK_C8380R_X6000R_IP04499_MT7981_SPI_16M256M_V9.4.0cu.1498_B20250826_ALL.zip`
  - run: `run_20260420_0253_totolink-c8380r-x6000r`
  - why:
    - strongest current triage score (`85`)
    - script-level HTTP input to `os.execute()` heuristic
    - web-exposed `HIGH` candidates
    - likely strongest new write-up candidate in the corpus
  - review targets:
    - `usr/lib/lua/luci/controller/mtkwifi.lua`
    - `usr/lib/lua/luci/controller/ipsec.lua`
    - `usr/sbin/cwmpd`

- `ipTIME AX3000M 15.024`
  - sample: `ax3000m_ml_15_024.bin`
  - run: `run_20260420_0241_ax3000m_ml_15_024`
  - why:
    - best ipTIME triage score (`62`)
    - same-model version set exists for recurrence testing
    - useful for a version-diff case study even if the sink later downgrades
  - review targets:
    - `home/httpd/192.168.0.1/cgi/d.cgi`
    - `sbin/lighttpd`

## Tier 2

- `Cudy WR3000E`
  - sample: `WR3000E-R53-2.2.7-20240910-160305-sysupgrade.zip`
  - run: `run_20260420_0236_wr3000e-r53-2-2-7`
  - why:
    - multiple HTTP command-injection style candidates
    - strong upgrade-surface findings for secondary discussion

- `Cudy WR1300 V4`
  - samples:
    - `WR1300V4-R98-2.3.8-20250124-115930-flash.zip`
    - `WR1300V4-R98-2.4.22-20251126-095302-flash.zip`
  - runs:
    - `run_20260420_0220_wr1300v4-r98-2-3-8`
    - `run_20260420_0234_wr1300v4-r98-2-4-22`
  - why:
    - repeated command-injection style candidates across versions
    - strong unsigned-upgrade story

- `TOTOLINK A3002RU`
  - sample: `A3002RU-V3.0.0-B20220304.1804.rar`
  - run: `run_20260420_0232_totolink-a3002ru-hh-v3-0`
  - why:
    - already has an existing ledger family
    - good for showing pattern recurrence within one vendor

## Tier 3

- `Archer AX23`
  - sample: `Archer AX23(US)_1.2_250904.zip`
  - run: `run_20260420_0233_ax23v1-2-us-ca-tw-up`
  - why:
    - completed successfully
    - currently mostly upgrade-surface value, less convincing than Tier 1/2

- `ipTIME AX2004M`
  - samples:
    - `ax2004m_ml_14_234.bin`
    - `ax2004m_ml_15_028.bin`
    - `ax2004m_ml_15_330.bin`
  - why:
    - good benchmark coverage
    - lower current triage value than AX3000M

## Current Blockers

- `Archer C80`
  - both tested versions still fail rootfs selection
  - likely needs TP-Link partition-aware extraction

- `TOTOLINK X6000R` old RAR images
  - blocked by current `7z` RAR decoder limitations
