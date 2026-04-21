# Firmware Target List

This file is the concrete phase-one collection shortlist.
Use it to keep vendor/model/version selection disciplined before the corpus grows too large.

## Current Priority

- `TOTOLINK`
  - `A3002RU`
    - `V3.0.0-B20201208`
    - `V3.0.0-B20220304.1804`
    - `V3.0.0-B20230809.1615`
  - `X6000R`
    - `V9.4.0cu.652_B20230116`
    - `V9.4.0cu.1360_B20241207_ALL`
    - `V9.4.0cu.1498_B20250826`

- `TP-Link`
  - `Archer C80`
    - `V2.2_230609`
    - `V2.2_240617`
  - `Archer AX23`
    - `1.2_250904`
  - `XE75 / XE5300 / WE10800`
    - `ver1-2-14-20241015`
    - `1.3.1 P1 [20251023-rel43624]`

- `ipTIME`
  - `AX2004M`
    - `14.234`
    - `15.028`
    - `15.330`
  - `AX3000M`
    - `14.234`
    - `15.024`
    - `15.330`

- `Cudy`
  - `WR3000E`
    - `R53-2.2.7-20240910-160305`
    - `R53-2.4.7-20250528-182254`
  - `WR1300 V4`
    - `R98-2.3.8-20250124-115930`
    - `R98-2.4.22-20251126-095302`

## Notes

- Keep old versions even if a newer one exists.
- Prefer running one representative version per model first, then fill the version gap.
- If a filename is ambiguous, keep the raw filename in the corpus and verify vendor/model later from the original source page.
