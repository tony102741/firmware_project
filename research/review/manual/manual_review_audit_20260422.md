# Manual Review Audit - Inputs Corpus 2026-04-22

## Summary

- packet rows: `30`
- manual rows: `30`
- missing manual reviews: `0`
- mismatch kinds: `{}`

| Field | Accuracy | Correct / Total |
|---|---:|---:|
| `has_rootfs` | `1.0000` | `30 / 30` |
| `has_web_ui` | `1.0000` | `30 / 30` |
| `artifact_kind` | `1.0000` | `30 / 30` |
| `probe_readiness` | `1.0000` | `30 / 30` |
| `blob_family` | `1.0000` | `30 / 30` |
| `encrypted_container` | `1.0000` | `30 / 30` |
| `best_next_action` | `1.0000` | `30 / 30` |
| `top_risk_family` | `1.0000` | `30 / 30` |

## Per Input

| Review ID | Vendor | Model | Engine Risk | Manual Risk | Action | Status |
|---|---|---|---|---|---|---|
| `totolink-a3002ru-v3-0-0-b20201208` | TOTOLINK | A3002RU | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `totolink-a3002ru-v3-0-0-b20230809-1615` | TOTOLINK | A3002RU | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `wr3000e-r53-2-4-7-20250528-182254` | Cudy | WR3000E | `upgrade-risk` | `upgrade-risk` | `triage-top-candidates` | `MATCH` |
| `tp-link-xe75-xe5300-we10800-sp1-ver1-3-1-p1-20251023` | TP-Link | XE75 / XE5300 / WE10800 | `crypto-risk` | `crypto-risk` | `triage-top-candidates` | `MATCH` |
| `totolink-a3002ru-v3-0-0-b20220304-1804` | TOTOLINK | A3002RU | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `tp-link-archer-ax23-1-2-250904` | TP-Link | Archer AX23 | `upgrade-risk` | `upgrade-risk` | `triage-top-candidates` | `MATCH` |
| `tp-link-archer-c80-v2-2-230609` | TP-Link | Archer C80 | `container-analysis` | `container-analysis` | `inspect-segmented-bundle` | `MATCH` |
| `tp-link-archer-c80-v2-2-240617` | TP-Link | Archer C80 | `container-analysis` | `container-analysis` | `inspect-segmented-bundle` | `MATCH` |
| `totolink-x6000r-v9-4-0cu-1498-b20250826-all` | TOTOLINK | X6000R | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `totolink-x6000r-v9-4-0cu-1360-b20241207-all` | TOTOLINK | X6000R | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `cudy-wr1300-v4-r98-2-3-8-20250124-115930` | Cudy | WR1300 V4 | `upgrade-risk` | `upgrade-risk` | `triage-top-candidates` | `MATCH` |
| `cudy-wr1300-v4-r98-2-4-22-20251126-095302` | Cudy | WR1300 V4 | `upgrade-risk` | `upgrade-risk` | `triage-top-candidates` | `MATCH` |
| `cudy-wr3000e-r53-2-2-7-20240910-160305` | Cudy | WR3000E | `upgrade-risk` | `upgrade-risk` | `triage-top-candidates` | `MATCH` |
| `totolink-x6000r-v9-4-0cu-652-b20230116` | TOTOLINK | X6000R | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `tp-link-xe75-xe5300-we10800-ver1-2-14-20241015` | TP-Link | XE75 / XE5300 / WE10800 | `crypto-risk` | `crypto-risk` | `triage-top-candidates` | `MATCH` |
| `iptime-ax2004m-14-234` | ipTIME | AX2004M | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `iptime-ax2004m-15-028` | ipTIME | AX2004M | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `iptime-ax2004m-15-330` | ipTIME | AX2004M | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `iptime-ax3000m-14-234` | ipTIME | AX3000M | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `iptime-ax3000m-15-024` | ipTIME | AX3000M | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `iptime-ax3000m-15-330` | ipTIME | AX3000M | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `totolink-a3002ru-v3-0-0-b20210302-1639` | TOTOLINK | A3002RU | `cmd-injection` | `cmd-injection` | `triage-top-candidates` | `MATCH` |
| `mercusys-mr60x-v2-20-1-1-0-build-2025111220251231070005` | MERCUSYS | MR60X | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `mercusys-mr70x-v2-1-2-0-build-2025090420251106082258` | MERCUSYS | MR70X | `container-analysis` | `container-analysis` | `inspect-container-payload` | `MATCH` |
| `mercusys-mr90x-eu-v1-20-23080820240123090924` | MERCUSYS | MR90X (EU) | `memory-corruption` | `memory-corruption` | `triage-top-candidates` | `MATCH` |
| `tenda-ax12pro-v3-0-16-03-68-19-td01` | Tenda | AX12Pro | `container-analysis` | `container-analysis` | `run-decrypt-probe` | `MATCH` |
| `tenda-tx2pro-v1-0-16-03-30-26-multi-tde01` | Tenda | TX2Pro | `container-analysis` | `container-analysis` | `run-decrypt-probe` | `MATCH` |
| `gl-inet-gl-mt3000-4-8-1` | GL.iNet | GL-MT3000 | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `gl-inet-gl-mt6000-4-8-4-release2-879-0330` | GL.iNet | GL-MT6000 | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
| `gl-inet-gl-x3000-4-8-3-release3-902-1106` | GL.iNet | GL-X3000 | `no-clear-rce` | `no-clear-rce` | `review-artifacts` | `MATCH` |
