# Manual Review Queue

- queue size: 15

## 1. TP-Link / Archer C80 / V2.2_230609

- `review_id`: `tp-link-archer-c80-v2-2-230609`
- `priority_score`: `-886`
- `review_status`: `REVIEWED`
- `success_quality`: `blob-success`
- `probe_readiness`: `bundle-probe-ready`
- `blob_family`: `tp-link-segmented-bundle`
- `priority_reasons`: bundle-probe-ready, blob-family:tp-link-segmented-bundle, general-mode, already-reviewed
- top candidate: `_c80v2.2-up-noboot_2023-06-09_09.17.23.bin.extracted::D4:blob-signal` (LOW)
- summary: web/admin strings: http, https, login, password; execution strings: bootcmd, command, exec

## 2. TP-Link / Archer C80 / V2.2_240617

- `review_id`: `tp-link-archer-c80-v2-2-240617`
- `priority_score`: `-886`
- `review_status`: `REVIEWED`
- `success_quality`: `blob-success`
- `probe_readiness`: `bundle-probe-ready`
- `blob_family`: `tp-link-segmented-bundle`
- `priority_reasons`: bundle-probe-ready, blob-family:tp-link-segmented-bundle, general-mode, already-reviewed
- top candidate: `_nested_1F79D6.7z::_decoded.bin:blob-signal` (LOW)
- summary: web/admin strings: goform, login, password, portal; execution strings: exec

## 3. Tenda / AX12Pro / V3.0_16.03.68.19_TD01

- `review_id`: `tenda-ax12pro-v3-0-16-03-68-19-td01`
- `priority_score`: `-891`
- `review_status`: `REVIEWED`
- `success_quality`: `blob-success`
- `probe_readiness`: `decrypt-probe-ready`
- `blob_family`: `tenda-openssl-container`
- `priority_reasons`: decrypt-probe-ready, blob-family:tenda-openssl-container, general-mode, already-reviewed
- top candidate: `US_AX12ProV3.0hi_V16.03.68.19_TD01.bin:container-signal` (LOW)
- summary: encrypted or signed vendor firmware container detected (Tenda-style encrypted firmware container): OpenSSL Salted__ header

## 4. Tenda / TX2Pro / V1.0_16.03.30.26_multi_TDE01

- `review_id`: `tenda-tx2pro-v1-0-16-03-30-26-multi-tde01`
- `priority_score`: `-891`
- `review_status`: `REVIEWED`
- `success_quality`: `blob-success`
- `probe_readiness`: `decrypt-probe-ready`
- `blob_family`: `tenda-openssl-container`
- `priority_reasons`: decrypt-probe-ready, blob-family:tenda-openssl-container, general-mode, already-reviewed
- top candidate: `US_TX2ProV1.0re_V16.03.30.26_multi_TDE01.bin:container-signal` (LOW)
- summary: encrypted or signed vendor firmware container detected (Tenda-style encrypted firmware container): OpenSSL Salted__ header

## 5. MERCUSYS / MR70X / V2_1.2.0_Build_2025090420251106082258

- `review_id`: `mercusys-mr70x-v2-1-2-0-build-2025090420251106082258`
- `priority_score`: `-896`
- `review_status`: `REVIEWED`
- `success_quality`: `blob-success`
- `probe_readiness`: `scan-probe-ready`
- `blob_family`: `mercusys-cloud-container`
- `priority_reasons`: scan-probe-ready, blob-family:mercusys-cloud-container, general-mode, already-reviewed
- top candidate: `MR70Xv2-up-ver1-2-0-P1[20250904-rel80221]-2048_nosign_2025-09-05_09.24.33.bin:container-signal` (LOW)
- summary: encrypted or signed vendor firmware container detected (TP-Link/MERCUSYS cloud firmware container): fw-type:cloud; Cloud-tagged firmware bundle; unsigned/nosign build marker

## 6. Cudy / WR1300 V4 / R98-2.3.8-20250124-115930

- `review_id`: `cudy-wr1300-v4-r98-2-3-8-20250124-115930`
- `priority_score`: `-984`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, missing-links, no-handler-surface, already-reviewed
- top candidate: `system.lua` (LOW)
- summary: pre-auth HTTP Command Injection via administration → /bin/sh
- missing links: exact_input_unknown

## 7. Cudy / WR1300 V4 / R98-2.4.22-20251126-095302

- `review_id`: `cudy-wr1300-v4-r98-2-4-22-20251126-095302`
- `priority_score`: `-984`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, missing-links, no-handler-surface, already-reviewed
- top candidate: `system.lua` (LOW)
- summary: pre-auth HTTP Command Injection via administration → /bin/sh
- missing links: exact_input_unknown

## 8. Cudy / WR3000E / R53-2.2.7-20240910-160305

- `review_id`: `cudy-wr3000e-r53-2-2-7-20240910-160305`
- `priority_score`: `-984`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, missing-links, no-handler-surface, already-reviewed
- top candidate: `system.lua` (LOW)
- summary: pre-auth HTTP Command Injection via administration → /bin/sh
- missing links: exact_input_unknown

## 9. Cudy / WR3000E / R53-2.4.7-20250528-182254

- `review_id`: `wr3000e-r53-2-4-7-20250528-182254`
- `priority_score`: `-984`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, missing-links, no-handler-surface, already-reviewed
- top candidate: `system.lua` (LOW)
- summary: pre-auth HTTP Command Injection via administration → /bin/sh
- missing links: exact_input_unknown

## 10. TP-Link / Archer AX23 / 1.2_250904

- `review_id`: `tp-link-archer-ax23-1-2-250904`
- `priority_score`: `-984`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, missing-links, no-handler-surface, already-reviewed
- top candidate: `firmware.lua` (LOW)
- summary: post-auth HTTP Command Injection via accountmgnt → | grep -v grep | grep -v '/bin/sh' | awk '{print $1}'
- missing links: auth_boundary_unknown

## 11. GL.iNet / GL-MT3000 / 4.8.1

- `review_id`: `gl-inet-gl-mt3000-4-8-1`
- `priority_score`: `-986`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, no-handler-surface, already-reviewed
- top candidate: `pc_schedule` (LOW)
- summary: Shell script unquoted variable injection via rule, config, id

## 12. GL.iNet / GL-MT6000 / 4.8.4-release2-879-0330

- `review_id`: `gl-inet-gl-mt6000-4-8-4-release2-879-0330`
- `priority_score`: `-986`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, no-handler-surface, already-reviewed
- top candidate: `pc_schedule` (LOW)
- summary: Shell script unquoted variable injection via rule, config, id

## 13. GL.iNet / GL-X3000 / 4.8.3-release3-902-1106

- `review_id`: `gl-inet-gl-x3000-4-8-3-release3-902-1106`
- `priority_score`: `-986`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, no-handler-surface, already-reviewed
- top candidate: `pc_schedule` (LOW)
- summary: Shell script unquoted variable injection via rule, config, id

## 14. MERCUSYS / MR60X / V2.20_1.1.0_Build_2025111220251231070005

- `review_id`: `mercusys-mr60x-v2-20-1-1-0-build-2025111220251231070005`
- `priority_score`: `-986`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, no-handler-surface, already-reviewed
- top candidate: `wifi_check_country` (LOW)
- summary: Shell script unquoted variable injection via country, country, device

## 15. ipTIME / AX2004M / 14.234

- `review_id`: `iptime-ax2004m-14-234`
- `priority_score`: `-986`
- `review_status`: `REVIEWED`
- `success_quality`: `rootfs-success`
- `probe_readiness`: `rootfs-ready`
- `blob_family`: `none`
- `priority_reasons`: weak-top-candidate, no-handler-surface, already-reviewed
- top candidate: `unit_test.sh` (LOW)
- summary: Shell script unquoted variable injection via FILENAME, DOWNLOAD_URL
