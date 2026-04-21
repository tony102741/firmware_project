# Holdout Blind Predictions — 2026-04-22

원칙:
- 아래 결론은 `results.json`, `llm_review packet`, 기존 도구 라벨을 보지 않고
  신규 `inputs/` raw artifact만 보고 먼저 적은 것이다.
- 목표는 과적합을 줄이기 위해 "도구 이전 판단"을 고정하는 것이다.

## Blind Predictions

| Input | Vendor/Model | Raw Observations | Blind Conclusion |
|---|---|---|---|
| `FW_MX4200_2.0.7.216620_prod.img` | Linksys `MX4200` | DTB-like signed image, `squashfs`, `boa`, `LinksysSigned` 흔적 | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |
| `FW_MX42SH_1.0.10.210447_prod.img` | Linksys `MX42SH` | DTB-like signed image, `squashfs`, `boa`, `LinksysSigned` 흔적 | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |
| `FW_RT_AX58U_300438825127.zip` | ASUS `RT-AX58U` | inner `.w`, `rootfs_ubifs`, `micro_httpd`, `boa`, `ASUSSPACELINK` | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |
| `FW_RT_AX58U_300438825155.zip` | ASUS `RT-AX58U` | same family layout as above | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |
| `FW_RT_AX58U_300438825277.zip` | ASUS `RT-AX58U` | same family layout as above | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |
| `RAX50-V1.0.0.30_2.0.20.zip` | NETGEAR `RAX50` | inner `.chk`, `rootfs_ubifs`, `micro_httpd`, Broadcom/UBI layout | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |
| `SRM_RT6600ax_9366.pat` | Synology `RT6600ax` | tar-like package, many firmware blobs + `hda1.tgz`/packages, package-style delivery | `rootfs-success`, `has_web_ui=true`, `top_risk_family=no-clear-rce`, `best_next_action=review-artifacts` |

## Notes

- 이번 holdout은 일부러 보수적으로 적었다.
- raw artifact 수준에서 곧바로 `cmd-injection`, `crypto-risk`, `memory-corruption`를 주장할 정도의 직접 근거는 아직 못 봤다.
- 따라서 도구가 이 7개에서 강한 위험 family를 올린다면, 그 근거가 진짜 구조적 단서인지 아니면 과잉 triage인지 검증해야 한다.
