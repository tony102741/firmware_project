# Holdout Blind vs Tool Comparison — 2026-04-22

목적:
- 신규 `inputs/` 7개를 기존 30개 학습 코퍼스와 분리된 holdout처럼 취급한다.
- 먼저 raw artifact만 보고 보수적으로 결론을 적는다.
- 그 다음 도구를 돌려 결과를 비교한다.
- 차이가 있더라도 바로 벤더별 규칙을 넣지 않고, 구조적으로 일반화 가능한 부분만 흡수한다.

## Compared Samples

| Sample | Blind First Conclusion | Tool Final Conclusion | Assessment |
|---|---|---|---|
| `FW_MX4200_2.0.7.216620_prod.img` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `blob-success`, `container-analysis`, `expand-binary-signals` | 도구가 더 보수적이다. 구조적으로는 signed blob에 가깝고, 강한 취약점 주장은 없어 일단 수용 가능 |
| `FW_MX42SH_1.0.10.210447_prod.img` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `blob-success`, `container-analysis`, `expand-binary-signals` | MX4200과 동일. 과장된 위험 family가 아니라서 수용 가능 |
| `FW_RT_AX58U_300438825127.zip` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `rootfs-success`, `cmd-injection`, `triage-top-candidates` | 차이 남음. 아직 흡수하지 않음 |
| `FW_RT_AX58U_300438825155.zip` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `rootfs-success`, `cmd-injection`, `triage-top-candidates` | 차이 남음. 아직 흡수하지 않음 |
| `FW_RT_AX58U_300438825277.zip` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `rootfs-success`, `cmd-injection`, `triage-top-candidates` | 차이 남음. 아직 흡수하지 않음 |
| `RAX50-V1.0.0.30_2.0.20.zip` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `rootfs-success`, `no-clear-rce`, `triage-top-candidates` | 거의 일치. 도구 쪽이 rootfs 추출과 triage를 더 진행 |
| `SRM_RT6600ax_9366.pat` | `rootfs-success`, `no-clear-rce`, `review-artifacts` | `blob-success`, `container-analysis`, `expand-binary-signals` | 도구가 더 보수적이다. package/blob 계열로 남긴 것은 합리적 |

## What Was Absorbed

이번 holdout에서 실제로 흡수한 변경은 벤더명이 아니라 `증거 수준` 기반이다.

- `summary.blob_candidates > 0`이면 `PARTIAL` 대신 `SUCCESS`로 본다.
- `analysis.system_path`가 있으면, 취약점 후보가 0이어도 `SUCCESS`로 본다.
- `general + blob evidence`는 `blob-success`로 분류한다.
- `blob-success` 또는 `blob/container probe-ready` 상태의 risk family는 `container-analysis` 쪽으로 보수적으로 묶는다.

이 변경으로 다음이 개선됐다.

- Linksys `MX4200`, `MX42SH`
  - 기존: `PARTIAL`
  - 현재: `SUCCESS / blob-success / blob-ready`
- NETGEAR `RAX50`
  - extracted filesystem이 있는데도 후보 0이라 애매했던 상태를 `SUCCESS / rootfs-success`로 안정화
- Synology `RT6600ax`
  - `blob-success`인데도 과장된 `cmd-injection`으로 튀지 않게 정리

## What Was Intentionally Not Absorbed

ASUS `RT-AX58U` 3개는 blind first 결론과 아직 차이가 남아 있다.

- blind first:
  - `rootfs-success`
  - `no-clear-rce`
  - `review-artifacts`
- tool:
  - `rootfs-success`
  - `cmd-injection`
  - `triage-top-candidates`

이 차이는 아직 코드에 흡수하지 않았다.

이유:
- 현재 도구가 `httpd`를 상위 후보로 올리긴 하지만, blind raw review 시점에는 곧바로 `cmd-injection`으로 확정할 정도의 직접 근거를 충분히 못 봤다.
- 여기서 바로 `ASUS면 cmd-injection` 또는 `micro_httpd/boa가 보이면 cmd-injection` 같은 규칙을 넣으면 과적합 위험이 크다.
- 따라서 이 케이스는 추가 확인 전까지 `known mismatch`로 남겨두는 게 맞다.

## Outcome

holdout 7개 기준으로 보면 이번 턴의 평가는 이렇다.

- 성공적 흡수:
  - Linksys 2개
  - NETGEAR 1개
  - Synology 1개
- 이미 거의 일치:
  - NETGEAR 1개
- 의도적 보류:
  - ASUS 3개

즉 이번 holdout은 `새 벤더 7개를 넣었더니 바로 다 맞췄다`가 아니라,
`과적합 없이 구조적 성공 판정과 보수적 blob/container triage를 일반화했고, ASUS처럼 애매한 강한 판정은 일부러 남겨뒀다`가 정확한 결론이다.
