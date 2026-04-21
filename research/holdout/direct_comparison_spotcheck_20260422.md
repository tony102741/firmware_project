# Direct Comparison Spot Check — 2026-04-22

목적:
- 현재 도구 결과와 직접 분석 결과를 몇 건 골라 비교한다.
- "LLM급 판단력 증류"가 실제로 작동하는지 확인한다.

샘플:
1. `iptime-ax3000m-15-024`
2. `tp-link-xe75-xe5300-we10800-sp1-ver1-3-1-p1-20251023`
3. `mercusys-mr90x-eu-v1-20-23080820240123090924`

---

## 1. ipTIME AX3000M 15.024

도구 packet 기준:
- top candidate: `d.cgi`
- engine state: `rootfs-success`, `rootfs-ready`, `web_surface_detected=true`
- 핵심 근거:
  - `/config`
  - `popen`
  - `d.cgi`
  - 비공개 diagnostic CGI 흔적

직접 분석:
- 기존 보고서 기준 `d.cgi`는 standalone 비공개 진단 CGI다.
- 인증, CSRF, 비공개 gate(`aaksjdkfj`) 이후 `cmd -> popen()` 경로가 직접 확인돼 있다.
- 따라서 본질은 generic local helper가 아니라 "숨은 진단 인터페이스의 명령 실행"이다.

직접 판정:
- `artifact_kind`: `rootfs-success`
- `best_next_action`: `triage-top-candidates`
- `top_risk_family`: `cmd-injection`

비교:
- 현재 도구 판단과 직접 분석 결론이 일치한다.
- 의미:
  - 예전엔 `arp_protection` 같은 주변 바이너리 noise가 섞일 수 있었지만,
  - 지금은 `d.cgi` hidden diagnostic path를 우선하게 정리된 상태다.

---

## 2. TP-Link Deco XE75 / XE5300 / WE10800 1.3.1 P1

도구 packet 기준:
- top candidate: `ndppd`
- engine state: `rootfs-success`, `rootfs-ready`, `web_surface_detected=false`
- summary:
  - `crypto_findings=3`
  - `upgrade_findings=19`
- `ndppd` 후보는 `session::system(` 문자열은 보이지만:
  - `web_exposed=false`
  - `handler_surface=false`
  - `too_many_unknowns`

직접 분석:
- 기존 보고서 기준 이 샘플의 강한 이슈는 `ndppd`가 아니다.
- 실제 핵심은 `group-info`에 하드코딩된 RSA-512 메시 그룹 개인키다.
- 이 키로 메시 인증 우회, 설정 덮어쓰기, 무서명 펌웨어 플래시, 전체 메시 피벗이 가능하다.

직접 판정:
- `artifact_kind`: `rootfs-success`
- `best_next_action`: `triage-top-candidates`
- `top_risk_family`: `crypto-risk`

비교:
- 현재 도구 판단과 직접 분석 결론이 일치한다.
- 의미:
  - 예전엔 `ndppd` 문자열 때문에 `cmd-injection` 쪽으로 흔들릴 수 있었지만,
  - 지금은 더 강한 실질 이슈인 `crypto-risk`를 우선하게 교정된 상태다.

---

## 3. MERCUSYS MR90X (EU)

도구 packet 기준:
- top candidate: `uhttpd`
- 보조 후보:
  - `offline_download_monitor.lua`
  - `cwmp`
- `uhttpd` dossier 기준:
  - `post-auth HTTP Stack Buffer Overflow via cgi-bin -> system`
  - `no canary`, `no PIE`
  - 다만 `exact_input_unknown`
  - 구조적 신호 위주, 확정 exploit chain은 아님

직접 분석:
- 이 샘플은 `system/popen` 문자열 때문에 `cmd-injection`처럼 보이기 쉽다.
- 하지만 현재 dossier 수준에선 명확한 attacker-controlled command construction보다
  memory-safety 쪽 구조 신호가 더 강하다.
- `uhttpd`, `miniupnpd`, `cwmp` 모두 overflow/unsafe copy 계열 단서가 반복된다.
- 따라서 지금 단계에서 가장 타당한 상위 분류는 `memory-corruption`이다.

직접 판정:
- `artifact_kind`: `rootfs-success`
- `best_next_action`: `triage-top-candidates`
- `top_risk_family`: `memory-corruption`

비교:
- 현재 도구 판단과 직접 분석 결론이 일치한다.
- 의미:
  - 예전엔 `system/popen` 문자열 때문에 `cmd-injection` 쪽으로 기울 수 있었지만,
  - 지금은 overflow 중심으로 분류되도록 보정된 상태다.

---

## Summary

이번 spot check 3건에서:
- `AX3000M 15.024` → `cmd-injection`
- `XE75 1.3.1 P1` → `crypto-risk`
- `MR90X` → `memory-corruption`

모두 현재 도구 판단과 직접 분석 결과가 일치했다.

의미:
- 단순 문자열 매칭이 아니라,
- 더 강한 구조적 근거를 우선하는 방향으로 도구 판단이 개선되고 있다.
- 즉 "도구 결과 vs 직접 LLM급 판단 비교 후 휴리스틱 흡수" 루프가 실제로 작동 중이다.
