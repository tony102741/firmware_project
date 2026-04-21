# Raw Firmware Blind Spot Check — 2026-04-22

목적:
- `도구 packet`을 먼저 읽지 않고 raw firmware artifact 쪽만 보고 직접 결론을 낸다.
- 그 뒤 현재 도구의 최종 판단과 비교한다.

샘플:
1. `iptime-ax3000m-15-024`
2. `tp-link-xe75-xe5300-we10800-sp1-ver1-3-1-p1-20251023`
3. `totolink-x6000r-v9-4-0cu-1498-b20250826-all`

---

## 1. ipTIME AX3000M 15.024

Raw artifact 확인:
- `strings d.cgi` 결과:
  - `popen`
  - `aaksjdkfj`
  - `fname`
  - `Command Name : <input type=text name="cmd"...`
  - `File Name : <input type=text name="fname"...`
- 기존 수동 분석 보고서:
  - standalone `d.cgi`
  - auth / csrf / hidden gate 이후 `cmd -> popen()`

직접 결론:
- hidden diagnostic CGI를 통한 명령 실행 계열
- `top_risk_family = cmd-injection`

도구 최종 라벨:
- `top_risk_family = cmd-injection`

비교:
- 일치

---

## 2. TP-Link Deco XE75 / XE5300 / WE10800 1.3.1 P1

Raw artifact 확인:
- `fw_data/user_data/group-info`에 JSON 형태 키 존재
- 같은 파일에서:
  - `role: AP`
  - `gid: 70303de6-63d9-11e8-a3f6-0000eb367511`
  - `key: AAAAB3NzaC1yc2E...`
- `tmp-luci`에서 `opcode_whitelist` 관련 로직 확인
- 기존 수동 분석 보고서:
  - hardcoded RSA-512 group private key
  - mesh auth bypass
  - unsigned firmware propagation / full-mesh pivot

직접 결론:
- strongest issue는 speculative `ndppd`가 아니라 crypto/authentication failure
- `top_risk_family = crypto-risk`

도구 최종 라벨:
- `top_risk_family = crypto-risk`

비교:
- 일치

---

## 3. TOTOLINK X6000R 1498

Raw artifact 확인:
- `mtkwifi.lua`에서:
  - `entry({"admin", "mtk", "multi_ap", "submit_dpp_uri"}, call("submit_dpp_uri"))`
  - `function submit_dpp_uri()`
  - `uri = http.formvalue("uri")`
  - `os.execute("wappctrl ra0 dpp dpp_qr_code ".."\\\"" .. uri .. "\\\"")`
- 같은 파일에서:
  - `apcli_cfg`
  - `apcli_connect`
  - `os.execute("iwpriv "..vifname.." set ApCliWPAPSK=\\""..mtkwifi.__handleSpecialChars(cfgs.ApCliWPAPSK).."\\"")`
  - `os.execute("iwpriv "..vifname.." set ApCliSsid=\\""..mtkwifi.__handleSpecialChars(cfgs.ApCliSsid).."\\"")`
- 직접 문자열만 봐도 web input이 shell command로 이어지는 구조가 노출됨

직접 결론:
- confirmed web command-injection family
- `top_risk_family = cmd-injection`

도구 최종 라벨:
- `top_risk_family = cmd-injection`

비교:
- 일치

---

## Summary

이번 blind spot check 3건에서:
- `AX3000M 15.024` → 직접 분석 `cmd-injection`, 도구 `cmd-injection`
- `XE75 1.3.1 P1` → 직접 분석 `crypto-risk`, 도구 `crypto-risk`
- `X6000R 1498` → 직접 분석 `cmd-injection`, 도구 `cmd-injection`

결론:
- 적어도 이 3건에 대해서는
  - raw firmware를 직접 훑어서 내린 결론과
  - 현재 도구의 최종 판단이 같았다.
- 즉 현재 도구는 단순 문자열 나열이 아니라,
  `직접 분석자가 최종적으로 선택할 위험 family` 쪽으로 상당히 맞춰진 상태다.
