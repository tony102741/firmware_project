# ipTIME AX3000M 비공개 진단 인터페이스의 명령 실행 취약점

> ipTIME AX3000M 펌웨어 `14.234`, `15.024`, `15.330` 기준
> 비공개 진단/디버그 CGI 인터페이스의 구조 및 보안성 분석

---

## 📌 1. Background

• AX3000M은 웹 관리 인터페이스 기반 CGI 구조를 사용함  
• 일부 CGI는 일반 설정 메뉴가 아니라 진단/테스트 용도로 보이는 별도 흐름을 가짐  
• `14.234`와 `15.024`에서는 비공개 진단 CGI가 일반 명령 실행 경로에 도달함  
• `15.330`에서는 동일한 구조가 보이지 않아 버전 차이 분석 가치가 큼  

---

## 🎯 2. Target

**Product**  
`ipTIME AX3000M`

**Analyzed Versions**  
- `14.234`
- `15.024`
- `15.330`

**Relevant Files**  
- `14.234` : `cgibin/timepro.cgi`
- `15.024` : `home/httpd/cgi/d.cgi`
- `15.330` : `home/httpd/cgi/ftm.cgi`

**Role**  
`비공개 진단 / factory-test CGI analysis`

---

## 🔗 3. Data Flow Structure

### `14.234`

[ HTTP Request ]  
↓  
[ timepro.cgi ]  
↓  
[ timepro_cgi_dispatcher (0x0040bfd0) ]  
↓  
[ non-public route "/cgibin/d.cgi" ]  
↓  
[ diagnostic handler (0x00410910) ]  
↓  
[ parameter gate ]  
↓  
[ popen() ]

### `15.024`

[ HTTP Request ]  
↓  
[ d.cgi ]  
↓  
[ diagnostic_cgi_handler (0x00410910) ]  
↓  
[ auth / csrf / non-public gate ]  
↓  
[ cmd parameter ]  
↓  
[ popen() ]

### `15.330`

[ HTTP Request ]  
↓  
[ ftm.cgi ]  
↓  
[ factory_test_mode_handler (0x00400950) ]  
↓  
[ get_value_from_query_string ]  
↓  
[ fixed on/off operation ]  
↓  
[ _run_cmd (fixed args) ]

---

## ⚙️ 4. Command Handling

### `14.234` / `15.024`

확인된 핵심 흐름:

- `check_default_pass()`
- `check_csrf_attack()`
- `httpcon_auth(...)`
- non-public parameter:
  - `aaksjdkfj`
- static literal 비교
- `cmd` 입력값 획득
- `popen(...)` 호출

즉, 사용자 입력이 비공개 진단 핸들러를 통해 shell command execution
sink에 도달함.

추가로 동일 handler는:

- `fname`

기반 파일 읽기 기능도 포함함. 그러나 핵심 보안 이슈는 generic command
execution 경로임.

### `15.330`

`ftm.cgi`는 `_run_cmd(...)`를 사용하지만:

- `cmd`
- `fname`
- `aaksjdkfj`
- `popen`

기반의 기존 diagnostic interface와는 구조가 다름.

`_run_cmd(...)`는 fixed internal argument에 묶인 factory-test 동작으로
보이며, 이전처럼 generic command 입력을 처리하는 형태는 확인되지 않음.

---

## 🔍 5. Verification Result

### ✔️ `14.234`

• `timepro.cgi` 메인 dispatcher가 비공개 `"/cgibin/d.cgi"` 경로를 분기함  
• 실제 비공개 진단 핸들러는 `0x00410910`에 존재  
• `fname`, `cmd`, `aaksjdkfj` 관련 흐름 확인됨  
• command execution sink는 `popen()`  

👉 즉 `15.024`의 `d.cgi`는 갑자기 생긴 것이 아니라  
이전 버전 `timepro.cgi` 내부에 숨겨져 있던 기능의 계승 구조임

### ✔️ `15.024`

• `d.cgi`가 standalone diagnostic CGI로 존재  
• 비공개 form 문자열 포함  
• auth / csrf / 비공개 gate 이후 `cmd -> popen()` 경로 확인됨  
• Ghidra에서 `diagnostic_cgi_handler`로 rename 완료  

👉 heuristic이 아니라 함수 단위로 직접 확인된 command-execution path

### ✔️ `15.330`

• 이전 `d.cgi`는 보이지 않음  
• `ftm.cgi`는 존재하지만 factory-test toggle 위주  
• `on/off` 스타일 고정 동작만 보임  
• 이전 generic command interface의 직접 대체물로 보이지 않음  

👉 기존 비공개 진단 명령 경로는 제거되었거나 크게 제한된 것으로 해석 가능

---

## 🔐 6. Access Control

### 🔒 Authentication 구조

`14.234` / `15.024` 기준 확인된 구조:

- `check_default_pass()`
- `check_csrf_attack()`
- `httpcon_auth(...)`

즉 현재 확인된 구현은 무인증 command path라기보다:

- 인증 필요
- 추가 비공개 gate 필요

구조임.

### Authentication Flow Summary

실행 순서는 구조적으로 다음과 같다.

1. diagnostic CGI 진입
2. 기본 비밀번호 / 상태 확인
3. CSRF 검증
4. 인증 세션 검증
5. 비공개 parameter gate 확인
6. 이후에만 `cmd` 처리 분기 도달

즉 이 경로는 현재 확인된 범위에서:

- pre-auth 기능이 아니라
- authenticated diagnostic flow 뒤에 숨겨진 기능

으로 보는 것이 맞다.

### 🔑 Hidden Gate

비공개 parameter:

- `aaksjdkfj`

그리고 binary 내부에 하드코딩된 deterministic literal 비교가 존재함.

확인된 literal:

- `!@dnjsrurelqjrm*&`

이는 정상적인 권한 모델이라기보다:

- debug
- engineering
- legacy diagnostic

인터페이스에서 자주 보이는 비공개 gate 패턴에 가깝다.

즉 이 gate는:

- role 기반 권한 모델이 아니고
- device-unique secret처럼 보이지도 않으며
- 정적 하드코딩 문자열을 아는 경우 통과 가능한 조건

이라는 점에서, 보안 경계라기보다 비공개 진단 스위치에 가깝다.

---

## 🧩 7. Why This Is Not A Legitimate Admin Feature

• 일반 관리자 UI 흐름에서 자연스럽게 노출되지 않음  
• `14.234`에서는 `timepro.cgi` 내부 비공개 route `"/cgibin/d.cgi"`로만 분기됨  
• `aaksjdkfj` 같은 비의미적 파라미터 이름 사용  
• 하드코딩된 고정 문자열 gate 사용  
• bounded admin action이 아니라 generic command execution capability 제공  
• 같은 펌웨어 내부 정상 CGI는 `tmenu`, `smenu`, `commit` 등 의미 있는 UI/action 패턴을 가짐  

👉 따라서 이 인터페이스는 정상 관리자 기능이라기보다  
비공개 진단 / debug interface로 보는 것이 타당함

### Same-Firmware Contrast

같은 펌웨어의 일반 administrative CGI는 보통:

- 설정 메뉴와 연결된 endpoint를 사용하고
- `tmenu`, `smenu`, `commit`, `save` 같은 의미 있는 action 구조를 가지며
- bounded operation을 수행한다

반면 본 인터페이스는:

- 비공개 route에 묶여 있고
- 비의미적 parameter 이름을 사용하며
- generic command execution capability를 제공한다

따라서 설계 철학 자체가 정상 관리 기능과 다르다.

---

## 🔄 8. Version Diff

| Version | File | 특징 | Command Execution |
|---|---|---|---|
| `14.234` | `timepro.cgi` | 비공개 `/cgibin/d.cgi` dispatcher 포함 | `YES` |
| `15.024` | `d.cgi` | standalone 비공개 진단 CGI | `YES` |
| `15.330` | `ftm.cgi` | factory-test toggle 위주 | restricted / no equivalent generic path |

### 해석

`15.330`의 변화는:

- 단순 rename보다는
- 비공개 레거시 진단 경로의 제거 또는 제한

쪽으로 해석하는 것이 더 자연스럽다.

이는 기능 변경이라기보다:

- hardening
- security fix
- risky diagnostic functionality reduction

의 성격을 가진다.

---

## 🌐 9. Exposure And Practical Reachability

### Reachability

- 관리 웹 인터페이스의 CGI 계층에 속하므로 기본적으로 LAN 관리 평면에 놓여 있다
- WAN 노출은 현재 정적 분석만으로 확정하지 않았으며, 원격 관리 설정 여부에 따라 달라질 수 있다

### Discoverability

- 일반 사용자 입장에서는 낮음
- UI에 노출되지 않고 비공개 route / 비공개 parameter를 요구함
- 그러나 펌웨어 추출 또는 바이너리 분석을 하면 경로와 gate는 복구 가능하다

### Practical Preconditions

- 유효한 관리 세션 또는 관리자 수준 접근 필요
- 비공개 route / 비공개 parameter 구조에 대한 사전 지식 필요

즉 practical attack surface는:

- blind Internet scanning형 대규모 악용보다는
- authenticated insider-style misuse
- reverse-engineering-aware attacker

쪽에 더 가깝다.

---

## ⚠️ 10. Impact

`14.234` / `15.024` 기준:

• 비공개 진단 인터페이스를 통한 command execution capability 존재  
• 정상 관리자 기능이 아닌 비공개 기능이 관리 평면 내부에 존재  
• 펌웨어 분석 없이 일반 사용자가 알기 어렵지만, 구조적으로는 명확한 보안 리스크  

---

## 🧭 11. Overlap Assessment

공개된 `ipTIME A8004T` 사례인:

- `CVE-2026-1740`
- `CVE-2026-1741`

와는 패턴상 강하게 유사하다.

공통점:

- `timepro.cgi` / `d.cgi` 계열 diagnostic 흐름
- 비공개 route / debug-style access
- command-capable diagnostic behavior

차이점:

- `AX3000M`에서 현재 확인된 구현은 인증 체크 이후 비공개 gate를 추가로 거친다
- 공개 A8004T 설명은 improper authentication와 debug interface를 별도로 강조한다

현재 가장 안전한 분류는:

- 동일 root cause 재사용이라고 단정하기보다
- 같은 vendor family 내 유사한 비공개 진단 취약점 패턴의 별도 구현

이다.

---

## 📏 12. CVSS v3.1 Estimate

현재 확인된 구조 기준 추정 값:

- `CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H`
- Base Score: `6.4`

해석:

- LAN management plane 접근 필요
- 관리자 권한 및 비공개 진단 인터페이스에 대한 지식 필요
- 하지만 성공 시 confidentiality / integrity / availability 영향은 모두 높다

---

## 🧩 13. Conclusion

`ipTIME AX3000M`의 `14.234`와 `15.024`에는
정상 UI에 노출되지 않는 비공개 진단 CGI 인터페이스가 존재하며,
이 인터페이스는 인증 및 추가 비공개 gate 이후 generic command execution
동작에 도달한다.

이는 정상적인 administrative feature라기보다
legacy/debug diagnostic functionality로 해석하는 것이 더 타당하다.

`15.330`에서는 동일한 generic diagnostic path가 보이지 않고,
`ftm.cgi`는 더 제한된 factory-test 동작만 수행하므로,
이전 인터페이스는 제거되었거나 의미 있게 제한된 것으로 보인다.

---

## 💬 One-line Summary

AX3000M의 `14.234` / `15.024`는 비공개 진단 CGI를 통해
generic command execution capability를 가지며,
`15.330`에서는 해당 기능이 제거 또는 제한된 것으로 보인다.
