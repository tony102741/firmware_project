# ipTIME AX3000M 비공개 진단 인터페이스 명령 실행 취약점의 변종 분석

> ipTIME AX3000M 펌웨어 `14.234`, `15.024`, `15.330` 기준  
> 비공개 진단/디버그 인터페이스의 구조 및 보안성 분석,  
> 그리고 `CVE-2025-14485`와의 변종 관계 검토

---

## 📌 1. Background

• AX3000M은 웹 관리 인터페이스 기반 CGI 구조를 사용함  
• `14.234`에는 `timepro.cgi` 내부 비공개 진단 분기 존재  
• `15.024`에는 같은 기능이 standalone `d.cgi`로 분리됨  
• 두 버전 모두 `aaksjdkfj` gate 뒤에서 `cmd -> popen()` 흐름이 확인됨  
• `15.330`에서는 동일 generic command path가 사라지고 `ftm.cgi`의 제한된 factory-test 동작만 남음  
• 공개된 `CVE-2025-14485` 역시 ipTIME 계열 `timepro.cgi` 기반 명령 실행 이슈이므로, 같은 계열의 재발생인지 구분이 필요함  

---

## 🎯 2. Target

**Product**  
`ipTIME AX3000M`

**Relevant Binaries**  
- `14.234` : `cgibin/timepro.cgi`
- `15.024` : `home/httpd/cgi/d.cgi`
- `15.330` : `home/httpd/cgi/ftm.cgi`

**Interface**  
`Hidden diagnostic CGI`

**Primary Parameters**  
- `aaksjdkfj`
- `cmd`
- `fname`

**Role**  
`비공개 진단 / debug / factory-test 계열 CGI`

---

## 🔗 3. Data Flow Structure

### `14.234`

```
[ HTTP Request ]
↓
[ timepro.cgi ]
↓
[ timepro_cgi_dispatcher (0x0040bfd0) ]
↓
[ hidden route "/cgibin/d.cgi" ]
↓
[ diagnostic handler (0x00410910) ]
↓
[ auth / csrf / static gate ]
↓
[ cmd ]
↓
[ popen() ]
```

### `15.024`

```
[ HTTP Request ]
↓
[ d.cgi ]
↓
[ diagnostic_cgi_handler (0x00410910) ]
↓
[ call_service_bool("assistance/config", 0) ]
↓
[ check_default_pass() ]
↓
[ check_csrf_attack() ]
↓
[ httpcon_auth(1, 0) ]
↓
[ get_value("aaksjdkfj") == "!@dnjsrurelqjrm*&" ]
↓
[ get_value("cmd") ]
↓
[ append " 2>&1" ]
↓
[ popen(command, "r") ]
```

### `15.330`

```
[ HTTP Request ]
↓
[ ftm.cgi ]
↓
[ factory_test_mode_handler ]
↓
[ get_value_from_query_string ]
↓
[ fixed on/off style operation ]
↓
[ _run_cmd (fixed args) ]
```

---

## ⚙️ 4. Command Handling

### `14.234` / `15.024`

확인된 핵심 특징:

- hidden diagnostic form 존재
- 입력 필드:
  - `aaksjdkfj`
  - `cmd`
  - `fname`
- 인증 및 CSRF 검사를 통과한 뒤
- `cmd`가 그대로 `popen()` 경로로 전달됨

`15.024` 검토 메모 기준 복원 체인:

```c
gate = get_value("aaksjdkfj");
if (gate != "!@dnjsrurelqjrm*&") exit();

cmd = get_value("cmd");
strcat(cmd_buf, " 2>&1");
popen(cmd_buf, "r");
```

즉, 이 이슈의 핵심은 단순 hidden page가 아니라
`attacker-controlled command string -> shell execution sink` 구조다.

### `15.330`

`ftm.cgi`는 `_run_cmd(...)`를 호출하지만:

- `cmd`
- `fname`
- `aaksjdkfj`
- generic `popen(cmd, ...)`

흐름은 보이지 않는다.

따라서 `15.330`은 이전 diagnostic command path의 직접 연장선이 아니라,
**제한된 factory-test 동작만 남긴 제거/축소 버전**으로 보는 것이 타당하다.

---

## 🔍 5. Verification Result

### ✔️ Endpoint / Handler

**`14.234`**
- `timepro.cgi` 내부에 비공개 route `"/cgibin/d.cgi"` 존재
- dispatcher가 hidden diagnostic handler로 분기

**`15.024`**
- `d.cgi` standalone binary 존재
- 비공개 diagnostic form 문자열 존재
- `cmd`, `fname`, `aaksjdkfj`, `popen`, `assistance/config` 확인

### ✔️ Input Controllability

- `cmd`는 CGI 입력값에서 직접 읽힘
- `aaksjdkfj`는 static literal gate
- `fname`는 보조 file-read path에 사용되지만, 핵심은 `cmd`

즉 `cmd`는 공격자가 제어 가능하고,
gate 값만 알면 shell sink로 전달된다.

### ✔️ Sanitization

확인된 범위에서:

- allowlist 없음
- escaping 없음
- shell metacharacter 차단 없음
- `get_value("cmd")` 이후 `popen()` 전 sanitization 단계 없음

따라서 이 경로는 generic command execution sink로 봐야 한다.

### ✔️ Authentication / Gate

실행 전 흐름:

1. `call_service_bool("assistance/config", 0)`
2. `check_default_pass()`
3. `check_csrf_attack()`
4. `httpcon_auth(1, 0)`
5. `aaksjdkfj` static literal compare
6. `cmd -> popen()`

이 경로는 **post-auth**다.  
하지만 `aaksjdkfj`는 보안 경계라기보다 debug/engineering gate에 가깝다.

---

## 🔐 6. Hardcoded Gate Weakness

비공개 parameter:

- `aaksjdkfj`

확인된 literal:

- `!@dnjsrurelqjrm*&`

이 값은:

- device-unique secret가 아님
- 사용자/세션/장비 상태에서 파생되지 않음
- binary 내부에 고정 하드코딩됨

즉 이 gate는
정상적인 권한 모델이 아니라 **펌웨어 분석으로 즉시 복구 가능한 static unlock token**이다.

보안적으로는:

- access control이라기보다
- hidden debug switch

로 보는 것이 맞다.

---

## 🔄 7. Version Diff / Patch Removal

| Version | File | Diagnostic Command Path | Status |
|---|---|---|---|
| `14.234` | `timepro.cgi` | hidden `/cgibin/d.cgi` dispatcher -> `cmd -> popen()` | `Vulnerable` |
| `15.024` | `d.cgi` | standalone hidden diagnostic CGI -> `cmd -> popen()` | `Vulnerable` |
| `15.330` | `ftm.cgi` | fixed factory-test operation only | `Patched / Removed` |

중요한 점:

- `14.234`와 `15.024`는 같은 diagnostic family
- `15.024`는 `14.234` hidden branch의 standalone 분리본에 가깝다
- `15.330`에서는 old diagnostic path가 사라짐

이건 단순 리팩토링보다
**취약한 diagnostic command path를 제거하거나 제한한 보안 hardening 흔적**으로 해석하는 편이 더 자연스럽다.

---

## 🧬 8. Variant Analysis vs CVE-2025-14485

공개 레퍼런스:

- `CVE-2025-14485`
- product: `ipTIME A3004T`
- file: `timepro.cgi`
- issue family: hidden diagnostic command execution

### 공통점

- 둘 다 ipTIME 계열
- 둘 다 `timepro.cgi` 계열 diagnostic path
- 둘 다 비의미적 hidden gate parameter `aaksjdkfj` 사용
- 둘 다 command execution sink를 향함
- 둘 다 정상 UI feature라기보다 hidden diagnostic/debug interface 성격

### 차이점

- 제품 모델이 다름:
  - `A3004T`
  - `AX3000M`
- AX3000M은 `15.024`에서 standalone `d.cgi`로 분리됨
- AX3000M은 `15.330`에서 제거/제한된 패치 흔적이 명확함
- gate literal은 계열상 매우 유사하지만, 현재 확보한 AX3000M 값은
  `!@dnjsrurelqjrm*&`로 기록됨

### 분류 판단

이 케이스는 완전히 새로운 설계라기보다:

- 같은 vendor family
- 같은 hidden diagnostic design
- 같은 gate naming pattern
- 같은 command-execution 목적

을 공유한다.

따라서 가장 타당한 분류는:

**`CVE-2025-14485`의 AX3000M 변종(variant)** 이다.

즉,

- `CASE A: identical` 는 아님
- `CASE B: similar but distinct` 보다는
- **같은 취약 기능군의 모델별 변종**

으로 보는 것이 맞다.

---

## ⚠️ 9. Impact

인증된 관리 세션과 static gate 값을 아는 공격자는:

- 임의 OS 명령 실행
- 설정/방화벽/라우팅 변경
- 장비 영구 손상 또는 서비스 중단
- 내부망 pivot

을 수행할 수 있다.

특히 root 권한 CGI라면 영향은 사실상 full compromise다.

---

## 🧩 10. Conclusion

AX3000M `14.234`와 `15.024`에는
hidden diagnostic CGI를 통한 `cmd -> popen()` command injection이 존재한다.

이 이슈는:

- attacker-controlled input 존재
- sanitization 부재
- static hardcoded gate
- same-family version recurrence
- `15.330` 패치/제거 흔적

까지 모두 갖추고 있다.

또한 구조적으로는
`CVE-2025-14485 (ipTIME A3004T timepro.cgi)`와 같은 취약 family의
**AX3000M 변종**으로 해석하는 것이 가장 설득력 있다.

---

## 💬 One-line Summary

AX3000M의 hidden diagnostic `timepro.cgi` / `d.cgi` 경로는  
static gate `aaksjdkfj` 뒤에서 `cmd`를 `popen()`으로 실행하며,  
이는 `CVE-2025-14485`와 같은 ipTIME diagnostic command-execution family의 변종이다.
