# TOTOLINK A3002RU V3 Command Injection Recurrence Summary

> `TOTOLINK A3002RU V3`
> 반복적으로 나타나는 command-injection 설계 패턴 요약

---

## 1. Scope

이 문서는 `TOTOLINK A3002RU V3`에서 이미 개별 분석이 끝난 3개 취약점을
하나의 recurrence case로 묶어 설명한다.

대상 이슈:

- `formWsc` / `peerRptPin` 계열
- `formWlSiteSurvey` / repeater SSID 계열
- `formUploadFile` / multipart `filename` 계열

검증 기준:

- 기존 개별 report
- `V3.0.0-B20210302.1639` 빌드 재검증 결과

---

## 2. Common Pattern

세 이슈는 모두 같은 구조를 반복한다.

1. 웹 또는 외부 환경 입력이 handler에 들어감
2. 값이 내부 설정 또는 로컬 버퍼에 거의 그대로 보존됨
3. `sprintf` / `snprintf` 류로 shell command 문자열이 조립됨
4. `system()` 또는 동등한 shell execution sink로 실행됨

즉 문제의 핵심은 특정 기능 하나가 아니라:

- **사용자 제어 값이 shell command 템플릿의 `%s`로 삽입되는 설계**
- **입력 검증보다 command construction에 의존하는 구현 습관**

에 있다.

---

## 3. Comparison Table

| Case | Entry point | User-controlled input | Execution sink | Authentication | Pattern type |
|---|---|---|---|---|---|
| WPS PIN | `/boafrm/formWsc` | `peerRptPin` / build-variant `peerPin` | `system()` | session gate present, bypass discussion exists in legacy logic | direct HTTP-to-shell |
| Repeater SSID | `/boafrm/formWlSiteSurvey` | external SSID via site survey / MIB path | `system()` | admin interaction required | indirect external-input-to-shell |
| Upload filename | `/boafrm/formUploadFile` | multipart `filename` | `system()` | config-dependent auth weakness discussed | direct HTTP-to-shell |

---

## 4. Per-Case Notes

### WPS / `formWsc`

- WPS PIN 관련 parameter가 shell command 템플릿에 직접 삽입된다
- `echo %s > /var/wps_peer_pin`
- `iwpriv ... set_mib pin=%s`
- 입력 검증이 충분하지 않아 shell metacharacter가 command 의미를 바꿀 수 있다

### Repeater / Site Survey

- 공격자 제어 SSID가 site survey cache와 MIB를 거쳐 command 재구성 단계에 도달한다
- 최종적으로 `iwpriv ... ap_profile_add="%s",...` 형태에 삽입된다
- 정상 UI parameter가 아니라 외부 무선 환경 입력이 sink까지 도달한다는 점이 특징이다

### Upload / `formUploadFile`

- multipart 업로드의 `filename`이 command string에 직접 반영된다
- `echo %s >/var/web/fw/%s/version`
- direct HTTP request에서 바로 shell execution sink로 이어지는 구조다

---

## 5. Why This Matters

이 3건은 서로 독립적인 버그처럼 보이지만, 실제로는 같은 vendor 구현 습관을
보여준다.

공통 특징:

- handler 경계에서 allowlist 검증이 약함
- `%s` 기반 shell command 조립이 반복됨
- 기능별 wrapper는 다르지만 sink는 동일 계열이다
- 관리 평면 안에서 shell execution을 과도하게 사용한다

따라서 `A3002RU` 사례는:

- 단발성 bug 1개가 아니라
- **동일 제품군 내부에서 반복된 command-injection anti-pattern**

으로 보는 것이 더 정확하다.

---

## 6. Build Recurrence

`V3.0.0-B20210302.1639` 빌드 재검증에서도 세 경로의 핵심 sink는 계속 보였다.

재확인된 요소:

- `formWsc`
- `formWlSiteSurvey`
- `/boafrm/formUploadFile`
- `echo %s > /var/wps_peer_pin`
- `iwpriv %s set_mib ap_profile_add="...`
- `echo %s >/var/web/fw/%s/version`

즉 기존 report 대상 취약점은 특정 오래된 샘플에만 존재한 것이 아니라,
적어도 `2021-03-02` 빌드에서도 구조적으로 유지된다.

---

## 7. Security Interpretation

이 recurrence case가 의미 있는 이유는:

- 서로 다른 기능 영역
  - WPS
  - repeater
  - firmware upload
- 서로 다른 입력 출처
  - 직접 HTTP parameter
  - multipart metadata
  - 외부 SSID

를 통해서도 같은 shell-injection 설계가 반복되기 때문이다.

이것은 특정 handler의 실수라기보다:

- command execution을 business logic 일부처럼 사용한 구현 스타일
- 입력을 shell-safe representation으로 바꾸지 않는 coding pattern

의 문제로 해석된다.

---

## 8. Bottom Line

`TOTOLINK A3002RU V3`는 개별 취약점 3개가 따로 존재하는 것에 그치지 않고,
관리 기능 전반에 걸쳐 사용자 제어 값을 shell command에 삽입하는 설계 패턴이
반복된다.

따라서 이 제품은 단일 command injection 사례보다
**vendor-level recurrence / product-level insecure command-construction
pattern**의 대표 사례로 쓰기에 적합하다.
