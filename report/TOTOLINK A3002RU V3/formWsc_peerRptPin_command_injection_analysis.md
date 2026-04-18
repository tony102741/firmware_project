# 📡 TOTOLINK WPS Command Injection 취약점 분석

> TOTOLINK A3002RU V3 Firmware 기반 formWsc (peerRptPin) 취약점 분석

---

## 📌 1. Background

• 공유기 웹 관리 인터페이스 존재  
• WPS (Wi-Fi Protected Setup) 설정 기능 제공  
• 사용자 입력 기반 설정 처리 구조 존재  
• 내부 shell 명령 실행 구조 포함 → 보안 검증 필요  

---

## 🎯 2. Target

**Product**  
`TOTOLINK A3002RU V3`

**Binary**  
`/bin/boa`

**Interface**  
`Web Interface (/boafrm/)`

**Endpoint**  
`/boafrm/formWsc`

**Parameter**  
`peerRptPin`

**Role**  
`WPS PIN configuration`

---

## 🔗 3. Data Flow Structure

[ External Input (peerRptPin) ]  
↓  
[ HTTP POST Parser ]  
↓  
[ FUN_0040fa44 (parameter fetch) ]  
↓  
[ FUN_00446d68 (formWsc handler) ]  
↓  
[ snprintf (command construction) ]  
↓  
[ system() Execution ]  

---

## ⚙️ 4. Command Handling

snprintf("echo %s > /var/wps_peer_pin", peerRptPin)  
system()

또는:

snprintf("iwpriv wlan%d-vxd set_mib pin=%s", ..., peerRptPin)  
system()

• peerRptPin 값이 `%s`로 직접 삽입됨  
• shell 명령 문자열이 동적으로 생성됨  
• system()을 통해 실제 실행됨  

---

## 🔍 5. Verification Result

### ✔️ 입력 처리 특성

• peerRptPin = HTTP POST 요청에서 공격자가 제어 가능  
• FUN_0040fa44를 통해 raw 값 그대로 획득  
• 입력값 검증 / 필터링 없음  

---

### ✔️ 데이터 흐름

• `/boafrm/formWsc` → handler 진입  
• `FUN_0040fa44` → peerRptPin 추출  
• `FUN_00446d68` → 분기 조건 확인  
• `snprintf()` → 명령 문자열 생성  
• `system()` → 실제 실행  

👉 입력 → 실행까지 direct dataflow 존재  

---

### ⚠️ Sanitization 문제

• regex validation 없음  
• digit filtering 없음  
• escaping 없음  

👉 다음과 같은 shell 메타문자 그대로 사용 가능

- `;`
- `&`
- `|`
- `$()`
- backtick
- newline  

---

### ⚠️ 취약 동작

peerRptPin = test; <command>

👉 system() 호출 시:

echo test; <command> > /var/wps_peer_pin

👉 shell에서 명령 분리 실행 발생  

---

## 🔐 6. Access Control

### 🔓 Handler Reachability

• `/boafrm/formWsc` endpoint 존재  
• dispatcher를 통해 handler 직접 호출 가능  
• POST 요청으로 접근 가능  

---

### 🔒 Authentication 구조

• session 기반 검증 존재 (Referer 기반 sessionCheck)  

---

### ⚠️ 인증 우회 가능성

• session이 존재하지 않는 경우  
→ auth check 조건이 false  
→ handler가 직접 실행됨  

👉 특정 상태에서 인증 없이 접근 가능  

---

## 🔄 7. System Relationship

[ Attacker (HTTP Request) ]  
↓  
[ boa Web Server ]  
↓  
[ Dispatcher (/boafrm/) ]  
↓  
[ formWsc Handler ]  
↓  
[ snprintf ]  
↓  
[ system() ]  

---

## ⚠️ 8. Impact

• 공유기 명령 실행 (RCE)  
• root 권한으로 실행됨  
• 시스템 설정 변경 가능  
• 서비스 중단 가능  
• 추가 악성 코드 실행 가능  

---

## 🧩 9. Conclusion

검증되지 않은 WPS 설정 입력값(peerRptPin)이  
직접 shell 명령으로 실행되는 구조적 취약점 존재  

또한 특정 조건에서 인증 없이 접근 가능하여  
공격 표면이 더욱 확대됨  

---

## 💬 One-line Summary

WPS 설정 파라미터 peerRptPin을 통해  
공유기 내부 명령 실행이 가능한 Command Injection 취약점  
