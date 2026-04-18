# 📡 TOTOLINK File Upload Command Injection 취약점 분석

> TOTOLINK A3002RU V3 Firmware 기반 formUploadFile 취약점 분석

---

## 📌 1. Background

• 공유기 웹 관리 인터페이스 존재  
• Firmware 업로드 기능 제공  
• multipart 기반 파일 업로드 처리 구조 존재  
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
`/boafrm/formUploadFile`

**Role**  
`Firmware upload / file handling`

---

## 🔗 3. Data Flow Structure


[ External Input (filename) ]
↓
[ Multipart Parser ]
↓
[ FUN_00444710 (filename 추출) ]
↓
[ FUN_00444ec8 (command 구성) ]
↓
[ system() Execution ]


---

## ⚙️ 4. Command Handling


sprintf("echo %s >/var/web/fw/%s/version", filename, path)


• filename 값이 `%s`로 직접 삽입됨  
• sprintf로 shell 명령 문자열 구성  
• system()으로 실행됨  

---

## 🔍 5. Verification Result

### ✔️ 입력 처리 특성

• filename = multipart 요청에서 공격자가 제어 가능  
• FUN_00444710에서 strncpy로 raw 복사  
• 입력값 검증 / 필터링 없음  

---

### ✔️ 데이터 흐름

• `/boafrm/formUploadFile` → handler 진입  
• `FUN_00444710` → filename 추출  
• `FUN_00444ec8` → command 문자열 생성  
• `system()` → 실제 실행  

👉 입력 → 실행까지 direct dataflow 존재  

---

### ⚠️ Sanitization 문제

• escape / validation 로직 없음  

👉 다음과 같은 shell 메타문자 그대로 사용 가능

- `;`
- `&`
- `|`
- `$()`
- backtick
- newline

---

### ⚠️ 취약 동작


filename = test; <command>


👉 system() 호출 시:


echo test; <command> > /var/web/fw/.../version


👉 shell에서 명령 분리 실행 발생  

---

## 🔐 6. Access Control

### 🔓 Authentication 구조

• 단일 auth gate: `FUN_0040aa84`  
• handler 내부 추가 인증 없음  

---

### 🔓 인증 우회 조건

• MIB username (0xb6) == ""  
• MIB password (0xb7) == ""  

👉 두 값이 모두 비어있을 경우:

→ 인증 로직 완전 스킵  
→ handler 직접 실행 가능  

---

### 🔒 일반 조건

• credentials 설정 시  
→ 인증된 사용자만 접근 가능  

---

### ⚠️ 특징

• 설정 상태에 따라 pre-auth / post-auth 모두 가능  
• session 기반 보호 약함 (IP 기반)  

---

## 🔄 7. System Relationship


[ Attacker (HTTP Request) ]
↓
[ boa Web Server ]
↓
[ Dispatcher ]
↓
[ formUploadFile Handler ]
↓
[ sprintf ]
↓
[ system() ]


• 웹 요청 → shell 실행으로 직접 연결  
• indirect 경로 없이 direct injection 구조  

---

## ⚠️ 8. Impact

• 공유기 명령 실행 (RCE)  
• root 권한으로 실행됨  
• 시스템 설정 변경 가능  
• 서비스 중단 가능  
• 추가 악성 코드 실행 가능  

---

## 🧩 9. Conclusion

multipart 업로드의 filename이 검증 없이 shell 명령으로 사용되며  
auth 조건에 따라 인증 없이도 실행 가능한 구조적 취약점 존재  

---

## 💬 One-line Summary

파일 업로드의 filename을 통해  
공유기 내부 명령 실행이 가능한 Direct Command Injection 취약점
