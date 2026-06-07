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

---

## 🔬 10. Binary Validation (Build: V3.0.0-B20210302.1639)

> `llvm-objdump --triple=mipsel` 기반 정적 분석으로 직접 확인한 결과

### 분석 대상 바이너리

```
work/a3002ru_b20210302/.../squashfs-root-0/bin/boa
Architecture : MIPS32 Little-Endian ELF (stripped, no section headers)
Load mapping : file offset 0x000000 → VA 0x400000
```

### 디스패치 테이블 확인

| 항목 | 값 |
|---|---|
| 핸들러 문자열 | `"formUploadFile"` (VA `0x45c818`) |
| 디스패치 테이블 위치 | 파일 오프셋 `0x74290` |
| 핸들러 함수 VA | `0x445724` (stack size `0xf0`) |

> 기존 리포트의 `FUN_00444ec8` 등은 다른 빌드 기준 명칭

### 관련 문자열 (VA)

```
"filename="                              : 0x46d704
"echo %s >/var/web/fw/%s/version"       : 0x46dc40
"mkdir -p /var/web/fw/%s >/dev/null"    : 0x46dbc0
"/var/web/fw/%s/%s"                      : 0x46dc60
"<b>Upload Successful, file name: %s</b>": 0x46dc88
```

### 인젝션 경로 (함수 호출 체인)

```
0x445724  formUploadFile 핸들러 (dispatch entry)
  └─ 0x444724  헤더 파서: strstr("filename=") + strchr('"') → 파일 데이터 오프셋 반환
  └─ 0x444e14  파일명 추출: Content-Disposition filename= 값 → 전역 버퍼 0x48b650에 raw 복사
  └─ 0x4455cc  업로드 처리 (stack 0x230) ← 실제 system() 호출 위치
```

### 함수 0x444e14 — 파일명 추출 (핵심)

```asm
; 인자: $4 = multipart body, $5 = 출력 버퍼 (0x48b650)
0x444e4c:  jal 0x472df0    ; strstr(body, "filename=")
0x444e5c:  jal 0x472ef0    ; strchr(result, '"')  ← 여는 따옴표
0x444e74:  jal 0x472ef0    ; strchr(+1, '"')       ← 닫는 따옴표
0x444e90:  jal 0x4736c0    ; strncpy(buf, filename_start, len-1)
; → 전역 버퍼 0x48b650에 raw 파일명 저장 (검증 없음)
```

### 함수 0x4455cc — system() 호출 (인젝션 지점)

```asm
; 진입 시 레지스터
; $7 = 0x48b650 (파일명 버퍼, 0x445724 → delay slot: addiu $7, $17, -0x49b0)

; delay slot에서 $16 설정 (항상 실행됨)
0x4455f8:  move $16, $7    ; $16 = 0x48b650 = 파일명 버퍼 ← delay slot

; [인젝션] sprintf + system
0x4456a0:  lui  $5, 0x47
0x4456a4:  move $6, $16              ; $6 = 0x48b650 (raw 파일명)
0x4456a8:  addiu $5, $5, -0x23c0    ; $5 = 0x46dc40 = "echo %s >/var/web/fw/%s/version"
0x4456ac:  move $7, $2              ; $7 = 폴더명 (firmware ID)
0x4456b0:  jal  0x4737e0             ; sprintf(sp+0x18, format, filename, folder)
0x4456b4:  addiu $4, $sp, 0x18      ; delay slot
0x4456b8:  jal  0x473400             ; system(sp+0x18)  ← INJECTION
```

**핵심 증거**:
- `0x444e14`가 Content-Disposition의 `filename=` 값을 raw 복사 (sanitization 없음)
- `0x4455cc` 진입 시 delay slot `move $16, $7` → `$16 = 파일명 버퍼` (양쪽 분기 모두)
- `$16`이 `0x4456a4`에서 echo 명령의 `%s` 인자로 직접 사용됨

### 검증 결론

**CONFIRMED** — B20210302 빌드에서 Content-Disposition `filename=` → `0x48b650` → `system("echo %s >/var/web/fw/.../version")` 경로가 검증 없이 직결됨
