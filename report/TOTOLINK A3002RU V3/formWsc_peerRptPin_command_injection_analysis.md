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
| 핸들러 문자열 | `"formWsc"` (VA `0x45e17c`) |
| 디스패치 테이블 위치 | 파일 오프셋 `~0x743xx` |
| 핸들러 함수 VA | `0x441f44` |

> 참고: 기존 리포트의 `FUN_00446d68`은 다른 빌드 기준 명칭이며, 이 빌드에서의 실제 핸들러는 `0x441f44`

### 취약 파라미터: `peerPin`

> 기존 리포트의 `peerRptPin`은 다른 빌드 기준이며,  
> **이 빌드(B20210302)의 실제 파라미터명은 `peerPin`**

```
String "peerPin"   : file offset 0x6ccd8, VA 0x46ccd8
Format string      : "echo %s > /var/wps_peer_pin"  (VA 0x46cce0)
```

### 레지스터 트레이스 (인젝션 경로)

```asm
; [1] get_cgi_param(req, "peerPin", buf) → $2 = peerPin_ptr
0x44272c:  lui   $5, 0x47
0x442730:  move  $4, $16            ; $4 = request object
0x442734:  addiu $5, $5, -0x3328   ; $5 = 0x46ccd8 = "peerPin"
0x442738:  addiu $6, $20, -0x2b0   ; $6 = output buffer
0x44272c:  jal   0x40f2b0           ; get_cgi_param()
0x442734:  move  $20, $2            ; delay slot: $20 = raw peerPin pointer

; [2] $20 수정 없음 (0x44273c → 0x4427e4 전체 구간 추적 완료)

; [3] sprintf + system()
0x4427e0:  move  $6, $20            ; arg = RAW peerPin (검증 없음)
0x4427e4:  jal   0x4737e0           ; sprintf(sp+0xe0, "echo %s > /var/wps_peer_pin", peerPin)
0x4427e8:  addiu $5, $5, -0x3320   ; delay slot: $5 = format string
0x4427ec:  jal   0x473400           ; system(sp+0xe0)  ← INJECTION
0x4427f0:  addiu $4, $sp, 0xe0     ; delay slot
```

**핵심 증거**: `$20` 레지스터가 `0x44273c`(읽기)부터 `0x4427e0`(sprintf 인자)까지 단 한 번도 수정되지 않음 — **sanitization 전무**

### PLT 함수 주소 (이 빌드 기준)

| 함수 | VA |
|---|---|
| `get_cgi_param` | `0x40f2b0` |
| `sprintf` | `0x4737e0` |
| `system` | `0x473400` |
| `strcpy` | `0x4733b0` |

### 검증 결론

**CONFIRMED** — B20210302 빌드에서 `peerPin` → `$20` → `system("echo %s > /var/wps_peer_pin")` 경로가 검증 없이 직결됨
