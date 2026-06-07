# 📡 Cudy QoS Rule Injection 취약점 분석

> Cudy WR3000E Firmware 기반 nftables Rule Injection 구조 보안 분석

---

## 📌 1. Background

• QoS: 트래픽 우선순위 제어 기능  
• 사용자 입력 기반 정책 구성 구조 존재  
• nftables 기반 동작 → 입력 검증 필요  

---

## 🎯 2. Target

**Product**  
`Cudy WR3000E`

**Component**  
`QoS (nft-qos)`

**Role**  
`방화벽 규칙 생성 및 트래픽 제어`

---

## 🔗 3. IPC Structure


/etc/config/nft-qos


| 항목 | 내용 |
|------|------|
| 입력 | QoS service 값 |
| 방식 | Plaintext config |
| 인증 | 없음 |

---

## ⚙️ 4. Command Handling


"$proto dport { $srv } accept"


---

## 🔍 5. Verification Result

### ✔️ 입력 처리 특성

• 사용자 입력 controllable  
• Command 검증 없음  
• 입력값 검증 없음  

---

### ⚠️ 노출된 기능

• nft parser 통과 (`nft -c -f`)  
• 규칙 적용 (`nft -f`)  
• injected rule 생성  

👉 외부 입력으로 실제 방화벽 규칙 변경 가능  

---

## 🔐 6. Access Control

### 🔓 접근 조건

• QoS 설정 접근 필요  

---

### 🔒 보호 수준

• 입력 validation 없음  
• 구조 보호 없음  

---

## 🔄 7. System Relationship


[ User Input ]
↓
[ UCI Config ]
↓
[ priority.sh ]
↓
[ nft Script ]


• 사용자 입력이 방화벽 규칙 생성에 직접 영향  

---

## ⚠️ 8. Impact

• 방화벽 정책 변조  
• 특정 트래픽 차단  
• 서비스 거부 가능  
• 네트워크 정책 변경  

---

## 🧩 9. Conclusion


검증되지 않은 QoS 입력값을 통해  
방화벽 규칙 생성 로직이 영향을 받는 구조  


---

## 💬 One-line Summary

QoS 입력값을 통해  
nftables 방화벽 규칙을 조작할 수 있는 구조