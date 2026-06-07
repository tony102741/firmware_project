# 📡 TP-Link Deco XE75 Hardcoded Mesh Group Key → Full Mesh RCE 취약점 분석

> TP-Link Deco XE75 / XE5300 / WE10800 Firmware 기반 TDP/TMP 메시 프로토콜 취약점 분석

---

## 📌 1. Background

• TP-Link Deco 시리즈는 독자적인 메시 프로토콜(TDP/TMP)을 사용하여 AP ↔ RE 간 통신 수행  
• 메시 노드 인증에 RSA 기반 그룹 키를 사용 (`group-info` 파티션)  
• 모든 Deco XE75/XE5300/WE10800 펌웨어 이미지에 동일한 RSA-512 **개인키** 포함  
• 키를 통과하면 UCI 설정 쓰기, 무서명 펌웨어 플래시, 전체 메시 피벗이 가능  
• `/usr/bin/tmpsvr` 데몬이 UDP 포트 20002에서 TDP, TCP 포트 20002에서 TMP 처리  

---

## 🎯 2. Target

**Product**  
`TP-Link Deco XE75 / XE5300 / WE10800`

**Binary**  
`/usr/bin/tmpsvr`, `/usr/bin/sync-server`

**Interface**  
`UDP 20002 (TDP), TCP 20002 (TMP)`

**Auth Gate**  
`sync_slave_check` / `sync_master_check` (discover.lua)

**Role**  
`Mesh node sync / firmware upgrade / config distribution`

---

## 🔗 3. Data Flow Structure

```
[ Attacker (UDP 20002 - TDP Packet) ]
          ↓
[ tmpsvr: recvfrom(buf, 0x400) ]
          ↓
[ CRC32 Check (no secret key — forgeable) ]
          ↓
[ relay_run: fork() → execl("/usr/bin/tmp-luci") ]
          ↓
[ tmp-luci: opcode_whitelist check (absent by default → SKIP) ]
          ↓
[ luci.sgi.tmp.run() → LuCI dispatcher ]
          ↓
[ discover.lua: sync_slave_check ]
          ↓  ← RSA-512 group private key (hardcoded in firmware)
[ op_manager.lua: opcode dispatch ]
          ↓
[ inspect_and_save_subconfig → uci_apply     ]  ← config write
[ forward_tmp_request → sync-server → RE×N  ]  ← mesh pivot
[ 0x40e0 handler → firmware flash            ]  ← RCE
```

---

## ⚙️ 4. Vulnerability: Hardcoded RSA-512 Private Key

**파일:** `fw_data/user_data/group-info` (UBI 파티션 27, type=USER\_DATA, method=MANU)

**내용 (JSON):**
```json
{
  "role": "AP",
  "key": "AAAAB3NzaC1yc2EAAAADAQABAAAAQQC/q1ssRADI...K8eTcQl...",
  "gid": "70303de6-63d9-11e8-a3f6-0000eb367511"
}
```

**키 구조 (Dropbear wire format, base64 decode 결과):**

| 필드 | 크기 | 값 |
|---|---|---|
| type | 7B | `ssh-rsa` |
| e (public exponent) | 4B | 65537 |
| n (modulus) | 65B | RSA-512 공개 모듈러스 |
| d (private exponent) | 64B | **개인키 d 포함** |
| p (prime 1) | 33B | **인수 p 포함** |
| q (prime 2) | 33B | **인수 q 포함** |

→ RSA 개인키의 모든 구성요소(n, e, d, p, q) 포함  
→ 동일 펌웨어를 탑재한 모든 기기가 **동일한 그룹 키 공유**  
→ 펌웨어 이미지에서 추출 즉시 인증 우회 가능  

---

## 🔍 5. Authentication Gate 분석

### sync_slave_check (discover.lua, offset 12755)

```
read_group_info()       ← group-info 파티션에서 키 로드
  → group_hid (CRC32 기반)
  → "group hid mismatched" (불일치 시 거부)
decrypt_table()         ← RSA-512 개인키로 챌린지 복호화
  → group_id 비교
  → "group id mismatched" (불일치 시 거부)
  → emmc_config_version 비교
  → 통과 시 응답을 encrypt_table()로 암호화 후 반환
```

**우회 조건:** 공격자가 동일한 RSA-512 키 보유 → `decrypt_table` 응답 정상 생성 가능  

### TDP CRC32 (tmpsvr, FUN_00111b50)

```c
*(buf + 8) = 0x5a6b7c8d;   // CRC32 필드 0으로 대체
crc = crc32(buf, pkt_len);  // 계산
if (crc != stored_crc) drop; // 비교
```

→ CRC32는 시크릿 키 없이 패킷 조작 후 재계산 가능 → 무의미한 게이트  

### opcode_whitelist (tmp-luci)

```lua
local opcode_whitelist = uci_s:get("firewall", "security", "opcode_whitelist")
if opcode_whitelist == "1" then ... end
```

→ `etc/config/firewall`에 `opcode_whitelist` 설정 없음 → **필터링 없이 전체 opcode 통과**  

---

## 🔐 6. Post-Auth 공격 표면 (sync_slave_check 통과 후)

### A. UCI 설정 전체 덮어쓰기 (inspect_and_save_subconfig)

**Opcode:** c4xx 시리즈 (op_manager.lua 등록 범위: 0xc401–0xc40f)

```
recv TDP (c4xx) → sync_slave_check → inspect_and_save_subconfig
  → md5sum /etc/config/* > <tmpfile>    ← 변경 전 스냅샷
  → diff                                 ← 변경 감지
  → is_user_config → "user config change!"
  → save_config_version
  → reload_user_config
  → uci_apply                           ← /etc/config/* 직접 쓰기
  → sync_boost_uloop                    ← 메시 재동기 트리거
```

**영향:** 방화벽 규칙, DNS, 라우팅, 관리자 패스워드(`accountmgnt`) 등 전체 UCI 설정 교체

---

### B. 무서명 펌웨어 플래시 (SYNC\_FIRMWARE + SYNC\_UPGRADE / 0x40e0)

**경로 1 — 0x40e0 opcode (op_manager.lua, offset 2885):**
```
recv TDP (0x40e0) → sync_slave_check
  → get_memfree < 15MB: drop_caches → retry
  → upgrade_type_get (luci.model.sync)
  → firmware flash 진행
```

**경로 2 — SYNC\_FIRMWARE + SYNC\_UPGRADE (C sync-server):**
```
SYNC_FIRMWARE {host=<attacker_ip>, filename=<name>, checksum=<attacker_md5>}
  → sync-server: 펌웨어 수신 → /var/firmwares/<name> 저장
  → MD5 검증 (공격자가 제공한 값과 대조)   ← 서명 검증 없음
SYNC_UPGRADE {}
  → /var/firmwares/<name> 플래시
```

→ 암호학적 서명 검증 없음: MD5는 공격자가 직접 계산하여 전달  
→ **임의 펌웨어 플래시 → 완전한 원격 코드 실행 (RCE)**  

---

### C. 전체 메시 피벗 (forward_tmp_request)

**Opcode:** c40b–c40f 범위 (op_manager.lua)

```
recv TDP (c40x) → sync_slave_check → forward_tmp_request
  → write JSON {opcode, target_id, params, data}
       → /tmp/sync-server/forward_tmp_request-<pid>
  → ubus call sync request
  → /lib/sync-server/scripts/request <infile> <outfile> <opcode> <RE_ip1> 1 ...
```

**request 스크립트 (평문 Lua):**
```lua
local usr = uci_r:get_profile("accountmgnt", "username")
local pwd = uci_r:get_profile("accountmgnt", "password")
-- 라우터 자신의 관리자 자격증명으로 RE에 인증
tmpcli:request(opcode, {infile = infile})
```

→ 공격자 제어 opcode + payload를 **라우터 관리자 자격증명**으로 모든 RE에 전달  
→ AP 1개 침해 → 전체 메시 네트워크 일괄 침해  

---

### D. 벌크 설정 덮어쓰기 (SYNC\_CONFIG)

```
SYNC_CONFIG {infile=<config_blob>}
  → sync-server: nvrammanager -p user-config -w <file>
  → user-config 파티션 전체 교체
```

→ UCI 레벨이 아닌 nvram 파티션 레벨로 설정 전체 교체  

---

## 🔄 7. System Relationship

```
[ Attacker ]
    ↓ UDP 20002 (TDP)
[ tmpsvr ]
    ↓ CRC32 (forgeable)
[ tmp-luci → discover.lua ]
    ↓ sync_slave_check (group-info RSA-512 key — hardcoded)
[ op_manager.lua ]
    ├─ c4xx → uci_apply (/etc/config/*)
    ├─ 0x40e0 → firmware flash (no sig check)
    └─ c40x → forward_tmp_request
                ↓ router's admin creds
              [ RE Node 1 ] [ RE Node 2 ] [ RE Node N ]
                   ↓               ↓              ↓
              firmware flash  config overwrite  config overwrite
```

---

## ⚠️ 8. Impact

• **RSA-512 키 크기**: 2024년 기준 512-bit RSA는 공개 인수분해 공격(GNFS)으로 수일~수주 내 크랙 가능 — 그러나 펌웨어에서 직접 추출하므로 크랙 불필요  
• **인증 완전 우회**: 네트워크 내 모든 Deco 기기에 대해 신뢰 노드로 위장 가능  
• **펌웨어 임의 교체**: 서명 없는 플래시 경로로 루트 레벨 백도어 영구 설치 가능  
• **전체 메시 일괄 침해**: AP 1대 접근으로 연결된 모든 RE에 대한 명령 실행 가능  
• **인증 자격증명 유출**: `uci_apply`로 `accountmgnt` 설정 교체 → 패스워드 탈취  
• **동일 모델 모든 기기 영향**: 펌웨어 공유로 인해 전 세계 동일 제품군 일괄 대상  

---

## 🧩 9. Conclusion

TP-Link Deco XE75 펌웨어에 RSA-512 메시 그룹 개인키가 하드코딩되어 있어  
동일 네트워크 내 공격자가 신뢰 노드로 위장하여 `sync_slave_check`를 통과하고  
UCI 설정 덮어쓰기, 무서명 펌웨어 플래시, 전체 메시 피벗을 달성할 수 있는  
구조적 다중 취약점이 존재함  

---

## 💬 One-line Summary

펌웨어에 하드코딩된 RSA-512 메시 그룹 개인키를 통해  
인증 게이트를 우회하고 전체 Deco 메시 네트워크에 대한  
설정 조작 / 무서명 펌웨어 플래시 / 완전한 원격 코드 실행이 가능한 취약점
