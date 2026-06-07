# 📡 TP-Link Deco XE75 메시 그룹 키 RCE — 베타 패치 검증 분석

> TP-Link Deco XE75 / XE75 Pro 베타 펌웨어(rel57690 / rel57838) 대상  
> 기존 메시 RCE 취약점 수정 여부 정적 검증

---

## 📌 1. Background

• 기존 취약점: `fw_data/user_data/group-info`에 하드코딩된 RSA-512 메시 그룹 개인키를 통한 인증 우회 → UCI 설정 덮어쓰기 / 무서명 펌웨어 플래시 / 전체 메시 피벗  
• TP-Link에서 2026-03-19 날짜로 베타 패치 펌웨어 2종을 배포  
• 본 분석은 베타 펌웨어에서 기존 취약점이 실질적으로 수정되었는지 정적 분석으로 검증

**검증 대상 5개 항목**
1. 키 소재 (group-info, RSA 개인키 구성요소, 키 크기, GID 정적/동적 여부)
2. TDP/TMP 진입점 (포트 20002, CRC32, 신규 인증 메커니즘)
3. sync_slave_check / 그룹 인증 로직
4. 인증 통과 후 민감 오퍼레이션 도달 가능성
5. 패치 판정

---

## 🎯 2. Target

**베타 이미지 1**  
`XE75_XE5300_WE10800-SP1-up-ver1-4-999-P1[20260319-rel57690]_2026-03-19_16.05.04.zip`  
대상 제품: TP-Link Deco XE75 / XE5300 / WE10800  
Rootfs: SquashFS 25.4 MB, 3246 inodes, 빌드 2026-03-19 08:01:51  
MD5 (tmpsvr): `69b86cfed788ea9aa60d313ae777e2e8`

**베타 이미지 2**  
`XE75Pro_XE70Pro-SP1-up-ver1-4-999-P1[20260319-rel57838]_2026-03-19_16.06.21.zip`  
대상 제품: TP-Link Deco XE75 Pro / XE70 Pro  
Rootfs: SquashFS 25.4 MB, 빌드 2026-03-19 08:04:20  
MD5 (tmpsvr): `ab4c8d3cb3d3f8368a5b8346bdff6639`

**핵심 바이너리**  
`/usr/bin/tmpsvr`, `/usr/bin/tmp-luci`, `/usr/lib/libtmpv2.so`, `/usr/lib/lua/luci/model/sync.lua`

**인터페이스**  
`UDP 20002 (TDP)`, `TCP 20002 (TMP)`, `TCP 20001 (Dropbear SSH)`

---

## 🔗 3. 신규 인증 흐름 구조 (tmpv2 v2.0)

베타에서 추가된 인증 레이어:

```
[ 클라이언트 (tmpcd / libtmpv2.so) ]
          ↓  SSH connect → 127.0.0.1 포트 20001 (Dropbear)
          ↓  ssh_userauth_publickey_auto (/etc/dropbear/id_rsa)
          ↓  fallback: ssh_userauth_password (/tmp/ssh_client_sec)
[ Dropbear SSH 데몬 — 포트 20001 ]
          ↓  SSH port-forward
          ↓
[ tmpsvr — TCP 127.0.0.1:20002 (로컬호스트 전용 바인드) ]
          ↓
[ ASSOC 핸드셰이크 — 4-state machine (VA 0xef24) ]
          ↓  UUID 세션 토큰 발급 (uuid_generate_time, 6 sites)
          ↓  "Connection %p received ASSOC REQ. Replying ASSOC ACCEPT"
[ 토큰 검증 통과 후 opcode dispatch ]
          ↓
[ /usr/bin/tmp-luci → luci.sgi.tmp.run() ]
          ↓
[ discover.lua: sync_slave_check ]         ← 여전히 group-info RSA-512 키로 검증
          ↓
[ op_manager.lua: opcode dispatch ]
          ↓
[ inspect_and_save_subconfig → uci_apply  ]  ← 설정 덮어쓰기
[ forward_tmp_request → sync-server → RE  ]  ← 메시 피벗
[ SYNC_FIRMWARE + SYNC_UPGRADE            ]  ← RCE
```

---

## ⚙️ 4. Check 1 — 키 소재 (Key Material)

**판정: NOT FIXED**

`fw_data/user_data/group-info` 파일이 두 베타 이미지 모두에 동일하게 존재하며, 기존 펌웨어와 동일한 키 소재를 포함한다.

**내용 (두 이미지 동일, byte-for-byte):**
```json
{
  "role": "AP",
  "key": "AAAAB3NzaC1yc2EAAAADAQABAAAAQQC/q1ssRADI/lt3+ZqGrkvGFcsqp2YwaDFm4BftZC17y...",
  "gid": "70303de6-63d9-11e8-a3f6-0000eb367511"
}
```

**키 구조 (Dropbear wire format):**

| 필드 | 크기 | 상태 |
|---|---|---|
| type | 7 B | `ssh-rsa` |
| e (public exponent) | 4 B | 65537 |
| n (modulus) | 65 B | RSA-512 공개 모듈러스 |
| d (private exponent) | 64 B | **개인키 d — 베타에도 그대로 존재** |
| p (prime) | 33 B | **소인수 p — 베타에도 그대로 존재** |
| q (prime) | 33 B | **소인수 q — 베타에도 그대로 존재** |

**교차 검증:**
```python
data['key']  == data2['key']   # True  — XE75와 XE75 Pro 키 블롭 동일
data['gid']  == data2['gid']   # True  — GID 동일
# GID: 70303de6-63d9-11e8-a3f6-0000eb367511 (기존 펌웨어와 변경 없음)
```

**RSA-2048 마이그레이션 코드 현황:**

`sync.lua`에 `generate_group_key_rsa_2048`, `save_group_key_rsa_2048`, `load_group_key_2048` 함수가 신규 추가됨 — 그러나 **실행되지 않음**  

`/etc/init.d/luarsa_keys_gen` 및 `/etc/rc.d/S48luarsa_keys_gen` 부팅 스크립트 전체가 주석 처리:
```sh
#if [ ! -e usr/bin/openssl ]; then
# luarsa_keys_gen
#fi
```

`/etc/dropbear/dropbear_rsa_host_key`: 0 bytes (빈 파일 — 런타임 생성 예정이나 키 생성 데몬 비활성)  
`/etc/dropbear/id_rsa`: 펌웨어 내 미존재 — `luarsa_keys_gen`이 비활성이므로 실기기에서도 생성 안 됨

→ RSA-2048 업그레이드 코드는 바이너리에 구현되어 있으나 **배포되지 않음**  
→ 모든 기기가 동일한 RSA-512 개인키를 공유하는 상태 유지

---

## 🔍 5. Check 2 — TDP/TMP 진입점

**판정: PARTIALLY FIXED**

`tmpsvr` 바이너리는 "tmpv2 v2.0"으로 교체됨 (소스 경로 내장: `/home/fanqh/Deco_TPS_XE75/.../tmpv2-2.0/tmp/session.c`)

**포트 바인딩 변경 (정적 확인):**

| 리스너 | 프로토콜 | 바인드 주소 | 변경 여부 |
|---|---|---|---|
| TMP (관리/동기화) | TCP | `127.0.0.1:20002` | **변경됨** — SSH 터널 경유만 가능 |
| TDP (디스커버리) | UDP | `0.0.0.0:20002` | 변경 없음 — LAN 직접 노출 |

코드 근거:
```
VA 0xe5b0: bl #0xca90 (usock)
  x0 = 0x900  ← USOCK_SERVER | USOCK_NUMERIC | TCP
  x1 = "127.0.0.1"
  x2 = "20002"
  → TMP TCP 리스너: 로컬호스트 전용 바인드

VA 0x12758: bl #0xca90 (usock)
  x0 = 0x901  ← USOCK_SERVER | USOCK_NUMERIC | UDP
  x1 = "0.0.0.0"
  x2 = "20002"
  → TDP UDP 리스너: 전체 인터페이스 바인드 (변경 없음)
```

**신규 ASSOC 핸드셰이크:**
- 4-state 머신 (VA 0xef24): ASSOC REQ → ASSOC ACCEPT
- UUID 세션 토큰 발급: `uuid_generate_time` 6개 사이트 호출
- 인증 없는 요청 경고: `"Warning: Received request(opcode: %.4X, flags: %.2X) without authentication"` (VA 0x15e9b)

**CRC32 무결성 검사:** 변경 없음 — 시크릿 키 없이 재계산 가능 (기존과 동일)

**SSH 인증 (클라이언트 측, libtmpv2.so):**
```
ssh_userauth_publickey_auto ← /etc/dropbear/id_rsa (펌웨어에 미존재, 생성 비활성)
  → 실패 시 fallback
ssh_userauth_password       ← /tmp/ssh_client_sec (런타임 생성 패스워드)
```

Dropbear 설정 (`/etc/config/dropbear`):
```
PasswordAuth     on
RootPasswordAuth on
Port             20001
```

`authorized_keys` 파일 없음 — 공개키 인증 신뢰 앵커 미존재

**부분 수정 근거:** TMP 관리 인터페이스가 SSH 터널 경유를 강제하도록 변경되었으나, SSH 인증의 신뢰 앵커(group-info RSA-512 키)가 그대로이므로 공격 경로가 완전히 차단되지 않음

---

## 🔐 6. Check 3 — sync_slave_check / 그룹 인증 로직

**판정: NOT FIXED**

`sync_slave_check` 문자열이 `tmpsvr` (dispatch 테이블), `controller/admin/sync.lua`, `discover.lua`에 모두 존재  

`sync.lua`의 그룹 인증 핵심 함수 유지:
- `read_group_info` — group-info 파티션에서 RSA 키 + GID 로드
- `decrypt_table` — RSA-512 개인키로 챌린지 복호화
- `__check_group_key_valid` — 그룹 키 유효성 검증
- `"group id mismatched"` — 불일치 시 거부 로직

**opcode_whitelist 비활성화 (구조적):**

```lua
-- /usr/bin/tmp-luci (두 이미지 MD5 동일: 6c3b0e88b311a73eeb486d4dcb550783)
local group_info = sync.read_group_info()
if not group_info or not group_info.gid then
    luci.sgi.tmp.set_switch_opcode_whitelist(true)   -- 도달 불가
else
    luci.sgi.tmp.set_switch_opcode_whitelist(false)  -- 항상 실행됨
end
```

`group_info.gid`가 하드코딩(`"70303de6-..."`)으로 항상 non-nil → `set_switch_opcode_whitelist(false)` 항상 호출 → 화이트리스트 영구 비활성  
`/etc/config/firewall`에 `opcode_whitelist` 설정 없음 → UCI 레벨에서도 비활성

---

## 🛡️ 7. Check 4 — 인증 통과 후 민감 오퍼레이션 도달 가능성

**판정: NOT FIXED**

인증(ASSOC) 통과 후 도달 가능한 민감 오퍼레이션이 모두 유지됨:

| 오퍼레이션 | 위치 | 영향 |
|---|---|---|
| `sync_slave_check` | `tmpsvr` dispatch, `discover.lua` | 그룹 인증 게이트 |
| `inspect_and_save_subconfig` | `op_manager.lua` | UCI 설정 전체 덮어쓰기 |
| `SYNC_FIRMWARE` | `tmpv2.so` Lua 바인딩 | 원격 펌웨어 수신 |
| `SYNC_UPGRADE` | `tmpv2.so` Lua 바인딩 | 서명 없는 펌웨어 플래시 → RCE |
| `SYNC_CONFIG` | `tmpv2.so` Lua 바인딩 | nvram 파티션 벌크 교체 |
| `forward_tmp_request` | `sync.lua`, `controller/admin/sync.lua` | 관리자 자격증명으로 RE 전체 피벗 |
| `inspect_subconfig` / `sync_subconfig` | `sync.lua` | 서브설정 조작 |

신규 추가 opcode (기존 오퍼레이션 미제거):
- `TMP_APPV2_OP_PIN_VERIFY`, `TMP_APPV2_OP_HY_PIN_VERIFY`
- `AUTH_GET`
- `TMP_APPV2_OP_SECURITY_WHITELIST_ADD/GET/REMOVE`

---

## 🔄 8. System Relationship (베타 패치 후)

```
[ 공격자 ]
    ↓  SSH connect → 포트 20001 (Dropbear)
    ↓  password auth (/tmp/ssh_client_sec) — ASSOC 통과 후 수신
    ↓  SSH port-forward → 127.0.0.1:20002
    ↓
[ tmpsvr — TCP 127.0.0.1:20002 ]
    ↓  ASSOC handshake (VA 0xef24)
    ↓  group-info RSA-512 개인키로 챌린지 응답 (변경 없음)
    ↓  UUID 세션 토큰 발급
[ tmp-luci → discover.lua ]
    ↓  sync_slave_check (group-info RSA-512 키 — 하드코딩, 변경 없음)
[ op_manager.lua ]
    ├─ c4xx  → uci_apply (/etc/config/*)          ← 설정 덮어쓰기
    ├─ 0x40e0 → firmware flash (서명 검사 없음)    ← RCE
    └─ c40x  → forward_tmp_request
                    ↓  라우터 관리자 자격증명
              [ RE Node 1 ]  [ RE Node 2 ]  [ RE Node N ]
                   ↓               ↓               ↓
            firmware flash   config overwrite  config overwrite

[ TDP UDP 0.0.0.0:20002 ] ← LAN 직접 노출, 디스커버리 전용 (변경 없음)
```

---

## ⚠️ 9. 패치 판정 (Patch Verdict)

### 이미지 1 — XE75 / XE5300 / WE10800 (rel57690)

| 점검 항목 | 판정 | 근거 |
|---|---|---|
| RSA-512 개인키 group-info 하드코딩 | **NOT FIXED** | 두 이미지 동일 키 블롭, 기존과 동일 |
| GID 정적 고정 | **NOT FIXED** | `70303de6-...` 변경 없음 |
| RSA-2048 마이그레이션 | **미배포** | 코드 존재, 부팅 스크립트 전체 주석 처리 |
| TMP 관리 인터페이스 직접 노출 | **FIXED** | 127.0.0.1:20002 로컬호스트 전용 바인드 |
| 신규 ASSOC 인증 레이어 | **ADDED** | SSH 기반 ASSOC + UUID 세션 토큰 |
| ASSOC 신뢰 앵커 | **NOT FIXED** | RSA-512 그룹 키가 여전히 인증 기반 |
| opcode_whitelist | **INOPERATIVE** | 하드코딩 GID로 인해 항상 비활성 |
| CRC32 무결성 | **NOT FIXED** | 시크릿 키 없이 재계산 가능 |
| 민감 오퍼레이션 post-auth 도달 가능 | **NOT FIXED** | SYNC_FIRMWARE/UPGRADE 등 전부 유지 |

**종합 판정: PARTIALLY FIXED**

---

### 이미지 2 — XE75 Pro / XE70 Pro (rel57838)

이미지 1과 모든 판정 동일.  
교차 확인: `group-info` 키 블롭 byte-for-byte 동일, `tmp-luci` MD5 동일(`6c3b0e88b311a73eeb486d4dcb550783`), `sync.lua` 동일 함수 구조, `luarsa_keys_gen` 동일하게 비활성.  
`tmpsvr` MD5는 상이(`ab4c8d3...`)하나 모든 보안 관련 문자열 및 동작 구조 일치.

**종합 판정: PARTIALLY FIXED**

---

## 🧩 10. Conclusion

베타 패치는 TMP 관리 인터페이스를 로컬호스트 전용 바인드로 변경하고 SSH 기반 ASSOC 핸드셰이크를 추가하는 아키텍처 개선을 포함한다. 그러나 이 신규 인증 레이어의 신뢰 앵커는 여전히 기존과 동일한 RSA-512 하드코딩 그룹 키이다. RSA-2048 마이그레이션 코드가 바이너리에 구현되어 있음에도 부팅 스크립트가 전체 주석 처리되어 실기기에서는 RSA-2048 키가 생성되지 않는다. 따라서 펌웨어에서 RSA-512 개인키를 추출한 공격자는 ASSOC를 통과하고 SSH 자격증명을 획득한 뒤 127.0.0.1:20002에 터널링하여 기존과 동일한 민감 오퍼레이션(SYNC_FIRMWARE, SYNC_UPGRADE, forward_tmp_request 등)을 실행할 수 있다. 루트 원인(하드코딩된 RSA-512 그룹 키)이 수정되지 않았으며, 공격 경로에 SSH 터널링 단계 하나가 추가된 것에 불과하다.

---

## 💬 One-line Summary

베타 패치는 SSH 기반 ASSOC 레이어를 추가하고 TMP 포트를 로컬호스트로 제한했으나, 신뢰 앵커인 RSA-512 메시 그룹 개인키와 GID는 변경되지 않았고 RSA-2048 마이그레이션은 배포되지 않아 — 기존 취약점은 SSH 터널링 단계 하나를 추가한 동일한 경로로 여전히 재현 가능하다
