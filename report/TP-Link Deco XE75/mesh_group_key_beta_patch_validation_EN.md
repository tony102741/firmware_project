# 📡 TP-Link Deco XE75 Mesh Group Key RCE — Beta Patch Validation Analysis

> Static validation of the original mesh RCE fix against TP-Link Deco XE75 / XE75 Pro beta firmware (rel57690 / rel57838)

---

## 📌 1. Background

• Original vulnerability: hardcoded RSA-512 mesh group private key in `fw_data/user_data/group-info` → authentication bypass → UCI config overwrite / unsigned firmware flash / full mesh pivot  
• TP-Link released two beta patch firmware images dated 2026-03-19  
• This analysis statically verifies whether the beta firmware meaningfully addresses the reported vulnerability

**Five validation categories:**
1. Key material — group-info, RSA private components, key size, static vs. dynamic GID
2. TDP/TMP entry point — port 20002 binding, CRC32, new authentication mechanisms
3. sync_slave_check / group authentication logic
4. Sensitive operation reachability after authentication
5. Patch verdict

---

## 🎯 2. Target

**Beta Image 1**  
`XE75_XE5300_WE10800-SP1-up-ver1-4-999-P1[20260319-rel57690]_2026-03-19_16.05.04.zip`  
Products: TP-Link Deco XE75 / XE5300 / WE10800  
Rootfs: SquashFS 25.4 MB, 3246 inodes, built 2026-03-19 08:01:51  
MD5 (tmpsvr): `69b86cfed788ea9aa60d313ae777e2e8`

**Beta Image 2**  
`XE75Pro_XE70Pro-SP1-up-ver1-4-999-P1[20260319-rel57838]_2026-03-19_16.06.21.zip`  
Products: TP-Link Deco XE75 Pro / XE70 Pro  
Rootfs: SquashFS 25.4 MB, built 2026-03-19 08:04:20  
MD5 (tmpsvr): `ab4c8d3cb3d3f8368a5b8346bdff6639`

**Key binaries analyzed**  
`/usr/bin/tmpsvr`, `/usr/bin/tmp-luci`, `/usr/lib/libtmpv2.so`, `/usr/lib/lua/luci/model/sync.lua`

**Interfaces**  
`UDP 20002 (TDP)`, `TCP 20002 (TMP)`, `TCP 20001 (Dropbear SSH)`

---

## 🔗 3. New Authentication Flow (tmpv2 v2.0)

The beta introduces an additional authentication layer over the original protocol:

```
[ Client (tmpcd / libtmpv2.so) ]
          ↓  SSH connect → port 20001 (Dropbear)
          ↓  ssh_userauth_publickey_auto (/etc/dropbear/id_rsa)
          ↓  fallback: ssh_userauth_password (/tmp/ssh_client_sec)
[ Dropbear SSH daemon — port 20001 ]
          ↓  SSH port-forward
          ↓
[ tmpsvr — TCP 127.0.0.1:20002 (localhost-only bind) ]
          ↓
[ ASSOC handshake — 4-state machine (VA 0xef24) ]
          ↓  UUID session token issued (uuid_generate_time, 6 call sites)
          ↓  "Connection %p received ASSOC REQ. Replying ASSOC ACCEPT"
[ Token verified → opcode dispatch ]
          ↓
[ /usr/bin/tmp-luci → luci.sgi.tmp.run() ]
          ↓
[ discover.lua: sync_slave_check ]         ← still verified against group-info RSA-512 key
          ↓
[ op_manager.lua: opcode dispatch ]
          ↓
[ inspect_and_save_subconfig → uci_apply  ]  ← configuration overwrite
[ forward_tmp_request → sync-server → RE  ]  ← mesh pivot
[ SYNC_FIRMWARE + SYNC_UPGRADE            ]  ← RCE
```

---

## ⚙️ 4. Check 1 — Key Material

**Verdict: NOT FIXED**

`fw_data/user_data/group-info` is present in both beta images, containing key material identical to the original firmware.

**Content (both images — byte-for-byte identical):**
```json
{
  "role": "AP",
  "key": "AAAAB3NzaC1yc2EAAAADAQABAAAAQQC/q1ssRADI/lt3+ZqGrkvGFcsqp2YwaDFm4BftZC17y...",
  "gid": "70303de6-63d9-11e8-a3f6-0000eb367511"
}
```

**Key structure (Dropbear wire format):**

| Field | Size | Status in beta |
|---|---|---|
| type | 7 B | `ssh-rsa` |
| e (public exponent) | 4 B | 65537 |
| n (modulus) | 65 B | RSA-512 public modulus |
| d (private exponent) | 64 B | **Private key d — unchanged, still present** |
| p (prime 1) | 33 B | **Prime factor p — unchanged, still present** |
| q (prime 2) | 33 B | **Prime factor q — unchanged, still present** |

**Cross-image verification:**
```python
data['key']  == data2['key']   # True  — XE75 and XE75 Pro key blobs identical
data['gid']  == data2['gid']   # True  — GID unchanged
# GID: 70303de6-63d9-11e8-a3f6-0000eb367511 (same as pre-patch firmware)
```

**RSA-2048 migration status:**

`sync.lua` contains new functions `generate_group_key_rsa_2048`, `save_group_key_rsa_2048`, `load_group_key_2048` — code is present but **never executed**

Startup scripts `/etc/init.d/luarsa_keys_gen` and `/etc/rc.d/S48luarsa_keys_gen` are entirely commented out:
```sh
#if [ ! -e usr/bin/openssl ]; then
# luarsa_keys_gen
#fi
```

`/etc/dropbear/dropbear_rsa_host_key`: 0 bytes — placeholder; key generation daemon is inactive  
`/etc/dropbear/id_rsa`: absent from firmware — not generated on real devices either, since `luarsa_keys_gen` is disabled

→ RSA-2048 upgrade is implemented in code but **not deployed** — all devices continue to share the same RSA-512 private key

---

## 🔍 5. Check 2 — TDP/TMP Entry Point

**Verdict: PARTIALLY FIXED**

`tmpsvr` binary replaced with "tmpv2 v2.0" (embedded source path: `/home/fanqh/Deco_TPS_XE75/.../tmpv2-2.0/tmp/session.c`)

**Port binding changes (statically confirmed):**

| Listener | Protocol | Bind address | Change |
|---|---|---|---|
| TMP (admin / sync) | TCP | `127.0.0.1:20002` | **Changed** — SSH tunnel required |
| TDP (discovery) | UDP | `0.0.0.0:20002` | Unchanged — still LAN-exposed |

Code evidence:
```
VA 0xe5b0: bl #0xca90 (usock)
  x0 = 0x900  ← USOCK_SERVER | USOCK_NUMERIC | TCP
  x1 = "127.0.0.1"
  x2 = "20002"
  → TMP TCP listener: localhost-only bind

VA 0x12758: bl #0xca90 (usock)
  x0 = 0x901  ← USOCK_SERVER | USOCK_NUMERIC | UDP
  x1 = "0.0.0.0"
  x2 = "20002"
  → TDP UDP listener: all-interface bind (unchanged)
```

**New ASSOC handshake:**
- 4-state machine at VA 0xef24: ASSOC REQ → ASSOC ACCEPT
- UUID session token issuance: `uuid_generate_time` called at 6 sites
- Unauthenticated request gate: `"Warning: Received request(opcode: %.4X, flags: %.2X) without authentication"` at VA 0x15e9b

**CRC32 packet integrity:** unchanged — recomputable without any secret key (same as before)

**SSH transport (client side, libtmpv2.so):**
```
ssh_userauth_publickey_auto ← /etc/dropbear/id_rsa (absent from firmware; key generation disabled)
  → fails; fallback to:
ssh_userauth_password       ← /tmp/ssh_client_sec (runtime-generated password)
```

Dropbear configuration (`/etc/config/dropbear`):
```
PasswordAuth     on
RootPasswordAuth on
Port             20001
```

No `authorized_keys` file present in firmware — no public-key trust anchor on the server side

**Rationale for partial fix:** The TMP admin interface now requires an SSH tunnel, which is a meaningful architectural change. However, the SSH authentication trust anchor is the same group-info RSA-512 key — an attacker who has extracted the private key can still pass ASSOC, receive SSH credentials, and reach the admin interface.

---

## 🔐 6. Check 3 — sync_slave_check / Group Authentication Logic

**Verdict: NOT FIXED**

`sync_slave_check` string present in `tmpsvr` dispatch table, `controller/admin/sync.lua`, and `discover.lua`

Core group authentication functions retained in `sync.lua`:
- `read_group_info` — loads RSA key and GID from group-info partition
- `decrypt_table` — RSA-512 private-key decryption of authentication challenge
- `__check_group_key_valid` — group key validity check
- `"group id mismatched"` — reject path on mismatch

**opcode_whitelist permanently disabled (structural):**

```lua
-- /usr/bin/tmp-luci (both images MD5 identical: 6c3b0e88b311a73eeb486d4dcb550783)
local group_info = sync.read_group_info()
if not group_info or not group_info.gid then
    luci.sgi.tmp.set_switch_opcode_whitelist(true)   -- unreachable
else
    luci.sgi.tmp.set_switch_opcode_whitelist(false)  -- always executed
end
```

`group_info.gid` is hardcoded (`"70303de6-..."`) and therefore always non-nil → `set_switch_opcode_whitelist(false)` always called → opcode whitelist permanently disabled  
`opcode_whitelist` option absent from `/etc/config/firewall` — inactive at UCI level as well

---

## 🛡️ 7. Check 4 — Sensitive Operation Reachability After Authentication

**Verdict: NOT FIXED**

All sensitive operations from the original vulnerability remain reachable after ASSOC:

| Operation | Location | Impact |
|---|---|---|
| `sync_slave_check` | `tmpsvr` dispatch, `discover.lua` | Authentication gate |
| `inspect_and_save_subconfig` | `op_manager.lua` | Full UCI configuration overwrite |
| `SYNC_FIRMWARE` | `tmpv2.so` Lua binding | Remote firmware fetch from attacker server |
| `SYNC_UPGRADE` | `tmpv2.so` Lua binding | Unsigned firmware flash → persistent RCE |
| `SYNC_CONFIG` | `tmpv2.so` Lua binding | nvram partition bulk overwrite |
| `forward_tmp_request` | `sync.lua`, `controller/admin/sync.lua` | Relay any opcode to all RE nodes via router admin credentials |
| `inspect_subconfig` / `sync_subconfig` | `sync.lua` | Sub-configuration manipulation |

New opcodes added but no existing sensitive operations removed:
- `TMP_APPV2_OP_PIN_VERIFY`, `TMP_APPV2_OP_HY_PIN_VERIFY`
- `AUTH_GET`
- `TMP_APPV2_OP_SECURITY_WHITELIST_ADD/GET/REMOVE`

---

## 🔄 8. System Relationship (After Beta Patch)

```
[ Attacker ]
    ↓  SSH connect → port 20001 (Dropbear)
    ↓  password auth via /tmp/ssh_client_sec (obtained after passing ASSOC)
    ↓  SSH port-forward → 127.0.0.1:20002
    ↓
[ tmpsvr — TCP 127.0.0.1:20002 ]
    ↓  ASSOC handshake (VA 0xef24)
    ↓  group-info RSA-512 private key used to answer challenge (unchanged)
    ↓  UUID session token issued
[ tmp-luci → discover.lua ]
    ↓  sync_slave_check (group-info RSA-512 key — hardcoded, unchanged across all units)
[ op_manager.lua ]
    ├─ c4xx  → uci_apply (/etc/config/*)          ← config overwrite
    ├─ 0x40e0 → firmware flash (no signature check) ← RCE
    └─ c40x  → forward_tmp_request
                    ↓  router admin credentials
              [ RE Node 1 ]  [ RE Node 2 ]  [ RE Node N ]
                   ↓               ↓               ↓
            firmware flash   config overwrite  config overwrite

[ TDP UDP 0.0.0.0:20002 ] ← LAN-exposed, discovery only (unchanged)
```

---

## ⚠️ 9. Patch Verdict

### Image 1 — XE75 / XE5300 / WE10800 (rel57690)

| Check item | Verdict | Evidence |
|---|---|---|
| RSA-512 private key hardcoded in group-info | **NOT FIXED** | Identical key blob in both beta images; unchanged from original |
| Static GID | **NOT FIXED** | `70303de6-...` unchanged |
| RSA-2048 key migration | **NOT DEPLOYED** | Code present in sync.lua; startup script entirely commented out |
| TMP admin interface directly LAN-exposed | **FIXED** | TCP bound to 127.0.0.1:20002; SSH tunnel required |
| New ASSOC authentication layer | **ADDED** | SSH-based ASSOC handshake + UUID session tokens |
| ASSOC trust anchor | **NOT FIXED** | RSA-512 group key still the credential; unchanged |
| opcode_whitelist | **INOPERATIVE** | Hardcoded GID prevents activation in all cases |
| CRC32-only packet integrity | **NOT FIXED** | No secret key involved; recomputable after packet modification |
| Sensitive operations reachable post-auth | **NOT FIXED** | SYNC_FIRMWARE, SYNC_UPGRADE, forward_tmp_request all retained |

**Overall verdict: PARTIALLY FIXED**

---

### Image 2 — XE75 Pro / XE70 Pro (rel57838)

All verdicts identical to Image 1.  
Cross-image confirmation: `group-info` key blob byte-for-byte identical; `tmp-luci` MD5 identical (`6c3b0e88b311a73eeb486d4dcb550783`); `sync.lua` same function structure; `luarsa_keys_gen` identically disabled.  
`tmpsvr` MD5 differs (`ab4c8d3...`) as expected for a separate build target; all security-relevant strings and behaviors match.

**Overall verdict: PARTIALLY FIXED**

---

## 🧩 10. Conclusion

The beta patch introduces a meaningful architectural change: the TMP admin interface is bound to localhost and requires an SSH tunnel, and a new four-state ASSOC handshake with UUID session tokens adds a protocol-level authentication layer. However, the trust anchor for this new authentication system is still the same hardcoded RSA-512 group private key that was the root cause of the original vulnerability. The RSA-2048 migration infrastructure (`generate_group_key_rsa_2048`, `luarsa_keys_gen`) is implemented in code but entirely disabled in the distributed firmware — no device running this beta will generate a unique key. An attacker who extracts the RSA-512 private key from any affected firmware image can still pass the ASSOC challenge, receive SSH credentials, tunnel to `127.0.0.1:20002`, and execute the same sensitive operations (SYNC_FIRMWARE, SYNC_UPGRADE, forward_tmp_request) as before. The root cause is not fixed; the attack chain gains one additional SSH tunneling step.

---

## 💬 One-line Summary

The beta patch adds an SSH-based ASSOC layer and restricts the TMP port to localhost, but the RSA-512 mesh group private key and static GID remain unchanged and the RSA-2048 migration is not deployed — the original vulnerability is still reproducible via the same attack chain, with one SSH tunneling step added.
