# 📡 TP-Link Deco XE75 Hardcoded Mesh Group Key → Full Mesh RCE Vulnerability Analysis

> Technical analysis of the TDP/TMP mesh protocol vulnerability in TP-Link Deco XE75 / XE5300 / WE10800 firmware

---

## 📌 1. Background

• TP-Link Deco series uses a proprietary mesh protocol (TDP/TMP) for AP ↔ RE node communication  
• Mesh node authentication relies on RSA-based group keys stored in the `group-info` partition  
• All Deco XE75/XE5300/WE10800 firmware images ship with an identical RSA-512 **private key**  
• Possessing this key allows an attacker to write UCI configuration, flash unsigned firmware, and pivot across the entire mesh  
• `/usr/bin/tmpsvr` daemon listens on UDP port 20002 (TDP) and TCP port 20002 (TMP)  

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
`Mesh node synchronization / firmware upgrade / configuration distribution`

---

## 🔗 3. Data Flow Structure

```
[ Attacker (UDP 20002 — TDP Packet) ]
          ↓
[ tmpsvr: recvfrom(buf, 0x400) ]
          ↓
[ CRC32 Check (no secret key — forgeable by attacker) ]
          ↓
[ relay_run: fork() → execl("/usr/bin/tmp-luci") ]
          ↓
[ tmp-luci: opcode_whitelist check (absent by default → SKIP) ]
          ↓
[ luci.sgi.tmp.run() → LuCI dispatcher ]
          ↓
[ discover.lua: sync_slave_check ]
          ↓  ← RSA-512 group private key (hardcoded in firmware image)
[ op_manager.lua: opcode dispatch ]
          ↓
[ inspect_and_save_subconfig → uci_apply      ]  ← configuration write
[ forward_tmp_request → sync-server → RE × N  ]  ← full mesh pivot
[ 0x40e0 handler → firmware flash             ]  ← RCE
```

---

## ⚙️ 4. Vulnerability: Hardcoded RSA-512 Private Key

**File:** `fw_data/user_data/group-info` (UBI partition 27, type=USER\_DATA, method=MANU)

**Content (JSON):**
```json
{
  "role": "AP",
  "key": "AAAAB3NzaC1yc2EAAAADAQABAAAAQQC/q1ssRADI...K8eTcQl...",
  "gid": "70303de6-63d9-11e8-a3f6-0000eb367511"
}
```

**Key structure (Dropbear wire format, after base64 decode):**

| Field | Size | Description |
|---|---|---|
| type | 7 B | `ssh-rsa` |
| e (public exponent) | 4 B | 65537 |
| n (modulus) | 65 B | RSA-512 public modulus |
| d (private exponent) | 64 B | **Private key d — present in firmware** |
| p (prime 1) | 33 B | **Prime factor p — present in firmware** |
| q (prime 2) | 33 B | **Prime factor q — present in firmware** |

→ All RSA private key components (n, e, d, p, q) are embedded in the firmware image  
→ Every device running the same firmware shares the **identical group key**  
→ Key extraction from a firmware image alone is sufficient to bypass authentication on any affected device  

---

## 🔍 5. Authentication Gate Analysis

### sync_slave_check (discover.lua, offset 12755)

```
read_group_info()         ← load key from group-info partition
  → compute group_hid (CRC32 of group fields)
  → "group hid mismatched"  (reject on mismatch)
decrypt_table()           ← RSA-512 private-key decryption of challenge
  → compare group_id against "70303de6-63d9-11e8-a3f6-0000eb367511"
  → "group id mismatched"   (reject on mismatch)
  → compare emmc_config_version
  → on pass: encrypt response with encrypt_table() and return
```

**Bypass condition:** Attacker holds the extracted RSA-512 private key → can generate a valid `decrypt_table` response  

### TDP CRC32 (tmpsvr, FUN_00111b50)

```c
*(buf + 8) = 0x5a6b7c8d;    // replace CRC32 field with constant before compute
crc = crc32(buf, pkt_len);  // compute over whole packet
if (crc != stored_crc) drop;
```

→ No secret key involved — CRC32 is recomputable after any packet modification → trivially bypassable  

### opcode_whitelist (tmp-luci)

```lua
local opcode_whitelist = uci_s:get("firewall", "security", "opcode_whitelist")
if opcode_whitelist == "1" then ... end
```

→ The `opcode_whitelist` option is absent from `/etc/config/firewall` → **all opcodes dispatched without filtering**  

---

## 🔐 6. Post-Auth Attack Surface (after passing sync_slave_check)

### A. Full UCI Configuration Overwrite (inspect_and_save_subconfig)

**Opcode:** c4xx series (op_manager.lua registered range: 0xc401–0xc40f)

```
recv TDP (c4xx) → sync_slave_check → inspect_and_save_subconfig
  → md5sum /etc/config/* > <tmpfile>      ← snapshot before change
  → diff                                   ← detect changed configs
  → is_user_config → "user config change!"
  → save_config_version
  → reload_user_config
  → uci_apply                             ← writes directly to /etc/config/*
  → sync_boost_uloop                      ← triggers mesh re-sync
```

**Impact:** Full replacement of UCI configuration — firewall rules, DNS, routing, admin password (`accountmgnt`), etc.  
No secondary authentication between TDP receipt and `uci_apply`.

---

### B. Unsigned Firmware Flash (SYNC\_FIRMWARE + SYNC\_UPGRADE / 0x40e0)

**Path 1 — Integer opcode (op_manager.lua, offset 2885):**
```
recv TDP opcode 0x40e0 → sync_slave_check
  → check memory (get_memfree; threshold 15 MB)
  → echo 3 > /proc/sys/vm/drop_caches (if low)
  → upgrade_type_get (luci.model.sync)
  → mobile_mount if required
  → proceed to firmware flash
```

**Path 2 — SYNC\_FIRMWARE + SYNC\_UPGRADE (C sync-server binary):**  
The master AP runs `lib/sync-server/scripts/firmware` which issues:
```
tmpcli:request("SYNC_FIRMWARE", {host=<ip>, filename=<name>, checksum=<md5>, type=...})
→ sync-server daemon stores firmware at /var/firmwares/<name>
→ verifies md5sum == checksum    ← checksum is attacker-supplied; no signature check
tmpcli:request("SYNC_UPGRADE", {})
→ sync-server flashes /var/firmwares/<name>
```

**No cryptographic signature verification** found in any analyzed code path. The only integrity check is an MD5 that the attacker computes and supplies themselves. `sync_download_bigfirm` (sync.lua:18444) uses `group_id` for download authentication — the same shared value derived from the hardcoded key.

**Impact:** Flash arbitrary firmware → persistent root-level RCE, survives reboots.

---

### C. Full Mesh Pivot via forward_tmp_request

**Opcode:** c40b–c40f range (op_manager.lua)

```
recv TDP → sync_slave_check → forward_tmp_request
  → write JSON {opcode, target_id, params, data}
       → /tmp/sync-server/forward_tmp_request-<pid>
  → ubus call sync request
  → /lib/sync-server/scripts/request <infile> <outfile> <opcode> <ip1> 1 <ip2> 1 ...
```

**`request` script (plaintext Lua — confirmed):**
```lua
local usr = uci_r:get_profile("accountmgnt", "username")
local pwd = uci_r:get_profile("accountmgnt", "password")
-- authenticates to target RE using the router's OWN admin credentials
tmpcli:request(opcode, {infile = infile})
```

**Impact:** A trusted AP can relay **any TMP opcode** to any RE in the mesh using the router's own admin credentials, with fully attacker-controlled `params` and `data`. Compromising a single node enables lateral movement to every satellite in one operation.

---

### D. Bulk Configuration Push via SYNC\_CONFIG

`lib/sync-server/scripts/sync-config` (plaintext — confirmed):
```lua
nvrammanager -p user-config -r <file>     -- master reads its own config
tmpcli:request("SYNC_CONFIG", {infile = config_file})  -- pushes to RE
```
RE's sync-server receives `SYNC_CONFIG` and writes the blob to its `user-config` nvram partition — a bulk overwrite distinct from the UCI-level `inspect_and_save_subconfig` path.

---

### E. Mesh Topology Read — fetch_subconfig

- Reads `/tmp/sync-server/mesh_dev_list` → returns all node IPs, firmware versions, config versions, roles  
- Useful for pre-attack enumeration of pivot targets

---

## 🔄 7. System Relationship

```
[ Attacker ]
    ↓  UDP 20002 (TDP)
[ tmpsvr ]
    ↓  CRC32 (no secret — forgeable)
[ tmp-luci → discover.lua ]
    ↓  sync_slave_check (group-info RSA-512 key — identical across all units)
[ op_manager.lua ]
    ├─ c4xx  → uci_apply (/etc/config/*)
    ├─ 0x40e0 → firmware flash (no signature check)
    └─ c40x  → forward_tmp_request
                    ↓  router admin credentials
              [ RE Node 1 ]  [ RE Node 2 ]  [ RE Node N ]
                   ↓               ↓               ↓
            firmware flash   config overwrite  config overwrite
```

---

## ⚠️ 8. Impact

| Item | Detail |
|---|---|
| **Key size** | RSA-512 is factorable via GNFS within days–weeks using commodity hardware — however, direct extraction from firmware makes factoring unnecessary |
| **Scope** | All units sharing the firmware image are authenticated against with the same key; affects every XE75/XE5300/WE10800 globally |
| **Config overwrite** | Firewall, DNS, routing, admin credentials — full UCI takeover without secondary auth |
| **Firmware flash** | Arbitrary image with no signature check → persistent root backdoor |
| **Mesh pivot** | Single compromised AP → all RE nodes reachable via router's own admin credentials |
| **Credential theft** | `uci_apply` can overwrite `accountmgnt` settings → admin password replacement or extraction |

---

## 🧩 9. Conclusion

TP-Link Deco XE75 firmware ships with a hardcoded RSA-512 mesh group private key that is identical across all units of the same model. An LAN-adjacent attacker who extracts this key from any publicly available firmware image can impersonate a trusted mesh node, bypass `sync_slave_check`, overwrite device configuration via `uci_apply`, flash unsigned arbitrary firmware, and pivot to every satellite node in the mesh — all without any prior authentication and without physical access to the device.

---

## 💬 One-line Summary

A hardcoded RSA-512 mesh group private key embedded in the TP-Link Deco XE75/XE5300/WE10800 firmware image enables any LAN-adjacent attacker to bypass mesh authentication and achieve full-mesh configuration overwrite, unsigned firmware flash, and persistent root-level remote code execution across all nodes.
