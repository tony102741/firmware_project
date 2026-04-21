# Candidate Alignment Snapshot

- corpus: `research/corpus/firmware_corpus.jsonl`
- ledgers: `1`

## Overall

| Metric | Value |
|---|---:|
| reviewed entries | `8` |
| matched by any pipeline candidate | `8` (100.0%) |
| matched by top shortlist candidate | `8` (100.0%) |
| missed by any pipeline candidate | `0` (0.0%) |
| unmatched pipeline top candidates | `45` |

## Reviewed Families Only

| Metric | Value |
|---|---:|
| reviewed entries | `8` |
| matched by any pipeline candidate | `8` (100.0%) |
| matched by top shortlist candidate | `8` (100.0%) |
| ranking misses (matched somewhere, not in top shortlist) | `0` |
| granularity misses | `0` |
| semantic misses | `0` |
| coverage misses | `0` |
| unmatched pipeline top candidates in reviewed families | `21` |

## Family Detail

### Cudy WR1300 V4

- versions in corpus: `R98-2.3.8-20250124-115930, R98-2.4.22-20251126-095302`
- runs: `2`
- review entries: `0`
- pipeline candidates: `14`
- pipeline top shortlist: `6`

- pipeline shortlist items without reviewed counterpart yet:
  - `system.lua`: pre-auth HTTP Command Injection via administration → /bin/sh
  - `system.lua`: pre-auth HTTP Command Injection via administration → /bin/sh
  - `system.lua`: pre-auth HTTP Command Injection via firmware.bin → /bin/sh
  - `system.lua`: pre-auth HTTP Command Injection via firmware.bin → /bin/sh
  - `autoupgrade.lua`: post-auth HTTP Command Injection via firmware.bin → /bin/sh

### Cudy WR3000E

- versions in corpus: `R53-2.2.7-20240910-160305, R53-2.4.7-20250528-182254`
- runs: `2`
- review entries: `1`
- pipeline candidates: `16`
- pipeline top shortlist: `6`

- matched in pipeline top shortlist:
  - `system.lua administration path to /bin/sh` -> `system.lua` (score `25`, reasons: endpoint:/administration, sink, tokens:administration,bin,controller,http, name)
- pipeline shortlist items without reviewed counterpart yet:
  - `system.lua`: pre-auth HTTP Command Injection via administration → /bin/sh
  - `system.lua`: pre-auth HTTP Command Injection via firmware.bin → /bin/sh
  - `autoupgrade.lua`: post-auth HTTP Command Injection via firmware.bin → /bin/sh
  - `system.lua`: pre-auth HTTP Command Injection via firmware.bin → /bin/sh
  - `autoupgrade.lua`: post-auth HTTP Command Injection via firmware.bin → /bin/sh

### ipTIME AX2004M

- versions in corpus: `14.234, 15.028, 15.330`
- runs: `3`
- review entries: `0`
- pipeline candidates: `12`
- pipeline top shortlist: `9`

- pipeline shortlist items without reviewed counterpart yet:
  - `arp_protection`: pre-auth HTTP Command Injection → Print MAC address in system(Flash)
  - `arp_protection`: pre-auth HTTP Command Injection → Print MAC address in system(Flash)
  - `unit_test.sh`: Shell script unquoted variable injection via FILENAME, DOWNLOAD_URL
  - `easycwmp`: Shell script unquoted variable injection via __arg3, __arg4, SERIAL_NUMBER
  - `unit_test.sh`: Shell script unquoted variable injection via FILENAME, DOWNLOAD_URL, version

### ipTIME AX3000M

- versions in corpus: `14.234, 15.024, 15.330`
- runs: `3`
- review entries: `2`
- pipeline candidates: `127`
- pipeline top shortlist: `7`

- matched in pipeline top shortlist:
  - `d.cgi config endpoint to popen heuristic` -> `d.cgi` (score `21`, reasons: endpoint:/config, sink, tokens:popen, name)
  - `hidden diagnostic d.cgi cmd parameter to popen` -> `d.cgi` (score `22`, reasons: text-endpoint:d.cgi, sink, tokens:bin,home,httpd,popen, name)
- pipeline shortlist items without reviewed counterpart yet:
  - `arp_protection`: pre-auth HTTP Command Injection → system
  - `arp_protection`: pre-auth HTTP Command Injection → execvp
  - `upnpd`: post-auth HTTP Command Injection via UPnPError → execvp
  - `chgrp`: pre-auth HTTP Command Injection via firmware → popen
  - `apscan`: post-auth FILE Command Injection via firmware → execve

### TOTOLINK A3002RU

- versions in corpus: `V3.0.0-B20201208, V3.0.0-B20220304.1804, V3.0.0-B20230809.1615`
- runs: `3`
- review entries: `3`
- pipeline candidates: `32`
- pipeline top shortlist: `9`

- matched in pipeline top shortlist:
  - `formWsc peer PIN command injection` -> `boa/formUploadFile` (score `14`, reasons: endpoint:/boafrm/formWsc, tokens:boa,boafrm,formwsc,http)
  - `repeater site-survey SSID command injection` -> `boa/formUploadFile` (score `14`, reasons: endpoint:/boafrm/formWlSiteSurvey, tokens:boa,boafrm,formwlsitesurvey,via)
  - `formUploadFile filename command injection` -> `boa/formUploadFile` (score `14`, reasons: endpoint:/boafrm/formUploadFile, tokens:boa,boafrm,formuploadfile,post)
- pipeline shortlist items without reviewed counterpart yet:
  - `boa`: post-auth HTTP Command Injection via Config*.bin → /bin/sh
  - `boa`: post-auth HTTP Command Injection via Config*.bin → /bin/sh
  - `sysconf`: pre-auth HTTP File-based Command Injection via groupIndex → echo %s:x:0:0:%s:/:/bin/sh >> /var/passwd
  - `sysconf`: pre-auth HTTP File-based Command Injection via vsftpd.conf → echo "%s:x:0:0:%s:/:/bin/sh" >> /var/passwd
  - `sysconf`: pre-auth HTTP File-based Command Injection via vsftpd.conf → echo "%s:x:0:0:%s:/:/bin/sh" >> /var/passwd

### TOTOLINK X6000R

- versions in corpus: `V9.4.0cu.1498_B20250826_ALL`
- runs: `1`
- review entries: `2`
- pipeline candidates: `8`
- pipeline top shortlist: `3`

- matched in pipeline top shortlist:
  - `mtkwifi apcli_connect command substitution injection` -> `mtkwifi.lua/submit_dpp_uri` (score `14`, reasons: endpoint:apcli_connect, tokens:apcli,apclissid,apcliwpapsk,bin)
  - `mtkwifi submit_dpp_uri direct os.execute injection` -> `mtkwifi.lua/submit_dpp_uri` (score `14`, reasons: endpoint:/admin/mtk/multi_ap/submit_dpp_uri, tokens:bin,code,dpp,execute)
- pipeline shortlist items without reviewed counterpart yet:
  - `ipsec.lua/ipsec_vpn_disconnect`: post-auth HTTP Command Injection via ipsec_vpn_disconnect → local handle = io.popen(" ipsec status  2>/dev/null")
  - `cwmpd`: post-auth HTTP Command Injection via PortMapping.c → IPPingDiagnostics: popen() -> %s

### TP-Link Archer AX23

- versions in corpus: `1.2_250904`
- runs: `1`
- review entries: `0`
- pipeline candidates: `12`
- pipeline top shortlist: `3`

- pipeline shortlist items without reviewed counterpart yet:
  - `firmware.lua`: post-auth HTTP Command Injection via config → | grep -v grep | grep -v '/bin/sh' | awk '{print $1}'
  - `easymesh_network.lua`: pre-auth HTTP Command Injection via firmware_install_status.lua → | grep -v grep | grep -v '/bin/sh' | awk '{print $1}'
  - `offline_download_monitor.lua`: post-auth HTTP Command Injection via config → /bin/sh

### TP-Link XE75 / XE5300 / WE10800

- versions in corpus: `1.3.1 P1 [20251023-rel43624], ver1-2-14-20241015`
- runs: `2`
- review entries: `0`
- pipeline candidates: `14`
- pipeline top shortlist: `6`

- pipeline shortlist items without reviewed counterpart yet:
  - `ndppd`: post-auth HTTP Command Injection via config → session::system(
  - `ndppd`: post-auth HTTP Command Injection via config → session::system(
  - `wifi`: Shell script unquoted variable injection via vap, mac
  - `wifi`: Shell script unquoted variable injection via vap, mac
  - `fw_input.sh`: Shell script unquoted variable injection via client_ip, app_ip, client_ip
