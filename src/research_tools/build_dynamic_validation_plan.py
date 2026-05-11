#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


OUTDIR = Path("/home/user/firmware_project/research/regeneration/full_corpus_20260508")


def write(path: str, text: str) -> None:
    (OUTDIR / path).write_text(text.rstrip() + "\n")


def dynamic_validation_checklist() -> str:
    return """# Dynamic Validation Checklist

## Scope

This checklist targets the highest-value dynamic question in the annotated orchestration graph:

- `MR90X tmp_server.lua -> sync-server`

It also includes direct runtime checks for the already statically-confirmed edges surrounding it, so the runtime experiment can establish a complete local chain.

## Static-Confirmed Edges

- `external packet -> tmpsvr`
- `tmpsvr -> tmp-luci`
- `tmp-luci -> tmp_server.lua`
- `sync-server -> /tmp/sync-server/onemesh_client_list`
- `sync-server -> request / request_clients / sync_wifi`
- `sync-server -> onemesh.lua`

## Dynamic Validation Required Edges

- `tmp_server.lua -> sync-server`
- `sync-server -> meshd / easymesh-side consumers`
- exact runtime trigger conditions for helper execution and state propagation

## Checklist

### 1. Validate `tmpsvr -> tmp-luci -> tmp_server.lua`

- Input stimulus:
  - benign TDP v2 UDP packet to port `20002`
  - JSON body with a marker string such as `MR90X_STAGE1_MARKER`
- Expected observable effect:
  - `tmpsvr` receives the datagram
  - `tmp-luci` is spawned
  - `tmp_server.lua` handles the opcode path or produces a parse/error response
- Files to monitor:
  - `/proc/<tmpsvr-pid>/fd`
  - if available, temporary CGI or LuCI scratch files under `/tmp`
- UCI keys to monitor:
  - none required for stage 1
- Processes to monitor:
  - `tmpsvr`
  - `tmp-luci`
  - optional short-lived `lua`
- Logs to monitor:
  - system log / `logread`
  - console / serial if available
- Commands to run:
  - `ps w | grep -E 'tmpsvr|tmp-luci|lua'`
  - `logread -f`
  - `strace -f -p <tmpsvr-pid> -e execve,recvfrom,sendto,write`
  - `tcpdump -ni any udp port 20002`
- Success criteria:
  - packet arrival is visible
  - `execve("/usr/bin/tmp-luci", ...)` is observed or equivalent child creation is confirmed
  - response behavior is deterministic with the test marker payload
- Failure interpretation:
  - no packet observed: transport/firewall issue
  - packet observed but no child process: opcode/header/CRC issue or non-matching packet type
  - child process observed but no useful result: payload reached Lua but handler/opcode/JSON format is wrong

### 2. Validate `tmp_server.lua -> sync-server`

- Input stimulus:
  - TDP v2 payloads targeting handlers likely to update device/client/mesh metadata
  - benign marker fields such as:
    - `alias = "MR90X_SYNC_MARKER"`
    - `note = "MR90X_SYNC_MARKER"`
    - client-info style JSON using marker strings
- Expected observable effect:
  - after `tmp_server.lua` processing, some state visible to `sync-server` changes
  - state may land in UCI, runtime files, ubus-visible state, or helper invocation arguments
- Files to monitor:
  - `/tmp/sync-server/onemesh_client_list`
  - `/tmp/sync-server/*`
  - `/tmp/client_list.json` if present at runtime
- UCI keys to monitor:
  - `onemesh`
  - `accountmgnt`
  - any tmp/client management namespace surfaced by `uci show`
- Processes to monitor:
  - `sync-server`
  - `tmpsvr`
  - `tmp-luci`
- Logs to monitor:
  - `logread -f`
  - sync-server stderr/stdout if launched manually in a test image
- Commands to run:
  - `uci show onemesh`
  - `ubus list`
  - `ubus -v list tdpServer`
  - `inotifywait -m /tmp/sync-server`
  - `strace -f -p <sync-server-pid> -e openat,read,write,execve`
- Success criteria:
  - a packet-induced state mutation is later read by `sync-server`
  - the same marker or an associated state transition appears in sync-server-observable files/UCI/IPC
- Failure interpretation:
  - no sync-server-visible effect may mean:
    - wrong tmp handler chosen
    - handler writes a different state namespace
    - sync-server only reacts under role/master conditions not currently satisfied

### 3. Validate `sync-server -> helper scripts`

- Input stimulus:
  - place the device in router/master mode with OneMesh enabled
  - stimulate a client-list or wifi-sync relevant state change
- Expected observable effect:
  - `sync-server` executes one or more of:
    - `request`
    - `request_clients`
    - `sync_wifi`
- Files to monitor:
  - helper script paths under `/lib/sync-server/scripts`
  - any helper output files in `/tmp/sync-server`
- UCI keys to monitor:
  - `onemesh.onemesh.enable`
  - `onemesh.onemesh.role`
  - wireless-related keys
- Processes to monitor:
  - `sync-server`
  - child `lua` processes
- Logs to monitor:
  - `logread -f`
  - shell tracing if helpers can be wrapped in a test environment
- Commands to run:
  - `ps w | grep sync-server`
  - `strace -f -p <sync-server-pid> -e execve`
  - `md5sum /tmp/sync-server/onemesh_client_list` in a loop
- Success criteria:
  - direct `execve` into helper scripts is observed
  - helper invocation correlates with a state change caused by the earlier packet stimulus
- Failure interpretation:
  - if helper exec never occurs, sync-server may be gated on role, topology, or timeout conditions rather than immediate update

### 4. Validate `sync-server -> /tmp/sync-server/onemesh_client_list`

- Input stimulus:
  - known benign state change in device/client topology
- Expected observable effect:
  - file created, modified, or rotated
- Files to monitor:
  - `/tmp/sync-server/onemesh_client_list`
  - neighboring `/tmp/sync-server/*`
- UCI keys to monitor:
  - `onemesh` role/enable keys
- Processes to monitor:
  - `sync-server`
- Logs to monitor:
  - `logread -f`
- Commands to run:
  - `inotifywait -m /tmp/sync-server`
  - `watch -n 0.5 'ls -l /tmp/sync-server; sha256sum /tmp/sync-server/onemesh_client_list 2>/dev/null'`
- Success criteria:
  - sync-server updates the file in response to management-plane state changes
- Failure interpretation:
  - the file may only update on timer, topology refresh, or helper completion

### 5. Validate `sync-server -> meshd / easymesh consumers`

- Input stimulus:
  - benign topology/config change that should require downstream mesh action
- Expected observable effect:
  - meshd or EasyMesh processes perform reads or follow-on IPC after sync-server state updates
- Files to monitor:
  - `/tmp/sync-server/*`
  - any mesh topology temp files under `/tmp`
- UCI keys to monitor:
  - `onemesh`
  - wireless-related config
- Processes to monitor:
  - `meshd`
  - `easymesh-agent`
  - `easymesh-controller`
- Logs to monitor:
  - `logread -f`
- Commands to run:
  - `strace -f -p <meshd-pid> -e openat,read,write,execve`
  - `ubus monitor`
- Success criteria:
  - meshd-side activity follows sync-server state mutation in time-correlated fashion
- Failure interpretation:
  - state may stay within sync-server/helper layer for the chosen stimulus
  - chosen marker may not target a state that the EasyMesh lane consumes
"""


def tdpv2_poc_plan() -> str:
    return """# TDP v2 Minimal PoC Plan

## Goal

Build a minimal, safe packet generator that can:
- construct a TDP v2 header
- append a benign JSON payload
- compute the CRC32/integrity field needed for parser acceptance
- send UDP to port `20002`
- receive and parse any response

## Minimal PoC Scaffold

### 1. Header fields

Use a small Python sender that supports:
- `version/header`
- `packet type`
- `opcode`
- `payload length`
- `flags`
- `session_id`
- `checksum / crc32`

The exact field semantics should be taken from the already reconstructed header notes before runtime use.

### 2. CRC32

- Implement standard CRC32 helper in Python using `zlib.crc32`
- Keep the implementation isolated so multiple candidate checksum layouts can be tested
- Log:
  - raw payload hex
  - header hex before checksum
  - final packet hex

### 3. Payload injection

- Start with compact benign JSON:
  - `{"marker":"MR90X_STAGE1_MARKER"}`
- Then evolve to handler-shaped JSON only after stage 1 confirms parser reachability

### 4. UDP transport

- send to `udp/<target-ip>:20002`
- support response timeout and hex dump of any reply

### 5. Response parsing

- log:
  - source IP/port
  - raw response length
  - response header fields
  - payload bytes
- if response payload looks like JSON, pretty-print it

## PoC Structure

Recommended local file layout:

```text
tools/runtime_poc/
  tdpv2_send.py
  payloads/
    stage1_marker.json
    stage2_client_marker.json
  notes.md
```

## Minimal Implementation Outline

```python
payload = b'{"marker":"MR90X_STAGE1_MARKER"}'
header = build_header(
    pkt_type=...,
    opcode=...,
    payload_len=len(payload),
    flags=...,
    session_id=...,
)
checksum = calc_crc32(header, payload)
packet = finalize_packet(header, checksum, payload)
sock.sendto(packet, (target_ip, 20002))
resp, addr = sock.recvfrom(4096)
```

## Safe Defaults

- random session id
- short timeout
- no destructive opcodes
- no repeated flood
- one packet per run until parser format is confirmed
"""


def runtime_observables() -> str:
    return """# MR90X Runtime Observables

## Files

- `/tmp/sync-server/onemesh_client_list`
- `/tmp/sync-server/*`
- `/tmp/client_list.json` if present
- mesh-related scratch files under `/tmp`

## UCI Keys

- `uci show onemesh`
- `uci show accountmgnt`
- `uci show wireless`
- `uci show sysmode`

## Processes

- `tmpsvr`
- `tmp-luci`
- `sync-server`
- `meshd`
- `easymesh-agent`
- `easymesh-controller`
- `ubusd`

## IPC / Control Plane

- `ubus list`
- `ubus -v list tdpServer`
- `ubus monitor`

## Logs

- `logread -f`
- serial console if available

## High-Value Runtime Signals

- `execve("/usr/bin/tmp-luci", ...)`
- `execve("/lib/sync-server/scripts/request", ...)` or equivalent Lua/script child
- file write or rotation of `/tmp/sync-server/onemesh_client_list`
- `uci` reads/writes correlated with packet stimulus
- `meshd` reading updated config/state shortly after sync-server activity
"""


def edge_confirmation_matrix() -> str:
    return """# Edge Confirmation Matrix

| Edge | Static Status | Dynamic Validation Needed | Best Observable | Success Condition | Failure Meaning |
| --- | --- | --- | --- | --- | --- |
| `external -> tmpsvr` | confirmed | optional sanity check | `tcpdump`, `strace recvfrom` | packet observed by `tmpsvr` | transport/firewall issue |
| `tmpsvr -> tmp-luci` | confirmed | yes | `strace execve`, child process observation | `/usr/bin/tmp-luci` executed after packet | bad header/opcode/checksum or different path |
| `tmp-luci -> tmp_server.lua` | confirmed | yes | response behavior, Lua child traces | Lua dispatch triggered | payload not accepted by SGI/handler |
| `tmp_server.lua -> sync-server` | inferred | highest priority | state change later consumed by `sync-server` | marker-correlated state reaches sync-server | wrong handler or missing trigger condition |
| `sync-server -> onemesh_client_list` | confirmed | yes | file update timestamps / hash | file changes after state change | sync not triggered or different state path |
| `sync-server -> request` | confirmed | yes | `execve` into helper | helper invocation observed | role/topology gating |
| `sync-server -> request_clients` | confirmed | yes | `execve` into helper | helper invocation observed | role/topology gating |
| `sync-server -> sync_wifi` | confirmed | yes | `execve` into helper | helper invocation observed | selected state did not trigger wifi sync |
| `uci_onemesh -> meshd` | confirmed | yes | `strace` / `ubus monitor` around `meshd` | meshd reacts after state update | state not consumed by meshd path |
| `meshd -> easymesh consumers` | confirmed/high-confidence | yes | child reads / IPC activity | downstream EasyMesh activity follows | chosen state not relevant to EasyMesh lane |
"""


def safe_test_payloads() -> str:
    return """# Safe Test Payloads

## Allowed Payload Style

- benign JSON only
- marker strings only
- no shell metacharacters needed
- no firmware upload / upgrade requests
- no reboot, reset, or flash operations

## Stage 1 Marker Payload

```json
{"marker":"MR90X_STAGE1_MARKER"}
```

Purpose:
- confirm `tmpsvr -> tmp-luci -> tmp_server.lua` reachability

## Stage 2 Client-Info Style Marker

```json
{
  "alias":"MR90X_SYNC_MARKER",
  "note":"MR90X_SYNC_MARKER",
  "client_id":"MR90X_SYNC_MARKER"
}
```

Purpose:
- probe whether handler-shaped benign fields can be observed later in runtime state

## Stage 3 Non-Destructive Topology Marker

```json
{
  "group_id":"MR90XGROUPMARKER",
  "model":"MR90X_MODEL_MARKER",
  "product_type":"MR90X_PRODUCT_MARKER"
}
```

Purpose:
- only if the chosen opcode/handler is already understood to consume these fields benignly

## Unsafe Tests To Avoid

- firmware flashing / upgrade opcodes
- config overwrite paths that may irreversibly break the device
- payloads containing commands, shell syntax, or filesystem redirection
- high-rate packet floods
- writes to credential fields unless the test environment is disposable
"""


def main() -> None:
    write("dynamic_validation_checklist.md", dynamic_validation_checklist())
    write("tdpuv2_packet_poc_plan.md", tdpv2_poc_plan())
    write("mr90x_runtime_observables.md", runtime_observables())
    write("edge_confirmation_matrix.md", edge_confirmation_matrix())
    write("safe_test_payloads.md", safe_test_payloads())


if __name__ == "__main__":
    main()
