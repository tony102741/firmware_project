# Vulnerability Pattern Taxonomy

Use one primary pattern and optional secondary tags for each candidate.

## Primary Classes

### 1. Config Injection

User-controlled input is written into configuration material that is later parsed unsafely.

Typical chains:

- web -> nvram / mib / config -> script -> shell
- web -> saved config -> restore parser -> runtime action

### 2. Rule Injection

User input influences firewall, routing, QoS, or ACL rule construction.

Typical chains:

- web -> config -> `iptables` / `route`
- web -> helper binary -> rule string formatting -> kernel rule application

### 3. Command Dispatch

Input reaches `system`, `popen`, or `exec*` directly or via helper wrappers.

Typical chains:

- CGI parameter -> binary -> `popen`
- upload metadata -> shell helper -> `system`

### 4. File Write -> Later Execution

Attacker controls file content or path, and that file is later executed or parsed with privilege.

Typical chains:

- upload -> `/tmp` -> startup script
- restore -> config overwrite -> boot-time execution

### 5. Dynamic Load / Plugin Control

Input controls module path, library path, or runtime-loaded component.

Typical chains:

- config -> path field -> `dlopen`
- file write -> plugin directory -> daemon restart

### 6. Privilege Boundary Crossing

The dangerous step is not direct code execution but privileged state transition.

Typical chains:

- user input -> admin-only config side effect
- low-trust source -> privileged helper / IPC

## Secondary Tags

- `web-cgi`
- `mobile-ui`
- `upload-restore`
- `qos`
- `firewall`
- `route`
- `wireless`
- `auth-bypass-dependent`
- `persistent`
- `post-reboot`

## Strong CVE Signals

- Input is unauthenticated or low-auth.
- Runtime sink is privileged and directly reachable.
- Exploit survives reboot or meaningfully changes security policy.
- Pattern is likely reused across models / vendors.

## Weak Signals

- Only client-side filtering exists.
- Candidate depends on unknown hidden parser behavior.
- Sink is visible only in strings, not in a coherent runtime chain.
- Impact is local-only without privilege escalation or policy break.
