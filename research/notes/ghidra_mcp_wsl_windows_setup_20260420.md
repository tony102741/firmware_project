# Ghidra MCP WSL/Windows Setup (2026-04-20)

This note records the working assumptions and fixes for the `Codex (WSL2) ->
MCP bridge (WSL2) -> Ghidra HTTP server (Windows)` setup used during the
`AX3000M` reverse-engineering session.

## Current Project-Side State

Codex is configured to start:

- [run_ghidra_auto_mcp.sh](/home/user/firmware_project/tools/ghidra_11.3.2_PUBLIC/run_ghidra_auto_mcp.sh:1)

via:

- `/home/user/.codex/config.toml`

The wrapper now probes, in order:

1. `http://127.0.0.1:8080/`
2. `http://<nameserver from /etc/resolv.conf>:8080/`
3. `http://<WSL default gateway>:8080/`

So the remaining failure mode is no longer Codex-side address selection. The
remaining failure mode is the Windows Ghidra HTTP bridge not being reachable.

## Required Windows-Side State

The Ghidra HTTP bridge must be reachable from WSL2.

Required conditions:

- bind host should be `0.0.0.0`
- port should be `8080`
- Windows Defender firewall should allow inbound TCP `8080`

If the bridge only binds to `127.0.0.1:8080`, WSL2 default NAT mode will not
reach it.

## Fast Checks

From WSL:

```bash
grep nameserver /etc/resolv.conf
ip route show default
curl http://127.0.0.1:8080/
curl http://$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf):8080/
curl http://$(ip route show default | awk 'NR==1 {print $3}'):8080/
```

From Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\JUNSUNG\firmware_project\tools\ghidra_11.3.2_PUBLIC\check_ghidra_bridge.ps1
```

Adjust the path if the repository is checked out elsewhere on Windows.

## Recommended Fix Order

1. make sure the Windows Ghidra bridge really starts an HTTP server
2. make sure it listens on `0.0.0.0:8080`
3. allow inbound TCP `8080` in Windows Defender
4. restart Codex so the MCP wrapper reconnects cleanly

## Longer-Term Fix

If available on the host:

- enable mirrored networking in `%USERPROFILE%\.wslconfig`

Configuration:

```ini
[wsl2]
networkingMode=mirrored
```

Then:

```powershell
wsl --shutdown
```

In mirrored mode, `localhost:8080` can often be used directly from both sides,
which removes the WSL host-IP churn problem.
