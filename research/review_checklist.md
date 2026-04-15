# Vulnerability Review Checklist

Use this checklist before promoting any candidate to "real vulnerability".

## Gate 1: Reachable Input

- Entry point is identified exactly.
- Input source is controllable by an attacker.
- Authentication requirement is known.
- The input path is not dead code.

## Gate 2: Full Processing Chain

- Input is traced through every material hop.
- Intermediate storage is identified.
- Crossing points are recorded.
  - Web -> config
  - Config -> script
  - Script -> binary
  - File write -> later parse / execution

## Gate 3: Real Sink

- Sink is concrete and executable.
- Sink class is one of:
  - `system` / `popen` / `exec*`
  - rule generation (`iptables`, `nft`, `route`, firewall helpers)
  - privileged file write with later execution or parse
  - dynamic loading / command dispatch
- Runtime trigger condition is known.

## Gate 4: Validation Quality

- Validation is present or absent.
- If present, reason why it is insufficient.
- Exact structure-breaking primitive is identified.
  - shell metacharacter injection
  - rule / delimiter injection
  - path traversal / filename control
  - format / parser confusion

## Gate 5: Security Impact

- Impact is concrete.
- Privilege boundary is described.
- Runtime result is one of:
  - command execution
  - firewall / routing manipulation
  - config persistence with later code execution
  - privileged file overwrite
- If impact is only UI, discard.

## Final Verdict Rules

- `CONFIRMED`: controllable input, reachable sink, insufficient validation, concrete impact.
- `LIKELY`: one hop still inferred, but exploit chain is coherent and runtime sink is real.
- `REJECTED`: dead code, no control, strong validation, no runtime sink, or low-impact only.

## Minimum Notes To Record

- Firmware / version
- Entry point
- Input fields
- Processing chain
- Sink
- Validation note
- Impact note
- Reproduction idea
- Why accepted or rejected
