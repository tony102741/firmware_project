# Manual Review Diff

- packets: 7
- manual rows: 7
- review statuses: {'REVIEWED': 7}
- mismatch kinds: {'next_action_mismatch': 4, 'risk_family_mismatch': 4}

## Field Accuracy

- `has_rootfs`: 7/7 (1.0000)
- `has_web_ui`: 7/7 (1.0000)
- `artifact_kind`: 7/7 (1.0000)
- `probe_readiness`: 7/7 (1.0000)
- `blob_family`: 7/7 (1.0000)
- `encrypted_container`: 7/7 (1.0000)
- `best_next_action`: 3/7 (0.4286)
- `top_risk_family`: 3/7 (0.4286)

## Review Mismatches

### ASUS / RT-AX58U / 3.0.0.4_388_25127

- `review_id`: `asus-rt-ax58u-3-0-0-4-388-25127`
- `best_next_action`: predicted `triage-top-candidates` vs manual `review-artifacts` (next_action_mismatch)
- `top_risk_family`: predicted `cmd-injection` vs manual `no-clear-rce` (risk_family_mismatch)
- notes: Holdout packet surfaces `httpd` as the top candidate, but the evidence still lacks handler-surface proof and a concrete attacker-controlled command construction path. Keep this family conservative until direct binary review confirms the `foreign_share_file_system()` chain.

### ASUS / RT-AX58U / 3.0.0.4_388_25155

- `review_id`: `asus-rt-ax58u-3-0-0-4-388-25155`
- `best_next_action`: predicted `triage-top-candidates` vs manual `review-artifacts` (next_action_mismatch)
- `top_risk_family`: predicted `cmd-injection` vs manual `no-clear-rce` (risk_family_mismatch)
- notes: Same RT-AX58U packet structure as 25127: strong web stack visibility but no demonstrated request-to-command chain beyond the `httpd` triage summary. Treat this as a known mismatch candidate, not yet as confirmed command injection.

### ASUS / RT-AX58U / 3.0.0.4_388_25277

- `review_id`: `asus-rt-ax58u-3-0-0-4-388-25277`
- `best_next_action`: predicted `triage-top-candidates` vs manual `review-artifacts` (next_action_mismatch)
- `top_risk_family`: predicted `cmd-injection` vs manual `no-clear-rce` (risk_family_mismatch)
- notes: Same RT-AX58U family again: current packet is enough to keep the sample in rootfs-success, but not enough to elevate it to command injection without direct reversing of the `httpd` handler path.

### NETGEAR / RAX50 / V1.0.0.30_2.0.20

- `review_id`: `netgear-rax50-v1-0-0-30-2-0-20`
- `best_next_action`: predicted `triage-top-candidates` vs manual `review-artifacts` (next_action_mismatch)
- notes: The holdout packet shows a clean rootfs extraction but no surfaced candidates, no web-exposed chains, and no stronger structural issue class. Keep this as successful extraction with conservative `no-clear-rce` triage rather than forcing a stronger family.

### Synology / RT6600ax / 9366

- `review_id`: `synology-rt6600ax-9366`
- `top_risk_family`: predicted `container-analysis` vs manual `memory-corruption` (risk_family_mismatch)
- notes: Even though extraction remains blob-level, the strongest repeated signals in the packet are overflow-style library findings (`libdiag.so`, `libtirpc.so`, `liblbcmnlibs.so`) rather than command execution. Keep artifact state conservative but classify the leading risk family as memory-corruption.
