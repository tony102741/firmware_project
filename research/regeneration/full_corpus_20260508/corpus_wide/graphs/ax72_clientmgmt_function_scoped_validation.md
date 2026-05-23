# AX72 client_mgmt Function-Scoped Validation

## Target confirmation

- Active Ghidra program matched `ghidra_targets/AX72/client_mgmt`
- confirmed by:
  - `saveconfig`
  - `history_list`
  - `uci_*`
  - `%02x`-formatted shell helper strings

## Function-level anchors recovered

- `FUN_0041b270`
  - strict 17-character textual MAC parser
  - accepts `:` and `-` forms
  - normalizes into a 6-byte native buffer

- `FUN_00409ea4`
  - bounded textual record parser
  - consumes fixed-width textual records
  - converts MAC text into byte-form native records
  - stores bounded textual metadata beside native MAC bytes

- `FUN_0041386c`
  - `uci_lookup_ptr`
  - `uci_set`
  - `uci_save`
  - `uci_commit`
  - generic persistence primitive

- `FUN_00414170`
  - derives node identity
  - reverts `/var/state/fing`
  - deletes matching `history_list` section
  - commits updated config

- `FUN_00413e18`
  - loads or creates `history_list` section
  - persists device-linked metadata
  - invokes `saveconfig()`

- `FUN_004133dc`
  - bulk `history_list` cleanup
  - delete plus commit path

## Main interpretation

`client_mgmt` is the strongest OneMesh downstream normalized sink seen so far:

- upstream text is still visible
- but the sink enforces stricter MAC grammar
- converts text to native bytes
- then performs local and persistent mutation

This is structurally different from:

- `meshd`, which amplifies orchestration
- `sync-server`, which stages and re-ingests helper output

It is the sink-side mutation and normalization boundary.
