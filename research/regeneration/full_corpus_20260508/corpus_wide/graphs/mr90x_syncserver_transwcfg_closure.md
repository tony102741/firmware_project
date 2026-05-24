# MR90X sync-server trans_*_wcfg Closure

## Target confirmation

- Active Ghidra program: `main at 0040f86c`
- Relevant helper strings:
  - `/lib/sync-server/scripts/trans_main_wcfg`
  - `/lib/sync-server/scripts/trans_backup_wcfg`
  - `/tmp/sync-server/request-input-*`
  - `/tmp/sync-server/request-output-*`

## trans_main_wcfg relationships

- `FUN_0040ec8c`
  - `main_wcfg_trans_call`
  - launches `/lib/sync-server/scripts/trans_main_wcfg`
  - scans `onemesh_client` for `mainWCfgTransNeeded == "1"`
  - resolves textual MAC/IP pairs before helper launch
  - stages `/tmp/sync-server/request-input-*`
  - stages `/tmp/sync-server/request-output-*`
  - registers callback `FUN_0040ec08`
  - appends request object to `main_wcfg_trans_list`

- `FUN_0040ec08`
  - `main_wcfg_trans_proc_cb`
  - callback-side completion path
  - logs staged outfile
  - immediately transitions into cleanup

- `FUN_0040eb8c`
  - `main_wcfg_trans_clean`
  - calls `FUN_0040e5dc(update_main_wcfg_trans_result)` before file unlink
  - unlinks staged input/output files
  - frees request object
  - clears the running flag
  - reschedules timeout handling

- `FUN_0040f5f0`
  - `main_wcfg_trans_timeout_cb`
  - re-enters `FUN_0040ec8c`
  - shows explicit retry/recovery wiring for the main wireless-config transfer family

## trans_backup_wcfg relationships

- `FUN_0040dc5c`
  - `backup_wcfg_trans_call`
  - launches `/lib/sync-server/scripts/trans_backup_wcfg`
  - scans `onemesh_client` for `backupWCfgTransNeeded == "1"`
  - resolves textual MAC/IP pairs before helper launch
  - stages `/tmp/sync-server/request-input-*`
  - stages `/tmp/sync-server/request-output-*`
  - registers callback `FUN_0040dbd8`
  - appends request object to `backup_wcfg_trans_list`

- `FUN_0040dbd8`
  - `backup_wcfg_trans_proc_cb`
  - callback-side completion path
  - logs staged outfile
  - immediately transitions into cleanup

- `FUN_0040db5c`
  - `backup_wcfg_trans_clean`
  - calls `FUN_0040d5ac(update_backup_wcfg_trans_result)` before file unlink
  - unlinks staged input/output files
  - frees request object
  - clears the running flag
  - reschedules timeout handling

## Shared staging and callback infrastructure

`trans_main_wcfg` and `trans_backup_wcfg` reuse the same native orchestration pattern already seen in `request`, `request_clients`, and `sync_wifi`:

1. helper-family entry function
2. textual inventory scan and MAC/IP preparation
3. staged helper input/output file creation
4. callback registration
5. callback-side transition into cleanup
6. downstream native update before staged-file unlink
7. timeout-driven retry or reschedule path

This is strong evidence that `sync-server` is not wrapping isolated helpers one by one. It is reusing one staging/callback lifecycle across multiple helper families.

## Ordering relationships defensible from static evidence

- helper launch precedes callback registration
- staged input/output path setup precedes helper launch
- callback dispatch precedes cleanup
- downstream update function is invoked from cleanup before staged file unlink
- timeout callback can re-enter the family launch path

No stronger runtime ordering is asserted beyond these direct static relationships.

## Downstream propagation

- `FUN_0040e5dc`
  - `update_main_wcfg_trans_result`
  - parses helper JSON output
  - extracts MACs
  - calls `FUN_0040d01c(uciSetOneMeshClientFlag)` with `mainWCfgTransNeeded`

- `FUN_0040d5ac`
  - `update_backup_wcfg_trans_result`
  - parses helper JSON output
  - extracts MACs
  - calls `FUN_0040d01c(uciSetOneMeshClientFlag)` with `backupWCfgTransNeeded`

- `FUN_0040d01c`
  - `uciSetOneMeshClientFlag`
  - traverses `onemesh_client`
  - updates `device` sections
  - commits UCI-backed state

So unlike `request` / `request_clients`, which rematerialize into meshdb and `/tmp/sync-server/onemesh_client_list`, the `trans_*_wcfg` family rematerializes into UCI-backed wireless-config transfer flags.
