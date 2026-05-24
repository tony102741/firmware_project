# trans_*_wcfg Helper Family Assessment

## What this family adds

The `trans_main_wcfg` and `trans_backup_wcfg` helpers extend the already-validated `sync-server` staging model into a wireless-config transfer family.

This matters because the architecture now covers:

- `request`
- `request_clients`
- `sync_wifi`
- `trans_main_wcfg`
- `trans_backup_wcfg`

with the same high-level orchestration discipline:

- helper launch from native entry functions
- `/tmp/sync-server/request-input-*` staging
- `/tmp/sync-server/request-output-*` staging
- callback-side completion
- cleanup-side downstream update
- timeout-driven retry or reschedule

## Architectural interpretation

The `trans_*_wcfg` family is not just another shell helper call.

It shows that `sync-server` reuses one multi-family bridge pattern across:

- inventory request helpers
- client-list refresh helpers
- Wi-Fi synchronization helpers
- wireless-config transfer helpers

The difference between families is downstream target, not orchestration style.

## Downstream difference from existing families

| Helper family | Downstream target |
|---|---|
| `request` | meshdb + staged client-list state |
| `request_clients` | meshdb + `/tmp/sync-server/onemesh_client_list` |
| `sync_wifi` | `onemesh_client` UCI-backed main transfer flags |
| `trans_main_wcfg` | `onemesh_client` UCI-backed `mainWCfgTransNeeded` flags |
| `trans_backup_wcfg` | `onemesh_client` UCI-backed `backupWCfgTransNeeded` flags |

## Static evidence quality

- launch wrappers: direct function-level confirmation
- staged file paths: direct function-level confirmation
- callback linkage: direct function-level confirmation
- cleanup-side update call: direct function-level confirmation
- timeout-driven relaunch:
  - confirmed for `main_wcfg_trans_timeout_cb`
  - backup family retains reschedule behavior through cleanup even without a separate named timeout function being closed here

## Remaining limits

- no exploitability claim
- no stronger runtime ordering than directly visible call relationships
- no automatic semantic recurrence application
- adjacent `trans_*` variants outside `main`/`backup` remain future work
