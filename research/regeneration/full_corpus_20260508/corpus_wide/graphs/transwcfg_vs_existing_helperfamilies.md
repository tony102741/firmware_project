# trans_*_wcfg vs Existing sync-server Helper Families

## Graph comparison

| Graph | Notes applied | Nodes | Edges | Warnings | Promoted edges | Hard conflicts |
|---|---:|---:|---:|---:|---:|---:|
| Previous helper-family graph | 55 | 226 | 236 | 1 | 37 | 0 |
| `trans_*_wcfg`-extended graph | 79 | 234 | 252 | 1 | 53 | 0 |

## Coverage change

- structured notes: `55 -> 79`
- promoted edges: `37 -> 53`
- warnings: `1 -> 1`
- hard conflicts: `0 -> 0`

The remaining warning is still the intentionally non-applied `semantic_recurrence_hint`.

## What increased

The extension did not materially change raw helper-node counts. It increased graph quality by adding function-scoped relationships:

- entry -> launch wrapper
- launch wrapper -> helper path
- launch wrapper -> staged request-input/output objects
- callback -> cleanup
- cleanup -> downstream UCI-backed propagation
- timeout/retry -> family relaunch

## Reuse vs family-specific behavior

### Reused across families

- staged helper I/O path convention
- callback registration and completion path
- cleanup-side unlink and object teardown
- reschedule or retry handling

### Family-specific behavior

- `request` / `request_clients`
  - client-list and meshdb rematerialization
- `sync_wifi`
  - main wireless transfer flag updates
- `trans_main_wcfg`
  - UCI-backed `mainWCfgTransNeeded` propagation
- `trans_backup_wcfg`
  - UCI-backed `backupWCfgTransNeeded` propagation

## Assessment

With `trans_*_wcfg` closed, `sync-server` now supports a stronger architectural claim:

- it is a reusable multi-family orchestration/staging bridge
- helper-family differences sit mainly in downstream state projection
- staging, callback, and cleanup lifecycles are reused rather than reinvented for each helper
