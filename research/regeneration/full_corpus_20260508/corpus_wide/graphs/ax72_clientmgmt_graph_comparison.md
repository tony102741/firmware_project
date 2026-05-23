# AX72 client_mgmt Graph Comparison

## Graph metrics

| Graph | Notes applied | Nodes | Edges | Warnings | Promoted edges |
| --- | ---: | ---: | ---: | ---: | ---: |
| Raw | 0 | 122 | 125 | 0 | 0 |
| Prose-drafted | 3 | 125 | 128 | 0 | 3 |
| Function-scoped | 18 | 133 | 134 | 1 | 11 |

## Prose drafting

The prose path remained weak:

- `3` notes total
- all replay-oriented
- only `3` promoted edges

This confirms the same pattern seen in other OneMesh binaries:

- prose drafting under-captures function-map style targets

## Function-scoped refinement

The function-scoped path materially improved:

- strict MAC normalization visibility
- bounded record ingestion visibility
- UCI mutation visibility
- `/var/state/fing` local-state cleanup visibility
- `history_list` persistence visibility
- `saveconfig()` sink visibility

## Warning interpretation

Only one warning remained:

- `semantic_recurrence_hint recorded but not auto-applied to single-binary graph`

There were no hard typing conflicts in the final function-scoped run.
