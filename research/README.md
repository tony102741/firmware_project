# Research Workflow

This folder is the long-term record for vulnerability research across many firmware images.

## Files

- `review_checklist.md` — fixed exploitability gate before accepting a bug
- `pattern_taxonomy.md` — reusable vulnerability classes and tags
- `candidate_ledger.schema.json` — canonical ledger entry format
- `candidate_ledger.template.jsonl` — example entry

## Recommended Process

1. Run the pipeline on a firmware image.
2. Read `runs/<run>/results.json` and `dossiers/`.
3. Review only strong candidates against `review_checklist.md`.
4. Record each investigated candidate in your own ledger file using the schema here.
5. Mark each reviewed candidate as one of:
   - `CONFIRMED`
   - `LIKELY`
   - `REJECTED`
   - `NEEDS_MORE_WORK`
6. Tag the candidate with one primary pattern from `pattern_taxonomy.md`.

## Ledger Conventions

- One JSON object per line.
- Keep rejected candidates too.
- Always write why a candidate was rejected.
- Prefer real chain descriptions over abstract labels.
- If a pattern repeats across vendors, preserve the same primary tag.

## Minimum Research Questions Per Candidate

- What exact user-controlled field starts the chain?
- Where is it stored or transformed?
- What real runtime sink executes?
- Why does validation fail?
- What concrete security boundary is crossed?
