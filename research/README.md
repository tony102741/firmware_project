# Research Workflow

This folder is the long-term record for vulnerability research across many firmware images.

## Layout

- `corpus/` — live corpus inventory, templates, and field guides
- `review/framework/` — review checklist, pattern taxonomy, and candidate-ledger schema
- `review/llm/` — review packets, predictions, gold labels, and LLM field docs
- `review/manual/` — manual review labels, diffs, and review queue outputs
- `holdout/` — blind-first holdout predictions and comparison snapshots
- `snapshots/` — aggregate evaluation tables and snapshot markdown/json outputs
- `notes/` — working notes, follow-up writeups, and historical context
- `ledgers/` — candidate-ledger JSONL files

## Recommended Process

1. If you bulk-drop files under `inputs/`, use `python3 src/corpus_tools/corpus_sync.py --write` to register missing rows first.
2. Run the pipeline on a firmware image.
3. Read `runs/<run>/results.json` and `dossiers/`.
4. Update `firmware_corpus.jsonl` with extraction and analysis status.
5. Review only strong candidates against `review_checklist.md`.
6. Record each investigated candidate in your own ledger file using the schema here.
7. Mark each reviewed candidate as one of:
   - `CONFIRMED`
   - `LIKELY`
   - `REJECTED`
   - `NEEDS_MORE_WORK`
8. Tag the candidate with one primary pattern from `pattern_taxonomy.md`.
9. Generate a combined progress report from corpus and ledger files when you want a paper-friendly summary.
10. Generate LLM review packets and gold-label stubs when you want to evaluate model judgment quality.
11. When API usage is off, compare the engine's labels against your own direct review and use the diff as the heuristic-improvement queue.

Useful commands:

```bash
python3 src/review/llm_review.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --batch-summary runs/regression/batch_regression_summary.json \
  --emit-corpus-packets research/review/llm/llm_review_packets.jsonl

python3 src/review/llm_review.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --batch-summary runs/regression/batch_regression_summary.json \
  --emit-corpus-packets-compact research/review/llm/llm_review_packets_compact.jsonl

python3 src/review/llm_review.py \
  --corpus research/corpus/firmware_corpus.jsonl \
  --batch-summary runs/regression/batch_regression_summary.json \
  --write-gold-stubs research/review/llm/llm_review_gold.jsonl

python3 src/review/llm_review_infer.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --provider heuristic \
  --output research/review/llm/llm_review_predictions.jsonl

python3 src/review/llm_review_infer.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --provider hybrid \
  --model gpt-5.2 \
  --output research/review/llm/llm_review_predictions_hybrid.jsonl

python3 src/review/llm_review_infer.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --provider openai \
  --model gpt-5.2 \
  --output research/review/llm/llm_review_predictions.jsonl

python3 src/review/llm_review_eval.py \
  --gold research/review/llm/llm_review_gold.jsonl \
  --predictions research/review/llm/llm_review_predictions.jsonl

python3 src/review/manual_review_compare.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --write-stubs research/review/manual/manual_review_labels.jsonl

python3 src/review/manual_review_compare.py \
  --packets research/review/llm/llm_review_packets.jsonl \
  --manual research/review/manual/manual_review_labels.jsonl \
  --json-out research/review/manual/manual_review_diff.json \
  --markdown-out research/review/manual/manual_review_diff.md
```

Manual review loop:

1. Run the pipeline or batch regression as usual.
2. Generate packets with `src/review/llm_review.py`.
3. Generate editable stubs with `src/review/manual_review_compare.py --write-stubs`.
4. Review one firmware yourself and correct `manual_labels`.
5. Re-run `src/review/manual_review_compare.py` with `--manual`.
6. Use `mismatch_kind_counts` and per-review diffs as the next heuristic-fix queue.

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
