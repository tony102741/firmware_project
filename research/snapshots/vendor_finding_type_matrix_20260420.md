# Vendor Finding Type Matrix (2026-04-20)

This note summarizes what kind of security value each vendor currently
contributes to the corpus.

---

## Matrix

| Vendor | Corpus samples | Current strongest value | Representative case | Interpretation |
|---|---:|---|---|---|
| `ipTIME` | `6` | likely-new deep-dive case | `AX3000M` hidden diagnostic CGI | best current case for authenticated hidden diagnostic command execution plus version-diff analysis |
| `TOTOLINK` | `6` | recurrence and overlap-aware confirmed command-injection cases | `A3002RU`, `X6000R` | strongest family for repeated command-construction issues, but novelty must be filtered carefully |
| `Cudy` | `4` | supporting family / weaker shell-heavy management patterns | `WR3000E`, `WR1300 V4` | useful supporting evidence, but currently weaker than `AX3000M` for fresh command-execution claims |
| `TP-Link` | `5` | benchmark / extraction coverage | `Archer AX23`, `XE75`, blocked `C80` | currently contributes more to corpus breadth and extraction evaluation than to confirmed security findings |

---

## Vendor Summaries

### `ipTIME`

Current best contribution:

- strongest likely-new case in the corpus

Why:

- `AX3000M` provides a clean hidden diagnostic interface case
- versioned samples make it possible to show persistence and later removal

Best use later:

- main deep-dive case study
- strongest example of “tool triage + manual reversing” payoff

### `TOTOLINK`

Current best contribution:

- strongest set of confirmed command-injection-style cases

Why:

- `A3002RU` shows recurrence across multiple handlers
- `X6000R` shows the tool also surfaces real issues that later require novelty
  filtering

Best use later:

- recurrence case
- overlap-filtering case

### `Cudy`

Current best contribution:

- supporting family for repeated shell-heavy admin logic

Why:

- `WR3000E` and `WR1300 V4` contain repeated shell execution and helper-command
  patterns
- but the current strongest evidence is still weaker than the primary cases

Best use later:

- supporting / secondary vendor family
- useful for discussing false starts or downgraded exploitability

### `TP-Link`

Current best contribution:

- extraction and corpus-diversity benchmark value

Why:

- current completed TP-Link cases help demonstrate that the pipeline handles
  multiple ecosystems
- blocked `Archer C80` cases are useful for discussing limitations

Best use later:

- extraction-coverage discussion
- benchmark breadth

---

## Why This Matrix Helps

This matrix keeps the paper from making every vendor do the same job.

Instead:

- `ipTIME` carries the main likely-new case
- `TOTOLINK` carries recurrence and overlap lessons
- `Cudy` carries supporting shell-pattern evidence
- `TP-Link` carries benchmark breadth and failure-analysis value

That division makes the evaluation section more coherent.

---

## Bottom Line

The current corpus is strongest when described not as “four vendors with equal
results,” but as a benchmark where different vendors contribute different
evaluation roles:

- novelty candidate
- recurrence
- overlap filtering
- supporting family
- extraction coverage
