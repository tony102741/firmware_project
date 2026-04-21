# Review Outcome Matrix (2026-04-20)

This note summarizes what the current ledger states mean in practice and gives
representative examples for each review outcome class.

---

## Outcome Matrix

| Verdict | Meaning in this project | Representative example | Why it landed there |
|---|---|---|---|
| `CONFIRMED` | manual review established a coherent input-to-sink chain with defensible security impact | `ipTIME AX3000M hidden d.cgi cmd -> popen` | Ghidra and static review confirmed the authenticated hidden diagnostic command-execution path |
| `CONFIRMED` | repeated design anti-pattern confirmed across handlers | `TOTOLINK A3002RU` WPS / repeater / upload cases | attacker-controlled values reach shell-backed command templates in multiple Boa handlers |
| `CONFIRMED` | code-level sink evidence is clean, but novelty is a separate question | `TOTOLINK X6000R` mtkwifi cases | command-substitution / `os.execute()` chains are real even though overlap risk remains |
| `NEEDS_MORE_WORK` | the surfaced clue is plausible, but attacker control into the final sink is not fully proven | `Cudy WR3000E system.lua -> /bin/sh` | visible shell execution exists, but currently appears mostly fixed-template rather than attacker-fragment driven |
| `REJECTED` | an early heuristic matched a real sink family, but the specific candidate framing was wrong | `AX3000M /config -> popen` heuristic | later reversing showed the real issue was a hidden diagnostic interface, not a generic `/config` path |

---

## Current Counts

From the compact review ledger:

- `CONFIRMED`: `6`
- `NEEDS_MORE_WORK`: `1`
- `REJECTED`: `1`

Why this split matters:

- it shows the workflow is not just “surfaced == vulnerability”
- the manual review stage actively separates:
  - strong findings
  - unresolved but interesting leads
  - heuristics that should not become claims

---

## How To Interpret Each Class

### `CONFIRMED`

Use when:

- the input source is identified
- the processing chain is coherent
- the privileged sink is real
- the security interpretation is defensible

What it supports later:

- deep-dive case study
- recurrence claim
- overlap-aware discussion

### `NEEDS_MORE_WORK`

Use when:

- the surfaced path is plausible
- shell execution or privileged behavior is visible
- but attacker-controlled data reaching the decisive sink is not yet proven

What it supports later:

- supporting example
- future work
- reviewer-effort measurement

### `REJECTED`

Use when:

- the heuristic was useful for triage
- but the specific vulnerability framing should not be counted

Why this is important:

- prevents overclaiming
- preserves provenance
- lets the project measure false-positive or misframed-lead behavior honestly

---

## Paper Value

This matrix is useful later because it lets you explain that the toolchain is
not evaluated only by “number of findings,” but by how well it supports
structured analyst decisions:

- confirmation
- downgrade
- rejection

That is a stronger story than a raw candidate count.

---

## Bottom Line

The current ledger already demonstrates a full review lifecycle:

- **confirmed high-value cases**
- **weaker leads kept under review**
- **heuristics explicitly rejected after manual validation**

This makes the workflow look like a serious analysis pipeline rather than a
one-pass scanner.
