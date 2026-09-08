# finsheet_style_minimal — PRE-REGISTRATION (frozen before any model call)

Written 2026-09-02, committed alone, before the primitive, the generator, the
harness or any API call exists. Predictions below are frozen at this commit;
the results document cites this file's commit hash.

## What is being measured

FinSheet-Bench (Ravnik et al., arXiv 2603.07316, 2026-03-07) reports that the
best LLM answers spreadsheet questions over synthetic private-equity portfolio
workbooks at 82.4% accuracy, falling to 48.6% on the largest file, and closes
with "reliable financial spreadsheet extraction will likely require
architectural approaches that separate document understanding from
deterministic computation." The paper states no data or code release. This
pilot builds a **FinSheet-STYLE** set from the paper's published recipe. It is
a reproduction of the shape, never FinSheet-Bench itself, and every external
sentence about it says so.

The question this pilot answers is NOT "how accurate is the model" — the paper
answered that. It is: **when the model is wrong, does a verifier-side
re-derivation say so, without seeing the gold answer?** Two arms, two different
questions:

| Arm | Primitive | What the auditor holds | What it catches | What it cannot catch |
|---|---|---|---|---|
| A, semantic recompute | `sheet_query_recompute` | the workbook bytes + the question as a closed-world query (`sheet-query-v1`), SHA-pinned in the anchored spec via `pinned_inputs` | any answer that is not the deterministic answer to the auditor's question | nothing in scope; this is the ceiling |
| B, derivation replay | `sheet_derivation_replay` | the workbook bytes only; the producer states its own derivation (op + operands) | an answer inconsistent with its own stated derivation; an operand that appears nowhere in the workbook | a wrong selection computed correctly (wrong fund's rows summed right) |

Arm A is the ceiling and is expected to catch almost everything; its content
is the faithfulness of two independent implementations (verifier primitive vs
generator gold) and the strictness delta between the verifier's tolerance and
the benchmark's grading tolerance. Arm B is the honest number: it needs nothing
from the auditor except the workbook, and its miss rate is the measure of how
much a spec-free checker buys. The **split** between arithmetic errors (B
catches) and selection errors (only A catches) is the finding nobody has
published.

## Set construction (generator, producer side, openpyxl)

24 workbooks = 6 layouts × 4 sizes, seeded, deterministic.

Sizes: S1 8 companies / 1 fund; S2 24 / 2; S3 72 / 4; S4 152 / 8 (the paper's
largest file is 152 companies, 8 funds).

Layouts: L1 flat single sheet with an explicit Fund column; L2 single sheet
with fund divider rows and per-fund subtotal rows; L3 one sheet per fund; L4
L2 plus multi-line headers and a units row; L5 a Summary sheet of per-fund
totals plus a Holdings sheet with dividers (the summary is a trap for
aggregation questions); L6 L4 plus a free-text Notes column and blank spacer
rows.

Columns: Company, Sector, Geography, Investment Date, Invested Capital ($m),
Realized Value ($m), Unrealized Value / NAV ($m), Total Value ($m), MOIC (x),
Ownership (%), Status. Money at 2 dp, MOIC at 2 dp, Total = Realized +
Unrealized, MOIC = Total / Invested rounded half-up to 2 dp. Values are stored
as values, not formulas.

16 question templates in the paper's four difficulty tiers, instantiated once
per workbook (384 questions):

- Low (lookup): Q01 NAV of company C; Q02 sector of C; Q03 invested capital of
  C; Q04 MOIC of C.
- Medium (list / filter / count): Q05 companies in fund F; Q06 companies in
  sector S; Q07 count of Exited companies in fund F; Q08 count of companies in
  geography G; Q09 companies with MOIC above threshold t.
- High (aggregate / sort): Q10 total NAV of fund F; Q11 sum of invested capital
  in sector S; Q12 company with highest MOIC in fund F; Q13 top-3 companies by
  NAV; Q14 mean MOIC in fund F (2 dp); Q15 total realized value, all funds.
- Very high: Q16 median NAV in fund F (2 dp).

Gold answers are computed by the generator's own code, which imports nothing
from `audit_bundle` (sibling ratchet). Verifier and generator agreeing on every
honest bundle is the faithfulness test; a deliberate one-cell mutation in the
generator's gold must be flagged by Arm A (mutant control, both directions).

## Model roster and cost guard

Replication trio, matching the paper's named models where the API still
serves them: `gemini-3.1-pro-preview`, `gpt-5.2` (reasoning effort medium),
`claude-opus-4-6` (extended thinking, 8k budget). Temperature 0 where the API
allows it. One sample per question. Cache key = sha256 over provider, model,
system prompt, user prompt, temperature, max_tokens, thinking/reasoning
config, sample index. `usage.prompt_tokens` is recorded per call and measured
on the S4 files BEFORE the sweep; if the largest prompt exceeds 120k tokens the
serialization is wrong and the run stops.

Serialization follows the paper: text, no row or column indices, one line per
row, cells tab-separated, blank cells empty, sheets labelled by name.

Output contract asked of the model: strict JSON `{"answer": ..., "derivation":
{"op": ..., "operands": [...], "column": ...}}`. Numbers as plain numbers at
the sheet's precision, lists as arrays of exact company names. Unparseable
output is a could-not-conclude for that cell, counted separately, never a
wrong answer and never a catch.

Verifier tolerance (anchored spec, per type): scalars `scalar_epsilon` with
epsilon 0.0051 absolute (half a unit in the last place of 2-dp values, plus
float slack); counts `exact`; lists `set`. Grading tolerance for the model's
answer against gold (harness side, reporting only): the paper's tier-1 rule,
2.5% relative for numbers, set equality for lists. Both are reported.

## Predictions (frozen)

- P1 Each model scores between 70% and 90% overall on the reproduction. If any
  model scores below 50% on S1 files, the harness is suspect and the run stops
  before any other number is read.
- P2 Every model drops at least 20 points from S1 to S4.
- P3 Arm A flags at least 95% of answers the harness grades wrong. Its
  false-alarm rate on answers graded correct is at most 10% at the strict
  epsilon; the false alarms are rounding and format, and the rate at 2.5%
  relative is under 2%.
- P4 Arm B flags between 30% and 70% of wrong answers overall; at least 60% on
  High and Very-high questions; at most 25% on Low questions. Its false-alarm
  rate on correct answers is at most 10%.
- P5 Among wrong answers that Arm B passes, selection errors (a stated
  derivation whose operands all exist in the workbook and reproduce the
  answer) are the majority on Low and Medium questions.
- P6 Operand hallucination (an operand that appears nowhere in the workbook)
  occurs in at least 5% of wrong answers on S4 files.
- P7 At least one model returns unparseable output on at least 2% of S4
  questions.
- P8 The benchmark's own tier-3 grading (LLM adjudication, ~48% of answers in
  the paper) is unnecessary here: deterministic grading resolves 100% of
  parseable answers. This is a claim about our set, not the paper's.

## Kill and stop conditions

- Verifier ERROR (exit 2, could-not-conclude) on more than 5% of bundles: stop,
  fix the harness, do not interpret any catch rate.
- Any model below 50% on S1: stop, inspect serialization and prompt.
- Largest prompt over 120k tokens: stop.
- A kill condition firing on ONE cell or ONE file is not a measurement; count
  distinct files and questions before acting.

## What is reported, whatever the outcome

Per model and overall: accuracy by tier and by size; Arm A and Arm B catch
rate and false-alarm rate at both tolerances; the arithmetic / selection /
hallucinated-operand split of wrong answers; could-not-conclude counts; token
usage and cost. Every number is reported with its denominator. Nothing is
dropped for being unflattering; a degenerate run is handled the same way in
every table.

## Language discipline for anything external

The verifier **re-derives**; a rejected answer is **not re-derived**, with a
reason code. Never "verified", "proved" or "certified". The set is
"FinSheet-style", never "FinSheet-Bench".
