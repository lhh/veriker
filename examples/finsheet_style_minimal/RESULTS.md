# finsheet_style_minimal — RESULTS (sweep of 2026-09-02)

Pre-registration: `PREREGISTRATION.md`, committed alone at `58fb3fb38` before
any code or model call. Report and every row: `harness/runs/2026-09-02/`
(`REPORT.md`, `results.jsonl`, 1,152 rows). Set: `_generate_set.py`, seed
20260902, deterministic bytes. Verifier: the hardened primitives at `2da1eb467`
(the adversarial pass and its fixes are in the README); the model completions
were made once and replayed from cache against the hardened verifier, so no
number below depends on the pre-hardening code.

## The one-line result

Frontier models answer this FinSheet-STYLE set at 97 to 99.5 percent. Every
one of their 21 wrong answers is a selection error: the right arithmetic over
the wrong rows. The auditor-held question (Arm A) caught 21 of 21 with zero
false alarms. The producer's own stated working (Arm B) caught 0 of 21,
because every wrong answer was internally consistent. The error class that
survives a frontier model is exactly the class a self-consistency check cannot
see and an independently held specification of the question can.

## Headline table

| model | concluded | acc strict | acc lenient | wrong | A catch | A false alarm | B catch | B false alarm |
|---|---|---|---|---|---|---|---|---|
| gpt-5.2 (reasoning medium) | 384/384 | 97.7% (375/384) | 98.2% | 9 | 100% (9/9) | 0.0% (0/375) | 0% (0/9) | 0.5% (2/375) |
| gemini-3.1-pro-preview | 382/384 | 99.5% (380/382) | 99.5% | 2 | 100% (2/2) | 0.0% (0/380) | 0% (0/2) | 0.0% (0/380) |
| claude-opus-4.6 via OpenRouter, thinking | 384/384 | 97.4% (374/384) | 97.9% | 10 | 100% (10/10) | 0.0% (0/374) | 0% (0/10) | 1.1% (4/374) |

Strict = the verifier's tolerance (0.0051 absolute on 2-dp values, exact
counts and strings, multiset-equal lists). Lenient = the paper's tier-1 rule
(2.5 percent relative). No abstentions, no inconclusive verdicts, no API
errors. Gemini's two non-concluded cells are JSON truncated at the harness's
8,000-token output cap with the correct answer already emitted (Gemini counts
thinking tokens against that cap); they are a harness limit, not model errors,
and they are excluded from every denominator above.

## What the 21 wrong answers are

| question shape | count | what happened |
|---|---|---|
| Q05 / Q06 list the companies in a fund or sector | 7 | one or two companies omitted (one case: one omitted, one wrong one added) |
| Q08 count companies in a geography | 7 | off by one, always low |
| Q10 / Q11 / Q15 sum over a fund, sector, or all funds | 6 | rows skipped, 20 to 120 operands |
| Q14 mean MOIC in a fund | 1 | one row skipped |

18 of 21 are on S4 files (152 companies, 8 funds) and 3 on S3. None on S1 or
S2. None on the Low or Very-high tiers. In every case the model's stated
operands were real cells and reproduce its own answer: `op matches question`
100 percent, hallucinated operands 0, malformed derivations 0.

## Predictions, scored

| id | predicted | measured | verdict |
|---|---|---|---|
| P1 accuracy 70 to 90 percent | | 97.4 to 99.5 percent | FALSE, all three models above the band |
| P1 stop: any model below 50 percent on S1 | | 100 percent on S1 for all three | did not fire |
| P2 at least a 20-point drop S1 to S4 | | drops of 8.3 (Claude), 6.2 (GPT), 2.1 (Gemini) | FALSE |
| P3 Arm A catches at least 95 percent, false alarm at most 10 percent strict, under 2 percent lenient | | 100 percent; 0.0 percent strict; 0.5, 0.0, 0.5 percent lenient | TRUE |
| P4 Arm B catches 30 to 70 percent overall, at least 60 percent on High | | 0 percent overall, 0 percent on High | FALSE, decisively |
| P5 selection errors are the majority of what B passes on Low and Medium | | 100 percent of all wrong answers are selection errors, every tier | TRUE, stronger than predicted |
| P6 hallucinated operands in at least 5 percent of S4 wrong answers | | 0 of 16 | FALSE |
| P7 at least one model unparseable on at least 2 percent of S4 | | Gemini 2 of 96 (2.1 percent), both output truncation | TRUE at the boundary, cause is the harness cap |
| P8 deterministic grading resolves 100 percent of parseable answers | | 1,150 of 1,150 | TRUE |

Kill conditions: verifier ERROR rate 0 of 1,152; largest prompt 9,648 tokens
(Gemini) against a 120,000 stop; nothing fired.

## Why the paper's numbers and ours differ, stated plainly

The paper reports 82.4 percent for its best model and 48.6 percent on its
largest file. We measured 97 to 99.5 percent and 92 to 98 percent on ours. This
set is easier, and the reasons are known:

- Our largest prompt is under 10,000 tokens; the paper's largest file is about
  44,000 GPT tokens. Same company and fund counts, but our tab-separated
  serialisation is compact and our column set is 11 to 12 wide.
- The prompt states the answer format (number, count, string, list) so the
  answer can be parsed strictly. The paper's models got only the question.
- Our 16 templates are regular; the paper's may include harder phrasing.
- Nine of the set's mean/median answers sit on an exact `.xx5` boundary, which
  we grade HALF_UP like the contract; the paper's grading tolerance would have
  hidden that either way.
- Claude ran through OpenRouter (the direct key had no credit), under its own
  label; the model id is the paper's, the transport is not.

So the accuracy numbers are not a replication of the paper and are not
presented as one. What transfers is the shape of the residual: as prompts get
harder the paper's models fail more, and the failures we can see at 97 percent
are all of one kind.

## What Arm B's false alarms are (6 of 1,129 correct answers)

Two are a right answer with wrong working: GPT's median operands replay to
72.28 while its answer, 70.41, is correct; GPT's sector sum lists 72 operands
that replay to 5,042.72 against a correct 608.72. One is Claude summing 152
rows and reporting 8 per-fund subtotals it computed itself, which are not
cells, so the existence check names them. Two are Claude list answers whose
operand lists differ from the answer list. One is Claude's count operands
listing 40 names for a correct answer of 39. None is a verifier defect. Each is
the model's stated working failing to be its actual working, which is
information a reviewer would want.

## What models do with subtotals

On the layouts that carry subtotal rows or a summary sheet, all three models
answered 23 to 28 of the 96 sum questions by reading the subtotal cell and
reporting the derivation as a `lookup`. Arm B accepts that, because the cell
exists. This is legitimate document reading, and on a real workbook a stale
subtotal would pass Arm B for exactly the same reason; only Arm A, which sums
the rows the auditor's question names, would disagree with it.

## What this result supports, and what it does not

Supports: on spreadsheet questions of this shape a frontier model is right 97
to 99 percent of the time; the residual errors are skipped rows, not bad
arithmetic; and the only check that caught any of them was one that re-derives
the answer from the workbook under a question the reviewer holds. A check that
only asks the model to show its own working caught none of the 21, because
every wrong answer's working was internally consistent with it.

Does not support: that this reproduces FinSheet-Bench; that Arm B "catches
arithmetic errors" (it caught nothing here, because there were none to catch);
or that these accuracies transfer to a 44,000-token workbook. The next
measurement that would move the claim is the same sweep on a set serialised
the paper's way, at the paper's prompt lengths.
