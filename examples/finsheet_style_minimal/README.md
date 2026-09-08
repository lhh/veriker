# finsheet_style_minimal — spreadsheet answers, re-derived from the workbook bytes

**Domain:** private-equity portfolio-monitoring workbooks, the FinSheet-Bench shape
(Ravnik et al., arXiv 2603.07316, 2026-03-07). The paper reports the best LLM at
82.4% on spreadsheet question answering, 48.6% on its largest file, and closes:
"reliable financial spreadsheet extraction will likely require architectural
approaches that separate document understanding from deterministic computation."
This pilot puts the deterministic half on the verifier's side of the line.

**This is a FinSheet-STYLE set, never FinSheet-Bench.** The paper states no data
or code release. `_generate_set.py` rebuilds the shape from the paper's published
recipe: 24 workbooks (6 layouts x 4 sizes, the largest 152 companies / 8 funds),
16 question templates across the paper's four difficulty tiers, 384 questions.
Pre-registration, predictions and stop conditions: `PREREGISTRATION.md`,
committed before any code.

## Two arms, one claimed value

| output | primitive | the auditor holds | catches | cannot catch |
|---|---|---|---|---|
| `answer_semantic` | `sheet_query_recompute@1` | the workbook bytes AND the question as a closed-world `sheet-query-v1` document, BOTH sha-pinned in the anchored spec via `pinned_inputs` | any answer that is not the deterministic answer to the auditor's question over the auditor's workbook | (the ceiling) |
| `answer_consistency` | `sheet_derivation_replay@1` | the pinned workbook bytes only; the producer states its own op + operands | an answer that disagrees with its own working; an operand that occurs nowhere in the workbook | a wrong selection computed correctly |

The workbook is parsed by the verifier from bytes (stdlib zip + xml, DTD-refusing,
size-bounded). The bundle carries no table the producer extracted.

## Quick start

```bash
cd <repo root>   # the directory holding pyproject.toml

# honest bundle -> PASS
python examples/finsheet_style_minimal/_build_bundle.py --demo --out-dir /tmp/fs_clean
python examples/finsheet_style_minimal/verify.py --bundle-dir /tmp/fs_clean

# each arm has teeth, and one profile shows the documented gap:
python examples/finsheet_style_minimal/_build_bundle.py --demo --profile wrong_arithmetic     --out-dir /tmp/fs_a  # A FAIL, B FAIL
python examples/finsheet_style_minimal/_build_bundle.py --demo --profile wrong_selection      --out-dir /tmp/fs_b  # A FAIL, B RE_DERIVED  <- B's scope limit
python examples/finsheet_style_minimal/_build_bundle.py --demo --profile hallucinated_operand --out-dir /tmp/fs_c  # A FAIL, B FAIL (operand_not_in_sheet)
python examples/finsheet_style_minimal/_build_bundle.py --demo --profile wrong_question       --out-dir /tmp/fs_d  # PINNED_INPUT_MISMATCH
python examples/finsheet_style_minimal/verify.py --bundle-dir /tmp/fs_b
```

Expected on the demo question (L2_S1, "total NAV of Fund I", 588.72):
`clean` exit 0; the other four exit 1 with the per-arm lines above on stderr.

## Build the set

```bash
python examples/finsheet_style_minimal/_generate_set.py --out-dir /tmp/finsheet_set
# 24 workbooks, questions.json (384), set_manifest.json (sha256 per file)
```

Generation is seeded and deterministic. Gold answers come from the generator's
own Decimal arithmetic; the generator imports nothing from `audit_bundle`. The
faithfulness check (verifier recompute == generator gold on all 384) is in
`tests/test_finsheet_style_minimal.py` on a per-layout sample and was run on the
full set. Its first run found a real disagreement: openpyxl serialises every
number with 16 significant digits, so `74.46` landed in the file as
`74.45999999999999` and a median came out one cent off. The verifier read the
document as written and was right; the generator now canonicalises the
worksheet XML it emits. The bytes are the truth both the model and the verifier
see.

## Harness (model sweep)

`harness/` asks models the 384 questions from a text serialisation of the
workbook (no row/column indices, as in the paper), builds one bundle per
answer with the model's own derivation, verifies each under a per-question
anchored spec generated OUTSIDE the bundle, and reports catch and false-alarm
rates per arm, per tier, per size, with the arithmetic / selection /
hallucinated-operand split of wrong answers. See `harness/README.md`.

## File layout

| file | role |
|---|---|
| `PREREGISTRATION.md` | frozen predictions P1–P8, roster, tolerances, stop conditions |
| `_generate_set.py` | producer: 24 workbooks + 384 questions + gold; `build_one(file_id)` |
| `_build_bundle.py` | producer: one bundle per (workbook, question, claim, derivation); `--demo --profile` |
| `auditor_entry.py` | auditor: `make_spec` (pins the question), `build_verifier` (anchored, strict, work-set), `read_outcomes` |
| `verify.py` | anchored CLI entry, defaults to the committed demo spec |
| `spec_pinned/finsheet_demo.spec.json`, `spec_pinned/demo_query.json` | the auditor's committed demo question and its binding spec |
| `harness/` | model sweep, caching, grading, report |

## What the adversarial pass found (2026-09-02) and what changed

A fresh-context auditor attacked the first version with bundles, not prose.
Ranked findings and the fix each got, all regression-tested in
`tests/test_finsheet_style_minimal.py`:

| severity | finding | fix |
|---|---|---|
| CRITICAL | the spec pinned the question but not the workbook: add 1.00 to one NAV, re-cohere the manifest, claim the new total — exit 0 on both arms | `make_spec` pins `data/workbook.xlsx` on both types; workbook bytes made deterministic (fixed zip and docProps dates) so the committed demo spec can pin them |
| SEVERE | a refusal was a plain dict; claiming that dict equalled it under `exact`, and its key list under `set` (the count/list kinds) with an empty derivation | refusals carry a per-call nonce as a KEY and a value; the first fix (value only) was caught by its own regression test through the list kind |
| SEVERE | no row/column bound: one cell at row 20,000,000 in a 6 KB file cost 4.1 GB | rows 1..1,048,576, columns A..16,384, at most 4,000,000 cells per sheet, refused at reference parse |
| SEVERE | the DOCTYPE guard scanned 4 KB; whitespace or a comment before `<!DOCTYPE>` expanded an entity into a cell at exit 0 | the whole entry is scanned |
| SEVERE | five exception classes reached `RECOMPUTE_ERROR`: `sNaN` operand, `Infinity`/`1e999999` cells, a NaN under median, a lying zip CRC, `MemoryError` | non-finite or out-of-double-range values refused at read and absent as operands; arithmetic errors are refusals; `BadZipFile`, `zlib.error`, `MemoryError` map to unreadable |
| MODERATE | the harness rounded with float `round()` (half-even); 9 of 48 mean/median questions sit exactly on a `.xx5` boundary | `Decimal` HALF_UP, the contract's rounding |
| MODERATE | `{"answer": null}` was dropped as unparseable, so an abstention inflated accuracy | its own `abstained` status; accuracy reported with and without |
| MODERATE | the wrong-answer split filed a malformed derivation and a checker error as "arithmetic" | a `malformed_derivation` bucket, `B_kind` keyed on reason code and refusal kind, an op-matches-question column |
| MODERATE | divider and exclusion regexes saw the raw cell: `Subtotal ` and `SUBTOTAL` were summed as companies | regexes match whitespace-collapsed text, case-insensitively |

Still true and now stated in the primitive's scope limits: Arm B's operand
existence is exact Decimal equality, so a real-world workbook whose XML carries
16-digit float noise (`74.45999999999999`) makes honest 2-dp operands "absent";
a substring number inside a Notes cell does NOT satisfy existence (measured),
but a number that occurs anywhere as a whole cell does. `RECOMPUTE_ERROR` is
exit 1 (REJECT), not exit 2, so a checker fault on the producer's bytes reads
as a rejection of the bundle.

## Re-derivability boundary (read before quoting)

- A PASS on `answer_semantic` means the claimed value is the deterministic
  answer to the auditor's pinned question over the auditor's PINNED workbook
  bytes, within the auditor's tolerance (0.0051 absolute on 2-dp values; exact
  for counts and normalized strings; multiset-equal for lists). It says nothing
  about whether the numbers in that workbook are true of the world; it does
  say the producer did not substitute the workbook.
- A PASS on `answer_consistency` means the producer's stated operands all occur
  in the workbook and replay to the claimed value. It does NOT mean the right
  cells were chosen; `wrong_selection` passes this arm by design.
- Operand existence is workbook-wide, not column-scoped. A number that occurs
  anywhere (a Notes cell, another fund's row) satisfies it.
- When BOTH arms mismatch, the verdict face also carries a
  `NO_RE_DERIVATION_PERFORMED` disclosure from the re-derivation surface guard.
  The exit code is 1 and the per-output rows name the mismatches; the
  disclosure is a pre-existing kernel behaviour (the corner_load drift profile
  shows the same) keyed on outputs that compared EQUAL rather than outputs that
  were recomputed. Noted, not changed here.
- External language: the verifier **re-derives**; a rejected answer is
  **not re-derived** with a reason code. Never "verified", "proved",
  "certified". The set is "FinSheet-style".
