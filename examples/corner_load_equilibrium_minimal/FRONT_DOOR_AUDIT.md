# Front-door conversion — fresh-context adversarial pass (2026-09-06)

The change under audit: this pilot's `verify.py` became the shipped CLI with the
auditor's three inputs prefilled (spec, kit, a committed work-set file), printing
the command it runs; dispatch began disclosing each passing primitive's detail
(`recompute_detail` rows); the CLI began printing every failure row rather than
only built-in-step and plugin rows; both entry-point ratchets learned the new form.

Three auditors with disjoint lenses, no inherited context, read-only against the
tree, each returning executable witnesses. Every severe hit below was reproduced
by the author before it was fixed, and each fix is held by a test that re-runs the
finding's own witness.

## Fixed — real defects

| # | lens | finding | disposition | regression test |
|---|---|---|---|---|
| 1 | red team | **A producer-chosen `output_id` forged the terminal face.** Dispatch built the check name `spec_pinned_dispatch:<id>` from the raw id before validating it; the new FAIL rows printed that name verbatim. An id carrying newlines printed a fake `PASS  file_integrity` row and a fake `PASS  (12 check(s) passed)` line above the real `FAIL` summary. Exit code and final line were right; a log tail or a `grep -c PASS` was not. | Two layers, both the class not the instance: the check name is built from the validated id or its bounded `repr`; and every row the CLI prints — names, details, the acceptance / type-selection / recompute-detail bodies, the manifest-admission and manifest-validation and receipt lines — passes through one terminal-safe renderer that escapes control characters. The JSON face needs neither; JSON escapes. | `tests/test_cli_prints_every_failure.py::test_a_producer_string_cannot_forge_a_row` (the witness: the injection lands on one escaped line, no forged summary, the real summary last) |
| 2 | red team | **The ratchet classifiers matched any list literal in the module.** A dead flags table carrying `"--spec-anchor"` and `"--require-rederivation"`, beside a real `command()` whose argv carried neither, classified ANCHORED and STRICT. A leftover constant would have kept a pilot off the frozen list for good. | The classifier is now dataflow-bound: only an argv literal that reaches a subprocess call counts — the first argument of `run`/`call`/`check_call`/`check_output`/`Popen`/`exec*`, resolved through a name assignment or a module-local function's return, three hops at most. One resolver, shared by both ratchets. | `tests/test_entry_point_ratchet.py::test_the_prefilled_cli_arm_is_load_bearing_and_fails_closed` (six shapes: direct, via name, via local function — this pilot's shape — flag removed, docstring only, the dead-table witness, an argv never run) and the strictness sibling, plus a corner_load strictness pin the process lens noted was missing |
| 3 | process | **My parity control was self-referential on one arm.** The test compared the printed first line with `display(command(...))` — both computed by the module under test — so a `display()` that dropped a flag agreed with itself. The control tripped only on the drift arm, by exit code. | The printed argv and the executed argv are compared token by token after resolving the display's package-relative paths. The mutation now goes red on both arms. | `tests/test_corner_load_equilibrium_minimal.py::test_the_printed_command_is_the_command_run_and_agrees_with_the_library` |
| 4 | process | The "44 mechanical / 25 nothing-to-anchor / 4 other" split of the 73 frozen pilots was quoted in the review note but never measured against the ratchet's own list; it came from a text grep over a smaller denominator. | Re-measured by the ratchet's classifier: 73 = 44 with a committed spec + 29 without (5 of the 29 named-firm). Corrected where it was stated. | none — a documentation correction; the ratchet's `FROZEN_UNANCHORED` remains the only authority |

## Accepted declared limits — disclosed on the artifact

- Pointing this front door at a non-bundle directory (the pilot root, its parent)
  is the CLI's `MANIFEST_MISSING` refusal at exit 1, one step before the auditor-
  input containment guard that used to answer exit 2. With the anchor and kit
  paths prefilled as constants outside any bundle, that guard is unreachable from
  here; it is exercised where it lives, in the CLI's own tests.
- Through the CLI the work-set's face says `SELF_AUTHORED` — the CLI read a file
  and cannot verify a claim of derivation. The miner's library path derives the
  same set from the anchored spec and says `EXTERNAL_STRUCTURE`. A parity test holds
  the file equal to the derived set; the two labels stay what each path can honestly
  claim.
- The fifth FAIL row on the drift bundle reads `re_derivation_surface
  NO_RE_DERIVATION_PERFORMED` while four outputs mismatched. That is a pre-existing
  open reading of the surface guard, previously hidden because the row never
  printed. It is now visible and unchanged.
- The classifier's dataflow resolution is bounded (three hops, module-local
  functions, name assignments). An argv assembled by a helper imported from another
  module, or built by concatenation, does not classify — such a pilot is refused as
  unanchored, never admitted, which is the failure direction the ratchet wants.
- Terminal-safe rendering escapes control characters only. A producer string that
  merely LOOKS like a row (no control characters) still prints inside its own row's
  detail column; the row prefix and the final summary line are the verifier's.

## Not reproduced — confirmed blocked

- Hiding a dispatch failure by colliding its check name with a built-in step or a
  plugin key: dispatch check names are fixed literals or carry the
  `spec_pinned_dispatch:` prefix, which can never equal `file_integrity`,
  `spec_sha_pinning`, `cross_refs`, or `typed_check_plugins:*`.
- Minting a `recompute_detail` row for an output that did not pass: the row is
  written only after the comparator agreed; a comparator that raises, a mismatch,
  or an incomplete never reaches it. Control in
  `tests/test_recompute_detail_disclosure.py`.
- Forging through the recompute-detail text itself: every detail this pilot's
  primitives emit is built from auditor-computed counts and rationals, and the
  output id in the row is repr'd.

## Mutation controls run by the author after the pass

| mutation | tests that went red | restored |
|---|---|---|
| delete the `recompute_details_out` assignment in dispatch | 3 of 4 in the detail-disclosure test | yes |
| delete the "every other failure" loop in the CLI printer | 2 of 3 in the every-failure test | yes |
| delete the argv arm in the entry-point classifier | the pin and the mutant control | yes |
| delete the argv arm in the strictness classifier | the mutant control and the new corner_load pin | yes |
| `display()` drops a flag the executed argv keeps | parity test, both arms (clean arm only after fix 3) | yes |
| one pin retyped in the committed work-set file | the file-equals-derived test and the clean-bundle PASS test | yes |

## Counts, with their denominators

- This pilot's battery alone: 39 passed, 0 failed.
- The substrate batch (`test_work_set`, `test_anchored_type_coverage`,
  `test_cli_prints_every_failure`, `test_recompute_detail_disclosure`,
  `test_dispatch_output_id_safety`, `test_dispatch_comparator_fail_closed`,
  `test_dispatch_claimed_value_admission`, `test_cli_spec_anchor`,
  `test_cli_work_set`, `test_verdict_exit_code`, both entry-point ratchets):
  128 passed, 0 failed after the fixes above.
- Full non-pilot suite before the red-team fixes: 4597 passed, 0 failed.
- Export self-check before the red-team fixes: clean on every gate, run gate
  4359 passed, 0 failed.

## Residual

The three lenses and the author are the same model family. Fresh context removes
inherited reasoning; it does not make the auditors independent of the author's
blind spots as a class. Two of the four fixed findings were in code written the
same day by the author who had, that morning, written the rule each one breaks.
