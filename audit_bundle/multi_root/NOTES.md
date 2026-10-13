# audit_bundle/multi_root — NOTES

One lesson per entry; corrections and confirmed approaches alike, with why. Scoping docs
live at the product root (`the internal design notes`, `the internal design notes`); this file
is what the next change to this package should read first.

## 2026-09-16 — the consumer's refusal reason (`Refused`)

1. **Decide what a refusal IS before touching a consumer.** Three shapes were priced for
   "a `signature_valid` that says why": `bool | str` (a non-empty str is truthy — the join's
   own wrapper did `bool(...)` and would have ADMITTED every reasoned refusal: fail-open),
   an exception (inverts the enumerated-wrapper doctrine: a raise is the verifier-defect
   channel), and a falsy value (`Refused(why)`, `__bool__` False: a coercing reader loses
   the reason and never admits). The consumers followed from the shape in one line each.
2. **A reason is consumer text that can carry producer bytes.** The first reason measured
   on the harness carried a producer's key name (`duplicate object key 'use_id'`). The
   roster bounds what it is handed (printable-only, `:`→`;`, cap 160, empty→generic) and
   reads `why` only from an EXACT `Refused` — a subclass is the consumer's code and is never
   read, so no hostile `__getattribute__`/`__str__`/`__repr__` can raise inside `admit`.
3. **Cap under the face's cap.** The face truncates details at 200 with a digest suffix; a
   roster cap of 160 keeps `provenance refused: ` + why under it, so a long reason is cut
   once, legibly, never twice.
4. **Grade the flip list BEFORE rewriting a test.** Running the suites against the new
   code before touching any assertion showed exactly the eight tests that pinned the
   generic sentence on a blank record went red and nothing else (P-S2) — the only
   measurement that distinguishes "the change did what was scoped" from "the tests were
   edited until green".
5. **Two scaffolding slips, caught by the controls' positive arms:** a hostile subclass
   built with a `@property` had no setter, so the frozen dataclass could not even be
   constructed (the control asserts the referent raises BEFORE handing it to `admit`); and
   `rows[1]` was the purchase order, not the goods receipt (index rows by `record_id`).
6. **What was left alone, and why it is written down:** `validate_content` / `is_stale`
   reasons are the same class of text and are NOT bounded here — committed rover verdicts
   and the probe's `results.json` pin them byte-for-byte. Filed in `the internal design notes`'s
   addendum as the sibling surface rather than fixed under a "no reason moves" invariant.
7. **No git write of any kind while a mutant runner holds the tree.** The runners restore
   files with `git checkout --`; a foreground `git commit` (of a doc, in another product)
   took the index lock at the moment the toy runner tried to restore `engagement.py` — exit
   128, runner dead, mutant M7 LIVE in the working tree. The tripwire says `git add -A`;
   the class is any index write during the window. Check `git status` before the next
   measurement, restore, re-run the runner in the foreground.
8. **"A subclass is never read" is not "a subclass is falsy."** The formatter's exact-type
   check ran AFTER `admit` had already tested truthiness; a `Refused` subclass overriding
   `__bool__` to `True` was ADMITTED (Stage 5 red team, SEVERE, reproduced). Consumer-side
   only — a producer cannot construct a Python object — but the docstring's claim was
   false and the fail-closed argument for choosing this shape rested on it. Fix at the
   class: `__init_subclass__` raises, so "exactly a Refused" is the only Refused there is.
   Rule: when a safety property is "X is falsy", make X's `__bool__` the ONLY one that can
   run; do not argue about which reader checks the type first.
9. **Normalise before you filter.** `:` → `;` caught the ASCII colon and nothing else; a
   fullwidth `：` (U+FF1A) passed `isprintable` and folds to `:` under NFKC in any reader
   that normalises before it splits. NFKC first, then the character rules. The ratio colon
   (U+2236) and combining marks do not fold and are declared cosmetic.
10. **Grade every pre-named example, not only the named predictions.** The C3 text said
    `Refused("\x00")` → the generic sentence; the code gives `provenance refused: ?` (a
    scrubbed byte leaves a mark). Two lenses found it; the Results table had graded P-S1–P-S8
    and skipped the control's own worked examples. Kept as behaviour, graded FALSIFIED.
