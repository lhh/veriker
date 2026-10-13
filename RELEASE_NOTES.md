# Release notes

What changed for a user of the published package, release by release. The
reason-code vocabulary is in `audit_bundle/plugins/REASON_CODES.md`; the
verifier's normative contract is `the internal design notes`.

## 0.2.2 (experimental)

Exit codes are unchanged: `0` OK, `1` REJECT, `2` ERROR.

### Removed public names

None of these was raised, imported or documented as behaviour; they were
reachable by name in 0.2.1 and are gone.

- `Verdict.ok_` on `audit_bundle.verdict.Verdict`. It was an alias of
  `passed`, one underscore away from the `.ok` property. Use `.ok`.
- 22 `ManifestError` subclasses in `audit_bundle.bundle_manifest` that mirrored
  plugin reason codes "for exception-based handling". Nothing raised them; the
  checks run under their string codes.
- 6 `VerifierIdentity*` exception classes in
  `audit_bundle.extensions.c18_verifier_identity`. The tripwire plugin emits
  `REASON_*` strings, not these.

### Plugin contract: a primitive declares what it reads

- Every re-derivation primitive must declare `expects` (the binding params it
  reads; `frozenset()` if none) and may declare `expects_optional`. A
  primitive without `expects` is refused before it runs:
  `PRIMITIVE_UNDECLARED`, exit 2. A subclass that overrides `recompute` must
  restate `expects`; it does not inherit the base's.
- Dispatch refuses a `comparator.params` key that neither the comparator kind
  nor the primitive reads (`UNKNOWN_SPEC_PARAM`) and a declared key the binding
  omits (`MISSING_SPEC_PARAM`). Both exit 2. Before, an unread key was ignored
  and a missing one was filled from a code default.
- `fea_witness_certificate` moves to contract revision 2: `equilibrium_tol`,
  `epsilon`, `input_anchor` and `conditioning_bound` must be stated.
- New reason codes: `PRIMITIVE_UNDECLARED`, `PRIMITIVE_EXPECTS_MALFORMED`,
  `UNKNOWN_SPEC_PARAM`, `DECLARED_INPUT_MALFORMED`, `MISSING_SPEC_PARAM`,
  `UNKNOWN_SPEC_KEY`.
- `veriker --kit <kit.py>` now warns (`WARN kit_declarations`) for each
  registered primitive with no `expects`. It is a warning in this release;
  whether kit mode exits non-zero on it is not decided here.

### Spec files are closed

- Each type body and each comparator object in a spec is closed to the keys the
  parser reads. An unknown key is `UNKNOWN_SPEC_KEY`: exit 2 when the spec is
  the auditor's anchored one, exit 1 when it is an in-bundle copy. Before, a
  misspelt `pinned_imputs` silently dropped every pin.
- A spec-level key that belongs at a lower level (`comparator`, `kind`,
  `params`, `pinned_inputs`, `primitive_id`) is refused at the top level.
- `scalar_epsilon`'s `epsilon` must be an int or float, not a bool.

### The verdict carries its decision

- The human face prints a `decision` line above the summary: what decided,
  on whose root, and how many propositions rest on the proposer's root alone.
  The JSON face (`--verdict-out`) is unchanged.
- A crash inside a trust-root consumer callable is `NO_VERDICT`
  (`VERIFIER_INTERNAL_ERROR`, exit 2), never a finding against the artifact.
  Before, the raise escaped unless the consumer wrapped it by hand.

### Claimset: four 0.2.1 fixes and one reclassification

- Bytes the stdlib parser reads as JSON (a BOM, a UTF-16/32 line after the
  first, lone surrogates, odd-length UTF-16) were admitted as one opaque
  element. Fixed.
- An unbalanced quote on an earlier line could hide a later line's nesting and
  raise `RecursionError`. Fixed; the kind no longer depends on caller stack
  depth, CPython version (3.11 to 3.13) or `sys.get_int_max_str_digits()`.
- Lenient readers (JSONC, trailing commas, concatenated values, RFC 7464, the
  XSSI guards, a UTF-8 reading where the parser detects UTF-16/32) missed
  inputs they should have refused. Fixed.
- The receipt-hashed conventions statement said "no UTF BOM" while BOM-prefixed
  prose was admitted. The statement is corrected and
  `CLAIMSET_CONVENTIONS_VERSION` is `v3`: every claimset `universe_sha` changes,
  and a pinned anchor reports `CLAIMSET_UNIVERSE_ANCHOR_MISMATCH`.
- A number token that overflows `float` (`1e999999`) is refused by the strict
  parser as `non_finite`, so a claim file holding one is now
  `JSON_SHAPED_BUT_CORRUPT` rather than a parsed `inf`. The conventions version
  did not bump for this change: two `v3` verifiers, one built before it and one
  after, classify such bytes differently.

### Other changes

- `strict_json`: nesting the stdlib parser cannot recurse into is a
  `StrictJSONError` of kind `too_deep`, not an escaping `RecursionError`. On
  `bytes` or `str` input every error is a `ValueError`.
- `iso8601.parse_iso8601_utc`: an instant that leaves `datetime`'s range once
  in UTC raises `ValueError`, not `OverflowError`.
- Admission helpers: a NUL byte or lone surrogate in a path is a refusal, not a
  crash.
- A passing output's `recompute_detail` is printed by the CLI; before, only a
  mismatch carried it.
- Pilots whose own `verify.py` executes code shipped inside the bundle now say
  so at the top of their README. Their output is not evidence of
  re-derivation; the anchored command in the root README is.
- `--kit`'s result and the kit declaration check are on the verdict face under
  `cli_gates`.

## 0.2.1 (experimental)

See the 0.2.1 tag. The 0.2.0 release checked less than the tree it was cut
from; 0.2.1 closed that gap.
