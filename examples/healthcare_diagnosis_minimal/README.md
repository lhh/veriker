# healthcare_diagnosis_minimal — Clinical Diagnostic-Suggestion Audit Bundle

Minimal domain pilot: a rule-based ICD-10 diagnostic-suggestion engine bundled
for V-Kernel audit verification (the audit-bundle contract §C5, §C6, §C9).

## The clinical traceability story

Clinical decision-support systems that surface diagnostic candidates must be
**computationally reproducible** end-to-end: the regulator, the payer, and the
clinician all need to confirm that the suggested diagnosis was derived
deterministically from the exact symptom set the model saw, using only
committed artifacts — no proprietary runtime, no black-box re-execution.

The V-Kernel audit bundle is exactly that receipt:

> A clinical-decision-support model surfaces a ranked list of ICD-10 candidate
> codes for a patient. The bundle contains the structured symptom set, the
> decision-tree rule definitions, and the bundled candidate list. A verifier
> re-traverses the same rules over the same symptoms and asserts the predicted
> ICD-10 codes, confidences, evidence anchors, and rule paths match byte-for-byte.

This pilot demonstrates the substrate claim on a synthetic but structurally
realistic rule-based engine. Production integrators replace the rule traversal
with a determinism-mode forward pass over a real clinical knowledge graph or
ontology lookup; the bundle shape and verification protocol are identical.

## Re-derivation primitive

```
for each rule (sorted by rule_id):
    for each condition: symptom must be present AND severity >= min_severity
    if all conditions match:
        confidence = round(sum(severity of matched symptoms) * weight, 6)
        emit candidate { icd10_code, confidence, matched_symptom_ids, rule_path }
```

All arithmetic is integer + float with 6-decimal rounding. Stdlib only
(no numpy/scipy). The verifier re-runs this traversal from committed
inputs and asserts the resulting list is identical to `payload/diagnosis.json`.

## Prerequisites

Python 3.11+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/healthcare_diagnosis_minimal/_build_bundle.py
```

By default this performs an **in-place build**: it writes manifest.json,
inputs/, payload/, and re_derive/ artifacts into the pilot directory itself
so verifying with `--bundle-dir examples/healthcare_diagnosis_minimal/`
Just Works.

To write the bundle into a fresh out-dir instead:

```bash
python examples/healthcare_diagnosis_minimal/_build_bundle.py --out-dir /tmp/hcd
```

Expected output:

```
Bundle written to .../healthcare_diagnosis_minimal
  symptoms         : 5
  rules            : 4
  candidates       : 4 ICD-10 codes
  evidence anchors : 10 OpaqueFragment
  manifest files   : <N>
  manifest         : .../manifest.json
```

## Step 2 — Verify

Two equivalent verifier routes are supported:

```bash
# Pilot wrapper — anchored, auto-detects re_derive/healthcare_diagnosis_pack.py
python examples/healthcare_diagnosis_minimal/verify.py --bundle-dir examples/healthcare_diagnosis_minimal/
```

```bash
# Pilot-local wrapper — registers HealthcareDiagnosisReDerivationCheck explicitly
python examples/healthcare_diagnosis_minimal/verify.py \
    --bundle-dir examples/healthcare_diagnosis_minimal/
```

Both must print `PASS` and exit 0. They invoke the same stdlib re-derivation
pack via subprocess — the pilot-local wrapper is a thinner shell for
domain-pilot smoke testing; the substrate CLI is the canonical auditor route.

| Plugin                              | Contract clause                                          |
|-------------------------------------|----------------------------------------------------------|
| `file_integrity_many_small`         | §C9 per-file SHA walk with named reason codes            |
| `re_derivation_invocation` / `healthcare_diagnosis_re_derivation` | §C6 deterministic ICD-10 re-derivation, exact match |

## Step 3 — Tamper-flow demo

Mutate the severity of one symptom — this shifts the rule-fire pattern and the
confidences, and the re-derivation detects the divergence:

```python
import json, pathlib
p = pathlib.Path('examples/healthcare_diagnosis_minimal/inputs/symptoms.json')
d = json.loads(p.read_text())
d[1]['severity'] = 1   # fever severity 4 -> 1; rule-J18 and rule-A49 stop firing
# Write back with the same canonical bytes layout as _build_bundle.py
import json as _j
p.write_bytes((_j.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8'))
```

Re-run the verifier:

```bash
python examples/healthcare_diagnosis_minimal/verify.py \
    --bundle-dir examples/healthcare_diagnosis_minimal/
```

Expected exit code: `1`. Stderr includes `BAD_FILE_SHA` (SHA mismatch caught
first) or `RE_DERIVATION_MISMATCH` (if manifest SHA was re-aligned
to the tampered symptom set).

## Fragment anchors

The bundle uses `OpaqueFragment` (the V-Kernel open-extension fragment type)
to anchor each evidence triplet that contributed to a candidate's confidence:

| Anchor key shape                       | kind_tag                  | Locator fields                            |
|----------------------------------------|---------------------------|-------------------------------------------|
| `<rule_id>-<symptom_id>-<icd10_code>`  | `icd10_evidence_anchor`   | `rule_id`, `symptom_id`, `icd10_code`     |

Substrate validates shape only; semantic validation (rule existence, symptom
existence, code well-formedness) is the responsibility of the
`HealthcareDiagnosisReDerivationCheck` plugin.

## File layout

```
examples/healthcare_diagnosis_minimal/
├── _build_bundle.py                            # synthesizes fixtures + builds audit bundle
├── verify.py                                   # pilot-local TypedCheck wrapper
├── HealthcareDiagnosisReDerivationCheck.py     # TypedCheck plugin (subprocess wrapper)
├── README.md
├── inputs/
│   ├── symptoms.json                           # 5 structured symptoms
│   └── rules.json                              # 4 decision-tree rule definitions
├── payload/
│   └── diagnosis.json                          # 4 ICD-10 candidates (model output)
├── re_derive/
│   └── healthcare_diagnosis_pack.py            # stdlib re-derivation pack (AB4)
└── manifest.json                               # generated; SHA-pinned for every file above
```

Tests live alongside the other domain-pilot tests at
`tests/test_healthcare_diagnosis_minimal.py` (one level up, same place as
test_kg_minimal.py / test_dp_minimal.py / test_bom_minimal.py).

## Tier-2 spec-pinned claim: per-candidate `confidence` (rational_band)

`spec_pinned_check.py` demonstrates a SECOND, additive spec-pinned surface
alongside the codes-only one described above (`RATIONAL_BAND_MIGRATION.md` §4b.2,
the "rational-band wave"). It builds an auditor-anchored bundle to a fresh temp
directory (the committed pilot files never gain an `outputs[]` array) that
declares:

- `healthcare_diagnosis_codes` — unchanged: the ordered icd10_code list,
  primitive `healthcare_diagnosis_recompute`, comparator `exact`.
- `healthcare_diagnosis_confidence` — **new**: one output per FIRED candidate,
  `output_id = "confidence:<icd10_code>"` (e.g. `confidence:J18.9`), primitive
  `healthcare_diagnosis_confidence_recompute`, comparator
  `rational_band {"epsilon": 1e-6}`.

**Why this is new, not a comparator swap.** The original spec description said
the per-candidate confidence float was "deliberately EXCLUDED to keep the output
exact-comparable" — that was a *vocabulary* limit (no float-safe comparator
existed for this substrate), not a durable scope decision. `rational_band`
dissolves the reason for the exclusion, so this slice is claim **authoring**: a
brand-new type + primitive_id, never a change to the existing `exact` codes
binding.

**Recompute.** `healthcare_diagnosis_confidence_recompute.py` parses the ICD-10
code out of the output_id, re-derives (its OWN independent rule-traversal — it
shares no code with either `_build_bundle.py`'s producer copy or the core
`healthcare_diagnosis_recompute` codes primitive) which committed rule fires for
that code, and returns the EXACT rational
`R = Fraction(severity_sum) * Fraction(confidence_weight)` — UNROUNDED
(`severity_sum` is an int sum of matched symptom severities; `confidence_weight`
is a committed JSON float literal, and `Fraction(float)` is exact for any
binary64 value). It refuses (raises) on a code that does not fire any committed
rule; dispatch maps that raise to a fail-closed `RECOMPUTE_ERROR` rather than
inventing a value.

**The claim** is read straight from the producer's OWN float pipeline —
`payload/diagnosis.json`'s own `confidence` field
(`round(severity_sum * confidence_weight, 6)`, written by `_build_bundle.py`) —
never from the new exact primitive. Epsilon = 1e-6 is the terminal 6dp
quantization grain: `confidence_weight` is a 2-decimal literal and
`severity_sum` is an integer, so the product's true decimal value already sits
on the 6dp grid and the round is a no-op up to float-representation noise many
orders below 1e-6.

**Coverage cross-check** (`confidence_coverage_check.ConfidenceCoverageCheck`,
wired into `spec_pinned_check.make_verifier()`'s plugin list): every icd10_code
present in the committed `healthcare_diagnosis_codes` claim must have a matching
`confidence:<code>` output declared in `manifest.outputs`. Without this, a
producer could silently drop one candidate's confidence output (e.g. to hide a
tampered value) — the dispatch-level `§4a.4` coverage invariant only enforces
that *declared* outputs have a matching file, it says nothing about the
codes↔confidence roster relationship. A mismatch surfaces as a
`typed_check_plugins:healthcare_diagnosis_confidence_coverage` / `plugin_failed`
failure whose detail names the missing/extra codes.

**work-set.** `make_verifier()` supplies an auditor **work-set**
(`audit_bundle.work_set.WorkSet`, `SELF_AUTHORED`) naming every possible
output_id (the codes output, plus `confidence:<code>` for every code the
fixture's own `_RULES` define — derived programmatically, not hand-duplicated)
with its required type. A manifest that rebinds a confidence output to the
codes type (or vice versa) is a fail-closed `ROLE_POLICY_VIOLATION`, checked
before any recompute runs; a manifest that drops one of these outputs, adds one
the set does not name, or declares one twice is a fail-closed
`WORK_SET_VIOLATION` (an exact multiset bijection, checked before dispatch
engages). This replaced the per-output `role_policy` on 2026-09-01, which was
allow-by-default for an unnamed output_id.

**Residuals (volunteered).**
- A PASS attests to the claims **present** in `manifest.outputs`; the coverage
  cross-check binds confidence outputs to whatever code roster the codes claim
  *itself* declares — it cannot force that codes claim to be complete. That is
  the pre-existing roster-completeness residual, unchanged by this slice.
- Sub-epsilon lies pass by definition: for a round-6dp claim, epsilon=1e-6 is
  exactly "sub-precision lies pass" — the claim's own declared precision.

**Tests:** `tests/test_healthcare_diagnosis_spec_pinned.py` (10 cells): the 5
original codes-only cells (now implicitly exercising the confidence surface too,
since it is built additively-by-presence) plus 5 new confidence-specific cells —
tampered-outside-epsilon, a `rational_band` edge cell (exact Fraction placement),
a nonexistent-code fail-closed cell, the coverage-gap RED cell, and the
work-set pin rebinding RED cell.
