# credit_scoring_minimal

Bank consumer-credit decisioning (loan-approval scorecard) pilot for the
V-Kernel S0 audit-bundle integrator, anchored to the **Brazilian** regulatory
surface a digital lender like Banco Inter faces.

**Regulatory anchors** (verified 2026-05-29 — full citations in
`examples/inter_seven_agent_gate_minimal/inter_regulatory_backbone_2026-05-29.md`):

- **LGPD (Lei 13.709/2018) art. 20 — IN FORCE.** A data subject may request review
  of a decision taken *solely* on automated processing that affects their interests
  (expressly including credit profile), and the controller must provide **"clear and
  adequate information on the criteria and procedures"** used (subject to trade-secret
  limits); the ANPD may audit for discriminatory effects.
- **PL 2338/2023 (Marco Legal da IA) — BILL, not enacted** (approved by the Senate
  2024-12-10; under review in the Câmara dos Deputados since 2025-03-17). Classifies
  **credit evaluation / granting as "high-risk"**, triggering algorithmic-impact-
  assessment duties.

This pilot models a **traditional ML scorecard** (logistic-regression-style
coefficient table over a Serasa-style 0–1000 credit score) — a deterministic
decision whose criteria art. 20 requires the lender be able to explain.

## Regulatory Mapping

| Obligation | What this pilot demonstrates |
|---|---|
| LGPD art. 20 — explain the criteria & procedures of an automated credit decision | `credit_scoring_re_derivation.py` replays applicant attributes through the bundled scorecard coefficients, recomputes PD scores and approve/decline + rate-tier verdicts, asserts exact match against the bundled payload (including `pd` itself — not merely the tier it falls into) — the explanation *is* the re-derivation |
| Auditable model record | `bundle_id`, `created_at`, `model/scorecard.json`, `model/threshold_table.json` constitute the model documentation |
| PL 2338 (pending) — high-risk algorithmic-impact artifact | `source_attributes` on the bureau-snapshot CID carries `publication_class="regulatory"` and `external_status_flags=["lgpd_art20_automated_credit_decision"]`, demonstrating V-Kernel's runtime emission of credit-bureau-data lineage |

## Re-derivation Primitive

Replay each applicant's credit attributes through the bundled scorecard
coefficients (stored in `model/scorecard.json`), recompute the
probability-of-default (PD) via the logistic function
`PD = 1 / (1 + exp(-Σ wᵢxᵢ))`, look up the approve/decline + rate-tier
verdict in `model/threshold_table.json`, and assert the result matches
`payload/credit_decisions.json` — **including `pd` itself**, compared at the
builder's 6dp storage grain (`|Δ| ≤ 1e-6`, 6dp round-trip stable — the last
stored digit may differ by one unit; the tolerance is sized for cross-platform
libm wobble). A PD range maps many
distinct raw probabilities onto the same tier/decision/apr, so matching tier
alone would let a materially different `pd` (the exact number LGPD art. 20
requires the lender disclose to the data subject) pass unnoticed; a missing
`pd` field fails closed.

**Input binding.** Before replaying, the pack binds every `applicants/<id>.json`'s
five bureau attributes to the bureau snapshot the bundle registers in
`manifest.snapshots` (`schema: bureau-snapshot-v1`, the CID-registered,
`publication_class="regulatory"` pull the 25 fragment anchors point at). An
applicant file that contradicts that snapshot is refused
(`[CREDIT_SCORING_BUREAU_MISMATCH]`) — without this, a forged input with an
honestly recomputed payload verified PASS while the bundle's own registered
pull said "decline" (found by a red-team pass, 2026-08-20). Stated limit: in
this synthetic pilot the snapshot is producer-authored (no issuer signature),
so the binding is consistency between inputs and the registered artifact, not
external provenance.

## Claim-field coverage (claimset)

`payload/credit_decisions.json` is the claim file, declared structured:
`manifest.claimset.claim_files = {"credit_decisions": "payload/credit_decisions.json"}`.
Its eight observed fields (the field set the shipped bytes carry — the
enumerator is instance-measured, not schema-derived) partition as:

| fields | disposition |
|---|---|
| `decisions[].applicant_id`, `decisions[].pd`, `decisions[].tier`, `decisions[].decision`, `decisions[].apr_pct` | **covered** — re-derived per applicant from `applicants/*.json` through `model/scorecard.json` and `model/threshold_table.json` (`applicant_id`: bundled rows ↔ applicant files is a bijection — duplicate ids refused, array length compared; `pd` within one 6dp grain, `1e-6`; the rest exact; `apr_pct` must be present in every row) |
| `scorecard_model`, `scorecard_version` | **covered** — bound to `model/scorecard.json`'s `model_name` / `model_version`, the scorecard whose coefficients the pack replays (these two fields were unread until the coverage gate named them) |
| `schema` | **residual, `INSPECTION_ONLY`** — a schema label carrying no claim: the pack reads a fixed key set regardless of the label and never checks conformance to anything the label names, so a relabelled file verifies the same; pinning the label string to a constant in the pack would be an assertion, not a comparison against independent data |

`CreditScoringReDerivationCheck` reports coverage ONLY when the pack exited 0,
and only for the fields the pack's `[COMPARED]` stdout line names (emitted
from the success return of the comparison, keyed by bundle-relative file) —
coverage follows what the pack compared, never a constant in the plugin.
The per-field tamper battery in `tests/test_credit_scoring_minimal.py`
requires every covered field to flip under the pack's own refusal
(`[CREDIT_SCORING_PD_MISMATCH]` for `pd`,
`[RE_DERIVATION_MISMATCH]` for the rest), never via a file-sha
mismatch. The spec-pinned overlay lane (`spec_pinned_check.py`) does not wire
the pack and drops the declaration, so that lane's verdict carries the honest
"claimset: not declared" disclosure.

## V-Kernel Extension Points Exercised

- `OpaqueFragment(kind_tag="credit_attribute")` — one anchor per
  (applicant, bureau attribute) pair; `source_cid` points to the
  bureau-snapshot CID registered in `snapshots`.
- `source_attributes[bureau_cid]` — `publication_class="regulatory"` tags
  the credit-bureau data pull as bureau-sourced (Serasa / Boa Vista / SPC style).
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"}))`
  — admits the new `SCORECARD_EVAL` op kind (one record per applicant) and
  `COMPUTE` (the threshold-lookup pass).

## Synthetic Fixtures

Five applicants spanning the full tier range (Serasa Score is a 0–1000 scale,
higher = lower risk; rate tiers shown in `apr_pct`, % a.a.):

| ID | Serasa Score | Utilization | Tradelines | DTI | Negativações | Expected Tier |
|---|---|---|---|---|---|---|
| APP-001 | 780 | 8% | 15 | 22% | 0 | A (approve) |
| APP-002 | 660 | 45% | 8 | 35% | 1 | B (approve) |
| APP-003 | 610 | 70% | 5 | 48% | 1 | C (approve) |
| APP-004 | 580 | 95% | 3 | 58% | 3 | D (decline) |
| APP-005 | 755 | 15% | 12 | 28% | 0 | A (approve) |

Loan amounts are in **BRL** (`loan_amount_brl`). The scorecard math is unchanged
from the generic scorecard; only the score field and currency are localized.

## Quick Start

```bash
# From v-kernel-audit-bundle root:

# Gate 1 — build
python examples/credit_scoring_minimal/_build_bundle.py --out-dir /tmp/credit_scoring_bundle

# Gate 2 — verify
python examples/credit_scoring_minimal/verify.py --bundle-dir /tmp/credit_scoring_bundle
# stdout: PASS

# Gate 3 — pilot tests
python -m pytest tests/test_credit_scoring_minimal.py -v

# Gate 4 — regression
python -m pytest tests/test_fragments.py tests/test_dispatch_record_wellformed.py -q
```

## Tamper Demo

To observe the verifier catching a manipulated Serasa Score:

```bash
# Build clean bundle
python examples/credit_scoring_minimal/_build_bundle.py --out-dir /tmp/credit_scoring_tamper

# Drop APP-001's score from 780 to 400 (changes tier A → D)
python -c "
import json, hashlib
from pathlib import Path
d = Path('/tmp/credit_scoring_tamper')
app = json.loads((d/'applicants/APP-001.json').read_text())
app['serasa_score'] = 400
(d/'applicants/APP-001.json').write_text(json.dumps(app, indent=2, sort_keys=True))
sha = hashlib.sha256((d/'applicants/APP-001.json').read_bytes()).hexdigest()
m = json.loads((d/'manifest.json').read_text())
m['files']['applicants/APP-001.json'] = sha
(d/'manifest.json').write_text(json.dumps(m, indent=2, sort_keys=True))
"

python examples/credit_scoring_minimal/verify.py --bundle-dir /tmp/credit_scoring_tamper
# stdout/stderr: FAIL ... [CREDIT_SCORING_BUREAU_MISMATCH] applicant 'APP-001': serasa_score=400 in applicants/ but 780 in the registered bureau snapshot
# (the tampered input contradicts the bundle's own registered bureau pull, so the
#  input binding refuses before the scorecard is replayed; a payload-side tamper
#  reaches the re-derivation comparisons — see the pd demo below)
```

To observe the verifier catching a `pd` substitution that keeps the same tier/decision/apr
(the disclosed PD is the specific number LGPD art. 20 requires — a tier match alone does not
bind it):

```bash
# Build clean bundle
python examples/credit_scoring_minimal/_build_bundle.py --out-dir /tmp/credit_scoring_pd_tamper

# Report a materially different pd for APP-002 without moving it out of tier C
python -c "
import json, hashlib
from pathlib import Path
d = Path('/tmp/credit_scoring_pd_tamper')
payload = json.loads((d/'payload'/'credit_decisions.json').read_text())
for dec in payload['decisions']:
    if dec['applicant_id'] == 'APP-002':
        assert dec['tier'] == 'C'
        dec['pd'] = 0.25  # still inside tier C's [0.20, 0.40) band
(d/'payload'/'credit_decisions.json').write_text(json.dumps(payload, indent=2, sort_keys=True))
sha = hashlib.sha256((d/'payload'/'credit_decisions.json').read_bytes()).hexdigest()
m = json.loads((d/'manifest.json').read_text())
m['files']['payload/credit_decisions.json'] = sha
(d/'manifest.json').write_text(json.dumps(m, indent=2, sort_keys=True))
"

python examples/credit_scoring_minimal/verify.py --bundle-dir /tmp/credit_scoring_pd_tamper
# stdout/stderr: FAIL ... RE_DERIVATION_MISMATCH (detail carries [CREDIT_SCORING_PD_MISMATCH])
```

## File Layout

```
examples/credit_scoring_minimal/
  _build_bundle.py                 Build script — synthesizes fixtures, writes bundle
  verify.py                        Verifier — registers plugins, runs BundleVerifier
  credit_scoring_re_derivation.py  Stdlib-only re-derivation pack (subprocess CLI)
  CreditScoringReDerivationCheck.py TypedCheck plugin wrapping the subprocess call
  README.md                        This file
tests/
  test_credit_scoring_minimal.py   Happy-path + tamper integration tests
```

## Scope honesty

Synthetic fixtures; no real Serasa/Boa Vista/SPC pull and no real lender model.
The scorecard coefficients are illustrative. PL 2338/2023 is a **pending bill**,
not enacted law — do not present it as current regulation. V-Kernel makes the
credit decision **re-derivable and explainable**; it does not validate that the
scorecard itself is fair or correct (that is the lender's model-governance duty).
```
