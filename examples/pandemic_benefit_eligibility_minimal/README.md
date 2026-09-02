# pandemic_benefit_eligibility_minimal

V-Kernel audit-bundle pilot demonstrating deterministic benefit-eligibility re-derivation
for a pandemic-benefit disbursement scenario.

## Honest claim (verbatim)

> "A deterministic benefit-eligibility decision and benefit amount can be independently
> re-derived and signed from the applicant's attested attributes and the published rule set
> BEFORE disbursement — the exact pre-payment check that was skipped. Synthetic rules and
> records; no CRA/Service Canada integration; not a fraud detector."

## Motivation

The Canadian pandemic-benefit program (modelled here) paid approximately $4.6B to ineligible
recipients, per the Auditor General of Canada. The root cause: disbursement decisions were
made without a deterministic pre-payment eligibility check against the published rule set.
This pilot demonstrates that such a check is machine-derivable, tamper-evident, and
independently verifiable — and that a check that was skipped could have been automated.

## Re-derivation primitive

Re-derive each applicant's eligibility verdict and benefit amount by evaluating the published
deterministic rule set (minimum prior income $5,000, income-drop threshold, eligibility
period window) against the applicant's attested attributes, and assert it equals the bundled
disbursement decision.

## Eligibility rules (synthetic)

| Rule | Value |
|---|---|
| Minimum prior annual income | $5,000 CAD |
| Income-drop threshold | period income ≤ 10% of prior weekly income |
| Benefit replacement rate | 60% of prior weekly income |
| Maximum weekly benefit | $500/week |
| Eligibility period window | weeks 1–26 |

Admitted employment statuses: employed, self_employed, gig_worker, unemployed.

## Quick start

From the `v-kernel-audit-bundle` root:

```bash
# Gate 1 — build
python examples/pandemic_benefit_eligibility_minimal/_build_bundle.py \
    --out-dir /tmp/pandemic_bundle

# Gate 2 — verify (stdout must contain PASS)
python examples/pandemic_benefit_eligibility_minimal/verify.py \
    --bundle-dir /tmp/pandemic_bundle

# Gate 3 — pilot tests
python -m pytest tests/test_pandemic_benefit_eligibility_minimal.py -v

# Gate 4 — regression
python -m pytest tests/test_fragments.py tests/test_dispatch_record_wellformed.py -q
```

## Tamper flow

The tamper test (`test_ineligible_applicant_approved_is_caught`) mutates APP-006 so the
bundled decision says APPROVED while the applicant's prior_income is below the $5,000 floor.
The verifier re-derives DENIED and returns `result.ok is False` with
`RE_DERIVATION_MISMATCH` in the failures list.

This is the central thesis: the verifier never trusts the disbursement system's verdict —
it re-derives it from the applicant's attested attributes and the published rule set, then
catches any divergence.

Two more tamper flows bind fields the verdict/amount re-derivation does not itself touch —
both re-sign with the bundled (disclosed-by-design) HMAC key, so a valid signature alone is
NOT proof of either field's honesty:

- **`test_period_week_forged_is_caught`** — `period_week` is shifted away from the value the
  build establishes (`_build_bundle.py` sets it to the applicant's own attested
  `eligibility_period_week`; there is no other source for it), then re-signed. The verifier
  binds `period_week` to that same attested field by exact equality and rejects with
  `PERIOD_WEEK_MISMATCH`.
- **`test_disbursement_system_id_forged_is_caught`** — `disbursement_system_id` is relabelled
  to an unprovisioned system, then re-signed. The verifier checks it against a verifier-held,
  never-read-from-the-bundle roster of the one disbursement system this synthetic deployment
  has actually provisioned (the verifier-held roster pattern other pilots use for recorder
  and approver identities) and rejects with `UNAUTHORIZED_DISBURSEMENT_SYSTEM`.

## File layout

```
pandemic_benefit_eligibility_minimal/
├── _build_bundle.py                       # build script (synthetic fixtures + manifest)
├── verify.py                              # verifier entry point (four plugins)
├── pandemic_eligibility_rederivation.py   # stdlib-only re-derivation engine (C5)
├── PandemicEligibilityReDerivationCheck.py # TypedCheck plugin (subprocess wrap)
├── pilot.json                             # pilot metadata (hand-authored, not auto-generated)
└── README.md
```

Tests live at `tests/test_pandemic_benefit_eligibility_minimal.py`.

## Scope and limitations

- **Synthetic data only.** No real applicant data. No CRA/Service Canada integration.
- **Not a fraud detector.** The verifier catches divergence between the bundled decision and
  the rule set — it does not detect identity fraud or fabricated attested attributes.
- **Deterministic rules only.** Rules with interpretive elements (e.g. exceptional
  circumstances, discretionary provisions) are out of scope for this pilot.
- **No legal or regulatory advice.** The rule set models published CERB eligibility criteria
  for demonstration purposes only.
- **Field coverage.** Every field on `payload/disbursement_decisions.json` is now bound:
  `verdict`/`weekly_benefit_cents` by re-derivation from the rule set, `applicant_id` by
  existence in `data/applicants.json`, `period_week` by exact equality to the applicant's
  own attested `eligibility_period_week`, and `disbursement_system_id` against a
  verifier-held, deployment-pinned roster. `signature` covers all of it as a
  no-silent-post-hoc-edit binding, but (by design, since the demo key is disclosed) does not
  by itself establish that any individual field is honest — that is why every field also has
  an independent binding above.
