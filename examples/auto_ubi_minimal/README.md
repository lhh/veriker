# auto_ubi_minimal — Usage-Based Auto Insurance (UBI) Telematics Rating Audit Bundle Pilot

Domain pilot: telematics feature aggregation and rate-table rating for usage-based
auto insurance (UBI), bundled for V-kernel audit verification
(the audit-bundle contract §C5, C6, C9, C15).

Regulator scope:
- **NAIC AI Systems Evaluation Tool** (Underwriting / telematics-UBI and Pricing categories)
- **Colorado Reg 10-1-1 § 5.A.11** quantitative-testing requirements for private passenger
  auto, effective 2025-10-15

Re-derivation primitive: re-aggregate telematics features (mileage, hard-brake count,
harsh-acceleration count, late-night driving fraction) from bundled raw trip records
via stdlib-only computation, re-evaluate the bundled rate-table JSON to recompute
the rating tier and discount — assert the bundle payload matches.

Extension surfaces exercised:
- `OpaqueFragment(source_cid, kind_tag="telematics_trip", locator={...})` — one fragment
  anchor per raw trip record bundled in `telematics/trips.jsonl`.
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"}))` —
  admits the two domain-specific op kinds introduced by this pilot.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Build the bundle

```bash
python examples/auto_ubi_minimal/_build_bundle.py --out-dir /tmp/auto_ubi_bundle
```

Expected output (abbreviated):

```
Bundle written to /tmp/auto_ubi_bundle
  policyholders    : 5
  trip records     : 69
  manifest files   : 3
  fragment anchors : 69 OpaqueFragment (kind_tag=telematics_trip)
  dispatch records : 10 (5 × COMPUTE + RATE_TABLE_LOOKUP)
  rating tiers     : ['high_risk_surcharge', 'low_mileage_discount', 'standard']
  manifest         : /tmp/auto_ubi_bundle/manifest.json
```

## Verify the bundle

```bash
python examples/auto_ubi_minimal/verify.py --bundle-dir /tmp/auto_ubi_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                        | Contract clause                                           |
|-------------------------------|-----------------------------------------------------------|
| `file_integrity_many_small`   | §C9 per-file SHA walk                                     |
| `auto_ubi_re_derivation`      | §C6 UBI telematics re-derivation (feature + tier match)   |
| `dispatch_record_wellformed`  | §C15 op-kind + effect well-formedness                     |

## Claim-field coverage (claimset)

Two payload files are declared, both structured JSON:
`manifest.claimset.claim_files = {"rate_table": "payload/rate_table.json",
"rating_decisions": "payload/rating_decisions.json"}`. Their 21 observed
fields (the field set the shipped bytes carry — the enumerator is
instance-measured, not schema-derived) partition very unevenly across the
two files:

| fields | disposition |
|---|---|
| `rating_decisions[].adjustment_pct`, `.annual_mileage_est`, `.hard_brake_per_mile`, `.harsh_accel_per_mile`, `.late_night_fraction`, `.tier`, `.total_miles` | **covered** — re-aggregated per policyholder from `telematics/trips.jsonl` and re-evaluated against `payload/rate_table.json`'s thresholds (the five features within a fixed tolerance that covers the bundle's rounding grain; the five features as typed JSON numbers within a fixed tolerance — a string `"107.6"` or `true` is refused; `tier` by string equality; `adjustment_pct` and `trip_count` as typed JSON integers — `15.0` and `false` are refused) |
| `rating_decisions[].trip_count` | **covered** — bound to the pack's own re-aggregation count (`features["trip_count"]`, already computed for `late_night_fraction`'s denominator but never diffed against the payload before this adoption) |
| `rating_decisions[].policyholder_id` | **covered** — a real bijection: a duplicate `policyholder_id` across decision rows is refused outright, and the SET of decision ids must equal the set of ids with trip records (a dropped or invented policyholder is refused), both added by this adoption |
| `rate_table:schema_version` | **residual, `INSPECTION_ONLY`** — a version tag on the `tier_thresholds`/`tiers` structure the comparator does read; not itself a re-derived value |
| `rate_table:tiers.high_risk_surcharge.description`, `.low_mileage_discount.description`, `.standard.description` | **residual, `NOT_MECHANICALLY_CHECKABLE`** — free-text prose restating a rule; judging it accurate against the numeric thresholds needs semantic judgment, not a comparison |
| `rate_table:tiers.high_risk_surcharge.surcharge_pct`, `rate_table:tiers.low_mileage_discount.discount_pct`, `rate_table:tiers.standard.discount_pct` | **covered** — each is the OTHER operand of the per-row `adjustment_pct` comparison on its tier (the pack's recomputed adjustment IS the table value, negated for the surcharge), so it is bound to `payload/rating_decisions.json` on every row of that tier and reported under `payload/rate_table.json` once a row of that tier has compared (a fixture without a tier leaves that element unreported → could-not-conclude). Second-copy consistency between two producer-written files: a producer who changes a tier value AND every matching decision together passes — the stated limit below. The `standard` tier's adjustment used to be a pack literal `0` (the table's `tiers.standard.discount_pct` was never read); both the builder and the pack read the table now (wave-2 review finding) |
| `rate_table:tier_thresholds.annual_mileage_low_max`, `.annual_mileage_high_min`, `.hard_brake_per_mile_surcharge_threshold`, `.harsh_accel_per_mile_surcharge_threshold`, `.late_night_fraction_surcharge_threshold` | **residual, `NO_BINDING_TARGET`** — each is the right-hand operand of an inequality that SELECTS a tier branch, never a compared value: the decisions constrain a threshold only to an interval (four of the five survive the battery's own +1 mutation on this fixture), and nothing in the bundle carries a second copy of the thresholds. `annual_mileage_high_min` is read by neither the pack nor the builder (dead config the table's `standard` description still mentions — a pilot finding, not an adoption edit) |

**Scope limit stated plainly, not papered over:** this is a starker split
than most adopted pilots (credit_scoring: 7/8 covered; payroll: 7/9) —
`payload/rate_table.json`'s entire 12-field element set is residual, because
this pilot's re-derivation proves `payload/rating_decisions.json` is
**faithful to** the bundled `telematics/trips.jsonl` and `payload/rate_table.json`,
never that either of those two is itself correct. A producer who changes a
threshold in `rate_table.json` *and* the matching `rating_decisions.json`
rows together is undetectable by this pack — there is no regulator-filed or
otherwise independently-anchored copy of the rate table in this bundle to
check against. Likewise, a producer who alters raw trip records and honestly
recomputes decisions from the altered trips is undetectable: the pack has no
second, independently-anchored source of driving behavior (unlike, e.g., a
separately-anchored bureau snapshot). `telematics/trips.jsonl`'s SHA is
integrity-pinned by `file_integrity_many_small` and every trip record carries
an `OpaqueFragment` anchor, but neither establishes the trips are the *true*
trips — only that the bundle is internally self-consistent about them.

`AutoUBIReDerivationCheck` reports coverage ONLY when the pack exited 0, and
only for the fields the pack's `[COMPARED]` stdout line names (emitted from
the success return at the bottom of `main()`, keyed by bundle-relative file): the pack adds each field to a set as its comparison passes and prints the set once from its success return; the plugin requires exactly ONE such line (none, several or malformed → nothing reported) and treats an exit 0 without the line as `incomplete=True`.
The per-field tamper battery in `tests/test_auto_ubi_minimal.py` requires
every covered field to flip under the pack's own `[RE_DERIVATION_MISMATCH]`
tag, never via a file-sha mismatch. Both spec-pinned lanes
(`spec_pinned_check.py` and the recipe-promoted variant in
`tests/test_recipe_auto_ubi_promoted.py`) build the same legacy bundle but
run the promoted primitive on a separate `outputs/` claim instead of wiring
this pack, so both drop the declaration and carry the honest "claimset: not
declared" disclosure.

## Tamper-flow demo

Mutate a trip record's hard-brake count so its SHA changes — the verifier
catches it via `FileIntegrityManySmall` (§C9 SHA walk):

```bash
python -c "
import json, pathlib
p = pathlib.Path('/tmp/auto_ubi_bundle/telematics/trips.jsonl')
lines = p.read_text().splitlines()
t = json.loads(lines[0])
t['hard_brakes'] = 999
lines[0] = json.dumps(t, sort_keys=True)
p.write_text('\n'.join(lines) + '\n')
"
python examples/auto_ubi_minimal/verify.py --bundle-dir /tmp/auto_ubi_bundle
```

Expected exit code: `1`. Expected stderr contains `bad_file_sha` (from
`FileIntegrityManySmall`) since the trips JSONL SHA no longer matches
`manifest.files`.

## File layout

```
examples/auto_ubi_minimal/
├── _build_bundle.py              # builds the deterministic bundle
├── verify.py                     # runs all three TypedCheck plugins
├── AutoUBIReDerivationCheck.py   # domain plugin (C6 UBI re-derivation)
├── auto_ubi_re_derivation.py     # re-derivation implementation (stdlib only)
└── README.md
tests/
└── test_auto_ubi_minimal.py      # happy-path + tamper test
```

Bundle layout (written to `--out-dir`):

```
<out-dir>/
├── telematics/
│   └── trips.jsonl               # synthetic raw trip records (5 policyholders)
├── payload/
│   ├── rate_table.json           # tier thresholds + discount/surcharge schedule
│   └── rating_decisions.json     # per-policyholder rating decision
└── manifest.json
```
