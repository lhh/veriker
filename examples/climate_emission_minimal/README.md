# climate_emission_minimal — V-Kernel S0 pilot

Domain: **climate / ESG** — Scope-3 supply-chain emission attribution.

Re-derivation primitive (one sentence): for each supplier in
`inputs/supplier_chain.json` (in list order, sorted by tier then `vendor_id`),
compute `attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)`;
sum to `total_scope3_kg_co2e` (round 6dp); assert per-supplier values + total
match `payload/emission_report.json` exactly.

## Quick start

```bash
cd v-kernel-audit-bundle

# Build out-of-tree, then verify with the pilot's own anchored wrapper.
# The bundle must NOT be this directory: auditor_kit.py lives here, and a kit
# resolving inside the bundle is refused (that guard is the point of the pilot).
python examples/climate_emission_minimal/_build_bundle.py --out-dir /tmp/climate_bundle
python examples/climate_emission_minimal/verify.py --bundle-dir /tmp/climate_bundle   # PASS

# Pilot pytest:
python -m pytest tests/test_climate_emission_minimal.py -v
```

## Re-derivation: Axis-2 spec-pinned dispatch

**Migrated 2026-08-16.** This pilot used to ship `re_derive/climate_emission_pack.py`
and have the verifier execute it in a subprocess (`permit_execution=True`). That
made the re-derivation verdict a claim authored by the bundle — a pack that simply
`exit(0)`s produced a PASS — and required running untrusted code locally.

It no longer ships any executable code. The bundle declares two outputs:

| Output | Claim file | Auditor spec | Comparator |
|---|---|---|---|
| `climate_total_scope3` | `outputs/climate_total_scope3.json` | `climate.spec.json` | `exact` |
| `climate_attribution_by_vendor` | `outputs/climate_attribution_by_vendor.json` | `climate_emission.spec.json` | `structured` |

The **verifier** recomputes both from committed evidence using its own registered
primitives and compares against the producer's claims. The `SpecAnchor` is built
from the **committed** spec bytes under `spec_pinned/`, never the bundle's `spec/`
copy — so a producer who ships a weakened spec yields a SHA the anchor does not
list and dispatch fails closed (Axis-1).

## Tamper-flow demo

All five flows are in `tests/test_climate_emission_minimal.py`:

```bash
# (1) Mutate inputs/supplier_chain.json, do NOT realign manifest SHA
#     -> file_integrity_many_small catches BAD_FILE_SHA.
# (2) Forge outputs/climate_total_scope3.json AND realign manifest SHA
#     -> bundle is hash-consistent; dispatch alone catches RE_DERIVATION_MISMATCH.
# (3) Forge outputs/climate_attribution_by_vendor.json AND realign the SHA
#     -> same, on the structured comparator (proves BOTH outputs dispatch).
# (4) Edit committed evidence AND realign its SHA
#     -> re-derived values move, claims do not -> RE_DERIVATION_MISMATCH.
# (5) Swap a laxer comparator into the bundle's spec/ copy + realign spec_files
#     -> AnchorViolation; the auditor's anchor does not list that SHA.
```

Cases (2)-(5) are the class a hash alone cannot catch: the bundle is internally
consistent and only an independent recompute rejects it.

> **Verifying this bundle — two equivalent ways.** The pilot's own `verify.py`
> loads the auditor kit (`auditor_kit.py`, which registers the pilot-local
> `ClimateAttributionRecompute`) and builds the anchor from the committed
> specs; it is the one-command wrapper. The generic top-level verify CLI
> reaches the same verdict with the anchor and the kit supplied explicitly:
> `--spec-anchor spec_pinned/climate.spec.json spec_pinned/climate_emission.spec.json
> --primitives auditor_kit.py` (point `--bundle-dir` at a PRODUCER bundle built
> elsewhere, not this dir — see `auditor_kit.py`). With no anchor, spec-pinned
> dispatch is a could-not-conclude (`AnchorNotSupplied` → `VERIFIER_INCOMPLETE`,
> exit 2 — not a REJECT); with an anchor but no `--primitives`, the pilot-local
> `climate_attribution_recompute` is `UNKNOWN_PRIMITIVE` (the verifier never
> loads a primitive from the bundle). The kit is auditor-held code the CLI
> executes: its sha256 is on the verdict face, a kit path inside the bundle is
> refused, and any registered primitive whose source resolves inside the bundle
> is refused (`PRIMITIVE_SOURCE_INSIDE_BUNDLE`).

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Manifest construction + the two `outputs/` claim files and the `spec/` auditor-spec copies. Sweeps `__pycache__` and sets `sys.dont_write_bytecode` (verifier-self-pollution guard). |
| `verify.py` | Pilot-local verifier — loads `auditor_kit.py`, builds the `SpecAnchor` from the committed specs via `from_files`, runs `FileIntegrityManySmall` + spec-pinned dispatch. Executes no bundle code. |
| `auditor_kit.py` | The auditor-held primitive kit: registers `ClimateAttributionRecompute` for the shipped CLI's `--primitives`. The one registration path (also used by `verify.py`). |
| `climate_attribution_recompute.py` | Verifier-side re-derivation primitive for the per-vendor attribution list (stdlib-only). |
| `spec_pinned/*.spec.json` | The auditor's committed binding specs — the anchor source of truth. |
| `spec/` | (generated) The bundle's copy of the auditor specs. Non-authoritative by construction. |
| `outputs/*.json` | (generated) The producer's claimed values, re-derived and compared at verify time. |
| `inputs/supplier_chain.json` | (generated) 4-tier synthetic supplier chain (8 suppliers). |
| `payload/emission_report.json` | (generated) Per-supplier attributions + `total_scope3_kg_co2e` + `aggregation_method: "sum"`. |
| `manifest.json` | (generated) Bundle manifest. `OpaqueFragment(kind_tag="supplier_emission_anchor")` per supplier. |

## Fragment kind

`OpaqueFragment(kind_tag="supplier_emission_anchor")` — one anchor per supplier
locating `(vendor_id, factor_source, tier)`. Substrate validates shape only;
the semantic property is carried by spec-pinned dispatch over the two declared
outputs, not by a bundle-supplied check.

## Synthetic-data caveat

Emission factors are plausible but **invented** (`synthetic-EF-v1.0/*`) — not
lifted from a real EF database (DEFRA, EPA, ecoinvent). Production integrators
replace the synthetic supplier chain with real procurement data + a certified
EF source; the bundle shape and verification protocol stay identical.

## Production integration

Real integrators swap `_SUPPLIER_CHAIN` in `_build_bundle.py` for live procurement
data, and the synthetic-EF tags for the integrator's certified EF database
references (DEFRA / EPA / ecoinvent / GHG Protocol). The deterministic
multiply-and-sum primitive does not change.

## Patent context

Demonstrates the V-Kernel S0 integrator on climate / ESG numeric-aggregation. One
row in the N-domain demonstration table of
`the internal design notes` (orchestrator updates
the portfolio after merge).
