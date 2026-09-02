"""_producer_compute.py — the PRODUCER's own copy of this pilot's computations.

Gate B (producer<->verifier non-tautology, PRIMITIVES.md): the bundle's claimed
values must be computed by code that is PHYSICALLY SEPARATE from the code the
verifier re-derives with. Otherwise `claimed == re-derived` is `f(x) == f(x)` —
green by construction, and the drift-detection capability the pilot demonstrates
is hollow.

Before 2026-08-29 this pilot had no such copy. `_build_bundle.py` imported
`compute_total` from `audit_bundle.rederivation.primitives.climate_emission` and
loaded `compute_attribution` from `climate_attribution_recompute.py` — in BOTH
cases the very function the verifier runs. Three docstrings stated the sharing as
a feature ("share ONE definition ... cannot drift"), which inverts the property:
code that cannot drift also cannot be caught drifting.

This module is that copy. Same semantics deliberately — the claims must not
change — but its own source, free to drift, so a divergence between producer and
verifier is DETECTABLE rather than impossible.

DO NOT "de-duplicate" this against the primitives. An edit that replaces either
function with an import from `audit_bundle.rederivation.primitives.*` or from
`climate_attribution_recompute` reintroduces the tautology. The file is named
`_producer_compute.py`, not `*_recompute.py`, so it is not mistaken for a
verifier-side re-export shim.

Stdlib-only; importable without `audit_bundle` on sys.path.
"""

from __future__ import annotations


def compute_total(supplier_chain: list) -> float:
    """Producer's Scope-3 total: each supplier's activity*factor rounded to 6dp,
    accumulated in list order, the total rounded to 6dp."""
    running = 0.0
    for supplier in supplier_chain:
        activity = float(supplier["activity_amount"])
        factor = float(supplier["emission_factor_kg_co2e_per_unit"])
        running += round(activity * factor, 6)
    return round(running, 6)


def compute_attribution(supplier_chain: list) -> list:
    """Producer's per-vendor attribution list, one record per supplier in list
    order, carrying exactly the climate_attribution_v1 fields.

    `attributed_kg_co2e` is the only derived field (activity * factor, 6dp); the
    other six are read verbatim from the supplier's committed record, which is
    what lets the structured comparator bind the disclosure-relevant fields
    (which factor basis, at what activity amount) and not merely their product.

    Raises ValueError on empty input.
    """
    if not supplier_chain:
        raise ValueError("supplier_chain is empty — cannot compute attribution")
    out = []
    for supplier in supplier_chain:
        activity = float(supplier["activity_amount"])
        factor = float(supplier["emission_factor_kg_co2e_per_unit"])
        out.append(
            {
                "vendor_id": supplier["vendor_id"],
                "tier": supplier["tier"],
                "activity_amount": supplier["activity_amount"],
                "activity_unit": supplier.get("activity_unit"),
                "emission_factor_kg_co2e_per_unit": supplier[
                    "emission_factor_kg_co2e_per_unit"
                ],
                "factor_source": supplier["factor_source"],
                "attributed_kg_co2e": round(activity * factor, 6),
            }
        )
    return out
