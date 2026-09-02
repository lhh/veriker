"""climate_attribution_recompute.py — verifier-side per-vendor Scope-3
attribution re-derivation primitive (NEW in-dir primitive; does NOT collide
with the central audit_bundle/rederivation/primitives/climate_emission.py
"climate_emission_recompute", which returns the scalar total under `exact`).

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the climate_emission_minimal pilot onto spec-pinned
dispatch. The recompute primitive lives HERE (verifier-distribution code,
registered by the spec-pinned builder), NOT in audit_bundle/rederivation/.

Representative output: the per-vendor emission attribution LIST. Each record has
EXACTLY the allowlisted climate_attribution_v1 fields:
    {vendor_id, tier, activity_amount, activity_unit,
     emission_factor_kg_co2e_per_unit, factor_source, attributed_kg_co2e}
where attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6).

FIX-E (claim-set coverage sweep): activity_amount, activity_unit,
emission_factor_kg_co2e_per_unit, and factor_source were added to this schema
because attributed_kg_co2e is a single PRODUCT of activity_amount and
emission_factor_kg_co2e_per_unit — the two factors cannot be recovered from
the product alone, and factor_source has no numeric relationship to it at all.
Binding only the product let a claimed record swap in a fictitious low-carbon
factor_source label, or a different factorization of the same product, while
still passing. All four fields are read VERBATIM from the same committed
supplier record used to compute attributed_kg_co2e, so a structured-comparator
PASS now means the claimed record's activity data, unit, emission factor, and
factor-source label all match inputs/supplier_chain.json — not just the total.

`tier` is NOT derived — every supplier in inputs/supplier_chain.json carries an
explicit integer `tier` field (1..4), so it is read verbatim from the committed
evidence. vendor_id, activity_amount, activity_unit, emission_factor_kg_co2e_per_unit,
and factor_source are likewise read verbatim. The list is produced in
supplier-chain list order; the structured comparator compares all 7 fields
field-wise over the list in that order.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()). The
spec-pinned BUILDER does not import it — the producer's copy lives in
_producer_compute.py (Gate B, 2026-08-29).
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation — VERIFIER SIDE. The producer has its OWN copy in
# _producer_compute.py (Gate B); do not import this from the build script.
# ---------------------------------------------------------------------------


def compute_attribution(supplier_chain: list) -> list:
    """Canonical per-vendor Scope-3 attribution list. For each supplier in list
    order, produce a record with exactly the climate_attribution_v1 fields:
    {vendor_id, tier, activity_amount, activity_unit,
     emission_factor_kg_co2e_per_unit, factor_source,
     attributed_kg_co2e=round(activity*factor, 6)}.

    `tier`, `activity_amount`, `activity_unit`, `emission_factor_kg_co2e_per_unit`,
    and `factor_source` are all read verbatim from the supplier's committed
    record in inputs/supplier_chain.json (no derivation) — this is what lets the
    structured comparator bind the disclosure-relevant fields (which emission-
    factor basis was used, at what activity amount) to committed evidence,
    not just the activity*factor product (FIX-E).

    The builder does NOT call this function — it has its own copy in
    _producer_compute.py, so a divergence between the claimed list and the
    re-derivation is detectable (Gate B; corrected 2026-08-29).

    Raises ValueError on empty input.
    """
    if not supplier_chain:
        raise ValueError("supplier_chain is empty — cannot compute attribution")
    records = []
    for s in supplier_chain:
        attributed = round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
        records.append(
            {
                "vendor_id": s["vendor_id"],
                "tier": s["tier"],
                "activity_amount": s["activity_amount"],
                "activity_unit": s.get("activity_unit"),
                "emission_factor_kg_co2e_per_unit": s[
                    "emission_factor_kg_co2e_per_unit"
                ],
                "factor_source": s["factor_source"],
                "attributed_kg_co2e": attributed,
            }
        )
    return records


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered by the spec-pinned builder before verify)
# ---------------------------------------------------------------------------


class ClimateAttributionRecompute:
    """Verifier-side primitive re-deriving the per-vendor attribution list."""

    primitive_id: str = "climate_attribution_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the attribution list from inputs/supplier_chain.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the list; the verifier's structured comparator
        compares it field-wise against the producer's claimed list.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        chain_path = bundle_dir / "inputs" / "supplier_chain.json"
        if not chain_path.is_file():
            raise FileNotFoundError(
                f"inputs/supplier_chain.json not found in bundle at {bundle_dir}"
            )
        supplier_chain = json.loads(chain_path.read_bytes())
        if not isinstance(supplier_chain, list):
            raise ValueError("inputs/supplier_chain.json must be a JSON array")
        records = compute_attribution(supplier_chain)
        return RecomputedValue(
            value=records,
            detail=f"re-derived per-vendor attribution over {len(records)} supplier(s)",
        )
