"""climate_emission_recompute — verifier-side Scope-3 emission re-derivation.

Axis-2 value-return form of the climate emission re-derivation (the fused
examples/climate_emission_minimal/re_derive/climate_emission_pack.py, split into
recompute + compare). The exemplar's representative output is the scalar
`total_scope3_kg_co2e`; the bound comparator is `exact` (deterministic
fixed-point arithmetic, no tolerance).

recompute(): reads inputs/supplier_chain.json, computes
round(sum(round(activity*factor, 6)), 6) in list order, and RETURNS the total.
The verifier's `exact` comparator checks it equals the producer's claimed total
(outputs/<id>.json). It does NOT compare.

Stdlib-only.
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


def compute_total(supplier_chain: list) -> float:
    """Canonical Scope-3 total: per-supplier activity*factor rounded to 6dp,
    summed in list order, total rounded to 6dp.

    VERIFIER-SIDE ONLY. The producer must NOT import this: the pilot's build
    script carries its own copy (`examples/climate_emission_minimal/
    _producer_compute.py`) so `claimed == re-derived` is a finding, not an
    identity. This docstring previously advertised the shared definition as
    drift-proofing — code that cannot drift also cannot be caught drifting
    (corrected 2026-08-29)."""
    total = 0.0
    for s in supplier_chain:
        total += round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
    return round(total, 6)


class ClimateEmissionRecompute:
    primitive_id: str = "climate_emission_recompute"
    primitive_shape: str = "scalar deterministic aggregate"
    primitive_version: str = "1"
    primitive_tier: str = "B"
    primitive_contract: str = (
        "total_scope3_kg_co2e = round(sum(round(activity_amount * "
        "emission_factor_kg_co2e_per_unit, 6) for each supplier in "
        "inputs/supplier_chain.json, in list order), 6)."
    )
    primitive_scope_limits: tuple[str, ...] = (
        "A reference implementation of a Scope-3 roll-up, not a citable "
        "emissions standard.",
        "Fixed-point summation IN LIST ORDER: a different summation order is a "
        "different value.",
        "Re-derives the arithmetic over the committed supplier chain. It does "
        "not vouch for the activity amounts or the emission factors themselves.",
    )

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        bundle_dir: Path = inputs.bundle_dir
        # Admission-bounded load (size/depth/cardinality) — gives this
        # bundle-controlled input the same discipline as manifest.json; an
        # InputInadmissible propagates → dispatch records RECOMPUTE_ERROR.
        chain = admit_json_file(bundle_dir / "inputs" / "supplier_chain.json")
        if not isinstance(chain, list):
            raise ValueError("inputs/supplier_chain.json must be a JSON array")
        total = compute_total(chain)
        return RecomputedValue(
            value=total,
            detail=f"re-derived total_scope3_kg_co2e over {len(chain)} supplier(s)",
        )


register_primitive(ClimateEmissionRecompute())
