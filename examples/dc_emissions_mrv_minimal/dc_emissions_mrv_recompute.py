"""dc_emissions_mrv_recompute.py — verifier-side embodied-carbon re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the dc_emissions_mrv pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by
verify.py / the spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    total_embodied_kg_co2e = round(sum over materials of
        round(quantity * emission_factor_kg_co2e_per_unit, 6), 6)

over inputs/embodied_carbon_inventory.json. The aggregation rule (per-row 6dp
round, summed in list order, total 6dp round) is FIXED in this primitive — the
primitive_id ("dc_emissions_mrv_embodied_recompute") IS the rule. The auditor's
SHA-pinned spec binds the output type "dc_embodied_carbon_total" to this
primitive_id and to a rational_band comparator; a producer cannot weaken the
aggregation without changing the primitive_id, which the anchor would reject.

INTERMEDIATE ROUNDING (rational_band migration, dc_emissions_mrv is the
wave's intermediate-rounding pilot): the per-material `round(q*ef, 6)` is
INFORMATION-BEARING — q*ef can carry more than 6 significant decimal digits,
so the round is part of the claim's declared procedure, not cosmetic noise.
The exact recompute below reproduces it EXACTLY in rational arithmetic: for
each material it takes the exact product Fraction(float(q)) * Fraction(float(ef))
(the exact product of the two committed binary64 values — Fraction(float) is
always exact) and rounds that exact rational to the nearest multiple of
10^-6 using ROUND-HALF-EVEN (matching Python float `round`'s banker's
rounding), then sums those 6dp-grid rationals exactly. The terminal
`round(total, 6)` in the float helper below is a NO-OP on the exact side (a
sum of 6dp-grid rationals is already on the 6dp grid), so the exact path
does NOT apply a second round after summing.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_embodied_total() standalone.
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_embodied_total(materials: list) -> float:
    """Canonical embodied-carbon total. Mirrors the legacy pack's
    _compute_embodied_carbon: per-material round(quantity*EF, 6), summed in list
    order, total rounded to 6dp. Builder and verifier share this ONE definition
    so the honest claimed total and the re-derivation cannot drift.

    Raises ValueError on empty input.
    """
    if not materials:
        raise ValueError("embodied_carbon_inventory is empty — cannot compute total")
    total = 0.0
    for m in materials:
        total += round(
            float(m["quantity"]) * float(m["emission_factor_kg_co2e_per_unit"]),
            6,
        )
    return round(total, 6)


# ---------------------------------------------------------------------------
# Exact rational recompute (rational_band migration) — NEW code, byte-separate
# from compute_embodied_total above. The claim is ALWAYS derived from the
# float helper; this path only feeds the verifier's recompute() below. No
# float anywhere in this function or its helper.
# ---------------------------------------------------------------------------


def _round_half_even_frac(x: Fraction, ndigits: int = 6) -> Fraction:
    """Round a Fraction to the nearest multiple of 10^-ndigits, ties-to-even
    (matching Python float `round`'s banker's rounding), computed exactly —
    no float anywhere. scale*x = num/den (den > 0); floor-divmod gives the
    unique 0 <= r < den remainder, so r/den is exactly the fractional part
    and 2*r vs den decides which side of .5 (or the tie) it falls on. This
    also matches Python's `round()` sign behavior for negative x, since
    Python's divmod floors toward -infinity for a positive divisor."""
    scale = Fraction(10) ** ndigits
    scaled = x * scale
    num, den = scaled.numerator, scaled.denominator
    q, r = divmod(num, den)
    twice_r = 2 * r
    if twice_r < den:
        rounded = q
    elif twice_r > den:
        rounded = q + 1
    else:
        rounded = q if q % 2 == 0 else q + 1
    return Fraction(rounded, 1) / scale


def _exact_material_term(m: dict) -> Fraction:
    """Exact 6dp-rounded rational for one material's quantity*EF product —
    the rational mirror of the float helper's per-material
    `round(quantity * emission_factor, 6)`."""
    q = Fraction(float(m["quantity"]))
    ef = Fraction(float(m["emission_factor_kg_co2e_per_unit"]))
    return _round_half_even_frac(q * ef, 6)


def compute_embodied_total_exact(materials: list) -> Fraction:
    """Exact-rational mirror of compute_embodied_total: sum of the exactly
    6dp-rounded per-material products. No terminal round is applied — the
    sum of 6dp-grid rationals is already on the 6dp grid, so the float
    helper's terminal round(total, 6) is a no-op on this side.

    Raises ValueError on empty input (matching compute_embodied_total).
    """
    if not materials:
        raise ValueError("embodied_carbon_inventory is empty — cannot compute total")
    total = Fraction(0)
    for m in materials:
        total += _exact_material_term(m)
    return total


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


class DcEmissionsMrvEmbodiedRecompute:
    """Verifier-side primitive for re-deriving the total embodied carbon."""

    primitive_id: str = "dc_emissions_mrv_embodied_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute total embodied carbon from inputs/embodied_carbon_inventory.json
        as an EXACT rational (rational_band migration) — no float on this path.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying {"kind": "rational", "num", "den"}; the
        verifier's rational_band comparator decides |R - claim| <= epsilon
        exactly on Fractions. The claim (compute_embodied_total, the float
        helper above) is UNCHANGED and is never used to derive this value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        inv_path = bundle_dir / "inputs" / "embodied_carbon_inventory.json"
        if not inv_path.is_file():
            raise FileNotFoundError(
                f"inputs/embodied_carbon_inventory.json not found in bundle at {bundle_dir}"
            )
        materials = json.loads(inv_path.read_bytes())
        if not isinstance(materials, list):
            raise ValueError(
                "inputs/embodied_carbon_inventory.json must be a JSON array"
            )
        R = compute_embodied_total_exact(materials)
        return RecomputedValue(
            value={"kind": "rational", "num": R.numerator, "den": R.denominator},
            detail=(
                f"re-derived total embodied carbon over {len(materials)} "
                f"material(s); exact R={R.numerator}/{R.denominator} "
                f"(~{float(R):.6f})"
            ),
        )
