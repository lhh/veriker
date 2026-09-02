"""tests/test_dc_emissions_mrv_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/dc_emissions_mrv_minimal.

rational_band migration (2026-07-21): the auditor-pinned comparator moved
scalar_epsilon{1e-6} -> rational_band{1e-6}. dc_emissions_mrv is the wave's
INTERMEDIATE-ROUNDING pilot: the primitive's per-material
round(quantity*emission_factor, 6) is information-bearing (not cosmetic), so
the exact recompute reproduces it EXACTLY in rational arithmetic (Fraction
round-half-even), summed with no terminal re-round (see
dc_emissions_mrv_recompute.compute_embodied_total_exact). Epsilon stays
1e-6, now covering only the producer's float pipeline noise (including the
terminal round) plus the single-grain float-boundary-slip residual
documented in the spec.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (a material EF) -> FAIL (RE_DERIVATION_MISMATCH): re-derivation
     from the tampered evidence no longer agrees with the (honest) claimed value.
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a WEAKER pinned spec (epsilon=1e30, SAME kind
     rational_band — a weak-same-kind substitution) the auditor did not
     anchor, with a tampered value the weak spec WOULD accept -> still
     fail-closed (the strong committed-spec anchor does not list the weak SHA).
  6. rational_band edge: claims just inside/outside the exact band on the
     committed fixture (whose per-material products happen to be exact
     integers, so intermediate rounding is a no-op there).
  7. Intermediate-rounding semantics: on a variant material set whose
     per-material products carry >6dp, the primitive's R is the sum of the
     EXACTLY-rounded per-material terms, not the unrounded exact sum — the
     honest procedure-correct claim PASSes; a claim built from the unrounded
     sum (which differs from R by more than epsilon here) REDs.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from fractions import Fraction
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "dc_emissions_mrv_minimal"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# The pilot's recompute module + spec-pinned harness are loaded by path so this
# test does not depend on cwd.
_load("dc_emissions_mrv_recompute", _PILOT_DIR / "dc_emissions_mrv_recompute.py")
_spc = _load("dc_emissions_mrv_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a value 1.0 kg off the honest re-derivation.
    materials = json.loads(
        (
            _PILOT_DIR.parent
            / "dc_emissions_mrv_minimal"
            / "inputs"
            / "embodied_carbon_inventory.json"
        ).read_bytes()
    )
    honest = _spc.compute_embodied_total(materials)
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=honest + 1.0
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb a material EF in the bundle's input. The claimed
    # value (honest) no longer matches the re-derivation from tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    inv_path = bundle_dir / "inputs" / "embodied_carbon_inventory.json"
    materials = json.loads(inv_path.read_bytes())
    materials[0]["emission_factor_kg_co2e_per_unit"] = (
        float(materials[0]["emission_factor_kg_co2e_per_unit"]) + 100.0
    )
    new_bytes = json.dumps(materials, indent=2).encode("utf-8")
    inv_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    import hashlib

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/embodied_carbon_inventory.json"] = hashlib.sha256(
        new_bytes
    ).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")

    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def _rehash_manifest_entry(bundle_dir: Path, rel_path: str, data: bytes) -> None:
    """Write `data` to bundle_dir/rel_path and re-mint its manifest.files SHA so
    FileIntegrityManySmall does not fire before re-derivation dispatch runs."""
    (bundle_dir / rel_path).write_bytes(data)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"][rel_path] = hashlib.sha256(data).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")


def test_no_anchor_fails_closed(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    result = _spc.make_verifier(anchor=None).verify(bundle_dir)
    assert not result.ok
    # AnchorNotSupplied, split out of AnchorViolation (auditor-entry ADR): "no
    # auditor anchor was supplied" is the VERIFIER's own incapacity, so the
    # verdict is a clean-ERROR (could-not-conclude) leg and NEVER a REJECT —
    # nothing was shown about the bundle. The artifact-side anchor failure (a
    # spec whose SHA the anchor does not list) keeps AnchorViolation + REJECT;
    # see the substituted/weakened-spec test in this file.
    assert result.state.value == "ERROR", (result.state, _reason_codes(result))
    _anchor = [
        r for r in result.reasons if r.check_name == "spec_pinned_dispatch:anchor"
    ]
    assert [r.code for r in _anchor] == ["VERIFIER_INCOMPLETE"], [
        (r.check_name, r.code) for r in result.reasons
    ]
    assert "no auditor SpecAnchor was supplied" in _anchor[0].detail, _anchor[0].detail


def test_weak_spec_substitution_fails_closed(tmp_path):
    # Producer ships a weak spec (epsilon=1e30 accepts anything) AND tampers the
    # claimed value. The auditor anchor is computed from the COMMITTED strong spec
    # (rational_band, epsilon=1e-6), so the weak spec's SHA is not anchored ->
    # fail-closed. The weak spec keeps the SAME kind (rational_band) so this
    # exercises a weak-same-kind substitution, not a kind swap (mirrors
    # the similarity-repro pilot's post-migration attack fixture).
    weak_spec = json.dumps(
        {
            "spec_id": "dc_emissions_mrv.v1",
            "types": {
                "dc_embodied_carbon_total": {
                    "primitive_id": "dc_emissions_mrv_embodied_recompute",
                    "comparator": {
                        "kind": "rational_band",
                        "params": {"epsilon": 1e30},
                    },
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=-1.0,
        spec_bytes_override=weak_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes


# ---------------------------------------------------------------------------
# Test 6: rational_band edge — near-edge claims land on the exact side
# ---------------------------------------------------------------------------


def _round_half_even_frac_local(x: Fraction, ndigits: int = 6) -> Fraction:
    """Test-LOCAL, independently-written mirror of the primitive's
    round-half-even helper (not imported from dc_emissions_mrv_recompute) —
    an independent re-implementation catches a primitive-side bug rather
    than merely echoing it."""
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


def _exact_total_local(materials: list) -> Fraction:
    """Test-local mirror of compute_embodied_total_exact: per-material exact
    round-half-even at 6dp, summed with no terminal re-round."""
    total = Fraction(0)
    for m in materials:
        q = Fraction(float(m["quantity"]))
        ef = Fraction(float(m["emission_factor_kg_co2e_per_unit"]))
        total += _round_half_even_frac_local(q * ef, 6)
    return total


def test_rational_band_edge(tmp_path):
    """The migrated comparator decides |R - c| <= 1e-6 EXACTLY on Fractions.
    On the committed fixture, every material's quantity*EF product is an
    exact integer (2500*8240, 50000*220, 800*1450, 8000*1100, 12000*1000 —
    all whole numbers), so the per-material round is a no-op here and
    R = 53,560,000 exactly. Pin one claim just inside the band (PASS) and
    one just outside (RE_DERIVATION_MISMATCH), computed independently via
    the test-local exact round-half-even mirror above — a mutant that
    widens the band flips the outside cell; one that narrows it flips the
    inside cell.
    """
    materials = json.loads(
        (_PILOT_DIR / "inputs" / "embodied_carbon_inventory.json").read_bytes()
    )
    R = _exact_total_local(materials)
    assert R == Fraction(53_560_000, 1)  # pins the exact fixture value
    eps = Fraction(1, 10**6)
    inside_claim = 53_560_000.0000005  # |Fraction(inside_claim) - R| < 1e-6
    outside_claim = 53_560_000.000002  # |Fraction(outside_claim) - R| > 1e-6
    assert abs(Fraction(inside_claim) - R) <= eps
    assert abs(Fraction(outside_claim) - R) > eps

    for claim, expect_ok in ((inside_claim, True), (outside_claim, False)):
        bundle_dir = _spc.build_spec_pinned(tmp_path / f"bundle_{expect_ok}")
        claim_bytes = json.dumps({"value": claim}, indent=2).encode("utf-8")
        _rehash_manifest_entry(
            bundle_dir, "outputs/dc_embodied_carbon_total.json", claim_bytes
        )
        anchor = _spc.anchor_from_committed_spec()
        result = _spc.make_verifier(anchor).verify(bundle_dir)
        if expect_ok:
            assert result.ok, [
                (f.check_name, f.reason_code, f.detail) for f in result.failures
            ]
        else:
            assert not result.ok
            assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(
                result
            )


# ---------------------------------------------------------------------------
# Test 7: intermediate-rounding semantics — the per-material round is
# information-bearing, not cosmetic
# ---------------------------------------------------------------------------
#
# The committed fixture's products are all exact integers (see test 6), so it
# cannot exercise the intermediate-rounding path: >6dp products never arise.
# This cell mints a variant materials file (re-hashing manifest.files) whose
# products DO carry >6dp, so the per-material round changes the result by
# more than epsilon relative to an (incorrect) unrounded raw sum.


_VARIANT_MATERIALS = [
    {"quantity": 1.0, "emission_factor_kg_co2e_per_unit": 10.00000051},
    {"quantity": 1.0, "emission_factor_kg_co2e_per_unit": 20.00000051},
    {"quantity": 1.0, "emission_factor_kg_co2e_per_unit": 30.00000051},
]


def test_intermediate_rounding_is_information_bearing(tmp_path):
    """On _VARIANT_MATERIALS, each product (e.g. 1.0*10.00000051) sits just
    past the 6dp half-grain boundary (fractional remainder ~0.51 grains), so
    the per-material round(., 6) moves each term up by ~4.9e-7; summed over
    3 materials the correct (per-material-rounded) total R differs from the
    unrounded raw sum by ~1.47e-6 > epsilon=1e-6 — well past the single-grain
    float-boundary-slip residual the spec documents, so this is a genuine
    procedure difference, not sub-epsilon noise.

    Cell (a): the honest, procedure-correct claim (computed by the
    byte-untouched float helper compute_embodied_total, which itself
    performs the per-material round) -> PASS.
    Cell (b): a claim computed by skipping the per-material round (the
    unrounded raw sum) -> RE_DERIVATION_MISMATCH, because the primitive's R
    is the per-material-rounded sum, not the raw sum.
    """
    raw_sum = sum(
        Fraction(float(m["quantity"]))
        * Fraction(float(m["emission_factor_kg_co2e_per_unit"]))
        for m in _VARIANT_MATERIALS
    )
    R = _exact_total_local(_VARIANT_MATERIALS)
    assert abs(raw_sum - R) > Fraction(1, 10**6), (
        "fixture does not exercise >epsilon intermediate-rounding delta"
    )

    honest_claim = _spc.compute_embodied_total(_VARIANT_MATERIALS)
    assert abs(Fraction(honest_claim) - R) <= Fraction(1, 10**6)
    wrong_claim = float(raw_sum)
    assert abs(Fraction(wrong_claim) - R) > Fraction(1, 10**6)

    materials_bytes = json.dumps(_VARIANT_MATERIALS, indent=2).encode("utf-8")

    # Cell (a): honest procedure-correct claim -> PASS.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle_honest")
    _rehash_manifest_entry(
        bundle_dir, "inputs/embodied_carbon_inventory.json", materials_bytes
    )
    _rehash_manifest_entry(
        bundle_dir,
        "outputs/dc_embodied_carbon_total.json",
        json.dumps({"value": honest_claim}, indent=2).encode("utf-8"),
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]

    # Cell (b): claim built from the unrounded raw sum (skips the
    # information-bearing per-material round) -> RE_DERIVATION_MISMATCH.
    bundle_dir2 = _spc.build_spec_pinned(tmp_path / "bundle_wrong")
    _rehash_manifest_entry(
        bundle_dir2, "inputs/embodied_carbon_inventory.json", materials_bytes
    )
    _rehash_manifest_entry(
        bundle_dir2,
        "outputs/dc_embodied_carbon_total.json",
        json.dumps({"value": wrong_claim}, indent=2).encode("utf-8"),
    )
    result2 = _spc.make_verifier(anchor).verify(bundle_dir2)
    assert not result2.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result2), _reason_codes(result2)
