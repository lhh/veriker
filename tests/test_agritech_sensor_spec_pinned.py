"""tests/test_agritech_sensor_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/agritech_sensor_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (a sample channel) -> FAIL (RE_DERIVATION_MISMATCH): re-derivation
     from the tampered evidence no longer agrees with the (honest) claimed value.
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a WEAKER pinned spec (epsilon=1e30) the auditor
     did not anchor, with a tampered value the weak spec WOULD accept -> still
     fail-closed (the strong committed-spec anchor does not list the weak SHA).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "agritech_sensor_minimal"
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
_load("agritech_sensor_recompute", _PILOT_DIR / "agritech_sensor_recompute.py")
_spc = _load("agritech_sensor_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a value 1.0 off the honest re-derivation.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    stream_doc = json.loads((bundle_dir / "inputs" / "sensor_stream.json").read_bytes())
    weights = json.loads((bundle_dir / "payload" / "fusion_weights.json").read_bytes())
    honest = _spc.compute_yield_score(stream_doc["samples"], weights)
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle2", claimed_override=honest + 1.0
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb a sample channel in the bundle's input. The claimed
    # value (honest) no longer matches the re-derivation from tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    stream_path = bundle_dir / "inputs" / "sensor_stream.json"
    stream_doc = json.loads(stream_path.read_bytes())
    stream_doc["samples"][0]["soil_moisture_pct"] = (
        float(stream_doc["samples"][0]["soil_moisture_pct"]) + 100.0
    )
    new_bytes = json.dumps(stream_doc, indent=2).encode("utf-8")
    stream_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    import hashlib

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/sensor_stream.json"] = hashlib.sha256(new_bytes).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")

    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


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
    # (epsilon=1e-6), so the weak spec's SHA is not anchored -> fail-closed.
    #
    # The weak spec keeps the SAME kind (rational_band) so the attack exercises a
    # weak-same-kind substitution against the migrated kind, not a kind swap —
    # otherwise this attack test would silently stop exercising rational_band.
    weak_spec = json.dumps(
        {
            "spec_id": "agritech_sensor.v1",
            "types": {
                "agritech_yield_score": {
                    "primitive_id": "agritech_sensor_recompute",
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


def test_rational_band_edge(tmp_path):
    """The comparator decides |R - c| <= 1e-6 EXACTLY on Fractions, with R the
    honest exact rational re-derived from the committed samples/weights
    (independent test-local arithmetic — recomputed here from the bundle's own
    committed bytes, not imported from the primitive's exact function). Pin one
    claim just inside the band (PASS) and one just outside
    (RE_DERIVATION_MISMATCH), each picked by exact Fraction comparison against
    Fraction(1, 10**6).
    """
    from fractions import Fraction

    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle_r")
    stream_doc = json.loads((bundle_dir / "inputs" / "sensor_stream.json").read_bytes())
    weights = json.loads((bundle_dir / "payload" / "fusion_weights.json").read_bytes())
    samples = stream_doc["samples"]
    n = len(samples)

    sum_moisture = sum(Fraction(s["soil_moisture_pct"]) for s in samples)
    sum_temp = sum(Fraction(s["soil_temp_c"]) for s in samples)
    sum_npk = sum(Fraction(s["npk_ppm"]) for s in samples)
    total_rain = sum(Fraction(s["rainfall_mm"]) for s in samples)
    R = (
        Fraction(weights["w_soil_moisture"]) * (sum_moisture / n)
        + Fraction(weights["w_soil_temp"]) * (sum_temp / n)
        + Fraction(weights["w_npk"]) * (sum_npk / n)
        + Fraction(weights["w_rainfall"]) * total_rain
        + Fraction(weights["bias"])
    )
    eps = Fraction(1, 10**6)

    # Search outward from R in 1e-6 float steps for a claim just inside and
    # just outside the band, verified by EXACT Fraction comparison (not by
    # assuming float step size lines up with the exact rational band).
    inside_claim = outside_claim = None
    base = float(R)
    for k in range(1, 2000):
        cand = round(base + k * 1e-7, 7)
        d = abs(Fraction(cand) - R)
        if inside_claim is None and d <= eps:
            inside_claim = cand
        if outside_claim is None and d > eps:
            outside_claim = cand
        if inside_claim is not None and outside_claim is not None:
            break
    assert inside_claim is not None and outside_claim is not None
    assert abs(Fraction(inside_claim) - R) <= eps
    assert abs(Fraction(outside_claim) - R) > eps

    for claim, expect_ok in ((inside_claim, True), (outside_claim, False)):
        b_dir = _spc.build_spec_pinned(
            tmp_path / f"bundle_{expect_ok}", claimed_override=claim
        )
        anchor = _spc.anchor_from_committed_spec()
        result = _spc.make_verifier(anchor).verify(b_dir)
        if expect_ok:
            assert result.ok, [
                (f.check_name, f.reason_code, f.detail) for f in result.failures
            ]
        else:
            assert not result.ok
            assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(
                result
            )
