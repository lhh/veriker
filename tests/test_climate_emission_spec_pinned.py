"""tests/test_climate_emission_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/climate_emission_minimal.

This pilot's representative output is the per-vendor Scope-3 emission attribution
LIST (records of exactly {vendor_id, tier, activity_amount, activity_unit,
emission_factor_kg_co2e_per_unit, factor_source, attributed_kg_co2e}), compared
with the generic `structured` comparator over the allowlisted
climate_attribution_v1 schema. It uses a NEW in-dir primitive
("climate_attribution_recompute") that does NOT collide with the central
"climate_emission_recompute" (scalar total under exact); the central
spec_pinned_demo / test_spec_pinned_dispatch are untouched.

FIX-E (claim-set coverage sweep): activity_amount, activity_unit,
emission_factor_kg_co2e_per_unit, and factor_source were added to the schema
(originally only vendor_id/tier/attributed_kg_co2e) — attributed_kg_co2e is a
single product of activity_amount * emission_factor_kg_co2e_per_unit, so
binding only the product let a claimed record swap in a different
factorization of the same product plus a fictitious factor_source label,
undetected. See test_factor_source_swap_fails.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed list (alter one record's attributed_kg_co2e) -> FAIL
     (RE_DERIVATION_MISMATCH).
  3. Claimed record swaps (activity_amount, emission_factor_kg_co2e_per_unit)
     for a different factorization of the SAME product + relabels
     factor_source -> FAIL (RE_DERIVATION_MISMATCH, field-bound to committed
     input — see test_factor_source_swap_fails).
  4. Tampered input (mutate a supplier activity_amount so a record's attributed
     value differs; re-align the manifest SHA) -> FAIL (RE_DERIVATION_MISMATCH):
     re-derivation from the tampered evidence no longer agrees with the honest
     claimed list.
  5. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  6. §4a attack: producer ships a substituted spec (a weaker `exact`-on-total
     binding the auditor did not anchor) -> still fail-closed (the committed-spec
     anchor does not list the substituted SHA).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"
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
_load("climate_attribution_recompute", _PILOT_DIR / "climate_attribution_recompute.py")
_spc = _load("climate_emission_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a list where ONE record's attributed_kg_co2e is altered.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    supplier_chain = json.loads(
        (bundle_dir / "inputs" / "supplier_chain.json").read_bytes()
    )
    honest = _spc.compute_attribution(supplier_chain)
    tampered = copy.deepcopy(honest)
    tampered[0]["attributed_kg_co2e"] = float(tampered[0]["attributed_kg_co2e"]) + 1.0
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle2", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_factor_source_swap_fails(tmp_path):
    """FIX-E (claim-set coverage sweep): the producer claims a DIFFERENT
    factorization of the same product (double activity_amount, halve
    emission_factor_kg_co2e_per_unit) for one vendor, plus a fictitious
    factor_source label, while attributed_kg_co2e (the product) is
    unchanged. Before FIX-E, climate_attribution_v1 only bound
    {vendor_id, tier, attributed_kg_co2e}, so this went undetected — the
    single product cannot reveal its two factors or a mislabeled
    factor_source. Strongest producer: the swap preserves the checked
    product exactly."""
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    supplier_chain = json.loads(
        (bundle_dir / "inputs" / "supplier_chain.json").read_bytes()
    )
    honest = _spc.compute_attribution(supplier_chain)
    tampered = copy.deepcopy(honest)
    old_activity = float(tampered[0]["activity_amount"])
    old_factor = float(tampered[0]["emission_factor_kg_co2e_per_unit"])
    product = round(old_activity * old_factor, 6)
    new_activity = old_activity * 2.0
    new_factor = round(product / new_activity, 10)
    tampered[0]["activity_amount"] = new_activity
    tampered[0]["emission_factor_kg_co2e_per_unit"] = new_factor
    tampered[0]["factor_source"] = "synthetic-EF-v1.0/FAKE-low-carbon"
    tampered[0]["attributed_kg_co2e"] = round(new_activity * new_factor, 6)
    assert tampered[0]["attributed_kg_co2e"] == round(old_activity * old_factor, 6), (
        "test setup bug: the swap must preserve the checked product"
    )

    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle2", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
    combined = " ".join(f.detail for f in result.failures)
    assert "activity_amount" in combined, combined


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb a supplier's activity_amount in the bundle's
    # input. The claimed list (honest) no longer matches the re-derivation from
    # the tampered evidence (that record's attributed value differs).
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    supplier_chain = json.loads(chain_path.read_bytes())
    supplier_chain[0]["activity_amount"] = (
        float(supplier_chain[0]["activity_amount"]) + 1000.0
    )
    new_bytes = json.dumps(supplier_chain, indent=2).encode("utf-8")
    chain_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/supplier_chain.json"] = hashlib.sha256(new_bytes).hexdigest()
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


def test_substituted_spec_fails_closed(tmp_path):
    # Producer ships a SUBSTITUTED spec (a different binding the auditor never
    # anchored) AND tampers the claimed value. The auditor anchor is computed
    # from the COMMITTED spec bytes, so the substituted spec's SHA is not
    # anchored -> fail-closed regardless of what the substitute would accept.
    substituted_spec = json.dumps(
        {
            "spec_id": "climate_emission.v1",
            "types": {
                "climate_attribution": {
                    "primitive_id": "climate_attribution_recompute",
                    "comparator": {
                        "kind": "structured",
                        "params": {"schema": "climate_attribution_v1"},
                    },
                }
            },
            "description": "attacker-substituted spec (auditor never anchored this SHA)",
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result), _reason_codes(result)
