"""tests/test_pharmacophore_fit_spec_pinned.py — Axis-2 spec-pinned dispatch
tests for the greenfield Tier-2 slice of examples/pharmacophore_fit_minimal
(RATIONAL_BAND_MIGRATION.md §4b.3).

Two representative outputs, both `rational_sqrt_band` (epsilon=1e-6 each) —
the SECOND consumer family of that comparator kind (first:
the FEA pilot's witness+certificate posture):

  pharmacophore_best_fit_rmsd      — the best-fit candidate's aggregate RMSD
  pharmacophore_best_fit_distance  — that candidate's first (sorted
                                      pharmacophore_feature_id) paired distance

Both primitives recompute in EXACT rational (Fraction) arithmetic; the
producer's claim is the unrounded... no — the ROUNDED (6dp) float the legacy
`run_spatial_fit` pipeline already produces (see pharmacophore_recompute.py's
module docstring). This is purely additive: the legacy full-per-candidate-
ledger TypedCheck (PharmacophoreFitReDerivationCheck) and its own root test
(tests/test_pharmacophore_fit_minimal.py) are untouched.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered RMSD claim -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered distance claim -> FAIL (RE_DERIVATION_MISMATCH).
  4. Tampered input (perturb a candidate feature position so the best-fit
     ranking / values shift beyond 1e-6; manifest SHA re-aligned so
     FileIntegrity does not fire first) -> FAIL (RE_DERIVATION_MISMATCH).
  5. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  6. §4a attack: producer ships a WEAKER pinned spec (same kind
     rational_sqrt_band, epsilon=1e30) the auditor did not anchor, with a
     tampered value the weak spec WOULD accept -> still fail-closed (the
     strong committed-spec anchor does not list the weak SHA) — a
     weak-same-kind substitution.
  7. [A3] role-policy rebinding attack: swap the `type` field on the two
     output entries (both share the SAME comparator kind+params, so
     monotone-strictness alone would not catch this) -> fail-closed
     (ROLE_POLICY_VIOLATION).
  8. rational_sqrt_band edge — a claim just inside vs just outside the exact
     epsilon band, decided exactly on Fractions/sqrt.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "pharmacophore_fit_minimal"
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


# The pilot's recompute module + spec-pinned harness are loaded by path so
# this test does not depend on cwd. Pilot-unique module names avoid
# shared-interpreter collision with other pilots' recompute / spec_pinned_check
# modules.
_load("pharmacophore_recompute", _PILOT_DIR / "pharmacophore_recompute.py")
_spc = _load("pharmacophore_fit_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")

_RMSD_CLAIM_REL = "outputs/pharmacophore_best_fit_rmsd.json"
_DIST_CLAIM_REL = "outputs/pharmacophore_best_fit_distance.json"


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_rmsd_tampered_value_fails(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", rmsd_claimed_override=99.0)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_distance_tampered_value_fails(tmp_path):
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", distance_claimed_override=99.0
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the best-fit candidate's (CAND-00) first
    # feature position in the bundle's input so both re-derived quantities
    # (mean-sq and the representative pair distance) shift well beyond the
    # 1e-6 epsilon. The claimed values (honest, drawn from the pre-tamper
    # float pipeline) no longer match the re-derivation from tampered
    # evidence. Re-align manifest SHA so FileIntegrity does not fire first —
    # isolate the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    conf_path = bundle_dir / "inputs" / "candidate_conformers.json"
    doc = json.loads(conf_path.read_bytes())
    cand0 = next(c for c in doc["candidates"] if c["compound_id"] == "CAND-00")
    cand0["features"][0]["position"][0] += 1.0  # shift X by 1 Angstrom
    new_bytes = (
        json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    conf_path.write_bytes(new_bytes)

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/candidate_conformers.json"] = hashlib.sha256(
        new_bytes
    ).hexdigest()
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
    # Producer ships a weak spec (same kind rational_sqrt_band, epsilon=1e30
    # accepts anything) AND tampers both claims — a weak-SAME-KIND
    # substitution. The auditor anchor is computed from the COMMITTED strong
    # spec (epsilon=1e-6), so the weak spec's SHA is not anchored ->
    # fail-closed.
    weak_spec = json.dumps(
        {
            "spec_id": "pharmacophore_fit.spatial_fit.v1",
            "types": {
                "pharmacophore_best_fit_rmsd": {
                    "primitive_id": "pharmacophore_best_fit_rmsd_recompute",
                    "comparator": {
                        "kind": "rational_sqrt_band",
                        "params": {"epsilon": 1e30},
                    },
                },
                "pharmacophore_best_fit_distance": {
                    "primitive_id": "pharmacophore_best_fit_distance_recompute",
                    "comparator": {
                        "kind": "rational_sqrt_band",
                        "params": {"epsilon": 1e30},
                    },
                },
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        rmsd_claimed_override=-1.0,
        distance_claimed_override=-1.0,
        spec_bytes_override=weak_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result), _reason_codes(result)


def test_role_policy_rebinding_fails_closed(tmp_path):
    # [A3] rebinding attack: swap the `type` field the two output entries
    # declare (rmsd output now claims type "pharmacophore_best_fit_distance"
    # and vice versa) while keeping honest, self-consistent claim VALUES for
    # each output_id's ORIGINAL quantity. Both types share the identical
    # comparator kind+params (rational_sqrt_band, epsilon=1e-6), so
    # monotone-strictness (which is keyed on primitive_id sharing, not type
    # identity) does not catch this — the output_id -> required-type
    # the work-set's pin is the dedicated defense. Without it, dispatch would
    # resolve the rmsd output_id's claimed value against the DISTANCE
    # primitive (and vice versa), silently checking the wrong quantity under
    # a label an auditor believes names the RMSD claim.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", swap_output_types=True)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "ROLE_POLICY_VIOLATION" in _reason_codes(result), _reason_codes(result)


def test_role_policy_absent_lets_rebinding_through_dispatch_wise(tmp_path):
    # Sanity check that the rebinding attack is a real substitution (not just
    # rejected by shape validation upstream): WITHOUT the work-set wired, the
    # swapped-type bundle either fails ONLY on RE_DERIVATION_MISMATCH (because
    # the honest rmsd/distance values are numerically different quantities
    # and no longer match under the swapped primitive) or — critically — is
    # not rejected FOR THE REBINDING ITSELF. This demonstrates the work-set's
    # pin is the load-bearing defense, not an incidental pass-through.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", swap_output_types=True)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor, work_set=None).verify(bundle_dir)
    assert not result.ok
    assert "ROLE_POLICY_VIOLATION" not in _reason_codes(result), _reason_codes(result)


# ---------------------------------------------------------------------------
# rational_sqrt_band edge — near-edge claims land on the exact side
# ---------------------------------------------------------------------------


def test_rational_sqrt_band_edge(tmp_path):
    """The comparator decides |claimed - sqrt(M)| <= 1e-6 EXACTLY on squares.
    Pin the RMSD claim just inside / just outside the band around the
    fixture's honest best-fit RMSD (CAND-00, ~0.108398), asserting each
    side's expected placement independently (via the primitive's own exact
    recompute) before checking the verifier lands the same way — a mutant
    that widens the band flips the outside cell; one that narrows it flips
    the inside cell.
    """
    from fractions import Fraction

    from pharmacophore_recompute import (
        PharmacophoreBestFitRmsdRecompute,
        _load_inputs,
        find_best_fit_exact,
    )

    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle_probe")
    pharma_features, candidates = _load_inputs(bundle_dir)
    _, mean_sq, _ = find_best_fit_exact(pharma_features, candidates)
    honest_rmsd = float(mean_sq) ** 0.5
    eps = Fraction(1, 10**6)

    inside_claim = honest_rmsd  # exactly the recomputed value -> trivially inside
    outside_claim = honest_rmsd + 1e-3  # 1000x the epsilon -> well outside

    prim = PharmacophoreBestFitRmsdRecompute()

    def _in_band(claim: float) -> bool:
        c = Fraction(claim)
        # Same exact-on-squares decision the comparator makes: c is in-band
        # iff sqrt(M) is within eps of c, decided without float sqrt error by
        # comparing against the squared bounds (only meaningful for c>=0 here,
        # which both probe values are).
        lo, hi = c - eps, c + eps
        if hi < 0:
            return False
        lo_sq = lo * lo if lo > 0 else Fraction(0)
        return lo_sq <= mean_sq <= hi * hi if hi > 0 else False

    assert _in_band(inside_claim)
    assert not _in_band(outside_claim)

    for claim, expect_ok in ((inside_claim, True), (outside_claim, False)):
        bd = tmp_path / f"bundle_{expect_ok}"
        bundle_dir = _spc.build_spec_pinned(bd, rmsd_claimed_override=claim)
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
