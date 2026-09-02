"""tests/test_iso42001_impact_fairness_minimal.py — tamper + §4a attack tests.

ISO/IEC 42001 A.5 disparate-impact re-derivation. Surfaces:

  0. Unit: compute_disparate_impact_ratio on a known input.
  1. Happy path -> PASS.
  2. Metric mutation: inflate the disclosed ratio toward 0.8 (cosmetic
     compliance) -> RE_DERIVATION_MISMATCH.
  3. Outcomes tamper: flip a group_c rejection to approval (raises group_c rate)
     without updating manifest.files -> BAD_FILE_SHA + RE_DERIVATION_MISMATCH.
  4. Weaker-spec substitution -> AnchorViolation.
  5. rational_band edge — near-edge claims land on the exact side.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_TEST_DIR = Path(__file__).resolve().parent
_PILOT_DIR = _TEST_DIR.parent
_PKG_ROOT = _PILOT_DIR.parents[1]

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
import iso42001_fairness_recompute as _prim_mod  # noqa: E402

register_primitive(_prim_mod.Iso42001DisparateImpactRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "iso42001_fairness.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_CLAIM_REL = "outputs/disparate_impact_ratio.json"


def _build(out_dir: Path) -> None:
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _anchor() -> SpecAnchor:
    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: hashlib.sha256(raw).hexdigest()})


def _verifier(anchor: SpecAnchor | None = None) -> BundleVerifier:
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor if anchor is not None else _anchor(),
    )


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_compute_dir_known_value():
    recs = (
        [{"group": "g1", "outcome": 1}] * 3
        + [{"group": "g1", "outcome": 0}] * 1  # g1 rate = 0.75
        + [{"group": "g2", "outcome": 1}] * 1
        + [{"group": "g2", "outcome": 0}] * 3  # g2 rate = 0.25
    )
    # DIR = min(0.75, 0.25) / max = 0.25 / 0.75 = 1/3
    assert abs(_prim_mod.compute_disparate_impact_ratio(recs) - (1.0 / 3.0)) < 1e-12


def test_honest_pass(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_metric_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    p = bundle_dir / _CLAIM_REL
    claimed = float(json.loads(p.read_bytes())["value"])
    nb = json.dumps({"value": claimed + 0.25}, indent=2).encode(
        "utf-8"
    )  # inflate toward 0.8
    p.write_bytes(nb)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][_CLAIM_REL] = hashlib.sha256(nb).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result)


def test_outcomes_tamper_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    op = bundle_dir / "inputs" / "outcomes.json"
    doc = json.loads(op.read_bytes())
    # Flip a group_c rejection to approval -> group_c rate rises -> DIR changes.
    for r in doc["outcomes"]:
        if r["group"] == "group_c" and r["outcome"] == 0:
            r["outcome"] = 1
            break
    op.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    # Do NOT update manifest.files -> BAD_FILE_SHA.
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    rc = _reason_codes(result)
    # The `or "plugin_failed"` arm was removed 2026-08-30: the verifier now
    # propagates a failing plugin's own reason_code, so that arm can no
    # longer match a real plugin failure -- and while it did, it would
    # have accepted a failure from ANY check, not this one.
    assert "bad_file_sha" in rc, rc
    assert "RE_DERIVATION_MISMATCH" in rc, rc


def test_weak_spec_substitution_fails(tmp_path):
    """Producer ships a 'weaker' spec keeping the SAME kind (rational_band) but
    with epsilon=1e30 (would accept any claimed value). The auditor anchor is
    still derived from the ORIGINAL committed spec (epsilon=1e-9); the weak
    spec has a different SHA -> not in anchor -> AnchorViolation fail-closed
    (§4a.1). Keeping rational_band exercises a weak-same-kind substitution,
    not a kind swap."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    weak = json.dumps(
        {
            "spec_id": "iso42001.impact.fairness.v1",
            "types": {
                "disparate_impact_ratio": {
                    "primitive_id": "iso42001_disparate_impact_recompute",
                    "comparator": {
                        "kind": "rational_band",
                        "params": {"epsilon": 1e30},
                    },
                }
            },
        }
    ).encode("utf-8")
    nb = json.dumps({"value": 1.0}, indent=2).encode("utf-8")  # "perfectly fair"
    (bundle_dir / _CLAIM_REL).write_bytes(nb)
    (bundle_dir / "spec" / "iso42001_fairness.spec.json").write_bytes(weak)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][_CLAIM_REL] = hashlib.sha256(nb).hexdigest()
    m["spec_files"]["iso42001_fairness.spec.json"] = hashlib.sha256(weak).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier(_anchor()).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 5. rational_band edge — near-edge claims land on the exact side
# ---------------------------------------------------------------------------


def test_rational_band_edge(tmp_path):
    """The migrated comparator decides |R - c| <= 1e-9 EXACTLY on Fractions,
    with R = 1/2 (min group rate 3/8 over max group rate 3/4, from the frozen
    fixture: group_a 6/8, group_b 4/8, group_c 3/8). Pin one claim just inside
    the band (PASS) and one just outside (RE_DERIVATION_MISMATCH), asserting
    each side's expected placement with the same exact arithmetic the
    comparator uses — a mutant that widens the band flips the outside cell;
    one that narrows it flips the inside cell.
    """
    from fractions import Fraction

    R = Fraction(1, 2)
    eps = Fraction(1, 10**9)
    inside_claim = 0.500000001  # |Fraction(inside_claim) - R| ~ 1.0e-9 <= 1e-9
    outside_claim = 0.500000002  # |Fraction(outside_claim) - R| ~ 2.0e-9 > 1e-9
    assert abs(Fraction(inside_claim) - R) <= eps
    assert abs(Fraction(outside_claim) - R) > eps

    for claim, expect_ok in ((inside_claim, True), (outside_claim, False)):
        bundle_dir = tmp_path / f"bundle_{expect_ok}"
        _build(bundle_dir)
        nb = json.dumps({"value": claim}, indent=2).encode("utf-8")
        (bundle_dir / _CLAIM_REL).write_bytes(nb)
        mp = bundle_dir / "manifest.json"
        m = json.loads(mp.read_bytes())
        m["files"][_CLAIM_REL] = hashlib.sha256(nb).hexdigest()
        mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

        result = _verifier().verify(bundle_dir)
        if expect_ok:
            assert result.ok, [
                (f.check_name, f.reason_code, f.detail) for f in result.failures
            ]
        else:
            assert not result.ok
            assert "RE_DERIVATION_MISMATCH" in _reason_codes(result)
