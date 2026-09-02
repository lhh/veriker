"""tests/test_iso42001_external_reporting_minimal.py — tamper + §4a attack tests.

ISO/IEC 42001 A.8 external-reporting reconciliation. Two disclosed figures, two
comparator kinds (exact count + rational_band rate). Surfaces:

  0. Unit: the two compute fns on a known input.
  1. Happy path -> PASS.
  2. Count mutation (exact comparator): bump disclosed count by +1 ->
     RE_DERIVATION_MISMATCH.
  3. Rate mutation (rational_band): nudge disclosed rate by +0.5 ->
     RE_DERIVATION_MISMATCH.
  4. Log tamper: flip a human_reviewed flag without updating manifest.files ->
     BAD_FILE_SHA + RE_DERIVATION_MISMATCH (rate changes).
  5. Weaker-spec substitution -> AnchorViolation.
  6. rational_band edge — near-edge claims land on the exact side.
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
import iso42001_external_reporting_recompute as _prim_mod  # noqa: E402

register_primitive(_prim_mod.Iso42001DecisionCountRecompute())
register_primitive(_prim_mod.Iso42001OversightRateRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "iso42001_external_reporting.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_COUNT_REL = "outputs/disclosed_automated_decision_count.json"
_RATE_REL = "outputs/disclosed_human_oversight_rate_pct.json"


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


def _retarget_claim(bundle_dir: Path, rel: str, new_value) -> None:
    """Overwrite a claimed-value file and re-align its manifest SHA so only the
    re-derivation comparison fires (not BAD_FILE_SHA)."""
    nb = json.dumps({"value": new_value}, indent=2).encode("utf-8")
    (bundle_dir / rel).write_bytes(nb)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256(nb).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


# ---------------------------------------------------------------------------
# 0. Unit
# ---------------------------------------------------------------------------


def test_compute_fns_known_values():
    recs = [
        {"automated": True, "human_reviewed": True},
        {"automated": True, "human_reviewed": False},
        {"automated": True, "human_reviewed": True},
        {"automated": False, "human_reviewed": True},
    ]
    assert _prim_mod.compute_automated_decision_count(recs) == 3
    # 2 of 3 automated reviewed -> 66.66..%
    assert (
        abs(_prim_mod.compute_human_oversight_rate_pct(recs) - (100.0 * 2 / 3)) < 1e-12
    )


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_honest_pass(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# ---------------------------------------------------------------------------
# 2. Count mutation (exact comparator)
# ---------------------------------------------------------------------------


def test_count_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    claimed = json.loads((bundle_dir / _COUNT_REL).read_bytes())["value"]
    _retarget_claim(bundle_dir, _COUNT_REL, int(claimed) + 1)  # over-disclose by 1
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 3. Rate mutation (rational_band comparator)
# ---------------------------------------------------------------------------


def test_rate_mutation_fails(tmp_path):
    """Recompute produces the honest exact rational; rational_band comparator
    rejects the inflated claimed value -> RE_DERIVATION_MISMATCH."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    claimed = json.loads((bundle_dir / _RATE_REL).read_bytes())["value"]
    _retarget_claim(bundle_dir, _RATE_REL, float(claimed) + 0.5)  # inflate oversight
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 4. Log tamper
# ---------------------------------------------------------------------------


def test_log_tamper_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    log = bundle_dir / "inputs" / "decision_log.json"
    doc = json.loads(log.read_bytes())
    # Flip d02 (automated, not reviewed) to reviewed -> oversight rate rises.
    for r in doc["decisions"]:
        if r["decision_id"] == "d02":
            r["human_reviewed"] = True
            break
    log.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
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


# ---------------------------------------------------------------------------
# 5. Weaker-spec substitution -> AnchorViolation
# ---------------------------------------------------------------------------


def test_weak_spec_substitution_fails(tmp_path):
    """Producer ships a 'weaker' spec keeping the SAME kind (rational_band) but
    with epsilon=1e30 (would accept any claimed value). The auditor anchor is
    still derived from the ORIGINAL committed spec (epsilon=1e-9); the weak
    spec has a different SHA -> not in anchor -> AnchorViolation fail-closed
    (§4a.1). The weak spec keeps rational_band so this exercises a
    weak-same-kind substitution, not a kind swap; the count stays exact."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    weak = json.dumps(
        {
            "spec_id": "iso42001.external_reporting.v1",
            "types": {
                # Weaken the rate to accept anything; keep count as exact.
                "disclosed_automated_decision_count": {
                    "primitive_id": "iso42001_decision_count_recompute",
                    "comparator": {"kind": "exact", "params": {}},
                },
                "disclosed_human_oversight_rate_pct": {
                    "primitive_id": "iso42001_oversight_rate_recompute",
                    "comparator": {
                        "kind": "rational_band",
                        "params": {"epsilon": 1e30},
                    },
                },
            },
        }
    ).encode("utf-8")

    nb = json.dumps({"value": 100.0}, indent=2).encode("utf-8")
    (bundle_dir / _RATE_REL).write_bytes(nb)
    spec_path = bundle_dir / "spec" / "iso42001_external_reporting.spec.json"
    spec_path.write_bytes(weak)

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][_RATE_REL] = hashlib.sha256(nb).hexdigest()
    m["spec_files"]["iso42001_external_reporting.spec.json"] = hashlib.sha256(
        weak
    ).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier(_anchor()).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 6. rational_band edge — near-edge claims land on the exact side
# ---------------------------------------------------------------------------


def test_rational_band_edge(tmp_path):
    """The migrated comparator decides |R - c| <= 1e-9 EXACTLY on Fractions,
    with R = 100*6/9 (6 of 9 automated decisions reviewed, from the frozen
    fixture). Pin one claim just inside the band (PASS) and one just outside
    (RE_DERIVATION_MISMATCH), asserting each side's expected placement with the
    same exact arithmetic the comparator uses — a mutant that widens the band
    flips the outside cell; one that narrows it flips the inside cell.
    """
    from fractions import Fraction

    R = Fraction(100 * 6, 9)
    eps = Fraction(1, 10**9)
    inside_claim = 66.666666667  # |Fraction(inside_claim) - R| ~ 3.3e-10 < 1e-9
    outside_claim = 66.666666668  # |Fraction(outside_claim) - R| ~ 1.3e-9 > 1e-9
    assert abs(Fraction(inside_claim) - R) <= eps
    assert abs(Fraction(outside_claim) - R) > eps

    for claim, expect_ok in ((inside_claim, True), (outside_claim, False)):
        bundle_dir = tmp_path / f"bundle_{expect_ok}"
        _build(bundle_dir)
        _retarget_claim(bundle_dir, _RATE_REL, claim)
        result = _verifier().verify(bundle_dir)
        if expect_ok:
            assert result.ok, [
                (f.check_name, f.reason_code, f.detail) for f in result.failures
            ]
        else:
            assert not result.ok
            assert "RE_DERIVATION_MISMATCH" in _reason_codes(result)


def test_count_leg_is_independent_of_the_producer_helper():
    """MUTANT CONTROL for the producer/verifier tautology (fixed 2026-08-29).

    The rate leg already re-derived on its own exact-rational path; the COUNT
    leg still called the producer's `compute_automated_decision_count`, so its
    re-derivation was f(x) == f(x). Measured then: adding +1 to that helper
    still verified CLEAN at exit 0; with the count leg on its own accumulation
    the same bundle is RE_DERIVATION_MISMATCH.

    Asserted here at the seam the primitive actually uses, so the test fails if
    anyone re-points the recompute at the shared helper.
    """
    import inspect

    src = inspect.getsource(_prim_mod.Iso42001DecisionCountRecompute.recompute)
    assert "compute_automated_decision_count" not in src, (
        "the count primitive is calling the PRODUCER's helper again -- that is "
        "the tautology this split exists to prevent:\n" + src
    )
    records = [
        {"automated": True, "human_reviewed": True},
        {"automated": False, "human_reviewed": False},
        {"automated": True, "human_reviewed": False},
    ]
    # the two must AGREE on honest input...
    assert _prim_mod.compute_automated_decision_count(records) == 2
    # ...and the rate leg's separate exact path is likewise not the float helper
    rate_src = inspect.getsource(_prim_mod.Iso42001OversightRateRecompute.recompute)
    assert "compute_human_oversight_rate_pct" not in rate_src, rate_src
