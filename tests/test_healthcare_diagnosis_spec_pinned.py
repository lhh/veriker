"""tests/test_healthcare_diagnosis_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/healthcare_diagnosis_minimal.

Representative output: the ordered list of icd10_code values in payload/diagnosis.json
(categorical codes only), recomputed by traversing the committed decision rules
(inputs/rules.json) in sorted rule_id order against the committed symptom set
(inputs/symptoms.json): a rule fires iff every condition's symptom is present and
meets min_severity, and each fired rule contributes its icd10_code in order.
Comparator: `exact` (no params; ordered-list element-wise equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (a REORDERED icd10_code list) -> FAIL
     (RE_DERIVATION_MISMATCH).
  3. Tampered input (lower a symptom severity below a rule's threshold so the
     re-derivation drops a code) -> FAIL (RE_DERIVATION_MISMATCH); manifest SHA
     re-aligned so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id,
     but a DIFFERENT primitive_id -> different bytes -> different SHA). For an
     `exact` comparator there is no epsilon to weaken, so the anchor defense is
     demonstrated via a substituted-spec SHA the anchor does not list ->
     fail-closed (AnchorViolation).

TIER-2 CONFIDENCE SLICE (rational-band wave, RATIONAL_BAND_MIGRATION.md §4b.2):
`_spc.build_spec_pinned` now ALSO overlays one `healthcare_diagnosis_confidence`
output per fired candidate (output_id "confidence:<icd10_code>", comparator
rational_band{epsilon=1e-6}) whenever that type is present in the spec bytes in
use — additive-by-presence, the same convention
the FEA pilot uses. This is a deliberate,
REPORTED harness extension: tests 1-5 above are byte-UNTOUCHED (no change to
their bodies), but because build_spec_pinned/make_verifier now always include
the confidence claims + the ConfidenceCoverageCheck plugin + a wider work-set,
those 5 pre-existing cells now ALSO exercise the confidence surface on every run
(the honest confidence outputs mirror the producer's own payload/diagnosis.json
"confidence" field — never the new exact primitive — so they stay green).

Six new cells cover the confidence slice itself:
  6. Confidence tampered outside epsilon -> RE_DERIVATION_MISMATCH.
  7. rational_band edge: one candidate's exact R computed test-locally with
     Fractions; a claim just inside epsilon PASSes, just outside REDs.
  8. Nonexistent/non-firing code confidence output -> fail-closed
     (RECOMPUTE_ERROR; the primitive refuses rather than inventing a value).
  9. Coverage cross-check: dropping one candidate's confidence output (with a
     self-consistently re-minted manifest, so file-integrity + dispatch's own
     §4a.4 coverage invariant both stay green) -> the pilot-level
     ConfidenceCoverageCheck plugin fails (CONFIDENCE_COVERAGE_GAP in its
     detail, and propagated onto VerifyFailure.reason_code since 2026-08-30).
  10. Rebinding: a confidence output declaring the codes type ->
      ROLE_POLICY_VIOLATION (the work-set's pin fires before any recompute).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "healthcare_diagnosis_minimal"
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
_load(
    "healthcare_diagnosis_recompute", _PILOT_DIR / "healthcare_diagnosis_recompute.py"
)
_spc = _load(
    "healthcare_diagnosis_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py"
)


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a REORDERED icd10_code list (swap first two entries) — a
    # different ordered list than the honest re-derivation.
    honest = _spc._honest_codes(_spc.build_spec_pinned(tmp_path / "honest"))
    assert len(honest) >= 2
    reordered = list(honest)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=reordered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED symptoms so the rule traversal
    # re-derives a DIFFERENT icd10_code list than the (honest) claimed value.
    # Lower sym-005 severity to 1: rules rule-A49/rule-I20/rule-J18 all require
    # sym-005 >= 2, so they stop firing and their codes drop out — the
    # re-derivation diverges from the honest 4-code claim. Re-align the
    # manifest SHA so FileIntegrity (step-2/3) does not fire first.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    symptoms_path = bundle_dir / "inputs" / "symptoms.json"
    symptoms = json.loads(symptoms_path.read_bytes())
    for s in symptoms:
        if s["symptom_id"] == "sym-005":
            s["severity"] = 1
    new_bytes = (
        json.dumps(symptoms, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    symptoms_path.write_bytes(new_bytes)

    # symptoms.json is recorded in manifest.files; re-align its SHA so
    # FileIntegrity does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/symptoms.json"] = hashlib.sha256(new_bytes).hexdigest()
    mp.write_text(
        json.dumps(m, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
    )

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
    # §4a attack (exact-comparator variant): producer ships a spec the auditor did
    # NOT anchor. Same spec_id, but a DIFFERENT primitive_id -> different bytes ->
    # different SHA. The auditor anchor is computed from the COMMITTED spec, so the
    # substituted spec's SHA is not anchored -> fail-closed (no `exact` epsilon to
    # weaken; the anchor defense is the SHA the anchor does not list).
    other_spec = json.dumps(
        {
            "spec_id": "healthcare_diagnosis.v1",
            "types": {
                "healthcare_diagnosis_codes": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=["tampered"],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes


# ---------------------------------------------------------------------------
# Tier-2 confidence slice (RATIONAL_BAND_MIGRATION.md §4b.2) — new cells 6-10.
# ---------------------------------------------------------------------------


def test_confidence_tampered_outside_epsilon_fails(tmp_path):
    """Inflate one candidate's confidence claim by 0.5 (>> epsilon=1e-6) ->
    RE_DERIVATION_MISMATCH on that output specifically; every other output
    (codes + the other 3 confidence claims) stays honest and PASSes."""
    honest_dir = _spc.build_spec_pinned(tmp_path / "honest")
    candidates = json.loads((honest_dir / "payload" / "diagnosis.json").read_bytes())
    target = next(c for c in candidates if c["icd10_code"] == "I20.9")
    tampered_output_id = f"confidence:{target['icd10_code']}"
    tampered_value = round(target["confidence"] + 0.5, 6)

    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        confidence_overrides={tampered_output_id: tampered_value},
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    reason_codes = _reason_codes(result)
    assert "RE_DERIVATION_MISMATCH" in reason_codes, reason_codes
    mismatch_checks = {
        f.check_name
        for f in result.failures
        if f.reason_code == "RE_DERIVATION_MISMATCH"
    }
    assert f"spec_pinned_dispatch:{tampered_output_id}" in mismatch_checks, (
        mismatch_checks
    )


def test_confidence_rational_band_edge(tmp_path):
    """The confidence comparator decides |R - c| <= 1e-6 EXACTLY on Fractions,
    R = Fraction(severity_sum) * Fraction(confidence_weight) UNROUNDED. Pin one
    fired candidate's R test-locally (I20.9: rule-I20 fires on sym-003 (severity
    5 >= min 4) and sym-005 (severity 3 >= min 2) -> severity_sum=8,
    confidence_weight=0.12 from the committed fixture), then place one claim
    just inside the band (PASS) and one just outside (RE_DERIVATION_MISMATCH) —
    a mutant that widens/narrows the band flips the corresponding cell.
    """
    from fractions import Fraction

    severity_sum = 8
    weight = 0.12
    R = Fraction(severity_sum) * Fraction(weight)
    eps = Fraction(1, 10**6)
    inside_claim = float(R) + 5e-7
    outside_claim = float(R) + 2e-6
    assert abs(Fraction(inside_claim) - R) <= eps
    assert abs(Fraction(outside_claim) - R) > eps

    output_id = "confidence:I20.9"
    for claim, expect_ok in ((inside_claim, True), (outside_claim, False)):
        bundle_dir = _spc.build_spec_pinned(
            tmp_path / f"bundle_{expect_ok}",
            confidence_overrides={output_id: claim},
        )
        anchor = _spc.anchor_from_committed_spec()
        result = _spc.make_verifier(anchor).verify(bundle_dir)
        if expect_ok:
            assert result.ok, [
                (f.check_name, f.reason_code, f.detail) for f in result.failures
            ]
        else:
            assert not result.ok
            reason_codes = _reason_codes(result)
            assert "RE_DERIVATION_MISMATCH" in reason_codes, reason_codes


def test_confidence_nonexistent_code_fails_closed(tmp_path):
    """A confidence output for a code that never fires any committed rule (here,
    a code absent from inputs/rules.json entirely) -> the primitive REFUSES
    (raises) rather than inventing a value -> dispatch records a fail-closed
    RECOMPUTE_ERROR, never a silently-passing fabricated confidence."""
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        extra_confidence_outputs={"Z00.0": 0.5},
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    reason_codes = _reason_codes(result)
    assert "RECOMPUTE_ERROR" in reason_codes, reason_codes
    error_checks = {
        f.check_name for f in result.failures if f.reason_code == "RECOMPUTE_ERROR"
    }
    assert "spec_pinned_dispatch:confidence:Z00.0" in error_checks, error_checks


def test_confidence_coverage_gap_fails(tmp_path):
    """Drop ONE candidate's confidence output (self-consistently: no file, no
    manifest.outputs entry — file-integrity and dispatch's own §4a.4
    declared-vs-present coverage invariant both stay satisfied) while the codes
    claim still lists all 4 codes -> the pilot-level ConfidenceCoverageCheck
    catches the roster gap the dispatch-level invariant cannot see, closing the
    selective-omission gap the triage found."""
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        omit_confidence_codes=["A49.9"],
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    # TypedCheck plugin failures surface under check_name
    # "typed_check_plugins:<plugin_name>", and the plugin's OWN
    # PluginResult.reason_code IS forwarded onto VerifyFailure
    # (_step_typed_check_plugins propagates it; only the crash arm and the
    # declared-but-unwired arm still emit the generic "plugin_failed"). So
    # assert the specific code, not the wrapper -- the detail text
    # (missing/extra code sets) is checked separately below.
    reason_codes = _reason_codes(result)
    assert "CONFIDENCE_COVERAGE_GAP" in reason_codes, reason_codes
    coverage_failures = [
        f
        for f in result.failures
        if f.check_name
        == "typed_check_plugins:healthcare_diagnosis_confidence_coverage"
    ]
    assert len(coverage_failures) == 1, result.failures
    detail = coverage_failures[0].detail
    assert "coverage cross-check" in detail, detail
    assert "missing=['A49.9']" in detail, detail
    # Dispatch's own coverage invariant must NOT have fired — the omission is
    # self-consistent (manifest and outputs/ agree), so only the pilot-level
    # cross-check should catch it.
    assert "COVERAGE_MISMATCH" not in reason_codes, reason_codes


def test_confidence_rebinding_fails_role_policy(tmp_path):
    """A confidence output that declares the CODES type (a same-primitive-
    family rebinding attempt) -> ROLE_POLICY_VIOLATION, fail-closed BEFORE any
    recompute runs — the auditor's work-set pins output_id -> required type
    independently of whatever type the manifest entry claims."""
    output_id = "confidence:J18.9"
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        type_overrides={output_id: "healthcare_diagnosis_codes"},
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    reason_codes = _reason_codes(result)
    assert "ROLE_POLICY_VIOLATION" in reason_codes, reason_codes
    violation_checks = {
        f.check_name
        for f in result.failures
        if f.reason_code == "ROLE_POLICY_VIOLATION"
    }
    assert f"spec_pinned_dispatch:{output_id}" in violation_checks, violation_checks
