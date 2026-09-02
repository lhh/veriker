"""Round-trip integration test for examples/credit_scoring_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.
  5. Structural assertions: OpaqueFragment anchors, dispatch_records, source_attributes.
  6. Tamper test: mutate a Serasa Score in one applicant file so re-evaluation
     produces a different tier.  Assert verifier returns result.ok=False with
     RE_DERIVATION_MISMATCH in failures.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "credit_scoring_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so CreditScoringReDerivationCheck can be imported directly.
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    """Dynamically import a module from an absolute path."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "credit_scoring_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_cs_check_mod = _import_module_from_path(
    "CreditScoringReDerivationCheck",
    _PILOT_DIR / "CreditScoringReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

CreditScoringReDerivationCheck = _cs_check_mod.CreditScoringReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            CreditScoringReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_credit_scoring_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_credit_scoring_minimal_has_opaque_fragments(tmp_path: Path) -> None:
    """The built manifest must contain OpaqueFragment(kind_tag=credit_attribute) anchors."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    opaque_credit = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "credit_attribute"
    ]
    # 5 applicants × 5 bureau attributes = 25 anchors
    assert len(opaque_credit) >= 25, (
        f"Expected >= 25 OpaqueFragment(kind_tag=credit_attribute) anchors; "
        f"got {len(opaque_credit)}"
    )


def test_credit_scoring_minimal_has_scorecard_eval_dispatch(tmp_path: Path) -> None:
    """The built manifest must contain dispatch_records with op.kind=SCORECARD_EVAL."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    kinds = [r.get("op", {}).get("kind") for r in records]
    assert "SCORECARD_EVAL" in kinds, (
        f"Expected a dispatch_record with op.kind=SCORECARD_EVAL; found kinds: {kinds}"
    )
    assert "COMPUTE" in kinds, (
        f"Expected a dispatch_record with op.kind=COMPUTE; found kinds: {kinds}"
    )


def test_credit_scoring_minimal_has_source_attributes(tmp_path: Path) -> None:
    """The built manifest must contain source_attributes with publication_class=regulatory."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    source_attrs = manifest.get("source_attributes", {})

    assert len(source_attrs) >= 1, (
        f"Expected at least one source_attributes entry; got {source_attrs}"
    )
    # Each entry must carry publication_class=regulatory (credit-bureau lineage; LGPD art. 20)
    for cid, props in source_attrs.items():
        assert props.get("publication_class") == "regulatory", (
            f"source_attributes[{cid!r}]: expected publication_class='regulatory'; "
            f"got {props.get('publication_class')!r}"
        )


def test_credit_scoring_minimal_decisions_have_expected_tiers(tmp_path: Path) -> None:
    """Built payload must include at least one approve-A, one approve-C, and one decline."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    payload = json.loads(
        (bundle_dir / "payload" / "credit_decisions.json").read_text(encoding="utf-8")
    )
    decisions = payload.get("decisions", [])
    tiers = {d["tier"] for d in decisions}
    decisions_set = {d["decision"] for d in decisions}

    assert "A" in tiers, f"Expected tier A in decisions; got tiers={sorted(tiers)}"
    assert "decline" in decisions_set, (
        f"Expected at least one decline decision; got decisions={sorted(decisions_set)}"
    )


# ---------------------------------------------------------------------------
# Tamper path: mutate a Serasa Score to produce a different tier
# ---------------------------------------------------------------------------


def test_credit_scoring_minimal_tamper_fico_fails_verification(tmp_path: Path) -> None:
    """Mutating an applicant's Serasa Score to produce a different tier must cause
    result.ok=False with RE_DERIVATION_MISMATCH in failures."""
    bundle_dir = tmp_path / "credit_scoring_tampered"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Find the prime applicant (APP-001, tier A, FICO=780) and drop FICO to 580
    # so that the re-derived PD pushes them into tier D (decline).
    app_path = bundle_dir / "applicants" / "APP-001.json"
    assert app_path.exists(), (
        f"Expected APP-001.json in bundle; not found at {app_path}"
    )

    app_data = json.loads(app_path.read_text(encoding="utf-8"))
    original_fico = app_data["serasa_score"]
    app_data["serasa_score"] = 400  # far below prime — guarantees a tier shift
    app_path.write_text(
        json.dumps(app_data, indent=2, sort_keys=True), encoding="utf-8"
    )

    # Update manifest.files SHA for the tampered applicant file so
    # FileIntegrityManySmall does not mask the re-derivation failure.
    import hashlib

    new_sha = hashlib.sha256(app_path.read_bytes()).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["applicants/APP-001.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        f"Expected result.ok=False after tampering APP-001 Serasa Score "
        f"(original={original_fico}, tampered=400)"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    # The tampered applicant file now contradicts the bundle's registered
    # bureau snapshot, so the INPUT binding refuses before the scorecard is
    # replayed (CREDIT_SCORING_BUREAU_MISMATCH). The tier-shift path itself is
    # exercised by the payload-side tests and the per-field tamper battery.
    assert "CREDIT_SCORING_BUREAU_MISMATCH" in combined, (
        f"Expected CREDIT_SCORING_BUREAU_MISMATCH in failures; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )
    assert "APP-001" in combined and "SERASA_SCORE" in combined, combined


# ---------------------------------------------------------------------------
# Planted-violation path: pd substituted within the same tier band
# (FIX-E — pd was previously referenced only in an error-message f-string,
# never asserted equal to the bundled value; a materially different pd could
# be reported while tier/decision/apr stayed untouched)
# ---------------------------------------------------------------------------


def test_credit_scoring_minimal_pd_substitution_same_tier_fails_verification(
    tmp_path: Path,
) -> None:
    """Report a different pd for one applicant while leaving tier/decision/apr_pct
    untouched (same tier band) — the strongest producer attack the bundled pd
    equality check exists to catch. Must fail with CREDIT_SCORING_PD_MISMATCH."""
    bundle_dir = tmp_path / "credit_scoring_pd_tampered"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    payload_path = bundle_dir / "payload" / "credit_decisions.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))

    target = next(d for d in payload["decisions"] if d["applicant_id"] == "APP-002")
    original_pd = target["pd"]

    # Derive the target's tier band from the builder's own threshold table
    # (rather than hardcoding a band) so this test stays correct if the
    # fixture coefficients ever change.
    tier_row = next(
        t
        for t in _build_bundle_mod._THRESHOLD_TABLE["tiers"]
        if t["tier"] == target["tier"]
    )
    pd_min, pd_max = tier_row["pd_min"], tier_row["pd_max"]
    # Midpoint of the band, guaranteed inside [pd_min, pd_max) and distinct
    # from original_pd — tier/decision/apr_pct stay untouched.
    tampered_pd = round((pd_min + pd_max) / 2, 6)
    assert pd_min <= tampered_pd < pd_max
    assert tampered_pd != original_pd
    target["pd"] = tampered_pd

    payload_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    # Re-sha manifest.files for the tampered payload file so
    # FileIntegrityManySmall does not mask the re-derivation failure.
    import hashlib

    new_sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/credit_decisions.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        f"Expected result.ok=False after substituting APP-002 pd "
        f"(original={original_pd}, tampered={tampered_pd}) within the same "
        f"tier band — tier/decision/apr_pct were left untouched"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "CREDIT_SCORING_PD_MISMATCH" in combined, (
        f"Expected CREDIT_SCORING_PD_MISMATCH in failures; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )


def test_credit_scoring_minimal_honest_bundle_still_passes_after_pd_check(
    tmp_path: Path,
) -> None:
    """An untampered bundle must still PASS with the pd-equality check in place."""
    bundle_dir = tmp_path / "credit_scoring_honest"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


# ---------------------------------------------------------------------------
# Claimset coverage (claim-field coverage gate adoption, 2026-08)
# ---------------------------------------------------------------------------


class _PreAdoptionCheck(CreditScoringReDerivationCheck):
    """The plugin as it shipped BEFORE the claimset adoption: same pack, same
    verdict, no coverage reported. Used as the honest control for "what the
    gate would have said over the pre-wave plugin"."""

    def check(self, bundle_dir: Path, manifest):
        import dataclasses

        return dataclasses.replace(
            super().check(bundle_dir, manifest), verified_claim_fields=frozenset()
        )


def _pre_adoption_plugins():
    return [
        FileIntegrityManySmall(),
        _PreAdoptionCheck(),
        DispatchRecordWellformedCheck(
            op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"})
        ),
        StampLatticeCheck(),
    ]


def _repin(bundle_dir: Path, rel: str) -> None:
    """Re-pin one file's sha in manifest.files — what every producer re-pins."""
    import hashlib

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_payload(bundle_dir: Path, payload: dict) -> None:
    payload_path = bundle_dir / "payload" / "credit_decisions.json"
    payload_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    _repin(bundle_dir, "payload/credit_decisions.json")


def test_credit_scoring_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its claimset: the verdict carries the coverage
    receipt identity (8 fields: 7 bound by the re-derivation pack, `schema`
    excused INSPECTION_ONLY), and dropping the re-derivation plugin turns the
    formerly-silent scope gap into could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    _build_bundle_mod.build(bundle_dir)

    verdict = _make_verifier().verify(bundle_dir)
    assert verdict.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in verdict.failures
    ]
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert len(lines) == 1, verdict.completeness.disclosures
    assert "n_universe=8 n_covered=7(self-reported) n_withheld=1" in lines[0]
    assert 'withheld_reasons={"INSPECTION_ONLY":1}' in lines[0]
    assert lines[0].endswith("n_opaque=0")

    # The honest control is the PRE-ADOPTION plugin: the same pack, wired,
    # reporting no coverage (exactly what shipped before this wave). Under
    # the declaration that lane is could-not-conclude naming "7 of 8"; with
    # the declaration removed, the same lane is GREEN — the formerly-silent
    # scope gap, on record. (A lane that drops the plugin entirely is not a
    # control: typed_checks names it, so that lane was never green.)
    pre = BundleVerifier(plugins=_pre_adoption_plugins()).verify(bundle_dir)
    assert pre.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "7 of 8" in r.detail
        for r in pre.reasons
    ), [(r.code, r.detail) for r in pre.reasons]

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("claimset")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    undeclared = BundleVerifier(plugins=_pre_adoption_plugins()).verify(bundle_dir)
    assert undeclared.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in undeclared.failures
    ]
    assert any(
        d.startswith("claimset: not declared") for d in undeclared.completeness.disclosures
    )


def test_credit_scoring_minimal_claimset_ratchet_all_covered_fields_flip(
    tmp_path: Path,
) -> None:
    """Evidence-grade leg: a producer-consistent mutation of every covered
    claim field flips the verdict via the pack's OWN comparison (never via
    file-sha — the battery re-pins). `pd` must refuse under the pack's PD
    tolerance tag; every other field under its re-derivation mismatch tag.
    The excused `schema` label is never probed and is listed as excused."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle_dir = tmp_path / "credit_scoring_bundle"
    _build_bundle_mod.build(bundle_dir)
    report = run_claimset_ratchet(
        bundle_dir,
        _make_verifier,
        tmp_path / "ratchet_scratch",
        # Deny-by-default scoring: name the code THIS pilot's comparator
        # emits when it refuses a value, so a flip caused by anything else
        # (a crash, an unwired check, a timeout, a code nobody classified)
        # scores INCONCLUSIVE instead of being credited as coverage.
        comparator_codes={"RE_DERIVATION_MISMATCH"},
    )
    assert report.baseline_state == "OK"
    assert not report.survived, [(o.element, o.detail) for o in report.survived]
    assert not report.skipped, [(o.element, o.detail) for o in report.skipped]
    assert not report.inconclusive, [
        (o.element, o.detail) for o in report.inconclusive
    ]
    assert {o.element for o in report.flipped} == {
        "credit_decisions:decisions[].applicant_id",
        "credit_decisions:decisions[].apr_pct",
        "credit_decisions:decisions[].decision",
        "credit_decisions:decisions[].pd",
        "credit_decisions:decisions[].tier",
        "credit_decisions:scorecard_model",
        "credit_decisions:scorecard_version",
    }
    assert report.excused == ("credit_decisions:schema",)
    for outcome in report.flipped:
        assert "BAD_FILE_SHA" not in outcome.reason_codes
        expected_tag = (
            "[CREDIT_SCORING_PD_MISMATCH]"
            if outcome.element.endswith(".pd")
            else "[RE_DERIVATION_MISMATCH]"
        )
        assert any(expected_tag in detail for _code, detail in outcome.reasons), (
            outcome.element,
            outcome.reasons,
        )


def test_credit_scoring_minimal_model_identity_is_bound(tmp_path: Path) -> None:
    """The adoption's finding, with a positive control for the new comparison:
    before this wave the pack replayed model/scorecard.json but never compared
    the payload's stated scorecard_model / scorecard_version to it. A payload
    claiming a different model version while carrying the same decisions must
    now fail."""
    bundle_dir = tmp_path / "credit_scoring_model_identity"
    _build_bundle_mod.build(bundle_dir)

    payload_path = bundle_dir / "payload" / "credit_decisions.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    assert payload["scorecard_version"] == "1.0.0"
    payload["scorecard_version"] = "1.0.1"
    payload_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    import hashlib

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/credit_decisions.json"] = hashlib.sha256(
        payload_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures)
    assert "[RE_DERIVATION_MISMATCH]" in combined
    assert "scorecard_version" in combined, combined


# ---------------------------------------------------------------------------
# Comparator defects found by the fresh-context audit of the adoption
# (red-team + claims lenses, 2026-08-20) — each with its witness
# ---------------------------------------------------------------------------


def test_credit_scoring_minimal_duplicate_decision_row_is_refused(tmp_path: Path) -> None:
    """Red-team witness: the pack indexed decisions in a dict and compared the
    DICT length to the applicant count, so a second row for an existing
    applicant_id — placed first, with a false approve — was silently shadowed
    by the honest row and never compared; verdict OK, receipt minted. Now a
    duplicate applicant_id is refused outright and the arity check is over
    the array."""
    bundle_dir = tmp_path / "credit_scoring_dup_row"
    _build_bundle_mod.build(bundle_dir)
    payload_path = bundle_dir / "payload" / "credit_decisions.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    honest_decline = next(d for d in payload["decisions"] if d["decision"] == "decline")
    false_row = {
        "applicant_id": honest_decline["applicant_id"],
        "pd": 0.01,
        "tier": "A",
        "decision": "approve",
        "apr_pct": 6.99,
    }
    payload["decisions"] = [false_row] + payload["decisions"]
    _write_payload(bundle_dir, payload)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "appears in more than one decision row" in combined, combined


def test_credit_scoring_minimal_absent_apr_pct_is_refused(tmp_path: Path) -> None:
    """Claims-lens witness: `bundled.get("apr_pct")` compared None == None for
    a decline row whose key was DELETED, so the field was reported covered
    over rows on which nothing was compared. Absence is now a mismatch."""
    bundle_dir = tmp_path / "credit_scoring_no_apr"
    _build_bundle_mod.build(bundle_dir)
    payload_path = bundle_dir / "payload" / "credit_decisions.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    removed = 0
    for d in payload["decisions"]:
        if d["decision"] == "decline":
            del d["apr_pct"]
            removed += 1
    assert removed >= 1
    _write_payload(bundle_dir, payload)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "has no 'apr_pct' field" in combined, combined


def test_credit_scoring_minimal_pack_opt_out_is_could_not_conclude(tmp_path: Path) -> None:
    """Claims-lens witness: the pack's opt-out branches exit 0 when model/ and
    applicants/ are absent, and the plugin used to report a green
    "re-derived successfully" leg over a run that compared nothing. Now an
    exit 0 without a [COMPARED] line is could-not-conclude (clean-ERROR), and
    the claimset gate independently names the 7 unaccounted fields."""
    bundle_dir = tmp_path / "credit_scoring_opt_out"
    _build_bundle_mod.build(bundle_dir)
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for rel in list(manifest["files"]):
        if rel.startswith("model/") or rel.startswith("applicants/"):
            (bundle_dir / rel).unlink()
            del manifest["files"][rel]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    assert result.state.value == "ERROR", (result.state, [r.code for r in result.reasons])
    assert any(
        r.check_name == "typed_check_plugins:credit_scoring_re_derivation"
        and "could not conclude" in r.detail
        for r in result.reasons
    ), [(r.check_name, r.code, r.detail[:120]) for r in result.reasons]
    assert any(
        r.check_name == "claimset_coverage" and "7 of 8" in r.detail for r in result.reasons
    )
    assert not any(
        d.startswith("claimset: receipt_sha=") for d in result.completeness.disclosures
    )


def test_credit_scoring_minimal_forged_input_contradicting_bureau_snapshot_is_refused(
    tmp_path: Path,
) -> None:
    """Red-team witness (input forgery, not output forgery): rewrite a declined
    applicant's bureau attributes in applicants/<id>.json to prime values,
    recompute the payload HONESTLY against the forgery, re-pin both files.
    Before this fix the verdict was OK with a receipt byte-identical to the
    honest one while snapshots/credit_bureau_attributes.json — CID-registered,
    publication_class="regulatory", anchored by 25 fragment anchors — still
    said "decline". The pack now binds applicants/ to that snapshot."""
    bundle_dir = tmp_path / "credit_scoring_forged_input"
    _build_bundle_mod.build(bundle_dir)

    app_path = bundle_dir / "applicants" / "APP-004.json"
    app = json.loads(app_path.read_text(encoding="utf-8"))
    assert app["serasa_score"] == 580 and app["derog_marks"] == 3
    app.update(
        {
            "serasa_score": 780,
            "utilization_pct": 8.0,
            "tradeline_count": 15,
            "dti_pct": 22.0,
            "derog_marks": 0,
        }
    )
    app_path.write_text(json.dumps(app, indent=2, sort_keys=True), encoding="utf-8")
    _repin(bundle_dir, "applicants/APP-004.json")

    # Honest recomputation of the payload over the forged input, with the
    # builder's own arithmetic — the output side is consistent.
    payload_path = bundle_dir / "payload" / "credit_decisions.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    pd = _build_bundle_mod._compute_pd(app, _build_bundle_mod._SCORECARD)
    tier = _build_bundle_mod._lookup_tier(pd, _build_bundle_mod._THRESHOLD_TABLE)
    for d in payload["decisions"]:
        if d["applicant_id"] == "APP-004":
            assert d["decision"] == "decline"
            d.update(
                {
                    "pd": round(pd, 6),
                    "tier": tier["tier"],
                    "decision": tier["decision"],
                    "apr_pct": tier["apr_pct"],
                }
            )
            assert d["decision"] == "approve"
    _write_payload(bundle_dir, payload)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, "forged input verified OK — the bureau binding is not live"
    combined = " ".join(f.detail for f in result.failures)
    assert "[CREDIT_SCORING_BUREAU_MISMATCH]" in combined, combined
    assert "APP-004" in combined and "serasa_score" in combined, combined
    assert not any(
        d.startswith("claimset: receipt_sha=") for d in result.completeness.disclosures
    )
