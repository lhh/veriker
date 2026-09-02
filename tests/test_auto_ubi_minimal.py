"""Round-trip integration test for examples/auto_ubi_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.

  5. Structural tests — manifest fragment anchors and dispatch records.

  6. Tamper test (SHA): mutate a trip record's hard_brakes count so the
     trips.jsonl SHA changes. Assert the verifier returns result.ok is False
     with FileSHAMismatch / bad_file_sha in the failures list.
     This exercises FileIntegrityManySmall (§C9) tamper-evidence on telematics inputs.

  7. Tamper test (re-derivation): mutate trips.jsonl AND update manifest SHA so
     FileIntegrityManySmall passes, but the re-derived features no longer match the
     bundled rating_decisions.json. Assert result.ok is False with
     RE_DERIVATION_MISMATCH surfaced.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "auto_ubi_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so AutoUBIReDerivationCheck can be imported directly.
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
    "auto_ubi_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_ubi_check_mod = _import_module_from_path(
    "AutoUBIReDerivationCheck",
    _PILOT_DIR / "AutoUBIReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

AutoUBIReDerivationCheck = _ubi_check_mod.AutoUBIReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            AutoUBIReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_auto_ubi_minimal_manifest_has_opaque_fragments(tmp_path: Path) -> None:
    """The built manifest must contain OpaqueFragment (kind_tag=telematics_trip) anchors."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    opaque_ubi = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "telematics_trip"
    ]
    assert len(opaque_ubi) >= 10, (
        f"Expected >= 10 OpaqueFragment(kind_tag=telematics_trip) anchors; "
        f"got {len(opaque_ubi)}"
    )


def test_auto_ubi_minimal_manifest_has_dispatch_records(tmp_path: Path) -> None:
    """The built manifest must contain both RATE_TABLE_LOOKUP and COMPUTE dispatch records."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    kinds = {r.get("op", {}).get("kind") for r in records}
    assert "RATE_TABLE_LOOKUP" in kinds, (
        f"Expected a dispatch_record with op.kind=RATE_TABLE_LOOKUP; found kinds: {kinds}"
    )
    assert "COMPUTE" in kinds, (
        f"Expected a dispatch_record with op.kind=COMPUTE; found kinds: {kinds}"
    )


def test_auto_ubi_minimal_rating_tiers_coverage(tmp_path: Path) -> None:
    """The bundle must include both low_mileage_discount and high_risk_surcharge tiers."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    decisions = json.loads(
        (bundle_dir / "payload" / "rating_decisions.json").read_text(encoding="utf-8")
    )
    tiers = {d["tier"] for d in decisions}
    assert "low_mileage_discount" in tiers, (
        f"Expected low_mileage_discount tier in decisions; tiers present: {tiers}"
    )
    assert "high_risk_surcharge" in tiers, (
        f"Expected high_risk_surcharge tier in decisions; tiers present: {tiers}"
    )


# ---------------------------------------------------------------------------
# Tamper test 1: SHA tamper — mutate trip record to break FileIntegrityManySmall
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_tamper_trips_sha_fails_verification(tmp_path: Path) -> None:
    """Mutating trips.jsonl without updating the manifest SHA must cause result.ok=False
    with bad_file_sha in the failures list (FileIntegrityManySmall §C9)."""
    bundle_dir = tmp_path / "auto_ubi_tampered_sha"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Overwrite the first trip record's hard_brakes to a large number
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    lines = trips_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    first_trip = json.loads(lines[0])
    first_trip["hard_brakes"] = 999
    lines[0] = json.dumps(first_trip, sort_keys=True)
    trips_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Do NOT update manifest SHA — this is the tamper test for FileIntegrityManySmall

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after SHA-tamper of telematics/trips.jsonl"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).lower()
    assert "bad_file_sha" in combined or "sha" in combined, (
        f"Expected bad_file_sha / SHA mismatch in failures; "
        f"got reason_codes={reason_codes!r}"
    )


# ---------------------------------------------------------------------------
# Tamper test 2: re-derivation tamper — update SHA but break feature invariant
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_tamper_trips_rederivation_fails(tmp_path: Path) -> None:
    """Mutating trips.jsonl AND updating the manifest SHA must cause result.ok=False
    with RE_DERIVATION_MISMATCH surfaced (re-derivation invariant broken)."""
    bundle_dir = tmp_path / "auto_ubi_tampered_redev"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Overwrite the first trip record's hard_brakes so re-derived features drift
    # from the bundled rating_decisions.json
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    lines = trips_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    first_trip = json.loads(lines[0])
    first_trip["hard_brakes"] = 999
    lines[0] = json.dumps(first_trip, sort_keys=True)
    trips_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Update manifest.files SHA so FileIntegrityManySmall does not mask the
    # re-derivation failure with a SHA mismatch first
    new_sha = _sha256(trips_path.read_bytes())
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["telematics/trips.jsonl"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after re-derivation tamper of telematics/trips.jsonl"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "RE_DERIVATION_MISMATCH" in combined, (
        f"Expected RE_DERIVATION_MISMATCH in failure reason_codes or detail; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )


# ---------------------------------------------------------------------------
# Claimset coverage (claim-field coverage gate adoption, 2026-08)
# ---------------------------------------------------------------------------


class _PreAdoptionCheck(AutoUBIReDerivationCheck):
    """The plugin as it shipped BEFORE the claimset adoption: same pack, same
    verdict, no coverage reported. Used as the honest control for "what the
    gate would have said over the pre-adoption plugin"."""

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
            op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"})
        ),
        StampLatticeCheck(),
    ]


def _repin(bundle_dir: Path, rel: str) -> None:
    """Re-pin one file's sha in manifest.files — what every producer re-pins."""
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_decisions(bundle_dir: Path, decisions: list) -> None:
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    dec_path.write_text(
        json.dumps(decisions, indent=2, sort_keys=True), encoding="utf-8"
    )
    _repin(bundle_dir, "payload/rating_decisions.json")


def test_auto_ubi_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its claimset: the verdict carries the coverage
    receipt identity (21 fields: all 9 of payload/rating_decisions.json and
    the 3 tier adjustment values of payload/rate_table.json bound by the
    re-derivation pack, the other 9 of payload/rate_table.json excused — see the README's coverage table for why), and dropping the
    re-derivation plugin turns the formerly-silent scope gap into
    could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    _build_bundle_mod.build(bundle_dir)

    verdict = _make_verifier().verify(bundle_dir)
    assert verdict.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in verdict.failures
    ]
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert len(lines) == 1, verdict.completeness.disclosures
    assert "n_universe=21 n_covered=12(self-reported) n_withheld=9" in lines[0]
    assert (
        'withheld_reasons={"INSPECTION_ONLY":1,"NOT_MECHANICALLY_CHECKABLE":3,'
        '"NO_BINDING_TARGET":5}' in lines[0]
    )
    assert lines[0].endswith("n_opaque=0")

    # The honest control is the PRE-ADOPTION plugin: the same pack, wired,
    # reporting no coverage (exactly what shipped before this adoption). Under
    # the declaration that lane is could-not-conclude naming "12 of 21"; with
    # the declaration removed, the same lane is GREEN — the formerly-silent
    # scope gap, on record. (A lane that drops the plugin entirely is not a
    # control: typed_checks names it, so that lane was never green.)
    pre = BundleVerifier(plugins=_pre_adoption_plugins()).verify(bundle_dir)
    assert pre.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "12 of 21" in r.detail
        for r in pre.reasons
    ), [(r.check_name, r.reason_code, r.detail) for r in pre.failures]

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
        d.startswith("claimset: not declared")
        for d in undeclared.completeness.disclosures
    )


def test_auto_ubi_minimal_claimset_ratchet_all_covered_fields_flip(
    tmp_path: Path,
) -> None:
    """Evidence-grade leg: a producer-consistent mutation of every covered
    claim field flips the verdict via the pack's OWN comparison (never via
    file-sha — the battery re-pins). The 9 excused rate_table fields are
    never probed and are listed as excused."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle_dir = tmp_path / "auto_ubi_bundle"
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
    assert not report.inconclusive, [(o.element, o.detail) for o in report.inconclusive]
    assert {o.element for o in report.flipped} == {
        "rating_decisions:[].adjustment_pct",
        "rating_decisions:[].annual_mileage_est",
        "rating_decisions:[].hard_brake_per_mile",
        "rating_decisions:[].harsh_accel_per_mile",
        "rating_decisions:[].late_night_fraction",
        "rating_decisions:[].policyholder_id",
        "rating_decisions:[].tier",
        "rating_decisions:[].total_miles",
        "rating_decisions:[].trip_count",
        "rate_table:tiers.high_risk_surcharge.surcharge_pct",
        "rate_table:tiers.low_mileage_discount.discount_pct",
        "rate_table:tiers.standard.discount_pct",
    }
    assert set(report.excused) == {
        "rate_table:schema_version",
        "rate_table:tier_thresholds.annual_mileage_high_min",
        "rate_table:tier_thresholds.annual_mileage_low_max",
        "rate_table:tier_thresholds.hard_brake_per_mile_surcharge_threshold",
        "rate_table:tier_thresholds.harsh_accel_per_mile_surcharge_threshold",
        "rate_table:tier_thresholds.late_night_fraction_surcharge_threshold",
        "rate_table:tiers.high_risk_surcharge.description",
        "rate_table:tiers.low_mileage_discount.description",
        "rate_table:tiers.standard.description",
    }
    for outcome in report.flipped:
        assert "BAD_FILE_SHA" not in outcome.reason_codes
        assert any(
            "[RE_DERIVATION_MISMATCH]" in detail
            for _code, detail in outcome.reasons
        ), (outcome.element, outcome.reasons)


def test_auto_ubi_minimal_trip_count_is_bound(tmp_path: Path) -> None:
    """The adoption's first finding, with a positive control: trip_count was
    computed by the pack (features["trip_count"]) but never compared to the
    bundled value before this adoption. A payload claiming a different trip_count
    for one policyholder while leaving every other field honest must now
    fail."""
    bundle_dir = tmp_path / "auto_ubi_trip_count_tampered"
    _build_bundle_mod.build(bundle_dir)

    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    decisions = json.loads(dec_path.read_text(encoding="utf-8"))
    target = next(d for d in decisions if d["policyholder_id"] == "PHD-002")
    target["trip_count"] = target["trip_count"] + 5
    _write_decisions(bundle_dir, decisions)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "trip_count mismatch" in combined, combined
    assert "PHD-002" in combined, combined


def test_auto_ubi_minimal_policyholder_id_bijection_is_bound(tmp_path: Path) -> None:
    """The adoption's second finding, with a positive control: swapping one
    decision row's policyholder_id for another real (but already-claimed) id
    — leaving the numeric fields untouched — must be refused as a duplicate,
    not silently compared against the wrong trip set."""
    bundle_dir = tmp_path / "auto_ubi_ph_id_swapped"
    _build_bundle_mod.build(bundle_dir)

    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    decisions = json.loads(dec_path.read_text(encoding="utf-8"))
    decisions[0]["policyholder_id"] = decisions[1]["policyholder_id"]
    _write_decisions(bundle_dir, decisions)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "appears in more than one payload/rating_decisions.json row" in combined, (
        combined
    )


# ---------------------------------------------------------------------------
# Comparator defects / non-defects found by the fresh-context red-team pass
# (2026-08-21) — each with its witness, per skill §11's four required probes
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_duplicate_decision_row_is_refused(tmp_path: Path) -> None:
    """Red-team witness (probe 1 — duplicate row for an existing identifier,
    placed BEFORE the honest one): the credit_scoring class of gap was a
    dict-indexed comparator silently shadowing a duplicate row. This pack
    loops over the decisions LIST (not a dict), so no row was ever silently
    dropped, but nothing previously refused the DUPLICATE outright — the new
    policyholder_id bijection (Invariant 0) now does, regardless of which
    copy is honest and which is first."""
    bundle_dir = tmp_path / "auto_ubi_dup_row"
    _build_bundle_mod.build(bundle_dir)
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    decisions = json.loads(dec_path.read_text(encoding="utf-8"))
    honest_first = decisions[0]
    assert honest_first["policyholder_id"] == "PHD-001"
    false_row = dict(honest_first)
    decisions = [false_row] + decisions
    _write_decisions(bundle_dir, decisions)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "appears in more than one payload/rating_decisions.json row" in combined, (
        combined
    )


def test_auto_ubi_minimal_key_deletion_is_refused(tmp_path: Path) -> None:
    """Red-team witness (probe 3 — deleting a key): unlike credit_scoring's
    pre-audit `bundled.get("apr_pct")` pattern (which compared None == None
    for a deleted key), this pack destructures every rating_decisions field
    with direct dict access inside a try/except — a deleted key raises
    KeyError and is refused as a malformed record. No field in this pilot's
    schema is ever null on any row, so there is no absence-compares-equal
    class of gap to close here; this test is the witness that the existing
    shape already closes it."""
    bundle_dir = tmp_path / "auto_ubi_key_deleted"
    _build_bundle_mod.build(bundle_dir)
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    decisions = json.loads(dec_path.read_text(encoding="utf-8"))
    del decisions[0]["adjustment_pct"]
    _write_decisions(bundle_dir, decisions)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "malformed decision record" in combined, combined


def test_auto_ubi_minimal_pack_opt_out_on_missing_input_is_rejected(
    tmp_path: Path,
) -> None:
    """Red-team witness (probe 4 — the pack's opt-out branches under the
    declaration): unlike credit_scoring's pre-audit pack (whose optional-
    input opt-out could exit 0 while payload/credit_decisions.json stayed
    fully present and enumerable, minting a receipt over a run that compared
    nothing), this pack's only exit-0-without-comparing paths require
    payload/rating_decisions.json ITSELF to be absent — and a declared claim
    file that goes missing is CLAIMSET_ENUMERATION_FAILED, not a silent
    could-not-conclude (covered by the next test). Removing an INPUT
    (telematics/trips.jsonl) while both declared claim files stay present
    hits `if trips is None: return 1` — a hard failure, not an opt-out — so
    the bundle is correctly REJECTed, never a false green receipt."""
    bundle_dir = tmp_path / "auto_ubi_missing_trips"
    _build_bundle_mod.build(bundle_dir)
    (bundle_dir / "telematics" / "trips.jsonl").unlink()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["files"]["telematics/trips.jsonl"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    reason_codes = [f.reason_code for f in result.failures]
    # The plugin's OWN code reaches the face now (was the generic
    # "plugin_failed" wrapper): dropping a declared input must be REFUSED by
    # the re-derivation comparator, not merely produce some plugin failure.
    assert "RE_DERIVATION_MISMATCH" in reason_codes, reason_codes
    assert not any(
        d.startswith("claimset: receipt_sha=") for d in result.completeness.disclosures
    )


def test_auto_ubi_minimal_missing_declared_claim_file_is_enumeration_failed(
    tmp_path: Path,
) -> None:
    """Companion to the above: removing the DECLARED claim file itself
    (payload/rating_decisions.json) is refused at enumeration
    (CLAIMSET_ENUMERATION_FAILED) — the bundle's own declaration is
    incoherent with its bytes — never a silent pass."""
    bundle_dir = tmp_path / "auto_ubi_missing_claim_file"
    _build_bundle_mod.build(bundle_dir)
    (bundle_dir / "payload" / "rating_decisions.json").unlink()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["files"]["payload/rating_decisions.json"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    reason_codes = [f.reason_code for f in result.failures]
    assert "CLAIMSET_ENUMERATION_FAILED" in reason_codes, reason_codes
    assert not any(
        d.startswith("claimset: receipt_sha=") for d in result.completeness.disclosures
    )


def test_auto_ubi_minimal_forged_trip_input_honestly_recomputed_still_passes(
    tmp_path: Path,
) -> None:
    """Red-team witness (probe 2 — forged INPUT, payload honestly recomputed,
    both re-pinned): mutate PHD-004's trips (clear the late_night flag on
    every trip) and honestly recompute payload/rating_decisions.json from
    the mutated trips using the pilot's OWN aggregation/classification
    functions, then re-pin both files. This PASSES — and that is the
    documented scope limit of this pilot's re-derivation, not a claimset
    coverage gap: unlike credit_scoring (which carries a SEPARATE
    fragment-anchored bureau snapshot the payload must also agree with),
    auto_ubi_minimal has no second, independently-anchored copy of trip
    behavior anywhere in the bundle. The re-derivation proves
    payload/rating_decisions.json is FAITHFUL TO the bundled
    telematics/trips.jsonl; it does not and cannot prove trips.jsonl
    reflects real driving. See the README's coverage table."""
    bundle_dir = tmp_path / "auto_ubi_forged_input"
    _build_bundle_mod.build(bundle_dir)

    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    trips = [
        json.loads(line)
        for line in trips_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for t in trips:
        if t["policyholder_id"] == "PHD-004":
            t["late_night"] = False
    new_bytes = ("\n".join(json.dumps(t, sort_keys=True) for t in trips) + "\n").encode(
        "utf-8"
    )
    trips_path.write_bytes(new_bytes)
    _repin(bundle_dir, "telematics/trips.jsonl")

    trips_by_ph: dict = {}
    for t in trips:
        trips_by_ph.setdefault(t["policyholder_id"], []).append(t)
    rate_table = json.loads(
        (bundle_dir / "payload" / "rate_table.json").read_text(encoding="utf-8")
    )
    honest_decisions = []
    for ph_id in sorted(trips_by_ph):
        features = _build_bundle_mod._aggregate_features(trips_by_ph[ph_id])
        tier_name, adjustment_pct = _build_bundle_mod._classify_tier(
            features, rate_table
        )
        honest_decisions.append(
            {
                "policyholder_id": ph_id,
                "trip_count": features["trip_count"],
                "total_miles": round(features["total_miles"], 2),
                "annual_mileage_est": round(features["annual_mileage_est"], 1),
                "hard_brake_per_mile": round(features["hard_brake_per_mile"], 5),
                "harsh_accel_per_mile": round(features["harsh_accel_per_mile"], 5),
                "late_night_fraction": round(features["late_night_fraction"], 4),
                "tier": tier_name,
                "adjustment_pct": adjustment_pct,
            }
        )
    _write_decisions(bundle_dir, honest_decisions)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    ]


def test_deleted_comparison_is_could_not_conclude(tmp_path: Path) -> None:
    """The drift test: copy the pilot directory to scratch, delete ONE
    comparison from the copied pack (the trip_count check, its `!=` and its
    `compared.add` together), import the copied plugin (it runs the copied
    pack via `Path(__file__).parent`), forge that field in a fresh bundle,
    re-pin, verify with the copied plugin in the pilot's wired set: the
    verdict must refuse to conclude NAMING the field, never stay OK. Control:
    the real plugin refuses the same forgery with the pack's own tag."""
    import shutil

    src_dir = _PILOT_DIR
    copy_dir = tmp_path / "pilot_copy"
    shutil.copytree(
        src_dir, copy_dir, ignore=shutil.ignore_patterns("__pycache__", "tests", "*.pyc")
    )
    pack = copy_dir / "auto_ubi_re_derivation.py"
    text = pack.read_text(encoding="utf-8")
    start_marker = "        # Invariant 1b (claim-field coverage adoption, 2026-08)"
    end_marker = '        compared.add("[].trip_count")\n\n'
    assert text.count(start_marker) == 1 and text.count(end_marker) == 1
    start = text.index(start_marker)
    end = text.index(end_marker) + len(end_marker)
    pack.write_text(text[:start] + text[end:], encoding="utf-8")
    drift_mod = _import_module_from_path(
        "auto_ubi_check_drift_copy", copy_dir / "AutoUBIReDerivationCheck.py"
    )

    bundle_dir = tmp_path / "bundle"
    _build_bundle_mod.build(bundle_dir)
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    decisions = json.loads(dec_path.read_text(encoding="utf-8"))
    decisions[0]["trip_count"] = int(decisions[0]["trip_count"]) + 11
    _write_decisions(bundle_dir, decisions)

    drifted = BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            drift_mod.AutoUBIReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    ).verify(bundle_dir)
    assert drifted.ok is False
    assert any(
        r.check_name == "claimset_coverage"
        and "1 of 21" in r.detail
        and "rating_decisions:[].trip_count" in r.detail
        for r in drifted.reasons
    ), [(r.code, r.detail) for r in drifted.reasons]

    control = _make_verifier().verify(bundle_dir)
    assert control.ok is False
    assert any(
        "[RE_DERIVATION_MISMATCH]" in f.detail and "trip_count" in f.detail
        for f in control.failures
    ), [f.detail for f in control.failures]


def test_trip_count_is_compared_as_typed(tmp_path: Path) -> None:
    """A float `12.0` or a string `"12"` is not the integer the aggregation
    produces; the comparison is typed, not coerced through `int()`."""
    bundle_dir = tmp_path / "bundle"
    _build_bundle_mod.build(bundle_dir)
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    honest = json.loads(dec_path.read_text(encoding="utf-8"))
    for forged in (float(honest[0]["trip_count"]), str(honest[0]["trip_count"])):
        decisions = json.loads(json.dumps(honest))
        decisions[0]["trip_count"] = forged
        _write_decisions(bundle_dir, decisions)
        result = _make_verifier().verify(bundle_dir)
        assert result.ok is False, forged
        assert any("trip_count" in f.detail for f in result.failures), [
            f.detail for f in result.failures
        ]


def _write_rate_table(bundle_dir: Path, table: dict) -> None:
    path = bundle_dir / "payload" / "rate_table.json"
    path.write_text(json.dumps(table, indent=2, sort_keys=True), encoding="utf-8")
    _repin(bundle_dir, "payload/rate_table.json")


def test_tier_adjustment_values_are_bound_to_the_decisions(tmp_path: Path) -> None:
    """Positive controls for the three rate-table values the re-partition
    reports covered: each is the other operand of the per-row adjustment_pct
    comparison on its tier, so changing it alone (decisions untouched) is
    refused naming a row of that tier — including the standard tier, whose
    adjustment used to be a pack literal `0` (wave-2 review hold-back)."""
    bundle_dir = tmp_path / "bundle"
    _build_bundle_mod.build(bundle_dir)
    honest = json.loads((bundle_dir / "payload" / "rate_table.json").read_text(encoding="utf-8"))
    for tier, key, row in (
        ("high_risk_surcharge", "surcharge_pct", "PHD-003"),
        ("low_mileage_discount", "discount_pct", "PHD-001"),
        ("standard", "discount_pct", "PHD-002"),
    ):
        table = json.loads(json.dumps(honest))
        table["tiers"][tier][key] = table["tiers"][tier][key] + 1
        _write_rate_table(bundle_dir, table)
        result = _make_verifier().verify(bundle_dir)
        assert result.ok is False, (tier, key)
        assert any(
            "[RE_DERIVATION_MISMATCH]" in f.detail
            and "adjustment_pct mismatch" in f.detail
            and row in f.detail
            for f in result.failures
        ), [(tier, f.detail) for f in result.failures]
    _write_rate_table(bundle_dir, honest)
    assert _make_verifier().verify(bundle_dir).ok is True


def test_payload_numerics_are_compared_as_typed_json(tmp_path: Path) -> None:
    """`"107.6"` for a feature, `true` for a feature, `15.0` / `false` for
    adjustment_pct: each verified OK through float() / bare `!=` before; the
    comparison is typed now (wave-2 red-team finding F2)."""
    bundle_dir = tmp_path / "bundle"
    _build_bundle_mod.build(bundle_dir)
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    honest = json.loads(dec_path.read_text(encoding="utf-8"))
    cases = [
        (0, "total_miles", str(honest[0]["total_miles"])),
        (0, "late_night_fraction", True),
        (0, "adjustment_pct", float(honest[0]["adjustment_pct"])),
        (1, "adjustment_pct", False),  # PHD-002's honest adjustment is 0
    ]
    for idx, key, forged in cases:
        decisions = json.loads(json.dumps(honest))
        decisions[idx][key] = forged
        _write_decisions(bundle_dir, decisions)
        result = _make_verifier().verify(bundle_dir)
        assert result.ok is False, (key, forged)
        assert any(key in f.detail for f in result.failures), [
            (key, forged, f.detail) for f in result.failures
        ]


def test_trip_records_are_compared_as_typed_json(tmp_path: Path) -> None:
    """A trip with `hard_brakes: 8.9` or `distance_miles: "8.2"` was coerced by
    the pack while the builder and the core primitive refuse it — the same
    bytes got PASS from one lane and a refusal from another (wave-2 red-team
    finding F1). The pack refuses non-typed trip values now."""
    bundle_dir = tmp_path / "bundle"
    _build_bundle_mod.build(bundle_dir)
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    honest_lines = trips_path.read_text(encoding="utf-8").splitlines()
    for key, forged in (("hard_brakes", 8.9), ("distance_miles", "8.2"), ("late_night", 1)):
        rows = [json.loads(line) for line in honest_lines if line.strip()]
        rows[0][key] = forged
        trips_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        _repin(bundle_dir, "telematics/trips.jsonl")
        result = _make_verifier().verify(bundle_dir)
        assert result.ok is False, (key, forged)
        assert any(key in f.detail for f in result.failures), [
            (key, forged, f.detail) for f in result.failures
        ]


def test_empty_decisions_file_is_refused_not_vacuously_covered(tmp_path: Path) -> None:
    """An empty decisions array with an empty trips file exited 0 with a
    `[COMPARED]` line naming policyholder_id over zero rows (wave-2 red-team
    finding F5). Refused by the pack now."""
    bundle_dir = tmp_path / "bundle"
    _build_bundle_mod.build(bundle_dir)
    (bundle_dir / "telematics" / "trips.jsonl").write_text("", encoding="utf-8")
    _repin(bundle_dir, "telematics/trips.jsonl")
    _write_decisions(bundle_dir, [])
    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    assert any("no decision rows" in f.detail for f in result.failures), [
        f.detail for f in result.failures
    ]
