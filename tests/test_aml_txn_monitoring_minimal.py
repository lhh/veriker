"""Round-trip integration test for examples/aml_txn_monitoring_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.

  Fixture tests:
  5. Assert manifest has OpaqueFragment (kind_tag=transaction) anchors.
  6. Assert manifest has RULE_TREE_EVAL and COMPUTE dispatch_records.
  7. Assert bundled COAF-report decisions match expected outcomes per customer.

  Tamper tests:
  8. Mutate a transaction amount in transactions.jsonl so velocity changes
     for C001 — assert verifier returns result.ok=False with
     RE_DERIVATION_MISMATCH.
  9. Directly mutate payload/coaf_reports.json — assert verifier returns
     result.ok=False (FILE_SHA_MISMATCH from FileIntegrityManySmall).
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
_PILOT_DIR = _PKG_ROOT / "examples" / "aml_txn_monitoring_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
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
    "aml_txn_monitoring_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "AmlTxnMonitoringReDerivationCheck",
    _PILOT_DIR / "AmlTxnMonitoringReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

AmlTxnMonitoringReDerivationCheck = _check_mod.AmlTxnMonitoringReDerivationCheck


# ---------------------------------------------------------------------------
# Discriminating-failure helper
# ---------------------------------------------------------------------------
#
# `check_name` alone is NOT enough, and finding that out cost a second round.
# `_step_typed_check_plugins` emits a failure under the SAME
# `typed_check_plugins:<name>` check_name in two very different situations:
#
#   ran and failed : "plugin 'X' reported failure: [RE_DERIVATION_MISMATCH] ..."
#   never wired    : "manifest.typed_checks lists 'X' but no matching plugin
#                     instance is registered with this BundleVerifier ..."
#
# Both are correct behaviour -- an unwired declared check MUST fail closed --
# but an assertion that only looks at check_name is satisfied by DELETING the
# plugin, which makes it a tautology of a subtler kind than the "FILE_SHA"
# disjunct it replaced. Measured 2026-08-30 by the control at the bottom of
# this file, which failed the first time it was written and is the only reason
# this helper exists.


def _check_ran_and_failed(result, check_name: str, marker: str) -> bool:
    """Did `check_name` actually RUN and report `marker`, as opposed to being
    declared-but-unwired?"""
    for f in result.failures:
        if (
            f.check_name == check_name
            and "reported failure" in f.detail
            and marker in f.detail.upper()
        ):
            return True
    return False

# ---------------------------------------------------------------------------
# Helper: build a fresh bundle and construct the verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            AmlTxnMonitoringReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"RULE_TREE_EVAL", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "expected ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


# ---------------------------------------------------------------------------
# Manifest structure assertions
# ---------------------------------------------------------------------------


def test_manifest_has_transaction_opaque_fragments(tmp_path: Path) -> None:
    """The manifest must contain OpaqueFragment(kind_tag=transaction) anchors."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    txn_frags = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "transaction"
    ]
    assert len(txn_frags) >= 30, (
        f"Expected >= 30 OpaqueFragment(kind_tag=transaction) anchors; got {len(txn_frags)}"
    )


def test_manifest_has_rule_tree_eval_dispatch(tmp_path: Path) -> None:
    """The manifest must contain dispatch_records with op.kind=RULE_TREE_EVAL."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    rule_tree_eval_records = [
        r for r in records if r.get("op", {}).get("kind") == "RULE_TREE_EVAL"
    ]
    compute_records = [r for r in records if r.get("op", {}).get("kind") == "COMPUTE"]
    assert len(rule_tree_eval_records) >= 5, (
        f"Expected >= 5 RULE_TREE_EVAL records (one per customer); got {len(rule_tree_eval_records)}"
    )
    assert len(compute_records) >= 5, (
        f"Expected >= 5 COMPUTE records (one per customer); got {len(compute_records)}"
    )


def test_sar_trigger_decisions_correct(tmp_path: Path) -> None:
    """Bundled COAF-report decisions must match known expected outcomes."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    sar = json.loads(
        (bundle_dir / "payload" / "coaf_reports.json").read_text(encoding="utf-8")
    )
    customers = sar["customers"]

    # C001 — velocity trigger
    assert customers["C001"]["coaf_report_triggered"] is True
    assert "R1" in customers["C001"]["rules_fired"]

    # C002 — structuring trigger
    assert customers["C002"]["coaf_report_triggered"] is True
    assert "R2" in customers["C002"]["rules_fired"]

    # C003 — peer deviation trigger
    assert customers["C003"]["coaf_report_triggered"] is True
    assert "R3" in customers["C003"]["rules_fired"]

    # C004 — clean (false-positive rate demo)
    assert customers["C004"]["coaf_report_triggered"] is False
    assert customers["C004"]["rules_fired"] == []

    # C005 — borderline structuring (exactly at threshold, not above)
    assert customers["C005"]["coaf_report_triggered"] is False


# ---------------------------------------------------------------------------
# Tamper test 1: mutate transaction amount → re-derivation mismatch
# ---------------------------------------------------------------------------


def test_tamper_transaction_amount_fails(tmp_path: Path) -> None:
    """Mutating a transaction amount must cause RE_DERIVATION_MISMATCH.

    Strategy: Change one of C001's large wire amounts so that the velocity
    feature for C001 changes (drops from 4 to 3 large txns), causing the
    re-derived SAR decision to differ from the bundled payload.
    The manifest SHA for transactions.jsonl is not updated, so
    FileIntegrityManySmall will also catch it — but the re-derivation
    check fires first in plugin order.
    """
    bundle_dir = tmp_path / "aml_bundle_tamper1"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Mutate T001-004 amount from $13,000 to $9,000 (drops below $10K threshold)
    txn_path = bundle_dir / "transactions" / "transactions.jsonl"
    lines = txn_path.read_text(encoding="utf-8").splitlines()
    new_lines = []
    for line in lines:
        if not line.strip():
            new_lines.append(line)
            continue
        rec = json.loads(line)
        if rec.get("txn_id") == "T001-004":
            rec["amount_brl"] = 9000.0  # drops below $10K, velocity falls to 3
        new_lines.append(json.dumps(rec, sort_keys=True))
    txn_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "expected ok=False after tampering transaction amount"
    # STRENGTHENED 2026-08-30, and this one was a LIVE TAUTOLOGY, not merely a
    # weak disjunction. The old form accepted
    #     "RE_DERIVATION_MISMATCH" in combined
    #       or "FILE_SHA" in combined or "SHA_MISMATCH" in combined
    # Mutating transactions.jsonl always trips the verifier's UNCONDITIONAL
    # core `_step_file_integrity`, which emits reason_code="bad_file_sha";
    # uppercased, that contains "FILE_SHA". MEASURED: with
    # AmlTxnMonitoringReDerivationCheck removed from the plugin list entirely,
    # the old assertion still PASSED -- so a test whose stated purpose is that
    # re-derivation caught the tamper would have survived deleting the
    # re-derivation check. "SHA_MISMATCH" is separately dead: it never appears
    # anywhere (file_integrity_many_small says `manifest_sha=... computed_sha=
    # ...`), so it was carrying nothing at all.
    #
    # This was NAMED in the reason-code collapse scoping record as one of the
    # assertions to fix, and was then left behind while a different third
    # assertion was fixed in its place under the heading "THREE WEAK
    # ASSERTIONS STRENGTHENED". The count should have read three of four.
    #
    # Assert on check_name: it is the field `plugin_failed` preserves, and it
    # names WHICH check fired.
    fired = {f.check_name for f in result.failures}
    assert _check_ran_and_failed(
        result,
        "typed_check_plugins:aml_txn_monitoring_re_derivation",
        "RE_DERIVATION_MISMATCH",
    ), (
        f"expected the re-derivation check to RUN and report a mismatch on a "
        f"tampered transaction amount -- that is what this test is for. "
        f"failures: {result.failures}"
    )
    assert "typed_check_plugins:file_integrity_many_small" in fired, (
        f"expected the file-integrity check to fire too; got: {sorted(fired)}"
    )


# ---------------------------------------------------------------------------
# Tamper test 2: mutate payload directly → SHA mismatch
# ---------------------------------------------------------------------------


def test_tamper_payload_coaf_report_triggered_fails(tmp_path: Path) -> None:
    """Directly mutating payload/coaf_reports.json must cause FILE_SHA_MISMATCH."""
    bundle_dir = tmp_path / "aml_bundle_tamper2"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Flip C004 from clean to triggered in the payload (without rebuilding manifest)
    coaf_path = bundle_dir / "payload" / "coaf_reports.json"
    payload = json.loads(coaf_path.read_text(encoding="utf-8"))
    payload["customers"]["C004"]["coaf_report_triggered"] = True
    payload["customers"]["C004"]["rules_fired"] = ["R1"]
    coaf_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after tampering payload/coaf_reports.json"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    # STRENGTHENED. The old form's bare "MISMATCH" disjunct matched any reason
    # code containing the word, so almost any failure satisfied it -- incidental
    # rejection, not binding sensitivity. Removing it made the test FAIL, which
    # is how we learned it had been carrying the assertion: neither "FILE_SHA"
    # nor "SHA_MISMATCH" ever appears (the integrity plugin says `manifest_sha=
    # ... computed_sha=...`). Assert on check_name instead -- that is the field
    # `plugin_failed` actually preserves, and it names WHICH check fired.
    fired = {f.check_name for f in result.failures}
    assert "typed_check_plugins:file_integrity_many_small" in fired, (
        f"expected the file-integrity check to fire; got: {sorted(fired)}"
    )
    # SECOND STRENGTHENING 2026-08-30. The check_name-only form this replaces
    # was itself satisfied by REMOVING the plugin, because a declared-but-
    # unwired check fails closed under the same check_name. See
    # `_check_ran_and_failed`.
    assert _check_ran_and_failed(
        result,
        "typed_check_plugins:aml_txn_monitoring_re_derivation",
        "RE_DERIVATION_MISMATCH",
    ), (
        f"expected the re-derivation check to RUN and report a mismatch; "
        f"failures: {result.failures}"
    )


def test_CONTROL_transaction_amount_assertion_needs_the_rederivation_check(
    tmp_path: Path,
) -> None:
    """ANTI-TAUTOLOGY CONTROL for `test_tamper_transaction_amount_fails`.

    That assertion WAS a tautology: its old form accepted `"FILE_SHA" in
    combined`, and mutating transactions.jsonl always trips the verifier's
    unconditional core file-integrity step, which emits `bad_file_sha`. So it
    passed with AmlTxnMonitoringReDerivationCheck deleted outright.

    This control pins the repair. With the re-derivation check removed, the
    check_name the strengthened assertion requires must NOT be among the
    failures -- while file integrity still fires, which is exactly what made
    the old disjunction unfalsifiable.
    """
    bundle_dir = tmp_path / "aml_control_amount"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    txn_path = bundle_dir / "transactions" / "transactions.jsonl"
    new_lines = []
    for line in txn_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            new_lines.append(line)
            continue
        rec = json.loads(line)
        if rec.get("txn_id") == "T001-004":
            rec["amount_brl"] = 9000.0
        new_lines.append(json.dumps(rec, sort_keys=True))
    txn_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    kept = [
        p for p in _make_verifier()._plugins
        if type(p).__name__ != "AmlTxnMonitoringReDerivationCheck"
    ]
    assert len(kept) == len(_make_verifier()._plugins) - 1, (
        "the re-derivation check was not in the plugin list, so this control "
        "removes nothing"
    )
    result = BundleVerifier(plugins=kept).verify(bundle_dir)
    fired = {f.check_name for f in result.failures}

    # NOTE the shape of this assertion. The check_name IS still present --
    # an unwired declared check fails closed, correctly -- which is exactly the
    # hole that made the first repair a tautology too. What must disappear is
    # the check having RUN and DISAGREED.
    assert "typed_check_plugins:aml_txn_monitoring_re_derivation" in fired, (
        "a declared-but-unwired check must still fail closed under its own "
        f"check_name; got: {sorted(fired)}"
    )
    assert not _check_ran_and_failed(
        result,
        "typed_check_plugins:aml_txn_monitoring_re_derivation",
        "RE_DERIVATION_MISMATCH",
    ), (
        "the re-derivation check reported a real mismatch after being removed "
        f"-- the assertion it carries is a tautology. failures: {result.failures}"
    )
    # The old assertion's escape hatch, still present and still firing -- which
    # is precisely why "FILE_SHA in combined" could never fail.
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "FILE_SHA" in combined, (
        "core file integrity no longer fires on this tamper; if that is "
        "intended, the tautology note on the strengthened assertion is stale"
    )
