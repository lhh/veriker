"""tests/test_aml_txn_monitoring_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/aml_txn_monitoring_minimal.

Representative output: the per-customer coaf_report_triggered decision
(payload/coaf_reports.json customers -> coaf_report_triggered boolean), emitted as a
deterministic ordered list of {customer_id, coaf_report_triggered} sorted ascending
by customer_id. It is recomputed by re-aggregating three per-customer features
(velocity_24h_gt_10k, structuring_proxy_7d, peer_z_score) from the committed raw
transaction stream (transactions/transactions.jsonl) + peer baselines
(baselines/customer_baselines.json), then evaluating the committed rule tree
(rule_tree/rule_tree.json). Comparator: `exact` (no params; ordered-list element-wise
equality of the decision records).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (flip one customer's coaf_report_triggered) -> FAIL
     (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate a transaction so a customer's flag flips; re-align the
     manifest SHA so FileIntegrity does not fire first) -> FAIL
     (RE_DERIVATION_MISMATCH).
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id,
     but a DIFFERENT primitive_id -> different bytes -> different SHA). For an
     `exact` comparator there is no epsilon to weaken, so the anchor defense is
     demonstrated via a substituted-spec SHA the anchor does not list ->
     fail-closed (AnchorViolation).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "aml_txn_monitoring_minimal"
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
_load("aml_txn_monitoring_recompute", _PILOT_DIR / "aml_txn_monitoring_recompute.py")
_spc = _load(
    "aml_txn_monitoring_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py"
)


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a decision list with one customer's coaf_report_triggered
    # flipped — a different ordered list than the honest re-derivation.
    honest = _spc._honest_decisions(_spc.build_spec_pinned(tmp_path / "honest"))
    assert len(honest) >= 1
    tampered = [dict(d) for d in honest]
    tampered[-1]["coaf_report_triggered"] = not tampered[-1]["coaf_report_triggered"]
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED transaction stream so the
    # re-derivation flips a customer's coaf_report_triggered relative to the
    # (honest) claimed value. C005 is borderline-clean: 2 cash deposits in the
    # R$9,000-R$9,999 band (structuring_proxy_7d == 2, rule fires only at > 2).
    # Inject a third such deposit within the 7-day window -> structuring == 3 ->
    # C005 flips to triggered, diverging from the honest claim. Re-align the
    # transactions.jsonl SHA in manifest.files so FileIntegrity does not fire first.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    txn_path = bundle_dir / "transactions" / "transactions.jsonl"
    lines = [
        ln for ln in txn_path.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    injected = {
        "amount_brl": 9300.0,
        "customer_id": "C005",
        "timestamp": "2026-04-03T10:00:00Z",  # within 7 days of C005's first deposit
        "txn_id": "T005-INJ",
        "txn_type": "cash_deposit",
    }
    lines.append(json.dumps(injected, sort_keys=True))
    new_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    txn_path.write_bytes(new_bytes)

    # The transactions file is recorded in manifest.files; re-align its SHA so
    # FileIntegrity (step-2/3) does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["transactions/transactions.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
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
    # §4a attack (exact-comparator variant): producer ships a spec the auditor did
    # NOT anchor. Same spec_id, but a DIFFERENT primitive_id -> different bytes ->
    # different SHA. The auditor anchor is computed from the COMMITTED spec, so the
    # substituted spec's SHA is not anchored -> fail-closed (no `exact` epsilon to
    # weaken; the anchor defense is the SHA the anchor does not list).
    other_spec = json.dumps(
        {
            "spec_id": "aml_txn_monitoring.v1",
            "types": {
                "aml_coaf_report_decisions": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[{"customer_id": "C999", "coaf_report_triggered": True}],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
