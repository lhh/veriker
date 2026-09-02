"""tests/test_anticheat_adjudication_policy_anchor.py — §4a.7 pinned-input coverage
for the anti-cheat pilot's detection POLICY.

Motivation: the legacy re-derivation proves the claimed verdict list follows from
the policy AS COMMITTED IN THE BUNDLE. That alone does NOT stop a producer who
substitutes a laxer detection policy, re-derives a consistent (all-clear) claim,
re-mints the HMACs, and repairs every manifest SHA — the bundle is internally
coherent and PASSED before this pin existed. The pitch claim "you cannot quietly
change the rule after the ban / a rule fixed before their match" requires the
policy to be pinned to the AUDITOR's anchor, not merely committed in the manifest
the producer controls.

pinned_inputs (spec_pinned/anticheat_adjudication.spec.json) fixes
evidence/detection_policy.json by SHA in the auditor-anchored spec. These tests
prove:
  1. honest bundle still PASSES (the pin matches the real policy);
  2. the coherent laxer-policy forge now fails closed (PINNED_INPUT_MISMATCH);
  3. compensating by editing the spec's pin fails closed (AnchorViolation — the
     edit changes the spec SHA the auditor anchored);
  4. deleting the pinned policy fails closed (PINNED_INPUT_MISSING).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "anticheat_adjudication_minimal"
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


_load(
    "anticheat_adjudication_recompute",
    _PILOT_DIR / "anticheat_adjudication_recompute.py",
)
_spc = _load(
    "anticheat_adjudication_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py"
)


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _loosen_policy_in_place(bundle_dir: Path) -> None:
    """Rewrite evidence/detection_policy.json so no rule can fire (every case
    re-derives 'clear')."""
    pol_p = bundle_dir / "evidence" / "detection_policy.json"
    pol = json.loads(pol_p.read_text(encoding="utf-8"))
    for rule in pol:
        for cond in rule["conditions"]:
            cond["threshold"] = -1e9 if cond["comparator"] == "<=" else 1e9
    pol_p.write_text(json.dumps(pol, indent=2, sort_keys=True), encoding="utf-8")


def _rewrite_consistent_claim(bundle_dir: Path) -> None:
    """Recompute the claimed verdict list from whatever policy is now on disk so
    the CLAIM matches the (tampered) policy — isolating the pin as the only
    remaining defense."""
    claimed = _spc.compute_verdict_list(
        _spc._load_cases(bundle_dir), _spc._load_policy(bundle_dir)
    )
    (bundle_dir / "outputs" / "anticheat_adjudication_verdict_list.json").write_bytes(
        json.dumps({"value": claimed}, indent=2).encode("utf-8")
    )


def _repair_manifest_file_shas(bundle_dir: Path) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    for rel in list(m["files"]):
        m["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")


def test_honest_still_passes(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    result = _spc.make_verifier(_spc.anchor_from_committed_spec()).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_coherent_policy_swap_fails_closed(tmp_path):
    # The exact attack that PASSED before pinned_inputs existed.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    _loosen_policy_in_place(bundle_dir)
    _rewrite_consistent_claim(bundle_dir)  # claim now matches the laxer policy
    _repair_manifest_file_shas(bundle_dir)  # FileIntegrity would otherwise fire
    result = _spc.make_verifier(_spc.anchor_from_committed_spec()).verify(bundle_dir)
    assert not result.ok
    assert "PINNED_INPUT_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_editing_spec_pin_to_compensate_fails_closed(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    _loosen_policy_in_place(bundle_dir)
    _rewrite_consistent_claim(bundle_dir)
    # Attacker also rewrites the in-bundle spec's pin to match the laxer policy.
    pol_sha = hashlib.sha256(
        (bundle_dir / "evidence" / "detection_policy.json").read_bytes()
    ).hexdigest()
    spec_p = bundle_dir / "spec" / "anticheat_adjudication.spec.json"
    sdoc = json.loads(spec_p.read_text(encoding="utf-8"))
    sdoc["types"]["anticheat_adjudication_verdict_list"]["pinned_inputs"][
        "evidence/detection_policy.json"
    ] = pol_sha
    spec_p.write_bytes(json.dumps(sdoc, indent=2).encode("utf-8"))
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m["spec_files"]["anticheat_adjudication.spec.json"] = hashlib.sha256(
        spec_p.read_bytes()
    ).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
    _repair_manifest_file_shas(bundle_dir)
    result = _spc.make_verifier(_spc.anchor_from_committed_spec()).verify(bundle_dir)
    assert not result.ok
    # Editing the spec knocks its SHA out of the auditor anchor.
    assert "AnchorViolation" in _reason_codes(result), _reason_codes(result)


def test_deleted_pinned_policy_fails_closed(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    (bundle_dir / "evidence" / "detection_policy.json").unlink()
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m["files"].pop("evidence/detection_policy.json", None)
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
    result = _spc.make_verifier(_spc.anchor_from_committed_spec()).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert (
        "PINNED_INPUT_MISMATCH" not in codes
    )  # must not falsely "match" an absent file
    assert "PINNED_INPUT_MISSING" in codes, codes
