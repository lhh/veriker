"""tests/test_secops_alert_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/secops_alert_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed label (different string) -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate alert_log line 0 so the re-derived label changes)
     -> FAIL (RE_DERIVATION_MISMATCH): re-derivation from the tampered evidence no
     longer agrees with the (honest) claimed label. The manifest SHA is re-aligned
     on the mutated file so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a substituted pinned spec (a SHA the auditor did
     not anchor) with a tampered value -> still fail-closed (the strong
     committed-spec anchor does not list the substituted spec's SHA).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "secops_alert_minimal"
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
_load("secops_alert_recompute", _PILOT_DIR / "secops_alert_recompute.py")
_spc = _load("secops_alert_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT label string than the honest re-derivation
    # (TRUE_POSITIVE for the SSH brute-force alert).
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override="FALSE_POSITIVE"
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate the alert_log line 0 by neutralizing the
    # "user=root" and "src=198.51.100.42" tokens. R002 (weight 4) and R004
    # (weight 3) no longer fire, so the re-derived score drops 12 -> 5
    # (TRUE_POSITIVE -> SUSPICIOUS) — the claimed (honest) label no longer
    # matches the re-derivation from tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    log_path = bundle_dir / "inputs" / "alert_log.txt"
    text = log_path.read_text(encoding="utf-8")
    assert "user=root " in text and "src=198.51.100.42 " in text, text
    new_text = text.replace("user=root ", "user=svc ", 1).replace(
        "src=198.51.100.42 ", "src=10.0.1.99 ", 1
    )
    new_bytes = new_text.encode("utf-8")
    log_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/alert_log.txt"] = hashlib.sha256(new_bytes).hexdigest()
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
    # Producer ships a substituted spec (a different spec_id the auditor did not
    # anchor) AND tampers the claimed value. The auditor anchor is computed from
    # the COMMITTED spec, so the substituted spec's SHA is not anchored ->
    # fail-closed.
    substituted_spec = json.dumps(
        {
            "spec_id": "secops_alert.attacker",
            "types": {
                "secops_alert_final_label": {
                    "primitive_id": "secops_alert_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override="FALSE_POSITIVE",
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
