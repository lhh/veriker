"""tests/test_tabular_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/tabular_minimal.

Representative re-derived output: the SHA-256 hex digest of the recomputed result
CSV bytes, obtained by re-executing the committed GROUP BY + SUM/COUNT query
(spec/query.json, tabular-query-v1 DSL) over data/sales.csv and serializing the
aggregated rows byte-identically to the producer's pack; comparator is `exact`
(byte-exact string equality of the hex digest).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (flip one hex char) -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate a row in data/sales.csv so the recomputed result sha
     differs from the honest claimed sha) -> FAIL (RE_DERIVATION_MISMATCH).
     Manifest SHA re-aligned so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a substituted spec (a SHA the auditor anchor does
     not list) -> still fail-closed (the committed-spec anchor rejects the
     unlisted SHA).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "tabular_minimal"
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
_load("tabular_recompute", _PILOT_DIR / "tabular_recompute.py")
_spc = _load("tabular_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _honest_result_sha(bundle_dir: Path) -> str:
    query_bytes = (bundle_dir / "spec" / "query.json").read_bytes()
    sales_bytes = (bundle_dir / "data" / "sales.csv").read_bytes()
    return _spc.compute_result_sha(query_bytes, sales_bytes)


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a result_sha with one hex character flipped from honest.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    honest = _honest_result_sha(bundle_dir)
    flipped = ("0" if honest[0] != "0" else "1") + honest[1:]
    assert flipped != honest
    # Rebuild with the tampered claimed value.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle2", claimed_override=flipped)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate one data row in data/sales.csv. The claimed value
    # (honest sha) no longer matches the re-derivation from the tampered input.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    sales_path = bundle_dir / "data" / "sales.csv"
    lines = sales_path.read_bytes().decode("utf-8").split("\n")
    # Mutate the first data row (index 1; index 0 is the header) — bump revenue.
    # region,product,units,revenue
    cols = lines[1].split(",")
    cols[3] = str(int(cols[3]) + 1000)
    lines[1] = ",".join(cols)
    new_bytes = "\n".join(lines).encode("utf-8")
    sales_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["data/sales.csv"] = hashlib.sha256(new_bytes).hexdigest()
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
    # Producer ships a substituted spec (extra field changes the bytes -> a SHA
    # the auditor anchor does not list) AND tampers the claimed value. The auditor
    # anchor is computed from the COMMITTED spec, so the substituted spec's SHA is
    # not anchored -> fail-closed.
    substituted_spec = json.dumps(
        {
            "spec_id": "tabular.v1",
            "description": "PRODUCER-SUBSTITUTED weaker spec (not auditor-anchored).",
            "types": {
                "result_sha": {
                    "primitive_id": "tabular_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override="deadbeef",
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
