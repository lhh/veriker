"""tests/test_build_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/build_minimal.

Representative re-derived output: the SHA-256 hex digest of the build artifact
bytes produced by re-executing the committed recipe (recipe/build_recipe.json)
against the committed sources/ tree (concat sources/{a,b,c}.txt with sep "\\n",
then canonical gzip mtime=0/level=6). Comparator is `exact` (byte-exact hex
string equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (flip one hex char) -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate a source file's bytes) -> FAIL
     (RE_DERIVATION_MISMATCH): re-derivation over the mutated sources yields a
     different artifact sha than the (honest) claimed sha. Manifest SHA on the
     mutated source re-aligned so FileIntegrity does not fire first.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "build_minimal"
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
_load("build_recompute", _PILOT_DIR / "build_recompute.py")
_spc = _load("build_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")

_ARTIFACT_REL = "payload/artifacts/combined.txt.gz"


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _honest_artifact_sha(bundle_dir: Path) -> str:
    return hashlib.sha256((bundle_dir / _ARTIFACT_REL).read_bytes()).hexdigest()


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims an artifact_sha with one hex character flipped from honest.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    honest = _honest_artifact_sha(bundle_dir)
    flipped = ("0" if honest[0] != "0" else "1") + honest[1:]
    assert flipped != honest
    # Rebuild with the tampered claimed value.
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle2", claimed_override=flipped
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate a committed source file. Re-execution of the
    # recipe over the mutated sources yields a different artifact sha, which no
    # longer matches the (honest) claimed sha.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    src_path = bundle_dir / "sources" / "a.txt"
    new_bytes = src_path.read_bytes() + b"TAMPERED EXTRA SOURCE LINE\n"
    src_path.write_bytes(new_bytes)
    # Re-align the manifest SHA on the mutated source so FileIntegrity does not
    # fire first — isolate the re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["sources/a.txt"] = hashlib.sha256(new_bytes).hexdigest()
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
            "spec_id": "build.v1",
            "description": "PRODUCER-SUBSTITUTED weaker spec (not auditor-anchored).",
            "types": {
                "artifact_sha": {
                    "primitive_id": "build_recompute",
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
