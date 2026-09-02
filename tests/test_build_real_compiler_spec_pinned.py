"""tests/test_build_real_compiler_spec_pinned.py -- Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/build_real_compiler_minimal.

Representative re-derived output: the SHA-256 hex digest of the recompiled
mod_a.pyc bytes (re-compile sources/mod_a.py with the pinned interpreter via
py_compile -- CHECKED_HASH invalidation, SOURCE_DATE_EPOCH=0, dfile pinned to the
base name -- then sha256 the produced .pyc bytes). Comparator is `exact`
(byte-exact hex-string equality). The primitive guards on
recipe.cache_tag == sys.implementation.cache_tag first (fail-closed raise on
toolchain mismatch).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (flip one hex char) -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate sources/mod_a.py so the recompiled .pyc sha differs)
     -> FAIL (RE_DERIVATION_MISMATCH): re-derivation over the mutated source no
     longer equals the (honest) claimed sha. Manifest SHA re-aligned so
     FileIntegrity does not fire first.
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
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "build_real_compiler_minimal"
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
_load("build_real_compiler_recompute", _PILOT_DIR / "build_real_compiler_recompute.py")
_spc = _load("build_real_compiler_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")

_REPR_SOURCE = "mod_a.py"


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a pyc_sha with one hex character flipped from honest.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    honest = _spc.compute_repr_pyc_sha_from_bundle(bundle_dir)
    flipped = ("0" if honest[0] != "0" else "1") + honest[1:]
    assert flipped != honest
    # Rebuild with the tampered claimed value.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle2", claimed_override=flipped)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate the representative source bytes. The claimed value
    # (honest sha) no longer matches the re-derivation: recompiling the mutated
    # source produces different .pyc bytes -> a different sha256.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    src_path = bundle_dir / "sources" / _REPR_SOURCE
    new_bytes = src_path.read_bytes() + b"MOD_A_TAMPER = 999\n"
    src_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first -- isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"][f"sources/{_REPR_SOURCE}"] = hashlib.sha256(new_bytes).hexdigest()
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
            "spec_id": "build_real_compiler.v1",
            "description": "PRODUCER-SUBSTITUTED weaker spec (not auditor-anchored).",
            "types": {
                "pyc_sha": {
                    "primitive_id": "build_real_compiler_recompute",
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


_SDE_MISSING = object()


def _snapshot_sde():
    """Sentinel-tagged snapshot of SOURCE_DATE_EPOCH (distinguishes unset)."""
    return os.environ.get("SOURCE_DATE_EPOCH", _SDE_MISSING)


def test_source_date_epoch_not_leaked(tmp_path):
    """SOURCE_DATE_EPOCH is process-global; the build/verify path sets it during
    py_compile but MUST restore it afterward, or it leaks into any later code in
    the same interpreter (root cause of a vendor epoch-0 manifest corruption).

    Asserts the var is identical before/after a full build + verify cycle, for
    both the recompute path and the legacy re-derivation pack.
    """
    # Force a known prior state (unset) so a leaked "0" would be detectable.
    os.environ.pop("SOURCE_DATE_EPOCH", None)
    before = _snapshot_sde()

    # build_spec_pinned -> legacy builder (_build_bundle.build) + compute_pyc_sha.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    after_build = _snapshot_sde()
    assert after_build == before, (
        f"SOURCE_DATE_EPOCH leaked after build: {before!r} -> {after_build!r}"
    )

    # Full verify cycle (exercises compute_repr_pyc_sha_from_bundle again).
    anchor = _spc.anchor_from_committed_spec()
    _spc.make_verifier(anchor).verify(bundle_dir)
    assert _snapshot_sde() == before, (
        f"SOURCE_DATE_EPOCH leaked after verify: {before!r} -> {_snapshot_sde()!r}"
    )

    # Legacy re-derivation pack (build_py_re_derivation._verify) must also restore.
    _pack = _load(
        "build_py_re_derivation", _PILOT_DIR / "build_py_re_derivation.py"
    )
    _pack._verify(bundle_dir)
    assert _snapshot_sde() == before, (
        f"SOURCE_DATE_EPOCH leaked after legacy pack: {before!r} -> {_snapshot_sde()!r}"
    )


def test_source_date_epoch_restored_to_prior_value(tmp_path):
    """If SOURCE_DATE_EPOCH was already set to a non-zero value, the build path
    must restore THAT value, not unset it and not leave it at '0'."""
    sentinel = "1234567890"
    os.environ["SOURCE_DATE_EPOCH"] = sentinel
    try:
        bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
        assert os.environ.get("SOURCE_DATE_EPOCH") == sentinel
        _pack = _load(
            "build_py_re_derivation_restore", _PILOT_DIR / "build_py_re_derivation.py"
        )
        _pack._verify(bundle_dir)
        assert os.environ.get("SOURCE_DATE_EPOCH") == sentinel
    finally:
        os.environ.pop("SOURCE_DATE_EPOCH", None)
