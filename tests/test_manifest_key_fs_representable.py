"""A manifest key the filesystem cannot hold is a malformed ARTIFACT, not a
verifier crash.

THE DEFECT (red team, 2026-09-01, pre-existing at the parent commit). A
`manifest.spec_files` key of 300 characters reached
`spec_binding.resolve_authoritative`'s `offline_copy.exists()` and raised
ENAMETOOLONG; a lone high surrogate (U+D800) in a `manifest.files` key reached
`Path.resolve()` and raised UnicodeEncodeError. Both escaped to verify()'s
fail-closed wrapper as `VERIFIER_INTERNAL_ERROR` — a could-not-conclude that
OUTRANKS every REJECT already collected. A producer could turn "the artifact
is bad" into "the verifier could not conclude" with one string in a file that
is not hash-covered. The `output_id` copy of this class was closed on
`session/work-set` (`OUTPUT_ID_UNSAFE`); these two sites were reported, not
fixed. This closes them, at the shared shape validator every parse of the
manifest runs first (`bundle_manifest._validate_field_shapes`), before any os
call can see the key — and, for every OTHER path-bearing field, at
`_safe_bundle_path`, the chokepoint they all route through (section 4).

Every cell asserts the verdict's STATE, not just its code: the property under
test is that the producer cannot move a run from REJECT to ERROR.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "corner_load_equilibrium_minimal"
for _p in (_PKG_ROOT, _PILOT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from audit_bundle.bundle_manifest import (  # noqa: E402
    MalformedManifest,
    UnsafeBundlePath,
    _safe_bundle_path,
    _validate_field_shapes,
    assert_fs_representable,
)

_CRASH_CODE = "VERIFIER_INTERNAL_ERROR"
_MALFORMED_CODE = "malformed_manifest"


def _import_from_path(name: str, path: Path):
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_mod = _import_from_path(
    "corner_load_fs_keys._build_bundle", _PILOT_DIR / "_build_bundle.py"
)


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("fs_keys_clean")
    _build_mod.build(out, "clean")
    return out


def _verify(bundle_dir: Path):
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.rederivation.kit import load_primitive_kit
    from audit_bundle.rederivation.spec_binding import SpecAnchor
    from audit_bundle.verifier import BundleVerifier

    load_primitive_kit([_PILOT_DIR / "auditor_kit.py"], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=SpecAnchor.from_files(
            [_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"],
            forbid_within=bundle_dir,
        ),
        require_rederivation=True,
    ).verify(bundle_dir)


def _manifest(bundle: Path) -> dict:
    return json.loads((bundle / "manifest.json").read_bytes())


def _write_manifest(bundle: Path, manifest: dict) -> None:
    # ensure_ascii escapes a lone surrogate as \ud800, which json.loads hands
    # back as the lone surrogate — the bytes a hostile producer would ship.
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True)
    )


def _copy(clean: Path, tmp_path: Path, name: str) -> Path:
    bundle = tmp_path / name
    shutil.copytree(clean, bundle)
    return bundle


def _codes(verdict) -> list[tuple[str, str]]:
    return [(r.check_name, r.code) for r in verdict.reasons]


def _offset_every_corner(bundle: Path, newtons: float) -> None:
    """A genuine physics REJECT, so the cells can show it is not swallowed."""
    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_text())
    loads_path.write_text(
        json.dumps([[str(float(x) + newtons) for x in row] for row in loads], indent=2)
    )
    manifest = _manifest(bundle)
    manifest["files"]["payload/corner_loads.json"] = hashlib.sha256(
        loads_path.read_bytes()
    ).hexdigest()
    _write_manifest(bundle, manifest)


# --------------------------------------------------------------------------
# 1. The two red-team witnesses, end to end
# --------------------------------------------------------------------------


def test_a_300_char_spec_files_key_is_a_reject_not_a_crash(
    clean_bundle: Path, tmp_path
) -> None:
    bundle = _copy(clean_bundle, tmp_path, "long_spec_key")
    _offset_every_corner(bundle, 15.0)
    manifest = _manifest(bundle)
    manifest["spec_files"]["x" * 300 + ".json"] = "0" * 64
    _write_manifest(bundle, manifest)

    verdict = _verify(bundle)
    assert not verdict.ok
    assert verdict.state.value == "REJECT", (verdict.state, _codes(verdict))
    assert not any(code == _CRASH_CODE for _, code in _codes(verdict)), _codes(verdict)
    assert any(code == _MALFORMED_CODE for _, code in _codes(verdict)), _codes(verdict)


def test_a_lone_surrogate_files_key_is_a_reject_not_a_crash(
    clean_bundle: Path, tmp_path
) -> None:
    bundle = _copy(clean_bundle, tmp_path, "surrogate_files_key")
    _offset_every_corner(bundle, 15.0)
    manifest = _manifest(bundle)
    manifest["files"]["payload/\ud800.json"] = "0" * 64
    _write_manifest(bundle, manifest)

    verdict = _verify(bundle)
    assert not verdict.ok
    assert verdict.state.value == "REJECT", (verdict.state, _codes(verdict))
    assert not any(code == _CRASH_CODE for _, code in _codes(verdict)), _codes(verdict)
    assert any(code == _MALFORMED_CODE for _, code in _codes(verdict)), _codes(verdict)


def test_an_embedded_nul_in_a_files_key_is_a_reject_not_a_crash(
    clean_bundle: Path, tmp_path
) -> None:
    """The third member of the class: `Path("a\\x00b").resolve()` raises
    ValueError, which is not an OSError and is not caught anywhere below."""
    bundle = _copy(clean_bundle, tmp_path, "nul_files_key")
    manifest = _manifest(bundle)
    manifest["files"]["payload/a\x00b.json"] = "0" * 64
    _write_manifest(bundle, manifest)

    verdict = _verify(bundle)
    assert verdict.state.value == "REJECT", (verdict.state, _codes(verdict))
    assert not any(code == _CRASH_CODE for _, code in _codes(verdict)), _codes(verdict)


# --------------------------------------------------------------------------
# 2. Inertness controls — the guard bounds representability, nothing else
# --------------------------------------------------------------------------


def test_a_255_byte_component_that_is_merely_missing_is_the_old_reject(
    clean_bundle: Path, tmp_path
) -> None:
    """At the bound, not past it: a name the filesystem CAN hold but which is
    absent must still be the file-integrity REJECT it always was, never
    malformed_manifest — otherwise the guard has moved from 'unrepresentable'
    to 'unusual', which is a different and wrong claim."""
    bundle = _copy(clean_bundle, tmp_path, "at_the_bound")
    manifest = _manifest(bundle)
    manifest["files"]["payload/" + "y" * 250 + ".json"] = "0" * 64  # 255 bytes
    _write_manifest(bundle, manifest)

    verdict = _verify(bundle)
    assert verdict.state.value == "REJECT", (verdict.state, _codes(verdict))
    codes = [code for _, code in _codes(verdict)]
    assert _MALFORMED_CODE not in codes, codes
    assert _CRASH_CODE not in codes, codes


def test_a_non_ascii_but_encodable_key_is_admitted(
    clean_bundle: Path, tmp_path
) -> None:
    """The refusal is about the filesystem ENCODING, not about ASCII. A real
    file under a real UTF-8 name verifies exactly as before."""
    bundle = _copy(clean_bundle, tmp_path, "utf8_key")
    rel = "payload/résumé_ünïcode.json"
    target = bundle / rel
    target.write_bytes(b'{"note": "extra, hash-covered"}\n')
    manifest = _manifest(bundle)
    manifest["files"][rel] = hashlib.sha256(target.read_bytes()).hexdigest()
    _write_manifest(bundle, manifest)

    verdict = _verify(bundle)
    codes = [code for _, code in _codes(verdict)]
    assert _MALFORMED_CODE not in codes, codes
    assert _CRASH_CODE not in codes, codes
    assert verdict.ok, codes


# --------------------------------------------------------------------------
# 3. The helper, in isolation, both directions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "x" * 256,
        "ok/" + "x" * 256 + "/ok",
        "payload/\ud800.json",
        "payload/\udfff.json",
        "a\x00b",
    ],
)
def test_helper_refuses_unrepresentable_keys(key: str) -> None:
    with pytest.raises(MalformedManifest):
        assert_fs_representable(key, where="manifest.files key")
    with pytest.raises(MalformedManifest):
        _validate_field_shapes({key: "0" * 64}, None, None, None)
    with pytest.raises(MalformedManifest):
        _validate_field_shapes(None, {key: "0" * 64}, None, None)


@pytest.mark.parametrize(
    "key",
    [
        "x" * 255,
        "a/" + "x" * 255 + "/b",
        "payload/résumé.json",
        "payload/日本語.json",
        "outputs/x.json",
        "",  # containment and object-type are policed downstream, not here
    ],
)
def test_helper_admits_representable_keys(key: str) -> None:
    assert_fs_representable(key, where="manifest.files key")
    _validate_field_shapes({key: "0" * 64}, {key: "0" * 64}, None, None)


def test_helper_names_the_field_and_the_reason() -> None:
    with pytest.raises(MalformedManifest, match=r"manifest\.spec_files.*255"):
        assert_fs_representable("x" * 300, where="manifest.spec_files key")
    with pytest.raises(MalformedManifest, match=r"manifest\.files.*encod"):
        assert_fs_representable("\ud800", where="manifest.files key")
    with pytest.raises(MalformedManifest, match=r"manifest\.files.*NUL"):
        assert_fs_representable("a\x00b", where="manifest.files key")


# --------------------------------------------------------------------------
# 4. The chokepoint — every OTHER path-bearing field
# --------------------------------------------------------------------------
# The red team named two fields. Asking which of `_safe_bundle_path`'s callers
# the parse-boundary check did NOT cover found the rest of the class:
# `decision_provenance_log`, `retrieval_trace_log`, `snapshots` values, the
# source_attributes logs, obligation URIs, cross_refs targets, append-only
# paths all route through the chokepoint, whose `except OSError` catches
# ENAMETOOLONG from lstat but not the UnicodeEncodeError / ValueError that
# `.resolve()` raises first. Measured 2026-09-02: a lone surrogate in
# `decision_provenance_log` -> VERIFIER_INTERNAL_ERROR with only the
# parse-boundary guard in place. So the guard lives in the chokepoint too.
# The long-name case is NOT a witness for the chokepoint copy (lstat's
# OSError already covered it); the surrogate and NUL cells are.


@pytest.mark.parametrize(
    "value, kind",
    [
        ("payload/\ud800.jsonl", "surrogate"),
        ("payload/a\x00b.jsonl", "nul"),
        ("x" * 300, "long"),
    ],
)
def test_a_hostile_decision_provenance_log_path_is_a_reject_not_a_crash(
    clean_bundle: Path, tmp_path, value: str, kind: str
) -> None:
    bundle = _copy(clean_bundle, tmp_path, f"prov_{kind}")
    _offset_every_corner(bundle, 15.0)
    manifest = _manifest(bundle)
    manifest["decision_provenance_log"] = value
    _write_manifest(bundle, manifest)

    verdict = _verify(bundle)
    assert verdict.state.value == "REJECT", (verdict.state, _codes(verdict))
    codes = [code for _, code in _codes(verdict)]
    assert _CRASH_CODE not in codes, codes
    assert "UnsafeBundlePath" in codes, codes


@pytest.mark.parametrize("key", ["\ud800", "a\x00b", "x" * 256, "d/" + "x" * 256])
def test_the_chokepoint_refuses_before_it_resolves(tmp_path, key: str) -> None:
    with pytest.raises(UnsafeBundlePath, match="manifest path"):
        _safe_bundle_path(tmp_path, key)


def test_the_chokepoint_still_passes_a_representable_absent_path(tmp_path) -> None:
    """Absence is the caller's concern; the chokepoint must hand a
    representable-but-missing path through unchanged, as its contract says."""
    out = _safe_bundle_path(tmp_path, "sub/" + "y" * 255)
    assert out == (tmp_path / "sub" / ("y" * 255)).resolve()


# --------------------------------------------------------------------------
# 5. The bound is stated in the HOST's unit
# --------------------------------------------------------------------------


def test_the_length_bound_counts_in_the_host_filesystems_unit() -> None:
    """NTFS holds 255 UTF-16 units; ext4/APFS hold 255 bytes. A 255-character
    CJK name is 255 units and 765 UTF-8 bytes: a name Windows holds and no
    POSIX filesystem does. Counting bytes everywhere rejected an honest
    Windows bundle (fresh-context pass, 2026-09-02). An 85-character CJK name
    is 255 bytes and 85 units, admitted on both."""
    import os

    cjk = "\u65e5"
    assert_fs_representable(cjk * 85, where="manifest.files key")
    if os.name == "nt":
        assert_fs_representable(cjk * 255, where="manifest.files key")
        with pytest.raises(MalformedManifest, match="256 UTF-16 units"):
            assert_fs_representable(cjk * 256, where="manifest.files key")
    else:
        with pytest.raises(MalformedManifest, match="765 bytes"):
            assert_fs_representable(cjk * 255, where="manifest.files key")
        with pytest.raises(MalformedManifest, match="258 bytes"):
            assert_fs_representable(cjk * 86, where="manifest.files key")
