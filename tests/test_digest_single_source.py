"""One sha256 helper for files and bytes — and the ratchet that keeps it one.

Five ``sha256_file`` definitions in three shapes; the orchestrator's returned
the digest of the empty string for an ABSENT file, so a missing artifact
agreed with any manifest declaring the empty digest. `audit_bundle.digest`
streams and raises on absence; absence is the caller's verdict.


"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.digest import sha256_bytes, sha256_file  # noqa: E402

EMPTY = hashlib.sha256(b"").hexdigest()


def test_streamed_digest_equals_one_shot_digest(tmp_path: Path):
    p = tmp_path / "big.bin"
    data = bytes(range(256)) * 1000  # 256 KB, crosses the chunk boundary
    p.write_bytes(data)
    assert sha256_file(p) == hashlib.sha256(data).hexdigest() == sha256_bytes(data)
    p.write_bytes(b"")
    assert sha256_file(p) == EMPTY


def test_absent_file_raises_and_never_digests_to_empty(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        sha256_file(tmp_path / "missing.bin")
    with pytest.raises(OSError):
        sha256_file(tmp_path)  # a directory is not a file


def test_every_verifier_side_helper_is_the_single_source():
    from audit_bundle import bundle_manifest, verifier
    from audit_bundle.emitter import pipeline
    from audit_bundle.extensions import c18_verifier_identity as c18
    from audit_bundle.rederivation import spec_binding

    assert bundle_manifest._sha256_file is sha256_file
    assert spec_binding._sha256_file is sha256_file
    assert c18._file_sha256 is sha256_file
    assert verifier._sha256_bytes is sha256_bytes
    assert pipeline.sha256(b"x") == sha256_bytes(b"x")


def test_orchestrator_absent_artifact_is_not_a_digest(tmp_path: Path):
    """The fail-open shape: the old local helper returned EMPTY for any missing
    path. The shared helper raises; the one caller that legitimately means
    'no events file => empty digest' now says so at the call site."""
    orch = pytest.importorskip("audit_bundle.orchestrator_turn.verifier")
    assert orch._sha256_file is sha256_file
    with pytest.raises(FileNotFoundError):
        orch._sha256_file(tmp_path / "prompt.txt")


# --- ratchet: no sixth definition ---

_HELPER_NAMES = {
    "sha256_file",
    "_sha256_file",
    "file_sha256",
    "_file_sha256",
    "sha256_bytes",
    "_sha256_bytes",
    "sha256_hex",
    "_sha256_hex",
    "_sha256",
}
#: files allowed to define one of those names besides the single source
ALLOWED_DEFINERS: dict[str, str] = {
    "audit_bundle/plugins/reference/control_rederivation.py": "standalone pack; sha256_file pinned to control by test_reference_pack_parity",
    "audit_bundle/plugins/reference/aigov_rederivation.py": "standalone pack; pinned copy",
}
_SOURCE = "audit_bundle/digest.py"


def test_no_sixth_sha256_helper():
    seen: dict[str, list[str]] = {}
    for path in sorted((_PKG_ROOT / "audit_bundle").rglob("*.py")):
        rel = path.relative_to(_PKG_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = [
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name in _HELPER_NAMES
        ]
        if names:
            seen[rel] = names
    assert _SOURCE in seen, (
        "the single source defines no helper — the ratchet measures nothing"
    )
    strays = {
        k: v for k, v in seen.items() if k != _SOURCE and k not in ALLOWED_DEFINERS
    }
    assert not strays, (
        f"a new sha256 helper definition — import audit_bundle.digest instead: {strays}"
    )
