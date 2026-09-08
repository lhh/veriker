"""The chain-fetched revocation root feeds the DSSE lane's revocation resolver.

`fetch_revocation_root` (the role document through the TUF chain) had no consumer.
`audit_bundle.dsse.context.build_dsse_context(revocation_root=RevocationRootTuf(...))`
now fetches it, verifies the document's own 2-of-3 Ed25519 signatures, pins the
list signer, and hands the resolver to `load_revocation_list`; the shipped CLI
reaches it with `--dsse-revocation-root-tuf`. Everything here drives the CLI in a
subprocess against a REAL served toy repository (python-tuf ngclient). Skips
without python-tuf.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

pytest.importorskip("tuf")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from audit_bundle.extensions import c18_tuf_client as tc  # noqa: E402
from tests.c18.test_c18_tuf_protocol import _role_targets, role_docs  # noqa: E402
from tests.fixtures.dsse_trust_material import (  # noqa: E402
    NOW,
    RevocationRootKeys,
    revocation_root_document,
    sealed_bundle,
    write_material,
)
from tests.fixtures.tuf_toy_repo import GOOD_IMAGE_DIGEST, ToyTUFRepo, serve  # noqa: E402

if sys.platform == "win32":
    from tests.fixtures import tuf_winshim

    tuf_winshim.install()

_CLI = _PKG_ROOT / "veriker" / "cli" / "verify.py"


def _serve_with_root(tmp_path: Path, root_doc: dict):
    docs = role_docs()
    docs["revocation-root"] = root_doc
    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_IMAGE_DIGEST, extra_targets=_role_targets(docs))
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    return root_path, base, httpd


def _run(tmp_path: Path, bundle: Path, paths, base: str, root_path: Path):
    face_path = tmp_path / "face.json"
    env = dict(
        os.environ,
        PYTHONDONTWRITEBYTECODE="1",
        # The subprocess must trust the toy repository's root, not the bundled
        # bootstrap root: point the embedded-root constant at it via sitecustomize.
        PYTHONPATH=str(tmp_path / "site")
        + os.pathsep
        + os.environ.get("PYTHONPATH", ""),
    )
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    (site / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        "import audit_bundle.extensions.c18_tuf_client as tc\n"
        f"tc._EMBEDDED_ROOT_PATH = Path({str(root_path)!r})\n"
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(_CLI),
            "--bundle-dir",
            str(bundle),
            "--verdict-out",
            str(face_path),
            "--dsse-allowlist",
            str(paths["allowlist"]),
            "--dsse-revocation-list",
            str(paths["list"]),
            "--dsse-revocation-root-tuf",
            str(tmp_path / "trust_dir"),
            "--dsse-tuf-feed-url",
            base,
            "--dsse-now",
            str(NOW),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
        env=env,
        timeout=180,
        check=False,
    )
    face = json.loads(face_path.read_text()) if face_path.exists() else {}
    return proc.returncode, face, proc.stdout, proc.stderr


@pytest.fixture()
def material(tmp_path):
    keys = RevocationRootKeys.generate()
    signer = Ed25519PrivateKey.generate()
    bundle = tmp_path / "bundle"
    sealed_bundle(bundle, signer)
    paths = write_material(tmp_path / "trust", keys, signer)
    return keys, signer, bundle, paths


def test_T1_chain_fetched_root_feeds_the_resolver_and_the_lane_passes(
    tmp_path, material
) -> None:
    keys, signer, bundle, paths = material
    root_path, base, httpd = _serve_with_root(tmp_path, revocation_root_document(keys))
    try:
        rc, face, out, err = _run(tmp_path, bundle, paths, base, root_path)
    finally:
        httpd.shutdown()
    assert rc == 0, (out, err)
    prov = "\n".join(
        {g["gate"]: g for g in face["cli_gates"]}["dsse_context"]["provenance"]
    )
    assert "revocation root: TUF chain" in prov
    assert base in prov
    assert "pinned_list_signer=" + keys.pinned_keyid in prov


def test_T2_expired_root_on_the_feed_is_refused_before_any_verdict(
    tmp_path, material
) -> None:
    keys, signer, bundle, paths = material
    root_path, base, httpd = _serve_with_root(
        tmp_path, revocation_root_document(keys, expires_in_days=-1)
    )
    try:
        rc, face, out, err = _run(tmp_path, bundle, paths, base, root_path)
    finally:
        httpd.shutdown()
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "TUFRootExpired" in err
    assert face["verdict"] is None  # no verdict about the bundle was formed


def test_T3_under_signed_root_on_the_feed_is_refused(tmp_path, material) -> None:
    """TUF authenticates the bytes; the role's own 2-of-3 is verified at the
    consumer. One valid signature rides the chain and is still refused."""
    keys, signer, bundle, paths = material
    root_path, base, httpd = _serve_with_root(
        tmp_path, revocation_root_document(keys, sign_with=(0,))
    )
    try:
        rc, face, out, err = _run(tmp_path, bundle, paths, base, root_path)
    finally:
        httpd.shutdown()
    assert rc == 2, (out, err)
    assert "TUFRevocationRootSignatureInvalid" in err


def test_T4_unpinned_list_signer_on_the_feed_is_refused(tmp_path, material) -> None:
    keys, signer, bundle, paths = material
    root_path, base, httpd = _serve_with_root(
        tmp_path, revocation_root_document(keys, list_pinned_signer_under_keys=False)
    )
    try:
        rc, face, out, err = _run(tmp_path, bundle, paths, base, root_path)
    finally:
        httpd.shutdown()
    assert rc == 2, (out, err)
    assert "TUFRevocationRootSignerUnpinned" in err


def test_T5_resolver_from_a_fetched_document_admits_only_the_pinned_signer(
    tmp_path, monkeypatch
) -> None:
    keys = RevocationRootKeys.generate()
    root_path, base, httpd = _serve_with_root(tmp_path, revocation_root_document(keys))
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        fetched = tc.fetch_revocation_root(
            feed_url=base, trust_dir=tmp_path / "trust_dir"
        )
    finally:
        httpd.shutdown()
    resolver, prov = tc.revocation_root_resolver_from_document(
        fetched["document"], source=fetched["authenticated_by"]
    )
    assert (
        resolver(keys.pinned_keyid) == keys.list_signer.public_key().public_bytes_raw()
    )
    for sk in keys.root:
        kid = (
            __import__("hashlib").sha256(sk.public_key().public_bytes_raw()).hexdigest()
        )
        with pytest.raises(KeyError, match="not the pinned"):
            resolver(kid)
    assert len(prov["signed_by"].split(",")) == 2
