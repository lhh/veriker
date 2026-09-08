"""`host_digest_verify` reaches its Rekor log key through the `sigstore-trust-root` role.

Until this battery existed the host-side Rekor leg verified the log checkpoint
against a compile-time constant (`REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM`) and the
`sigstore-trust-root` role — the ceremony-filled document that pins Sigstore's key
DIGESTS — had no consumer. The role holds digests, not bytes, so the key bytes are
themselves TUF targets (`sigstore-trust-root/keys/<entry>`): fetched through the same
chain, hash-pinned by the targets metadata, AND required to hash to the digest the
role document declares. That second pin is the one the ceremony writes.

Everything here drives the SHIPPED CLI (`host_digest_verify.main`) against a REAL
served toy TUF repository (python-tuf's own ngclient), with only cosign / crane
mocked to report the toy's image digest. The Rekor bundle is the synthetic
image-binding shape signed by the key the role pins.

Skips cleanly without python-tuf (the dev interpreter has none; the declared
dependency means CI and consumers do).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

pytest.importorskip("tuf")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

from audit_bundle.extensions import c18_tuf_client as tc  # noqa: E402
from veriker.cli import host_digest_verify  # noqa: E402
from tests.c18.test_c18_tuf_protocol import (  # noqa: E402
    _role_targets,
    role_docs,
    sign_role_docs,
)
from tests.c18.test_release_image_binding_bundle import (  # noqa: E402
    _log_id_b64,
    IMAGE_DIGEST,
    _statement,
    image_binding_bundle,
)
from tests.fixtures.tuf_toy_repo import ToyTUFRepo, serve  # noqa: E402

if sys.platform == "win32":
    from tests.fixtures import tuf_winshim

    tuf_winshim.install()


def _pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _served(
    tmp_path: Path, *, docs, key_targets: dict[str, bytes] | None, key_payload_type=None
):
    repo = ToyTUFRepo(tmp_path / "repo")
    if docs is not None:
        sign_role_docs(docs)  # after every _pin: the strict fetch verifies the 2-of-3
    extra = _role_targets(docs) if docs is not None else {}
    for entry, pem in (key_targets or {}).items():
        extra[tc.sigstore_trust_root_key_target_name(entry)] = (
            pem,
            key_payload_type or tc.SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE,
        )
    repo.build(image_digest=IMAGE_DIGEST, extra_targets=extra)
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    return repo, root_path, base, httpd


def _pin(
    docs, entry: str, pem: bytes, *, key_type: str = "ecdsa-public-key-pem"
) -> None:
    docs["sigstore-trust-root"]["signed"]["targets"][entry] = {
        "purpose": "test log key",
        "upstream_url": "(test)",
        "expected_sha256_at_v0_3_cut": "sha256:" + hashlib.sha256(pem).hexdigest(),
        "type": key_type,
    }


def _run(tmp_path: Path, base: str, bundle: dict, *extra_args: str) -> int:
    path = tmp_path / "image-binding.sigstore-bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    with (
        patch.object(host_digest_verify, "_which", side_effect=lambda b: f"/bin/{b}"),
        patch.object(
            host_digest_verify,
            "_run_cosign_manifest",
            return_value=(True, IMAGE_DIGEST, ""),
        ),
        patch.object(
            host_digest_verify,
            "_run_crane_digest",
            return_value=(True, IMAGE_DIGEST, ""),
        ),
    ):
        return host_digest_verify.main(
            [
                "--release",
                "v0.3.0",
                "--tuf-trust-bundle",
                str(tmp_path / "trust"),
                "--tuf-feed-url",
                base,
                "--rekor-bundle",
                str(path),
                *extra_args,
            ]
        )


@pytest.fixture()
def log_sk():
    return ec.generate_private_key(ec.SECP256R1())


def test_K1_key_resolved_from_the_role_through_the_chain_reaches_exit_0(
    tmp_path, monkeypatch, capsys, log_sk
) -> None:
    docs = role_docs()
    _pin(docs, "rekor.pub", _pem(log_sk))
    repo, root_path, base, httpd = _served(
        tmp_path, docs=docs, key_targets={"rekor.pub": _pem(log_sk)}
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        rc = _run(
            tmp_path, base, image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk)
        )
    finally:
        httpd.shutdown()
    out = capsys.readouterr().out
    assert rc == host_digest_verify.EXIT_OK, out
    assert "Rekor log key: sigstore-trust-root role target 'rekor.pub'" in out
    assert "ecdsa-public-key-pem" in out
    assert "sha256:" + hashlib.sha256(_pem(log_sk)).hexdigest() in out
    assert "Official (TUF):    " + IMAGE_DIGEST in out


def test_K2_role_absent_from_the_feed_is_a_typed_refusal(
    tmp_path, monkeypatch, capsys, log_sk
) -> None:
    """The plain repository carries the release manifest and no role documents:
    the digest legs pass (TUF is real), the Rekor leg refuses — never the constant."""
    repo, root_path, base, httpd = _served(tmp_path, docs=None, key_targets=None)
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        rc = _run(
            tmp_path, base, image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk)
        )
    finally:
        httpd.shutdown()
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_LOG_KEY_UNRESOLVED" in err


def test_K3_role_digest_disagreeing_with_the_served_key_is_refused(
    tmp_path, monkeypatch, capsys, log_sk
) -> None:
    """The served key bytes are hash-pinned by the targets metadata (they ARE what
    the feed signed); the ROLE says another digest. The role's pin is the ceremony's
    authority, so the disagreement refuses."""
    docs = role_docs()
    _pin(docs, "rekor.pub", b"-----BEGIN PUBLIC KEY-----\nsomething else\n")
    repo, root_path, base, httpd = _served(
        tmp_path, docs=docs, key_targets={"rekor.pub": _pem(log_sk)}
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        rc = _run(
            tmp_path, base, image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk)
        )
    finally:
        httpd.shutdown()
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_LOG_KEY_DIGEST_MISMATCH" in err


def test_K4_role_type_disagreeing_with_the_loaded_key_is_refused(
    tmp_path, monkeypatch, capsys, log_sk
) -> None:
    docs = role_docs()
    _pin(docs, "rekor.pub", _pem(log_sk), key_type="ed25519-public-key-pem")
    repo, root_path, base, httpd = _served(
        tmp_path, docs=docs, key_targets={"rekor.pub": _pem(log_sk)}
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        rc = _run(
            tmp_path, base, image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk)
        )
    finally:
        httpd.shutdown()
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_LOG_KEY_TYPE_MISMATCH" in err


def test_K5_an_entry_the_role_does_not_name_is_refused(
    tmp_path, monkeypatch, capsys, log_sk
) -> None:
    docs = role_docs()
    _pin(docs, "rekor.pub", _pem(log_sk))
    repo, root_path, base, httpd = _served(
        tmp_path,
        docs=docs,
        key_targets={"rekor.pub": _pem(log_sk), "rekor-v2.pub": _pem(log_sk)},
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        rc = _run(
            tmp_path,
            base,
            image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk),
            "--rekor-log-key-target",
            "rekor-v2.pub",
        )
    finally:
        httpd.shutdown()
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_LOG_KEY_UNRESOLVED" in err
    assert "rekor-v2.pub" in err


def test_K6_ed25519_v2_key_pins_under_its_own_entry(
    tmp_path, monkeypatch, capsys
) -> None:
    """A Rekor v2 (Ed25519) log key is a SEPARATE entry with its own type; the
    operator selects it. The checkpoint under that key verifies (Ed25519 hint)."""

    v2_sk = ed25519.Ed25519PrivateKey.generate()
    docs = role_docs()
    _pin(docs, "rekor-v2.pub", _pem(v2_sk), key_type="ed25519-public-key-pem")
    repo, root_path, base, httpd = _served(
        tmp_path, docs=docs, key_targets={"rekor-v2.pub": _pem(v2_sk)}
    )
    # An Ed25519-signed one-leaf checkpoint (c2sp hint over the origin name).
    import base64

    from audit_bundle.extensions import rekor_anchor

    payload = _statement(IMAGE_DIGEST[7:])
    bundle = image_binding_bundle(payload, ec.generate_private_key(ec.SECP256R1()))
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    root = base64.b64decode(entry["inclusionProof"]["rootHash"])
    origin = "log2025.test - 1"
    body = f"{origin}\n1\n{base64.b64encode(root).decode()}\n"
    sig = v2_sk.sign(body.encode())
    hint = rekor_anchor.rekor_key_hint(v2_sk.public_key(), origin.split(" ")[0])
    # The entry names the v2 log it came from (c2sp key id; leads with the hint).
    entry["logId"]["keyId"] = _log_id_b64(v2_sk.public_key(), origin.split(" ")[0])
    entry["inclusionProof"]["checkpoint"]["envelope"] = (
        body
        + "\n— "
        + origin.split(" ")[0]
        + " "
        + base64.b64encode(hint + sig).decode()
        + "\n"
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        rc = _run(tmp_path, base, bundle, "--rekor-log-key-target", "rekor-v2.pub")
    finally:
        httpd.shutdown()
    out = capsys.readouterr().out
    assert rc == host_digest_verify.EXIT_OK, out
    assert "ed25519-public-key-pem" in out


def test_K7_key_target_under_the_role_document_payload_type_is_refused(
    tmp_path, monkeypatch
) -> None:
    docs = role_docs()
    _pin(docs, "rekor.pub", _pem(ec.generate_private_key(ec.SECP256R1())))
    pem = _pem(ec.generate_private_key(ec.SECP256R1()))
    _pin(docs, "rekor.pub", pem)
    repo, root_path, base, httpd = _served(
        tmp_path,
        docs=docs,
        key_targets={"rekor.pub": pem},
        key_payload_type=tc.ROLE_TARGET_PAYLOAD_TYPES[tc.ROLE_SIGSTORE_TRUST_ROOT],
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFTargetUnknownPayloadType):
            tc.fetch_sigstore_trust_root_key(
                "rekor.pub", feed_url=base, trust_dir=tmp_path / "trust"
            )
    finally:
        httpd.shutdown()


def test_K8_fetched_key_envelope_names_its_provenance(
    tmp_path, monkeypatch, log_sk
) -> None:
    docs = role_docs()
    _pin(docs, "rekor.pub", _pem(log_sk))
    repo, root_path, base, httpd = _served(
        tmp_path, docs=docs, key_targets={"rekor.pub": _pem(log_sk)}
    )
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        got = tc.fetch_sigstore_trust_root_key(
            "rekor.pub", feed_url=base, trust_dir=tmp_path / "trust"
        )
    finally:
        httpd.shutdown()
    assert got["key_bytes"] == _pem(log_sk)
    assert got["entry"] == "rekor.pub"
    assert got["declared_type"] == "ecdsa-public-key-pem"
    assert (
        got["declared_sha256"] == "sha256:" + hashlib.sha256(_pem(log_sk)).hexdigest()
    )
    assert got["target_name"] == "sigstore-trust-root/keys/rekor.pub"
    assert "TUF chain" in got["authenticated_by"]
    assert "role document digest" in got["authenticated_by"]
