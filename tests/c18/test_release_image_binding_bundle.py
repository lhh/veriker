"""The release's image-binding bundle satisfies `host_digest_verify --rekor-bundle`.

The release job emits `v-kernel-audit-bundle-<ver>.image-binding.sigstore-bundle.json`:
`cosign attest-blob --new-bundle-format --bundle` over the OCI image MANIFEST bytes.
The image digest IS sha256 of those bytes, so the in-toto Statement's
`subject[0].digest.sha256` is the image digest — the one value the host-side
verifier holds (from TUF) and requires the logged Rekor entry to commit to.

Before that artifact existed no file the job shipped could satisfy the binding:
`sign-blob` bundles commit to an SBOM / provenance / statement digest, and the
image signature + attestations live in the registry with no local bundle, so the
honest host-side check exited 7 on every real release.

This battery is SYNTHETIC by necessity (the live cosign call needs Fulcio + Rekor):
it builds a Sigstore v0.3 bundle of the EXACT shape cosign emits for that command —
a `dsse` v0.0.1 Rekor body whose `payloadHash` is sha256 of the DSSE payload, an
in-toto v0.1 Statement with the pinned predicate type, a one-leaf tree under a test
log key — and drives the shipped CLI end to end with cosign / crane / TUF mocked to
agree on the image digest. The producer-side test (not shipped) pins its
constants to the literals below so the two shapes cannot drift.

Scope limit, stated: this proves the CONSUMER accepts the shape the job is written
to emit. Whether cosign 2.4.1 emits exactly this shape is confirmed on the first
real emission (the ceremony runbook names the fields to check); a shape drift
there fails closed here (exit 7), never open.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from veriker.cli import host_digest_verify  # noqa: E402
from tests.c18.test_host_digest_rekor_subject_binding import (  # noqa: E402
    _log_id_b64,
    _patch_key,
    _signed_checkpoint,
)

# Literals shared with the producer (its sigstore_sign module, not shipped, pins to these).
PREDICATE_TYPE = "https://vkernel.dev/predicates/release-image-binding/v1"
ARTIFACT_NAME = "v-kernel-audit-bundle-v0.3.0.image-binding.sigstore-bundle.json"
SUBJECT_NAME = "image-manifest.json"

# A plausible OCI image manifest; its sha256 IS the image digest.
IMAGE_MANIFEST = (
    b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",'
    b'"config":{"mediaType":"application/vnd.oci.image.config.v1+json",'
    b'"digest":"sha256:' + b"00" * 32 + b'","size":1},"layers":[]}'
)
IMAGE_DIGEST = "sha256:" + hashlib.sha256(IMAGE_MANIFEST).hexdigest()
OTHER = "sha256:" + "11" * 32


def _statement(subject_digest_hex: str) -> bytes:
    """The in-toto Statement cosign attest-blob wraps: v0.1 `_type`, the blob's
    name + sha256 as the single subject, our predicate type, the job's predicate."""
    return json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": PREDICATE_TYPE,
            "subject": [
                {"name": SUBJECT_NAME, "digest": {"sha256": subject_digest_hex}}
            ],
            "predicate": {
                "predicate_type": PREDICATE_TYPE,
                "release_version": "v0.3.0",
                "release_commit_sha": "0" * 40,
                "image_digest": "sha256:" + subject_digest_hex,
                "image_digest_uri": (
                    "ghcr.io/veriker/veriker@sha256:"
                    + subject_digest_hex
                ),
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def image_binding_bundle(
    payload: bytes,
    log_sk: ec.EllipticCurvePrivateKey,
    *,
    tamper_payload: bytes | None = None,
) -> dict:
    """The v0.3 bundle `cosign attest-blob --new-bundle-format --bundle` writes,
    with a one-leaf Rekor tree signed by `log_sk` standing in for the log."""
    envelope = {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{"sig": base64.b64encode(b"\x01" * 64).decode()}],
    }
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(json.dumps(envelope).encode()).hexdigest(),
            },
            "payloadHash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(payload).hexdigest(),
            },
            "signatures": [
                {"signature": envelope["signatures"][0]["sig"], "verifier": "AA=="}
            ],
        },
    }
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    from audit_bundle.extensions import rekor_anchor  # noqa: PLC0415

    root = rekor_anchor.rfc6962_leaf_hash(body_bytes)
    if tamper_payload is not None:
        envelope["payload"] = base64.b64encode(tamper_payload).decode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(b"\x30\x00").decode()},
            "tlogEntries": [
                {
                    "logIndex": "0",
                    "logId": {"keyId": _log_id_b64(log_sk.public_key())},
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                    "integratedTime": "1700000000",
                    "inclusionPromise": {"signedEntryTimestamp": "AA=="},
                    "inclusionProof": {
                        "logIndex": "0",
                        "rootHash": base64.b64encode(root).decode(),
                        "treeSize": "1",
                        "hashes": [],
                        "checkpoint": {"envelope": _signed_checkpoint(root, log_sk)},
                    },
                    "canonicalizedBody": base64.b64encode(body_bytes).decode(),
                }
            ],
        },
        "dsseEnvelope": envelope,
    }


def _run_cli(tmp_path: Path, bundle: dict, digest: str, log_sk) -> int:
    path = tmp_path / ARTIFACT_NAME
    path.write_text(json.dumps(bundle), encoding="utf-8")
    with (
        _patch_key(log_sk.public_key()),
        patch.object(host_digest_verify, "_which", side_effect=lambda b: f"/bin/{b}"),
        patch.object(
            host_digest_verify, "_run_cosign_manifest", return_value=(True, digest, "")
        ),
        patch.object(
            host_digest_verify, "_run_crane_digest", return_value=(True, digest, "")
        ),
        patch.object(
            host_digest_verify,
            "_fetch_tuf_expected_digest",
            return_value=(True, digest, ""),
        ),
    ):
        return host_digest_verify.main(
            [
                "--release",
                "v0.3.0",
                "--tuf-trust-bundle",
                str(tmp_path / "trust"),
                "--rekor-bundle",
                str(path),
            ]
        )


def test_image_manifest_digest_is_the_image_digest() -> None:
    """The premise: an attestation over the manifest bytes names the image digest."""
    assert IMAGE_DIGEST == "sha256:" + hashlib.sha256(IMAGE_MANIFEST).hexdigest()
    assert IMAGE_DIGEST != OTHER


def test_release_image_binding_bundle_reaches_exit_0(tmp_path: Path, capsys) -> None:
    log_sk = ec.generate_private_key(ec.SECP256R1())
    bundle = image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk)
    rc = _run_cli(tmp_path, bundle, IMAGE_DIGEST, log_sk)
    out = capsys.readouterr().out
    assert rc == host_digest_verify.EXIT_OK, out
    assert "commits to release image digest " + IMAGE_DIGEST in out
    assert "dsse.payloadHash->in-toto.subject" in out


def test_same_artifact_against_another_release_digest_exits_7(
    tmp_path: Path, capsys
) -> None:
    """TUF (and cosign + crane) name a different image: the honest artifact for
    release A must not verify release B."""
    log_sk = ec.generate_private_key(ec.SECP256R1())
    bundle = image_binding_bundle(_statement(IMAGE_DIGEST[7:]), log_sk)
    rc = _run_cli(tmp_path, bundle, OTHER, log_sk)
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_SUBJECT_NOT_BOUND" in err
    assert "inclusion_proof=ok checkpoint=ok subject_binding=FAILED" in err


def test_statement_swapped_after_logging_exits_7(tmp_path: Path, capsys) -> None:
    """The logged payloadHash is over the honest statement (naming OTHER); the
    shipped file carries a swapped statement naming the release digest."""
    log_sk = ec.generate_private_key(ec.SECP256R1())
    bundle = image_binding_bundle(
        _statement(OTHER[7:]), log_sk, tamper_payload=_statement(IMAGE_DIGEST[7:])
    )
    rc = _run_cli(tmp_path, bundle, IMAGE_DIGEST, log_sk)
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_DSSE_PAYLOAD_HASH_MISMATCH" in err


def test_predicate_naming_the_digest_does_not_bind(tmp_path: Path, capsys) -> None:
    """Only the in-toto SUBJECT binds. A statement whose subject is some other
    blob but whose predicate `image_digest` field names the release must not
    bind — the predicate is producer prose, never read by the binding."""
    log_sk = ec.generate_private_key(ec.SECP256R1())
    stmt = json.loads(_statement(OTHER[7:]))
    stmt["predicate"]["image_digest"] = IMAGE_DIGEST
    payload = json.dumps(stmt, separators=(",", ":"), sort_keys=True).encode()
    bundle = image_binding_bundle(payload, log_sk)
    rc = _run_cli(tmp_path, bundle, IMAGE_DIGEST, log_sk)
    err = capsys.readouterr().err
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    assert "REKOR_SUBJECT_NOT_BOUND" in err
