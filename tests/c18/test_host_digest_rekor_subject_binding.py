"""The Rekor leg of `host_digest_verify` must bind the LOGGED LEAF to the RELEASE.

Before this battery existed, `_verify_rekor_inclusion` took the leaf preimage straight
out of the supplied Sigstore bundle, re-derived the RFC 6962 proof, verified the
checkpoint signature against the pinned log key, and returned `ok=True` — having proved
only "these bytes are in the public log". Any genuine public entry satisfies that; the
repo's own positive test fed a third party's entry (logIndex 250000000) and asserted ok.

The fix: the verifier holds the release image digest (from TUF, already equal to the
cosign + crane digests by the time the Rekor leg runs) and the Rekor body must COMMIT
to it, by entry kind (hashedrekord data digest, or dsse/intoto payload → in-toto
subject). Nothing read from the bundle enters the expected set. The binding
failure is a DISTINCT reason from a proof failure so the flip is attributable.

Positive bytes:
  * `sigstore_staging_bundle_v0_3.json` — a real Sigstore STAGING hashedrekord v0.0.2
    entry; the staging log key comes from `sigstore_staging_trust_anchors.json`
    (also captured from the public staging TUF root). This is the first test in the
    tree that evaluates the staging CHECKPOINT leg at all.
  * a synthetic dsse entry over a one-leaf tree signed by a test P-256 key (the dsse
    positive cannot be real bytes: the only real dsse fixture is somebody else's entry).
Negative bytes:
  * `rekor_real_entry_v1.json` — the real third-party production entry; both legs
    verify, and the verdict must still be NOT ok because nothing binds it to us.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.extensions import rekor_anchor  # noqa: E402
from veriker.cli import host_digest_verify  # noqa: E402

_FIX = _PKG_ROOT / "tests" / "fixtures"
_REAL_PROD = _FIX / "rekor_real_entry_v1.json"
_STAGING_BUNDLE = _FIX / "sigstore_staging_bundle_v0_3.json"
_STAGING_ANCHORS = _FIX / "sigstore_staging_trust_anchors.json"

OTHER = "sha256:" + "11" * 32


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _third_party_prod_bundle() -> dict:
    """The real production dsse entry re-wrapped in a v0.3 bundle envelope (no payload)."""
    fx = json.loads(_REAL_PROD.read_text(encoding="utf-8"))
    response = fx["response"]
    entry = response[next(iter(response))]
    ip = entry["verification"]["inclusionProof"]
    b64 = lambda h: base64.b64encode(bytes.fromhex(h)).decode("ascii")  # noqa: E731
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": str(ip["logIndex"]),
                    "logId": {"keyId": b64(entry["logID"])},
                    "integratedTime": str(entry["integratedTime"]),
                    "inclusionProof": {
                        "logIndex": str(ip["logIndex"]),
                        "rootHash": b64(ip["rootHash"]),
                        "treeSize": str(ip["treeSize"]),
                        "hashes": [b64(h) for h in ip["hashes"]],
                        "checkpoint": {"envelope": ip["checkpoint"]},
                    },
                    "canonicalizedBody": entry["body"],
                }
            ]
        },
    }


def _staging_bundle() -> dict:
    return json.loads(_STAGING_BUNDLE.read_text(encoding="utf-8"))


def _staging_log_key() -> ec.EllipticCurvePublicKey:
    anchors = json.loads(_STAGING_ANCHORS.read_text(encoding="utf-8"))
    bundle = _staging_bundle()
    log_id_hex = base64.b64decode(
        bundle["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"]
    ).hex()
    for tlog in anchors["rekor_tlogs"]:
        if tlog["log_id_hex"] == log_id_hex:
            return rekor_anchor.load_rekor_log_public_key(
                tlog["key_pem"].encode("utf-8")
            )
    raise AssertionError(f"staging anchors carry no key for log_id {log_id_hex}")


def _staging_subject() -> str:
    ms = _staging_bundle()["messageSignature"]["messageDigest"]
    return "sha256:" + base64.b64decode(ms["digest"]).hex()


def _patch_key(key):
    """Inject the Rekor log key the CLI would otherwise resolve from the
    sigstore-trust-root role (tests/c18/test_host_digest_rekor_key_from_role.py
    drives that resolution for real); main() must never read a constant."""
    return patch.object(
        host_digest_verify,
        "_resolve_rekor_log_key",
        return_value=host_digest_verify.RekorLogKeyResolution(
            key, "test-injected log key", None, ""
        ),
    )


def _log_id_b64(log_pk, name: str | None = None) -> str:
    """The entry's `logId.keyId` for the log `log_pk` signs for. Rekor v1 (P-256):
    sha256 of the DER SubjectPublicKeyInfo. Rekor v2 (Ed25519): the c2sp key id
    `SHA256(name ‖ "\n" ‖ 0x01 ‖ raw)` over the checkpoint origin `name`. Either
    way its leading 4 bytes are the checkpoint key-hint, which `verify_anchor`
    binds (measured on the real staging v2 fixture: logId d3d3a70c…, hint
    d3d3a70c)."""
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415

    if isinstance(log_pk, ed25519.Ed25519PublicKey):
        assert name is not None, "a v2 log id needs the checkpoint origin name"
        raw = log_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.b64encode(
            hashlib.sha256(name.encode() + b"\n" + b"\x01" + raw).digest()
        ).decode()
    der = log_pk.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def _signed_checkpoint(root: bytes, log_sk: ec.EllipticCurvePrivateKey) -> str:
    origin = "vkernel.test - 1"
    body = f"{origin}\n1\n{base64.b64encode(root).decode()}\n"
    sig = log_sk.sign(body.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    hint = rekor_anchor.rekor_key_hint(log_sk.public_key())
    sigline = f"— {origin.split(' ')[0]} {base64.b64encode(hint + sig).decode()}"
    return body + "\n" + sigline + "\n"


def _intoto_statement(subject_digest_hex: str) -> bytes:
    return json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "ghcr.io/veriker/veriker",
                    "digest": {"sha256": subject_digest_hex},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _synthetic_dsse_bundle(
    payload: bytes,
    log_sk: ec.EllipticCurvePrivateKey,
    *,
    body_payload_hash: str | None = None,
    include_payload: bool = True,
) -> dict:
    """A one-leaf Rekor tree whose leaf is a dsse v0.0.1 body over `payload`."""
    ph = body_payload_hash or hashlib.sha256(payload).hexdigest()
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": "00" * 32},
            "payloadHash": {"algorithm": "sha256", "value": ph},
            "signatures": [{"signature": "AA==", "verifier": "AA=="}],
        },
    }
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    root = rekor_anchor.rfc6962_leaf_hash(body_bytes)
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": "0",
                    "logId": {"keyId": _log_id_b64(log_sk.public_key())},
                    "integratedTime": "1700000000",
                    "inclusionProof": {
                        "logIndex": "0",
                        "rootHash": base64.b64encode(root).decode(),
                        "treeSize": "1",
                        "hashes": [],
                        "checkpoint": {"envelope": _signed_checkpoint(root, log_sk)},
                    },
                    "canonicalizedBody": base64.b64encode(body_bytes).decode(),
                }
            ]
        },
    }
    if include_payload:
        bundle["dsseEnvelope"] = {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "AA=="}],
        }
    return bundle


def _write(tmp_path: Path, bundle: dict) -> Path:
    p = tmp_path / "release.sigstore-bundle.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1. the attack: a stranger's genuine entry must NOT verify our release
# ---------------------------------------------------------------------------


def test_third_party_production_entry_is_not_bound(tmp_path: Path) -> None:
    """Both cryptographic legs pass on the real entry; the verdict is still NOT ok,
    and the reason is the BINDING, not the proof — so the flip is attributable."""
    path = _write(tmp_path, _third_party_prod_bundle())
    res = host_digest_verify._verify_rekor_inclusion(
        path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=rekor_anchor.load_rekor_log_public_key()
    )
    assert res.err == ""
    assert res.inclusion_ok is True
    assert res.checkpoint_ok is True
    assert res.ok is False
    # The real entry is a dsse kind and the fixture carries no payload: it cannot bind.
    assert res.reasons == ("REKOR_DSSE_PAYLOAD_ABSENT",)
    assert res.bound_to is None


def test_third_party_entry_with_forged_payload_naming_our_digest(
    tmp_path: Path,
) -> None:
    """Attach a forged in-toto statement that names OUR digest beside the stranger's
    honest log entry. The logged payloadHash is over THEIR statement, so the forgery
    is refused as a hash mismatch — never as a bound subject."""
    bundle = _third_party_prod_bundle()
    bundle["dsseEnvelope"] = {
        "payload": base64.b64encode(_intoto_statement(OTHER[7:])).decode(),
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{"sig": "AA=="}],
    }
    path = _write(tmp_path, bundle)
    res = host_digest_verify._verify_rekor_inclusion(
        path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=rekor_anchor.load_rekor_log_public_key()
    )
    assert res.inclusion_ok is True and res.checkpoint_ok is True
    assert res.ok is False
    assert res.reasons == ("REKOR_DSSE_PAYLOAD_HASH_MISMATCH",)
    assert res.bound_to is None


def test_third_party_entry_binding_failure_reaches_exit_7(
    tmp_path: Path, capsys
) -> None:
    """End to end: mocked cosign/crane/TUF all agree on OTHER; a stranger's bundle → 7."""
    path = _write(tmp_path, _third_party_prod_bundle())
    with (
        _patch_key(rekor_anchor.load_rekor_log_public_key()),
        patch.object(host_digest_verify, "_which", side_effect=lambda b: f"/bin/{b}"),
        patch.object(
            host_digest_verify, "_run_cosign_manifest", return_value=(True, OTHER, "")
        ),
        patch.object(
            host_digest_verify, "_run_crane_digest", return_value=(True, OTHER, "")
        ),
        patch.object(
            host_digest_verify,
            "_fetch_tuf_expected_digest",
            return_value=(True, OTHER, ""),
        ),
    ):
        rc = host_digest_verify.main(
            [
                "--release",
                "v0.3.0",
                "--tuf-trust-bundle",
                str(tmp_path),
                "--rekor-bundle",
                str(path),
            ]
        )
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    captured = capsys.readouterr()
    assert "REKOR_DSSE_PAYLOAD_ABSENT" in captured.err
    assert "subject_binding=FAILED" in captured.err
    assert "inclusion_proof=ok checkpoint=ok" in captured.err
    assert "VERIFIED" not in captured.out


# ---------------------------------------------------------------------------
# 2/3. real staging bytes, hashedrekord v0.0.2: bound ⇒ ok; other digest ⇒ not ok
# ---------------------------------------------------------------------------


def test_staging_hashedrekord_binds_to_its_message_digest(tmp_path: Path) -> None:
    path = _write(tmp_path, _staging_bundle())
    res = host_digest_verify._verify_rekor_inclusion(
        path, frozenset({_staging_subject()}), expected_predicate_type=None, rekor_log_key=_staging_log_key()
    )
    assert res.err == ""
    assert res.inclusion_ok is True
    assert res.checkpoint_ok is True, res.reasons
    assert res.ok is True, res.reasons
    assert res.bound_via == "hashedrekord.data.digest"
    assert res.bound_to == _staging_subject()


def test_staging_hashedrekord_other_digest_not_bound(tmp_path: Path) -> None:
    path = _write(tmp_path, _staging_bundle())
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=_staging_log_key())
    assert res.inclusion_ok is True
    assert res.checkpoint_ok is True
    assert res.ok is False
    assert "REKOR_SUBJECT_NOT_BOUND" in res.reasons


def test_staging_hashedrekord_naming_the_digest_is_not_the_release_attestation(
    tmp_path: Path, capsys
) -> None:
    """Until 2026-09-02 this test reached exit 0: the real staging v2 hashedrekord
    entry NAMES the digest, and any entry naming the digest bound. The release
    consumer now requires the image-binding attestation (a dsse entry whose
    statement carries `IMAGE_BINDING_PREDICATE_TYPE`), so a hashedrekord over the
    same bytes is `REKOR_PREDICATE_TYPE_MISMATCH` at exit 7 — the inclusion proof
    and the v2 checkpoint still verify, and the face says which leg failed."""
    path = _write(tmp_path, _staging_bundle())
    subj = _staging_subject()
    with (
        _patch_key(_staging_log_key()),
        patch.object(host_digest_verify, "_which", side_effect=lambda b: f"/bin/{b}"),
        patch.object(
            host_digest_verify, "_run_cosign_manifest", return_value=(True, subj, "")
        ),
        patch.object(
            host_digest_verify, "_run_crane_digest", return_value=(True, subj, "")
        ),
        patch.object(
            host_digest_verify,
            "_fetch_tuf_expected_digest",
            return_value=(True, subj, ""),
        ),
    ):
        rc = host_digest_verify.main(
            [
                "--release",
                "v0.3.0",
                "--tuf-trust-bundle",
                str(tmp_path),
                "--rekor-bundle",
                str(path),
            ]
        )
    assert rc == host_digest_verify.EXIT_REKOR_INCLUSION_FAILED
    err = capsys.readouterr().err
    assert "REKOR_PREDICATE_TYPE_MISMATCH" in err
    assert "inclusion_proof=ok checkpoint=ok subject_binding=FAILED" in err


# ---------------------------------------------------------------------------
# 4. dsse / in-toto: subject binding through the payload hash
# ---------------------------------------------------------------------------


@pytest.fixture
def log_sk() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_dsse_subject_matches_expected(tmp_path: Path, log_sk) -> None:
    payload = _intoto_statement(OTHER[7:])
    path = _write(tmp_path, _synthetic_dsse_bundle(payload, log_sk))
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=log_sk.public_key())
    assert res.ok is True, res.reasons
    assert res.bound_via == "dsse.payloadHash->in-toto.subject"
    assert res.bound_to == OTHER


def test_dsse_subject_differs_not_bound(tmp_path: Path, log_sk) -> None:
    payload = _intoto_statement("22" * 32)
    path = _write(tmp_path, _synthetic_dsse_bundle(payload, log_sk))
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=log_sk.public_key())
    assert res.inclusion_ok is True and res.checkpoint_ok is True
    assert res.ok is False
    assert "REKOR_SUBJECT_NOT_BOUND" in res.reasons


def test_dsse_payload_tampered_after_logging_is_caught(tmp_path: Path, log_sk) -> None:
    """The logged payloadHash is over the HONEST statement; the bundle carries a
    forged statement naming our digest. sha256(payload) ≠ payloadHash → refused."""
    honest = _intoto_statement("22" * 32)
    forged = _intoto_statement(OTHER[7:])
    bundle = _synthetic_dsse_bundle(
        honest, log_sk, body_payload_hash=hashlib.sha256(honest).hexdigest()
    )
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(forged).decode()
    path = _write(tmp_path, bundle)
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=log_sk.public_key())
    assert res.ok is False
    assert "REKOR_DSSE_PAYLOAD_HASH_MISMATCH" in res.reasons
    assert "REKOR_SUBJECT_NOT_BOUND" not in res.reasons


def test_dsse_payload_absent_cannot_bind(tmp_path: Path, log_sk) -> None:
    payload = _intoto_statement(OTHER[7:])
    path = _write(
        tmp_path, _synthetic_dsse_bundle(payload, log_sk, include_payload=False)
    )
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=log_sk.public_key())
    assert res.ok is False
    assert "REKOR_DSSE_PAYLOAD_ABSENT" in res.reasons


# ---------------------------------------------------------------------------
# 5. unknown kind is deny-by-default; malformed body is refused not skipped
# ---------------------------------------------------------------------------


def test_unknown_body_kind_is_unsupported() -> None:
    body = {
        "apiVersion": "0.0.1",
        "kind": "rpm",
        "spec": {"data": {"hash": {"value": "aa"}}},
    }
    subjects, via, reason = rekor_anchor.rekor_body_subject_digests(body, None)
    assert subjects == frozenset()
    assert via is None
    assert reason == "REKOR_BODY_KIND_UNSUPPORTED"


def test_unparseable_body_is_refused(tmp_path: Path, log_sk) -> None:
    payload = _intoto_statement(OTHER[7:])
    bundle = _synthetic_dsse_bundle(payload, log_sk)
    raw = b"not json at all"
    root = rekor_anchor.rfc6962_leaf_hash(raw)
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    entry["canonicalizedBody"] = base64.b64encode(raw).decode()
    entry["inclusionProof"]["rootHash"] = base64.b64encode(root).decode()
    entry["inclusionProof"]["checkpoint"]["envelope"] = _signed_checkpoint(root, log_sk)
    path = _write(tmp_path, bundle)
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=log_sk.public_key())
    assert res.inclusion_ok is True and res.checkpoint_ok is True
    assert res.ok is False
    assert "REKOR_BODY_UNPARSEABLE" in res.reasons


def test_empty_expected_set_never_binds(tmp_path: Path) -> None:
    """A caller that holds nothing cannot be satisfied — no vacuous PASS."""
    path = _write(tmp_path, _staging_bundle())
    res = host_digest_verify._verify_rekor_inclusion(path, frozenset(), expected_predicate_type=None, rekor_log_key=_staging_log_key())
    assert res.ok is False
    assert "REKOR_SUBJECT_NOT_BOUND" in res.reasons


def test_hashedrekord_v001_hex_binds() -> None:
    body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {"data": {"hash": {"algorithm": "sha256", "value": OTHER[7:]}}},
    }
    subjects, via, reason = rekor_anchor.rekor_body_subject_digests(body, None)
    assert subjects == frozenset({OTHER})
    assert via == "hashedrekord.data.digest"
    assert reason is None


def test_intoto_v002_binds_through_payload() -> None:
    payload = _intoto_statement(OTHER[7:])
    body = {
        "apiVersion": "0.0.2",
        "kind": "intoto",
        "spec": {
            "content": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(payload).hexdigest(),
                }
            }
        },
    }
    subjects, via, reason = rekor_anchor.rekor_body_subject_digests(body, payload)
    assert OTHER in subjects
    assert via == "intoto.payloadHash->in-toto.subject"
    assert reason is None


def test_staging_key_is_not_the_pinned_production_key() -> None:
    """Guard the test's own premise: the injected staging key differs from the pinned
    production constant, so a green staging positive is not a production tautology."""
    prod = rekor_anchor.load_rekor_log_public_key()
    stg = _staging_log_key()
    der = lambda k: k.public_bytes(  # noqa: E731
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert der(prod) != der(stg)


def test_image_binding_predicate_type_is_required_when_expected(tmp_path):
    """Fresh-pass red-team LOW (2026-09-02): any in-toto statement naming the
    digest among its subjects bound, whatever its predicateType. The release
    consumer now names the predicate it expects; a SLSA statement over the same
    digest is `REKOR_PREDICATE_TYPE_MISMATCH`, not a binding."""
    log_sk = ec.generate_private_key(ec.SECP256R1())
    payload = _intoto_statement(OTHER[len("sha256:"):])
    path = tmp_path / "b.json"
    path.write_text(json.dumps(_synthetic_dsse_bundle(payload, log_sk)))
    res = host_digest_verify._verify_rekor_inclusion(
        path,
        frozenset({OTHER}),
        expected_predicate_type=rekor_anchor.IMAGE_BINDING_PREDICATE_TYPE,
        rekor_log_key=log_sk.public_key(),
    )
    assert res.ok is False
    assert rekor_anchor.REASON_PREDICATE_TYPE_MISMATCH in res.reasons
    assert res.bound_to is None


def test_depth_bombed_bundle_is_could_not_evaluate_not_a_traceback(tmp_path, log_sk):
    """Red-team MEDIUM (2026-09-02): a depth-bombed `--rekor-bundle` escaped as a
    RecursionError — exit 1 with a traceback AFTER the digest PASS line. The leg
    now reports could-not-evaluate (exit 7 through main)."""
    path = tmp_path / "bomb.json"
    path.write_text("[" * 300_000 + "]" * 300_000)
    res = host_digest_verify._verify_rekor_inclusion(
        path, frozenset({OTHER}), expected_predicate_type=None, rekor_log_key=log_sk.public_key()
    )
    assert res.ok is False
    assert "RecursionError" in res.err or "bounds" in res.err or "cannot read" in res.err
