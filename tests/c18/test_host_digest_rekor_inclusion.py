"""Tests for the REAL Rekor inclusion verification wired into host_digest_verify.

`veriker/cli/host_digest_verify._verify_rekor_inclusion` is the consumer-side host check
that closes the seam flagged in SECURITY.md: until it was wired, the `--sth-gossip`
path was a STRUCTURAL pre-check only (no Merkle fold, no checkpoint-signature
verification). This helper now drives `audit_bundle.extensions.rekor_anchor`'s real
RFC 6962 inclusion recompute + checkpoint ECDSA-P256 signature verification against
the Rekor log key the CLI resolves from the sigstore-trust-root role (this battery
injects the documented real rekor.sigstore.dev key directly), fail-closed.

Every positive byte here is the REAL captured public Rekor entry
(`tests/fixtures/rekor_real_entry_v1.json`); only the cosign-bundle ENVELOPE is
synthetic — mirroring `test_rekor_anchor._real_entry_as_sigstore_bundle`. The
negatives prove teeth: a tampered proof hash, a tampered checkpoint, and a
malformed/absent bundle all fail closed (never a silent pass).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.extensions import rekor_anchor  # noqa: E402
from veriker.cli import host_digest_verify  # noqa: E402

from tests._optional_deps import requires_cryptography

_FIXTURE = _PKG_ROOT / "tests" / "fixtures" / "rekor_real_entry_v1.json"


def _real_sigstore_bundle() -> dict:
    """Re-encode the real Rekor v1 fixture into a cosign Sigstore bundle v0.3 envelope.

    Only the envelope is synthetic; the inclusion proof, checkpoint, and body are
    the real captured public Rekor entry.
    """
    fx = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    response = fx["response"]
    entry = response[next(iter(response))]
    ip = entry["verification"]["inclusionProof"]

    def _hex_to_b64(h: str) -> str:
        return base64.b64encode(bytes.fromhex(h)).decode("ascii")

    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": str(ip["logIndex"]),
                    "logId": {
                        "keyId": base64.b64encode(bytes.fromhex(entry["logID"])).decode(
                            "ascii"
                        )
                    },
                    "integratedTime": str(entry["integratedTime"]),
                    "inclusionProof": {
                        "logIndex": str(ip["logIndex"]),
                        "rootHash": _hex_to_b64(ip["rootHash"]),
                        "treeSize": str(ip["treeSize"]),
                        "hashes": [_hex_to_b64(h) for h in ip["hashes"]],
                        "checkpoint": {"envelope": ip["checkpoint"]},
                    },
                    "canonicalizedBody": entry["body"],
                }
            ]
        },
    }


def _write(tmp_path: Path, bundle: dict) -> Path:
    p = tmp_path / "release.sigstore-bundle.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    return p


_ANY = frozenset({"sha256:" + "ab" * 32})
# The production log key the real fixture was logged under. The CLI resolves its
# key from the sigstore-trust-root role (tests/c18/test_host_digest_rekor_key_from_role.py);
# these unit tests hand the documented real bytes in explicitly.
_PROD_KEY = rekor_anchor.load_rekor_log_public_key()


@requires_cryptography
def test_real_bundle_verifies_both_legs_but_binds_to_nothing_of_ours(
    tmp_path: Path,
) -> None:
    """The real captured entry: inclusion re-derives AND checkpoint sig is valid — and
    the verdict is still NOT ok, because it is a third party's entry and commits to
    nothing this verifier holds. Before 2026-09-02 this test asserted ``ok is True``:
    that assertion was the fail-open (any public entry verified our release)."""
    path = _write(tmp_path, _real_sigstore_bundle())
    res = host_digest_verify._verify_rekor_inclusion(path, _ANY, expected_predicate_type=None, rekor_log_key=_PROD_KEY)
    assert res.err == ""
    assert res.inclusion_ok is True
    assert res.checkpoint_ok is True
    assert res.ok is False
    assert res.reasons == ("REKOR_DSSE_PAYLOAD_ABSENT",)
    assert res.bound_to is None


@requires_cryptography
def test_tampered_proof_hash_fails_closed(tmp_path: Path) -> None:
    """Flipping one inclusion-proof sibling hash breaks the Merkle re-derive → not ok."""
    bundle = _real_sigstore_bundle()
    hashes = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"][
        "hashes"
    ]
    raw = bytearray(base64.b64decode(hashes[0]))
    raw[0] ^= 0xFF
    hashes[0] = base64.b64encode(bytes(raw)).decode("ascii")
    path = _write(tmp_path, bundle)

    res = host_digest_verify._verify_rekor_inclusion(path, _ANY, expected_predicate_type=None, rekor_log_key=_PROD_KEY)
    ok, reasons, err = res.ok, list(res.reasons), res.err
    assert ok is False
    # Inclusion failed → no silent pass; the err channel stays empty (verdict, not parse error).
    assert err == ""
    assert any("INCLUSION" in r for r in reasons)


@requires_cryptography
def test_tampered_checkpoint_fails_closed(tmp_path: Path) -> None:
    """A checkpoint whose signed root no longer matches → checkpoint leg fails → not ok."""
    bundle = _real_sigstore_bundle()
    ip = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    # Corrupt the signed-note checkpoint body so its signature no longer verifies.
    ip["checkpoint"]["envelope"] = ip["checkpoint"]["envelope"].replace(
        "rekor.sigstore.dev", "rekor.attacker.example", 1
    )
    path = _write(tmp_path, bundle)

    res = host_digest_verify._verify_rekor_inclusion(path, _ANY, expected_predicate_type=None, rekor_log_key=_PROD_KEY)
    ok, reasons, err = res.ok, list(res.reasons), res.err
    assert ok is False
    assert err == ""
    assert any("CHECKPOINT" in r for r in reasons)


def test_malformed_bundle_fails_closed(tmp_path: Path) -> None:
    """An empty tlogEntries list is a malformed anchor → fail-closed with an err."""
    path = _write(tmp_path, {"verificationMaterial": {"tlogEntries": []}})
    res = host_digest_verify._verify_rekor_inclusion(path, _ANY, expected_predicate_type=None, rekor_log_key=_PROD_KEY)
    ok, err = res.ok, res.err
    assert ok is False
    assert err != ""


def test_absent_bundle_fails_closed(tmp_path: Path) -> None:
    """A path that does not exist fails closed (never a silent pass)."""
    res = host_digest_verify._verify_rekor_inclusion(
        tmp_path / "does-not-exist.json", _ANY, expected_predicate_type=None, rekor_log_key=_PROD_KEY
    )
    ok, err = res.ok, res.err
    assert ok is False
    assert err != ""
