"""Auditor-held DSSE trust material for the open-drop sealing lane, minted with real keys.

Builds, for a test: a `revocation-root` role document in the exact shape of
`audit_bundle/extensions/_tuf_root/revocation_root.json` AFTER a ceremony (three
Ed25519 root keys, the document signed by `threshold` of them over
`rfc8785.dumps(signed)`, a pinned list signer, a current expiry); a revocation list
signed by that pinned signer; a `{kid: b64url pubkey}` allowlist file; and a
DSSE-sealed post-cutover bundle the shipped CLI can verify. Import-only
infrastructure for `tests/test_cli_dsse_context.py` and the chain-form battery
under `tests/c18/`.
"""

from __future__ import annotations

import base64
import hashlib
import time
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.dsse.envelope import sign_envelope
from audit_bundle.dsse.pae import b64url_nopad_encode, kid_from_raw32

#: The verifier clock every window below is minted around. Wall-relative, fixed
#: at import: `build_dsse_context` refuses a clock more than 300 s behind the
#: wall (a backdated clock un-revokes keys), so a constant in the past cannot
#: drive the CLI. Windows are wide (list expires NOW + 10**6 s) so a slow run
#: never crosses one.
NOW = int(time.time())


def _raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes_raw()


def _keyid(sk: Ed25519PrivateKey) -> str:
    return hashlib.sha256(_raw(sk)).hexdigest()


@dataclass(frozen=True)
class RevocationRootKeys:
    root: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey]
    list_signer: Ed25519PrivateKey  # the pinned signer (a fourth key by default)

    @classmethod
    def generate(cls, *, list_signer_is_root_key: bool = False) -> "RevocationRootKeys":
        root = tuple(Ed25519PrivateKey.generate() for _ in range(3))
        signer = root[0] if list_signer_is_root_key else Ed25519PrivateKey.generate()
        return cls(root, signer)  # type: ignore[arg-type]

    @property
    def pinned_keyid(self) -> str:
        return _keyid(self.list_signer)


def revocation_root_document(
    keys: RevocationRootKeys,
    *,
    sign_with: tuple[int, ...] = (0, 1),
    expires_in_days: int = 30,
    pinned_signer_keyid: str | None = None,
    list_pinned_signer_under_keys: bool = True,
) -> dict[str, Any]:
    """The role document, signed by `sign_with` (indices into `keys.root`)."""
    signed_keys = {
        _keyid(sk): {
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keytype": "ed25519",
            "keyval": {"public": _raw(sk).hex()},
            "scheme": "ed25519",
        }
        for sk in keys.root
    }
    if list_pinned_signer_under_keys:
        signed_keys.setdefault(
            _keyid(keys.list_signer),
            {
                "keyid_hash_algorithms": ["sha256", "sha512"],
                "keytype": "ed25519",
                "keyval": {"public": _raw(keys.list_signer).hex()},
                "scheme": "ed25519",
            },
        )
    expires = (
        (datetime.now(timezone.utc) + timedelta(days=expires_in_days))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed = {
        "_type": "revocation-root",
        "consistent_snapshot": True,
        "expires": expires,
        "pinned_revocation_list_signer_fingerprint": (
            pinned_signer_keyid
            if pinned_signer_keyid is not None
            else keys.pinned_keyid
        ),
        "keys": signed_keys,
        "roles": {
            "revocation-root": {
                "keyids": [_keyid(sk) for sk in keys.root],
                "threshold": 2,
            }
        },
        "spec_version": "1.0.31",
        "version": 1,
    }
    message = rfc8785.dumps(signed)
    return {
        "schema": "v-kernel-audit-bundle/revocation-root/v0.3",
        "spec_version": "1.0.31",
        "role_name": "revocation-root",
        "signatures": [
            {"keyid": _keyid(keys.root[i]), "sig": keys.root[i].sign(message).hex()}
            for i in sign_with
        ],
        "signed": signed,
        "rotation_policy": {
            "minimum_distinct_human_approvers": 2,
            "minimum_total_approvers": 3,
            "max_validity_days": 90,
        },
    }


def signed_revocation_list(
    signer: Ed25519PrivateKey,
    *,
    revocations: list[dict[str, Any]] | None = None,
    issued_at: int = NOW - 100,
    expires: int = NOW + 10**6,
    root_kid: str | None = None,
) -> bytes:
    payload = {
        "revocations": revocations or [],
        "issued_at": issued_at,
        "expires": expires,
    }
    sig = signer.sign(rfc8785.dumps(payload))
    return json.dumps(
        {
            "payload": payload,
            "sig": b64url_nopad_encode(sig),
            "root_kid": root_kid if root_kid is not None else _keyid(signer),
        }
    ).encode("utf-8")


def allowlist_json(*signers: Ed25519PrivateKey) -> bytes:
    return json.dumps(
        {
            kid_from_raw32(_raw(sk)): base64.urlsafe_b64encode(_raw(sk))
            .rstrip(b"=")
            .decode()
            for sk in signers
        }
    ).encode("utf-8")


def sealed_bundle(
    bundle_dir: Path,
    signing_key: Ed25519PrivateKey,
    *,
    schema_version: str = "vcp-v1.2-dsse",
    seal: bool = True,
) -> None:
    """A minimal post-cutover bundle: one content file, manifest, DSSE sidecar over
    `{schema_version, manifest_sha256, iat, files}` (the emitter's payload shape)."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    content = b"synthetic corpus entry for the dsse context test\n"
    (bundle_dir / "corpus_entry.txt").write_bytes(content)
    manifest = {
        "schema_version": schema_version,
        "bundle_id": "dsse-context-test",
        "created_at": "2026-06-04T00:00:00Z",
        "files": {"corpus_entry.txt": hashlib.sha256(content).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    (bundle_dir / "manifest.json").write_bytes(manifest_bytes)
    if not seal:
        return
    payload = {
        "schema_version": schema_version,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "iat": NOW,
        "files": [
            {"path": "corpus_entry.txt", "sha256": hashlib.sha256(content).hexdigest()}
        ],
    }
    sidecar = sign_envelope(rfc8785.dumps(payload), signing_key)
    (bundle_dir / "bundle.dsse.json").write_bytes(
        json.dumps(sidecar, ensure_ascii=False).encode("utf-8")
    )


def write_material(
    out_dir: Path,
    keys: RevocationRootKeys,
    bundle_signer: Ed25519PrivateKey,
    *,
    root_doc: dict[str, Any] | None = None,
    revocation_list: bytes | None = None,
) -> dict[str, Path]:
    """Write allowlist / root / list under `out_dir` (OUTSIDE any bundle)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "allowlist": out_dir / "allowlist.json",
        "root": out_dir / "revocation_root.json",
        "list": out_dir / "vkernel_revocations.json",
    }
    paths["allowlist"].write_bytes(allowlist_json(bundle_signer))
    paths["root"].write_text(
        json.dumps(
            root_doc if root_doc is not None else revocation_root_document(keys),
            indent=2,
        )
    )
    paths["list"].write_bytes(
        revocation_list
        if revocation_list is not None
        else signed_revocation_list(keys.list_signer)
    )
    return paths


def sign_role_document(
    doc: dict[str, Any],
    role_name: str,
    keys: RevocationRootKeys,
    *,
    sign_with: tuple[int, ...] = (0, 1),
) -> dict[str, Any]:
    """Re-key a signed-shape role document (`revocation-root` or
    `sigstore-trust-root`) under `keys` and sign it with `sign_with` — the toy
    feed's way of modelling a POST-ceremony document whose 2-of-3 really verifies.
    The pinned list signer is set only for the revocation root."""
    import rfc8785  # noqa: PLC0415

    signed = doc["signed"]
    signed["keys"] = {
        _keyid(sk): {
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keytype": "ed25519",
            "keyval": {"public": _raw(sk).hex()},
            "scheme": "ed25519",
        }
        for sk in keys.root
    }
    signed["roles"] = {
        role_name: {"keyids": [_keyid(sk) for sk in keys.root], "threshold": 2}
    }
    if role_name == "revocation-root":
        signed["keys"][_keyid(keys.list_signer)] = {
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keytype": "ed25519",
            "keyval": {"public": _raw(keys.list_signer).hex()},
            "scheme": "ed25519",
        }
        signed["pinned_revocation_list_signer_fingerprint"] = keys.pinned_keyid
    message = rfc8785.dumps(signed)
    doc["signatures"] = [
        {"keyid": _keyid(keys.root[i]), "sig": keys.root[i].sign(message).hex()}
        for i in sign_with
    ]
    return doc
