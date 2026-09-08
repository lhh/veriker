"""SCITT v0.5 Phase B — anchor a Signed Statement to Rekor and embed its NATIVE proof.

Builds the "Rekor-backed transparent statement": the COSE_Sign1 Signed Statement
(`release/scitt_signed_statement.py`) plus Rekor's NATIVE inclusion proof and signed checkpoint.

WHY "Rekor-backed", NOT "SCITT Receipt" (grounded against current drafts):
  Rekor does NOT issue a SCITT COSE Receipt. Its `cose` entry type is for *submitting* a COSE
  object to be logged, not for issuing a COSE_Sign1 Receipt. Rekor returns a native inclusion
  proof plus a signed checkpoint under its log key. The proof math bridges cleanly — Rekor's
  tree IS the RFC9162_SHA256 / RFC 6962 tree the COSE-Receipts draft profiles — but a
  conformant Receipt needs a COSE_Sign1 signed over the tree head. Rekor does not provide that
  signer; only a real SCITT TS (the reserved premium leg) would. So this module verifies
  Rekor's NATIVE artifacts, and external copy must say "Rekor-backed", never "SCITT Receipt".

‼ MERKLE CONVENTION — RFC 6962, NOT the in-tree per-bundle convention. Rekor/RFC 6962 use
  leaf = H(0x00 || data), node = H(0x01 || left || right). The codebase's
  `audit_bundle.extensions.c19.layer_a_counter.compute_bundle_merkle_root` uses the INVERTED
  prefixes (leaf 0x01 / node 0x00) for its own per-bundle event DAG. Do NOT reuse it here: it
  would compute wrong roots against real Rekor data, and would only fail against a live log.
  `test_rekor_anchor.test_rfc6962_convention_differs_from_inner_tree` locks the distinction.

WHAT IS REAL HERE (offline, non-tautological):
  * `verify_inclusion_proof` — the canonical RFC 6962 §2.1.1 inclusion-proof recompute. Real
    teeth: a tampered hash, a wrong root, a wrong index, or a wrong leaf all fail.
  * `verify_checkpoint_signature` — parses Rekor's Go signed-note checkpoint and verifies its
    log signature against the pinned log key (ECDSA P-256 for the Rekor v1
    `rekor.sigstore.dev` log; Ed25519 for tile-backed Rekor v2 logs).
  * `assemble_rekor_backed_statement` / `register_signed_statement` — the bundle shape plus a
    transport-abstracted registration client (replayable for tests).

GROUNDED against a REAL public Rekor v1 entry (read-only fetch, no write/POST) — see
`tests/fixtures/rekor_real_entry_v1.json` and `tests/test_rekor_anchor.py::test_real_rekor_*`.
The two former "deferred fidelity" gaps are now pinned empirically against live Rekor bytes:

  * LEAF CANONICALIZATION (resolved). The Merkle leaf preimage is the base64-DECODED `body`
    field of the Rekor entry; the RFC 6962 leaf hash is `SHA256(0x00 || base64decode(body))`.
    Verified: `root_from_inclusion_proof(rfc6962_leaf_hash(base64decode(body)), ip.logIndex,
    ip.treeSize, ip.hashes)` equals the real `inclusionProof.rootHash`. (Pass `leaf_preimage =
    base64decode(entry["body"])` to the verifiers.)
  * CHECKPOINT KEY + NOTE FORMAT (resolved). The checkpoint is a Go sumdb / c2sp.org
    signed-note: a text body (line 1 = origin `<host> - <treeID>`, line 2 = tree size,
    line 3 = base64 root hash), a BLANK separator line, then one or more signature lines
    `— <name> <base64(4-byte key-hint || ECDSA-DER-sig)>`. The SIGNED bytes are the body
    plus a single trailing newline (`checkpoint.split("\\n\\n", 1)[0] + "\\n"`); the blank
    line and signature block are NOT signed. The v1 `rekor.sigstore.dev` log key is ECDSA
    P-256 with key-hint `SHA256(DER SubjectPublicKeyInfo)[:4]`; Rekor v2 logs sign with
    Ed25519 and the c2sp hint `SHA256(name ‖ "\n" ‖ 0x01 ‖ raw)[:4]` (see `rekor_key_hint`);
    either hint equals the leading 4 bytes of that log's entry `logID`. The pinned key is
    `REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM` (provenance: GET .../api/v1/log/publicKey).

WHAT REMAINS DEFERRED (gated, NOT a fidelity gap):
  * The LIVE network POST to a Rekor instance (`LiveRekorTransport` raises until enabled).
  * NEXI signing its OWN Signed Statement under a Fulcio-rooted keyless release identity, and
    registering its own releases to the log (a write and a posture decision). The Ed25519
    issuer-statement path lives in `release/scitt_signed_statement.py`, not here; the
    checkpoint path above uses the LOG's key type (P-256 for v1, Ed25519 for v2).

Tier-2 / network-substrate side (sibling to c18_tuf_client.py). Pure-stdlib Merkle (hashlib);
checkpoint-sig and key load use `cryptography` (an existing substrate dep). MUST NOT be pulled
onto the offline stdlib core (`veriker/cli/verify.py` / `audit_bundle/verifier.py`) — the
two-verifier boundary.


"""

from __future__ import annotations

import base64
import binascii
import hashlib
from audit_bundle.strict_json import strict_json_loads
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

# --- RFC 6962 §2.1 domain-separated hashing (opposite prefixes to the inner tree). ---
_RFC6962_LEAF_PREFIX = b"\x00"
_RFC6962_NODE_PREFIX = b"\x01"


class RekorAnchorError(RuntimeError):
    """Raised on a malformed anchor or a failed inclusion-proof recompute."""


def rfc6962_leaf_hash(leaf_preimage: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_preimage)."""
    return hashlib.sha256(_RFC6962_LEAF_PREFIX + leaf_preimage).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(_RFC6962_NODE_PREFIX + left + right).digest()


def root_from_inclusion_proof(
    leaf_hash: bytes, leaf_index: int, tree_size: int, proof: list[bytes]
) -> bytes:
    """Recompute the Merkle tree root from an RFC 6962 §2.1.1 inclusion proof.

    `leaf_hash` is the already-computed RFC6962 leaf hash (see `rfc6962_leaf_hash`),
    `leaf_index` is 0-based, and `proof` is the ordered list of sibling node hashes. Returns
    the recomputed 32-byte root. Raises :class:`RekorAnchorError` if the proof is the wrong
    length for the (index, size) pair.

    This is the canonical algorithm (RFC 6962; matches the certificate-transparency
    reference), independent of how any tree was built — so a wrong proof yields a wrong root
    rather than silently passing.
    """
    if tree_size <= 0:
        raise RekorAnchorError(f"tree_size must be positive, got {tree_size}")
    if not 0 <= leaf_index < tree_size:
        raise RekorAnchorError(
            f"leaf_index {leaf_index} out of range for tree_size {tree_size}"
        )
    if len(leaf_hash) != 32:
        raise RekorAnchorError(f"leaf_hash must be 32 bytes, got {len(leaf_hash)}")

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash
    for sibling in proof:
        if len(sibling) != 32:
            raise RekorAnchorError("proof entry is not a 32-byte hash")
        if sn == 0:
            raise RekorAnchorError("inclusion proof too long for tree_size")
        if (fn & 1) == 1 or fn == sn:
            r = rfc6962_node_hash(sibling, r)
            # When fn is even but fn == sn (we are the rightmost node at this level),
            # ascend past the run of left-edges until the LSB is set.
            while (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = rfc6962_node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise RekorAnchorError("inclusion proof too short for tree_size")
    return r


@dataclass(frozen=True)
class RekorAnchor:
    """Rekor's native proof-of-inclusion for one logged entry (NOT a SCITT COSE Receipt).

    Mirrors the fields of Rekor's `verification.inclusionProof` block plus entry metadata.
    `root_hash` and `hashes` are raw 32-byte digests (decode hex at the parse boundary).
    `checkpoint` is the signed-note bytes, verified separately against the pinned log key.
    """

    log_id: str
    log_index: int
    tree_size: int
    root_hash: bytes
    hashes: tuple[bytes, ...]
    checkpoint: bytes
    integrated_time: int | None = None

    @classmethod
    def from_rekor_verification(cls, log_id: str, verification: dict) -> "RekorAnchor":
        """Parse a Rekor `verification` object (the `inclusionProof` sub-block + metadata)."""
        proof = verification.get("inclusionProof")
        if not isinstance(proof, dict):
            raise RekorAnchorError(
                "verification.inclusionProof missing or not an object"
            )
        try:
            log_index = int(proof["logIndex"])
            tree_size = int(proof["treeSize"])
            root_hash = bytes.fromhex(proof["rootHash"])
            hashes = tuple(bytes.fromhex(h) for h in proof["hashes"])
            checkpoint = str(proof["checkpoint"]).encode("utf-8")
        except (KeyError, TypeError, ValueError) as exc:
            raise RekorAnchorError(f"malformed inclusionProof: {exc}") from exc
        integrated = verification.get("integratedTime")
        return cls(
            log_id=log_id,
            log_index=log_index,
            tree_size=tree_size,
            root_hash=root_hash,
            hashes=hashes,
            checkpoint=checkpoint,
            integrated_time=int(integrated) if integrated is not None else None,
        )


def verify_inclusion_proof(leaf_preimage: bytes, anchor: RekorAnchor) -> bool:
    """Recompute the root from `leaf_preimage` plus the anchor's proof, and compare to `root_hash`.

    Returns True iff the leaf is provably included at `anchor.log_index` in a tree whose root
    is `anchor.root_hash`. This binds the leaf to the checkpoint root. It does NOT by itself
    prove the root is Rekor's genuine tree head — that is `verify_checkpoint_signature` against
    the pinned Rekor log key. For a real Rekor entry, `leaf_preimage = base64decode(entry["body"])`
    (the grounded leaf canonicalization — see the module docstring).
    """
    leaf_hash = rfc6962_leaf_hash(leaf_preimage)
    try:
        recomputed = root_from_inclusion_proof(
            leaf_hash, anchor.log_index, anchor.tree_size, list(anchor.hashes)
        )
    except RekorAnchorError:
        return False
    return recomputed == anchor.root_hash


# --- Rekor log key (ECDSA P-256) + Go signed-note checkpoint parsing. ---

#: The published `rekor.sigstore.dev` transparency-log public key (ECDSA P-256 / secp256r1).
#: Provenance: GET https://rekor.sigstore.dev/api/v1/log/publicKey (a public, read-only fetch).
#: SHA-256(DER SubjectPublicKeyInfo) = c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d.
#: Its 4-byte prefix (c0d23d6a) is BOTH the checkpoint signed-note key-hint AND the leading
#: bytes of every active-shard entry's `logID`. Documented REAL bytes, kept so the tests
#: over the captured production entry have a known key. Since 2026-09-02 the shipped
#: consumer (`veriker/cli/host_digest_verify.py`) does NOT read this constant: it resolves the
#: log key from the `sigstore-trust-root` TUF role (`c18_tuf_client.fetch_sigstore_trust_root_key`,
#: entry `rekor.pub`), whose ceremony-filled digest must equal sha256 of the served PEM.
REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
    b"kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n"
    b"-----END PUBLIC KEY-----\n"
)


RekorLogKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


def load_rekor_log_public_key(
    pem: bytes | None = None,
) -> RekorLogKey:
    """Load a Rekor log public key. Defaults to the pinned production (v1) key.

    Two key types are Rekor checkpoint keys: ECDSA P-256 (the `rekor.sigstore.dev` v1
    log) and Ed25519 (the tile-backed Rekor v2 logs, e.g. `log2025-alpha3.rekor.sigstage.dev`
    — grounded on `tests/fixtures/sigstore_staging_bundle_v0_3.json`, whose checkpoint
    verifies under the Ed25519 key captured in `sigstore_staging_trust_anchors.json`).
    Raises :class:`RekorAnchorError` for any other key type. Which key is PINNED is the
    caller's decision; this function only refuses to load a key no Rekor log signs with.
    """
    try:
        key = load_pem_public_key(
            pem if pem is not None else REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM
        )
    except (ValueError, TypeError) as exc:
        raise RekorAnchorError(f"could not parse Rekor log public key: {exc}") from exc
    if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1":
        return key
    if isinstance(key, ed25519.Ed25519PublicKey):
        return key
    raise RekorAnchorError(
        "Rekor log key must be ECDSA P-256 (secp256r1) or Ed25519; got "
        f"{type(key).__name__}/{getattr(getattr(key, 'curve', None), 'name', '?')}"
    )


def rekor_key_hint(
    rekor_log_pubkey: RekorLogKey, note_name: str | None = None
) -> bytes:
    """The 4-byte signed-note key-hint that names `rekor_log_pubkey` on a signature line.

    Two conventions, by key type — both grounded on real checkpoints:
      * ECDSA P-256 (Rekor v1): `SHA-256(DER SubjectPublicKeyInfo)[:4]`. Equals the
        signature-line prefix and the entry logID prefix on `rekor.sigstore.dev`.
      * Ed25519 (Rekor v2, c2sp.org/signed-note): `SHA-256(name ‖ "\\n" ‖ 0x01 ‖ raw32)[:4]`,
        where `name` is the signature line's own name (the log origin). Equals the entry
        logID prefix on the staging v2 log. `note_name` is REQUIRED for this key type; the
        hint is a function of the name, so it must be computed per signature line.
    """
    if isinstance(rekor_log_pubkey, ed25519.Ed25519PublicKey):
        if note_name is None:
            raise RekorAnchorError("Ed25519 key hint needs the signature line's name")
        raw = rekor_log_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return hashlib.sha256(note_name.encode("utf-8") + b"\n\x01" + raw).digest()[:4]
    der = rekor_log_pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()[:4]


@dataclass(frozen=True)
class CheckpointNote:
    """A parsed Rekor checkpoint (Go sumdb / c2sp.org signed-note).

    `signed_body` is the exact byte string the signature covers: the origin/size/root lines
    plus a single trailing newline, NOT the blank separator or the signature block.
    `signatures` is a tuple of (name, 4-byte key_hint, signature_bytes).
    """

    origin: str
    tree_size: int
    root_hash: bytes
    signed_body: bytes
    signatures: tuple[tuple[str, bytes, bytes], ...]


def parse_checkpoint_note(checkpoint: bytes) -> CheckpointNote:
    """Parse a Rekor signed-note checkpoint into its body fields + signature lines.

    Format (c2sp.org/tlog-checkpoint over golang.org/x/mod/sumdb/note):
        <origin: "<host> - <treeID>">\\n<tree size>\\n<base64 root hash>\\n[<other lines>\\n]
        \\n                                     # blank separator (NOT signed)
        — <name> <base64(4-byte key-hint || signature)>\\n   # one or more

    The SIGNED bytes are `checkpoint.split(b"\\n\\n", 1)[0] + b"\\n"`. Raises
    :class:`RekorAnchorError` if the note is malformed.
    """
    try:
        text = checkpoint.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RekorAnchorError(f"checkpoint is not valid UTF-8: {exc}") from exc
    if "\n\n" not in text:
        raise RekorAnchorError(
            "checkpoint is not a signed note (no blank-line body/signature separator)"
        )
    body_part, sig_part = text.split("\n\n", 1)
    signed_body = (body_part + "\n").encode("utf-8")
    lines = body_part.split("\n")
    if len(lines) < 3:
        raise RekorAnchorError(
            "checkpoint body must have >=3 lines (origin, tree size, root hash)"
        )
    origin = lines[0]
    try:
        tree_size = int(lines[1])
    except ValueError as exc:
        raise RekorAnchorError(f"checkpoint tree-size line malformed: {exc}") from exc
    try:
        root_hash = base64.b64decode(lines[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RekorAnchorError(f"checkpoint root-hash line not base64: {exc}") from exc

    signatures: list[tuple[str, bytes, bytes]] = []
    for line in sig_part.split("\n"):
        if not line.startswith("— "):  # signature lines begin with U+2014 + space
            continue
        parts = line.split(" ")
        if len(parts) < 3:
            raise RekorAnchorError(f"malformed checkpoint signature line: {line!r}")
        name = parts[1]
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RekorAnchorError(f"checkpoint signature not base64: {exc}") from exc
        if len(raw) <= 4:
            raise RekorAnchorError("checkpoint signature too short (key-hint only)")
        signatures.append((name, raw[:4], raw[4:]))
    if not signatures:
        raise RekorAnchorError("checkpoint carries no signature lines")
    return CheckpointNote(origin, tree_size, root_hash, signed_body, tuple(signatures))


def verify_checkpoint_signature(
    checkpoint: bytes, rekor_log_pubkey: RekorLogKey
) -> bool:
    """Verify the log's signature carried in a Rekor checkpoint against the log key.

    Parses the signed-note (`parse_checkpoint_note`), selects the signature line whose 4-byte
    key-hint matches `rekor_log_pubkey` (hint convention by key type — see `rekor_key_hint`),
    and verifies it over the note's signed body: ECDSA/SHA-256 for a P-256 key (Rekor v1),
    pure Ed25519 for an Ed25519 key (Rekor v2). Witness co-signature lines on a v2 checkpoint
    carry other names and other hints and are simply not selected — this verifies the LOG's
    signature only, never a witness quorum. The signature is embedded IN the checkpoint (a Go
    signed-note), not supplied separately. Returns False on a malformed note, a missing
    matching signature, or a bad signature.

    GROUNDED: verifies the real `rekor.sigstore.dev` v1 checkpoint in
    `tests/fixtures/rekor_real_entry_v1.json` against the pinned ECDSA P-256 log key, and the
    real `log2025-alpha3.rekor.sigstage.dev` v2 checkpoint in
    `tests/fixtures/sigstore_staging_bundle_v0_3.json` against the captured Ed25519 key.
    """
    return _verified_checkpoint_hint(checkpoint, rekor_log_pubkey) is not None


def _verified_checkpoint_hint(
    checkpoint: bytes,
    rekor_log_pubkey: ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey,
) -> bytes | None:
    """The 4-byte key-hint of the signature line that VERIFIED under the log key,
    or None (malformed note, no matching line, bad signature). `verify_checkpoint_signature`
    is the boolean view; `verify_anchor` uses the hint to bind the entry's logID."""
    try:
        note = parse_checkpoint_note(checkpoint)
    except RekorAnchorError:
        return None
    is_ed = isinstance(rekor_log_pubkey, ed25519.Ed25519PublicKey)
    for name, hint, signature in note.signatures:
        key_hint = rekor_key_hint(rekor_log_pubkey, name if is_ed else None)
        if hint != key_hint:
            continue
        try:
            if is_ed:
                rekor_log_pubkey.verify(signature, note.signed_body)
            else:
                rekor_log_pubkey.verify(
                    signature, note.signed_body, ec.ECDSA(hashes.SHA256())
                )
            return hint
        except InvalidSignature:
            return None
    return None  # no signature line matched the pinned log key's hint


def assemble_rekor_backed_statement(
    signed_statement_cose: bytes, anchor: RekorAnchor
) -> dict:
    """Assemble the Rekor-backed transparent statement: Signed Statement + native Rekor anchor.

    NOTE: "transparent" here means "anchored to Rekor's append-only log", verified by
    re-deriving the inclusion proof. It is NOT a SCITT Transparent Statement (no COSE Receipt).
    """
    return {
        "format": "vkernel/rekor-backed-transparent-statement/v0.5-draft",
        "signed_statement_cose_hex": signed_statement_cose.hex(),
        "rekor": {
            "log_id": anchor.log_id,
            "log_index": anchor.log_index,
            "tree_size": anchor.tree_size,
            "root_hash": anchor.root_hash.hex(),
            "hashes": [h.hex() for h in anchor.hashes],
            "checkpoint": anchor.checkpoint.decode("utf-8", errors="replace"),
            "integrated_time": anchor.integrated_time,
        },
        "transparency_note": (
            "Rekor-backed (Sigstore transparency log). NOT a SCITT Transparent Statement: "
            "Rekor returns a native inclusion proof + signed checkpoint, not a COSE Receipt."
        ),
    }


class RekorTransport(Protocol):
    """Abstracts submitting a leaf preimage to a Rekor log and getting back its
    `(log_id, verification)` response. The live transport is network; tests replay a fixture."""

    def submit(self, leaf_preimage: bytes) -> tuple[str, dict]: ...


class ReplayTransport:
    """A RekorTransport that returns a pre-recorded `(log_id, verification)` response.

    For offline development and tests. A REAL captured Rekor response lives at
    `tests/fixtures/rekor_real_entry_v1.json` and validates Rekor's leaf canonicalization and
    checkpoint key against live bytes. The synthetic RFC 6962 fixtures additionally exercise
    the recompute math across tree sizes (see the module docstring).
    """

    def __init__(self, log_id: str, verification: dict) -> None:
        self._log_id = log_id
        self._verification = verification

    def submit(self, leaf_preimage: bytes) -> tuple[str, dict]:  # noqa: ARG002
        return self._log_id, self._verification


class LiveRekorTransport:
    """GATED live network transport. Raises until the gate is flipped, so it cannot no-op.

    It exists for registering NEXI's OWN SCITT signed statement natively
    (`register_signed_statement`). Nothing in the release path calls it: cosign is the
    SOLE Rekor writer for release artifacts (`sign-blob`, `attest-blob` for the
    image-binding bundle, `sign` / `attest` into the registry), so a release is
    checkable with this gated. Flipping it is three things in order — a posture
    decision (native registration is a further public, irreversible disclosure), an
    implementation of `submit` (POST `<rekor>/api/v1/log/entries`, returning the v1
    REST `(logID, verification)` shape) on a networked runner, and
    `register_signed_statement(verify=True)` so a proof that does not re-derive its
    own root refuses at registration. The first live entry is checked against the
    key resolved from the `sigstore-trust-root` role (`verify_anchor` also refuses
    an entry whose logID does not lead with that key's hint) and
    `rekor_body_subject_digests` naming the intended digest — the ceremony
    runbook lists the manual checks beside these. `ReplayTransport` is the
    offline default."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url

    def submit(self, leaf_preimage: bytes) -> tuple[str, dict]:  # noqa: ARG002
        raise NotImplementedError(
            "LiveRekorTransport is deferred to a networked runner (network POST to "
            f"{self._base_url}/api/v1/log/entries + response parse). Offline builds use "
            "ReplayTransport. See this module's docstring."
        )


def register_signed_statement(
    signed_statement_cose: bytes,
    transport: RekorTransport,
    *,
    leaf_preimage: bytes | None = None,
    verify: bool = True,
) -> dict:
    """Submit the Signed Statement to a Rekor log (via `transport`) and assemble the bundle.

    `leaf_preimage` defaults to the COSE statement bytes. A real Rekor entry canonicalizes the
    submitted object into its `body`, whose base64-decode is the logged leaf preimage (see the
    module docstring on leaf canonicalization). When `verify` is True (default), the returned
    anchor's inclusion proof is re-derived and a mismatch raises — so a transport that returns a
    proof inconsistent with the leaf fails closed at registration time.
    """
    preimage = leaf_preimage if leaf_preimage is not None else signed_statement_cose
    log_id, verification = transport.submit(preimage)
    anchor = RekorAnchor.from_rekor_verification(log_id, verification)
    if verify and not verify_inclusion_proof(preimage, anchor):
        raise RekorAnchorError(
            "Rekor returned an inclusion proof that does not re-derive its own root for the "
            "submitted leaf — refusing to assemble (fail-closed)."
        )
    return assemble_rekor_backed_statement(signed_statement_cose, anchor)


def rekor_anchor_from_sigstore_bundle(bundle: dict) -> tuple[RekorAnchor, bytes]:
    """Lossless reshape of a cosign Sigstore protobuf-bundle tlog entry → (anchor, leaf_preimage).

    `cosign sign-blob --bundle` (the NEW bundle format,
    `application/vnd.dev.sigstore.bundle.v0.3+json`) records the Rekor entry under
    `verificationMaterial.tlogEntries[0]`. This extracts that entry's inclusion proof, signed
    checkpoint, and canonicalized body into the in-tree :class:`RekorAnchor` shape, so the
    grounded offline verifier (`verify_rekor_backed_statement`) can check cosign's OWN entry
    WITHOUT re-running cosign or trusting its verdict. Cosign is the sole Fulcio+Rekor *writer*
    here; this keeps the *verify* side native — one write stack, verify-only re-derivation.

    This is PURE field extraction and decode: NO Merkle recompute, NO re-canonicalization of
    the body or checkpoint (a re-canonicalization would silently become a second verification
    path; losslessness is a binding condition). Field-encoding deltas vs the Rekor v1 REST
    shape (:meth:`RekorAnchor.from_rekor_verification`):

      * `rootHash` / `hashes` are base64 (protobuf `bytes`) here, hex in the REST API;
      * `logIndex` / `treeSize` are strings (protobuf int64→JSON) here, ints in REST;
      * the checkpoint is nested at `inclusionProof.checkpoint.envelope`;
      * the Merkle leaf preimage is `base64decode(tlogEntries[0].canonicalizedBody)`.

    Returns `(anchor, leaf_preimage)`; pass `leaf_preimage` to `verify_rekor_backed_statement`.
    Raises :class:`RekorAnchorError` if the bundle is malformed.

    GROUNDING: the field MAPPING is verified against the sigstore protobuf-bundle spec and a
    fixture re-encoded from the REAL Rekor v1 entry (`test_rekor_anchor.test_sigstore_bundle_*`):
    the same real Merkle data and real checkpoint, only the cosign-bundle envelope around them.
    The remaining deferred check is that cosign emits exactly this layout for OUR own `.cose`
    on the first live registration (`LiveRekorTransport` still raises). The leaf-canon rule
    `SHA256(0x00 ‖ base64decode(body))` is Trillian-level, so it holds across the
    `cose`/`dsse`/`hashedrekord` kinds — but confirm it once on the first own entry.
    """
    try:
        entries = bundle["verificationMaterial"]["tlogEntries"]
        if not entries:
            raise RekorAnchorError("Sigstore bundle has no tlogEntries")
        entry = entries[0]
        proof = entry["inclusionProof"]
        log_index = int(proof["logIndex"])
        tree_size = int(proof["treeSize"])
        root_hash = base64.b64decode(proof["rootHash"], validate=True)
        hashes = tuple(base64.b64decode(h, validate=True) for h in proof["hashes"])
        checkpoint = str(proof["checkpoint"]["envelope"]).encode("utf-8")
        # protobuf logId.keyId is base64; surface as hex to match the REST `log_id` convention.
        key_id_b64 = (entry.get("logId") or {}).get("keyId")
        log_id = base64.b64decode(key_id_b64, validate=True).hex() if key_id_b64 else ""
        integrated = entry.get("integratedTime")
        leaf_preimage = base64.b64decode(entry["canonicalizedBody"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise RekorAnchorError(
            f"malformed Sigstore protobuf-bundle tlog entry: {exc}"
        ) from exc
    anchor = RekorAnchor(
        log_id=log_id,
        log_index=log_index,
        tree_size=tree_size,
        root_hash=root_hash,
        hashes=hashes,
        checkpoint=checkpoint,
        integrated_time=int(integrated) if integrated is not None else None,
    )
    return anchor, leaf_preimage


# -----------------------------------------------------------------------------
# Phase C: consumer-side verification of a Rekor-backed transparent statement.
# -----------------------------------------------------------------------------

# Reason codes returned in the verdict — stable strings for callers to branch on.
REASON_MALFORMED_BUNDLE = "MALFORMED_BUNDLE"
REASON_MALFORMED_ANCHOR = "MALFORMED_ANCHOR"
REASON_INCLUSION_PROOF_FAILED = "INCLUSION_PROOF_DOES_NOT_REDERIVE_ROOT"
REASON_CHECKPOINT_SIGNATURE_INVALID = "CHECKPOINT_SIGNATURE_INVALID"
REASON_CHECKPOINT_NOT_EVALUATED = "CHECKPOINT_SIGNATURE_NOT_EVALUATED"
REASON_CHECKPOINT_ROOT_MISMATCH = "CHECKPOINT_ROOT_DISAGREES_WITH_INCLUSION_PROOF"
REASON_LOG_ID_DISAGREES_WITH_CHECKPOINT_KEY = "REKOR_LOG_ID_DISAGREES_WITH_CHECKPOINT_KEY"

# --- Subject binding: what does the logged LEAF commit to? ---------------------------------
# An inclusion proof + signed checkpoint prove "these leaf bytes are in the log". That is
# true of every public entry. A verdict about OUR artifact needs the leaf's CONTENT to commit
# to a digest the verifier holds. These codes are distinct from the proof codes above so a
# binding failure is attributable as binding, never mistaken for a broken proof.
REASON_SUBJECT_NOT_BOUND = "REKOR_SUBJECT_NOT_BOUND"
REASON_BODY_KIND_UNSUPPORTED = "REKOR_BODY_KIND_UNSUPPORTED"
REASON_BODY_UNPARSEABLE = "REKOR_BODY_UNPARSEABLE"
REASON_DSSE_PAYLOAD_ABSENT = "REKOR_DSSE_PAYLOAD_ABSENT"
REASON_DSSE_PAYLOAD_HASH_MISMATCH = "REKOR_DSSE_PAYLOAD_HASH_MISMATCH"
REASON_PREDICATE_TYPE_MISMATCH = "REKOR_PREDICATE_TYPE_MISMATCH"

#: in-toto predicateType of the release IMAGE-BINDING attestation (cosign
#: attest-blob over the image manifest bytes). The producer (release job) pins
#: to this string; `intoto_predicate_type` reads it back off a logged statement
#: so a consumer can require THIS attestation kind rather than any statement that
#: happens to name the digest among its subjects.
IMAGE_BINDING_PREDICATE_TYPE = "https://vkernel.dev/predicates/release-image-binding/v1"

_SHA256_ALGS = frozenset({"sha256", "sha2_256", "sha-256", "sha2-256"})


def _sha256_hex_or_none(algorithm: object, value: object, *, b64: bool) -> str | None:
    """Normalise one (algorithm, value) digest pair to `sha256:<64 hex>`; None if not sha256."""
    if not isinstance(algorithm, str) or algorithm.lower() not in _SHA256_ALGS:
        return None
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True) if b64 else bytes.fromhex(value)
    except (ValueError, binascii.Error):
        return None
    if len(raw) != 32:
        return None
    return "sha256:" + raw.hex()


def intoto_predicate_type(payload: bytes) -> str | None:
    """The `predicateType` an in-toto Statement payload declares, or None."""
    try:
        stmt = strict_json_loads(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(stmt, dict):
        return None
    pt = stmt.get("predicateType")
    return pt if isinstance(pt, str) else None


def _intoto_subject_digests(payload: bytes) -> frozenset[str]:
    """sha256 subject digests named by an in-toto Statement (v0.1 or v1) payload."""
    try:
        stmt = strict_json_loads(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return frozenset()
    if not isinstance(stmt, dict) or not isinstance(stmt.get("subject"), list):
        return frozenset()
    out: set[str] = set()
    for subj in stmt["subject"]:
        digest = subj.get("digest") if isinstance(subj, dict) else None
        if not isinstance(digest, dict):
            continue
        for alg, val in digest.items():
            norm = _sha256_hex_or_none(alg, val, b64=False)
            if norm is not None:
                out.add(norm)
    return frozenset(out)


def rekor_body_subject_digests(
    body: dict, dsse_payload: bytes | None
) -> tuple[frozenset[str], str | None, str | None]:
    """The `sha256:<hex>` digests a decoded Rekor entry body commits to, by entry kind.

    Returns `(digests, bound_via, reason)`. `bound_via` names the path the digests came from
    (printed on the verdict face); `reason` is a `REASON_*` code when NO binding is possible.
    Deny-by-default: an entry kind this function does not know is `REKOR_BODY_KIND_UNSUPPORTED`,
    never "assume the caller knows what they logged".

      * `hashedrekord` v0.0.1 — `spec.data.hash{algorithm,value(hex)}` (cosign `sign-blob`
        on Rekor v1: the digest IS sha256 of the signed blob).
      * `hashedrekord` v0.0.2 — `spec.hashedRekordV002.data{algorithm,digest(base64)}`
        (Rekor v2; grounded on `tests/fixtures/sigstore_staging_bundle_v0_3.json`).
      * `dsse` v0.0.1 — `spec.payloadHash` is sha256 of the DSSE payload. The body carries the
        HASH only, so the caller must supply the payload (the bundle's `dsseEnvelope.payload`);
        sha256(payload) must equal the logged hash, and the digests are then the in-toto
        Statement's `subject[*].digest.sha256`. A payload whose hash does not match is
        `REKOR_DSSE_PAYLOAD_HASH_MISMATCH` (a forged statement beside an honest log entry);
        no payload is `REKOR_DSSE_PAYLOAD_ABSENT`.
      * `intoto` v0.0.2 — `spec.content.payloadHash`, then as for `dsse`.
    """
    kind = body.get("kind")
    spec = body.get("spec")
    if not isinstance(spec, dict):
        return frozenset(), None, REASON_BODY_UNPARSEABLE

    if kind == "hashedrekord":
        v002 = spec.get("hashedRekordV002")
        if isinstance(v002, dict):
            data = v002.get("data") if isinstance(v002.get("data"), dict) else {}
            norm = _sha256_hex_or_none(
                data.get("algorithm"), data.get("digest"), b64=True
            )
        else:
            data = spec.get("data") if isinstance(spec.get("data"), dict) else {}
            h = data.get("hash") if isinstance(data.get("hash"), dict) else {}
            norm = _sha256_hex_or_none(h.get("algorithm"), h.get("value"), b64=False)
        if norm is None:
            return frozenset(), None, REASON_BODY_UNPARSEABLE
        return frozenset({norm}), "hashedrekord.data.digest", None

    if kind in ("dsse", "intoto"):
        if kind == "dsse":
            ph = spec.get("payloadHash")
        else:
            content = (
                spec.get("content") if isinstance(spec.get("content"), dict) else {}
            )
            ph = content.get("payloadHash")
        if not isinstance(ph, dict):
            return frozenset(), None, REASON_BODY_UNPARSEABLE
        logged = _sha256_hex_or_none(ph.get("algorithm"), ph.get("value"), b64=False)
        if logged is None:
            return frozenset(), None, REASON_BODY_UNPARSEABLE
        if dsse_payload is None:
            return frozenset(), None, REASON_DSSE_PAYLOAD_ABSENT
        if "sha256:" + hashlib.sha256(dsse_payload).hexdigest() != logged:
            return frozenset(), None, REASON_DSSE_PAYLOAD_HASH_MISMATCH
        via = f"{kind}.payloadHash->in-toto.subject"
        return _intoto_subject_digests(dsse_payload), via, None

    return frozenset(), None, REASON_BODY_KIND_UNSUPPORTED


def sigstore_bundle_dsse_payload(bundle: dict) -> bytes | None:
    """The decoded `dsseEnvelope.payload` of a Sigstore v0.3 bundle, or None if absent/bad."""
    env = bundle.get("dsseEnvelope")
    if not isinstance(env, dict) or not isinstance(env.get("payload"), str):
        return None
    try:
        return base64.b64decode(env["payload"], validate=True)
    except (ValueError, binascii.Error):
        return None


@dataclass(frozen=True)
class RekorVerdict:
    """Outcome of verifying a Rekor-backed transparent statement.

    ‼ `ok` is True ONLY when BOTH legs pass. `inclusion_verified` alone is necessary but NOT
    sufficient: an inclusion proof shows "this leaf is in a tree whose root is R", but R is
    just the root the bundle CLAIMS. Only `checkpoint_verified` — the checkpoint signed by
    Rekor's pinned log key — binds R to Rekor's genuine tree head. Without it, an adversary can
    forge an entire tree with any root. So a verdict with `checkpoint_verified is None` (no
    pinned key supplied) is INCOMPLETE and reports `ok=False`, never a pass. The checkpoint leg
    also requires the signed checkpoint's root to equal the inclusion proof's root, else the two
    legs attest different trees — a mismatch is a checkpoint failure, not a pass.
    """

    ok: bool
    inclusion_verified: bool
    checkpoint_verified: bool | None  # None => not evaluated (no pinned key supplied)
    reasons: tuple[str, ...]


def verify_anchor(
    anchor: RekorAnchor,
    leaf_preimage: bytes,
    *,
    rekor_log_pubkey: ec.EllipticCurvePublicKey | None = None,
) -> RekorVerdict:
    """Verify a parsed :class:`RekorAnchor` and its leaf preimage — both legs, fail-closed.

    The shared core of :func:`verify_rekor_backed_statement`, exposed so a caller that already
    holds an extracted anchor (e.g. ``rekor_anchor_from_sigstore_bundle`` on a cosign
    ``.sigstore-bundle.json``) can verify WITHOUT re-serialising into the assembled-statement
    dict shape:
      1. re-derive the inclusion proof (`verify_inclusion_proof`) — always evaluated;
      2. verify the checkpoint's log signature (P-256 or Ed25519 by key type) against Rekor's
         PINNED log key, and bind
         the signed checkpoint's root to the inclusion proof's root — ONLY when
         ``rekor_log_pubkey`` is supplied.

    ``ok`` is True iff BOTH legs pass. A None checkpoint (no pinned key) is INCOMPLETE, hence
    not ok (the contract on :class:`RekorVerdict`): an inclusion proof alone binds the leaf to
    a CLAIMED root; only the pinned-key checkpoint binds that root to Rekor's genuine tree head.
    """
    reasons: list[str] = []

    inclusion_ok = verify_inclusion_proof(leaf_preimage, anchor)
    if not inclusion_ok:
        reasons.append(REASON_INCLUSION_PROOF_FAILED)

    checkpoint_ok: bool | None
    if rekor_log_pubkey is not None:
        hint = _verified_checkpoint_hint(anchor.checkpoint, rekor_log_pubkey)
        if hint is None:
            checkpoint_ok = False
            reasons.append(REASON_CHECKPOINT_SIGNATURE_INVALID)
        else:
            # Signature valid — now bind the signed checkpoint to the proof: same root
            # AND same tree size, else the checkpoint attests a DIFFERENT tree head than
            # the one the inclusion proof re-derives (a signed head of size N with the
            # proof's root is not a head of size M). Until 2026-09-02 only the root was
            # compared (fresh-pass witness `w_rekor.py D`: size 999 vs proof size 1).
            try:
                note = parse_checkpoint_note(anchor.checkpoint)
            except RekorAnchorError:
                checkpoint_ok = False
                reasons.append(REASON_CHECKPOINT_SIGNATURE_INVALID)
            else:
                if note.root_hash == anchor.root_hash and note.tree_size == anchor.tree_size:
                    checkpoint_ok = True
                else:
                    checkpoint_ok = False
                    reasons.append(REASON_CHECKPOINT_ROOT_MISMATCH)
            # The entry's logID names the log; its leading 4 bytes are the key-hint of
            # the log's own signature line, so an entry that names a DIFFERENT log than
            # the key that verified its checkpoint is refused. An empty logID (REST
            # callers that never carried one) is not compared — disclosed, not graded.
            if anchor.log_id and not anchor.log_id.lower().startswith(hint.hex()):
                checkpoint_ok = False
                reasons.append(REASON_LOG_ID_DISAGREES_WITH_CHECKPOINT_KEY)
    else:
        checkpoint_ok = None
        reasons.append(REASON_CHECKPOINT_NOT_EVALUATED)

    # Both legs required for a pass. checkpoint_ok None (no pinned key) => INCOMPLETE => not ok.
    ok = inclusion_ok and checkpoint_ok is True
    return RekorVerdict(ok, inclusion_ok, checkpoint_ok, tuple(reasons))


def verify_rekor_backed_statement(
    bundle: dict,
    *,
    rekor_log_pubkey: ec.EllipticCurvePublicKey | None = None,
    leaf_preimage: bytes | None = None,
) -> RekorVerdict:
    """Verify an `assemble_rekor_backed_statement` bundle on the tier-2 network verifier.

    Composes the two real verifiers into one verdict:
      1. re-derive the inclusion proof (`verify_inclusion_proof`) — always evaluated;
      2. verify the checkpoint's log signature (P-256 or Ed25519 by key type) against Rekor's
         PINNED log key
         (`verify_checkpoint_signature`), and bind the signed checkpoint's root to the
         inclusion proof's root — evaluated ONLY when `rekor_log_pubkey` is supplied (e.g. via
         `load_rekor_log_public_key()` or the `sigstore-trust-root` TUF role). The signature is
         carried inside the checkpoint signed-note; it is NOT a separate argument.

    `leaf_preimage` defaults to the embedded COSE statement bytes (the default registration
    used by `register_signed_statement`); for a real Rekor entry pass
    `base64decode(entry["body"])` (the grounded leaf canonicalization — see module docstring).
    """
    rekor = bundle.get("rekor")
    statement_hex = bundle.get("signed_statement_cose_hex")
    if not isinstance(rekor, dict) or not isinstance(statement_hex, str):
        return RekorVerdict(False, False, None, (REASON_MALFORMED_BUNDLE,))
    try:
        preimage = (
            leaf_preimage if leaf_preimage is not None else bytes.fromhex(statement_hex)
        )
        anchor = RekorAnchor(
            log_id=str(rekor["log_id"]),
            log_index=int(rekor["log_index"]),
            tree_size=int(rekor["tree_size"]),
            root_hash=bytes.fromhex(rekor["root_hash"]),
            hashes=tuple(bytes.fromhex(h) for h in rekor["hashes"]),
            checkpoint=str(rekor["checkpoint"]).encode("utf-8"),
            integrated_time=rekor.get("integrated_time"),
        )
    except (KeyError, TypeError, ValueError):
        return RekorVerdict(False, False, None, (REASON_MALFORMED_ANCHOR,))

    return verify_anchor(anchor, preimage, rekor_log_pubkey=rekor_log_pubkey)
