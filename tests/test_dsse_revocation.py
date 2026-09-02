"""tests/test_dsse_revocation.py — verifier-side revocation (iat-ignoring, signed list).

PRD success criterion (D1 — iat-backdating closure)
----------------------------------------------------
``is_revoked(rev_list, kid, verifier_now)`` takes NO ``iat`` argument and
makes NO decision based on any envelope ``iat``.  The load-bearing test
``test_iat_independence`` proves this structurally:

  * ``is_revoked`` has no ``iat`` parameter in its signature (asserted
    by inspecting ``inspect.signature``).
  * Two hypothetical envelopes with radically different ``iat`` values
    (iat=0, iat=10**12) produce IDENTICAL verdicts for the same
    (kid, verifier_now, rev_list) triple — because ``iat`` is simply
    never passed and never consulted.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.revocation import (
    DSSE_KEY_REVOKED,
    DSSE_REVOCATION_LIST_ABSENT,
    DSSE_REVOCATION_LIST_STALE,
    DSSE_REVOCATION_TIME_UNSOUND,
    RevocationList,
    RevocationListInvalid,
    is_revoked,
    load_revocation_list,
)

# ---------------------------------------------------------------------------
# Test fixture helpers
# ---------------------------------------------------------------------------

_NOW = 1_700_000_000  # fixed "present" for deterministic tests


def _b64url_nopad_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _kid_from_raw32(pubkey_raw32: bytes) -> str:
    """Derive kid = base64url_nopad(sha256(pubkey_raw32))."""
    return _b64url_nopad_encode(hashlib.sha256(pubkey_raw32).digest())


def _make_root_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    """Generate a test Ed25519 root keypair.

    Returns (private_key, pubkey_raw32, root_kid).
    """
    priv = Ed25519PrivateKey.generate()
    pub_raw32 = priv.public_key().public_bytes_raw()
    root_kid = _kid_from_raw32(pub_raw32)
    return priv, pub_raw32, root_kid


def _sign_revocation_list(
    priv_key: Ed25519PrivateKey,
    pub_raw32: bytes,
    revocations: list[dict],
    issued_at: int,
    expires: int,
) -> bytes:
    """Build and sign a vkernel_revocations.json document.

    Returns the raw JSON bytes of the complete signed document.
    """
    root_kid = _kid_from_raw32(pub_raw32)
    payload = {
        "revocations": revocations,
        "issued_at": issued_at,
        "expires": expires,
    }
    canonical_payload_bytes = rfc8785.dumps(payload)
    sig_bytes = priv_key.sign(canonical_payload_bytes)
    sig_str = _b64url_nopad_encode(sig_bytes)
    doc = {
        "payload": payload,
        "sig": sig_str,
        "root_kid": root_kid,
    }
    return json.dumps(doc).encode("utf-8")


def _make_resolver(pub_raw32: bytes, root_kid: str):
    """Return a resolver callable that returns pub_raw32 for root_kid."""

    def resolver(kid: str) -> bytes:
        if kid == root_kid:
            return pub_raw32
        raise RevocationListInvalid(f"unknown root_kid: {kid!r}")

    return resolver


def _load_list(raw_bytes: bytes, resolver) -> RevocationList:
    return load_revocation_list(raw_bytes, revocation_root_resolver=resolver)


# ---------------------------------------------------------------------------
# Shared fixture: a root keypair + one revoked kid + one not-listed kid
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def root_keypair():
    priv, pub_raw32, root_kid = _make_root_keypair()
    return priv, pub_raw32, root_kid


@pytest.fixture(scope="module")
def revoked_kid():
    """A kid for a key that IS in the revocation list with not_after = _NOW."""
    raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    return _kid_from_raw32(raw)


@pytest.fixture(scope="module")
def other_kid():
    """A kid for a key that is NOT in the revocation list."""
    raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    return _kid_from_raw32(raw)


@pytest.fixture(scope="module")
def fresh_rev_list_raw(root_keypair, revoked_kid):
    priv, pub_raw32, root_kid = root_keypair
    return _sign_revocation_list(
        priv,
        pub_raw32,
        revocations=[{"kid": revoked_kid, "not_after": _NOW}],
        issued_at=_NOW - 3600,
        expires=_NOW + 86400,
    )


@pytest.fixture(scope="module")
def resolver(root_keypair):
    priv, pub_raw32, root_kid = root_keypair
    return _make_resolver(pub_raw32, root_kid)


@pytest.fixture(scope="module")
def rev_list(fresh_rev_list_raw, resolver) -> RevocationList:
    return _load_list(fresh_rev_list_raw, resolver)


# ===========================================================================
# D1 LOAD-BEARING TEST — iat-independence
# ===========================================================================


class TestIatIndependence:
    """Proves structurally that is_revoked never reads any envelope iat.

    The PRD success criterion: a compromised key cannot escape revocation by
    backdating the envelope iat because iat is not a parameter of is_revoked
    and is never consulted in the decision.
    """

    def test_is_revoked_has_no_iat_parameter(self):
        """is_revoked's signature must have no 'iat' parameter."""
        sig = inspect.signature(is_revoked)
        assert "iat" not in sig.parameters, (
            "is_revoked must NOT have an 'iat' parameter — the entire "
            "revocation decision must be independent of any signer-controlled "
            "envelope field (D1 closure)"
        )

    @pytest.mark.parametrize(
        "hypothetical_envelope_iat",
        [
            0,  # iat=0: the epoch — an adversary's extreme backdating attempt
            10**12,  # iat far in the future: another forged iat
            _NOW - 86400 * 365,  # iat one year ago
            _NOW,  # iat = now (normal case)
        ],
        ids=["iat_zero", "iat_far_future", "iat_one_year_ago", "iat_now"],
    )
    def test_revoked_verdict_identical_regardless_of_hypothetical_iat(
        self, rev_list, revoked_kid, hypothetical_envelope_iat
    ):
        """For a revoked kid, the verdict is identical for any hypothetical envelope iat.

        Since is_revoked takes no iat argument, we demonstrate this by:
        1. Calling is_revoked with the same (rev_list, kid, verifier_now) triple.
        2. Observing that the verdict is revoked=True / DSSE_KEY_REVOKED.
        3. Noting that no iat was passed — it is simply not a parameter.

        The parametrization over hypothetical_envelope_iat documents the
        invariant: no matter what iat value a malicious signer put in the
        envelope (iat=0, iat=10^12, anything), the verdict is the same because
        iat is never consulted.
        """
        # verifier_now = _NOW means not_after = _NOW, so revoked (>= boundary)
        verdict = is_revoked(rev_list, revoked_kid, _NOW)
        # hypothetical_envelope_iat is NEVER passed — it is not a parameter.
        # It is listed here only to document the invariant and make the test
        # parametric over different adversarial iat values.
        _ = hypothetical_envelope_iat  # explicitly unused — that IS the proof

        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_KEY_REVOKED

    def test_same_call_same_verdict_two_adversarial_iats(self, rev_list, revoked_kid):
        """Explicit cross-iat comparison: two calls with IDENTICAL arguments.

        Both calls represent envelopes with different iat values (iat=0 vs
        iat=10**12), but since iat is not passed to is_revoked, the call is
        LITERALLY the same call with the same arguments. The verdicts are
        identical by construction — not by coincidence.
        """
        # "envelope A" with iat=0 (extreme backdating)
        verdict_a = is_revoked(rev_list, revoked_kid, _NOW)
        # "envelope B" with iat=10**12 (far future — also adversarial)
        verdict_b = is_revoked(rev_list, revoked_kid, _NOW)

        # Both calls are identical because iat is not a parameter.
        # The verdicts must be identical.
        assert verdict_a.revoked == verdict_b.revoked
        assert verdict_a.reason_code == verdict_b.reason_code
        assert verdict_a.revocation_list_hash == verdict_b.revocation_list_hash
        # Comment: if iat were consulted, a backdated-iat envelope could produce
        # a different verdict than a normal-iat envelope. It cannot here.


# ===========================================================================
# Core revocation logic
# ===========================================================================


class TestRevocationDecision:
    def test_revoked_at_boundary(self, rev_list, revoked_kid):
        """verifier_now == not_after → revoked (inclusive boundary)."""
        verdict = is_revoked(rev_list, revoked_kid, _NOW)
        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_KEY_REVOKED
        assert verdict.revocation_list_hash == rev_list.revocation_list_hash
        assert verdict.verifier_now == _NOW

    def test_revoked_after_boundary(self, rev_list, revoked_kid):
        """verifier_now > not_after → revoked."""
        verdict = is_revoked(rev_list, revoked_kid, _NOW + 1)
        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_KEY_REVOKED

    def test_not_yet_revoked_before_boundary(self, rev_list, revoked_kid):
        """verifier_now < not_after → not revoked (key's cutoff not elapsed)."""
        verdict = is_revoked(rev_list, revoked_kid, _NOW - 1)
        assert verdict.revoked is False
        assert verdict.reason_code is None
        assert verdict.revocation_list_hash == rev_list.revocation_list_hash
        assert verdict.verifier_now == _NOW - 1

    def test_not_listed_kid_not_revoked(self, rev_list, other_kid):
        """A kid absent from the list is not revoked (list is fresh, time sound)."""
        verdict = is_revoked(rev_list, other_kid, _NOW - 100)
        assert verdict.revoked is False
        assert verdict.reason_code is None

    def test_verdict_records_list_hash_and_verifier_now(self, rev_list, revoked_kid):
        """Every verdict carries revocation_list_hash and verifier_now."""
        t = _NOW + 500
        verdict = is_revoked(rev_list, revoked_kid, t)
        assert verdict.revocation_list_hash == rev_list.revocation_list_hash
        assert verdict.verifier_now == t
        assert len(verdict.revocation_list_hash) == 64  # sha256 hex


# ===========================================================================
# Fail-closed: stale list
# ===========================================================================


class TestStaleList:
    def test_stale_list_fails_closed(self, root_keypair, revoked_kid, other_kid):
        """verifier_now > expires → DSSE_REVOCATION_LIST_STALE (fail-closed)."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[{"kid": revoked_kid, "not_after": _NOW - 9999}],
            issued_at=_NOW - 7200,
            expires=_NOW - 3600,  # already expired
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)

        # verifier_now > expires
        verdict = is_revoked(rl, other_kid, _NOW)
        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_REVOCATION_LIST_STALE

    def test_stale_via_max_list_age(self, root_keypair, revoked_kid, other_kid):
        """max_list_age exceeded → DSSE_REVOCATION_LIST_STALE."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[],
            issued_at=_NOW - 10000,
            expires=_NOW + 86400,  # formally not expired
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)

        # max_list_age=5000 < 10000 seconds since issued_at
        verdict = is_revoked(rl, other_kid, _NOW, max_list_age=5000)
        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_REVOCATION_LIST_STALE

    def test_absent_list_fails_closed(self, other_kid):
        """None rev_list → DSSE_REVOCATION_LIST_ABSENT (fail-closed)."""
        verdict = is_revoked(None, other_kid, _NOW)
        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_REVOCATION_LIST_ABSENT
        assert verdict.verifier_now == _NOW


# ===========================================================================
# Fail-closed: time unsound
# ===========================================================================


class TestTimeUnsound:
    def test_backward_clock_jump_fails_closed(self, root_keypair, other_kid):
        """verifier_now far before issued_at → DSSE_REVOCATION_TIME_UNSOUND."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[],
            issued_at=_NOW,
            expires=_NOW + 86400,
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)

        # verifier_now = _NOW - 1000, issued_at = _NOW, skew = 300 → unsound
        verdict = is_revoked(rl, other_kid, _NOW - 1000, max_clock_skew=300)
        assert verdict.revoked is True
        assert verdict.reason_code == DSSE_REVOCATION_TIME_UNSOUND

    def test_within_clock_skew_is_ok(self, root_keypair, other_kid):
        """verifier_now within max_clock_skew of issued_at is accepted."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[],
            issued_at=_NOW,
            expires=_NOW + 86400,
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)

        # verifier_now = _NOW - 100, issued_at = _NOW, skew = 300 → OK
        verdict = is_revoked(rl, other_kid, _NOW - 100, max_clock_skew=300)
        assert verdict.revoked is False
        assert verdict.reason_code is None


# ===========================================================================
# Signature verification: bad sig → RevocationListInvalid
# ===========================================================================


class TestSignatureVerification:
    def test_tampered_payload_raises(self, root_keypair):
        """Tampering one byte of the payload JSON → RevocationListInvalid."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[],
            issued_at=_NOW - 100,
            expires=_NOW + 86400,
        )
        # Parse and tamper: change issued_at in the payload
        doc = json.loads(raw)
        doc["payload"]["issued_at"] = doc["payload"]["issued_at"] + 1
        tampered = json.dumps(doc).encode("utf-8")

        resolver = _make_resolver(pub_raw32, root_kid)
        with pytest.raises(RevocationListInvalid, match="signature"):
            load_revocation_list(tampered, revocation_root_resolver=resolver)

    def test_wrong_root_key_raises(self, root_keypair):
        """Signing with key A but verifying with key B → RevocationListInvalid."""
        priv_a, pub_raw32_a, root_kid_a = root_keypair
        priv_b, pub_raw32_b, root_kid_b = _make_root_keypair()

        # Signed by key B, but doc says root_kid = root_kid_a
        raw = _sign_revocation_list(
            priv_b,  # wrong key
            pub_raw32_a,  # root_kid derived from A
            revocations=[],
            issued_at=_NOW - 100,
            expires=_NOW + 86400,
        )
        # Resolver returns A's pubkey for root_kid_a
        resolver = _make_resolver(pub_raw32_a, root_kid_a)
        with pytest.raises(RevocationListInvalid, match="signature"):
            load_revocation_list(raw, revocation_root_resolver=resolver)

    def test_corrupted_sig_bytes_raises(self, root_keypair):
        """One byte flipped in the sig field → RevocationListInvalid."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[],
            issued_at=_NOW - 100,
            expires=_NOW + 86400,
        )
        doc = json.loads(raw)
        # Corrupt the first character of the base64url sig
        sig = doc["sig"]
        # Flip a character (A→B or B→A)
        corrupted_first = "B" if sig[0] != "B" else "A"
        doc["sig"] = corrupted_first + sig[1:]
        tampered = json.dumps(doc).encode("utf-8")

        resolver = _make_resolver(pub_raw32, root_kid)
        with pytest.raises(RevocationListInvalid):
            load_revocation_list(tampered, revocation_root_resolver=resolver)

    def test_unknown_root_kid_raises(self, root_keypair):
        """Resolver raising for an unknown kid → RevocationListInvalid."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[],
            issued_at=_NOW - 100,
            expires=_NOW + 86400,
        )

        # Resolver that rejects everything
        def empty_resolver(kid: str) -> bytes:
            raise RevocationListInvalid(f"unknown: {kid!r}")

        with pytest.raises(RevocationListInvalid):
            load_revocation_list(raw, revocation_root_resolver=empty_resolver)

    def test_malformed_json_raises(self):
        """Non-JSON bytes → RevocationListInvalid."""
        with pytest.raises(RevocationListInvalid, match="JSON"):
            load_revocation_list(
                b"not json at all!!!", revocation_root_resolver=lambda k: b"\x00" * 32
            )

    def test_missing_sig_field_raises(self, root_keypair):
        """Document missing 'sig' key → RevocationListInvalid."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv, pub_raw32, revocations=[], issued_at=_NOW - 100, expires=_NOW + 86400
        )
        doc = json.loads(raw)
        del doc["sig"]
        resolver = _make_resolver(pub_raw32, root_kid)
        with pytest.raises(RevocationListInvalid, match="sig"):
            load_revocation_list(
                json.dumps(doc).encode(), revocation_root_resolver=resolver
            )


# ===========================================================================
# revocation_list_hash recorded in every verdict
# ===========================================================================


class TestAuditTrail:
    def test_hash_and_now_in_revoked_verdict(self, rev_list, revoked_kid):
        v = is_revoked(rev_list, revoked_kid, _NOW)
        assert v.revocation_list_hash == rev_list.revocation_list_hash
        assert v.verifier_now == _NOW

    def test_hash_and_now_in_not_revoked_verdict(self, rev_list, other_kid):
        t = _NOW - 100
        v = is_revoked(rev_list, other_kid, t)
        assert v.revocation_list_hash == rev_list.revocation_list_hash
        assert v.verifier_now == t

    def test_hash_and_now_in_stale_verdict(self, root_keypair, other_kid):
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv, pub_raw32, revocations=[], issued_at=_NOW - 7200, expires=_NOW - 1
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)
        v = is_revoked(rl, other_kid, _NOW)
        assert v.revoked is True
        assert v.reason_code == DSSE_REVOCATION_LIST_STALE
        assert v.revocation_list_hash == rl.revocation_list_hash
        assert v.verifier_now == _NOW

    def test_list_hash_is_sha256_of_raw_bytes(self, root_keypair, revoked_kid):
        """RevocationList.revocation_list_hash == sha256(raw_bytes)."""
        priv, pub_raw32, root_kid = root_keypair
        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[{"kid": revoked_kid, "not_after": _NOW}],
            issued_at=_NOW - 3600,
            expires=_NOW + 86400,
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)
        expected_hash = hashlib.sha256(raw).hexdigest()
        assert rl.revocation_list_hash == expected_hash


# ===========================================================================
# Multiple entries in revocation list
# ===========================================================================


class TestMultipleEntries:
    def test_only_matching_kid_is_revoked(self, root_keypair):
        priv, pub_raw32, root_kid = root_keypair
        kid_a_raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        kid_b_raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        kid_a = _kid_from_raw32(kid_a_raw)
        kid_b = _kid_from_raw32(kid_b_raw)

        raw = _sign_revocation_list(
            priv,
            pub_raw32,
            revocations=[
                {"kid": kid_a, "not_after": _NOW - 100},  # already revoked
                {"kid": kid_b, "not_after": _NOW + 9999},  # not yet revoked
            ],
            issued_at=_NOW - 3600,
            expires=_NOW + 86400,
        )
        resolver = _make_resolver(pub_raw32, root_kid)
        rl = _load_list(raw, resolver)

        verdict_a = is_revoked(rl, kid_a, _NOW)
        assert verdict_a.revoked is True
        assert verdict_a.reason_code == DSSE_KEY_REVOKED

        verdict_b = is_revoked(rl, kid_b, _NOW)
        assert verdict_b.revoked is False
        assert verdict_b.reason_code is None


# ---------------------------------------------------------------------------
# Base64url strict-parse (sig-field malleability)
#
# The stdlib urlsafe_b64decode does NOT validate: it silently DISCARDS
# characters outside the alphabet. audit_bundle.dsse.pae.b64url_nopad_decode
# guards against that explicitly; this module's deliberately-duplicated copy
# (standalone-auditability contract) had lost the guard. Measured before the
# fix: "aGVs!!!!bG8gd29ybGQ" decoded to b"hello world", aliasing the canonical
# encoding. The `remainder == 1` length check does not cover it — stray
# characters injected in MULTIPLES OF FOUR leave len(s) % 4 unchanged and pass
# straight through. Accidentally safe is not safe.
# ---------------------------------------------------------------------------

CANONICAL_B64URL = "aGVsbG8gd29ybGQ"  # -> b"hello world", 15 chars

# Stray characters injected 4 at a time: len % 4 is unchanged, so the length
# check cannot fire. Only alphabet validation rejects these.
LENGTH_PRESERVING_INJECTIONS = [
    CANONICAL_B64URL[:4] + "!!!!" + CANONICAL_B64URL[4:],
    CANONICAL_B64URL[:4] + "\n\n\n\n" + CANONICAL_B64URL[4:],
    CANONICAL_B64URL[:4] + "\n \n " + CANONICAL_B64URL[4:],
    CANONICAL_B64URL[:4] + "****" + CANONICAL_B64URL[4:],
]


@pytest.mark.parametrize("probe", LENGTH_PRESERVING_INJECTIONS)
def test_b64url_decode_rejects_non_alphabet_characters(probe):
    """Non-alphabet characters must be REJECTED, not silently discarded into
    an alias of the canonical encoding."""
    from audit_bundle.revocation import _b64url_nopad_decode

    with pytest.raises(ValueError):  # binascii.Error subclasses ValueError
        _b64url_nopad_decode(probe)


def test_b64url_decode_still_accepts_canonical():
    """The guard must not reject well-formed input."""
    from audit_bundle.revocation import _b64url_nopad_decode

    assert _b64url_nopad_decode(CANONICAL_B64URL) == b"hello world"
    assert _b64url_nopad_decode("") == b""


@pytest.mark.parametrize("probe", LENGTH_PRESERVING_INJECTIONS)
def test_revocation_copy_agrees_with_pae_copy(probe):
    """Drift guard for the two hand-maintained copies.

    revocation._b64url_nopad_decode is duplicated from dsse.pae rather than
    imported, to preserve this module's standalone-auditability contract. That
    contract's cost is drift: the revocation copy silently lost pae's alphabet
    guard. Pin the copies to the same behaviour so the next divergence fails
    loudly here instead of in a verdict.
    """
    from audit_bundle.dsse.pae import b64url_nopad_decode as pae_decode
    from audit_bundle.revocation import _b64url_nopad_decode as rev_decode

    pae_exc = rev_exc = None
    try:
        pae_out = pae_decode(probe)
    except ValueError as exc:
        pae_exc, pae_out = type(exc).__name__, None
    try:
        rev_out = rev_decode(probe)
    except ValueError as exc:
        rev_exc, rev_out = type(exc).__name__, None

    assert (pae_exc, pae_out) == (rev_exc, rev_out), (
        f"pae and revocation base64url decoders disagree on {probe!r}: "
        f"pae={pae_exc or pae_out!r} revocation={rev_exc or rev_out!r}"
    )


def test_malleable_sig_field_is_rejected_end_to_end(root_keypair):
    """A signed list whose `sig` string carries stray characters must be
    refused as malformed — not silently normalized into the valid signature."""
    priv, pub_raw32, root_kid = root_keypair
    raw = _sign_revocation_list(
        priv, pub_raw32, [{"kid": "some-kid", "not_after": 1000}], 500, 10**12
    )
    doc = json.loads(raw)
    resolver = _make_resolver(pub_raw32, root_kid)

    # Control: the untampered document loads.
    assert _load_list(json.dumps(doc).encode("utf-8"), resolver) is not None

    # Inject 4 stray characters into `sig` — len % 4 unchanged, bytes identical
    # under a non-validating decoder.
    sig = doc["sig"]
    doc["sig"] = sig[:8] + "\n \n " + sig[8:]
    with pytest.raises(RevocationListInvalid, match="base64url"):
        _load_list(json.dumps(doc).encode("utf-8"), resolver)


# ---------------------------------------------------------------------------
# Non-canonical base64url (trailing-bit malleability)
#
# base64 leaves unused low bits in the final group. A 32-byte kid encodes to 43
# chars with 2 slack bits (4 strings per value); a 64-byte Ed25519 signature to
# 86 chars with 4 slack bits (16 strings per value). Every alias decodes to
# identical bytes, so one signature verifies under all 16 spellings while
# load_revocation_list records revocation_list_hash = sha256(raw_bytes) — a
# different hash for each. The hash is documented as the auditor's replay
# handle for the decision; 16 hashes for one signed list breaks that.
#
# Measured before the guard: 78/78 genuine base64url values in examples/ and
# tests/ were already canonical, so rejecting aliases costs nothing in-tree.
# ---------------------------------------------------------------------------

B64URL_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _aliases_of(canonical: str) -> list[str]:
    """Every non-canonical string that decodes to the same bytes as
    ``canonical``, produced by varying the final character over the alphabet."""
    want = base64.urlsafe_b64decode(
        canonical + "=" * ((4 - len(canonical) % 4) % 4)
    )
    out = []
    for ch in B64URL_ALPHABET:
        cand = canonical[:-1] + ch
        if cand == canonical:
            continue
        try:
            got = base64.urlsafe_b64decode(
                cand + "=" * ((4 - len(cand) % 4) % 4)
            )
        except Exception:
            continue
        if got == want:
            out.append(cand)
    return out


def test_slack_bits_exist_at_the_real_payload_sizes():
    """Control: the aliasing this guard closes is real at the sizes actually
    used — a 32-byte kid and a 64-byte Ed25519 signature."""
    kid = _b64url_nopad_encode(hashlib.sha256(b"some-pubkey").digest())
    sig = _b64url_nopad_encode(b"\x01" * 64)
    assert len(kid) == 43 and len(_aliases_of(kid)) == 3   # 2 slack bits -> 4 total
    assert len(sig) == 86 and len(_aliases_of(sig)) == 15  # 4 slack bits -> 16 total


def test_non_canonical_encodings_are_rejected_by_both_copies():
    from audit_bundle.dsse.pae import b64url_nopad_decode as pae_decode
    from audit_bundle.revocation import _b64url_nopad_decode as rev_decode

    kid = _b64url_nopad_encode(hashlib.sha256(b"some-pubkey").digest())
    sig = _b64url_nopad_encode(b"\x01" * 64)

    for canonical in (kid, sig):
        # The canonical spelling still decodes.
        assert rev_decode(canonical) == pae_decode(canonical)
        # Every alias is refused by BOTH copies.
        for alias in _aliases_of(canonical):
            with pytest.raises(ValueError):
                rev_decode(alias)
            with pytest.raises(ValueError):
                pae_decode(alias)


def test_alias_sig_cannot_produce_a_second_valid_list_hash(root_keypair):
    """The end-to-end consequence: an aliased `sig` would verify identically
    while changing sha256(raw_bytes), giving one signed list two replay
    handles. It must be refused at parse instead."""
    priv, pub_raw32, root_kid = root_keypair
    raw = _sign_revocation_list(
        priv, pub_raw32, [{"kid": "some-kid", "not_after": 1000}], 500, 10**12
    )
    doc = json.loads(raw)
    resolver = _make_resolver(pub_raw32, root_kid)

    # Control: canonical document loads and records a hash.
    good = _load_list(json.dumps(doc).encode("utf-8"), resolver)
    assert good.revocation_list_hash

    aliases = _aliases_of(doc["sig"])
    assert aliases, "a 64-byte Ed25519 signature must have trailing-bit aliases"
    for alias in aliases[:3]:
        tampered = dict(doc, sig=alias)
        with pytest.raises(RevocationListInvalid, match="base64url"):
            _load_list(json.dumps(tampered).encode("utf-8"), resolver)
