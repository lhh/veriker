"""verify_envelope(payload_type=...) reaches the header parser.

Finding (2026-09-06, authority_join_probe two-hop build): ``verify_envelope`` took a
``payload_type`` keyword, documented it as "the payloadType URI to pin", and used it for
the PAE preimage — but step 1 called ``parse_strict_envelope(raw)`` with no argument, and
the parser compared against its own ``PINNED_PAYLOAD_TYPE`` constant. So every value but
the pin was refused at the header (DSSE_PAYLOADTYPE_MISMATCH) before a signature was
read, and a real in-toto envelope (``application/vnd.in-toto+json``) could never verify.
``sign_envelope(payload_type=X)`` honoured X, so the module could sign what it could not
verify.

The class this file tests is "header check and PAE preimage use ONE value, the caller's":

* the parameter is honoured (round-trip under a non-default type verifies);
* the pin still holds by default (an in-toto envelope is refused with no parameter);
* the parameter is enforced in BOTH directions (a pinned envelope is refused when the
  caller asks for in-toto);
* the PAE binds the type: an attacker who rewrites the header's ``payloadType`` to what
  the verifier asks for gets DSSE_SIGNATURE_INVALID, not a pass;
* NFC normalisation applies to the parameter as well as the envelope;
* a non-str or empty parameter is a caller bug and raises ValueError before any producer
  byte is read (the never-raise contract covers producer bytes only).

Control: reverting ``parse_strict_envelope(raw_sidecar_bytes, payload_type=pt)`` to the
old no-argument call makes ``test_parameter_is_honoured_round_trip`` fail with
DSSE_PAYLOADTYPE_MISMATCH (run 2026-09-06 while landing the fix).
"""

from __future__ import annotations

import json
import unicodedata

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.dsse.envelope import PINNED_URI, sign_envelope, verify_envelope
from audit_bundle.dsse.header import (
    DSSE_PAYLOADTYPE_MISMATCH,
    PINNED_PAYLOAD_TYPE,
    DSSEHeaderError,
    parse_strict_envelope,
)
from audit_bundle.dsse.pae import kid_from_raw32

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x5a" * 32)
_PUB = _KEY.public_key().public_bytes_raw()
_ALLOWLIST = {kid_from_raw32(_PUB): _PUB}

INTOTO = "application/vnd.in-toto+json"
_PAYLOAD = b'{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x"}'


def _sidecar(payload_type: str) -> bytes:
    return json.dumps(sign_envelope(_PAYLOAD, _KEY, payload_type=payload_type)).encode()


def test_parameter_is_honoured_round_trip() -> None:
    res = verify_envelope(_sidecar(INTOTO), _ALLOWLIST, payload_type=INTOTO)
    assert res.ok, (res.reason_code, res.detail)
    assert res.payload_bytes == _PAYLOAD


def test_default_still_pins_the_vkernel_uri() -> None:
    res = verify_envelope(_sidecar(INTOTO), _ALLOWLIST)
    assert not res.ok
    assert res.reason_code == DSSE_PAYLOADTYPE_MISMATCH
    assert PINNED_URI in res.detail


def test_parameter_is_enforced_in_both_directions() -> None:
    # A pinned-type envelope is NOT accepted by a caller asking for in-toto.
    res = verify_envelope(_sidecar(PINNED_URI), _ALLOWLIST, payload_type=INTOTO)
    assert not res.ok
    assert res.reason_code == DSSE_PAYLOADTYPE_MISMATCH
    assert INTOTO in res.detail


def test_rewriting_the_header_to_the_requested_type_fails_the_signature() -> None:
    # Signed under the pin; attacker edits payloadType to what the verifier wants.
    d = sign_envelope(_PAYLOAD, _KEY, payload_type=PINNED_URI)
    d["payloadType"] = INTOTO
    res = verify_envelope(json.dumps(d).encode(), _ALLOWLIST, payload_type=INTOTO)
    assert not res.ok
    assert res.reason_code == "DSSE_SIGNATURE_INVALID", (res.reason_code, res.detail)


def test_nfc_normalisation_applies_to_the_parameter() -> None:
    nfc = "https://example.test/typé"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfd != nfc
    # Envelope signed under NFC; caller passes NFD. Both normalise to NFC.
    res = verify_envelope(_sidecar(nfc), _ALLOWLIST, payload_type=nfd)
    assert res.ok, (res.reason_code, res.detail)
    # And the parser reports the caller's NFC form.
    env = parse_strict_envelope(_sidecar(nfc), payload_type=nfd)
    assert env.payload_type == nfc


def test_parser_default_equals_the_module_pin() -> None:
    env = parse_strict_envelope(_sidecar(PINNED_URI))
    assert env.payload_type == PINNED_PAYLOAD_TYPE == PINNED_URI
    with pytest.raises(DSSEHeaderError) as ei:
        parse_strict_envelope(_sidecar(INTOTO))
    assert ei.value.code == DSSE_PAYLOADTYPE_MISMATCH


@pytest.mark.parametrize("bad", ["", None, 7, b"application/vnd.in-toto+json"])
def test_a_bad_parameter_is_a_caller_error_not_a_verdict(bad: object) -> None:
    with pytest.raises(ValueError):
        parse_strict_envelope(_sidecar(PINNED_URI), payload_type=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify_envelope(_sidecar(PINNED_URI), _ALLOWLIST, payload_type=bad)  # type: ignore[arg-type]


def test_an_empty_parameter_cannot_match_an_empty_header() -> None:
    # The reason "" is refused as a parameter: an envelope carrying payloadType ""
    # must not become verifiable by a caller mis-configured with "".
    d = sign_envelope(_PAYLOAD, _KEY, payload_type=PINNED_URI)
    d["payloadType"] = ""
    with pytest.raises(ValueError):
        verify_envelope(json.dumps(d).encode(), _ALLOWLIST, payload_type="")


# Red-team witness (2026-09-06 Stage 5): a lone surrogate is a legal non-empty str that
# passed the first guard, and `pae()` raised UnicodeEncodeError out of verify_envelope
# AFTER the producer's JSON, payload and signatures had been parsed. The class is "the
# parameter reaches the PAE without the guard having proven it encodable".
@pytest.mark.parametrize("surrogate", ["\ud800", "application/\udcff", "x\ud83d"])
def test_a_lone_surrogate_parameter_is_a_ValueError_before_any_producer_byte(
    surrogate: str,
) -> None:
    # Producer bytes that would themselves be refused if ever read: not JSON at all.
    with pytest.raises(ValueError):
        parse_strict_envelope(b"not json", payload_type=surrogate)
    with pytest.raises(ValueError):
        verify_envelope(b"not json", _ALLOWLIST, payload_type=surrogate)
    # And the exact red-team witness: a matching surrogate in the envelope header.
    d = sign_envelope(_PAYLOAD, _KEY, payload_type=PINNED_URI)
    d["payloadType"] = surrogate
    raw = json.dumps(d).encode("ascii")  # \uXXXX escapes, pure ASCII
    with pytest.raises(ValueError):
        verify_envelope(raw, _ALLOWLIST, payload_type=surrogate)
    # A surrogate in the ENVELOPE alone, under a sane parameter, is a verdict, not a raise.
    res = verify_envelope(raw, _ALLOWLIST)
    assert not res.ok and res.reason_code == DSSE_PAYLOADTYPE_MISMATCH
