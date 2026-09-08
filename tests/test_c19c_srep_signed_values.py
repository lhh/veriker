"""Trusted time is graded from the SIGNED SREP, never from the unsigned envelope.

Each Roughtime response in `per_event_roughtime[*].srep_responses` carries the
signed inner SREP (`srep_bytes_b64`: CBOR {PUBK, MIDP, RADI, NONC} + Ed25519 sig)
AND an unsigned convenience copy (`midp_ms`, `radi_ms`). Measured 2026-09-02:
`_verify_srep` verified the signature over the inner bytes, then read ONLY `NONC`
from it — the RADI ceiling (`_verify_srep` step 3), the pairwise fork check
(`_check_pairwise_misbehavior`) and the convergence windows
(`extract_trusted_time_windows`) all read the UNSIGNED outer copy. The signed
MIDP / RADI were decoded and never read anywhere in the tree. So a holder of a
validly signed SREP could rewrite the asserted instant and radius in the envelope
and defeat ROUGHTIME_RADI_EXCEEDS_PROFILE_MAX, ROUGHTIME_FORK_DETECTED and
TRUSTED_TIME_INCONSISTENT — the three checks whose entire purpose is to bound
the asserted time. The fixture docstring said "extracts MIDP, RADI, NONC from
srep"; two of the three were false.

Now: every time-valued decision reads the signed inner; an outer copy that is
present and disagrees is ROUGHTIME_SREP_ENVELOPE_MISMATCH (a determinate finding
about the producer's bytes); an absent outer copy is fine (it was never
load-bearing).
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from audit_bundle.extensions.c19 import tsa_roughtime_bls as m  # noqa: E402
from tests.fixtures.c19c import mint_fixtures as fx  # noqa: E402

PROFILE = "production-standard"  # RADI ceiling 100 ms
CEILING = m.PROFILE_MAX_RADIUS_MS[PROFILE]
T0 = 1_700_000_000_000


@pytest.fixture
def pinned(monkeypatch):
    monkeypatch.setattr(
        m,
        "_TEST_OVERRIDE_ROUGHTIME_ROOTS",
        fx.make_test_pinned_roughtime_roots(),
        raising=False,
    )


def _nonce():
    preimage = b"S19c-preimage-event-0"
    return preimage, fx.expected_nonce_for("event", preimage)


def _layer_b(sreps):
    return {
        "per_event_roughtime": [
            {
                "event_id": "event-0",
                "event_hash_hex": hashlib.sha256(b"event-0").hexdigest(),
                "preimage_label": "event",
                "srep_responses": sreps,
            }
        ]
    }


def _quorum(midps, radis, nonce):
    names = ["cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se"]
    return [
        fx.mint_srep(root_name=n, midp_ms=mp, radi_ms=r, nonce=nonce)
        for n, mp, r in zip(names, midps, radis)
    ]


def _verify(layer_b, preimage):
    m.verify_per_event_roughtime_quorum(
        layer_b,
        assurance_profile=PROFILE,
        expected_preimage_by_event_id={"event-0": preimage},
    )


# ---------------------------------------------------------------------------
# the three attacks: rewrite the unsigned copy, keep the signature valid
# ---------------------------------------------------------------------------


def test_A1_signed_radi_over_ceiling_with_envelope_understated_is_refused(pinned):
    """Signed RADI = 5 s (over the 100 ms ceiling); envelope says 10 ms."""
    preimage, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 5_000], nonce)
    sreps[2]["radi_ms"] = 10  # the lie lives in the unsigned copy
    with pytest.raises(
        (m.ROUGHTIME_SREP_ENVELOPE_MISMATCH, m.ROUGHTIME_RADI_EXCEEDS_PROFILE_MAX)
    ):
        _verify(_layer_b(sreps), preimage)


def test_A2_signed_fork_with_envelope_agreeing_is_refused(pinned):
    """Signed MIDPs fork by an hour; the envelope copies are rewritten to agree."""
    preimage, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 3_600_000], [50, 50, 50], nonce)
    sreps[2]["midp_ms"] = T0 + 20
    with pytest.raises((m.ROUGHTIME_SREP_ENVELOPE_MISMATCH, m.ROUGHTIME_FORK_DETECTED)):
        _verify(_layer_b(sreps), preimage)


def test_A3_convergence_windows_come_from_the_signature(pinned):
    """`extract_trusted_time_windows` must report the SIGNED interval, not the
    envelope's — otherwise TRUSTED_TIME_INCONSISTENT grades a number nobody signed."""
    _, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    sreps[0]["midp_ms"] = T0 + 5_000_000
    sreps[0]["radi_ms"] = 1
    _, windows = m.extract_trusted_time_windows(
        _layer_b(sreps), assurance_profile=PROFILE
    )
    assert (T0 - 50, T0 + 50) in windows
    assert (T0 + 5_000_000 - 1, T0 + 5_000_000 + 1) not in windows


def test_A4_pairwise_check_reads_signed_values():
    """Unit: two SREPs whose envelopes overlap but whose signed MIDPs fork."""
    _, nonce = _nonce()
    a = fx.mint_srep(root_name="int08h-roughtime", midp_ms=T0, radi_ms=50, nonce=nonce)
    b = fx.mint_srep(
        root_name="roughtime-se", midp_ms=T0 + 3_600_000, radi_ms=50, nonce=nonce
    )
    b["midp_ms"] = T0 + 10
    with pytest.raises(m.ROUGHTIME_FORK_DETECTED):
        m._check_pairwise_misbehavior([a, b])


# ---------------------------------------------------------------------------
# the honest shapes still pass; the envelope is optional, not load-bearing
# ---------------------------------------------------------------------------


def test_H1_honest_quorum_passes(pinned):
    preimage, nonce = _nonce()
    _verify(_layer_b(_quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)), preimage)


def test_H2_envelope_copy_absent_still_passes(pinned):
    """The unsigned copy was only ever a convenience; the signed values suffice."""
    preimage, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    for s in sreps:
        del s["midp_ms"]
        del s["radi_ms"]
    _verify(_layer_b(sreps), preimage)


def test_H3_envelope_mismatch_has_its_own_code_even_when_values_are_benign(pinned):
    """A disagreeing envelope is a finding on its own: the producer made two
    statements about one instant. Values chosen so neither ceiling nor fork
    fires — only the mismatch can."""
    preimage, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    sreps[1]["radi_ms"] = 49
    with pytest.raises(m.ROUGHTIME_SREP_ENVELOPE_MISMATCH):
        _verify(_layer_b(sreps), preimage)


def test_H4_signed_values_must_be_integers(pinned):
    """A signed SREP whose MIDP/RADI are not ints cannot be graded — refused, not skipped."""
    import base64

    import cbor2

    preimage, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    # Re-mint one SREP with a string MIDP under the same test key.
    sk, pk = fx.make_roughtime_test_keypair("roughtime-se")
    inner = cbor2.dumps(
        {"PUBK": pk, "MIDP": "soon", "RADI": 50, "NONC": nonce}, canonical=True
    )
    sreps[2]["srep_bytes_b64"] = base64.b64encode(
        cbor2.dumps({"srep": inner, "sig": sk.sign(inner)}, canonical=True)
    ).decode("ascii")
    del sreps[2]["midp_ms"]
    del sreps[2]["radi_ms"]
    with pytest.raises(m.C19LayerBError):
        _verify(_layer_b(sreps), preimage)


def _remint(sreps, idx, inner_obj, root_name="roughtime-se"):
    import base64

    import cbor2

    sk, _pk = fx.make_roughtime_test_keypair(root_name)
    inner = cbor2.dumps(inner_obj, canonical=True)
    sreps[idx]["srep_bytes_b64"] = base64.b64encode(
        cbor2.dumps({"srep": inner, "sig": sk.sign(inner)}, canonical=True)
    ).decode("ascii")
    sreps[idx].pop("midp_ms", None)
    sreps[idx].pop("radi_ms", None)


def test_H5_inner_that_is_not_a_map_is_a_typed_refusal(pinned):
    """Red-team: a signed inner that is a list raised AttributeError out of the
    plugin (an unattributable crash). Now a typed ROUGHTIME_SREP_SIGNATURE_INVALID."""
    preimage, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    _remint(sreps, 2, ["not", "a", "map"])
    with pytest.raises(m.ROUGHTIME_SREP_SIGNATURE_INVALID):
        _verify(_layer_b(sreps), preimage)


def test_H6_bignum_midp_is_refused_not_compared(pinned):
    _, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    _, pk = fx.make_roughtime_test_keypair("roughtime-se")
    _remint(sreps, 2, {"PUBK": pk, "MIDP": 2**200, "RADI": 50, "NONC": nonce})
    with pytest.raises(m.ROUGHTIME_SREP_SIGNATURE_INVALID):
        m._signed_midp_radi(sreps[2])


def test_H7_convergence_windows_skip_only_undecodable_sreps(pinned):
    """`extract_trusted_time_windows` skips a SREP it cannot decode (its own
    per-structure check refuses first on the quorum path) — documented, and now
    pinned: the skip never turns into a window."""
    _, nonce = _nonce()
    sreps = _quorum([T0, T0 + 10, T0 + 20], [50, 50, 50], nonce)
    _remint(sreps, 2, ["not", "a", "map"])
    _, windows = m.extract_trusted_time_windows(
        _layer_b(sreps), assurance_profile=PROFILE
    )
    assert len(windows) == 2
