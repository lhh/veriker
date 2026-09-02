"""tests/test_primitive_ref_mutants.py — D1 negative controls.

probe_check discipline: mutate every part of an AUTHORITATIVE reference and
require each mutant to be refused FOR ITS EXPECTED REASON. Incidental rejection
is not binding sensitivity -- a battery that scores 13/13 because everything
happens to raise `MalformedPrimitiveRef` proves nothing about the digest check.

These never skip (no optional dependency), unlike the hypothesis properties.

The two mutants that must NOT be rejected are as load-bearing as the rest:
stripping the version or the digest is a WEAKENING, and a weakening that
produces an identical face is invisible. Those assert the face MOVES.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.rederivation import registry  # noqa: E402
from audit_bundle.rederivation.primitive_ref import (  # noqa: E402
    MalformedPrimitiveRef,
    PrimitiveRefViolation,
    parse_primitive_ref,
    resolve_primitive_ref,
)

NAME = "d1_probe_primitive"
VERSION = "2"


class _Authoritative:
    primitive_id = NAME
    primitive_version = VERSION

    def recompute(self, inputs, pack_section):  # pragma: no cover
        return None


@pytest.fixture(autouse=True)
def _registered():
    registry._ensure_primitives_loaded()
    saved = dict(registry._PRIMITIVE_REGISTRY)
    registry._PRIMITIVE_REGISTRY[NAME] = _Authoritative()
    yield
    registry._PRIMITIVE_REGISTRY.clear()
    registry._PRIMITIVE_REGISTRY.update(saved)


def _real_sha() -> str:
    sha = registry.derive_provenance(registry._PRIMITIVE_REGISTRY[NAME])["sha256"]
    assert sha, "authoritative fixture must have a derivable source digest"
    return sha


def _outcome(raw: str) -> tuple[str, object]:
    """The full verdict for one ref: ("parse_error"|"violation"|"unknown"|"ok",
    payload). 'Caught' is a change in THIS map, never a keyword match."""
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef as exc:
        return ("parse_error", type(exc).__name__)
    try:
        _, rec = resolve_primitive_ref(ref)
    except registry.UnknownPrimitive:
        return ("unknown", None)
    except PrimitiveRefViolation as exc:
        return ("violation", exc.reason_code)
    return ("ok", (rec["version_status"], rec["digest_status"]))


def test_the_authoritative_ref_is_accepted():
    """Anti-tautology baseline. If the authoritative ref does not pass CLEANLY,
    every mutant below is rejected for the wrong reason and the battery is
    meaningless."""
    raw = f"{NAME}@{VERSION}#{_real_sha()}"
    assert _outcome(raw) == ("ok", ("matched", "matched"))


# ---------------------------------------------------------------------------
# Mutants that MUST be refused, each for its own reason
# ---------------------------------------------------------------------------


def _mutants():
    sha = _real_sha()
    flipped = ("b" if sha[0] != "b" else "c") + sha[1:]
    return [
        # (label, ref, expected outcome)
        ("digest flipped one char", f"{NAME}@{VERSION}#{flipped}",
         ("violation", "PRIMITIVE_DIGEST_MISMATCH")),
        ("digest truncated", f"{NAME}@{VERSION}#{sha[:-1]}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("digest extended", f"{NAME}@{VERSION}#{sha}a",
         ("parse_error", "MalformedPrimitiveRef")),
        ("digest emptied", f"{NAME}@{VERSION}#",
         ("parse_error", "MalformedPrimitiveRef")),
        ("digest non-hex", f"{NAME}@{VERSION}#{'z' * 64}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("version changed", f"{NAME}@9#{sha}",
         ("violation", "PRIMITIVE_VERSION_MISMATCH")),
        ("version emptied", f"{NAME}@#{sha}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("version duplicated", f"{NAME}@{VERSION}@{VERSION}#{sha}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("sigils reordered", f"{NAME}#{sha}@{VERSION}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("name renamed", f"{NAME}_x@{VERSION}#{sha}",
         ("unknown", None)),
        ("name emptied", f"@{VERSION}#{sha}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("whitespace inserted", f"{NAME} @{VERSION}#{sha}",
         ("parse_error", "MalformedPrimitiveRef")),
        ("control char inserted", f"{NAME}\t@{VERSION}#{sha}",
         ("parse_error", "MalformedPrimitiveRef")),
    ]


def test_every_mutant_is_refused_for_its_expected_reason():
    sha = _real_sha()
    clean = _outcome(f"{NAME}@{VERSION}#{sha}")
    misses = []
    for label, raw, expected in _mutants():
        got = _outcome(raw)
        if got != expected:
            misses.append(f"{label}: expected {expected}, got {got}")
        if got == clean:
            misses.append(f"{label}: verdict map UNCHANGED from clean baseline")
    assert not misses, "\n".join(misses)


def test_the_battery_exercises_more_than_one_refusal_reason():
    """A battery whose 13 mutants all trip the SAME branch measures one branch
    13 times. Require every reason class to be represented."""
    reasons = {_outcome(raw) for _, raw, _ in _mutants()}
    kinds = {r[0] for r in reasons}
    assert kinds == {"parse_error", "violation", "unknown"}, kinds
    violation_codes = {r[1] for r in reasons if r[0] == "violation"}
    assert violation_codes == {
        "PRIMITIVE_DIGEST_MISMATCH",
        "PRIMITIVE_VERSION_MISMATCH",
    }, violation_codes


# ---------------------------------------------------------------------------
# Weakening mutants — accepted, but the face MUST move
# ---------------------------------------------------------------------------


def test_stripping_the_digest_is_visible_on_the_face():
    """A producer (or a careless edit) that removes the pin gets a WEAKER check.
    That is allowed -- pinning is optional by decision (ADR R2) -- but it must
    never produce a face identical to the pinned one, or the weakening is
    undetectable by the reader."""
    sha = _real_sha()
    pinned = _outcome(f"{NAME}@{VERSION}#{sha}")
    stripped = _outcome(f"{NAME}@{VERSION}")
    assert stripped == ("ok", ("matched", "unpinned"))
    assert stripped != pinned


def test_stripping_the_version_is_visible_on_the_face():
    sha = _real_sha()
    full = _outcome(f"{NAME}@{VERSION}#{sha}")
    stripped = _outcome(f"{NAME}#{sha}")
    assert stripped == ("ok", ("unversioned", "matched"))
    assert stripped != full


def test_stripping_both_degrades_to_todays_guarantee_and_says_so():
    bare = _outcome(NAME)
    assert bare == ("ok", ("unversioned", "unpinned"))


def test_uppercase_digest_is_accepted_and_normalized_not_silently_mismatched():
    """An expected NON-rejection. Accepting only lowercase would turn an
    auditor's uppercase sha into a DIGEST_MISMATCH -- a refusal for the wrong
    reason, which reads as a tampered bundle."""
    sha = _real_sha()
    assert _outcome(f"{NAME}@{VERSION}#{sha.upper()}") == ("ok", ("matched", "matched"))


# ---------------------------------------------------------------------------
# The undeclared/unavailable legs — fail-closed, not fail-open
# ---------------------------------------------------------------------------


def test_pinning_a_version_on_a_primitive_that_declares_none_refuses():
    obj = _Authoritative()
    obj.primitive_version = None
    registry._PRIMITIVE_REGISTRY[NAME] = obj
    assert _outcome(f"{NAME}@{VERSION}") == (
        "violation",
        "PRIMITIVE_VERSION_UNDECLARED",
    )


def test_pinning_a_digest_on_an_unhashable_primitive_refuses():
    obj = _Authoritative()
    obj.recompute = "not callable"
    registry._PRIMITIVE_REGISTRY[NAME] = obj
    assert _outcome(f"{NAME}#{'a' * 64}") == (
        "violation",
        "PRIMITIVE_DIGEST_UNAVAILABLE",
    )
