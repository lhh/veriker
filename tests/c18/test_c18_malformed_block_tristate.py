"""tests/c18/test_c18_malformed_block_tristate.py — a malformed verifier_identity
block must not be read as an absent one.

THREAT_MODEL row 20 (rederivation/THREAT_MODEL.md): **absent may pass;
present-but-unparseable must NEVER share a return value with absent.**

MEASURED on master a35ca9035 before this change: `_extract_verifier_identity_block`
returns `dict | None`, and

    absent                            -> None
    evidence.verifier_identity = "x"  -> None
    evidence.verifier_identity = 0    -> None
    evidence.verifier_identity = []   -> None

while both callers read None as "legacy pre-C18 bundle -> clean PASS". So a
producer skips every C18 structural check by making the field any non-dict.

Note the GRADIENT, which is the sharp part: a well-formed-but-INCOMPLETE block
draws 7 blocking reasons, while a MALFORMED one passes clean. Degrading the
input past the parser's recognition threshold is REWARDED. The fix must invert
that, and must NOT do it by reporting a malformed block as "every field
missing" — that is a false account of what was found and re-buries the same
distinction one level up (row 20).

Blame: REJECT-side, never could-not-conclude. The block is inside the bundle and
producer-authored; the verifier DID conclude — it concluded "not well-formed".
Precedent is CLAIMED_VALUE_MALFORMED / MalformedSpec, not the operator-omission
rows 10/17.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from audit_bundle.extensions import c18_verifier_identity as C18  # noqa: E402
from audit_bundle.plugins import verifier_identity_tripwire as TRIP  # noqa: E402
from veriker.cli.verify import _c18_locate_verifier_identity as CLI_LOCATE  # noqa: E402

FOUND, ABSENT, MALFORMED = "FOUND", "ABSENT", "MALFORMED"

_GOOD = {
    "verifier_oci_digest": "sha256:" + "a" * 64,
    "verifier_self_check_status": "passed",
}

# label -> (manifest, expected state)
_CASES = {
    # --- genuinely absent: must stay a clean pass (legacy bundles) ---
    "no evidence attribute at all": (SimpleNamespace(), ABSENT),
    "dict with no evidence key": ({"other": 1}, ABSENT),
    "dict evidence, no verifier_identity key": ({"evidence": {}}, ABSENT),
    "attr evidence, verifier_identity is None": (
        SimpleNamespace(evidence=SimpleNamespace(verifier_identity=None)),
        ABSENT,
    ),
    # --- well formed ---
    "dict style, dict block": ({"evidence": {"verifier_identity": _GOOD}}, FOUND),
    "attr style, dict block": (
        SimpleNamespace(evidence=SimpleNamespace(verifier_identity=_GOOD)),
        FOUND,
    ),
    "top-level fallback dict block": (
        SimpleNamespace(
            evidence=SimpleNamespace(verifier_identity=None), verifier_identity=_GOOD
        ),
        FOUND,
    ),
    # --- present but unparseable: the hole ---
    "dict style, block is a str": ({"evidence": {"verifier_identity": "x"}}, MALFORMED),
    "dict style, block is an int": ({"evidence": {"verifier_identity": 0}}, MALFORMED),
    "dict style, block is a list": ({"evidence": {"verifier_identity": []}}, MALFORMED),
    "dict style, block is a bool": (
        {"evidence": {"verifier_identity": False}},
        MALFORMED,
    ),
    "attr style, block is a str, no fallback": (
        SimpleNamespace(evidence=SimpleNamespace(verifier_identity="x")),
        MALFORMED,
    ),
    "top-level verifier_identity is a str": (
        SimpleNamespace(verifier_identity="x"),
        MALFORMED,
    ),
    # --- the same degradation ONE LEVEL UP: evidence itself unparseable ---
    "evidence is a str": ({"evidence": "x"}, MALFORMED),
    "evidence is a list": ({"evidence": []}, MALFORMED),
    # --- top-level key on a RAW DICT: not the declared field; ABSENT in all three
    # copies (the attribute-style fallback is for dataclasses only). Pinned so the
    # CLI copy cannot grow a dict fallback the extension lacks — a first draft did,
    # and this guard caught it. ---
    "dict top-level verifier_identity block": ({"verifier_identity": _GOOD}, ABSENT),
    "dict top-level verifier_identity is a string": (
        {"verifier_identity": "x"},
        ABSENT,
    ),
    "dict top-level verifier_identity is None": ({"verifier_identity": None}, ABSENT),
}


@pytest.mark.parametrize("label", sorted(_CASES))
def test_locator_is_tri_state(label):
    manifest, expected = _CASES[label]
    state, block = C18._locate_verifier_identity(manifest)
    assert state == expected, f"{label!r}: expected {expected}, got {state}"
    if state == FOUND:
        assert isinstance(block, dict)
    else:
        assert block is None


@pytest.mark.parametrize("label", sorted(_CASES))
def test_the_hand_maintained_copies_agree(label):
    """Drift guard, extended to the tri-state. The copies are duplicated rather
    than imported ('to avoid an extra import cycle'), and nothing else holds
    them in agreement — which is exactly how they drifted last time. THREE copies
    since 2026-09-02: the stdlib CLI's `_c18_locate_verifier_identity` joins for
    every dict-shaped manifest (it never sees a dataclass)."""
    manifest, _ = _CASES[label]
    assert C18._locate_verifier_identity(manifest) == TRIP._locate_verifier_identity(
        manifest
    ), f"extractor copies disagree on {label!r}"
    if isinstance(manifest, dict):
        assert CLI_LOCATE(manifest) == C18._locate_verifier_identity(manifest), (
            f"CLI copy disagrees with the extension on {label!r}"
        )


def _structural(manifest):
    return C18.verify_verifier_identity_structural(Path("/nonexistent"), manifest)


def _tripwire(manifest):
    return TRIP.VerifierIdentityTripwireCheck().check(Path("/nonexistent"), manifest)


def test_absent_still_clean_passes():
    """Anti-regression. If this breaks, every legacy pre-C18 bundle starts
    failing and the fix is worse than the hole."""
    assert _structural(SimpleNamespace()) == []
    assert _structural({"other": 1}) == []


def test_malformed_block_is_rejected_with_its_own_reason_code():
    reasons = _structural({"evidence": {"verifier_identity": "x"}})
    assert reasons, "a malformed block must not pass clean"
    assert any(r.startswith(C18.REASON_BLOCK_MALFORMED) for r in reasons), reasons


def test_malformed_is_not_reported_as_missing_fields():
    """Row 20: MALFORMED must not be folded into the missing-field vocabulary.
    Reporting an unparseable block as 'every required field is missing' is a
    false account of what was found, and re-buries the distinction one level up."""
    reasons = _structural({"evidence": {"verifier_identity": "x"}})
    # Both halves matter. Before the fix this test passed VACUOUSLY: a malformed
    # block produced NO reasons at all, so "none are field-missing" was trivially
    # true while the block sailed through. Assert it failed first.
    assert reasons, "vacuous — the malformed block produced no reasons at all"
    assert not any(r.startswith(C18.REASON_FIELD_MISSING) for r in reasons), reasons


def test_the_gradient_is_inverted():
    """The defect in one assertion: degrading the input further must not buy a
    SOFTER verdict. Before the fix, incomplete -> 7 blocking reasons and
    malformed -> clean pass."""
    incomplete = _structural({"evidence": {"verifier_identity": {}}})
    malformed = _structural({"evidence": {"verifier_identity": "x"}})
    assert incomplete, "an incomplete block must still fail (control)"
    assert malformed, (
        "a MALFORMED block must fail at least as hard as an incomplete one"
    )


def test_tripwire_plugin_refuses_a_malformed_block():
    res = _tripwire({"evidence": {"verifier_identity": "x"}})
    assert res.ok is False, res
    assert res.reason_code == C18.REASON_BLOCK_MALFORMED, res


def test_tripwire_plugin_still_passes_a_legacy_bundle():
    res = _tripwire(SimpleNamespace())
    assert res.ok is True, res
