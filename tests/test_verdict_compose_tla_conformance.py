"""Conformance harness: the REAL verdict.compose vs the TLA+ VerdictLattice model.

formal/tla/VerdictLattice.tla proves the abstract order CRASH > REJECT > INCOMPLETE
> OK is a join-semilattice and obeys the no-laundering safety laws — but it models a
leg as a bare 4-element rank. It deliberately drops three code paths that the real
compose() has and where a laundering bug would actually hide:

  1. Verdict.__post_init__ CRASH-DEFAULTING (verdict.py:148-157): an ERROR built with
     NO error_kind silently becomes CRASH. If that defaulting broke, compose() would
     fall through is_crash / REJECT / is_incomplete and land an unclassified ERROR in
     the OK branch — a verifier crash laundered to GREEN. The TLA+ model cannot see
     this; this harness drives it directly (the CRASH_DEFAULTED leg kind).
  2. Reason ORDERING (verdict.py:353-359): the dominant class's reasons must come
     FIRST (the property the o5 single-fault tests rely on).
  3. Advisory-leg isolation over a real gating mask.

This harness checks the SAME laws as the TLA+ spec on the real compose(), scored
against an INDEPENDENT oracle built from each leg's construction label (NOT from the
verdict's own is_crash/state read-back), so a classification/defaulting divergence is
caught rather than absorbed.
"""

from __future__ import annotations

import pytest
# `hypothesis` ships in the `dev` extra, not at runtime. A bare top-level import
# does not skip this module when it is absent -- it INTERRUPTS collection for
# the whole suite, so a run provisioned without the extra reports exit 2 having
# run nothing rather than skipping the slice that needs it.
pytest.importorskip("hypothesis")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st

from audit_bundle.verdict import (
    ErrorKind,
    Verdict,
    VerdictReason,
    VerdictState,
    VerifierError,
    compose,
)

# Composition rank (verdict.py:316-329). Higher = more dominant.
RANK = {"OK": 1, "INCOMPLETE": 2, "REJECT": 3, "CRASH": 4, "CRASH_DEFAULTED": 4}
# Reason-code prefix each class emits, for the ordering check.
PREFIX = {
    "REJECT": "INPUT_",
    "CRASH": "VERIFIER_",
    "INCOMPLETE": "VERIFIER_",
    "CRASH_DEFAULTED": "VERIFIER_",
}


def _make_leg(cls: str, idx: int) -> Verdict:
    if cls == "OK":
        return Verdict.passed()
    if cls == "REJECT":
        return Verdict.reject(f"INPUT_R{idx}", check_name=f"leg{idx}")
    if cls == "CRASH":
        return Verdict.error(f"VERIFIER_C{idx}", check_name=f"leg{idx}")
    if cls == "INCOMPLETE":
        return Verdict.incomplete(f"VERIFIER_I{idx}", check_name=f"leg{idx}")
    if cls == "CRASH_DEFAULTED":
        # ERROR with NO error_kind -> __post_init__ must default it to CRASH.
        return Verdict(
            VerdictState.ERROR, (VerdictReason(f"VERIFIER_D{idx}", f"leg{idx}"),)
        )
    raise AssertionError(cls)


def _real_rank(v: Verdict) -> int:
    """The composite's rank, read from the REAL verdict (the value under test)."""
    if v.is_crash:
        return 4
    if v.state is VerdictState.REJECT:
        return 3
    if v.is_incomplete:
        return 2
    if v.state is VerdictState.OK:
        return 1
    return -1  # ERROR with no kind == a laundering hole (must never happen)


def _cls(v: Verdict) -> tuple:
    return (v.state, v.error_kind)


LEG = st.tuples(st.sampled_from(list(RANK)), st.booleans())  # (class, is_gating)


@settings(max_examples=600, deadline=None)
@given(st.lists(LEG, min_size=0, max_size=6))
def test_compose_conformance(spec: list[tuple[str, bool]]) -> None:
    legs = [_make_leg(c, i) for i, (c, _) in enumerate(spec)]
    mask = [g for (_, g) in spec]
    composite = compose(legs, gating=mask)

    gating_cls = [c for (c, g) in spec if g]
    gating_verdicts = [legs[i] for i, (_, g) in enumerate(spec) if g]
    exp_rank = max((RANK[c] for c in gating_cls), default=1)

    # --- class oracle: this single assertion encodes no-laundering (a crash can
    # only map to rank 4 via is_crash), reject-not-downgraded (rank 3 -> REJECT),
    # and OK-closure (rank 1 iff every gating leg is OK). Independent of read-back.
    assert _real_rank(composite) == exp_rank, (spec, _cls(composite))

    # --- error_kind coherence (verdict.py:148-157): kind set iff ERROR.
    if composite.state is VerdictState.ERROR:
        assert composite.error_kind in (ErrorKind.CRASH, ErrorKind.INCOMPLETE)
    else:
        assert composite.error_kind is None

    # --- reason ORDERING: dominant class's reasons come first.
    if exp_rank > 1 and composite.reasons:
        dom_cls = max(gating_cls, key=lambda c: RANK[c])
        assert composite.reasons[0].code.startswith(PREFIX[dom_cls]), composite.reasons

    # --- advisory isolation: advisory legs never move the composite class.
    gating_only = compose(gating_verdicts)
    assert _cls(gating_only) == _cls(composite)

    # --- nesting soundness (associativity on the real legs tree): a left fold of
    # the gating legs composes to the same class as the flat compose.
    if len(gating_verdicts) >= 2:
        folded = gating_verdicts[0]
        for v in gating_verdicts[1:]:
            folded = compose([folded, v])
        assert _cls(folded) == _cls(gating_only)


def test_unclassified_error_leg_never_launders_to_ok() -> None:
    """The audit-flagged path the TLA+ model dropped: an ERROR leg with no error_kind
    must compose to a CRASH-ERROR, never to OK."""
    leg = Verdict(VerdictState.ERROR, (VerdictReason("VERIFIER_X"),))
    assert leg.is_crash  # __post_init__ defaulted it
    out = compose([Verdict.passed(), leg])
    assert out.state is VerdictState.ERROR and out.is_crash


def test_crash_dominates_reject_no_laundering() -> None:
    """A verifier crash beside a real reject must surface as crash-ERROR, never as a
    reject indistinguishable from a real one (verdict.py:20-23)."""
    out = compose([Verdict.reject("INPUT_MALFORMED_JSON"), Verdict.error("VERIFIER_C")])
    assert out.state is VerdictState.ERROR and out.is_crash
    assert out.state is not VerdictState.REJECT


def test_advisory_crash_does_not_poison_state() -> None:
    """An ADVISORY crash leg is recorded but must not move the composite state."""
    out = compose([Verdict.passed(), Verdict.error("VERIFIER_C")], gating=[True, False])
    assert out.state is VerdictState.OK
    assert len(out.legs) == 2  # advisory leg still preserved


def test_gating_mask_length_mismatch_raises() -> None:
    with pytest.raises(VerifierError):
        compose([Verdict.passed()], gating=[True, False])
