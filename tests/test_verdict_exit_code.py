"""The ONE verdict -> exit-code mapping (ADR BI-1 tri-state).

This mapping was re-implemented per entry point and the copies lost a state:
measured 2026-08-31, 104 of 107 examples/<pilot>/verify.py branched on
`result.ok` alone and returned 1 for everything non-OK, so a could-not-conclude
reached the operator as "the artifact is bad". These tests pin the three states
and the property that makes the collapse wrong.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from audit_bundle.verdict import (  # noqa: E402
    VERIFIER_INCOMPLETE,
    ErrorKind,
    Verdict,
    VerdictState,
    exit_code,
)


def test_the_three_states_map_to_the_three_codes() -> None:
    assert exit_code(Verdict.passed()) == 0
    assert exit_code(Verdict.reject("INPUT_MALFORMED_MANIFEST")) == 1
    assert exit_code(Verdict.incomplete(reason=VERIFIER_INCOMPLETE, detail="d")) == 2


def test_could_not_conclude_is_not_reported_as_a_bad_artifact() -> None:
    """The property the collapse destroys. REJECT is a statement about the
    ARTIFACT; ERROR is a statement about the VERIFIER. A verifier that reports
    its own incapacity as exit 1 is accusing the producer of something it never
    established."""
    incomplete = Verdict.incomplete(reason=VERIFIER_INCOMPLETE, detail="no anchor")
    assert incomplete.state is VerdictState.ERROR
    assert exit_code(incomplete) != exit_code(Verdict.reject("INPUT_MALFORMED_MANIFEST"))


def test_both_failure_states_stay_non_zero() -> None:
    """Callers keying on `exit != 0` must be unaffected by the split -- that is
    what makes this a safe change to make fleet-wide."""
    for verdict in (
        Verdict.reject("INPUT_MALFORMED_MANIFEST"),
        Verdict.incomplete(reason=VERIFIER_INCOMPLETE, detail="d"),
        Verdict.error(detail="boom"),
    ):
        assert exit_code(verdict) != 0


def test_a_crash_error_is_also_could_not_conclude() -> None:
    crash = Verdict.error(detail="unexpected")
    assert crash.error_kind is ErrorKind.CRASH
    assert exit_code(crash) == 2
