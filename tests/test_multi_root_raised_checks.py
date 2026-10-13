"""multi_root.admit — a consumer callable that RAISES becomes a labelled row, never a
traceback and never a determinate finding (exception_escape/SPEC.md, layer 3).

The engine cannot tell a raise caused by a bad record from a raise caused by our own code, so
it does two things and nothing else: the row's reason names the callable and the exception
type, and `Admission.raised` carries the (record_id, callable, error) so the run can count
them. The split between "bad record" and "our bug" is made by the POPULATION tests in every
product (`raised` must be empty over every committed bundle), not here.

Five callables × four planted types = twenty cases, each the spec table's disposition; in
every case the OTHER record on the roster is ADMITTED with its content intact. Mutant
controls at the bottom name what each wrap is the only thing catching.
"""

from __future__ import annotations

import pytest

from audit_bundle import multi_root as M
from audit_bundle.multi_root import roster as MR
from audit_bundle.multi_root.roots import RootTable

R_A, R_B = "R-ERP", "R-BANK"
TABLE = RootTable.declare(
    {"erp": R_A, "bank": R_B}, proposer_root=R_A, roots=(R_A, R_B)
)
NONCE = "0" * 16

TYPES = (OverflowError, TypeError, KeyError, RecursionError)
TABLE_OF_DISPOSITIONS = {
    "validate_content": (MR.UNUSABLE, False),
    "signature_valid": (MR.UNUSABLE, False),
    "fetch": (MR.UNREACHED, False),
    "subject_from": (MR.UNREACHED, False),
    "is_stale": (MR.ADMITTED, True),
}


def _rec(kind: str, nonce: str) -> dict:
    return {"subject": {"kind": kind, "nonce": nonce}, "body": {"v": 1}}


def _boom(exc_type):
    def boom(*a, **k):
        raise exc_type("planted")

    return boom


def _roster(*, fetch_bad=None, subject_from_bad=None):
    rows = [
        M.Expected(
            "erp:good",
            "erp",
            ("P1",),
            {"kind": "good"},
            lambda c, n, rows: _rec("good", n),
        ),
        M.Expected(
            "bank:bad",
            "bank",
            ("P1",),
            {"kind": "bad"},
            fetch_bad or (lambda c, n, rows: _rec("bad", n)),
            subject_from=subject_from_bad,
        ),
    ]
    return M.Roster.declare(rows, TABLE, source="tests:raised")


def _admit(which: str, exc_type):
    """Plant `exc_type` in callable `which` for record `bank:bad` only."""
    boom = _boom(exc_type)
    only_bad = lambda fn: (
        lambda e_or_id, rec: fn(e_or_id, rec) if _is_bad(e_or_id) else None
    )  # noqa: E731
    sig = (
        (lambda e, r: True)
        if which != "signature_valid"
        else (lambda e, r: boom() if e.record_id == "bank:bad" else True)
    )
    content = None if which != "validate_content" else only_bad(lambda i, r: boom())
    stale = None if which != "is_stale" else only_bad(lambda e, r: boom())
    roster = _roster(
        fetch_bad=boom if which == "fetch" else None,
        subject_from_bad=boom if which == "subject_from" else None,
    )
    return M.admit(
        roster,
        object(),
        signature_valid=sig,
        validate_content=content,
        is_stale=stale,
        nonce=NONCE,
    )


def _is_bad(e_or_id) -> bool:
    return (e_or_id if isinstance(e_or_id, str) else e_or_id.record_id) == "bank:bad"


@pytest.mark.parametrize("which", sorted(TABLE_OF_DISPOSITIONS))
@pytest.mark.parametrize("exc_type", TYPES, ids=lambda t: t.__name__)
def test_a_raise_in_each_callable_is_the_tables_row_and_the_other_record_survives(
    which, exc_type
):
    adm = _admit(which, exc_type)
    rows = {r["record_id"]: r for r in adm.rows}
    bad, good = rows["bank:bad"], rows["erp:good"]
    disposition, stale = TABLE_OF_DISPOSITIONS[which]
    assert bad["disposition"] == disposition, (which, exc_type)
    assert bad["stale"] is stale
    # the reason SAYS it raised — which callable, which type — never a determinate sentence
    assert f"{which} raised: {exc_type.__name__}" in bad["reason"]
    for determinate in (
        "malformed content",
        "signature does not validate",
        "no response",
        "not attached",
        "record is about",
        "ok",
    ):
        assert bad["reason"] != determinate and not bad["reason"].startswith(
            determinate
        )
    assert bad["record"] is None or which == "is_stale"
    # the other record is untouched
    assert (
        good["disposition"] == MR.ADMITTED
        and good["stale"] is False
        and good["record"]["body"] == {"v": 1}
    )
    # the count the run carries
    assert len(adm.raised) == 1
    rid, name, err = adm.raised[0]
    assert (rid, name) == ("bank:bad", which)
    # exact: KeyError's str() quotes its argument, the other three do not
    assert err == ("KeyError: 'planted'" if exc_type is KeyError else f"{exc_type.__name__}: planted")
    # never dropped a row, receipt still seals the full denominator
    assert set(rows) == {"erp:good", "bank:bad"}


def test_is_stale_raise_keeps_the_stale_shape_and_admits_for_contradiction_only():
    adm = _admit("is_stale", TypeError)
    row = {r["record_id"]: r for r in adm.rows}["bank:bad"]
    assert (
        row["reason"]
        == "stale: is_stale raised: TypeError; admitted for contradiction only"
    )
    assert row["record"]["body"] == {"v": 1}
    ch = M.admission_channels(adm.rows, ["P1"])["P1"]
    assert (
        "bank:bad" in ch.present and "bank:bad" not in ch.verified
    )  # contradiction only: not confirming


def test_an_honest_admission_carries_no_raised_and_the_face_is_unchanged():
    roster = _roster()
    adm = M.admit(
        roster,
        object(),
        signature_valid=lambda e, r: True,
        validate_content=lambda i, r: None,
        is_stale=lambda e, r: None,
        nonce=NONCE,
    )
    assert adm.raised == ()
    assert [r["disposition"] for r in adm.rows] == [MR.ADMITTED, MR.ADMITTED]
    assert [r["reason"] for r in adm.rows] == ["ok", "ok"]
    assert M.admit_nothing(roster, "nothing").raised == ()


def test_a_refusal_is_not_a_raise():
    """`Refused(why)` and a bare False stay determinate refusals; `raised` stays empty."""
    roster = _roster()
    adm = M.admit(
        roster,
        object(),
        signature_valid=lambda e, r: MR.Refused("bad key") if _is_bad(e) else True,
        nonce=NONCE,
    )
    row = {r["record_id"]: r for r in adm.rows}["bank:bad"]
    assert (
        row["disposition"] == MR.UNUSABLE
        and row["reason"] == "provenance refused: bad key"
    )
    assert adm.raised == ()


def test_the_error_text_is_bounded_and_survives_a_hostile_message():
    class Hostile(Exception):
        def __str__(self):
            raise RuntimeError("no message for you")

    assert MR._error_text(Hostile()) == "Hostile: <unprintable message>"
    long = ValueError("x:" * 500)
    text = MR._error_text(long)
    assert (
        text.startswith("ValueError: x;x;")
        and ":" not in text[len("ValueError:") :]
        and text.endswith("…")
    )
    assert len(text) <= len("ValueError: ") + MR.REFUSAL_WHY_CAP + 1
    assert MR._error_text(KeyError()) == "KeyError"


def test_a_hostile_exception_type_name_is_bounded_on_the_row_and_the_count():
    """Red team 2026-09-22 (measured): a dynamically made class named `A:B\nC` reached the
    row reason and `raised` unbounded — a `:` past the face's delimiter, a newline in a
    reason. The type name is the consumer's, so it is bounded like the message."""
    Hostile = type("A:B\nC" + "x" * 400, (Exception,), {})
    roster = _roster(fetch_bad=_boom(Hostile))
    adm = M.admit(roster, object(), signature_valid=lambda e, r: True, nonce=NONCE)
    row = {r["record_id"]: r for r in adm.rows}["bank:bad"]
    assert row["reason"].startswith("fetch raised: A;B?C") and ":" not in row["reason"][len("fetch raised:") :]
    assert "\n" not in row["reason"] and len(row["reason"]) <= len("fetch raised: ") + MR.REFUSAL_WHY_CAP + 1
    (_, _, err), = adm.raised
    assert err.startswith("A;B?C") and "\n" not in err


@pytest.mark.parametrize(
    "which,ret,disposition,reason",
    [
        ("subject_from", 5, MR.UNREACHED, "subject_from returned int, not a mapping"),
        ("validate_content", 5, MR.UNUSABLE, "malformed content: validate_content returned int, not a str"),
        ("is_stale", 5, MR.ADMITTED, "stale: is_stale returned int, not a str; admitted for contradiction only"),
    ],
)
def test_a_consumers_wrong_typed_return_is_a_determinate_row_not_a_crash(which, ret, disposition, reason):
    """Red team 2026-09-22 (measured): `subject_from` returning 5 raised TypeError one line
    below the wrap, out of `admit`. A wrong RETURN is the consumer's contract violation, said
    so on the row; it is not a raise and is not on `raised`."""

    class Loud:  # a return whose str() raises — the f-string must never call it
        def __str__(self):
            raise RuntimeError("no str")

    for value in (ret, Loud()):
        roster = _roster(subject_from_bad=(lambda rows, v=value: v) if which == "subject_from" else None)
        adm = M.admit(
            roster,
            object(),
            signature_valid=lambda e, r: True,
            validate_content=(lambda i, r, v=value: v if _is_bad(i) else None) if which == "validate_content" else None,
            is_stale=(lambda e, r, v=value: v if _is_bad(e) else None) if which == "is_stale" else None,
            nonce=NONCE,
        )
        row = {r["record_id"]: r for r in adm.rows}["bank:bad"]
        assert row["disposition"] == disposition
        assert row["reason"] == reason.replace("int", type(value).__name__)
        assert adm.raised == ()


# --- D1 fix: the DECISION on a raise is NO_VERDICT (the v-kernel README verdict contract) ------


@pytest.mark.parametrize("which", sorted(TABLE_OF_DISPOSITIONS))
def test_overall_on_a_raised_admission_is_NO_VERDICT_and_the_face_is_a_crash_error(which):
    """README, "Verdict contract: tri-state + exit codes": a verifier-crashing input must not
    produce a REJECT indistinguishable from a real one. The rows keep their conservative
    dispositions (UNUSABLE / UNREACHED would REFUSE on their own); the decision does not."""
    from audit_bundle.verdict import VERIFIER_INTERNAL_ERROR, ErrorKind, VerdictState

    adm = _admit(which, TypeError)
    assert adm.raised
    ov = M.overall({}, adm, table=TABLE)
    assert ov["decision"] == M.NO_VERDICT, which
    v = M.to_verdict(ov)
    assert v.state == VerdictState.ERROR and v.error_kind == ErrorKind.CRASH, which
    assert v.reasons[0].code == VERIFIER_INTERNAL_ERROR, which


def test_NO_VERDICT_dominates_contradicted_inadmissible_and_policy():
    """A crash short-circuits the meet `crash-ERROR > REJECT > clean-ERROR > OK`: nothing a
    raised admission ALSO carries can turn it back into a REFUSE or a HOLD."""
    adm = _admit("validate_content", OverflowError)
    states = {"p": {"state": M.CONTRADICTED, "qualifier": None}}
    ov = M.overall(states, adm, table=TABLE, inadmissible="also inadmissible", hold_if=lambda s: True)
    assert ov["decision"] == M.NO_VERDICT
    # the other facts stay on the dict for the reader; only the decision is dominated
    assert ov["contradicted"] == ["p"] and ov["inadmissible_input"] == "also inadmissible"


def test_raised_travels_with_the_admission_and_by_keyword_for_loose_rows():
    adm = _admit("signature_valid", KeyError)  # an UNUSABLE row: REFUSE on its own
    assert M.overall({}, adm, table=TABLE)["decision"] == M.NO_VERDICT
    # loose rows lose the Admission's flag (the red-team witness `overall` names) unless passed
    assert M.overall({}, adm.rows, table=TABLE)["decision"] == M.REFUSE
    assert M.overall({}, adm.rows, table=TABLE, raised=adm.raised)["decision"] == M.NO_VERDICT


def test_an_honest_admission_decides_exactly_as_before():
    adm = M.admit(
        _roster(),
        object(),
        signature_valid=lambda e, r: True,
        validate_content=lambda i, r: None,
        is_stale=lambda e, r: None,
        nonce=NONCE,
    )
    assert M.overall({}, adm, table=TABLE)["decision"] == M.RELEASE
    assert M.overall({}, adm, table=TABLE, raised=())["decision"] == M.RELEASE


def test_NO_VERDICT_is_the_top_of_the_severity_order_improves_reads():
    from audit_bundle._degradation import Severity
    from audit_bundle.multi_root.propositions import DECISION_SEVERITY

    assert DECISION_SEVERITY[M.NO_VERDICT] == Severity.ERROR_CRASH == max(DECISION_SEVERITY.values())
    crashed = {"overall": {"decision": M.NO_VERDICT}, "states": {}}
    refused = {"overall": {"decision": M.REFUSE}, "states": {}}
    # a degradation that turns a REFUSE into a crash is not an improvement; the reverse moves up
    assert M.improves(crashed, refused, propositions=())["decision_moved_up"] is False
    assert M.improves(refused, crashed, propositions=())["decision_moved_up"] is True


def test_operator_interrupts_are_not_rows():
    roster = _roster(fetch_bad=_boom(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        M.admit(roster, object(), signature_valid=lambda e, r: True, nonce=NONCE)


def test_raised_is_frozen_with_the_admission():
    adm = _admit("fetch", KeyError)
    assert isinstance(adm.raised, tuple)
    with pytest.raises((AttributeError, TypeError)):
        adm.raised = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# mutant controls: each wrap is the ONLY thing between that callable and a traceback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("which", sorted(TABLE_OF_DISPOSITIONS))
def test_control_without_the_wrap_the_callable_raises_out_of_admit(which, monkeypatch):
    """In-suite sentinel, not the control: it shows every wrap routes through `_error_text`
    (neutered to re-raise, the planted exception escapes `admit`). The controls that remove
    each `except` clause are K6–K10 in exception_escape/controls_mutants.py."""
    import audit_bundle.multi_root.roster as R

    src_admit = R.admit

    def reraise(*a, **k):  # what admit does with the exception when nothing records it
        raise a[0]

    # `_raised` is a closure inside admit; the chokepoint reachable from outside is `_error_text`
    monkeypatch.setattr(R, "_error_text", reraise)
    with pytest.raises(OverflowError):
        _admit(which, OverflowError)
    assert R.admit is src_admit
