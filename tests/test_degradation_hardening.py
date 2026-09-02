"""tests/test_degradation_hardening.py — the oracle's second red team.

A fresh-context pass at the instrument in `audit_bundle/_degradation.py` found
that it reported ok=True on real fail-opens, manufactured findings on
defect-free targets, and could answer differently depending on path order.
Each test below is one of those witnesses, written RED before the fix, and each
fix was mutant-killed (the one line it turns on removed, the test watched go
red again, the line restored). The c18 differential stays in
`test_degradation_monotonicity.py`; this file is the instrument probing itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle._degradation import (  # noqa: E402
    DegradationConfigError,
    Severity,
    format_report,
    probe_monotonicity,
)

PASS, ERR, REJ, CRASH = (
    Severity.PASS,
    Severity.ERROR_CLEAN,
    Severity.REJECT,
    Severity.ERROR_CRASH,
)


def _always_pass(root):
    return PASS, ()


# ---------------------------------------------------------------------------
# #3 — the verdict must not depend on path order
# ---------------------------------------------------------------------------

_MIXED_KEYS = [{1: "a"}, {"1": "a"}]


def _int_key_strict(root):
    """PASS on the untouched fixture; REJECT any dict carrying a non-str key;
    otherwise every dict must be exactly {"1": "a"}."""
    if root == _MIXED_KEYS:
        return PASS, ()
    if not isinstance(root, list):
        return REJ, ("ROOT",)
    for d in root:
        if not isinstance(d, dict):
            return REJ, ("BAD",)
        if any(not isinstance(k, str) for k in d):
            return REJ, ("NON_STR_KEY",)
        if d != {"1": "a"}:
            return REJ, ("BAD",)
    return PASS, ()


def test_a_non_str_dict_key_is_refused_not_canonicalised_away():
    """`json.dumps(sort_keys=True, default=repr)` turns {1:"a"} and {"1":"a"}
    into ONE string, so the verdict cache handed one root's verdict to the
    other and the answer depended on which was walked first. A non-str key is
    now as loud as a non-JSON value."""
    with pytest.raises(DegradationConfigError, match="key"):
        probe_monotonicity(_MIXED_KEYS, _int_key_strict)
    with pytest.raises(DegradationConfigError, match="key"):
        probe_monotonicity(_MIXED_KEYS, _int_key_strict, paths=[(1,)])


def test_a_projection_is_still_kind_checked():
    """`paths=` used to skip `_walk` entirely, so `_kind_ok` never ran on a
    projected fixture and an unmodelled node reached `run` via a parent rung."""

    class Opaque:
        pass

    def chk(root):
        return (PASS, ()) if root.get("a") == 1 else (REJ, ("X",))

    with pytest.raises(DegradationConfigError, match="Opaque"):
        probe_monotonicity({"a": 1, "b": Opaque()}, chk, paths=[("a",)])


def test_a_bare_string_path_is_rejected_not_iterated_charwise():
    with pytest.raises(DegradationConfigError, match="tuple"):
        probe_monotonicity({"a": {"b": 1}}, _always_pass, paths=["a"])


@pytest.mark.parametrize("bad", [("nope",), (0,), ("a", "b", "c")])
def test_a_path_that_does_not_resolve_is_a_config_error_not_a_keyerror(bad):
    with pytest.raises(DegradationConfigError, match="resolve"):
        probe_monotonicity({"a": {"b": 1}}, _always_pass, paths=[bad])


def test_canon_is_injective_over_accepted_kinds():
    """The cache key must spell distinct accepted roots distinctly."""
    from audit_bundle._degradation import _canon

    roots = [1, 1.0, True, "1", [1], {"1": 1}, {"1": "1"}, None, 0, False, ""]
    keys = [_canon(r) for r in roots]
    assert len(set(keys)) == len(roots), keys


# ---------------------------------------------------------------------------
# #4 — never raise (C9): every hostile fixture is a config error or a
# labelled leg, never a bare traceback; one bad leg costs one leg
# ---------------------------------------------------------------------------


def test_a_cyclic_fixture_is_a_config_error_not_a_recursion_error():
    cyc = {"a": 1}
    cyc["self"] = cyc
    with pytest.raises(DegradationConfigError, match="cyclic"):
        probe_monotonicity(cyc, _always_pass)


def test_a_tower_fixture_is_a_config_error_not_a_recursion_error():
    deep = 0
    for _ in range(2000):
        deep = [deep]
    with pytest.raises(DegradationConfigError, match="deeper"):
        probe_monotonicity(deep, _always_pass)


def test_a_key_whose_repr_raises_is_refused_without_being_repr_d():
    """`_walk` used `sorted(node, key=repr)`; a key with a raising __repr__
    escaped as its own exception. Closed by #3's str-key rule, which names the
    key's TYPE and never spells the key."""

    class NoRepr:
        def __repr__(self):
            raise RuntimeError("no repr for you")

        def __hash__(self):
            return 1

        def __eq__(self, other):
            return self is other

    with pytest.raises(DegradationConfigError, match="NoRepr key"):
        probe_monotonicity({NoRepr(): 1, "b": 2}, _always_pass)


def test_a_giant_int_is_a_config_error_not_a_valueerror():
    with pytest.raises(DegradationConfigError, match="digit"):
        probe_monotonicity({"a": 10**1000000}, _always_pass)


def test_a_raising_leg_is_quarantined_not_fatal():
    """One leg that raises used to abort the whole probe. Now it is recorded,
    labelled, blocks ok — and every other leg still yields its evidence,
    including the fail-open sitting on a different path."""

    def chk(root):
        if root == {"a": 1, "b": {"k": "ok"}}:
            return PASS, ()
        if not isinstance(root, dict):
            return REJ, ("ROOT",)
        if root.get("a") == "x":
            raise RuntimeError("boom")
        v = root.get("b")
        if not isinstance(v, dict):
            return PASS, ()  # the fail-open on the OTHER path
        return (PASS, ()) if v.get("k") == "ok" else (REJ, ("BAD",))

    rep = probe_monotonicity({"a": 1, "b": {"k": "ok"}}, chk)
    assert rep.quarantined == [
        (("a",), "wrong_type", "RuntimeError: boom")
    ], rep.quarantined
    assert rep.counts["quarantined"] == 1
    assert rep.ok is False
    assert any(
        f.path == ("b",) and f.rung == "wrong_type" and f.tier == 1
        for f in rep.findings
    ), "the other path's fail-open was lost with the raising leg"


def test_a_run_that_raises_on_the_untouched_fixture_is_still_a_config_error():
    def chk(root):
        raise RuntimeError("cannot even")

    with pytest.raises(DegradationConfigError, match="fixture"):
        probe_monotonicity({"a": 1}, chk)


def test_quarantine_alone_blocks_ok():
    """A control for the line above it.

    The FIRST quarantine test asserts `ok is False`, but that run also files a
    real finding, so the assertion held with the `not rep.quarantined` clause
    mutated away — a guard you can delete with the test still green is not a
    guard. Here the only thing wrong with the target is that one leg raised:
    no finding, no disclosure, not vacuous. Evidence NOT COLLECTED is not
    evidence of correctness, so `ok` must still be False.
    """
    fixture = {"a": "ok"}

    def chk(root):
        if root == {"a": 0}:
            raise RuntimeError("boom")
        return (PASS, ()) if root == fixture else (REJ, ("BAD",))

    rep = probe_monotonicity(fixture, chk)
    assert rep.findings == [], rep.findings
    assert rep.disclosures == [], rep.disclosures
    assert rep.vacuous is False
    assert rep.counts["quarantined"] == 1, rep.quarantined
    assert rep.ok is False


# ---------------------------------------------------------------------------
# #1 — the false negative: a softening between two LATER rungs
# ---------------------------------------------------------------------------


_LATER_FIXTURE = {"id": "ID-1", "amount": 100}


def _null_fail_open(root):
    """`amount` accepts an int, REJECTS a string, and wrongly accepts null.

    `wrong_type=REJECT -> null=PASS` is a textbook REJECT->PASS fail-open. The
    `id` field is strict at every rung, so the probe is not vacuous and the old
    MR-1 reported a clean bill of health with the fail-open sitting in it.
    """
    if not isinstance(root, dict):
        return REJ, ("ROOT",)
    if root.get("id") != "ID-1":
        return REJ, ("ID_BAD",)
    v = root.get("amount")
    if v is None:
        return PASS, ()  # <- the fail-open
    if not isinstance(v, int):
        return REJ, ("AMOUNT_TYPE",)
    return PASS, ()


def test_a_softening_between_two_LATER_rungs_is_caught():
    """MR-1 anchored only on `shape_preserving`, so when the base PASSed the
    whole ladder was DISCARDED AFTER BEING COMPUTED and no rung was ever
    compared to another rung. Measured before the fix: ok=True, tier1=0, with
    ('amount',) filed as V2-indifferent."""
    rep = probe_monotonicity(_LATER_FIXTURE, _null_fail_open)
    assert rep.vacuous is False, rep.counts
    hits = {(f.path, f.rung, f.base_rung) for f in rep.findings if f.tier == 1}
    assert (("amount",), "null", "wrong_type") in hits, rep.findings
    assert rep.ok is False


def test_a_pass_baseline_is_vacuous_only_when_EVERY_rung_passes():
    """The old V2 read a PASS `shape_preserving` as 'nothing to see at this
    path'. It means nothing of the kind: it means the least-degraded rung did
    not move, which says nothing about the seven below it."""
    rep = probe_monotonicity(_LATER_FIXTURE, _null_fail_open)
    assert ("amount",) not in rep.indifferent, rep.indifferent
    # ...while a path where nothing at all moves is still reported as vacuous.
    allpass = probe_monotonicity({"a": 1}, _always_pass)
    assert ("a",) in allpass.indifferent and allpass.vacuous is True


# ---------------------------------------------------------------------------
# #2 — the false positive that scales with the width of the document
# ---------------------------------------------------------------------------


def _parse_refusing(root):
    """A DEFECT-FREE target with no ordering defect anywhere.

    It is strict about every field it can read, and it answers "cannot parse
    this document" — a clean could-not-conclude — to a destroyed root. That is
    an answer every tool is entitled to give, and ERROR_CLEAN sits BELOW
    REJECT, so the `parent_scalar` rung of every top-level field manufactured a
    softening out of it.
    """
    if not isinstance(root, dict):
        return ERR, ("CANNOT_PARSE",)
    for k, v in root.items():
        if not isinstance(v, int):
            return REJ, (f"BAD:{k}",)
    return PASS, ()


@pytest.mark.parametrize("n", [1, 3, 6, 10])
def test_destroying_the_document_is_not_a_finding_against_one_of_its_fields(n):
    """Measured before the fix: one false finding per top-level key, so the
    false-positive rate scaled with the width of the input. A false-positive
    hunt is how the tool gets switched off."""
    rep = probe_monotonicity({f"k{i}": 1 for i in range(n)}, _parse_refusing)
    assert rep.findings == [], (
        f"{len(rep.findings)} finding(s) manufactured against a defect-free "
        f"target with {n} top-level key(s): "
        + "; ".join(f"{list(f.path)} {f.rung}: {f.detail}" for f in rep.findings)
    )


def test_the_parent_rungs_still_fire_one_level_down():
    """The control for the fix above: rung 6/7 is not deleted, it is scoped.

    `evidence: "x"` hiding a nested block is the c18 witness verbatim, and it
    must still be caught — the exclusion is only for a parent that IS the whole
    document.
    """
    fixture = {"evidence": {"blk": {"k": "ok"}}}

    def chk(root):
        if not isinstance(root, dict):
            return ERR, ("CANNOT_PARSE",)
        ev = root.get("evidence")
        if not isinstance(ev, dict):
            return PASS, ()  # <- the real fail-open, one level down
        blk = ev.get("blk")
        if not isinstance(blk, dict):
            return PASS, ()
        return (PASS, ()) if blk.get("k") == "ok" else (REJ, ("BAD",))

    rep = probe_monotonicity(fixture, chk)
    assert any(
        f.tier == 1 and f.rung == "parent_scalar" and f.path == ("evidence", "blk")
        for f in rep.findings
    ), rep.findings


def test_an_absent_rung_discloses_only_when_a_PRESENT_rung_bites():
    """A control for the `worst_sev != PASS` clause in MR-2.

    MR-2's claim is "every guard at this path is bypassable by deletion". If
    nothing less-degraded rejects, there is no guard yet and a passing `absent`
    rung discloses nothing. That clause survived its first mutant — dropping it
    filed a disclosure for every passing ABSENT rung, and since an undeclared
    disclosure blocks `ok`, that is a false positive with teeth.
    """
    fixture = {"outer": {"a": 1}}

    def chk(root):
        if not isinstance(root, dict):
            return ERR, ("CANNOT_PARSE",)
        o = root.get("outer")
        if o is None:
            return PASS, ()  # nothing guards `a`, and absent `outer` is fine
        if not isinstance(o, dict):
            return REJ, ("OUTER_BAD",)
        return PASS, ()  # ...and the checker is indifferent to a's value

    rep = probe_monotonicity(fixture, chk)
    hit = {(d.path, d.rung) for d in rep.disclosures}
    assert (("outer", "a"), "absent") not in hit, (
        "deleting `a` bypasses nothing — no less-degraded rung rejects it: "
        f"{sorted(hit)}"
    )
    # ...while deleting the PARENT does bypass a guard that `outer: "x"` trips,
    # so that one is a real disclosure and must stay.
    assert (("outer", "a"), "parent_absent") in hit, sorted(hit)


# ---------------------------------------------------------------------------
# #6 — a comparison counts only if BOTH rungs were spoken by the check
# ---------------------------------------------------------------------------


def _loader_upstream(root):
    """A pipeline whose type-strict LOADER refuses a wrong-typed `amount`
    before the check under test ever runs, and whose check has no ordering
    defect of its own.

    The third element is `spoke`: False means the verdict came from UPSTREAM of
    the check. Every verdict the check itself produced here is monotone; the
    only REJECT on the ladder is the loader's.
    """
    if not isinstance(root, dict):
        return REJ, ("PARSE_REFUSED",), False
    body = root.get("body")
    if not isinstance(body, dict):
        return ERR, ("BODY_UNREADABLE",), True  # the CHECK's could-not-conclude
    amt = body.get("amount")
    if amt is not None and not isinstance(amt, int):
        return REJ, ("SCHEMA_REFUSED",), False  # the LOADER, upstream of it
    return PASS, (), True


def test_a_comparison_against_an_UPSTREAM_verdict_is_not_a_finding():
    """V4 decided "the check spoke" from the BASE leg's flag plus one global
    `any()`, so a path counted as probed even when the rung it was compared
    AGAINST was decided upstream. Measured before the fix on this defect-free
    target: 2 TIER-1/2 findings and 1 disclosure at ('body', 'amount'), every
    one of them a comparison against the loader's SCHEMA_REFUSED — a verdict
    the check under test never produced."""
    rep = probe_monotonicity({"body": {"amount": 100}}, _loader_upstream)
    assert rep.findings == [], (
        "findings manufactured against verdicts the check never produced: "
        + "; ".join(f"{list(f.path)} {f.rung}: {f.detail}" for f in rep.findings)
    )
    assert rep.disclosures == [], rep.disclosures
    # ...and NOT by dropping the path: the check's own verdicts still probe it.
    assert rep.counts["paths_probed"] >= 1, rep.counts
    assert rep.ok is True, format_report(rep)


# ---------------------------------------------------------------------------
# #5 — a waiver must name the transition it excuses
# ---------------------------------------------------------------------------


_W_FIXTURE = {"blk": {"k": "ok"}}


def _softens_to_error(root):
    """`blk: "x"` draws a clean could-not-conclude where an INCOMPLETE blk
    rejects — a TIER-2 softening (REJECT -> ERROR_CLEAN)."""
    if not isinstance(root, dict):
        return REJ, ("ROOT",)
    v = root.get("blk")
    if v is None:
        return REJ, ("BLK_MISSING",)
    if not isinstance(v, dict):
        return ERR, ("BLK_UNREADABLE",)
    return (PASS, ()) if v.get("k") == "ok" else (REJ, ("BAD",))


def _softens_to_pass(root):
    """The SAME (path, rung), regressed: `blk: "x"` now sails through clean.
    REJECT -> PASS, a TIER-1 fail-open under every lattice."""
    if not isinstance(root, dict):
        return REJ, ("ROOT",)
    v = root.get("blk")
    if v is None:
        return REJ, ("BLK_MISSING",)
    if not isinstance(v, dict):
        return PASS, ()  # <- the regression
    return (PASS, ()) if v.get("k") == "ok" else (REJ, ("BAD",))


_TIER2_WAIVER = {
    (("blk",), "wrong_type", "MR-1", REJ, ERR): (
        "the loader cannot read a scalar blk and says so as a could-not-"
        "conclude; the consumer blocks on any non-zero exit"
    )
}


def test_a_waiver_clears_the_transition_it_names():
    rep = probe_monotonicity(
        _W_FIXTURE, _softens_to_error, paths=[("blk",)], declared=_TIER2_WAIVER
    )
    assert rep.findings == [], rep.findings
    assert rep.declared_limits, "the waiver matched nothing"
    assert rep.ok is True, format_report(rep)


def test_a_waiver_does_NOT_excuse_a_WORSE_regression_at_the_same_spot():
    """`declared` was keyed on (path, rung) alone and `_file` routed on that
    key with no regard for relation, tier, or the DIRECTION of the softening.
    So a waiver written for REJECT -> ERROR_CLEAN silently swallowed a later
    REJECT -> PASS at the same (path, rung): `ok` flipped green and the
    staleness check never fired, because the key still matched."""
    with pytest.raises(DegradationConfigError, match="stale"):
        probe_monotonicity(
            _W_FIXTURE, _softens_to_pass, paths=[("blk",)], declared=_TIER2_WAIVER
        )
    # ...and with the dead waiver removed, the regression is a TIER-1 finding.
    rep = probe_monotonicity(_W_FIXTURE, _softens_to_pass, paths=[("blk",)])
    assert [(f.tier, f.rung, f.rung_severity) for f in rep.findings] == [
        (1, "wrong_type", PASS)
    ], rep.findings
    assert rep.ok is False


@pytest.mark.parametrize(
    "bad",
    [
        (("blk",), "wrong_type"),  # the old, too-coarse 2-tuple
        (("blk",), "wrong_type", "MR-1", "REJECT", "ERROR_CLEAN"),  # stringy sevs
        (("blk",), "wrong_type", "MR-9", REJ, ERR),  # no such relation
        (("blk",), "no_such_rung", "MR-1", REJ, ERR),  # no such rung
        ("blk", "wrong_type", "MR-1", REJ, ERR),  # path not a tuple
    ],
)
def test_a_malformed_waiver_key_is_refused_by_SHAPE(bad):
    """Not a fail-open: a key that does not match simply never matches, so it
    would raise as stale anyway. But "stale" points the author at the TARGET's
    behaviour when the real problem is the key they typed, so the shape is
    checked and named. (These guards survived their first mutant for exactly
    this reason — nothing exercised them.)"""
    with pytest.raises(DegradationConfigError, match="transition is part of the key"):
        probe_monotonicity(
            _W_FIXTURE, _softens_to_error, paths=[("blk",)], declared={bad: "why"}
        )
