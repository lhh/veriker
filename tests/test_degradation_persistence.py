"""tests/test_degradation_persistence.py — MR-4 finding persistence, and its controls.

P5 of the internal design notes, verbatim: a synthetic checker that
erases its conviction when a sibling is null -> TIER-1; one that persists ->
clean; one that refuses with a different code -> `masked`; one that raises ->
`crashes`, never a finding; ancestor rungs skipped; and with the comparison
deleted from the oracle (mutant), the positive control reads clean.

THE MUTANTS ARE THE POINT. Every positive control here is paired with a
source-level mutant of the ORACLE that must turn that control green; a green
control against an oracle nobody has shown failing is not evidence.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import audit_bundle._degradation as D  # noqa: E402
from audit_bundle._degradation import (  # noqa: E402
    DegradationConfigError,
    Severity,
    probe_persistence,
)

FIX = {"amount": 100, "note": "n", "meta": {"k": 1, "j": 2}}
TAMPER = (("amount",), 99)  # the conviction: amount != 100


def _convict(root):
    if not isinstance(root, dict):
        return Severity.ERROR_CLEAN, ("NOT_A_DOC",), True
    if root.get("amount") != 100:
        return Severity.REJECT, ("AMOUNT_MISMATCH",), True
    return Severity.PASS, (), True


# --- controls ----------------------------------------------------------------


def _erasing(root):
    """The fail-open under test: a guard on an UNRELATED field skips the check."""
    if isinstance(root, dict) and root.get("note") is None:
        return Severity.PASS, (), True  # "legacy bundle, nothing to check"
    return _convict(root)


def test_positive_control_erased_is_tier1():
    rep = probe_persistence(FIX, _erasing, tamper=TAMPER)
    hits = [(f.path, f.rung, f.tier) for f in rep.findings]
    assert (("note",), "null", 1) in hits, rep.findings
    assert (("note",), "absent", 1) in hits, "deleting the sibling must not erase either"
    assert rep.ok is False and rep.counts["erased"] >= 2
    assert rep.baseline == Severity.REJECT


def test_negative_control_persisting_checker_is_clean():
    rep = probe_persistence(FIX, _convict, tamper=TAMPER)
    assert rep.ok is True, [f.detail for f in rep.findings]
    assert rep.counts["persisted"] == rep.counts["legs"] > 0
    assert rep.counts["findings_tier1"] == rep.counts["findings_tier2"] == 0


def _masking(root):
    """A sibling guard fires FIRST and returns without judging the tamper."""
    if isinstance(root, dict) and not isinstance(root.get("meta"), dict):
        return Severity.REJECT, ("META_BAD",), True
    return _convict(root)


def test_masked_is_tier2_with_the_lost_reason_named():
    rep = probe_persistence(FIX, _masking, tamper=TAMPER)
    masked = [f for f in rep.findings if "masked" in f.detail]
    assert masked and all(f.tier == 2 for f in masked)
    assert any(f.path == ("meta",) and f.rung == "wrong_type" for f in masked)
    assert all("AMOUNT_MISMATCH" in f.detail for f in masked)
    assert rep.counts["masked"] == len(masked)
    # the ERASED count stays zero: this checker never PASSes a convicted doc
    assert rep.counts["erased"] == 0


def test_masked_by_an_upstream_refusal_is_filed_and_counted_apart():
    def upstream_masking(root):
        if isinstance(root, dict) and not isinstance(root.get("meta"), dict):
            return Severity.REJECT, ("MALFORMED",), False  # the loader spoke, not the check
        return _convict(root)

    rep = probe_persistence(FIX, upstream_masking, tamper=TAMPER)
    assert rep.counts["masked"] == rep.counts["masked_upstream"] > 0
    assert rep.counts["masked_spoken"] == 0
    assert all("[upstream" in f.detail for f in rep.findings if "masked" in f.detail)
    assert rep.ok is False  # filed, not excused


def _demoting(root):
    if isinstance(root, dict) and not isinstance(root.get("note"), str):
        return Severity.ERROR_CLEAN, ("NOTE_UNREADABLE",), True
    return _convict(root)


def test_demoted_is_tier2():
    rep = probe_persistence(FIX, _demoting, tamper=TAMPER)
    dem = [f for f in rep.findings if "demoted" in f.detail]
    assert dem and all(f.tier == 2 and f.rung_severity == Severity.ERROR_CLEAN for f in dem)
    assert rep.counts["demoted"] == len(dem) >= 3  # empty/wrong_type/null on note


def _crashing(root):
    if isinstance(root, dict) and root.get("note") is None:
        return Severity.ERROR_CRASH, ("Traceback",), True
    return _convict(root)


def test_crash_is_reported_never_a_finding():
    rep = probe_persistence(FIX, _crashing, tamper=TAMPER)
    assert rep.crashes and not rep.findings
    assert rep.ok is True  # noise, not a persistence failure; stated in the docstring


def _raising(root):
    if isinstance(root, dict) and root.get("note") is None:
        raise RuntimeError("boom")
    return _convict(root)


def test_raise_is_quarantined_and_blocks_ok():
    rep = probe_persistence(FIX, _raising, tamper=TAMPER)
    assert rep.quarantined and not rep.findings
    assert rep.ok is False


def test_ancestor_sites_are_skipped_and_counted():
    fix = {"meta": {"k": 1, "j": 2}, "x": 1}

    def chk(root):
        if not isinstance(root, dict) or not isinstance(root.get("meta"), dict):
            return Severity.ERROR_CLEAN, ("META_UNREADABLE",), True
        if root["meta"].get("k") != 1:
            return Severity.REJECT, ("K_MISMATCH",), True
        return Severity.PASS, (), True

    rep = probe_persistence(fix, chk, tamper=(("meta", "k"), 5))
    probed_paths = {leg.path for leg in rep.legs}
    assert ("meta",) not in probed_paths and ("meta", "k") not in probed_paths
    assert ("meta", "j") in probed_paths and ("x",) in probed_paths
    # ("meta","j")'s parent rungs would hit ("meta",), an ancestor of the tamper
    assert rep.counts["rungs_skipped_ancestor"] == 2
    assert not any(leg.rung in ("parent_scalar", "parent_absent") and leg.path == ("meta", "j") for leg in rep.legs)
    assert rep.ok is True, [f.detail for f in rep.findings]


# --- gates ---------------------------------------------------------------------


def test_v1a_rejected_baseline_is_a_config_error():
    with pytest.raises(DegradationConfigError, match="V1a"):
        probe_persistence({"amount": 99, "note": "n"}, _convict, tamper=(("amount",), 98))


def test_v1b_accepted_tamper_is_a_config_error():
    with pytest.raises(DegradationConfigError, match="not a conviction"):
        probe_persistence(FIX, _convict, tamper=(("note",), "other"))


def test_v1b_could_not_conclude_tamper_is_a_config_error():
    def chk(root):
        if isinstance(root, dict) and root.get("amount") != 100:
            return Severity.ERROR_CLEAN, ("AMOUNT_UNREADABLE",), True
        return Severity.PASS, (), True

    with pytest.raises(DegradationConfigError, match="not REJECT"):
        probe_persistence(FIX, chk, tamper=TAMPER)


def test_v1b_upstream_conviction_is_a_config_error():
    def chk(root):
        sev, r, _ = _convict(root)
        return sev, r, False

    with pytest.raises(DegradationConfigError, match="UPSTREAM"):
        probe_persistence(FIX, chk, tamper=TAMPER)


def test_noop_tamper_is_a_config_error():
    with pytest.raises(DegradationConfigError, match="no-op"):
        probe_persistence(FIX, _convict, tamper=(("amount",), 100))


def _reasonless(root):
    sev, _r, s = _convict(root)
    return sev, (), s


def test_reasonless_conviction_needs_the_declaration():
    with pytest.raises(DegradationConfigError, match="severity_only=True"):
        probe_persistence(FIX, _reasonless, tamper=TAMPER)
    rep = probe_persistence(FIX, _reasonless, tamper=TAMPER, severity_only=True)
    assert rep.counts["reason_mode"] == "severity_only" and rep.ok is True


def test_severity_only_cannot_see_masking_declared_limit():
    """The stated limit: on an exit-code surface a REJECT for the WRONG reason
    counts as persisted. This test pins that it is a limit, not a bug."""

    def masking_reasonless(root):
        sev, _r, s = _masking(root)
        return sev, (), s

    rep = probe_persistence(FIX, masking_reasonless, tamper=TAMPER, severity_only=True)
    assert rep.counts["masked"] == 0 and rep.ok is True


def test_reason_key_normalises_details():
    def chk(root):
        sev, r, s = _convict(root)
        tag = hashlib.sha256(D._canon(root).encode()).hexdigest()[:8]
        return sev, tuple(f"{c}:{tag}" for c in r), s  # rung-dependent detail

    # identity key: every rung's detail differs from the tamper's -> all masked (the
    # documented false-masked mode)
    rep = probe_persistence(FIX, chk, tamper=TAMPER)
    assert rep.counts["masked"] == rep.counts["legs"] > 0
    # code-only key: persisted
    rep2 = probe_persistence(FIX, chk, tamper=TAMPER, reason_key=lambda r: r.split(":")[0])
    assert rep2.ok is True and rep2.counts["masked"] == 0


# --- waivers -------------------------------------------------------------------


def test_waiver_moves_a_finding_to_declared_and_stale_raises():
    key = (("note",), "null", "MR-4", Severity.REJECT, Severity.PASS)
    rep = probe_persistence(
        FIX, _erasing, tamper=TAMPER, declared={key: "legacy bundles carry no note; tracked #1"}
    )
    assert rep.counts["declared_limits"] == 1
    assert not any(f.path == ("note",) and f.rung == "null" for f in rep.findings)
    assert rep.ok is False  # the `absent` erase is still unexcused
    with pytest.raises(DegradationConfigError, match="stale"):
        probe_persistence(FIX, _convict, tamper=TAMPER, declared={key: "nothing to excuse"})
    with pytest.raises(DegradationConfigError, match="only MR-4"):
        probe_persistence(
            FIX, _erasing, tamper=TAMPER,
            declared={(("note",), "null", "MR-1", Severity.REJECT, Severity.PASS): "x"},
        )


def _two_reason_convict(root):
    if not isinstance(root, dict):
        return Severity.ERROR_CLEAN, ("NOT_A_DOC",), True
    if root.get("amount") != 100:
        return Severity.REJECT, ("AMOUNT_MISMATCH", "AMOUNT_NEGATIVE"), True
    return Severity.PASS, (), True


def _mask_one(root):  # sibling guard drops ONE of the two convicting reasons
    if isinstance(root, dict) and not isinstance(root.get("meta"), dict):
        return Severity.REJECT, ("FLAG_BAD", "AMOUNT_MISMATCH"), True
    return _two_reason_convict(root)


def _mask_both(root):  # the later regression: TOTAL masking at the same spot
    if isinstance(root, dict) and not isinstance(root.get("meta"), dict):
        return Severity.REJECT, ("FLAG_BAD",), True
    return _two_reason_convict(root)


def test_red_team_R1_a_masked_waiver_names_the_lost_set_and_a_wider_loss_is_unexcused():
    """Stage-5 witness (2026-09-12): keyed on REJECT->REJECT alone, one waiver
    excused both a 1-of-2 and a 2-of-2 masking at the same (path, rung)."""
    spot = (("meta",), "wrong_type", "MR-4", Severity.REJECT, Severity.REJECT)
    # a masked hit is never matched by a set-less key (that key shape is for
    # erased/demoted): it goes STALE, and the hit stays live on the report
    with pytest.raises(DegradationConfigError, match="stale"):
        probe_persistence(FIX, _mask_one, tamper=TAMPER, declared={spot: "no set named"})
    with pytest.raises(DegradationConfigError, match="sixth element"):
        probe_persistence(FIX, _mask_one, tamper=TAMPER, declared={spot + (frozenset(),): "empty set"})
    key = spot + (frozenset({"AMOUNT_NEGATIVE"}),)
    rep = probe_persistence(FIX, _mask_one, tamper=TAMPER, declared={key: "redundant reason"})
    assert not any(f.path == ("meta",) and f.rung == "wrong_type" for f in rep.findings)
    # the SAME waiver against the wider loss: stale (matches nothing) AND the hit is live
    with pytest.raises(DegradationConfigError, match="stale") as ei:
        probe_persistence(FIX, _mask_both, tamper=TAMPER, declared={key: "redundant reason"})
    assert "UNEXCUSED" in str(ei.value)


def test_red_team_R2_unhashable_reason_is_a_named_config_error():
    def chk(root):
        sev, r, s = _convict(root)
        return sev, tuple([list(x)] for x in r), s  # a list is not hashable

    with pytest.raises(DegradationConfigError, match="not hashable"):
        probe_persistence(FIX, chk, tamper=TAMPER)


# --- anti-tautology: mutate the ORACLE, the controls must go green -------------


def _load_mutant(old: str, new: str):
    src = (_PKG_ROOT / "audit_bundle" / "_degradation.py").read_text()
    assert src.count(old) == 1, f"mutation site not unique: {old!r}"
    name = f"_degradation_mutant_{hashlib.sha256(old.encode()).hexdigest()[:8]}"
    spec = importlib.util.spec_from_loader(name, loader=None)
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = str(_PKG_ROOT / "audit_bundle" / "_degradation.py")
    sys.modules[name] = mod  # dataclasses resolve `from __future__` annotations via sys.modules
    try:
        exec(compile(src.replace(old, new), mod.__file__, "exec"), mod.__dict__)
    finally:
        sys.modules.pop(name, None)
    return mod


def test_mutant_erased_branch_deleted_turns_the_positive_control_green():
    M = _load_mutant(
        "            if sev == Severity.PASS:\n                erased += 1",
        "            if False:\n                erased += 1",
    )
    rep = M.probe_persistence(FIX, _erasing, tamper=TAMPER)
    # under the mutant a PASS falls through to the REJECT arm and is scored persisted
    assert rep.counts["erased"] == 0 and rep.counts["findings_tier1"] == 0


def test_mutant_masked_comparison_deleted_turns_the_masked_control_green():
    M = _load_mutant(
        "            missing = convicting - got\n",
        "            missing = frozenset()\n",
    )
    rep = M.probe_persistence(FIX, _masking, tamper=TAMPER)
    assert rep.counts["masked"] == 0 and rep.ok is True


def test_mutant_ancestor_skip_deleted_manufactures_a_false_finding():
    """Without the ancestor skip, `parent_scalar` at ("meta","j") replaces the whole
    of "meta" with "x", the tamper leaves the artifact, and a defect-free checker's
    ERROR_CLEAN is filed as `demoted`. The skip is load-bearing."""
    M = _load_mutant(
        "            if _is_prefix(rung_site, tuple(site)):\n                skipped_ancestor += 1\n                continue\n",
        "            if False:\n                skipped_ancestor += 1\n                continue\n",
    )
    fix = {"meta": {"k": 1, "j": 2}, "x": 1}

    def chk(root):
        if not isinstance(root, dict) or not isinstance(root.get("meta"), dict):
            return Severity.ERROR_CLEAN, ("META_UNREADABLE",), True
        if root["meta"].get("k") != 1:
            return Severity.REJECT, ("K_MISMATCH",), True
        return Severity.PASS, (), True

    rep = M.probe_persistence(fix, chk, tamper=(("meta", "k"), 5))
    assert rep.counts["demoted"] >= 1 and rep.ok is False
