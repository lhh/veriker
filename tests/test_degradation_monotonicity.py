"""tests/test_degradation_monotonicity.py — the row-20 guard, and its control.

THREAT_MODEL row 20 states a doctrine ("absent may pass; present-but-unparseable
must NEVER share a return value with absent") whose reason-code column reads
"own code per surface", under a document that says "A doctrine row is not a
guard." `audit_bundle/_degradation.py` is the guard. This file is what stops it
rotting into one.

THE CONTROL IS THE POINT. A green run of a detector that was never shown a
positive case is not evidence. So the differential below runs the SAME oracle
over the SAME fixture against two versions of one module:

  * `tests/fixtures/degradation/c18_verifier_identity_a35ca9035.py` — the
    verbatim pre-fix module from commit a35ca9035, where
    `_extract_verifier_identity_block` returned `dict | None` and collapsed
    ABSENT into MALFORMED while both callers read None as "legacy -> clean
    PASS". Committed as a fixture rather than fetched with `git show` so the
    control still RUNS in an export, a tarball, or any tree without git
    history. `tests/test_degradation_fixture_provenance.py` (internal-only;
    not in the OSS drop, because it needs internal git history) pins it back
    to a35ca9035, so the fixture cannot drift into a convenient forgery.
  * the live `audit_bundle/extensions/c18_verifier_identity.py`.

Pre-fix must FIRE; post-fix must be clean at the same rung. Only the pair is
evidence: green-on-master alone would pass with the oracle deleted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle._degradation import (  # noqa: E402
    DegradationConfigError,
    Severity,
    build_ladder,
    probe_monotonicity,
    reasons_adapter,
)

_PREFIX_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "degradation"
    / "c18_verifier_identity_a35ca9035.py"
)
_PREFIX_COMMIT = "a35ca9035"
_LIVE_REL = "audit_bundle/extensions/c18_verifier_identity.py"

# A COMPLETE, accepted verifier_identity block. Every one of the 8 required
# fields is present and well-formed, so the untouched fixture is a clean PASS
# and V1 does not refuse the probe. (It refused the first draft of this
# fixture, which was missing 6 fields — the vacuity gate catching its author.)
_GOOD_BLOCK = {
    "verifier_release_id": "v0.1.4",
    "release_manifest_url": "https://example.invalid/release_manifest.json",
    "release_manifest_hash": "sha256:" + "b" * 64,
    "scitt_statement_hash": "sha256:" + "c" * 64,
    "sigstore_bundle_hash": "sha256:" + "d" * 64,
    "rekor_inclusion_proof": {
        "leaf_index": 1,
        "tree_size": 2,
        "hashes": ["e" * 64],
        "root_hash": "f" * 64,
    },
    "verifier_oci_digest": "sha256:" + "a" * 64,
    "verifier_self_check_status": "passed",
}
_FIXTURE = {"evidence": {"verifier_identity": dict(_GOOD_BLOCK)}}
_BLOCK_PATH = ("evidence", "verifier_identity")

# `null` at the block path is treated as ABSENT by the LIVE module, on purpose:
# cd5c782cd, "None counts as ABSENT so a `verifier_identity: dict | None = None`
# dataclass default is unaffected". It grants a producer no capability that
# deleting the key does not already grant, so it is a declared limit and not a
# hole — but it is a THIRD spelling of absence that row 20's text does not
# mention, which is why it is declared here in writing rather than filtered out
# in silence.
_NULL_IS_ABSENT = (
    "JSON null is read as ABSENT by _locate_verifier_identity so a "
    "`verifier_identity: dict | None = None` dataclass default keeps "
    "working (cd5c782cd). Same capability as deleting the key; no new "
    "escape. THREAT_MODEL row 20 names two spellings of absence, not three."
)
# Keyed on the TRANSITION, not just the spot: (path, rung, relation,
# base_severity, rung_severity). A waiver naming REJECT -> PASS does not excuse
# anything worse turning up at the same rung later.
_LIVE_DECLARED = {
    (_BLOCK_PATH, "null", "MR-1", Severity.REJECT, Severity.PASS): _NULL_IS_ABSENT,
    # The SAME convention one container level up, and the oracle could not see
    # it until MR-1 started comparing rung to rung: `evidence: "x"` is
    # VI_MALFORMED (REJECT) but `evidence: null` falls through the
    # `elif evidence is not None` at c18_verifier_identity.py:424 to VI_ABSENT
    # (clean PASS). The base-anchored MR-1 anchored this path on a PASSing
    # shape_preserving rung and discarded the ladder, so the second spelling
    # was invisible. It is the declared limit above, not a new escape — an
    # `evidence` key holding null grants a producer nothing that omitting the
    # key does not already grant.
    (
        ("evidence",),
        "null",
        "MR-1",
        Severity.REJECT,
        Severity.PASS,
    ): _NULL_IS_ABSENT,
}


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _run_for(mod):
    def structural(manifest):
        return mod.verify_verifier_identity_structural(Path("/nonexistent"), manifest)

    return reasons_adapter(structural)


@pytest.fixture(scope="module")
def prefix_mod():
    return _load(_PREFIX_FIXTURE, "_c18_prefix_a35ca9035")


@pytest.fixture(scope="module")
def live_mod():
    return _load(_PKG_ROOT / _LIVE_REL, "_c18_live_under_probe")


# ---------------------------------------------------------------------------
# provenance of the control
# ---------------------------------------------------------------------------
# The byte-for-byte pin of the fixture to the internal commit a35ca9035 lives
# in tests/test_degradation_fixture_provenance.py, which the OSS drop does NOT
# ship: it reads a blob out of internal git history, and the public repo is
# published as one fresh commit with no history, so in a consumer's clone it
# could only fail. The differential control below (pre-fix fires, live is
# clean, the delta is pinned by count) needs no history and ships.


def test_both_modules_accept_the_good_block(prefix_mod, live_mod):
    """Anti-vacuity floor: if the untouched fixture did not pass on BOTH sides,
    the differential below would be comparing two rejections."""
    for mod in (prefix_mod, live_mod):
        assert (
            mod.verify_verifier_identity_structural(Path("/nonexistent"), _FIXTURE)
            == []
        ), f"{mod.__name__} rejects the good block; the probe would be vacuous"


# ---------------------------------------------------------------------------
# the differential — the whole reason this file exists
# ---------------------------------------------------------------------------


def test_oracle_FIRES_on_the_real_pre_fix_module(prefix_mod):
    """RED half. Degrading the block past the parser bought a clean PASS while a
    merely-INCOMPLETE block drew blocking reasons. If this ever goes quiet, the
    oracle has stopped working — it is not evidence that c18 got better."""
    rep = probe_monotonicity(_FIXTURE, _run_for(prefix_mod))
    assert not rep.vacuous, rep.counts
    hits = {(f.path, f.rung) for f in rep.findings if f.tier == 1}
    assert (_BLOCK_PATH, "wrong_type") in hits, (
        f"the oracle did not catch the a35ca9035 defect: {sorted(hits)}"
    )
    assert (_BLOCK_PATH, "parent_scalar") in hits, (
        f"the one-level-up degradation (`evidence: 'x'`) was not caught: {sorted(hits)}"
    )


def test_live_module_is_clean_at_those_rungs(live_mod):
    """GREEN half. Every rung the pre-fix module lost is now closed, and the one
    surviving hit is DECLARED in writing (see _LIVE_DECLARED) rather than
    filtered out."""
    rep = probe_monotonicity(_FIXTURE, _run_for(live_mod), declared=_LIVE_DECLARED)
    assert not rep.vacuous, rep.counts
    assert rep.findings == [], "row 20 regression on the c18 surface: " + "; ".join(
        f"{list(f.path)} rung={f.rung}: {f.detail}" for f in rep.findings
    )
    assert rep.declared_limits, "the null declaration went stale — re-derive it"


# The one (path, rung) the c18 fix ADDED, pinned by name so it cannot grow a
# companion in silence. The pre-fix module was uniformly fail-open at
# `evidence` — both `"x"` and `null` collapsed to None and passed — which is
# MONOTONE, so no ordering hit existed there. The fix made `evidence: "x"`
# VI_MALFORMED (REJECT) and deliberately left `null` on the ABSENT path, and
# that asymmetry is what the rung-to-rung MR-1 now sees. It grants a producer
# nothing that omitting the key does not already grant; it is declared in
# _LIVE_DECLARED, in writing, for that reason.
_ADDED_BY_THE_FIX = {(("evidence",), "null")}


def test_the_fix_strictly_closed_rungs(prefix_mod, live_mod):
    """The delta, asserted as a delta. Guards against a 'fix' that merely moved
    the defect to a different rung."""
    pre = probe_monotonicity(_FIXTURE, _run_for(prefix_mod))
    post = probe_monotonicity(_FIXTURE, _run_for(live_mod))
    pre_hits = {(f.path, f.rung) for f in pre.findings}
    post_hits = {(f.path, f.rung) for f in post.findings}
    added = post_hits - pre_hits
    assert added == _ADDED_BY_THE_FIX, (
        f"the fix added an ordering hit that is not the one pinned above: "
        f"{sorted(added)}. This is the 'moved the defect to a different rung' "
        f"case — do not re-baseline it, derive it."
    )
    assert added <= {(k[0], k[1]) for k in _LIVE_DECLARED}, (
        "a rung the fix ADDED is not declared in writing; a new hit must be "
        "argued, not absorbed into the baseline"
    )
    assert (post_hits - added) < pre_hits, (
        f"the fix did not strictly shrink the pre-existing finding set: "
        f"pre={sorted(pre_hits)} post={sorted(post_hits)}"
    )


# ---------------------------------------------------------------------------
# the oracle's own gates — each asserted to FIRE, not merely to exist
# ---------------------------------------------------------------------------


def test_V1_refuses_a_fixture_that_is_already_rejected():
    with pytest.raises(DegradationConfigError, match="V1"):
        probe_monotonicity({"a": 1}, lambda root: (Severity.REJECT, ("X",)))


def test_V2_reports_an_indifferent_path_instead_of_a_pass():
    """A checker that ignores everything must not read as green."""
    rep = probe_monotonicity({"a": 1}, lambda root: (Severity.PASS, ()))
    assert rep.vacuous is True
    assert rep.ok is False
    assert ("a",) in rep.indifferent


def test_V4_a_check_that_never_spoke_is_vacuous_not_clean():
    """The instrument's own measured defect: a 12-plugin sweep read clean for
    plugins that were inert, because every rejection came from the parse
    boundary upstream of them."""

    def upstream_only(root):
        # rejects on any mutation, but never speaks as the check under test
        return (
            (Severity.PASS, (), True)
            if root == {"a": "aaa"}
            else (Severity.REJECT, ("PARSE_REFUSED",), False)
        )

    rep = probe_monotonicity({"a": "aaa"}, upstream_only)
    assert rep.vacuous is True, rep.counts
    assert rep.ok is False
    assert rep.counts["paths_upstream_only_v4"] >= 1
    assert rep.counts["paths_probed"] == 0


def test_MR1_fires_on_a_synthetic_softening():
    """The row-20 shape in twelve lines: a wrong value rejects, an unparseable
    one sails through."""

    def checker(root):
        if not isinstance(root, dict):
            return (Severity.REJECT, ("ROOT_MALFORMED",))
        v = root.get("blk")
        if not isinstance(v, dict):
            return (Severity.PASS, ())  # <- collapses malformed into absent
        return (
            (Severity.PASS, ())
            if v.get("k") == "ok"
            else (Severity.REJECT, ("FIELD_BAD",))
        )

    rep = probe_monotonicity({"blk": {"k": "ok"}}, checker)
    assert any(
        f.tier == 1 and f.relation == "MR-1" and f.rung == "wrong_type"
        for f in rep.findings
    ), rep.findings


def test_MR2_absent_pass_is_a_disclosure_never_a_finding():
    """Row 20 clause 1 is 'absent MAY pass'. The oracle must not call that a
    defect — but must not stay silent about it either."""

    def checker(root):
        if not isinstance(root, dict):
            return (Severity.REJECT, ("ROOT_MALFORMED",))
        if "blk" not in root:
            return (Severity.PASS, ())
        return (
            (Severity.PASS, ()) if root["blk"] == "ok" else (Severity.REJECT, ("BAD",))
        )

    rep = probe_monotonicity({"blk": "ok"}, checker)
    assert any(d.rung == "absent" for d in rep.disclosures), rep.disclosures
    assert not any(f.rung == "absent" for f in rep.findings), rep.findings


def test_TIER2_is_a_reject_softening_to_error_not_a_pass():
    """The two tiers must not be conflated: TIER-1 reaches PASS under every
    lattice, TIER-2 depends on how the consumer treats could-not-conclude."""

    def checker(root):
        if not isinstance(root, dict):
            return (Severity.REJECT, ("ROOT_MALFORMED",))
        v = root.get("blk")
        if not isinstance(v, dict):
            return (Severity.ERROR, ("CANNOT_PARSE",))
        return (
            (Severity.PASS, ())
            if v.get("k") == "ok"
            else (Severity.REJECT, ("FIELD_BAD",))
        )

    rep = probe_monotonicity({"blk": {"k": "ok"}}, checker)
    tiers = {f.tier for f in rep.findings if f.rung == "wrong_type"}
    assert tiers == {2}, rep.findings


def test_a_declaration_needs_a_reason_and_must_not_go_stale():
    def checker(root):
        if not isinstance(root, dict):
            return (Severity.REJECT, ("ROOT_MALFORMED",))
        v = root.get("blk")
        if not isinstance(v, dict):
            return (Severity.PASS, ())
        return (
            (Severity.PASS, ())
            if v.get("k") == "ok"
            else (Severity.REJECT, ("FIELD_BAD",))
        )

    fixture = {"blk": {"k": "ok"}}
    live_key = (("blk",), "wrong_type", "MR-1", Severity.REJECT, Severity.PASS)
    with pytest.raises(DegradationConfigError, match="non-empty reason"):
        probe_monotonicity(fixture, checker, declared={live_key: "  "})
    with pytest.raises(DegradationConfigError, match="stale"):
        probe_monotonicity(
            fixture,
            checker,
            declared={
                (("nope",), "wrong_type", "MR-1", Severity.REJECT, Severity.PASS): (
                    "not live"
                )
            },
        )
    # ...and the key SHAPE is checked: (path, rung) alone is refused, because
    # it excused whatever softening turned up at that spot.
    with pytest.raises(DegradationConfigError, match="transition is part of the key"):
        probe_monotonicity(
            fixture, checker, declared={(("blk",), "wrong_type"): "too coarse"}
        )


def test_ladder_drops_no_op_mutations():
    """A rung whose root equals the fixture (or an earlier rung) is not a probe.
    An empty dict has no shape-preserving mutant and no empty-same-type one."""
    names = [r.name for r in build_ladder({"a": {}}, ("a",))]
    assert "shape_preserving" not in names
    assert "empty_same_type" not in names
    assert "wrong_type" in names


# ---------------------------------------------------------------------------
# post-audit additions — each of these exists because a fresh-context pass
# found the claim it pins was unbacked
# ---------------------------------------------------------------------------


def test_scalar_mutant_is_probe_checks_and_has_not_been_re_authored():
    """AUDIT #1. The scalar arm of `_shape_preserving` used to be a hand-copy of
    `_total_binding._default_mutant`, and it had already DRIFTED: the original
    returns None on an empty string (a loud ProbeConfigError telling the author
    to supply a predicate), the copy returned () (a silent missing rung) — the
    copy being the fail-open one. It now delegates. This pins that."""
    from audit_bundle._degradation import _shape_preserving
    from audit_bundle._total_binding import _default_mutant

    for node in (True, False, 0, 7, -3, 0.0, 2.5, "", "a", "abc", "000"):
        expected = _default_mutant(node)
        expected = () if expected is None else expected
        assert _shape_preserving(node) == expected, (
            f"scalar mutant drifted from probe_check's on {node!r}"
        )


def test_walkers_agree_with_total_bindings_on_json_ish_roots():
    """AUDIT #1 cont. The walkers stay local because they are genuinely
    different (JSON-only, root-first, deletion-capable). 'Different on purpose'
    is only credible if the overlap is pinned."""
    from audit_bundle import _total_binding as TB
    from audit_bundle._degradation import _node_at, _set_at, _walk

    root = {"a": {"b": [1, "two", {"c": True}]}, "d": None}
    mine = {p for p, _ in _walk(root)}
    theirs = {p for p, _ in TB._walk_nodes(root)}
    assert mine == theirs, f"path sets diverge: {mine ^ theirs}"
    for path in sorted(mine, key=repr):
        assert _node_at(root, path) == TB._node_at(root, path)
        if path:
            assert _set_at(root, path, "Z") == TB._set_at(root, path, "Z"), path


def test_the_prefix_delta_is_pinned_by_COUNT_not_only_by_membership(
    prefix_mod, live_mod
):
    """AUDIT #7. The commit message asserted '7 TIER-1 pre-fix, 1 post-fix' and
    nothing in the tree produced either number. These are WITNESSES of one
    defect, not seven defects — the count is pinned so the claim is
    reproducible, and labelled so it is not read as a defect tally.

    RE-BASELINED when MR-1 became a whole-ladder relation (finding #1) and the
    parent rungs stopped destroying the whole document (finding #2). PRE went
    7 -> 6 and POST 1 -> 2, and neither number moved because the modules
    changed:
      * -2  the two MR-3 hits are now the SAME MR-1 hits. MR-3 was
            `severity(parent_scalar) >= severity(wrong_type)` — one ordered
            pair of PRESENT rungs, which the running-maximum rule covers, so
            the relation was deleted rather than left to double-report.
      * +1  `verifier_oci_digest` `parent_scalar`, a REAL pre-fix softening
            that was INVISIBLE: its `shape_preserving` rung passed, so the old
            rule discarded the whole ladder after computing it.
      * +1  POST `('evidence',) null`, the second spelling of the declared
            null-is-absent limit (see _LIVE_DECLARED), hidden by the same
            PASSing-base discard.
    Both new hits are the false negative #1 names, showing up on the one
    artifact this repo has a verified control for."""
    pre = probe_monotonicity(_FIXTURE, _run_for(prefix_mod))
    post = probe_monotonicity(_FIXTURE, _run_for(live_mod))
    assert len([f for f in pre.findings if f.tier == 1]) == 6, (
        f"pre-fix TIER-1 witness count moved: "
        f"{[(list(f.path), f.rung) for f in pre.findings]}"
    )
    assert len([f for f in post.findings if f.tier == 1]) == 2, (
        f"post-fix TIER-1 witness count moved: "
        f"{[(list(f.path), f.rung) for f in post.findings]}"
    )
    assert {f.rung for f in post.findings} == {"null"}, (
        "the only surviving post-fix witnesses must be the DECLARED null rungs"
    )


def test_a_crash_outranks_reject_and_is_never_filed_as_a_softening():
    """AUDIT #4. verdict.py's ratified order is crash-ERROR > REJECT >
    clean-ERROR > OK. Flattening ERROR to one rank below REJECT filed
    REJECT->crash as a softening the codebase's own algebra calls a
    STRENGTHENING. A crash is not a finding — and not silence either."""
    assert Severity.PASS < Severity.ERROR_CLEAN < Severity.REJECT < Severity.ERROR_CRASH

    def crashes_on_garbage(root):
        if not isinstance(root, dict):
            return (Severity.REJECT, ("ROOT",))
        v = root.get("blk")
        if v is None:
            return (Severity.PASS, ())
        if not isinstance(v, dict):
            return (Severity.ERROR_CRASH, ("TypeError",))
        return (
            (Severity.PASS, ()) if v.get("k") == "ok" else (Severity.REJECT, ("BAD",))
        )

    rep = probe_monotonicity({"blk": {"k": "ok"}}, crashes_on_garbage)
    assert not any(f.rung == "wrong_type" for f in rep.findings), rep.findings
    assert rep.crashes, "a crash on producer bytes must still be reported"


def test_an_undeclared_disclosure_blocks_ok():
    """AUDIT #8. `ok` ignored disclosures, so a run in which every guard was
    bypassable by deletion returned ok=True and said so only in prose — the
    instrument reproducing the very collapse row 20 prohibits."""

    def checker(root):
        if not isinstance(root, dict):
            return (Severity.REJECT, ("ROOT",))
        if "blk" not in root:
            return (Severity.PASS, ())
        return (
            (Severity.PASS, ()) if root["blk"] == "ok" else (Severity.REJECT, ("BAD",))
        )

    rep = probe_monotonicity({"blk": "ok"}, checker)
    assert rep.disclosures and rep.ok is False
    declared = {
        (
            d.path,
            d.rung,
            d.relation,
            d.base_severity,
            d.rung_severity,
        ): "optional by design; legacy artifacts omit it"
        for d in rep.disclosures
    }
    assert probe_monotonicity({"blk": "ok"}, checker, declared=declared).ok is True
