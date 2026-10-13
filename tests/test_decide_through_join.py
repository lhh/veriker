"""tests/test_decide_through_join.py — One F depth 1: the generic verifier decides through the join.

What is pinned here (each by an assertion that fails if the claim is false):

  * the PROJECTION: each join decision lands on exactly one tri-state (RELEASE→OK,
    REFUSE→REJECT, HOLD→clean-ERROR, NO_VERDICT→crash-ERROR) and the returned verdict is
    BUILT from it (a `_STATE_OF` that lies changes `state`; the meet then disagrees);
  * ABSENCE IS NOT AGREEMENT: an early exit of the walk, or an admission step that did
    not finish, confirms nothing — no proposition is residual, none is established;
  * every EXIT of the walk reaches the join (eight early exits plus the crash boundary,
    each driven through the real `BundleVerifier`), and the crash class arrives as
    NO_VERDICT with a face;
  * the FACE: every RELEASE on a completed walk rests on the proposer's root only, BY
    CONSTRUCTION (one record, producer envelope);
  * LEGS: a single-verdict exit returns master's shape (no legs); a composite keeps every leg;
  * the CROSS-CHECK: a meet that disagrees with the join, from a lying projection or from a
    broken attribution, is a crash-ERROR (DECISION_DIVERGENCE) that reaches the caller
    through `fail_closed`; a malformed leg or an unknown check name is refused before
    either side can read it differently;
  * the DENOMINATOR: every check name the walk's own code can put on a reason is in an
    attribution class (a source census with a planted-name control);
  * the ORACLE: `probe_monotonicity` through `BundleVerifier.verify` finds nothing beyond
    master's two declared null-field hits.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle import decide as D  # noqa: E402
from audit_bundle._degradation import Severity, probe_monotonicity, verdict_adapter  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verdict import (  # noqa: E402
    VERIFIER_INCOMPLETE,
    ErrorKind,
    Verdict,
    VerdictState,
    VerifierError,
)
from audit_bundle.verifier import BundleVerifier, VerifyFailure  # noqa: E402


def _rej(check: str, code: str = "X", detail: str = "d") -> Verdict:
    return Verdict.from_failures([VerifyFailure(check, code, detail)])


def _inc(check: str) -> Verdict:
    return Verdict.incomplete(
        VERIFIER_INCOMPLETE, "could not conclude", check_name=check
    )


_MANIFEST = {
    "schema_version": "vcp-v1.1-canary4",
    "bundle_id": "depth1-oracle",
    "created_at": "2026-10-07T00:00:00Z",
    "files": {},
    "spec_files": {},
    "cross_refs": {},
}


def _write_manifest(bundle_dir: Path, manifest, raw: bytes | None = None) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    p = bundle_dir / "manifest.json"
    p.write_bytes(raw if raw is not None else json.dumps(manifest).encode("utf-8"))
    return bundle_dir


# ---------------------------------------------------------------------------
# projection
# ---------------------------------------------------------------------------


def test_ok_walk_releases_on_the_proposer_root_only():
    v = D.decide_through_join(Verdict.passed())
    assert v.state is VerdictState.OK and v.ok and v.legs == ()
    face = v.decision
    assert (
        face["engine"] == "multi_root"
        and face["depth"] == 1
        and face["walk_completed"] is True
    )
    assert face["decision"] == "RELEASE"
    assert face["denominator"] == len(D.PROPOSITIONS) == 13
    assert sorted(face["residual_proposer_root_only"]) == sorted(D.PROPOSITIONS)
    assert face["established"] == [] and face["independent_roots_establishing"] == []
    assert face["record_dispositions"] == {D.RECORD_ID: "ADMITTED"}
    assert list(face["steps_ran"]) == list(D.PROPOSITIONS)


def test_a_provenance_reject_is_refused_at_signature_and_refuses():
    v = D.decide_through_join(_rej("file_integrity", "BAD_FILE_SHA"))
    assert v.state is VerdictState.REJECT and v.legs == ()
    assert v.decision["decision"] == "REFUSE"
    assert v.decision["unusable_records"] == [D.RECORD_ID]
    assert "BAD_FILE_SHA" in v.decision["admission_reasons"][D.RECORD_ID]
    assert "malformed content" not in v.decision["admission_reasons"][D.RECORD_ID]
    assert v.reasons[0].code == "BAD_FILE_SHA"  # the step's own reason survives


def test_a_content_reject_is_malformed_content_and_refuses():
    v = D.decide_through_join(_rej("cross_refs", "BROKEN_CROSS_REF"))
    assert v.state is VerdictState.REJECT
    assert v.decision["unusable_records"] == [D.RECORD_ID]
    assert v.decision["admission_reasons"][D.RECORD_ID].startswith("malformed content")


def test_a_proposition_reject_is_a_contradiction_and_refuses():
    v = D.decide_through_join(_rej("typed_check_plugins:my_plugin", "plugin_failed"))
    assert v.state is VerdictState.REJECT
    assert v.decision["contradicted"] == ["typed_check_plugins"]
    assert v.decision["unusable_records"] == []


def test_a_clean_error_leg_holds_as_incomplete():
    v = D.decide_through_join(Verdict.passed(), [_inc("claimset_coverage")])
    assert v.state is VerdictState.ERROR and v.is_incomplete
    assert v.decision["decision"] == "HOLD"
    assert v.decision["unconfirmed"] == ["claimset_coverage"]
    assert v.decision["states"]["claimset_coverage"] == [
        "CANNOT_CONCLUDE",
        "INSUFFICIENT",
    ]
    assert len(v.legs) == 2  # a composite keeps every leg, as compose always did


def test_reject_dominates_a_clean_error_leg():
    v = D.decide_through_join(_rej("cross_refs", "BROKEN"), [_inc("claimset_coverage")])
    assert v.state is VerdictState.REJECT and v.decision["decision"] == "REFUSE"
    assert any(leg.is_incomplete for leg in v.legs)


def test_a_crash_leg_is_no_verdict_and_dominates_everything():
    crash = Verdict.error("VERIFIER_INTERNAL_ERROR", "boom", "BundleVerifier.verify")
    v = D.decide_through_join(
        _rej("cross_refs", "BROKEN"), [_inc("claimset_coverage")], crashes=(crash,)
    )
    assert v.state is VerdictState.ERROR and v.is_crash
    assert v.decision["decision"] == "NO_VERDICT"


def test_the_verdict_is_built_from_the_join_not_the_meet(monkeypatch):
    """A projection that lies changes `state`; the meet then disagrees and the
    cross-check fires. If the returned verdict were the meet's, this would pass silently."""
    monkeypatch.setattr(
        D, "_STATE_OF", {**D._STATE_OF, "RELEASE": (VerdictState.REJECT, None)}
    )
    with pytest.raises(VerifierError) as ei:
        D.decide_through_join(Verdict.passed())
    assert ei.value.code == D.DECISION_DIVERGENCE


# ---------------------------------------------------------------------------
# absence is not agreement
# ---------------------------------------------------------------------------


def test_an_early_exit_confirms_nothing():
    v = D.decide_single(
        Verdict.incomplete(
            "SNAPSHOT_MATERIALIZATION_FAILED", "ENOSPC", "sealed_snapshot"
        )
    )
    assert v.state is VerdictState.ERROR and v.is_incomplete and v.legs == ()
    face = v.decision
    assert face["walk_completed"] is False and face["steps_ran"] == []
    assert face["residual_proposer_root_only"] == [] and face["established"] == []
    assert sorted(face["unconfirmed"]) == sorted(D.PROPOSITIONS)
    assert face["admission_unfinished"] == [
        "'sealed_snapshot': 'SNAPSHOT_MATERIALIZATION_FAILED'"
    ]


def test_an_unfinished_admission_on_a_completed_walk_confirms_nothing():
    v = D.decide_through_join(
        Verdict.passed(), [_inc("sealed_snapshot")], walk_completed=True
    )
    assert v.state is VerdictState.ERROR and v.is_incomplete
    assert (
        v.decision["steps_ran"] == []
        and v.decision["residual_proposer_root_only"] == []
    )


def test_an_early_reject_exit_refuses_with_every_proposition_unreached():
    v = D.decide_single(Verdict.reject("malformed_manifest", "bad", "manifest_load"))
    assert v.state is VerdictState.REJECT and v.legs == ()
    assert v.decision["unusable_records"] == [D.RECORD_ID]
    assert sorted(v.decision["unreached"]) == sorted(D.PROPOSITIONS)
    assert v.decision["residual_proposer_root_only"] == []


# ---------------------------------------------------------------------------
# refusals before either side can read a leg differently
# ---------------------------------------------------------------------------


def test_an_unknown_check_name_is_a_verifier_defect():
    with pytest.raises(VerifierError) as ei:
        D.decide_through_join(_rej("some_future_step:instance", "NEW_CODE"))
    assert ei.value.code == D.UNATTRIBUTED_CHECK_NAME


_REASONLESS_INCOMPLETE = Verdict(
    VerdictState.ERROR, (), error_kind=ErrorKind.INCOMPLETE
)


@pytest.mark.parametrize(
    "base, incompletes, crashes",
    [
        (Verdict.passed(), (_REASONLESS_INCOMPLETE,), ()),
        (Verdict.passed(), (_rej("cross_refs"),), ()),
        (Verdict.passed(), (), (_inc("claimset_coverage"),)),
        (_inc("claimset_coverage"), (), ()),
        (Verdict(VerdictState.REJECT, ()), (), ()),
    ],
    ids=[
        "reasonless-incomplete",
        "reject-in-incompletes",
        "incomplete-in-crashes",
        "error-as-base",
        "reasonless-reject",
    ],
)
def test_a_malformed_leg_is_refused(base, incompletes, crashes):
    with pytest.raises(VerifierError) as ei:
        D.decide_through_join(base, incompletes, crashes=crashes)
    assert ei.value.code == D.MALFORMED_LEG


def test_decide_single_refuses_an_ok_verdict():
    with pytest.raises(VerifierError) as ei:
        D.decide_single(Verdict.passed())
    assert ei.value.code == D.MALFORMED_LEG


def test_a_broken_attribution_is_a_divergence_through_the_real_verifier(
    tmp_path, monkeypatch
):
    """A divergence that originates in `_split` (a SILENT leg misread as CONTRADICTS)
    reaches the caller of `BundleVerifier.verify` as a crash-ERROR carrying the code."""
    real_split = D._split

    def broken_split(base, incompletes, crashes):
        contradicts, silent, provenance, content, unfinished, crashed = real_split(
            base, incompletes, crashes
        )
        for p, rs in silent.items():
            contradicts[p].extend(rs)
            rs.clear()
        return contradicts, silent, provenance, content, unfinished, crashed

    monkeypatch.setattr(D, "_split", broken_split)
    bundle = _write_manifest(tmp_path / "b", _MANIFEST)
    v = BundleVerifier(plugins=(), require_rederivation=True).verify(bundle)
    assert v.state is VerdictState.ERROR and v.error_kind is ErrorKind.CRASH
    assert v.reasons[0].code == D.DECISION_DIVERGENCE


def test_decision_is_excluded_from_equality_and_frozen():
    a = D.decide_through_join(Verdict.passed())
    b = D.decide_through_join(Verdict.passed())
    assert a == b
    with pytest.raises((TypeError, AttributeError)):
        a.decision["decision"] = "RELEASE"  # deep-frozen face


# ---------------------------------------------------------------------------
# the committed denominator (source-level census, with a planted-name control)
# ---------------------------------------------------------------------------

_CHECK_NAME_KW = re.compile(r'check_name(?:: str)?\s*=\s*f?"([^"{]+)')
_VERDICT_CTOR = re.compile(
    r'Verdict\.(?:reject|incomplete|error)\(\s*"[^"]*"\s*,\s*[^,]+,\s*"([^"]+)"\s*\)',
    re.S,
)
_FAIL_CLOSED = re.compile(r'fail_closed\("([^"]+)"\)')
_WALK_FILES = ("audit_bundle/verifier.py", "audit_bundle/admission.py")


def _walk_check_names(extra_text: str = "") -> set[str]:
    """The check names the WALK's own code can put on a reason. Plugin and primitive
    results are re-labelled by the walk (`typed_check_plugins:<id>`,
    `spec_pinned_dispatch:<id>`), so their files are out of scope by design."""
    names: set[str] = set()
    texts = [(_PKG_ROOT / rel).read_text(encoding="utf-8") for rel in _WALK_FILES] + [
        extra_text
    ]
    for text in texts:
        for rx in (_CHECK_NAME_KW, _VERDICT_CTOR, _FAIL_CLOSED):
            names.update(m.group(1).rstrip(":") for m in rx.finditer(text))
    return names


def _classify(name: str) -> str:
    if name in D.CRASH_CHECKS:
        return "crash"
    try:
        return "admission" if D.proposition_of(name) is None else "proposition"
    except VerifierError:
        return "UNKNOWN"


def test_every_walk_check_name_is_attributed():
    names = _walk_check_names()
    assert len(names) >= 25, (
        f"census found too few names ({len(names)}): the regexes or the paths are stale"
    )
    for expected in (
        "sealed_snapshot",
        "manifest_load",
        "dsse_gate",
        "manifest_admission",
        "BundleVerifier.verify",
        "file_integrity",
        "claimset_coverage",
    ):
        assert expected in names, f"census missed {expected!r}"
    unknown = sorted(n for n in names if _classify(n) == "UNKNOWN")
    assert unknown == [], f"check names in no attribution class: {unknown}"
    assert set(D.ATTRIBUTION.values()) <= set(D.PROPOSITIONS)


def test_census_catches_a_planted_name():
    """The control: a name planted in the census input must come out UNKNOWN. Without
    this the ratchet above could pass with the regexes matching nothing new."""
    planted = _walk_check_names(
        'x = Verdict.reject("CODE", "detail", "zz_planted_step")\n'
    )
    assert "zz_planted_step" in planted
    assert _classify("zz_planted_step") == "UNKNOWN"


def test_proposition_of_reads_the_prefix_before_the_colon():
    assert D.proposition_of("typed_check_plugins:anything") == "typed_check_plugins"
    assert D.proposition_of("spec_pinned_dispatch:anchor") == "spec_pinned_dispatch"
    assert D.proposition_of("extension_receipt:some_kind") == "extension_receipts"
    assert D.proposition_of("file_integrity") is None
    assert D.proposition_of("manifest_load") is None
    with pytest.raises(VerifierError):
        D.proposition_of(None)


# ---------------------------------------------------------------------------
# every exit of the real verifier reaches the join
# ---------------------------------------------------------------------------


def _verify(bundle: Path, **kw) -> Verdict:
    return BundleVerifier(plugins=(), **kw).verify(bundle)


def test_exit_missing_manifest(tmp_path):
    v = _verify(tmp_path / "nowhere")
    assert v.state is VerdictState.REJECT and v.legs == ()
    assert v.decision["decision"] == "REFUSE" and v.decision["walk_completed"] is False


def test_exit_malformed_manifest(tmp_path):
    v = _verify(_write_manifest(tmp_path / "b", None, raw=b"{not json"))
    assert v.state is VerdictState.REJECT and v.reasons[0].code == "malformed_manifest"
    assert (
        v.decision["unusable_records"] == [D.RECORD_ID]
        and v.decision["walk_completed"] is False
    )


def test_exit_schema_version(tmp_path):
    v = _verify(
        _write_manifest(
            tmp_path / "b", {**_MANIFEST, "schema_version": "vcp-v9.9-nope"}
        )
    )
    assert v.state is VerdictState.REJECT and v.reasons[0].code == "schema_version"
    assert v.decision["decision"] == "REFUSE" and v.decision["walk_completed"] is False


def test_exit_manifest_admission(tmp_path):
    deep = b"[" * 20000 + b"]" * 20000
    v = _verify(_write_manifest(tmp_path / "b", None, raw=deep))
    assert v.state is not VerdictState.OK
    assert v.decision is not None and v.decision["walk_completed"] is False
    assert v.reasons[0].check_name == "manifest_admission"


def test_exit_dsse_gate(tmp_path):
    b = _write_manifest(tmp_path / "b", _MANIFEST)
    (b / "bundle.dsse.json").write_text("garbage", encoding="utf-8")
    v = _verify(b)
    assert v.state is VerdictState.REJECT and v.reasons[0].check_name == "dsse_gate"
    assert (
        v.decision["unusable_records"] == [D.RECORD_ID]
        and v.decision["walk_completed"] is False
    )
    assert "dsse_gate" in v.decision["admission_reasons"][D.RECORD_ID]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO needs a POSIX host")
def test_exit_non_regular_file_in_place(tmp_path):
    b = _write_manifest(tmp_path / "b", _MANIFEST)
    os.mkfifo(b / "pipe")
    v = _verify(b, unsafe_in_place=True)
    assert v.state is VerdictState.REJECT and v.reasons[0].check_name == "conservation"
    assert v.decision["walk_completed"] is False and v.decision["steps_ran"] == []
    assert v.completeness is not None and v.completeness.layers == ("conservation",)


def test_exit_anchor_guard_legs_match_master(tmp_path):
    """The anchor guard refuses before a bundle byte is judged: clean-ERROR, no legs
    (master's shape), nothing confirmed."""
    b = _write_manifest(tmp_path / "b", _MANIFEST)
    spec = b / "spec_inside.json"
    spec.write_text(json.dumps({"spec_id": "s", "x": 1}), encoding="utf-8")
    # Built with a forbid_within that does not cover the bundle, so construction passes and
    # the per-verify containment guard is what refuses (the source resolves INSIDE the bundle).
    anchor = SpecAnchor.from_files([spec], forbid_within=tmp_path / "elsewhere")
    v = _verify(b, spec_anchor=anchor)
    assert v.state is VerdictState.ERROR and v.is_incomplete and v.legs == ()
    assert v.reasons[0].check_name == "spec_pinned_dispatch:anchor"
    assert (
        v.decision["walk_completed"] is False
        and v.decision["residual_proposer_root_only"] == []
    )


def test_exit_snapshot_materialization_error(tmp_path, monkeypatch):
    from audit_bundle import verifier as V

    class _Boom(V.SnapshotMaterializationError):
        pass

    def no_snapshot(_dir):
        raise _Boom("ENOSPC (simulated)")

    monkeypatch.setattr(V, "sealed_snapshot", no_snapshot)
    v = _verify(_write_manifest(tmp_path / "b", _MANIFEST))
    assert v.state is VerdictState.ERROR and v.is_incomplete and v.legs == ()
    assert v.reasons[0].code == "SNAPSHOT_MATERIALIZATION_FAILED"
    assert (
        v.decision["steps_ran"] == []
        and v.decision["residual_proposer_root_only"] == []
    )


def test_a_plugin_crash_reaches_the_join_as_no_verdict(tmp_path):
    class Raises:
        plugin_id = "raises"
        name = "raises"

        def check(self, bundle_dir, manifest):
            raise RuntimeError("plugin exploded")

    b = _write_manifest(tmp_path / "b", {**_MANIFEST, "typed_checks": ["raises"]})
    v = BundleVerifier(plugins=(Raises(),)).verify(b)
    assert v.state is VerdictState.ERROR and v.error_kind is ErrorKind.CRASH
    assert v.decision is not None and v.decision["decision"] == "NO_VERDICT"
    assert (
        v.decision["walk_completed"] is False
        and v.decision["residual_proposer_root_only"] == []
    )


def test_a_completed_walk_through_the_real_verifier_releases_residual(tmp_path):
    v = _verify(_write_manifest(tmp_path / "b", _MANIFEST))
    assert v.state is VerdictState.OK and v.legs == ()
    assert v.decision["walk_completed"] is True
    assert sorted(v.decision["residual_proposer_root_only"]) == sorted(D.PROPOSITIONS)
    assert v.completeness is not None and "shallow_walk" in v.completeness.layers


# ---------------------------------------------------------------------------
# the oracle
# ---------------------------------------------------------------------------

# Measured 2026-10-07 on master (bare checkout) and on this branch with the same probe
# (`one_f/depth1_verifier_join/probe_master.py`, outputs committed beside it): byte-identical
# reports, 28 legs, these two MR-1 hits and six MR-2 deletion disclosures on both. The two
# hits are the open null-valued-field class (`the internal design notes`): a null `bundle_id`
# / `created_at` PASSES where a wrong-typed one REJECTS. They predate the join; they are
# declared here so this test fails on anything NEW, and `_raise_if_stale` makes it fail the
# day the class is fixed and the waiver should go.
_MASTER_KNOWN = {
    (("bundle_id",), "null", "MR-1", Severity.REJECT, Severity.PASS): (
        "pre-existing on master: null bundle_id passes where wrong_type rejects (NULL_CONTAINER_SCOPING, open)"
    ),
    (("created_at",), "null", "MR-1", Severity.REJECT, Severity.PASS): (
        "pre-existing on master: null created_at passes where wrong_type rejects (NULL_CONTAINER_SCOPING, open)"
    ),
}


def test_degradation_oracle_finds_nothing_new_with_the_join_deciding(tmp_path):
    counter = {"n": 0}

    def run(root):
        counter["n"] += 1
        return _verify(_write_manifest(tmp_path / f"b{counter['n']}", root))

    rep = probe_monotonicity(_MANIFEST, verdict_adapter(run), declared=_MASTER_KNOWN)
    assert not rep.quarantined, rep.quarantined
    assert not rep.vacuous
    assert rep.findings == [], "\n".join(str(f) for f in rep.findings)
    # `ok` is False whenever a declared limit was USED; the gate here is "nothing new".
    assert rep.counts["declared_limits"] == 2 and rep.counts["findings_tier1"] == 0
