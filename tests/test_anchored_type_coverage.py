"""The anchored-spec-type coverage channel, and the accounting engine under it.

THE DEFECT, measured 2026-08-31 on `corner_load_equilibrium_minimal`:

  A producer's only remaining degree of freedom under spec-pinned dispatch is
  WHICH ROW of the auditor's binding table judges each claim. `manifest.json`
  is not hash-covered (`integrity_ownership.py`: "parse-validated but
  byte-integrity-owned by nobody"), so retyping one output costs a single
  string edit and no re-hashing. Retype the vertical-equilibrium residual as
  the ROLL residual and the ε=40 N vertical rule runs zero times, while the
  roll rule — which a uniform +N offset on all four corners leaves untouched —
  passes. Exit 0 on a bundle whose vertical residual is 60.5 N.

  `verifier.py` already carries nine `_step_*_guard` methods, seven of which
  hand-write `present − verified; if uncovered: could-not-conclude` for other
  channels. Anchored spec types is the channel nobody wrote the tenth copy for.

These tests hold the fix to four things, in this order:

  1. it FIRES on the exploit (measured red against the pre-fix tree);
  2. it does NOT fire on an honest bundle, here or anywhere in the fleet —
     a guard that also reddens honest bundles is worse than the hole;
  3. deleting the registration brings the exploit BACK (the mutant control:
     without it, a green run cannot distinguish a working guard from a dead
     one — `the internal design notes`);
  4. the accounting is keyed on the AUTHORITY's set, not the producer's
     declaration — the inertness shape that made `manifest.outputs` deletion
     fail open.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "corner_load_equilibrium_minimal"

for _p in (_PKG_ROOT, _PILOT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from audit_bundle.coverage_channels import (  # noqa: E402
    CoverageChannel,
    account_channels,
)


def _import_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_mod = _import_from_path(
    "corner_load_type_coverage._build_bundle", _PILOT_DIR / "_build_bundle.py"
)

# Exit codes, spelled once. 0 PASS / 1 FAIL (concluded against the artifact) /
# 2 ERROR (could not conclude). A coverage remainder is ALWAYS 2: it is a
# statement about what the verifier covered, never an accusation.
PASS, FAIL, COULD_NOT_CONCLUDE = 0, 1, 2


def _run_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(_PILOT_DIR / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _verify_lib(bundle_dir: Path, *, work_set=None):
    """A library verifier over the same anchored authority as the pilot, with
    the auditor's WORK-SET optional.

    Two configurations have to be tested separately and they are easy to
    conflate. WITHOUT a work-set is the fleet-generic case: the anchored-type
    coverage channel is the FALLBACK, the only thing standing between a retyped
    output and a green verdict, and its refusal must be a could-not-conclude.
    WITH one — what `examples/corner_load_equilibrium_minimal/verify.py` ships —
    the retype is refused earlier and harder, as a REJECT, before any recompute
    runs. Asserting only the pilot's behaviour would leave the generic path
    untested on every other bundle in the fleet, which is where the channel
    does its work.
    """
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.rederivation.kit import load_primitive_kit
    from audit_bundle.rederivation.spec_binding import SpecAnchor
    from audit_bundle.verifier import BundleVerifier

    load_primitive_kit([_PILOT_DIR / "auditor_kit.py"], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=SpecAnchor.from_files(
            [_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"],
            forbid_within=bundle_dir,
        ),
        require_rederivation=True,
        work_set=work_set,
    ).verify(bundle_dir)


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("atc_clean")
    _build_mod.build(out, "clean")
    return out


def _offset_every_corner(bundle: Path, newtons: float) -> None:
    """Add `newtons` to all four corners of every sample, then re-cohere the
    manifest SHA exactly as an honest producer would after a legitimate edit.

    A uniform offset moves the VERTICAL sum by 4N and leaves the roll
    DIFFERENCE (FR+RR−FL−RL) and the pitch difference identically unchanged —
    which is what makes the sibling type a viable place to hide.
    """
    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_text())
    loads_path.write_text(
        json.dumps([[str(float(x) + newtons) for x in row] for row in loads], indent=2)
    )
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["payload/corner_loads.json"] = hashlib.sha256(
        loads_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def _retype(bundle: Path, output_id: str, new_type: str) -> None:
    """The whole attack: one string, no re-hashing (manifest.json is owned by
    nobody's hash)."""
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    hit = False
    for entry in manifest["outputs"]:
        if entry["output_id"] == output_id:
            entry["type"] = new_type
            hit = True
    assert hit, f"no output {output_id!r} to retype — the fixture drifted"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


# --------------------------------------------------------------------------
# 1. The exploit, and the guard that must catch it
# --------------------------------------------------------------------------


def test_the_tamper_alone_is_caught(clean_bundle: Path, tmp_path) -> None:
    """Control for the attack: WITHOUT the retype, the vertical rule catches it.

    Without this, a passing test in this file could be measuring a bundle that
    was never violating in the first place.
    """
    bundle = tmp_path / "tampered_only"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "corner_load_vertical_residual" in (result.stdout + result.stderr)
    assert "RE_DERIVATION_MISMATCH" in (result.stdout + result.stderr)


def test_retyping_an_output_onto_a_sibling_rule_cannot_pass(
    clean_bundle: Path, tmp_path
) -> None:
    """THE FIRING TEST. Measured red (exit 0, "PASS") before the channel existed.

    The bundle is +15 N on every corner and declares its vertical residual as a
    ROLL residual. The roll rule passes it. The vertical rule — the one the
    auditor wrote for this claim — never runs. The accounting channel notices
    that `corner_load_vertical_residual` is named by the anchored spec and was
    reached by nothing, and refuses to conclude.
    """
    bundle = tmp_path / "retyped"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)
    _retype(bundle, "corner_load_vertical_residual", "corner_load_roll_residual")

    verdict = _verify_lib(bundle)
    assert not verdict.ok, (
        "a bundle whose vertical residual is 60.5 N against an auditor epsilon "
        "of 40 N verified GREEN by retyping one string"
    )
    reasons = [(r.check_name, r.code) for r in verdict.reasons]
    assert ("anchored_spec_types", "VERIFIER_INCOMPLETE") in reasons, reasons

    # And through the pilot's shipped entry point, which ALSO pins output_id ->
    # type: the same edit is refused earlier, as a REJECT.
    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "ROLE_POLICY_VIOLATION" in (result.stdout + result.stderr)


def test_the_remainder_is_could_not_conclude_not_a_reject(
    clean_bundle: Path, tmp_path
) -> None:
    """A coverage remainder is a statement about the VERIFIER's coverage.

    Exit 2, not 1: the verifier is saying "a rule the authority names was never
    applied", which establishes nothing against the artifact. Collapsing this
    into a REJECT would make an honest bundle verified by an under-configured
    auditor indistinguishable from a forged one (ADR BI-1 tri-state).
    """
    bundle = tmp_path / "retyped_state"
    shutil.copytree(clean_bundle, bundle)
    _retype(bundle, "corner_load_vertical_residual", "corner_load_roll_residual")

    # No work-set: the coverage channel is the only thing that notices, and
    # what it establishes is that a rule went unapplied — not that the artifact
    # is bad. ERROR, never REJECT.
    verdict = _verify_lib(bundle)
    assert verdict.state.value == "ERROR", verdict.state
    assert verdict.error_kind.value == "INCOMPLETE", verdict.error_kind
    assert [r.code for r in verdict.reasons] == ["VERIFIER_INCOMPLETE"]


def test_the_refusal_names_the_type_that_was_skipped(
    clean_bundle: Path, tmp_path
) -> None:
    """A count alone is what lets a remapped type read as a rounding error.

    The detail must name the uncovered member, and must NOT name the ones that
    were covered — a refusal that lists the whole table tells the operator
    nothing about where to look.
    """
    bundle = tmp_path / "retyped_detail"
    shutil.copytree(clean_bundle, bundle)
    _retype(bundle, "corner_load_vertical_residual", "corner_load_roll_residual")

    detail = next(
        r.detail
        for r in _verify_lib(bundle).reasons
        if r.check_name == "anchored_spec_types"
    )
    assert "corner_load_vertical_residual" in detail
    assert "corner_load_pitch_residual" not in detail, (
        "the refusal named a type that WAS covered: " + detail
    )


# --------------------------------------------------------------------------
# 2. The negative control — the honest bundle must be untouched
# --------------------------------------------------------------------------


def test_the_honest_bundle_still_passes(clean_bundle: Path) -> None:
    """A guard that also reddens honest bundles is worse than the hole."""
    result = _run_verify(clean_bundle)
    assert result.returncode == PASS, result.stdout + result.stderr


def test_an_honest_violation_still_reads_as_a_reject(
    clean_bundle: Path, tmp_path
) -> None:
    """Coverage accounting must not swallow a genuine physics FAIL into an ERROR.

    The drift bundle re-derives every anchored channel — the accounting is
    satisfied — and one of them disagrees. That is a REJECT (exit 1), and it is
    what the mining gate is allowed to export.
    """
    bundle = tmp_path / "honest_fail"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "anchored_spec_types" not in (result.stdout + result.stderr)


# --------------------------------------------------------------------------
# 3. The mutant control — the guard must be able to fail
# --------------------------------------------------------------------------


def test_without_the_registration_the_exploit_returns(
    clean_bundle: Path, tmp_path, monkeypatch
) -> None:
    """MUTANT CONTROL. Neutralise `account_channels` and the retyped bundle goes
    green again.

    Once the channel exists, every other test in this file passes whether the
    accounting is live or dead — a fix disarms the evidence that it works. This
    is the only test here that would notice the engine being replaced by a
    no-op, so it is the one that keeps the rest honest.
    """
    from audit_bundle import verifier as verifier_mod
    from audit_bundle.rederivation.spec_binding import SpecAnchor

    bundle = tmp_path / "mutant"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)
    _retype(bundle, "corner_load_vertical_residual", "corner_load_roll_residual")

    def _build() -> verifier_mod.BundleVerifier:
        from audit_bundle.plugins.file_integrity_many_small import (
            FileIntegrityManySmall,
        )
        from audit_bundle.rederivation.kit import load_primitive_kit

        load_primitive_kit([_PILOT_DIR / "auditor_kit.py"], forbid_within=bundle)
        return verifier_mod.BundleVerifier(
            plugins=[FileIntegrityManySmall()],
            spec_anchor=SpecAnchor.from_files(
                [_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"],
                forbid_within=bundle,
            ),
            require_rederivation=True,
        )

    live = _build().verify(bundle)
    assert not live.ok, "the channel did not fire on the retyped bundle"

    monkeypatch.setattr(verifier_mod, "account_channels", lambda channels, out: None)
    dead = _build().verify(bundle)
    assert dead.ok, (
        "the retyped bundle was still refused with the accounting engine "
        "neutralised — something ELSE is catching it, so these tests are not "
        "measuring this channel. Find what, before trusting any of them."
    )


# --------------------------------------------------------------------------
# 4. The engine's own contract
# --------------------------------------------------------------------------


def test_an_empty_authority_is_inert() -> None:
    """`present` empty == no authority was established == nothing to account for.

    This is the ONLY inertness the engine grants, and it is keyed on the
    AUTHORITY. Inertness keyed on the producer's declaration being empty is the
    exact shape that made `manifest.outputs` deletion fail open.
    """
    out: list = []
    account_channels([CoverageChannel("empty", frozenset(), frozenset())], out)
    assert out == []


def test_a_verified_set_larger_than_present_does_not_launder() -> None:
    """A check reporting coverage of something the authority never named is not
    evidence about the members it DID name."""
    out: list = []
    account_channels(
        [CoverageChannel("x", frozenset({"a", "b"}), frozenset({"a", "z", "q"}))],
        out,
    )
    assert len(out) == 1
    assert "'b'" in out[0].reasons[0].detail
    assert "'z'" not in out[0].reasons[0].detail


def test_full_coverage_appends_nothing() -> None:
    out: list = []
    account_channels(
        [CoverageChannel("x", frozenset({"a", "b"}), frozenset({"a", "b"}))], out
    )
    assert out == []


def test_the_detail_formatter_never_raises_on_a_hostile_member() -> None:
    """§C9: an error formatter that raises converts a fail-closed refusal into a
    crash. `sorted()` over mixed types raises TypeError; a member's own
    `__str__` is never consulted."""

    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("boom")

        def __repr__(self) -> str:
            return "<hostile>"

        def __hash__(self) -> int:
            return 7

        def __eq__(self, other) -> bool:
            return self is other

    channel = CoverageChannel("x", frozenset({"a", 3, Hostile()}), frozenset())
    detail = channel.detail()
    assert "<hostile>" in detail
    assert "3" in detail


def test_channel_reports_under_its_own_check_name() -> None:
    out: list = []
    account_channels(
        [CoverageChannel("my_channel", frozenset({"a"}), frozenset())], out
    )
    assert out[0].reasons[0].check_name == "my_channel"
    assert out[0].reasons[0].code == "VERIFIER_INCOMPLETE"


# --------------------------------------------------------------------------
# 5. SELECTION, the whole class — coverage accounting is the FALLBACK, not the
#    mechanism
# --------------------------------------------------------------------------
#
# The type channel asks whether every anchored rule was EXERCISED. It cannot ask
# BY WHICH CLAIM, and the gap is reachable: MEASURED 2026-09-01, with the
# channel live, a decoy output that exercises the vertical type honestly
# restored the exit-0 forgery. What closes the whole class is the auditor's
# WORK-SET (`audit_bundle/work_set.py`): the complete multiset of output_ids the
# bundle must deliver, each pinned to its type, checked as an exact bijection.
# Its own battery is `tests/test_work_set.py`; the cells here pin the CHANNEL's
# scope beside it, so the fallback is never mistaken for the mechanism.


def _plant_decoy(bundle: Path, output_id: str, type_key: str, value: float) -> None:
    """Declare an EXTRA output that exercises `type_key` with a value that will
    re-derive correctly, so the accounting is satisfied by a claim nobody asked
    for."""
    claim = bundle / "outputs" / f"{output_id}.json"
    claim.write_bytes(json.dumps({"value": value}, indent=2).encode())
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"][f"outputs/{output_id}.json"] = hashlib.sha256(
        claim.read_bytes()
    ).hexdigest()
    manifest["outputs"].append(
        {
            "conforms_to": "spec/corner_load_equilibrium.spec.json",
            "output_id": output_id,
            "type": type_key,
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def _drop_output(bundle: Path, output_id: str) -> None:
    (bundle / "outputs" / f"{output_id}.json").unlink()
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    del manifest["files"][f"outputs/{output_id}.json"]
    manifest["outputs"] = [
        e for e in manifest["outputs"] if e["output_id"] != output_id
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def _corner_work_set():
    from audit_bundle.work_set import WorkSet

    return WorkSet.declare(
        {
            "corner_load_vertical_residual": "corner_load_vertical_residual",
            "corner_load_pitch_residual": "corner_load_pitch_residual",
            "corner_load_roll_residual": "corner_load_roll_residual",
            # Channel 4, added 2026-09-03: the front/rear transfer split. Named
            # here because a work-set must cover the anchored spec's type keys
            # COMPLETELY -- a type the spec defines and the set omits is a
            # delivered-but-not-named violation, which is what this cell
            # reported when the channel landed.
            "corner_load_transfer_split_residual": "corner_load_transfer_split_residual",
        },
        source="test: the corner_load channels -- three residuals plus the transfer split",
        provenance="SELF_AUTHORED",
    )


# The true vertical residual of a uniformly +15 N payload, which is what makes
# the decoy re-derive cleanly. Pinned so a fixture change that moved it would
# fail loudly here instead of quietly turning the attack into a no-op.
_TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N = 60.501022


def test_coverage_accounting_alone_is_bypassed_by_a_decoy(
    clean_bundle: Path, tmp_path
) -> None:
    """THE STATED LIMIT OF THE CHANNEL, executed rather than argued.

    Retype the real claim onto the roll rule AND declare a decoy that exercises
    the vertical rule honestly. `present - verified` is empty, so the channel
    is silent — and it is RIGHT to be silent, because every anchored rule did
    run. The question it cannot ask is which claim each rule judged.

    This cell pins the CHANNEL's scope: it asserts the channel is SILENT here,
    and nothing more. It deliberately does NOT assert the bundle passes.

    An earlier version did, and that was a ratchet against ever fixing the hole:
    102 of 107 pilots run this exact no-work-set configuration, so
    `assert verdict.ok` would have made "a forged bundle verifies green in the
    fleet-generic configuration" a green-suite invariant. Any future generic
    closure would have turned this red with a message telling the next engineer
    their fix broke a documented scope limit. The scope limit belongs on the
    channel, not on the verdict.
    """
    bundle = tmp_path / "decoy_vs_channel"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)
    _retype(bundle, "corner_load_vertical_residual", "corner_load_roll_residual")
    _plant_decoy(
        bundle,
        "decoy_vertical",
        "corner_load_vertical_residual",
        _TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N,
    )

    verdict = _verify_lib(bundle)  # no work-set: the fallback alone
    assert not any(r.check_name == "anchored_spec_types" for r in verdict.reasons), (
        "the coverage channel fired on a bundle where every anchored type WAS "
        "exercised — its documented scope no longer matches its behaviour"
    )
    if verdict.ok:
        return  # the scope limit is live, exactly as documented
    # Something ELSE now refuses this bundle. That is an IMPROVEMENT, not a
    # regression — record what closed it rather than failing, so this cell can
    # never be read as a reason to revert a fix.
    print(
        "NOTE: the remap+decoy bundle is now refused by "
        + repr([(r.check_name, r.code) for r in verdict.reasons])
        + " — the type channel is still (correctly) silent. Update the "
        "fallback paragraph in _step_anchored_type_coverage_guard to say so."
    )


def test_the_work_set_closes_what_the_decoy_reopened(
    clean_bundle: Path, tmp_path
) -> None:
    """The same bundle, through the pilot's shipped verifier. The auditor's
    work-set pins output_id -> type, so the retype is refused before any
    recompute — and the decoy is itself an output nobody named."""
    bundle = tmp_path / "decoy_vs_work_set"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)
    _retype(bundle, "corner_load_vertical_residual", "corner_load_roll_residual")
    _plant_decoy(
        bundle,
        "decoy_vertical",
        "corner_load_vertical_residual",
        _TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N,
    )

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "ROLE_POLICY_VIOLATION" in (result.stdout + result.stderr)
    assert "WORK_SET_VIOLATION" in (result.stdout + result.stderr)
    assert "corner_load_vertical_residual" in (result.stdout + result.stderr)


def test_dropping_a_pinned_claim_is_a_work_set_reject(
    clean_bundle: Path, tmp_path
) -> None:
    """THE OMISSION TWIN. A per-output pin is only consulted for outputs the
    producer DECLARES, so deleting the pinned claim skips its pin entirely.
    Drop the vertical output and substitute an honestly-valued decoy under a
    different output_id: the pin is silent, type coverage is satisfied, and
    the claim the auditor asked for is gone.

    The work-set's bijection is what notices — as a REJECT, because a named
    claim the bundle did not deliver is the artifact's failure. (This used to
    be a could-not-conclude on the retired `role_policy_roster` channel.)
    """
    bundle = tmp_path / "dropped_claim"
    shutil.copytree(clean_bundle, bundle)
    _offset_every_corner(bundle, 15.0)
    _drop_output(bundle, "corner_load_vertical_residual")
    _plant_decoy(
        bundle,
        "decoy_vertical",
        "corner_load_vertical_residual",
        _TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N,
    )

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "WORK_SET_VIOLATION" in (result.stdout + result.stderr)
    assert "corner_load_vertical_residual" in (result.stdout + result.stderr)


def test_the_fallback_alone_sees_the_dropped_claim_only_as_an_unexercised_rule(
    clean_bundle: Path, tmp_path
) -> None:
    """A verifier holding no work-set has named no roster, so nothing can
    refuse the omission as such — the TYPE channel still fires (the dropped
    claim left its rule unapplied), which is the fallback doing all it can,
    and the face says selection was the producer's."""
    bundle = tmp_path / "no_work_set_drop"
    shutil.copytree(clean_bundle, bundle)
    _drop_output(bundle, "corner_load_vertical_residual")

    verdict = _verify_lib(bundle)  # no work-set
    assert not any(r.code == "WORK_SET_VIOLATION" for r in verdict.reasons)
    assert any(r.check_name == "anchored_spec_types" for r in verdict.reasons)


def test_every_verdict_says_whether_selection_was_pinned(clean_bundle: Path) -> None:
    """Silence about a residual reads as closure. A green verdict must state
    whether WHICH-claims-and-WHICH-rule was the auditor's call or the
    producer's — and name the fallback in the unconfigured case."""
    with_set = _verify_lib(clean_bundle, work_set=_corner_work_set())
    without = _verify_lib(clean_bundle)
    assert with_set.ok and without.ok

    applied = [d for d in with_set.completeness.disclosures if "type_selection" in d]
    absent = [d for d in without.completeness.disclosures if "type_selection" in d]
    assert len(applied) == 1 and "WORK-SET APPLIED" in applied[0], applied
    assert len(absent) == 1 and "NO auditor work-set" in absent[0], absent
    assert "anchored_spec_types" in absent[0]
