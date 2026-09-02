"""Integration tests for examples/corner_load_equilibrium_minimal.

The pilot's claim is that a published set of four contact-patch loads can be
checked for physical admissibility by an auditor who never solves for them and
never sees the producer's suspension model. These tests hold that claim to its
two halves: the check must PASS a model operating in-distribution, and must
FAIL one that has left its training envelope -- while every byte of the failing
bundle is internally consistent.

NOTE ON LOCATION: this file lives in the ROOT tests/ directory, not in
examples/corner_load_equilibrium_minimal/tests/. pyproject sets
testpaths = ["tests"], so a battery under examples/ is never collected and a
green run would say nothing about it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
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


def _import_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_mod = _import_from_path(
    "corner_load_equilibrium_minimal._build_bundle", _PILOT_DIR / "_build_bundle.py"
)
# By NAME, so this is the same module object auditor_kit.py registers from.
import equilibrium_residual_recompute as _resid  # noqa: E402
import hard_negatives as _mining  # noqa: E402


def _run_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PILOT_DIR / "verify.py"), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("sl_clean")
    _build_mod.build(out, "clean")
    return out


@pytest.fixture(scope="module")
def drift_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("sl_drift")
    _build_mod.build(out, "drift")
    return out


# --------------------------------------------------------------------------
# The two halves of the claim
# --------------------------------------------------------------------------


def test_in_distribution_bundle_passes(clean_bundle: Path) -> None:
    result = _run_verify(clean_bundle)
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout


def test_out_of_distribution_bundle_fails_on_physics_alone(drift_bundle: Path) -> None:
    """The drift bundle is byte-perfect; only the physics is wrong."""
    manifest = json.loads((drift_bundle / "manifest.json").read_bytes())
    for rel, declared_sha in manifest["files"].items():
        actual = hashlib.sha256((drift_bundle / rel).read_bytes()).hexdigest()
        assert actual == declared_sha, f"{rel} is not internally consistent"

    result = _run_verify(drift_bundle)
    assert result.returncode == 1
    # RE_DERIVATION_MISMATCH, not REDERIVATION_MISMATCH: this pilot landed on
    # master while session/reason-code-collapse was in flight, and the two met
    # at the merge. The bare spelling is NOT a substring of the canonical one
    # (the underscore breaks it), so this assertion failed closed rather than
    # silently matching -- and tests/test_reason_code_emission_ratchet.py named
    # the file before the suite did.
    assert "RE_DERIVATION_MISMATCH" in result.stderr
    # All three conservation laws are broken, not just the cheapest one.
    for channel in ("vertical", "pitch", "roll"):
        assert f"corner_load_{channel}_residual" in result.stderr


# --------------------------------------------------------------------------
# Mutant control -- a green suite that cannot go red proves nothing
# --------------------------------------------------------------------------


def test_faulted_primitive_turns_the_clean_bundle_red(
    clean_bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If dispatch were inert, faulting the residual would change nothing."""
    from fractions import Fraction

    real = _resid.max_abs_residual

    def faulted(bundle_dir, channel, stats=None):
        worst, index = real(bundle_dir, channel, stats)
        return worst + Fraction(1000), index

    monkeypatch.setattr(_resid, "max_abs_residual", faulted)

    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.rederivation.spec_binding import SpecAnchor
    from audit_bundle.verifier import BundleVerifier

    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=SpecAnchor.from_files(
            [_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"],
            forbid_within=clean_bundle,
        ),
        require_rederivation=True,
    )
    result = verifier.verify(clean_bundle)
    assert not result.ok, "faulting the primitive left the verdict green -- dispatch is inert"


# --------------------------------------------------------------------------
# Tamper discipline
# --------------------------------------------------------------------------


def test_edited_loads_without_realigned_sha_fails(clean_bundle: Path, tmp_path) -> None:
    import shutil

    bundle = tmp_path / "tampered"
    shutil.copytree(clean_bundle, bundle)
    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_bytes())
    loads[0][0] = "9999.000000"
    loads_path.write_bytes(
        json.dumps(loads, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    result = _run_verify(bundle)
    assert result.returncode == 1
    assert "bad_file_sha" in result.stderr.lower()


def test_producer_supplied_weaker_spec_is_refused(clean_bundle: Path, tmp_path) -> None:
    """A producer who widens the epsilon in its own spec/ copy changes nothing:
    the anchor is derived from the auditor's committed bytes."""
    import shutil

    bundle = tmp_path / "weakened"
    shutil.copytree(clean_bundle, bundle)
    spec_path = bundle / "spec" / "corner_load_equilibrium.spec.json"
    spec = json.loads(spec_path.read_bytes())
    for binding in spec["types"].values():
        binding["comparator"]["params"]["epsilon"] = 1e9
    spec_path.write_bytes(json.dumps(spec, indent=2).encode("utf-8"))

    result = _run_verify(bundle)
    assert result.returncode == 1, "a weakened in-bundle spec was accepted"


# --------------------------------------------------------------------------
# The mining half
# --------------------------------------------------------------------------


def test_clean_trip_yields_no_hard_negatives(clean_bundle: Path) -> None:
    report = _mining.mine(clean_bundle)
    assert report["samples_violating"] == 0
    assert report["samples_examined"] > 0


def test_drift_trip_yields_negatives_concentrated_out_of_envelope(
    drift_bundle: Path,
) -> None:
    """The mining run must FIND the extrapolation boundary, not just count
    failures. Every negative should sit outside the trained |ay| range."""
    report = _mining.mine(drift_bundle)
    assert report["samples_violating"] > 0
    assert report["samples_violating"] < report["samples_examined"], (
        "every sample violating would mean the check is firing on everything"
    )
    trained_ay_limit = 4.0
    for negative in report["negatives"]:
        assert abs(float(negative["input_state"]["ay_mps2"])) > trained_ay_limit, (
            f"sample {negative['sample_index']} violates inside the trained "
            f"envelope -- the failure is not an extrapolation failure"
        )
    # Ranked worst-first so a retraining run can take the top-k.
    multiples = [n["worst_epsilon_multiple"] for n in report["negatives"]]
    assert multiples == sorted(multiples, reverse=True)


def test_negatives_are_bound_to_the_model_version(drift_bundle: Path) -> None:
    """A negative that cannot name the model build that produced it is not an
    auditable ledger entry."""
    report = _mining.mine(drift_bundle)
    produced_by = report["produced_by"]
    assert produced_by["bundle_id"]
    spec_bytes = (_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json").read_bytes()
    assert produced_by["anchored_spec_sha256"] == hashlib.sha256(spec_bytes).hexdigest()


# --------------------------------------------------------------------------
# The structural property the pilot exists to show
# --------------------------------------------------------------------------


def test_auditor_never_reads_the_suspension_model(clean_bundle: Path) -> None:
    """The check must not need the producer's IP. Deleting every suspension
    parameter from the committed vehicle spec must leave the verdict reachable
    -- it is the solver that needs them, not the checker."""
    import shutil

    bundle = clean_bundle.parent / "stripped"
    if bundle.exists():
        shutil.rmtree(bundle)
    shutil.copytree(clean_bundle, bundle)
    vehicle_path = bundle / "inputs" / "vehicle_spec.json"
    vehicle = json.loads(vehicle_path.read_bytes())
    rigid_body_only = {
        k: v
        for k, v in vehicle.items()
        if k
        in {
            "vehicle_id",
            "mass_kg",
            "gravity_mps2",
            "cg_to_front_axle_m",
            "cg_to_rear_axle_m",
            "track_width_m",
            "cg_height_m",
        }
    }
    assert len(rigid_body_only) < len(vehicle), "nothing was stripped"
    vehicle_path.write_bytes(
        json.dumps(rigid_body_only, indent=2, sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )
    )
    # The residual computation itself must still run to completion.
    for channel in (_resid.VERTICAL, _resid.PITCH, _resid.ROLL):
        worst, _ = _resid.max_abs_residual(bundle, channel)
        assert worst >= 0


def test_verifier_side_shares_no_code_with_the_producer() -> None:
    """Gate B: the check is a different computation, not a re-run of the
    producer's. If the auditor's module ever imports either producer module,
    the independence claim in the README is false."""
    source = (_PILOT_DIR / "equilibrium_residual_recompute.py").read_text()
    for forbidden in ("_producer_solve", "_producer_surrogate"):
        assert forbidden not in source


def test_producing_the_claim_costs_more_than_checking_it(tmp_path) -> None:
    """The asymmetry is reported as a measurement, so hold it to one. The two
    halves are measured on their OWN sides -- the producer cannot report the
    auditor's cost, because it must not import the auditor's module."""
    bundle = tmp_path / "cost"
    producer = _build_mod.build(bundle, "clean")
    auditor = _mining.audit_cost(bundle)
    assert producer["producer_ops"] > auditor["auditor_ops"]


def test_producer_does_not_import_the_verifier_module() -> None:
    """The sibling-tautology hazard, asserted directly. The claim written to
    outputs/ is a constant; if a later edit made it a MEASURED residual while
    this import existed, the pilot would become a function agreeing with
    itself."""
    source = (_PILOT_DIR / "_build_bundle.py").read_text()
    for forbidden in ("equilibrium_residual_recompute", "max_abs_residual"):
        assert f"import {forbidden}" not in source
        assert f"from {forbidden}" not in source


# --------------------------------------------------------------------------
# The admission gate -- mining must be an attribution, not a file read
# --------------------------------------------------------------------------
#
# A hard negative asserts that a MODEL published an inadmissible value. The
# miner originally read the bundle's files directly and never verified
# anything, so an edited payload produced ranked, stamped "negatives" that
# were really a statement about a text editor. These tests hold the gate to
# both directions: it must refuse what is not authentic, and it must still
# admit the bundle that fails on physics alone -- including one that violates
# a single channel, which is what most real drift looks like.

import auditor_entry as _entry  # noqa: E402


def _recohere(bundle: Path) -> None:
    """Re-emit manifest file hashes so the bundle is internally consistent.

    Models a producer that genuinely published these loads, as opposed to a
    third party editing a payload after emission. Without this a physics-only
    fixture would be indistinguishable from tampering -- which is the whole
    distinction under test.
    """
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for rel in manifest["files"]:
        manifest["files"][rel] = hashlib.sha256((bundle / rel).read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def _copy(bundle: Path, tmp_path: Path, name: str) -> Path:
    import shutil

    dest = tmp_path / name
    shutil.copytree(bundle, dest)
    return dest


def test_mining_refuses_a_payload_edited_after_emission(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The motivating case: forged loads must not become attributed negatives."""
    bundle = _copy(clean_bundle, tmp_path, "forged_payload")
    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_bytes())
    for row in loads[:60]:
        row[0] = f"{float(row[0]) + 900.0:.6f}"
    loads_path.write_text(json.dumps(loads, indent=2), encoding="utf-8")

    with pytest.raises(_entry.MiningRefused) as refusal:
        _mining.mine(bundle)
    assert "file_integrity" in str(refusal.value)


def test_the_refused_bundle_really_did_contain_minable_samples(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """Mutant control for the test above.

    A refusal proves nothing if the forged bundle had no violations in it to
    begin with. Compute the residuals directly -- bypassing the gate, which is
    the only place this is legitimate -- and confirm the samples the gate
    withheld are exactly the ones that would have been exported.
    """
    bundle = _copy(clean_bundle, tmp_path, "forged_control")
    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_bytes())
    for row in loads[:60]:
        row[0] = f"{float(row[0]) + 900.0:.6f}"
    loads_path.write_text(json.dumps(loads, indent=2), encoding="utf-8")

    epsilons = _mining._epsilons()
    violating = [
        index
        for index, _sample, _corners, residuals in _mining._per_sample_residuals(bundle)
        if any(abs(r) > epsilons[channel] for channel, r in residuals.items())
    ]
    assert len(violating) == 60, (
        "the forge did not produce violations, so the refusal above is vacuous"
    )


def test_mining_refuses_inputs_edited_after_emission(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """Not just the motivating file. Rewriting the vehicle mass moves every
    residual without touching a single published load -- an attacker's cheapest
    way to manufacture negatives against a model that did nothing wrong."""
    bundle = _copy(clean_bundle, tmp_path, "forged_inputs")
    vehicle_path = bundle / "inputs" / "vehicle_spec.json"
    vehicle = json.loads(vehicle_path.read_bytes())
    vehicle["mass_kg"] = str(float(vehicle["mass_kg"]) + 120.0)
    vehicle_path.write_text(
        json.dumps(vehicle, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(_entry.MiningRefused):
        _mining.mine(bundle)


def test_mining_refuses_when_the_output_declaration_is_deleted(
    drift_bundle: Path, tmp_path: Path
) -> None:
    """Deleting manifest.outputs makes dispatch inert in the general case. Here
    it trips the coverage check -- which is NOT a residual channel, so the
    deny-by-default allowlist refuses it rather than mining a bundle whose
    claims were never compared."""
    bundle = _copy(drift_bundle, tmp_path, "no_outputs")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest.pop("outputs", None)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(_entry.MiningRefused) as refusal:
        _mining.mine(bundle)
    assert "coverage" in str(refusal.value).lower()


def test_mining_admits_a_violation_on_a_single_channel(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The over-strictness direction, and it is the one that would quietly cost
    the most: most real drift breaks ONE conservation law, not all three. A
    gate that only admitted the shipped drift fixture (all three channels)
    would refuse the majority of genuine findings.

    Construct a load set that breaks vertical alone -- add F/2 to each front
    corner and R/2 to each rear with R = F*a/b, which leaves both moment
    balances exactly zero -- and re-cohere the manifest, so the bundle is a
    byte-honest publication that is physically inadmissible.
    """
    from fractions import Fraction

    bundle = _copy(clean_bundle, tmp_path, "single_channel")
    vehicle = json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    a = Fraction(vehicle["cg_to_front_axle_m"])
    b = Fraction(vehicle["cg_to_rear_axle_m"])
    front = Fraction(300) / (1 + a / b)
    rear = front * a / b

    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_bytes())
    for row in loads:
        for corner, delta in enumerate((front / 2, front / 2, rear / 2, rear / 2)):
            row[corner] = f"{float(Fraction(row[corner]) + delta):.6f}"
    loads_path.write_text(json.dumps(loads, indent=2), encoding="utf-8")
    _recohere(bundle)

    report = _mining.mine(bundle)
    assert report["samples_violating"] == report["samples_examined"] > 0
    channels = {
        v["channel"] for n in report["negatives"] for v in n["violations"]
    }
    assert channels == {_resid.VERTICAL}, (
        f"the fixture was meant to break vertical alone, broke {sorted(channels)}"
    )
    assert report["produced_by"]["verdict_state"] == "REJECT"


def test_negatives_carry_the_verdict_they_were_reached_under(
    drift_bundle: Path,
) -> None:
    """Provenance must come from the anchor that judged and the verdict it
    produced. A stamp the exporting tool can compute unaided -- the old
    sha256(<own spec copy>) -- is constant across every run and attests to the
    tool, not to any verdict."""
    produced_by = _mining.mine(drift_bundle)["produced_by"]
    assert produced_by["verdict_state"] == "REJECT"
    assert produced_by["spec_id"] == "corner_load.equilibrium.v1"
    assert produced_by["anchored_specs"], "no anchored spec recorded"
    admitted = {r["check_name"] for r in produced_by["admitted_reasons"]}
    for channel in ("vertical", "pitch", "roll"):
        assert f"spec_pinned_dispatch:corner_load_{channel}_residual" in admitted


def test_clean_bundle_mines_under_an_ok_verdict(clean_bundle: Path) -> None:
    """An empty export is a result, not an error -- but it must be reached
    through the gate, so the verdict it was reached under is on the record."""
    report = _mining.mine(clean_bundle)
    assert report["samples_violating"] == 0
    assert report["produced_by"]["verdict_state"] == "OK"


def test_the_miner_and_the_verifier_share_one_anchored_constructor() -> None:
    """Anti-drift. The defect was two auditor-side tools with unrelated
    verification postures; a second BundleVerifier or SpecAnchor built inside
    either tool is that split reappearing, and a hardening applied to one would
    not reach the other."""
    for name in ("hard_negatives.py", "verify.py"):
        source = (_PILOT_DIR / name).read_text()
        for forbidden in ("BundleVerifier(", "SpecAnchor("):
            assert forbidden not in source, (
                f"{name} constructs its own {forbidden.rstrip('(')} -- both tools "
                f"must go through auditor_entry.build_verifier"
            )
        assert "auditor_entry" in source


def test_unusable_auditor_inputs_are_could_not_conclude_not_a_traceback() -> None:
    """Pointing --bundle-dir at the pilot root puts BOTH auditor inputs inside
    the directory under audit: the kit and the anchored spec. Refusing them is
    the guard working -- but it happens before any verdict exists, so it is an
    operator error, not a finding about an artifact, and it belongs in the same
    could-not-conclude lane as every other one.

    Until 2026-08-31 it surfaced as an uncaught KitConstructionError traceback
    exiting 1: the tri-state landing routed `result` correctly and left the
    branch that never produces a `result` at all. build_verifier still RAISES --
    admit_for_mining is its other caller and maps the same condition to
    MiningRefused."""
    result = _run_verify(_PILOT_DIR)
    assert result.returncode == 2, (
        f"unusable auditor inputs exited {result.returncode}; "
        "an operator error must not read as a verdict about a bundle"
    )
    assert "could not conclude" in (result.stdout + result.stderr).lower()
    assert "AUDITOR_INPUTS_UNUSABLE" in result.stderr
    assert "Traceback" not in result.stderr
