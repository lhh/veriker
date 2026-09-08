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
    # The front door is the shipped CLI, prefilled (2026-09-06); the CLI
    # prints its verdict rows on stdout, so assert on the combined stream.
    combined = result.stdout + result.stderr
    assert "RE_DERIVATION_MISMATCH" in combined
    # All three conservation laws are broken, not just the cheapest one.
    for channel in ("vertical", "pitch", "roll"):
        assert f"corner_load_{channel}_residual" in combined


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
    assert not result.ok, (
        "faulting the primitive left the verdict green -- dispatch is inert"
    )


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
    assert "bad_file_sha" in (result.stdout + result.stderr).lower()


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


def test_consistent_tamper_of_loads_and_mass_is_rejected(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The consistent-tamper witness (MEASURED 2026-09-02).

    Inflate all four published corner loads AND the vehicle mass by the same
    10% factor, then re-cohere the manifest so every SHA matches. Nothing in
    equilibrium_residual_recompute.py's three residuals can tell this bundle
    from an honest one: scaling both sides of `sum(loads) - m*g` (and the two
    moment balances, which also carry an `m*...*h` term) by one constant
    leaves every residual inside epsilon. Byte integrity is preserved on
    purpose -- the point is that FORGERY discipline alone cannot explain a
    REJECT here; only a verifier-held anchor on the vehicle spec bytes can.
    """
    from decimal import Decimal

    bundle = _copy(clean_bundle, tmp_path, "consistent_tamper")
    vehicle_path = bundle / "inputs" / "vehicle_spec.json"
    vehicle = json.loads(vehicle_path.read_bytes())
    assert vehicle["mass_kg"] == "1850", vehicle["mass_kg"]
    vehicle["mass_kg"] = "2035.00"
    vehicle_path.write_text(
        json.dumps(vehicle, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_bytes())
    scale = Decimal("1.10")
    for row in loads:
        for i, value in enumerate(row):
            row[i] = str((Decimal(value) * scale).quantize(Decimal("0.000001")))
    loads_path.write_text(
        json.dumps(loads, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    _recohere(bundle)

    result = _run_verify(bundle)
    assert result.returncode != 0, (
        "a consistent 10% inflation of every corner load AND the vehicle "
        "mass verified PASS -- the equilibrium residual is scale-invariant "
        "under this tamper, and byte integrity alone cannot catch it"
    )


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
    spec_bytes = (
        _PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"
    ).read_bytes()
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
        json.dumps(
            rigid_body_only, indent=2, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
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
    channels = {v["channel"] for n in report["negatives"] for v in n["violations"]}
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


def test_pointing_the_front_door_at_the_pilot_root_is_refused_without_a_traceback() -> None:
    """Pointing --bundle-dir at the pilot root used to reach the auditor-input
    containment guard first (kit and spec inside the directory under audit)
    and exit 2 as AUDITOR_INPUTS_UNUSABLE. Through the shipped CLI (the front
    door since 2026-09-06) the same directory is refused one step earlier, at
    manifest admission: it is not a bundle at all. That is the CLI's
    not-a-bundle refusal -- MANIFEST_MISSING, exit 1 -- and it is a refusal
    of the artifact, not a traceback. The containment guard itself is now
    unreachable from this front door (its anchor and kit paths are prefilled
    constants outside any bundle) and is covered where it lives:
    tests/test_cli_spec_anchor.py drives the CLI's own refusal."""
    result = _run_verify(_PILOT_DIR)
    assert result.returncode == 1, (
        f"a non-bundle directory exited {result.returncode}; the CLI refuses "
        "it at manifest admission with MANIFEST_MISSING (exit 1)"
    )
    assert "manifest.json" in (result.stdout + result.stderr)
    assert "Traceback" not in result.stderr


def test_coordinated_trip_and_load_forgery_is_refused(clean_bundle: Path, tmp_path: Path) -> None:
    """Was `..._still_passes`, asserting the UNDESIRABLE behaviour on purpose.

    It carried instructions to flip it if anyone closed the hole. Channel 4
    closed it, so it is flipped, and the history is kept here rather than
    rewritten: before the transfer-split channel this forgery returned PASS,
    exit 0 -- zero load on both front wheels, with `ax` solved to 27.1 m/s^2 to
    null pitch and `ay` set to 0 to null roll.

    Note WHICH refusal this is. Driving `ay` to zero to null the roll channel
    also drives the total lateral transfer to zero, so no sample clears the
    transfer floor and the split channel has nothing to evaluate. It refuses on
    that ground -- COULD NOT CONCLUDE -- rather than on a physics disagreement.
    That is the correct outcome and it is a different statement from the 450 N
    diagonal case, which the channel refuses because the split genuinely
    disagrees with the calibration. A verifier that returned a clean PASS
    because it had nothing to check is the vacuity this pilot keeps finding.
    """
    import shutil
    from fractions import Fraction
    from decimal import Decimal

    bundle = tmp_path / "forged"
    shutil.copytree(clean_bundle, bundle)

    vehicle = json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    m = Fraction(str(vehicle["mass_kg"]))
    g = Fraction(str(vehicle["gravity_mps2"]))
    a = Fraction(str(vehicle["cg_to_front_axle_m"]))
    b = Fraction(str(vehicle["cg_to_rear_axle_m"]))
    t = Fraction(str(vehicle["track_width_m"]))
    h = Fraction(str(vehicle["cg_height_m"]))
    weight = m * g

    def dec(x: Fraction) -> str:
        return str(Decimal(x.numerator) / Decimal(x.denominator))

    samples = json.loads((bundle / "inputs" / "trip_samples.json").read_bytes())
    fl = fr = Fraction(0)
    rl = rr = weight / 2
    ax = -((fl + fr) * a - (rl + rr) * b) / (m * h)
    ay = ((fr + rr - fl - rl) * (t / 2)) / (m * h)

    (bundle / "payload" / "corner_loads.json").write_text(
        json.dumps([[dec(fl), dec(fr), dec(rl), dec(rr)] for _ in samples], indent=2)
    )
    (bundle / "inputs" / "trip_samples.json").write_text(
        json.dumps([dict(s, ax_mps2=dec(ax), ay_mps2=dec(ay)) for s in samples], indent=2)
    )

    vehicle_sha = _resid.TRUSTED_RIGID_BODY_SPEC_SHA256
    assert vehicle_sha == _resid._rigid_body_digest(
        json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    ), "the forgery must leave the pinned rigid-body fields untouched"

    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        path = bundle / rel
        if path.exists():
            manifest["files"][rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )

    result = _run_verify(bundle)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        "zero load on both front wheels verified clean:\n" + combined[-2500:]
    )
    assert "transfer_split" in combined, (
        "refused, but not by the split channel -- this test would then no longer "
        "be about the hole it was written for:\n" + combined[-2500:]
    )


def test_a_diagonal_shift_is_refused_as_a_disagreement_not_a_vacuity(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The other half of the pair: a forgery the channel refuses on the physics.

    A 450 N cross-weight shift leaves the trip untouched, so every gated sample
    still carries the check and the refusal is a genuine disagreement with the
    calibration -- not the could-not-conclude refusal the zero-|ay| forgery
    earns. Keeping both means neither reason code can quietly become the other.
    """
    import shutil

    bundle = tmp_path / "diagonal"
    shutil.copytree(clean_bundle, bundle)
    _diagonal_forgery(bundle, "450")

    assert _resid.gated_sample_count(bundle) > 0, (
        "fixture no longer exercises the channel: nothing cleared the transfer floor"
    )
    result = _run_verify(bundle)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, combined[-2500:]
    assert "RE_DERIVATION_MISMATCH" in combined and "transfer_split" in combined, (
        "expected a split DISAGREEMENT, got something else:\n" + combined[-2500:]
    )

def _diagonal_forgery(bundle: Path, shift: str) -> None:
    """Shift load along the diagonal: +d front-left, -d front-right, -d
    rear-left, +d rear-right. That vector is in the EXACT null space of all
    three equilibrium channels -- the sum is preserved, the pitch couple is
    preserved, and the total lateral transfer is preserved -- so no residual
    moves however large `d` grows. It is the cross-weight mode, the one degree
    of freedom three rigid-body equations cannot reach."""
    from decimal import Decimal

    d = Decimal(shift)
    loads_path = bundle / "payload" / "corner_loads.json"
    rows = json.loads(loads_path.read_bytes())
    forged = [
        [
            str(Decimal(fl) + d),
            str(Decimal(fr) - d),
            str(Decimal(rl) - d),
            str(Decimal(rr) + d),
        ]
        for fl, fr, rl, rr in rows
    ]
    loads_path.write_text(json.dumps(forged, indent=2, ensure_ascii=False))
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        p = bundle / rel
        if p.exists():
            manifest["files"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )


def test_a_negative_corner_load_is_refused(clean_bundle: Path, tmp_path: Path) -> None:
    """A wheel cannot pull the car toward the road.

    Needs nothing from the producer's physics -- it is the sign convention, not
    a suspension model -- so it costs none of this pilot's "no producer IP"
    property. MEASURED 2026-09-03 before this check existed: a diagonal shift of
    8000 N drove two corners to roughly -3260 N and -3900 N and still returned
    PASS, exit 0, with the vehicle spec and trip samples both byte-identical.
    """
    import shutil

    bundle = tmp_path / "negative_loads"
    shutil.copytree(clean_bundle, bundle)
    _diagonal_forgery(bundle, "8000")

    rows = json.loads((bundle / "payload" / "corner_loads.json").read_bytes())
    from decimal import Decimal

    assert min(Decimal(v) for row in rows for v in row) < 0, "fixture grew no negative load"

    result = _run_verify(bundle)
    assert result.returncode != 0, (
        "a claim placing NEGATIVE load on a wheel verified clean:\n"
        + (result.stdout + result.stderr)[-2000:]
    )


def test_stripping_the_suspension_model_does_not_trip_the_pin(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The pin must cover what the auditor READS, and nothing more.

    `equilibrium_residual_recompute` advertises that it reads no suspension or
    tire parameters -- that is the pilot's whole "a partner who will not share
    their physics" claim, and `test_auditor_never_reads_the_suspension_model`
    enforces it. A pin over the WHOLE vehicle_spec.json contradicts that: it
    makes the auditor's verdict depend on producer model parameters it is
    designed never to look at. Those fields are in the file because
    `_producer_solve.py` needs them, not because the auditor does.

    So stripping every suspension field must leave the pin satisfied. Without
    this, the two properties can only coexist via a monkeypatch in the test
    that noticed the collision.
    """
    import shutil

    bundle = tmp_path / "stripped_spec"
    shutil.copytree(clean_bundle, bundle)
    spec_path = bundle / "inputs" / "vehicle_spec.json"
    vehicle = json.loads(spec_path.read_bytes())
    rigid_only = {
        k: v
        for k, v in vehicle.items()
        if "roll_stiffness" not in k and "sprung" not in k
    }
    assert len(rigid_only) < len(vehicle), "nothing was stripped"
    spec_path.write_text(
        json.dumps(rigid_only, indent=2, sort_keys=True, ensure_ascii=False)
    )
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    manifest["files"]["inputs/vehicle_spec.json"] = hashlib.sha256(
        spec_path.read_bytes()
    ).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )

    result = _run_verify(bundle)
    combined = result.stdout + result.stderr  # the pin message lands on stderr
    assert "does not match the verifier-pinned" not in combined, (
        "the pin fired on suspension fields the auditor never reads:\n"
        + combined[-2000:]
    )
    assert result.returncode == 0, (
        "stripping the suspension model must leave a reachable, clean verdict -- "
        "that is what 'the auditor never reads the suspension model' means:\n"
        + combined[-2000:]
    )


# --------------------------------------------------------------------------
# Channel 4 -- the front/rear split of lateral load transfer
# --------------------------------------------------------------------------


def _republish_with_mislearned_split(bundle: Path, chi_0: str) -> None:
    """Re-solve the trip with a DIFFERENT front roll-stiffness fraction and
    publish the result.

    This is not a tamper. Every load it publishes is the exact output of a
    consistent rigid-body solve, so all three equilibrium residuals stay at
    machine zero -- it is what a surrogate that mis-learned the one quantity
    the expensive solve exists to compute would actually emit. Importing the
    producer's solver is legitimate HERE (a test may look at both sides); the
    auditor module may not, and `test_verifier_side_shares_no_code_with_the_
    producer` enforces that.
    """
    import copy
    import importlib.util as _ilu

    spec = _ilu.spec_from_file_location(
        "_ps_for_test", _PILOT_DIR / "_producer_solve.py"
    )
    ps = _ilu.module_from_spec(spec)
    # register before exec: the module's dataclasses use PEP-563 annotations and
    # resolve them via sys.modules[cls.__module__] at decoration time.
    sys.modules["_ps_for_test"] = ps
    spec.loader.exec_module(ps)

    vehicle = json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    samples = json.loads((bundle / "inputs" / "trip_samples.json").read_bytes())
    mislearned = copy.deepcopy(vehicle)
    mislearned["front_roll_stiffness_fraction"] = chi_0
    loads = ps.solve_corner_loads(mislearned, samples, ps.SolveStats())
    (bundle / "payload" / "corner_loads.json").write_text(
        json.dumps([[str(x) for x in row] for row in loads], indent=2, ensure_ascii=False)
    )
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        p = bundle / rel
        if p.exists():
            manifest["files"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )


def test_mislearned_transfer_split_is_caught(clean_bundle: Path, tmp_path: Path) -> None:
    """The error mode the three equilibrium channels cannot see, at all.

    MEASURED 2026-09-03, against the auditor's declared epsilons (40 N vertical,
    60 N-m pitch and roll): a surrogate whose front roll-stiffness fraction is
    0.30 instead of 0.58 publishes corner loads wrong by up to 631 N, and all
    three residuals read about 1e-12. Machine zero. Meanwhile a mis-learned
    MASS -- a number off a spec sheet, needing no expensive solve at all -- is
    loudly visible at 490 N against a 40 N epsilon.

    So without this channel the auditor sees precisely the errors that do not
    need the reference solve, and is blind to precisely the ones that do.
    """
    import shutil

    bundle = tmp_path / "mislearned"
    shutil.copytree(clean_bundle, bundle)
    _republish_with_mislearned_split(bundle, "0.30")

    result = _run_verify(bundle)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        "a surrogate that mis-learned the load-transfer split -- the ONLY output "
        "of the expensive nonlinear solve -- verified clean:\n" + combined[-2500:]
    )
    assert "transfer_split" in combined, (
        "rejected, but not by the split channel; this test would then pass for "
        "the wrong reason:\n" + combined[-2500:]
    )


def test_the_three_equilibrium_channels_are_blind_to_it(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """Control for the test above, and the justification for the whole channel.

    If the mis-learned bundle tripped a residual channel too, channel 4 would be
    redundant. It does not: this asserts the three residuals stay inside their
    epsilons on exactly the bundle channel 4 must reject, so the new channel is
    established as the ONLY thing standing between that model defect and a PASS.
    """
    import shutil

    bundle = tmp_path / "mislearned_residuals"
    shutil.copytree(clean_bundle, bundle)
    _republish_with_mislearned_split(bundle, "0.30")

    for channel in (_resid.VERTICAL, _resid.PITCH, _resid.ROLL):
        worst, _index = _resid.max_abs_residual(bundle, channel)
        assert abs(float(worst)) < 1.0, (
            f"{channel} residual is {float(worst)} on the mis-learned bundle -- "
            "an equilibrium channel DOES see this, so the split channel is not "
            "the only guard and this test's premise needs restating"
        )


def test_the_calibration_shape_is_load_bearing(clean_bundle: Path, tmp_path: Path) -> None:
    """Replaces test_the_calibration_shape_is_inert_at_the_current_epsilon.

    That test pinned a measured weakness: over the original 5.0 m/s^2 envelope
    the whole reference migration was 0.0758 against a 0.05 tolerance, so a
    CONSTANT reference sat within tolerance of the true curve everywhere and
    replacing the 100-entry table with 0.62 left every test green. It carried
    instructions to be replaced by a discriminating witness once the shape began
    to bite, and widening the envelope to 10.0 m/s^2 -- forced by the drift
    profile, which corners to |ay| = 7.5 -- did that: the migration is now
    0.581584 -> 0.726239, or 0.1446.

    The witness is an HONEST bundle at high |ay|: the trip re-solved with the
    reference solver, so every equilibrium residual is at machine zero and the
    split matches the calibration exactly. It must PASS. Under a constant
    reference it does not -- at |ay| = 7.5 the true share is about 0.70 against a
    constant 0.62, a 0.08 deviation past the 0.05 epsilon -- so a flattened table
    now FALSE-REJECTS honest work. That is what makes the shape load-bearing, and
    it is a stronger control than a forgery would be: it fails in the direction
    that costs the producer, which no adversary would help us find.
    """
    import shutil
    import sys as _sys
    import importlib.util as _ilu

    bundle = tmp_path / "honest_high_ay"
    shutil.copytree(clean_bundle, bundle)

    spec = _ilu.spec_from_file_location("_ps_hi", _PILOT_DIR / "_producer_solve.py")
    ps = _ilu.module_from_spec(spec)
    _sys.modules["_ps_hi"] = ps
    spec.loader.exec_module(ps)

    vehicle = json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    samples = json.loads((bundle / "inputs" / "trip_samples.json").read_bytes())
    # push the trip into the high-|ay| half of the envelope, where the reference
    # curve and a constant diverge
    hot = [dict(s, ay_mps2=str(round(6.0 + 0.01 * i, 2))) for i, s in enumerate(samples)]
    loads = ps.solve_corner_loads(vehicle, hot, ps.SolveStats())
    (bundle / "inputs" / "trip_samples.json").write_text(json.dumps(hot, indent=2))
    (bundle / "payload" / "corner_loads.json").write_text(
        json.dumps([[str(x) for x in row] for row in loads], indent=2)
    )
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        path = bundle / rel
        if path.exists():
            manifest["files"][rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )

    coverage = _resid.split_coverage(bundle)
    assert coverage["above_envelope"] == 0, coverage
    assert coverage["gated"] == coverage["total"], coverage

    result = _run_verify(bundle)
    assert result.returncode == 0, (
        "an HONEST high-|ay| bundle -- the trip re-solved by the reference solver "
        "itself -- was rejected. If the calibration were flattened to a constant "
        "this is exactly how it would show up:\n"
        + (result.stdout + result.stderr)[-2500:]
    )

def test_epsilon_is_not_silently_calibrated_from_the_producers_error() -> None:
    """The tolerance's provenance, recorded because I got it backwards once.

    Epsilon 0.05 was chosen to admit the shipped surrogate, whose own split error
    reaches 0.0369. That is deriving the AUDITOR's tolerance from the PRODUCER's
    error -- a quieter form of letting the producer declare its own tolerance,
    which is the failure this pilot exists to demonstrate against. The number
    should come from an engineering requirement on load accuracy, which this
    synthetic pilot does not have and must not invent.

    Pinned here so the provenance travels with the number: if epsilon changes,
    this test names what must be justified.
    """
    import json as _json

    spec = _json.loads(
        (_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json").read_bytes()
    )
    epsilon = spec["types"]["corner_load_transfer_split_residual"]["comparator"][
        "params"
    ]["epsilon"]
    assert epsilon == 0.05, (
        "the split tolerance changed. It was 0.05, chosen to admit the shipped "
        "surrogate's own 0.0369 split error -- a provisional number with backwards "
        "provenance. Any new value needs a stated basis in required load accuracy, "
        "not in what the current model happens to achieve."
    )


def _forge_out_of_envelope(bundle: Path, n_poison: int) -> None:
    """Put the whole vehicle weight on one wheel for `n_poison` samples, and
    solve ax/ay to null pitch and roll exactly. The implied |ay| is ~14 m/s^2 --
    far outside the calibrated envelope -- which is the point: the producer owns
    the trip, so it can choose to drive where the auditor has no reference."""
    from decimal import Decimal
    from fractions import Fraction

    vehicle = json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    m = Fraction(str(vehicle["mass_kg"]))
    g = Fraction(str(vehicle["gravity_mps2"]))
    a = Fraction(str(vehicle["cg_to_front_axle_m"]))
    b = Fraction(str(vehicle["cg_to_rear_axle_m"]))
    t = Fraction(str(vehicle["track_width_m"]))
    h = Fraction(str(vehicle["cg_height_m"]))
    weight = m * g

    def dec(x: Fraction) -> str:
        return str(Decimal(x.numerator) / Decimal(x.denominator))

    fl, fr, rl, rr = Fraction(0), weight, Fraction(0), Fraction(0)
    ax = -((fl + fr) * a - (rl + rr) * b) / (m * h)
    ay = ((fr + rr - fl - rl) * (t / 2)) / (m * h)

    samples = json.loads((bundle / "inputs" / "trip_samples.json").read_bytes())
    loads = json.loads((bundle / "payload" / "corner_loads.json").read_bytes())
    new_s, new_l = [], []
    for i, (s, r) in enumerate(zip(samples, loads)):
        if i < n_poison:
            new_s.append(dict(s, ax_mps2=dec(ax), ay_mps2=dec(ay)))
            new_l.append([dec(fl), dec(fr), dec(rl), dec(rr)])
        else:
            new_s.append(s)
            new_l.append(r)
    (bundle / "inputs" / "trip_samples.json").write_text(json.dumps(new_s, indent=2))
    (bundle / "payload" / "corner_loads.json").write_text(json.dumps(new_l, indent=2))
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        p = bundle / rel
        if p.exists():
            manifest["files"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )


def test_driving_outside_the_calibrated_envelope_does_not_buy_silence(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The channel's own refuse-rather-than-extrapolate skip was the escape hatch.

    `_reference_split` returns None above the calibrated |ay| envelope, and the
    loop SKIPPED those samples -- contributing nothing to the reported deviation.
    The producer owns `trip_samples.json`, so it chooses where to drive. Combined
    with a coverage floor of "at least one sample, anywhere", that let a producer
    put an unbounded error on almost the whole trip.

    MEASURED 2026-09-03 before the fix: 119 of 120 samples claiming the ENTIRE
    18,142 N vehicle weight on a single wheel, one honest sample left to satisfy
    the floor -> PASS, exit 0, on both verify entry points.

    Outside the calibration is a place the auditor cannot judge. That is a
    could-not-conclude, never a pass.
    """
    import shutil

    bundle = tmp_path / "out_of_envelope"
    shutil.copytree(clean_bundle, bundle)
    _forge_out_of_envelope(bundle, 119)

    result = _run_verify(bundle)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        "119 of 120 samples put the whole car on one wheel and the bundle "
        "verified clean:\n" + combined[-2500:]
    )


def test_a_single_gated_sample_is_not_coverage(clean_bundle: Path, tmp_path: Path) -> None:
    """The floor was `gated == 0`, which is a floor of ONE.

    Stated over coverage rather than over a particular forgery, so it keeps
    biting if someone later changes how samples fall out of the gate. A channel
    that judged 1 of 120 samples and reported the same clean verdict as one that
    judged 94 cannot be read as having checked the trip.
    """
    import shutil

    bundle = tmp_path / "one_gated"
    shutil.copytree(clean_bundle, bundle)
    _forge_out_of_envelope(bundle, 119)

    gated = _resid.gated_sample_count(bundle)
    total = len(json.loads((bundle / "inputs" / "trip_samples.json").read_bytes()))
    assert gated <= 1, f"fixture no longer starves the channel: gated={gated}"
    result = _run_verify(bundle)
    assert result.returncode != 0, (
        f"the split channel judged {gated} of {total} samples and still returned "
        "a clean verdict; coverage that low is not a check"
    )


def test_a_straight_line_trip_cannot_hide_cross_weight(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The sibling attack: starve the channel from BELOW instead of above.

    Every sample below the lateral-transfer floor is skipped as legitimately
    ill-conditioned. A producer who drives in a straight line therefore presents
    a trip on which the split can never be evaluated -- and can then misstate
    cross-weight freely. The honest verdict is could-not-conclude, not pass.
    """
    import shutil
    from decimal import Decimal

    bundle = tmp_path / "straight_line"
    shutil.copytree(clean_bundle, bundle)
    samples = json.loads((bundle / "inputs" / "trip_samples.json").read_bytes())
    (bundle / "inputs" / "trip_samples.json").write_text(
        json.dumps([dict(s, ay_mps2="0.0") for s in samples], indent=2)
    )
    loads = json.loads((bundle / "payload" / "corner_loads.json").read_bytes())
    d = Decimal("450")
    (bundle / "payload" / "corner_loads.json").write_text(
        json.dumps(
            [
                [str(Decimal(fl) + d), str(Decimal(fr) - d), str(Decimal(rl) - d), str(Decimal(rr) + d)]
                for fl, fr, rl, rr in loads
            ],
            indent=2,
        )
    )
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        p = bundle / rel
        if p.exists():
            manifest["files"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )

    result = _run_verify(bundle)
    assert result.returncode != 0, (
        "a straight-line trip starved the split channel and carried a 450 N "
        "cross-weight misstatement to a clean verdict:\n"
        + (result.stdout + result.stderr)[-2500:]
    )


def test_out_of_envelope_refusal_is_isolated_from_the_coverage_floor(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """Isolating control. Mutating either guard alone left every test green,
    because the 119-of-120 witness trips BOTH -- the forged samples leave the
    envelope AND starve coverage. Redundant guards look like tested guards until
    one is deleted for the wrong reason.

    Here 30 of 120 samples are pushed out of the envelope, few enough that 64
    remain gated -- above the coverage floor. Only the out-of-envelope refusal
    can catch this, and 30 samples still carry the whole vehicle weight on one
    wheel, so it is a real misstatement and not merely a coverage probe.
    """
    import shutil

    bundle = tmp_path / "envelope_only"
    shutil.copytree(clean_bundle, bundle)
    _forge_out_of_envelope(bundle, 30)

    coverage = _resid.split_coverage(bundle)
    assert coverage["above_envelope"] == 30, coverage
    assert coverage["gated"] * 2 >= coverage["total"], (
        f"fixture starves coverage too, so it does not isolate the guard: {coverage}"
    )

    result = _run_verify(bundle)
    assert result.returncode != 0, (
        "30 samples drove outside the calibration, each claiming the entire "
        "vehicle weight on one wheel, and the bundle passed:\n"
        + (result.stdout + result.stderr)[-2500:]
    )


def test_coverage_floor_is_isolated_from_the_envelope_refusal(
    clean_bundle: Path, tmp_path: Path
) -> None:
    """The other half of the pair: starve coverage WITHOUT leaving the envelope.

    Most of the trip is dropped below the lateral-transfer floor -- a legitimate,
    in-envelope, gentle trip -- while a cross-weight misstatement rides along.
    Nothing here is out of range, so only the coverage floor can refuse it. The
    honest verdict is could-not-conclude: a trip this gentle cannot carry a
    trip-level verdict on the split.
    """
    import shutil
    from decimal import Decimal

    bundle = tmp_path / "coverage_only"
    shutil.copytree(clean_bundle, bundle)
    import sys as _sys
    import importlib.util as _ilu

    spec = _ilu.spec_from_file_location("_ps_gentle", _PILOT_DIR / "_producer_solve.py")
    ps = _ilu.module_from_spec(spec)
    _sys.modules["_ps_gentle"] = ps
    spec.loader.exec_module(ps)

    samples = json.loads((bundle / "inputs" / "trip_samples.json").read_bytes())
    # Gentle for most of the trip. The gate reads the LOADS' lateral transfer,
    # not ay, so the loads have to be re-solved for the gentle trip or the
    # samples stay gated and this fixture proves nothing.
    gentle = [dict(s, ay_mps2="0.1") if i < 90 else s for i, s in enumerate(samples)]
    vehicle = json.loads((bundle / "inputs" / "vehicle_spec.json").read_bytes())
    solved = ps.solve_corner_loads(vehicle, gentle, ps.SolveStats())
    (bundle / "inputs" / "trip_samples.json").write_text(json.dumps(gentle, indent=2))
    loads = [[str(x) for x in row] for row in solved]
    # The misstatement hides ONLY in the samples that fall below the transfer
    # floor. The still-gated samples are left honest, so the split deviation
    # cannot catch this and the coverage floor is the only guard that can --
    # which is the point of an isolating control. A first version shifted every
    # row, and the gated ones then carried the disagreement, so the mutant on
    # the coverage floor survived.
    d = Decimal("450")
    shifted = []
    for i, (fl, fr, rl, rr) in enumerate(loads):
        if i < 90:
            shifted.append(
                [str(Decimal(fl) + d), str(Decimal(fr) - d), str(Decimal(rl) - d), str(Decimal(rr) + d)]
            )
        else:
            shifted.append([fl, fr, rl, rr])
    (bundle / "payload" / "corner_loads.json").write_text(
        json.dumps(shifted, indent=2)
    )
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for rel in list(manifest["files"]):
        p = bundle / rel
        if p.exists():
            manifest["files"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    )

    coverage = _resid.split_coverage(bundle)
    assert coverage["above_envelope"] == 0, (
        f"fixture leaves the envelope, so it does not isolate the guard: {coverage}"
    )
    assert coverage["gated"] * 2 < coverage["total"], coverage

    result = _run_verify(bundle)
    assert result.returncode != 0, (
        "a gentle in-envelope trip starved the split channel to under half its "
        "samples and still carried a 450 N cross-weight misstatement to a clean "
        "verdict:\n" + (result.stdout + result.stderr)[-2500:]
    )


# ---------------------------------------------------------------------------
# The front door is the production command, prefilled (ADR D3 as amended by
# Max, 2026-09-06). Three properties hold it to that: the command it PRINTS is
# the command it RUNS and agrees with the miner's library constructor; the
# committed work-set file equals the derived one; and the split channel's
# coverage statement reaches the terminal through the CLI, not by hand.
# ---------------------------------------------------------------------------
import shlex  # noqa: E402

# By PATH under a unique name: `verify` is the least unique module name in the
# fleet, and a bare import would bind whichever pilot's verify.py a shared
# process saw first (the finsheet lesson, e0c11995d).
_front_door = _import_from_path(
    "corner_load_equilibrium_minimal.verify", _PILOT_DIR / "verify.py"
)


def _rerun_printed_command(stdout: str, verdict_out: Path) -> dict:
    """Take the `$ ...` line the front door printed, run exactly that from the
    package root with --verdict-out appended, return the face."""
    first = stdout.splitlines()[0]
    assert first.startswith("$ python -m veriker.cli.verify "), first
    argv = shlex.split(first[2:])
    argv[0] = sys.executable
    proc = subprocess.run(
        [*argv, "--verdict-out", str(verdict_out)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert verdict_out.is_file(), proc.stderr[-2000:]
    face = json.loads(verdict_out.read_text(encoding="utf-8"))
    assert face["exit_code"] == proc.returncode
    return face


@pytest.mark.parametrize("profile", ["clean", "drift"])
def test_the_printed_command_is_the_command_run_and_agrees_with_the_library(
    tmp_path: Path, profile: str
) -> None:
    """Anti-drift, the executable form. (1) `verify.command()` is what the
    subprocess ran: re-running the PRINTED line reproduces the exit code.
    (2) The CLI path and the miner's library path (auditor_entry.build_verifier)
    reach the same conclusion on the same bytes -- same ok-ness, and every
    reason the library concluded is on the CLI's face -- so a hardening
    applied to one input set cannot silently miss the other tool."""
    bundle = tmp_path / profile
    subprocess.run(
        [
            sys.executable,
            str(_PILOT_DIR / "_build_bundle.py"),
            "--out-dir",
            str(bundle),
            "--profile",
            profile,
        ],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    result = _run_verify(bundle)
    first = result.stdout.splitlines()[0]
    assert first == _front_door.display(_front_door.command(bundle.resolve()))
    # The PRINTED argv and the EXECUTED argv, compared token by token after
    # resolving the display's package-relative paths. Not through display()
    # again: a display() that dropped a flag would agree with itself (the
    # mutation control caught that only on the drift arm, by exit code).
    printed = shlex.split(first[2:])[1:]
    executed = _front_door.command(bundle.resolve())[1:]

    def _norm(tok: str) -> str:
        cand = _PKG_ROOT / tok
        return str(cand.resolve()) if not Path(tok).is_absolute() and cand.exists() else tok

    assert [_norm(t) for t in printed] == [_norm(t) for t in executed]
    face = _rerun_printed_command(result.stdout, tmp_path / f"{profile}.face.json")
    assert face["exit_code"] == result.returncode

    verifier, _anchor = _entry.build_verifier(bundle.resolve())
    lib = verifier.verify(bundle.resolve())
    assert lib.ok == (result.returncode == 0), (
        f"library ok={lib.ok} but the front door exited {result.returncode}"
    )
    lib_codes = {f.reason_code for f in lib.failures}
    assert lib_codes <= set(face["reason_codes"]), (
        f"library concluded {sorted(lib_codes)} but the CLI face carries only "
        f"{sorted(set(face['reason_codes']))}"
    )
    if profile == "drift":
        assert "RE_DERIVATION_MISMATCH" in lib_codes


def test_the_committed_work_set_file_equals_the_derived_one() -> None:
    """The CLI reads the work-set as a FILE; the miner derives it from the
    anchored spec. A channel added to the spec without the file following is
    a red test here, not a silently narrower CLI run."""
    doc = json.loads(_entry.WORK_SET_PATH.read_text(encoding="utf-8"))
    derived = {e["output_id"]: e["type"] for e in _entry._work_set().expected}
    assert doc["pins"] == derived
    assert not doc.get("withheld"), doc.get("withheld")
    assert _front_door.WORK_SET_PATH == _entry.WORK_SET_PATH


def test_the_split_coverage_reaches_the_terminal_through_the_cli(
    clean_bundle: Path,
) -> None:
    """Until 2026-09-06 verify.py recomputed and printed the split coverage
    itself. That line is the primitive's own detail, and it now rides the
    CLI's recompute_detail rows -- so a green run says how much of the trip
    the split channel judged, through the production command, for anyone."""
    result = _run_verify(clean_bundle)
    assert result.returncode == 0, result.stderr[-2000:]
    rows = [ln for ln in result.stdout.splitlines() if "recompute_detail" in ln]
    split = [ln for ln in rows if "corner_load_transfer_split_residual" in ln]
    assert len(split) == 1, rows
    assert "gated sample(s) of 120" in split[0], split[0]
    assert "split_coverage" not in result.stdout, (
        "the hand-printed line is back; the CLI's recompute_detail row is the channel"
    )
