"""Battery for fea_vonmises_minimal — re-run the pinned solve and compare.

What this pilot demonstrates, and what each surface below pins down:

  THE PUBLIC VERIFIER RUNS THE METHOD. `fea_vonmises_recompute` ships in the
  distribution. This pilot is the public bundle it runs on: no demo-local
  `register_primitive`, no import of the primitive module, nothing but core
  auto-registration resolving the recompute.

  THE CLAIM IS THE PRODUCER'S. `_producer_solve.py` is a separately written copy
  of the pinned CST algorithm. Two copies of one algorithm agree to floating-
  point accumulation order — measured at 1.4e-12 on the committed exemplar,
  six orders under the 1e-6 epsilon — so an honest PASS says the claim came from
  the producer, not that the two used different methods. The auditor pinned this
  algorithm; running it is the claim.

  THE PIN IS MEASURED, NOT ASSERTED. Every file the recompute reads is written
  by the producer, so all four are SHA-pinned in the anchored spec. One arm
  shows the pin doing work nothing else does (an honest analysis of a
  substituted load case verifies CLEAN once the pin is removed). The other arm
  shows the opposite and is kept anyway: loosening the solver tolerance is
  caught by the comparator too, so there the pin is defence in depth.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_PILOT = Path(__file__).resolve().parents[1]
_PKG_ROOT = _PILOT.parents[1]
for p in (str(_PKG_ROOT), str(_PILOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402

_BUILD = _PILOT / "_build_bundle.py"
_SPEC_SRC = _PILOT / "spec_pinned" / "fea_vonmises.spec.json"
_OUTPUT_ID = "fea_sigma_vm_max"
_CLAIM_REL = f"outputs/{_OUTPUT_ID}.json"
_NORMS_REL = "payload/output_norms.json"
_MATERIAL_REL = "inputs/material.json"

#: The authority-pinned acceptance band, read from the anchored spec rather than
#: restated here — a second copy of a number is a second thing to drift.
_EPSILON = json.loads(_SPEC_SRC.read_bytes())["types"]["fea_vonmises_sigma_vm_max"][
    "comparator"
]["params"]["epsilon"]


def _load_producer_module():
    """The pilot's `_producer_solve.py` by PATH under a pilot-unique module name.

    Same collision as `_load_verify_module` below, one axis over: three pilots
    ship a top-level `_producer_solve.py`, and every pilot battery prepends its
    own directory to `sys.path` at import. A bare `import _producer_solve` in a
    test BODY therefore resolves against whichever pilot was collected last, not
    against this one. When the batteries are collected together that handed this
    test `witness_cert_minimal`'s producer — which it survived only because that
    producer's element data is dicts where this one's is 4-tuples. Had the
    shapes agreed, the test certifying that producer and verifier are NOT the
    same arithmetic would have passed against a producer from another pilot.
    """
    spec = importlib.util.spec_from_file_location(
        "fea_vonmises_minimal__producer_solve", _PILOT / "_producer_solve.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_verify_module():
    """The pilot's verify.py by PATH under a pilot-unique module name (a bare
    `import verify` collides across pilots)."""
    spec = importlib.util.spec_from_file_location(
        "fea_vonmises_minimal__verify", _PILOT / "verify.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(out_dir: Path, *, tol=None, shear_scale=None) -> Path:
    cmd = [sys.executable, str(_BUILD), "--out-dir", str(out_dir)]
    if tol is not None:
        cmd += ["--tol", repr(tol)]
    if shear_scale is not None:
        cmd += ["--shear-scale", repr(shear_scale)]
    subprocess.run(cmd, check=True, capture_output=True)
    return out_dir


def _verify(bundle_dir: Path, spec_src: Path = _SPEC_SRC):
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier

    anchor = SpecAnchor.from_files([spec_src], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def _realign(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _unpin(bundle_dir: Path, tmp_path: Path) -> Path:
    """Strip `pinned_inputs` from the auditor's spec and re-ship it.

    The counterfactual arm: the verifier resolves the authoritative spec from
    manifest.spec_files and checks its bytes against the anchor, so the bundle's
    own copy has to be swapped and re-pinned too. Returns the new auditor spec
    path to anchor on.
    """
    spec = json.loads(_SPEC_SRC.read_bytes())
    for tdef in spec["types"].values():
        tdef.pop("pinned_inputs", None)
    spec["spec_id"] = "fea.vonmises.minimal.unpinned.v1"
    raw = (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")

    unpinned = tmp_path / "unpinned.spec.json"
    unpinned.write_bytes(raw)
    (bundle_dir / "spec" / _SPEC_SRC.name).write_bytes(raw)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["spec_files"][_SPEC_SRC.name] = hashlib.sha256(raw).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return unpinned


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


# --------------------------------------------------------------------------- #
# The honest bundle
# --------------------------------------------------------------------------- #


def test_honest_bundle_passes(tmp_path):
    result = _verify(_build(tmp_path / "b"))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_pilot_verify_entry_point_passes(tmp_path):
    mod = _load_verify_module()
    bundle = _build(tmp_path / "b")
    assert mod.make_verifier(bundle).verify(bundle).ok


def test_committed_bundle_passes():
    """The bundle checked into the repo is the one the README's commands run."""
    result = _verify(_PILOT / "bundle")
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# Gate B — the claim is the producer's, never the verifier's
# --------------------------------------------------------------------------- #


def _import_targets(path: Path) -> set[str]:
    """Every module path a file can reach, as dotted strings.

    `from x.y import z` yields BOTH `x.y` and `x.y.z`. Recording only
    `node.module` would miss one spelling entirely --
    `from audit_bundle.rederivation import primitives` has module
    `audit_bundle.rederivation`, and `primitives/__init__.py` eagerly imports
    every primitive module, so the verifier's compute would be one attribute
    access away from a producer this check had just called clean.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, (
                f"{path.name}: relative import — this is a top-level script "
                "where that cannot bind, and it would be invisible to the check "
                "below"
            )
            if node.module:
                targets.add(node.module)
                targets |= {f"{node.module}.{a.name}" for a in node.names}
    return targets


def test_producer_does_not_import_the_verifier():
    """AST, not substring: both producer modules DISCUSS the rule in prose, so a
    text search matches its own documentation and proves nothing."""
    for mod in ("_build_bundle.py", "_producer_solve.py"):
        offending = {
            m
            for m in _import_targets(_PILOT / mod)
            if m == "audit_bundle.rederivation.primitives"
            or m.startswith("audit_bundle.rederivation.primitives.")
        }
        assert not offending, (
            f"{mod} imports the verifier's own primitive {sorted(offending)} — the "
            f"comparison would be f(x) == f(x)"
        )


def test_claim_is_the_producers_own_payload(tmp_path):
    """The declared claim is the number the producer's solver emitted, byte for
    byte — not a value re-derived at claim-writing time from anywhere else."""
    bundle = _build(tmp_path / "b")
    claimed = json.loads((bundle / _CLAIM_REL).read_bytes())["value"]
    produced = json.loads((bundle / _NORMS_REL).read_bytes())["sigma_vm_max"]
    assert claimed == produced


# --------------------------------------------------------------------------- #
# The acceptance band is a band: it admits below epsilon and refuses above
# --------------------------------------------------------------------------- #


def _perturb_claim(bundle: Path, delta: float) -> None:
    path = bundle / _CLAIM_REL
    doc = json.loads(path.read_bytes())
    doc["value"] += delta
    path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign(bundle, _CLAIM_REL)


def test_mutant_claim_fails_rederivation(tmp_path):
    """THE MUTANT CONTROL. +1.0 on the claimed sigma_vm_max — six orders above
    the epsilon — and the manifest SHA realigned so file integrity cannot
    preempt the verdict."""
    bundle = _build(tmp_path / "b")
    _perturb_claim(bundle, 1.0)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_mutant_claim_fails_through_the_shipped_entry_point(tmp_path):
    """The same mutant through `verify.py` itself: FAIL on stdout, exit 1."""
    bundle = _build(tmp_path / "b")
    _perturb_claim(bundle, 1.0)
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "RE_DERIVATION_MISMATCH" in proc.stdout


def test_perturbation_just_above_epsilon_fails(tmp_path):
    """Keeps the mutant above from proving only that a huge number is rejected:
    the refusal starts just past the auditor's band, not at some larger scale."""
    bundle = _build(tmp_path / "b")
    _perturb_claim(bundle, _EPSILON * 1.1)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_perturbation_just_below_epsilon_passes(tmp_path):
    """The other half of the bracket. Without it, an epsilon of zero — or a
    comparator that rejected everything — would pass every test above."""
    bundle = _build(tmp_path / "b")
    _perturb_claim(bundle, _EPSILON * 0.9)
    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_honest_delta_sits_far_inside_the_band(tmp_path):
    """Whatever the two implementations differ by, it is nowhere near the band.
    The assertion is the two-orders-of-margin property, not a pinned number."""
    bundle = _build(tmp_path / "b")
    claimed = json.loads((bundle / _CLAIM_REL).read_bytes())["value"]
    # Re-derive the way the verifier does, with the SAME core primitive dispatch
    # resolves — imported here (an auditor-side test, not the producer) purely to
    # read the number out.
    from audit_bundle.rederivation.primitives.fea_vonmises import compute_sigma_vm_max

    assert abs(compute_sigma_vm_max(bundle) - claimed) < _EPSILON / 100.0


def _sum_is_compensated() -> bool:
    """Does this interpreter's builtin sum() carry a compensation term?

    CPython grew Neumaier summation for float sequences; a naive left fold does
    not have it. This probe is the difference, isolated: a naive fold of these
    four values is 0.0 and a compensated one is 2.0.
    """
    return sum([1.0, 1e100, 1.0, -1e100]) != 0.0


def test_the_two_implementations_are_not_the_same_arithmetic():
    """WHY THERE IS A TOLERANCE AT ALL, measured on whatever interpreter runs.

    An earlier reading of this pilot held that `_producer_solve.py` is a
    retyping of the primitive and that the two must therefore agree exactly.
    They do not, and the reason is exact and singular. Assembly, the
    boundary-condition passes and stress recovery are bit-equal — asserted
    below, term by term. The conjugate-gradient loops are not: the verifier
    writes its matrix-vector product as a builtin `sum()` over a generator and
    the producer accumulates in an explicit loop, so on an interpreter whose
    `sum()` compensates, the two products differ in their last bits.

    That is why the auditor binds `scalar_epsilon` rather than `exact`:
    compensated summation is an interpreter implementation detail, not a
    property of IEEE-754, so an exact comparator would bind the claim to one
    interpreter.
    """
    from audit_bundle.rederivation.primitives import fea_vonmises as verifier

    producer = _load_producer_module()

    bundle = _PILOT / "bundle"
    mesh = json.loads((bundle / "inputs" / "mesh.json").read_bytes())
    material = json.loads((bundle / "inputs" / "material.json").read_bytes())
    bcs = json.loads((bundle / "inputs" / "bcs.json").read_bytes())
    cfg = json.loads((bundle / "spec" / "solver_config.json").read_bytes())

    k_p, ed_p = producer.assemble(mesh, material)
    k_v, ed_v = verifier._assemble_global(
        mesh["nodes"],
        mesh["elements"],
        float(material["E"]),
        float(material["nu"]),
        float(material["thickness"]),
    )
    assert k_p == k_v, "the two assemblies differ — the difference is not the CG"
    assert [(b, d) for _m, b, d, _a in ed_p] == [(b, d) for _m, b, d, _a in ed_v]

    n = 2 * len(mesh["nodes"])
    f_p = [0.0] * n
    producer.apply_neumann(f_p, bcs["neumann"])
    producer.apply_dirichlet(k_p, f_p, bcs["dirichlet"])
    f_v = [0.0] * n
    verifier._apply_neumann(f_v, bcs["neumann"])
    verifier._apply_dirichlet(k_v, f_v, bcs["dirichlet"])
    assert f_p == f_v and k_p == k_v, "the boundary-condition passes differ"

    tol, max_iter = float(cfg["tol"]), int(cfg["max_iter"])
    u_p = producer.conjugate_gradient([r[:] for r in k_p], list(f_p), tol, max_iter)
    u_v = verifier._cg_solve([r[:] for r in k_v], list(f_v), tol, max_iter)

    if _sum_is_compensated():
        assert u_p != u_v, (
            "this interpreter's sum() compensates, so the two solves should "
            "differ in their last bits — if they agree, one of them changed "
            "and the epsilon's justification no longer holds"
        )
        gap = abs(
            producer.max_von_mises(u_p, ed_p) - verifier._stress_recovery(u_v, ed_v)
        )
        assert 0.0 < gap < _EPSILON / 100.0, gap
    else:  # pragma: no cover - depends on the interpreter running the suite
        assert u_p == u_v, (
            "this interpreter's sum() does not compensate, so the two solves "
            "should be bit-identical"
        )


# --------------------------------------------------------------------------- #
# The auditor pins every file the recompute reads (§4a.7)
# --------------------------------------------------------------------------- #


def test_substituted_load_case_is_refused_by_the_pin(tmp_path):
    """An analyst who honestly analyses a DIFFERENT load case. The claim is
    correct for the problem it was given; the mathematics has no complaint."""
    bundle = _build(tmp_path / "light", shear_scale=0.6)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"PINNED_INPUT_MISMATCH"}, _reason_codes(result)


def test_the_same_substituted_load_case_passes_UNPINNED(tmp_path):
    """The counterfactual that gives the previous test its meaning: with
    `pinned_inputs` removed the identical bundle verifies CLEAN, because the
    re-derivation really does reproduce the claim — for the substituted problem.
    The pin, not the mathematics, is what refuses it."""
    bundle = _build(tmp_path / "light", shear_scale=0.6)
    unpinned = _unpin(bundle, tmp_path)
    result = _verify(bundle, spec_src=unpinned)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_material_is_refused_by_the_pin(tmp_path):
    bundle = _build(tmp_path / "b")
    path = bundle / _MATERIAL_REL
    material = json.loads(path.read_bytes())
    material["thickness"] *= 2
    path.write_bytes(json.dumps(material, indent=2, sort_keys=True).encode("utf-8"))
    _realign(bundle, _MATERIAL_REL)

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"PINNED_INPUT_MISMATCH"}, _reason_codes(result)


def test_loosened_solver_tolerance_is_refused_by_the_pin(tmp_path):
    """The producer writes the file the verifier reads its own stopping
    tolerance from. The pin fixes it at the auditor."""
    bundle = _build(tmp_path / "loose", tol=1e-1)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"PINNED_INPUT_MISMATCH"}, _reason_codes(result)


def test_loosened_tolerance_would_ALSO_have_failed_the_comparator(tmp_path):
    """The negative result, recorded rather than hidden. Unlike the substituted
    load case, this attack does not survive the removal of the pin: under early
    stopping the producer's and verifier's independently-written CG copies stop
    at different points, and the gap between them (4.1e-4 at this tolerance) is
    far outside the band. On THIS exemplar the parameter pin is defence in
    depth, not the load-bearing control — a control that is never the one doing
    the work should say so."""
    bundle = _build(tmp_path / "loose", tol=1e-1)
    unpinned = _unpin(bundle, tmp_path)
    result = _verify(bundle, spec_src=unpinned)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


# --------------------------------------------------------------------------- #
# The anchor may not come from inside the bundle
# --------------------------------------------------------------------------- #


def test_anchor_taken_from_inside_the_bundle_is_refused(tmp_path):
    bundle = _build(tmp_path / "b")
    with pytest.raises(Exception) as exc:
        SpecAnchor.from_files(
            [bundle / "spec" / _SPEC_SRC.name], forbid_within=bundle
        )
    assert "INSIDE" in str(exc.value).upper() or "within" in str(exc.value).lower()


def test_bundle_dir_at_the_pilot_root_is_COULD_NOT_CONCLUDE_not_a_reject(tmp_path):
    """The tri-state matters. An unusable anchor is an OPERATOR error — no
    verdict about the artifact was formed — so `spec_binding.AnchorConstructionError`
    must route to could-not-conclude (exit 2), NEVER to a REJECT (exit 1). Letting
    it escape `main()` as a traceback also exits 1, which is the same wrong
    answer wearing a stack trace."""
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(_PILOT)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "COULD NOT CONCLUDE" in proc.stdout
    assert "Traceback" not in proc.stderr


def _cli(bundle_dir: Path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle_dir),
            "--spec-anchor",
            str(_SPEC_SRC),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_the_shipped_CLI_verifies_this_bundle(tmp_path):
    """The README documents `python -m veriker.cli.verify --spec-anchor ...` as the way
    an auditor reaches this pilot with no pilot code at all. Walk it, rather
    than assert it."""
    proc = _cli(_build(tmp_path / "b"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_shipped_CLI_rejects_the_mutant(tmp_path):
    """And the same path exits non-zero on the mutant, so the line above is a
    verification and not a smoke test."""
    bundle = _build(tmp_path / "b")
    _perturb_claim(bundle, 1.0)
    proc = _cli(bundle)
    assert proc.returncode == 1, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# Nothing re-derived must not read as PASS
# --------------------------------------------------------------------------- #


def test_deleting_manifest_outputs_no_longer_makes_the_dispatch_inert(tmp_path):
    """THE FAIL-OPEN THIS PILOT USED TO SHIP, now closed in the substrate.

    `manifest.outputs` is a producer-authored declaration of what to check.
    Deleting it -- three lines -- USED TO make spec-pinned dispatch inert:
    every pinned byte still matched, every plugin still passed, and a
    `BundleVerifier` returned ok=True having re-derived nothing at all. The
    adversary who can realign the manifest for any other tamper in this file
    could do this one instead, and it was strictly easier.

    Two stacked early returns on `not outputs` -- one in
    `BundleVerifier._step_spec_pinned_dispatch`, one in
    `run_spec_pinned_dispatch` -- skipped the SS4a.4 coverage invariant, the
    guard written to catch exactly this. Partial omission (drop one entry of
    several) engaged dispatch and fired COVERAGE_MISMATCH; total omission
    returned OK. Both returns are now file-presence-triggered, so a bundle
    that ships outputs/*.json while declaring none is refused, and a bundle
    with no outputs/ tree at all stays inert as before.

    This assertion is INVERTED from the one this test shipped with. It is not
    a relaxed expectation: the pilot-level mitigation below is now defence in
    depth behind a substrate fix, rather than the only thing standing between
    a forged claim and a clean PASS.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    assert manifest.pop("outputs", None), "fixture declares no outputs to delete"
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    result = _verify(bundle)
    assert not result.ok, "deleting manifest.outputs must no longer read as clean"
    assert "COVERAGE_MISMATCH" in {r.code for r in result.reasons}, [
        (r.check_name, r.code) for r in result.reasons
    ]


def test_the_shipped_entry_point_REFUSES_the_inert_bundle(tmp_path):
    """And the closure, now STRONGER than when this test was written.

    `verify.py` builds its verifier with `require_rederivation=True`, which
    used to be the only thing refusing this bundle -- and it refused as
    COULD NOT CONCLUDE at exit 2, on the reasoning that nothing had been shown
    wrong with the artifact and the verifier had merely been prevented from
    concluding.

    That reasoning no longer holds, so neither does the exit code. The
    coverage invariant now shows something IS wrong with the artifact: it
    ships an output file its own manifest does not declare. That is an
    artifact-side finding, so it is a REJECT at exit 1 naming
    COVERAGE_MISMATCH, not a could-not-conclude.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest.pop("outputs", None)
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    assert "COVERAGE_MISMATCH" in proc.stdout, proc.stdout


def test_require_rederivation_still_owns_the_no_outputs_tree_case(tmp_path):
    """The case the coverage invariant CANNOT see, and the flag still does.

    SS4a.4 coverage triggers on files present at `outputs/*.json`. A producer
    who removes the declaration AND the tree leaves coverage nothing to count
    -- and the same is true of the cheaper restages coverage misses (rename
    `outputs/` to `results/`, nest a subdir, change the extension). Here
    nothing is re-derived and nothing is provably wrong with the artifact, so
    this is a COULD NOT CONCLUDE at exit 2, and `require_rederivation=True` is
    the only reason it is not a clean PASS.

    This replaces the exit-2 assertion that the coverage hoist moved to exit 1
    in the test above: without it, no test in this battery would pin the
    entry point's NO_RE_DERIVATION_PERFORMED -> exit 2 mapping any more.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest.pop("outputs", None)
    if isinstance(manifest.get("files"), dict):
        for rel in [k for k in manifest["files"] if k.startswith("outputs/")]:
            manifest["files"].pop(rel)
    shutil.rmtree(bundle / "outputs", ignore_errors=True)
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "COULD NOT CONCLUDE" in proc.stdout
    assert "VERIFIER_INCOMPLETE" in proc.stdout
