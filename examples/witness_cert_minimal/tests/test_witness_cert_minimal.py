"""Battery for witness_cert_minimal — the witness+certificate posture.

What this pilot demonstrates, and what each surface below pins down:

  SOLVE/VERIFY ASYMMETRY. The producer may solve however it likes. Two
  unrelated solvers ship (iterative CG, direct dense elimination); they produce
  DIFFERENT displacement vectors and both pass the SAME auditor certificate,
  because the certificate checks equilibrium rather than reproduction. The
  verifier never runs a solver at all.

  THE AUDITOR PINS THE PROBLEM, NOT ONLY THE MATHEMATICS. An analyst who
  honestly solves a LIGHTER load case produces a witness that satisfies
  equilibrium — for the problem it was given. Unanchored, that passes. The
  auditor's `input_anchor` is the thing that refuses it.

  FAITHFULNESS, NOT FITNESS. A PASS says the claim follows from the anchored
  problem and the committed witness. It says nothing about whether the
  structure is adequate.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
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
_SPEC_SRC = _PILOT / "spec_pinned" / "witness_cert.spec.json"
_WITNESS_REL = "payload/displacement_field.json"
_SIGMA_OUT = "outputs/wc_sigma_vm_max.json"


def _load_verify_module():
    """The pilot's verify.py by PATH under a pilot-unique module name (a bare
    `import verify` collides across pilots)."""
    spec = importlib.util.spec_from_file_location(
        "witness_cert_minimal__verify", _PILOT / "verify.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(out_dir: Path, *, solver: str = "cg", load_scale: float = 1.0) -> Path:
    cmd = [sys.executable, str(_BUILD), "--out-dir", str(out_dir), "--solver", solver]
    if load_scale != 1.0:
        cmd += ["--load-scale", str(load_scale)]
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


def _details(result) -> str:
    return " | ".join(f.detail for f in result.failures)


# --------------------------------------------------------------------------- #
# Solve/verify asymmetry
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("solver", ["cg", "dense"])
def test_either_solver_passes_the_same_certificate(tmp_path, solver):
    result = _verify(_build(tmp_path / solver, solver=solver))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_the_two_solvers_really_do_disagree(tmp_path):
    """Guards the demo above from becoming vacuous: if both solvers emitted the
    SAME witness, 'both pass' would prove nothing about solver independence."""
    a = json.loads((_build(tmp_path / "cg", solver="cg") / _WITNESS_REL).read_bytes())
    b = json.loads(
        (_build(tmp_path / "dense", solver="dense") / _WITNESS_REL).read_bytes()
    )
    assert a["u"] != b["u"], "the two solvers produced identical witnesses"
    assert max(abs(x - y) for x, y in zip(a["u"], b["u"])) > 0.0


def test_verifier_never_runs_a_solver(tmp_path):
    """The certificate is solver-independent by construction. Structurally: the
    verifier-side primitive must not import the producer's solver module."""
    src = (
        _PKG_ROOT / "audit_bundle" / "rederivation" / "primitives" / "fea_witness_cert.py"
    ).read_text(encoding="utf-8")
    assert "_producer_solve" not in src


# --------------------------------------------------------------------------- #
# Gate B — the claim is the producer's, never the verifier's
# --------------------------------------------------------------------------- #


def test_producer_does_not_import_the_verifier(tmp_path):
    """AST, not substring: both producer modules DISCUSS the rule in prose, so a
    text search matches its own documentation and proves nothing."""
    import ast

    for mod in ("_build_bundle.py", "_producer_solve.py"):
        tree = ast.parse((_PILOT / mod).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module)
        offending = {
            m
            for m in imported
            if m == "audit_bundle.rederivation.primitives"
            or m.startswith("audit_bundle.rederivation.primitives.")
        }
        assert not offending, (
            f"{mod} imports the verifier's own primitive {sorted(offending)} — the "
            f"certificate would be checking its own output"
        )


# --------------------------------------------------------------------------- #
# Tamper surfaces
# --------------------------------------------------------------------------- #


def test_tampered_claim_fails(tmp_path):
    bundle = _build(tmp_path / "b")
    path = bundle / _SIGMA_OUT
    doc = json.loads(path.read_bytes())
    doc["value"]["value"] += 1.0  # far outside the certified interval
    path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign(bundle, _SIGMA_OUT)

    result = _verify(bundle)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in {f.reason_code for f in result.failures}


def test_perturbed_witness_fails_equilibrium(tmp_path):
    """Move one free DOF. The claim is untouched and the file SHA is realigned,
    so only the physics can catch this."""
    bundle = _build(tmp_path / "b")
    path = bundle / _WITNESS_REL
    doc = json.loads(path.read_bytes())
    doc["u"][-1] += 1e-3
    path.write_bytes(json.dumps(doc, indent=2, sort_keys=True).encode("utf-8"))
    _realign(bundle, _WITNESS_REL)

    result = _verify(bundle)
    assert not result.ok
    assert "EQUILIBRIUM" in _details(result).upper()


def test_understated_certified_interval_fails(tmp_path):
    """The interval is the auditor's published bound. Committing a smaller one
    claims more precision than the certificate supports."""
    bundle = _build(tmp_path / "b")
    path = bundle / _SIGMA_OUT
    doc = json.loads(path.read_bytes())
    doc["value"]["certified_interval"] /= 1000.0
    path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign(bundle, _SIGMA_OUT)

    result = _verify(bundle)
    assert not result.ok


# --------------------------------------------------------------------------- #
# The auditor pins the PROBLEM (H1)
# --------------------------------------------------------------------------- #


def test_honest_analysis_of_a_lighter_load_case_is_refused_when_anchored(tmp_path):
    bundle = _build(tmp_path / "light", load_scale=0.5)
    result = _verify(bundle)
    assert not result.ok
    assert "INPUT_ANCHOR_MISMATCH" in _details(result)


def test_the_same_lighter_case_passes_UNANCHORED(tmp_path):
    """The counterfactual that gives the previous test its meaning: without the
    auditor's input anchor the substituted problem verifies clean, because the
    witness really does satisfy equilibrium for the problem it was handed. The
    anchor — not the mathematics — is what refuses it."""
    bundle = _build(tmp_path / "light", load_scale=0.5)

    spec = json.loads(_SPEC_SRC.read_bytes())
    for tdef in spec["types"].values():
        params = tdef["comparator"]["params"]
        params.pop("input_anchor", None)
        params["conditioning_bound"] = False  # a delta requires the full anchor
    spec["spec_id"] = "witness.cert.unanchored.v1"
    spec_bytes = (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")
    unanchored = tmp_path / "unanchored.spec.json"
    unanchored.write_bytes(spec_bytes)

    # The bundle must SHIP the spec the auditor anchored: the verifier resolves
    # the authoritative spec from manifest.spec_files and checks its bytes
    # against the anchor. Swap the bundle's copy and re-pin its SHA.
    (bundle / "spec" / "witness_cert.spec.json").write_bytes(spec_bytes)
    manifest_pre = json.loads((bundle / "manifest.json").read_bytes())
    manifest_pre["spec_files"]["witness_cert.spec.json"] = hashlib.sha256(
        spec_bytes
    ).hexdigest()
    (bundle / "manifest.json").write_bytes(
        json.dumps(manifest_pre, indent=2).encode("utf-8")
    )

    # Without conditioning_bound the claim is a plain scalar, not
    # {value, certified_interval}.
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for entry in manifest["outputs"]:
        rel = f"outputs/{entry['output_id']}.json"
        doc = json.loads((bundle / rel).read_bytes())
        doc["value"] = doc["value"]["value"]
        (bundle / rel).write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
        _realign(bundle, rel)

    result = _verify(bundle, spec_src=unanchored)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# The anchor may not come from inside the bundle
# --------------------------------------------------------------------------- #


def test_anchor_taken_from_inside_the_bundle_is_refused(tmp_path):
    bundle = _build(tmp_path / "b")
    with pytest.raises(Exception) as exc:
        SpecAnchor.from_files([bundle / "spec" / "witness_cert.spec.json"],
                              forbid_within=bundle)
    assert "INSIDE" in str(exc.value).upper() or "within" in str(exc.value).lower()


def test_pilot_verify_entry_point_passes(tmp_path):
    mod = _load_verify_module()
    bundle = _build(tmp_path / "b")
    assert mod.make_verifier(bundle).verify(bundle).ok
