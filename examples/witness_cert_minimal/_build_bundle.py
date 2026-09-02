"""_build_bundle.py — the PRODUCER for witness_cert_minimal.

Emits a plane-stress cantilever analysis bundle: the committed problem
(mesh / material / boundary conditions), the solver configuration, the
DISPLACEMENT FIELD as a witness, and the producer's claimed quantities.

    python examples/witness_cert_minimal/_build_bundle.py --out-dir DIR
    python examples/witness_cert_minimal/_build_bundle.py --out-dir DIR --solver dense

`--solver` selects which of the two independent solvers in `_producer_solve.py`
produces the witness. Both satisfy equilibrium; both pass the same auditor
certificate. Nothing about the choice is recorded in the acceptance criterion.

LAYOUT IS THE LESSON. The bundle is written to `bundle/`, a SUBDIRECTORY, while
the auditor's spec stays in the sibling `spec_pinned/`. That is not tidiness: an
anchor taken from inside the bundle it judges lets the producer author both
sides of the comparison, and `SpecAnchor.from_files(..., forbid_within=...)`
refuses it. Committing the bundle at the pilot root would put `spec_pinned/`
inside the audited directory and the verifier would (correctly) refuse to run.

GATE B: every claimed number here comes from `_producer_solve.py`. This module
must never import `audit_bundle.rederivation.primitives.*` — the verifier's own
code — or the certificate would be checking its own output.

The one number this producer does NOT compute is `certified_interval`: that is
the AUDITOR's published bound (spec_pinned/auditor_intervals.json), copied into
the claim and RE-DERIVED by the verifier. Understating it fails closed, so
copying it asserts nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

import _producer_solve as solver  # noqa: E402

_BUNDLE_ID = "witness-cert-minimal-0001"
_CREATED_AT = "2026-08-29T00:00:00Z"
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_TYPED_CHECKS = ["file_integrity_many_small"]

_SPEC_SRC = _HERE / "spec_pinned" / "witness_cert.spec.json"
_INTERVALS_SRC = _HERE / "spec_pinned" / "auditor_intervals.json"

# (output_id, spec type key, producer field)
_OUTPUTS = (
    ("wc_sigma_vm_max", "witness_cert_sigma_vm_max", "sigma_vm_max"),
    ("wc_u_norm_2", "witness_cert_u_norm_2", "u_norm_2"),
    ("wc_u_norm_inf", "witness_cert_u_norm_inf", "u_norm_inf"),
)

# --- The committed problem: a 4x3 cantilever plate, fixed along x=0, loaded
#     downward along x=3. Bending, not tension — deliberately a different
#     problem shape from any other FEA fixture in the fleet.
_NX, _NY = 4, 3
_LOAD_Y = -120.0


def _canonical(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_problem(load_scale: float = 1.0) -> tuple[dict, dict, dict, dict]:
    """The committed inputs, generated deterministically.

    `load_scale` exists for ONE demonstration: an analyst who runs an entirely
    honest analysis of a LIGHTER load case. Its witness satisfies equilibrium
    for the problem it was given, so an unanchored certificate passes it. The
    auditor's `input_anchor` is what refuses it — the auditor pins the problem,
    not just the mathematics."""
    nodes = [[float(x), float(y)] for y in range(_NY) for x in range(_NX)]
    elements = []
    for y in range(_NY - 1):
        for x in range(_NX - 1):
            n0 = y * _NX + x
            n1, n2, n3 = n0 + 1, n0 + _NX, n0 + _NX + 1
            elements.append([n0, n1, n2])
            elements.append([n1, n3, n2])
    mesh = {
        "schema": "fea-mesh-v1",
        "dim": 2,
        "element_type": "CST",
        "nodes": nodes,
        "elements": elements,
    }
    material = {
        "schema": "fea-material-v1",
        "model": "linear_elastic_isotropic",
        "stress_state": "plane_stress",
        "E": 70000.0,
        "nu": 0.33,
        "thickness": 2.0,
    }
    fixed_nodes = [y * _NX for y in range(_NY)]
    loaded_nodes = [y * _NX + (_NX - 1) for y in range(_NY)]
    bcs = {
        "schema": "fea-bcs-v1",
        "dirichlet": [
            {"node": n, "dof": d, "value": 0.0} for n in fixed_nodes for d in ("x", "y")
        ],
        "neumann": [
            {"node": n, "dof": "y", "value": _LOAD_Y * load_scale}
            for n in loaded_nodes
        ],
    }
    solver_config = {
        "schema": "fea-solver-config-v1",
        "solver": "cg",
        "tol": 1e-10,
        "max_iter": 2000,
        "preconditioner": "none",
    }
    return mesh, material, bcs, solver_config


def solve(mesh: dict, material: dict, bcs: dict, cfg: dict, kind: str):
    """Run the chosen producer solver. Returns (u, norms)."""
    k, element_data = solver.assemble(mesh, material)
    f = [0.0] * (len(mesh["nodes"]) * 2)
    solver.apply_neumann(f, bcs["neumann"])
    solver.apply_dirichlet(k, f, bcs["dirichlet"])
    u = solver.SOLVERS[kind](k, f, cfg["tol"], cfg["max_iter"])
    return u, solver.output_norms(u, element_data)


def build(out_dir: Path, solver_kind: str = "cg", load_scale: float = 1.0) -> None:
    out_dir = Path(out_dir).resolve()
    mesh, material, bcs, cfg = build_problem(load_scale)
    cfg = {**cfg, "solver": solver_kind}
    u, norms = solve(mesh, material, bcs, cfg, solver_kind)

    files = {
        "inputs/mesh.json": _canonical(mesh),
        "inputs/material.json": _canonical(material),
        "inputs/bcs.json": _canonical(bcs),
        "payload/displacement_field.json": _canonical(
            {"schema": "fea-displacement-witness-v1", "u": u}
        ),
        "payload/output_norms.json": _canonical(
            {"schema": "fea-output-norms-v1", **norms}
        ),
    }
    spec_files = {"solver_config.json": _canonical(cfg)}
    extra: dict = {}

    # The auditor's binding spec + published intervals, if they exist yet.
    # (They are generated from the committed inputs by
    # spec_pinned/_generate_auditor_spec.py; absent = bootstrap build.)
    if _SPEC_SRC.is_file() and _INTERVALS_SRC.is_file():
        spec_bytes = _SPEC_SRC.read_bytes()
        spec_files[_SPEC_SRC.name] = spec_bytes
        intervals = json.loads(_INTERVALS_SRC.read_bytes())
        types_present = json.loads(spec_bytes)["types"]
        outputs = []
        for output_id, type_key, field in _OUTPUTS:
            if type_key not in types_present:
                continue
            # The dispatch envelope is {"value": <claimed>}. Under
            # conditioning_bound the CLAIMED VALUE is itself the object
            # {value, certified_interval}, so it nests.
            claimed: object = norms[field]
            if type_key in intervals:
                claimed = {
                    "value": norms[field],
                    "certified_interval": intervals[type_key],
                }
            files[f"outputs/{output_id}.json"] = _canonical({"value": claimed})
            outputs.append({"output_id": output_id, "type": type_key})
        extra["outputs"] = outputs

    write_bundle(
        out_dir,
        BundleContent(
            bundle_id=_BUNDLE_ID,
            created_at=_CREATED_AT,
            schema_version=_SCHEMA_VERSION,
            files=files,
            spec_files=spec_files,
            typed_checks=_TYPED_CHECKS,
            extra_manifest_fields=extra,
        ),
    )
    print(f"Bundle written to {out_dir}")
    print(f"  solver           : {solver_kind}")
    print(f"  mesh             : {len(mesh['nodes'])} nodes, {len(mesh['elements'])} CST elements")
    print(f"  sigma_vm_max     : {norms['sigma_vm_max']!r}")
    print(f"  claims declared  : {len(extra.get('outputs', []))}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the witness_cert_minimal bundle")
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=_HERE / "bundle",
        help="where to write the bundle (default: the committed bundle/ subdir)",
    )
    ap.add_argument("--solver", choices=sorted(solver.SOLVERS), default="cg")
    ap.add_argument(
        "--load-scale",
        type=float,
        default=1.0,
        help="scale the applied load — a DIFFERENT problem, honestly solved "
        "(used to demonstrate the auditor's input anchor refusing it)",
    )
    args = ap.parse_args()
    build(args.out_dir.resolve(), args.solver, args.load_scale)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
