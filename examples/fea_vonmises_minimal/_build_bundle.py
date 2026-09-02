"""_build_bundle.py — the PRODUCER for fea_vonmises_minimal.

Emits a plane-stress bracket analysis bundle: the committed problem
(mesh / material / boundary conditions), the pinned solver parameters, the
producer's own displacement field, and its claimed `sigma_vm_max`.

    python examples/fea_vonmises_minimal/_build_bundle.py --out-dir DIR

Every claimed number comes from `_producer_solve.py`, the analyst's own copy of
the pinned CST algorithm. This module must never import
`audit_bundle.rederivation.primitives.*` — the verifier's own code — or the
claimed value would be the verifier's recompute and the pilot would certify
nothing. `tests/test_fea_vonmises_minimal.py` enforces that by AST, and the
repo-wide `tests/test_recipe_producer_verifier_disjoint.py` enforces it for
every pilot that binds a distribution primitive, which this one does.

LAYOUT. The bundle is written to `bundle/`, a SUBDIRECTORY, while the auditor's
spec stays in the sibling `spec_pinned/`. An anchor taken from inside the bundle
it judges lets the producer author both sides of the comparison, and
`SpecAnchor.from_files(..., forbid_within=...)` refuses it.

THE TWO ATTACK FLAGS. Every file the re-derivation reads is written by the
PRODUCER, so the auditor pins all four by SHA (§4a.7 `pinned_inputs`). The flags
below exist so the pin's contribution is MEASURED rather than asserted:

  --shear-scale  an entirely honest analysis of a DIFFERENT load case. The
                 claimed stress is correct for the problem it was given, so the
                 verifier re-derives it and agrees. Nothing in the mathematics
                 refuses this; only the pin on `inputs/bcs.json` does.

  --tol          loosens the verifier's own stopping tolerance, which the
                 producer writes into `spec/solver_config.json`. The pin refuses
                 it — but so, measured, does the comparator: under early
                 stopping the producer's and verifier's implementations stop at
                 different points and diverge by 4.1e-4 (tol=1e-1) and 2.7e-5
                 (tol=1e-2), both far above the 1e-9 epsilon, while from
                 tol=1e-3 down the 36-DOF system is fully converged and the
                 answer does not move. So on THIS exemplar the parameter pin is
                 defence in depth, not the thing that catches it. Recorded
                 because a control that is never the load-bearing one should
                 say so.
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

import _producer_solve as analysis  # noqa: E402

_BUNDLE_ID = "fea-vonmises-minimal-0001"
_CREATED_AT = "2026-08-29T00:00:00Z"
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_TYPED_CHECKS = ["file_integrity_many_small"]

_SPEC_SRC = _HERE / "spec_pinned" / "fea_vonmises.spec.json"

_OUTPUT_ID = "fea_sigma_vm_max"
_TYPE_KEY = "fea_vonmises_sigma_vm_max"

# --- The committed problem: a 6x3 node plane-stress bracket, a steel-like plate
#     fixed along x=0 and carrying a downward shear along the free edge.
#     Deliberately a different mesh, material and load from every other FEA
#     fixture in the fleet.
_NX, _NY = 6, 3
_DX, _DY = 1.5, 1.0
_SHEAR_PER_NODE = -85.0

_DEFAULT_TOL = 1e-12
_DEFAULT_MAX_ITER = 5000


def _canonical(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_problem(
    tol: float = _DEFAULT_TOL,
    max_iter: int = _DEFAULT_MAX_ITER,
    shear_scale: float = 1.0,
) -> tuple[dict, dict, dict, dict]:
    """The committed inputs, generated deterministically.

    `shear_scale` exists for ONE demonstration: an analyst who runs a completely
    honest analysis of a DIFFERENT load case. Its claimed stress is right for the
    problem it was handed, so the re-derivation agrees with it — the auditor's
    SHA pin on `inputs/bcs.json` is the only thing that refuses it."""
    nodes = [[x * _DX, y * _DY] for y in range(_NY) for x in range(_NX)]
    elements = []
    for y in range(_NY - 1):
        for x in range(_NX - 1):
            sw = y * _NX + x
            se, nw, ne = sw + 1, sw + _NX, sw + _NX + 1
            # Both triangles wound counter-clockwise.
            elements.append([sw, se, ne])
            elements.append([sw, ne, nw])
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
        "E": 205000.0,
        "nu": 0.29,
        "thickness": 3.0,
    }
    root_nodes = [y * _NX for y in range(_NY)]
    tip_nodes = [y * _NX + (_NX - 1) for y in range(_NY)]
    bcs = {
        "schema": "fea-bcs-v1",
        "dirichlet": [
            {"node": n, "dof": d, "value": 0.0} for n in root_nodes for d in ("x", "y")
        ],
        "neumann": [
            {"node": n, "dof": "y", "value": _SHEAR_PER_NODE * shear_scale}
            for n in tip_nodes
        ],
    }
    solver_config = {
        "schema": "fea-solver-config-v1",
        "solver": "cg",
        "tol": tol,
        "max_iter": max_iter,
        "preconditioner": "none",
    }
    return mesh, material, bcs, solver_config


def build(
    out_dir: Path,
    tol: float = _DEFAULT_TOL,
    max_iter: int = _DEFAULT_MAX_ITER,
    shear_scale: float = 1.0,
) -> None:
    out_dir = Path(out_dir).resolve()
    mesh, material, bcs, solver_config = build_problem(tol, max_iter, shear_scale)
    u, sigma_vm_max = analysis.solve(mesh, material, bcs, solver_config)

    files = {
        "inputs/mesh.json": _canonical(mesh),
        "inputs/material.json": _canonical(material),
        "inputs/bcs.json": _canonical(bcs),
        "payload/displacement_field.json": _canonical(
            {"schema": "fea-displacement-field-v1", "u": u}
        ),
        "payload/output_norms.json": _canonical(
            {"schema": "fea-output-norms-v1", "sigma_vm_max": sigma_vm_max}
        ),
    }
    spec_files = {"solver_config.json": _canonical(solver_config)}
    extra: dict = {}

    # The auditor's binding spec, if it exists yet. (It is generated from the
    # committed inputs by spec_pinned/_generate_auditor_spec.py; absent = the
    # bootstrap build that generator itself runs.)
    if _SPEC_SRC.is_file():
        spec_bytes = _SPEC_SRC.read_bytes()
        spec_files[_SPEC_SRC.name] = spec_bytes
        files[f"outputs/{_OUTPUT_ID}.json"] = _canonical({"value": sigma_vm_max})
        extra["outputs"] = [
            {
                "output_id": _OUTPUT_ID,
                "type": _TYPE_KEY,
                "conforms_to": f"spec/{_SPEC_SRC.name}",
            }
        ]

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
    print(
        f"  mesh            : {len(mesh['nodes'])} nodes, "
        f"{len(mesh['elements'])} CST elements"
    )
    print(f"  solver          : cg, tol={tol!r}, max_iter={max_iter!r}")
    print(f"  sigma_vm_max    : {sigma_vm_max!r}")
    print(f"  claims declared : {len(extra.get('outputs', []))}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the fea_vonmises_minimal bundle")
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=_HERE / "bundle",
        help="where to write the bundle (default: the committed bundle/ subdir)",
    )
    ap.add_argument(
        "--tol",
        type=float,
        default=_DEFAULT_TOL,
        help="solver stopping tolerance written into spec/solver_config.json — "
        "loosening it is the producer-controlled-parameter attack the auditor's "
        "SHA pin refuses",
    )
    ap.add_argument("--max-iter", type=int, default=_DEFAULT_MAX_ITER)
    ap.add_argument(
        "--shear-scale",
        type=float,
        default=1.0,
        help="scale the applied shear — a DIFFERENT problem, honestly solved "
        "(used to demonstrate the auditor's input pin refusing it)",
    )
    args = ap.parse_args()
    build(args.out_dir.resolve(), args.tol, args.max_iter, args.shear_scale)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
