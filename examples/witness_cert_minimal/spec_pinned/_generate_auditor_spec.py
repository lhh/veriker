"""_generate_auditor_spec.py — AUDITOR-side generator for this pilot's binding
spec and published certified intervals.

Run when the committed problem changes:

    python examples/witness_cert_minimal/spec_pinned/_generate_auditor_spec.py

It builds a bundle from the producer's deterministic inputs, hashes the three
committed input roles into `input_anchor`, writes `witness_cert.spec.json`, then
runs the certificate to publish the exact certified interval eps+delta per
quantity into `auditor_intervals.json`.

This module IS allowed to import the verifier's primitive — it stands in for the
auditor, not the producer. `_build_bundle.py` must never do so (Gate B).
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PILOT = _HERE.parent
_PKG_ROOT = _HERE.resolve().parents[2]
for p in (str(_PKG_ROOT), str(_PILOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from audit_bundle.rederivation.primitives.fea_witness_cert import (  # noqa: E402
    certified_interval_ceil_float,
)

import _build_bundle as producer  # noqa: E402

_EPSILON = 1e-06
_EQUILIBRIUM_TOL = 1e-06
_TYPES = (
    ("witness_cert_sigma_vm_max", "fea_witness_certificate", "rational_sqrt_band"),
    ("witness_cert_u_norm_2", "fea_witness_certificate_u_norm_2", "rational_sqrt_band"),
    ("witness_cert_u_norm_inf", "fea_witness_certificate_u_norm_inf", "rational_band"),
)
_QUANTITY = {
    "witness_cert_sigma_vm_max": "sigma_vm_max",
    "witness_cert_u_norm_2": "u_norm_2",
    "witness_cert_u_norm_inf": "u_norm_inf",
}

_DESCRIPTION = (
    "Auditor binding spec for witness_cert_minimal. The WHOLE acceptance "
    "criterion is authority-pinned here and none of it is producer-asserted: "
    "epsilon (the claim band around the witness-implied quantity), "
    "equilibrium_tol (free-DOF residual of the ORIGINAL K), input_anchor "
    "(sha256 of the canonical committed inputs — the auditor pins the PROBLEM, "
    "so an honest witness for a substituted lighter load case is refused), and "
    "conditioning_bound (the verifier re-derives the exact certified interval "
    "eps+delta and REFUSES a committed interval below it). The witness is "
    "deliberately NOT anchored: it is the producer's asserted solution, and the "
    "certificate's job is to check it, not to trust it. The verifier never runs "
    "a solver, so any solver that satisfies equilibrium is accepted."
)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle"
        producer.build(bundle, "cg")

        anchor = {
            role: hashlib.sha256((bundle / rel).read_bytes()).hexdigest()
            for role, rel in (
                ("mesh", "inputs/mesh.json"),
                ("material", "inputs/material.json"),
                ("bcs", "inputs/bcs.json"),
            )
        }
        params = {
            "epsilon": _EPSILON,
            "equilibrium_tol": _EQUILIBRIUM_TOL,
            "input_anchor": anchor,
            "conditioning_bound": True,
        }
        spec = {
            "spec_id": "witness.cert.v1",
            "description": _DESCRIPTION,
            "types": {
                tkey: {
                    "primitive_id": pid,
                    "comparator": {"kind": kind, "params": dict(params)},
                }
                for tkey, pid, kind in _TYPES
            },
        }
        (_HERE / "witness_cert.spec.json").write_bytes(
            (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )

        intervals = {
            tkey: certified_interval_ceil_float(bundle, params, _QUANTITY[tkey])
            for tkey, _pid, _kind in _TYPES
        }
        (_HERE / "auditor_intervals.json").write_bytes(
            (json.dumps(intervals, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
    print("wrote witness_cert.spec.json + auditor_intervals.json")
    for k, v in intervals.items():
        print(f"  {k}: certified_interval = {v!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
