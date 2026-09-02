"""_generate_auditor_spec.py — AUDITOR-side generator for this pilot's binding
spec.

Run when the committed problem changes:

    python examples/fea_vonmises_minimal/spec_pinned/_generate_auditor_spec.py

It builds a bundle from the producer's deterministic inputs, hashes each file the
verifier's re-derivation READS, and writes those hashes into the spec's
`pinned_inputs` (§4a.7) alongside the authority-pinned comparator.

`spec/solver_config.json` is pinned for a reason worth stating: the primitive
takes its own stopping tolerance and iteration cap from that file, and the
PRODUCER writes it. Unpinned, a producer could loosen `tol`, stop the solve
early, claim the early-stopped stress and watch the verifier reproduce it
exactly. Pinning it makes the acceptance criterion authority-fixed all the way
down to the arithmetic, not only at the epsilon.

This module stands in for the auditor, so it MAY read the verifier's side. The
producer may not — see `_build_bundle.py`.
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

import _build_bundle as producer  # noqa: E402

_SPEC_ID = "fea.vonmises.minimal.v1"
_TYPE_KEY = "fea_vonmises_sigma_vm_max"
_PRIMITIVE_ID = "fea_vonmises_recompute"
_EPSILON = 1e-09

#: Every bundle file the bound primitive reads. All four are pinned by SHA.
_CONSUMED = (
    "inputs/mesh.json",
    "inputs/material.json",
    "inputs/bcs.json",
    "spec/solver_config.json",
)

_DESCRIPTION = (
    "Auditor binding spec for fea_vonmises_minimal. The representative "
    "re-derived output is the scalar sigma_vm_max: re-assemble the global CST "
    "plane-stress stiffness from inputs/{mesh,material,bcs}.json, re-run the "
    "committed conjugate-gradient solve with the tol/max_iter in "
    "spec/solver_config.json, and recover the maximum von-Mises stress. The "
    "ACCEPTANCE epsilon is authority-pinned HERE, never read from the "
    "producer's solver_config (Path-beta). Every file the recompute CONSUMES is "
    "pinned by SHA in pinned_inputs (section 4a.7) — including "
    "spec/solver_config.json, because the producer writes that file and the "
    "verifier takes its own stopping tolerance from it. MEASURED CAVEAT on that "
    "last point, recorded rather than assumed: on this committed problem "
    "loosening tol does not in fact slip past the comparator (the two "
    "implementations diverge under early stopping by far more than the band), "
    "so the parameter pin is defence in depth here and the pin on "
    "inputs/bcs.json is the one demonstrably doing work. "
    "WHY A TOLERANCE AT ALL, and why THIS one. The producer runs its own "
    "implementation of the same pinned algorithm. The two are not bit-identical "
    "and the reason is exact and singular: the verifier's matrix-vector product "
    "is a builtin sum() over a generator, which on CPython 3.12 applies "
    "compensated (Neumaier) summation, while the producer accumulates in an "
    "explicit loop, which does not. From conjugate-gradient iteration 2 onward "
    "8 of the 36 rows differ in the last bits, and the difference reaches "
    "sigma_vm_max as 1.4e-12 (measured, CPython 3.12.3). Because that "
    "compensation is an interpreter implementation detail rather than a "
    "property of IEEE-754, an `exact` comparator would bind the claim to one "
    "interpreter; epsilon=1e-9 is roughly 700x the measured difference and "
    "still about five orders below any physically meaningful change in the "
    "stress. NUMERIC MODEL (numeric_model=binary64_exact): every operation is "
    "IEEE-754 double plus math.sqrt, which is correctly rounded and therefore "
    "bit-identical across platforms; no libm transcendental is involved, so the "
    "residual difference is a summation-rounding artifact of the same "
    "arithmetic and NOT a margin for a different method."
)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle"
        producer.build(bundle)
        pinned = {
            rel: hashlib.sha256((bundle / rel).read_bytes()).hexdigest()
            for rel in _CONSUMED
        }

    spec = {
        "spec_id": _SPEC_ID,
        "description": _DESCRIPTION,
        "types": {
            _TYPE_KEY: {
                "primitive_id": _PRIMITIVE_ID,
                "comparator": {
                    "kind": "scalar_epsilon",
                    "params": {
                        "epsilon": _EPSILON,
                        "numeric_model": "binary64_exact",
                    },
                },
                "pinned_inputs": pinned,
            }
        },
    }
    (_HERE / "fea_vonmises.spec.json").write_bytes(
        (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    print("wrote fea_vonmises.spec.json")
    for rel, sha in pinned.items():
        print(f"  pinned {rel}: {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
