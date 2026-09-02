"""_build_bundle.py — build a corner_load_equilibrium_minimal audit bundle.

Domain: vehicle-dynamics per-corner vertical load estimation. A tire digital
twin publishes four contact-patch loads per sample, inferred from in-vehicle
signals with no load sensor anywhere in the loop.

What the producer does here (BOTH halves are producer code):
  1. _producer_solve.py      -- the reference solve that cannot run on an ECU:
                                Newton iteration on a progressive-roll-stiffness
                                cubic, per sample. Satisfies equilibrium by
                                construction.
  2. _producer_surrogate.py  -- the deployed approximation: four independently
                                ridge-fitted per-corner models, trained offline
                                against (1), evaluated in a few operations per
                                sample. Satisfies nothing by construction.

The bundle publishes the SURROGATE's loads, because that is what the vehicle
actually emits. The reference solve never ships.

Profiles
--------
  --profile clean   trip stays inside the surrogate's training envelope
  --profile drift   trip leaves it (|ay| beyond the trained range)

BOTH bundles are internally consistent: every SHA matches, the manifest is
well-formed, nothing is tampered. The drift bundle fails ONLY the physics. That
is the demonstration -- byte integrity cannot see this class of defect, and a
re-derivation that re-ran the producer's own model could not see it either,
because the producer's model is the thing that is wrong.

GATE B (producer/verifier non-tautology)
----------------------------------------
Neither module above is importable by the verifier, and the verifier does not
contain a solver. The auditor evaluates residuals of the published loads --
a structurally different computation from producing them, roughly three orders
of magnitude cheaper (measured, printed at build time). This is the property
that makes the check independent: it is not a re-run of the producer's pack.

Usage:
    python examples/corner_load_equilibrium_minimal/_build_bundle.py \
        --out-dir /tmp/corner_load_clean --profile clean
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util as _ilu
import json
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_CREATED_AT = "2026-08-30T00:00:00Z"

_SPEC_SRC = _HERE / "spec_pinned" / "corner_load_equilibrium.spec.json"

_OUTPUT_IDS = {
    "corner_load_vertical_residual": "corner_load_vertical_residual",
    "corner_load_pitch_residual": "corner_load_pitch_residual",
    "corner_load_roll_residual": "corner_load_roll_residual",
}

# Vehicle parameters as exact decimal STRINGS. The first six are rigid-body
# geometry the auditor reads. The remainder describe the suspension and are
# used ONLY by the producer's solver -- the auditor never loads them.
_VEHICLE = {
    "vehicle_id": "SYNTH-D-SEGMENT-01",
    "mass_kg": "1850",
    "gravity_mps2": "9.80665",
    "cg_to_front_axle_m": "1.28",
    "cg_to_rear_axle_m": "1.52",
    "track_width_m": "1.58",
    "cg_height_m": "0.55",
    "sprung_mass_kg": "1620",
    "roll_moment_arm_m": "0.42",
    "roll_stiffness_nm_per_rad": "58000",
    "roll_stiffness_cubic_nm_per_rad3": "410000",
    "front_roll_stiffness_fraction": "0.58",
    "front_roll_stiffness_phi_gain": "1.35",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def _decimal(numerator: int, scale: int = 10) -> str:
    """Exact one-decimal string from an integer tenths value."""
    sign = "-" if numerator < 0 else ""
    whole, frac = divmod(abs(numerator), scale)
    return f"{sign}{whole}.{frac}"


def _make_samples(count: int, ax_tenths: int, ay_tenths: int, phase: int) -> list:
    """Deterministic synthetic trip. No RNG: the sequence is a fixed integer
    walk so the bundle is byte-reproducible on any platform."""
    samples = []
    for i in range(count):
        ax = ((i * 37 + phase) % (2 * ax_tenths + 1)) - ax_tenths
        ay = ((i * 23 + phase * 3) % (2 * ay_tenths + 1)) - ay_tenths
        samples.append(
            {
                "t_ms": i * 20,
                "ax_mps2": _decimal(ax),
                "ay_mps2": _decimal(ay),
            }
        )
    return samples


def _load_producer_module(name: str, filename: str):
    """Load a producer module by PATH under a builder-private name, so the
    verifier's sys.modules namespace is never touched."""
    private_name = f"corner_load_equilibrium_minimal__{name}"
    spec = _ilu.spec_from_file_location(private_name, _HERE / filename)
    module = _ilu.module_from_spec(spec)
    # Register before exec: @dataclass resolves annotations via
    # sys.modules[cls.__module__], which is None for an unregistered
    # path-loaded module.
    sys.modules[private_name] = module
    spec.loader.exec_module(module)
    return module


def build(out_dir: Path, profile: str) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / "inputs"
    payload_dir = out_dir / "payload"
    spec_dir = out_dir / "spec"
    outputs_dir = out_dir / "outputs"
    for d in (inputs_dir, payload_dir, spec_dir, outputs_dir):
        d.mkdir(parents=True, exist_ok=True)

    solve_mod = _load_producer_module("solve", "_producer_solve.py")
    surrogate_mod = _load_producer_module("surrogate", "_producer_surrogate.py")

    # --- Offline: run the expensive reference solve over the TRAINING trip ---
    train_samples = _make_samples(240, ax_tenths=30, ay_tenths=40, phase=0)
    train_stats = solve_mod.SolveStats()
    infer_stats = surrogate_mod.SurrogateStats()
    producer_t0 = time.perf_counter()
    train_targets = solve_mod.solve_corner_loads(_VEHICLE, train_samples, train_stats)
    models = surrogate_mod.fit(train_samples, train_targets, infer_stats)
    producer_seconds = time.perf_counter() - producer_t0

    # --- The trip the vehicle actually drives -------------------------------
    if profile == "clean":
        trip = _make_samples(120, ax_tenths=28, ay_tenths=35, phase=7)
    elif profile == "drift":
        trip = _make_samples(120, ax_tenths=28, ay_tenths=75, phase=7)
    else:  # pragma: no cover - argparse constrains this
        raise ValueError(f"unknown profile {profile!r}")

    # --- In-vehicle: the surrogate publishes four loads per sample ----------
    corner_loads = surrogate_mod.predict(models, trip, infer_stats)

    vehicle_bytes = _canonical_json_bytes(_VEHICLE)
    trip_bytes = _canonical_json_bytes(trip)
    loads_bytes = _canonical_json_bytes(corner_loads)
    (inputs_dir / "vehicle_spec.json").write_bytes(vehicle_bytes)
    (inputs_dir / "trip_samples.json").write_bytes(trip_bytes)
    (payload_dir / "corner_loads.json").write_bytes(loads_bytes)

    spec_bytes = _SPEC_SRC.read_bytes()
    (spec_dir / _SPEC_SRC.name).write_bytes(spec_bytes)

    # --- The producer's claim -----------------------------------------------
    # The twin publishes loads and, by publishing them as physical loads,
    # asserts they are physically realisable: zero equilibrium residual. It
    # does not check this -- nothing in the model can. That unexamined
    # assertion is exactly what the auditor re-derives.
    claim_files = {}
    for output_id in _OUTPUT_IDS.values():
        claim_bytes = json.dumps({"value": 0}, indent=2).encode("utf-8")
        (outputs_dir / f"{output_id}.json").write_bytes(claim_bytes)
        claim_files[f"outputs/{output_id}.json"] = _sha256(claim_bytes)

    files = {
        "inputs/vehicle_spec.json": _sha256(vehicle_bytes),
        "inputs/trip_samples.json": _sha256(trip_bytes),
        "payload/corner_loads.json": _sha256(loads_bytes),
        **claim_files,
    }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": f"corner-load-equilibrium-minimal-{profile}",
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {_SPEC_SRC.name: _sha256(spec_bytes)},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "fragment_anchors": {},
        "outputs": [
            {
                "output_id": output_id,
                "type": type_name,
                "conforms_to": f"spec/{_SPEC_SRC.name}",
            }
            for type_name, output_id in _OUTPUT_IDS.items()
        ],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    # NOTE: this script deliberately does NOT import the auditor's residual
    # module, even to print a diagnostic. A producer module importing symbols
    # the bound primitive reaches is the sibling-tautology pattern, and the
    # fleet ratchet refuses it on structure rather than intent -- correctly:
    # the claim written above is the constant 0, but a later edit that wrote a
    # MEASURED residual there would turn this pilot into a function agreeing
    # with itself, and a blessed import would have hidden it. The residual and
    # produce-vs-check figures are reported by hard_negatives.py, on the
    # auditor's side, where computing them is the whole job.

    print(f"Bundle written to {out_dir}")
    print(f"  profile            : {profile}")
    print(f"  trip samples       : {len(trip)}")
    print(f"  saturated preds    : {infer_stats.saturated_predictions} of {len(trip) * 4}")
    print("  --- producer cost to be ABLE to publish this claim ---")
    print(f"    reference solves : {train_stats.samples} "
          f"({train_stats.newton_iterations} Newton iterations)")
    print(f"    solve + fit ops  : {train_stats.ops + infer_stats.fit_ops:,d}"
          f"   {producer_seconds * 1000:.1f} ms")
    print(f"    inference ops    : {infer_stats.ops:,d} for {len(trip)} samples")
    print("  (auditor-side residuals + cost: hard_negatives.py)")
    return {
        "producer_ops": train_stats.ops + infer_stats.fit_ops,
        "producer_seconds": producer_seconds,
        "trip_samples": len(trip),
        "saturated_predictions": infer_stats.saturated_predictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a corner_load_equilibrium_minimal audit bundle"
    )
    parser.add_argument("--out-dir", required=False, type=Path, default=_HERE)
    parser.add_argument(
        "--profile", choices=("clean", "drift"), default="clean",
        help="clean = trip inside the surrogate's training envelope; "
             "drift = trip outside it",
    )
    args = parser.parse_args()
    build(args.out_dir.resolve(), args.profile)
    return 0


if __name__ == "__main__":
    sys.exit(main())
