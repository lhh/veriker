"""equilibrium_residual_recompute.py — AUDITOR-SIDE certificate primitive.

The cheap half of the solve/verify asymmetry. This module NEVER solves for the
corner loads. It takes the loads the producer already published and evaluates
whether they satisfy the three rigid-body equilibrium conditions that any
physically realisable set of four contact-patch loads must satisfy:

    vertical :  (FL + FR + RL + RR) - m*g
    pitch    :  (FL + FR)*a - (RL + RR)*b + m*ax*h
    roll     :  (FR + RR - FL - RL)*(t/2) - m*ay*h

Each is a handful of multiply-adds per sample. There is no iteration, no
factorisation, no closure model, and -- the point for a partner who will not
share their physics -- NO SUSPENSION OR TIRE PARAMETERS. This module reads
only mass, wheelbase geometry, track width and CG height. The roll-stiffness
model that the producer needs in order to SOLVE is not needed in order to
CHECK, and is never loaded here.

Exactness
---------
Every committed input is a decimal STRING, so `Fraction(s)` is exact and the
residual is an exact rational. The accept path therefore contains no floating
point at all: the producer's solve is float (as real solvers are) and the
auditor's check is exact. The only approximate object anywhere in the decision
is the auditor's declared epsilon, which is anchored data, not producer input.

The value returned is max |residual| over the trip for the requested channel,
in the `rational_band` certificate form {"kind": "rational", "num", "den"}.
The comparator -- not this primitive -- decides agreement.

Stdlib only (contract C5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

# Channel id -> the residual it evaluates. Bound by the AUDITOR's spec.
VERTICAL = "corner_load_vertical_residual"
PITCH = "corner_load_pitch_residual"
ROLL = "corner_load_roll_residual"

_CHANNELS = (VERTICAL, PITCH, ROLL)


@dataclass
class CheckStats:
    """Coarse elementary-operation counter for the check half."""

    ops: int = 0
    samples: int = 0


def _load_exact(bundle_dir: Path) -> tuple:
    vehicle_path = bundle_dir / "inputs" / "vehicle_spec.json"
    samples_path = bundle_dir / "inputs" / "trip_samples.json"
    loads_path = bundle_dir / "payload" / "corner_loads.json"
    for p in (vehicle_path, samples_path, loads_path):
        if not p.is_file():
            raise FileNotFoundError(f"required bundle artifact missing: {p}")
    vehicle = json.loads(vehicle_path.read_bytes())
    samples = json.loads(samples_path.read_bytes())
    loads = json.loads(loads_path.read_bytes())
    if not isinstance(samples, list) or not samples:
        raise ValueError("inputs/trip_samples.json must be a non-empty JSON array")
    if not isinstance(loads, list):
        raise ValueError("payload/corner_loads.json must be a JSON array")
    if len(loads) != len(samples):
        raise ValueError(
            f"corner_loads has {len(loads)} record(s) but trip_samples has "
            f"{len(samples)} -- a claim that does not cover the trip cannot be "
            f"checked, and is refused rather than checked partially"
        )
    return vehicle, samples, loads


def max_abs_residual(
    bundle_dir: Path, channel: str, stats: CheckStats | None = None
) -> tuple:
    """Return (max |residual| as Fraction, index of the worst sample).

    Reads ONLY rigid-body geometry from the vehicle spec. Raises on an unknown
    channel rather than defaulting -- a mis-bound spec must fail closed, not
    silently check something else.
    """
    if channel not in _CHANNELS:
        raise ValueError(f"unknown residual channel {channel!r}; known: {_CHANNELS!r}")
    stats = stats if stats is not None else CheckStats()
    vehicle, samples, loads = _load_exact(bundle_dir)

    # Rigid-body geometry only. Deliberately no roll-stiffness / tire terms.
    m = Fraction(vehicle["mass_kg"])
    g = Fraction(vehicle["gravity_mps2"])
    a = Fraction(vehicle["cg_to_front_axle_m"])
    b = Fraction(vehicle["cg_to_rear_axle_m"])
    t = Fraction(vehicle["track_width_m"])
    h = Fraction(vehicle["cg_height_m"])
    weight = m * g

    worst = Fraction(0)
    worst_index = -1
    for index, (sample, corners) in enumerate(zip(samples, loads)):
        stats.samples += 1
        if not isinstance(corners, list) or len(corners) != 4:
            raise ValueError(
                f"payload/corner_loads.json[{index}] must be a 4-element list "
                f"[FL, FR, RL, RR]"
            )
        fl, fr, rl, rr = (Fraction(str(v)) for v in corners)
        if channel == VERTICAL:
            residual = fl + fr + rl + rr - weight
            stats.ops += 4
        elif channel == PITCH:
            ax = Fraction(sample["ax_mps2"])
            residual = (fl + fr) * a - (rl + rr) * b + m * ax * h
            stats.ops += 8
        else:
            ay = Fraction(sample["ay_mps2"])
            residual = (fr + rr - fl - rl) * (t / Fraction(2)) - m * ay * h
            stats.ops += 9
        magnitude = residual if residual >= 0 else -residual
        if magnitude > worst:
            worst = magnitude
            worst_index = index
    return worst, worst_index


class _ChannelResidualPrimitive:
    """Base: each concrete primitive is PINNED to exactly one residual channel.

    One primitive per channel, rather than one primitive reading the channel
    from the spec, for two reasons. The substrate rejects a single primitive_id
    bound by several types under non-identical comparators (§4a.3 monotone
    strictness) -- a producer could otherwise claim the weakest of them. And
    the three channels are not commensurable: vertical is newtons, pitch and
    roll are newton-metres, so a shared epsilon would be dimensionally
    meaningless. The channel is fixed in code and the epsilon travels with it
    in the auditor's anchored spec.
    """

    channel: str = ""

    def _certificate(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        declared = pack_section.get("type")
        if declared != self.channel:
            raise ValueError(
                f"primitive {self.primitive_id!r} is pinned to channel "
                f"{self.channel!r} but the spec bound it to type {declared!r} "
                f"-- a mis-bound spec fails closed rather than checking the "
                f"wrong quantity"
            )
        stats = CheckStats()
        worst, worst_index = max_abs_residual(inputs.bundle_dir, self.channel, stats)
        return RecomputedValue(
            value={
                "kind": "rational",
                "num": worst.numerator,
                "den": worst.denominator,
            },
            detail=(
                f"{self.channel}: worst |residual| over {stats.samples} "
                f"sample(s) at index {worst_index} = {float(worst):.6f} "
                f"({stats.ops} exact rational ops, no solve)"
            ),
        )


# Each concrete primitive defines `recompute` itself rather than inheriting it.
# That is not style: the fleet's producer/verifier sibling reachability analysis
# resolves a bound primitive_id to its DECLARING CLASS and skips a class with no
# methods -- so an inherited-only recompute left this pilot UNRESOLVED, neither
# cleared nor flagged, and the independence check silently vacuous for it.


class VerticalResidualRecompute(_ChannelResidualPrimitive):
    """Sum of the four published loads against m*g. Newtons."""

    primitive_id: str = "corner_load_vertical_residual_recompute"
    channel: str = VERTICAL

    def recompute(self, inputs, pack_section: dict):
        return self._certificate(inputs, pack_section)


class PitchResidualRecompute(_ChannelResidualPrimitive):
    """Longitudinal moment balance about the CG. Newton-metres."""

    primitive_id: str = "corner_load_pitch_residual_recompute"
    channel: str = PITCH

    def recompute(self, inputs, pack_section: dict):
        return self._certificate(inputs, pack_section)


class RollResidualRecompute(_ChannelResidualPrimitive):
    """Lateral moment balance about the CG. Newton-metres."""

    primitive_id: str = "corner_load_roll_residual_recompute"
    channel: str = ROLL

    def recompute(self, inputs, pack_section: dict):
        return self._certificate(inputs, pack_section)
