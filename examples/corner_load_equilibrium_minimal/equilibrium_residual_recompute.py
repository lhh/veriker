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

import hashlib
import json
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

# Channel id -> the residual it evaluates. Bound by the AUDITOR's spec.
VERTICAL = "corner_load_vertical_residual"
PITCH = "corner_load_pitch_residual"
ROLL = "corner_load_roll_residual"
SPLIT = "corner_load_transfer_split_residual"

_CHANNELS = (VERTICAL, PITCH, ROLL)
_ALL_CHANNELS = (VERTICAL, PITCH, ROLL, SPLIT)

# The RIGID-BODY fields this module reads, and the digest of exactly those.
#
# The pin covers the subset the auditor actually consumes -- NOT the whole
# vehicle_spec.json. `sprung_mass_kg` and the roll-stiffness fields live in that
# file because the producer's own solver needs them to SOLVE; this module is
# documented above as reading no suspension or tire parameters, which is the
# pilot's "a partner who will not share their physics" property. Pinning the
# whole file would make the auditor's verdict depend on producer model
# parameters it is designed never to look at, and would break
# test_auditor_never_reads_the_suspension_model -- which it did, for one commit,
# until the pin was narrowed to this subset.
#
# What the pin still closes: a claim that inflates every published corner load
# AND the vehicle mass by the same factor leaves all three residuals inside
# epsilon (they are scale-invariant under it), so no residual can catch it.
# `mass_kg` is in this subset, so that attack still fails closed.
#
# What it does NOT close: the diagonal (cross-weight) mode -- see
# `_assert_physically_admissible` and the README. In production a fleet or
# engineering authority would sign each CURRENT snapshot of these fields and the
# verifier would validate that signature under an out-of-band key, rather than
# trust a build-time constant that says nothing about whether the spec is still
# current for the vehicle it names.
RIGID_BODY_SPEC_FIELDS = (
    "cg_height_m",
    "cg_to_front_axle_m",
    "cg_to_rear_axle_m",
    "gravity_mps2",
    "mass_kg",
    "track_width_m",
    "vehicle_id",
)

TRUSTED_RIGID_BODY_SPEC_SHA256 = (
    "fb0adc64f37d41d0e6f5a65fdd58c908ceaa641e91d0b54bf003b23b6b7bfbd4"
)


def _rigid_body_digest(vehicle: dict) -> str:
    """sha256 over a canonical serialisation of ONLY the fields read here.

    Keyed on `RIGID_BODY_SPEC_FIELDS` rather than "everything except the
    suspension model", so a NEW producer field cannot silently enter the pinned
    surface, and a missing rigid-body field is a KeyError rather than a quietly
    shorter digest that still matches nothing.
    """
    subset = {k: vehicle[k] for k in RIGID_BODY_SPEC_FIELDS}
    return hashlib.sha256(
        json.dumps(subset, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _assert_physically_admissible(loads: list) -> None:
    """A wheel can push the car up. It cannot pull the car down.

    The sign convention, not a suspension model -- so this costs none of the
    "no producer physics" property above. It is the one constraint on the
    CROSS-WEIGHT direction the three equilibrium channels cannot see: the
    diagonal vector (+d, -d, -d, +d) preserves the load sum, the pitch couple
    and the total lateral transfer exactly, so every residual is blind to it at
    any magnitude. MEASURED 2026-09-03, vehicle spec and trip samples both
    byte-identical: d = 8000 N drove two corners to about -3260 N and -3900 N
    and the bundle still returned PASS, exit 0.

    This bounds that mode; it does not close it. A forger who keeps every corner
    non-negative still has the diagonal freedom, and closing it needs a fourth
    relation -- the front/rear split of lateral load transfer -- which needs a
    suspension coefficient this module deliberately does not read. See the
    README section on what is pinned and what is not.
    """
    for index, row in enumerate(loads):
        for corner, value in zip(("FL", "FR", "RL", "RR"), row):
            if Fraction(str(value)) < 0:
                raise ValueError(
                    f"corner_loads[{index}] declares {corner} = {value} N: a "
                    f"negative contact-patch load means the wheel pulls the "
                    f"vehicle toward the road, which no physically realisable "
                    f"claim can assert. Refused rather than checked -- the three "
                    f"equilibrium residuals are blind to the diagonal mode this "
                    f"rides on, at any magnitude."
                )


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
    # PIN CHECK over the rigid-body subset, before the spec is trusted for
    # anything. trip_samples and corner_loads are NOT pinned -- trip_samples is
    # generated fresh per run, corner_loads is the claim under test -- so this
    # is the one bundle input checkable against a verifier-held reference
    # rather than only against itself.
    actual_sha = _rigid_body_digest(vehicle)
    if actual_sha != TRUSTED_RIGID_BODY_SPEC_SHA256:
        raise ValueError(
            f"inputs/vehicle_spec.json rigid-body fields digest {actual_sha} "
            f"does not match the verifier-pinned "
            f"{TRUSTED_RIGID_BODY_SPEC_SHA256} -- a vehicle spec that differs "
            f"from the auditor's held reference is refused rather than trusted, "
            f"because a consistent scale-up of the published loads AND the "
            f"vehicle mass leaves every equilibrium residual inside epsilon and "
            f"only this pin can catch it"
        )
    samples = json.loads(samples_path.read_bytes())
    loads = json.loads(loads_path.read_bytes())
    if not isinstance(samples, list) or not samples:
        raise ValueError("inputs/trip_samples.json must be a non-empty JSON array")
    if not isinstance(loads, list):
        raise ValueError("payload/corner_loads.json must be a JSON array")
    _assert_physically_admissible(loads)
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


# ---------------------------------------------------------------------------
# Channel 4 -- the front/rear split of lateral load transfer
# ---------------------------------------------------------------------------
# READ THIS BEFORE TRUSTING THE CHANNEL. It is weaker in kind than the three
# above, and the difference is not a detail.
#
# The three equilibrium channels trust NOTHING. They ask whether the published
# loads are physically realisable, and any set that is not fails against laws
# nobody has to vouch for. This channel asks a different question -- whether the
# published loads AGREE WITH A REFERENCE -- and to ask it the auditor must hold
# a calibration that somebody produced. Here that is `_SPLIT_REFERENCE`, swept
# offline across the |ay| envelope from the reference solve. In deployment it
# would come from the producer's own high-fidelity solve on their cluster.
#
# So: an equilibrium failure is a fact about physics. A split excursion is a
# disagreement with a reference the producer supplied. Both are useful; only
# the first is independent of the producer, and no external claim may blur them.
#
# WHY IT EXISTS ANYWAY. Read the producer's solver: the axle loads and the TOTAL
# lateral transfer are "fixed by rigid-body statics (cheap, exact in form)" --
# precisely what channels 1-3 check. The expensive nonlinear roll-angle solve
# determines exactly one thing, `chi`, the front/rear SPLIT of that transfer, and
# `chi` lives in the cross-weight null space the three residuals cannot reach.
# Measured 2026-09-03: chi_0 0.58 -> 0.30 puts 631 N of error on a corner and
# leaves every residual at about 1e-12, while a mis-learned MASS -- needing no
# expensive solve at all -- shows up at 490 N against a 40 N epsilon. Without
# this channel the auditor sees the errors that did not need the cluster and is
# blind to the ones that did.
#
# TWO LIMITS, both measured, neither closed:
#   * RESOLUTION. The anchored epsilon must admit the shipped surrogate, whose
#     own split error reaches 0.0369 over the gated samples, so it is 0.05.
#     Measured: chi_0 0.58 -> 0.55 is NOT caught (deviation 0.03). This channel
#     catches gross mis-learning, not fine error, and must never be described as
#     establishing that a model is accurate.
#   * CONDITIONING. The share is a ratio whose denominator is the total lateral
#     transfer, so it is meaningless in a straight line: at |t| = 0.018 N one
#     sample's measured share was -24.39. `_MIN_TRANSFER_N` gates it out. The
#     gate is a threshold on a NOISE floor, not a physical constant.
_MIN_TRANSFER_N = Fraction(1000)

# NOTE: the auditor's tolerance on the share is NOT here. It travels as the
# comparator epsilon in the anchored spec, exactly like the three residual
# epsilons, so it is authority-pinned and a producer who loosens its own
# tolerance changes nothing. This primitive reports the raw deviation and takes
# no view on what is acceptable. An earlier draft applied the tolerance inside
# here and left the spec epsilon at 0, which the substrate rightly refused --
# a comparator that accepts only an exact match cannot express a tolerance, and
# burying it in the primitive would have put it beyond the anchor's reach.
# Front share of lateral load transfer against |ay| (m/s^2), swept offline from
# the reference solve. Keys are |ay| in 0.1 steps; the lookup floors to the
# nearest key at or below, and refuses ABOVE the envelope rather than
# extrapolating.
#
# The envelope runs to 10.0 m/s^2 deliberately. It must cover everything a real
# vehicle can reach -- road tires top out near 0.9 g and competition slicks near
# 1.1 g, so 10.0 is past the physical limit -- because a legitimate trip that
# falls outside is REFUSED under the coverage rules below, and the pilot's own
# `--profile drift` bundle corners to |ay| = 7.5 by design. An envelope of 5.0
# refused that honest bundle, which is how the width was caught. Beyond the
# physically reachable range there is nothing to calibrate and refusal is right:
# the 18,142 N one-wheel forgery implies |ay| = 14.09.
_SPLIT_REFERENCE = {
    "0.1": "0.581584",
    "0.2": "0.583167",
    "0.3": "0.584751",
    "0.4": "0.586334",
    "0.5": "0.587917",
    "0.6": "0.589499",
    "0.7": "0.591081",
    "0.8": "0.592662",
    "0.9": "0.594242",
    "1": "0.595822",
    "1.1": "0.597400",
    "1.2": "0.598978",
    "1.3": "0.600554",
    "1.4": "0.602130",
    "1.5": "0.603704",
    "1.6": "0.605276",
    "1.7": "0.606848",
    "1.8": "0.608417",
    "1.9": "0.609986",
    "2": "0.611552",
    "2.1": "0.613117",
    "2.2": "0.614679",
    "2.3": "0.616240",
    "2.4": "0.617799",
    "2.5": "0.619356",
    "2.6": "0.620910",
    "2.7": "0.622463",
    "2.8": "0.624013",
    "2.9": "0.625560",
    "3": "0.627105",
    "3.1": "0.628648",
    "3.2": "0.630188",
    "3.3": "0.631725",
    "3.4": "0.633259",
    "3.5": "0.634791",
    "3.6": "0.636320",
    "3.7": "0.637846",
    "3.8": "0.639369",
    "3.9": "0.640888",
    "4": "0.642405",
    "4.1": "0.643918",
    "4.2": "0.645429",
    "4.3": "0.646935",
    "4.4": "0.648439",
    "4.5": "0.649939",
    "4.6": "0.651436",
    "4.7": "0.652929",
    "4.8": "0.654419",
    "4.9": "0.655905",
    "5": "0.657387",
    "5.1": "0.658866",
    "5.2": "0.660340",
    "5.3": "0.661812",
    "5.4": "0.663279",
    "5.5": "0.664742",
    "5.6": "0.666202",
    "5.7": "0.667658",
    "5.8": "0.669110",
    "5.9": "0.670557",
    "6": "0.672001",
    "6.1": "0.673441",
    "6.2": "0.674876",
    "6.3": "0.676308",
    "6.4": "0.677735",
    "6.5": "0.679158",
    "6.6": "0.680577",
    "6.7": "0.681992",
    "6.8": "0.683403",
    "6.9": "0.684809",
    "7": "0.686211",
    "7.1": "0.687609",
    "7.2": "0.689002",
    "7.3": "0.690391",
    "7.4": "0.691776",
    "7.5": "0.693157",
    "7.6": "0.694533",
    "7.7": "0.695905",
    "7.8": "0.697272",
    "7.9": "0.698635",
    "8": "0.699994",
    "8.1": "0.701348",
    "8.2": "0.702698",
    "8.3": "0.704043",
    "8.4": "0.705384",
    "8.5": "0.706721",
    "8.6": "0.708053",
    "8.7": "0.709381",
    "8.8": "0.710704",
    "8.9": "0.712023",
    "9": "0.713337",
    "9.1": "0.714647",
    "9.2": "0.715953",
    "9.3": "0.717254",
    "9.4": "0.718551",
    "9.5": "0.719843",
    "9.6": "0.721131",
    "9.7": "0.722414",
    "9.8": "0.723694",
    "9.9": "0.724968",
    "10": "0.726239",
}


def _reference_split(abs_ay: Fraction) -> Fraction | None:
    """Calibrated reference share at |ay|, or None if outside the envelope."""
    best_key = None
    for key in _SPLIT_REFERENCE:
        k = Fraction(key)
        if k <= abs_ay and (best_key is None or k > best_key):
            best_key = k
    if best_key is None:
        return None
    hi = max(Fraction(k) for k in _SPLIT_REFERENCE)
    if abs_ay > hi:
        return None
    return Fraction(_SPLIT_REFERENCE[_fmt_key(best_key)])


def _fmt_key(k: Fraction) -> str:
    for key in _SPLIT_REFERENCE:
        if Fraction(key) == k:
            return key
    raise KeyError(k)


def max_split_deviation(
    bundle_dir: Path, stats: CheckStats | None = None
) -> tuple:
    """Return (max |published share - reference share|, worst index).

    Maximised over samples whose total lateral transfer clears
    `_MIN_TRANSFER_N`. The auditor's tolerance is applied by the comparator, not
    here.

    Samples outside the calibrated |ay| envelope are SKIPPED, not passed: they
    are counted in `stats.samples` but contribute no excursion, because the
    auditor has no reference there. A bundle whose whole trip sits outside the
    envelope therefore yields zero -- which is why the caller must not read a
    zero as "the split was checked". `gated_sample_count` reports how many
    samples actually carried the check.
    """
    stats = stats if stats is not None else CheckStats()
    vehicle, samples, loads = _load_exact(bundle_dir)
    m = Fraction(vehicle["mass_kg"])
    t = Fraction(vehicle["track_width_m"])
    h = Fraction(vehicle["cg_height_m"])
    worst = Fraction(0)
    worst_index = -1
    for index, (sample, corners) in enumerate(zip(samples, loads)):
        stats.samples += 1
        fl, fr, rl, rr = (Fraction(str(v)) for v in corners)
        front = fr - fl
        rear = rr - rl
        total = front + rear
        stats.ops += 3
        if total < 0:
            magnitude = -total
        else:
            magnitude = total
        if magnitude < _MIN_TRANSFER_N:
            continue
        ay = Fraction(str(sample["ay_mps2"]))
        reference = _reference_split(-ay if ay < 0 else ay)
        if reference is None:
            continue
        share = front / total
        delta = share - reference
        if delta < 0:
            delta = -delta
        stats.ops += 3
        if delta > worst:
            worst = delta
            worst_index = index
    return worst, worst_index


# A sample the channel did not judge is not a sample it approved, and the two
# reasons it can fail to judge one are NOT alike:
#
#   below the transfer floor -- benign. The share is a ratio whose denominator is
#     the lateral transfer, so in a straight line it is genuinely ill-conditioned
#     and no auditor could form an opinion.
#
#   above the calibrated envelope -- NOT benign, and treating it as a skip was a
#     measured fail-open. The auditor has no reference out there, which is true,
#     and the PRODUCER OWNS trip_samples.json, so it chooses whether to go there.
#     A skip therefore hands the producer a switch that turns the channel off.
#     MEASURED 2026-09-03: 119 of 120 samples claiming the ENTIRE 18,142 N
#     vehicle weight on one wheel, ax and ay solved to null pitch and roll, one
#     honest sample left to satisfy a floor of "at least one" -> PASS, exit 0,
#     and a cleaner verdict than a 450 N shift two orders of magnitude smaller.
#
# So: outside the calibration REFUSES, and coverage has a real floor.
#
# The floor is a POLICY threshold, not a physical constant, and it is stated that
# way on purpose after the epsilon's provenance went the same way. Basis: the
# channel's verdict is about the trip, so judging a minority of it and reporting
# a trip-level result is the vacuity. A majority is the weakest defensible line;
# the honest bundle clears it with 94 of 120 (78%). A genuinely gentle real trip
# could fall below and be refused -- that is a COULD-NOT-CONCLUDE, which is the
# correct answer for a trip that cannot carry the check, not a false accusation.
_MIN_GATED_FRACTION = Fraction(1, 2)


def split_coverage(bundle_dir: Path) -> dict:
    """Account for EVERY sample by why the split channel did or did not judge it."""
    vehicle, samples, loads = _load_exact(bundle_dir)
    gated = below_floor = above_envelope = 0
    for sample, corners in zip(samples, loads):
        fl, fr, rl, rr = (Fraction(str(v)) for v in corners)
        total = (fr - fl) + (rr - rl)
        if (total if total >= 0 else -total) < _MIN_TRANSFER_N:
            below_floor += 1
            continue
        ay = Fraction(str(sample["ay_mps2"]))
        if _reference_split(-ay if ay < 0 else ay) is None:
            above_envelope += 1
            continue
        gated += 1
    return {
        "total": len(samples),
        "gated": gated,
        "below_floor": below_floor,
        "above_envelope": above_envelope,
    }


def gated_sample_count(bundle_dir: Path) -> int:
    """How many samples the split channel actually evaluated."""
    return split_coverage(bundle_dir)["gated"]


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


class TransferSplitRecompute:
    """Front/rear split of lateral load transfer against the auditor's offline
    calibration. Dimensionless share.

    Declared separately from `_ChannelResidualPrimitive` rather than added as a
    fourth `channel`, because it is not a residual and must not be mistaken for
    one: the three residual channels establish PHYSICAL ADMISSIBILITY and trust
    nothing, while this one establishes AGREEMENT WITH A REFERENCE the producer
    supplied. Sharing a base class would invite a caller to treat the four
    uniformly and report them under one sentence, which no external claim may do.

    `recompute` is defined here, not inherited -- see the note above the residual
    primitives: the fleet's reachability analysis resolves a bound primitive_id
    to its declaring class and skips one with no methods, leaving the pilot
    silently unresolved.
    """

    primitive_id: str = "corner_load_transfer_split_recompute"
    channel: str = SPLIT

    def recompute(self, inputs, pack_section: dict):
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
        worst, worst_index = max_split_deviation(inputs.bundle_dir, stats)
        coverage = split_coverage(inputs.bundle_dir)
        gated = coverage["gated"]
        if coverage["above_envelope"]:
            raise ValueError(
                f"{coverage['above_envelope']} of {coverage['total']} sample(s) "
                f"sit outside the calibrated |ay| envelope, where this auditor "
                f"holds no reference and cannot form an opinion. The trip is the "
                f"producer's to choose, so a sample the auditor cannot judge is "
                f"refused rather than skipped -- skipping it would let a producer "
                f"switch the channel off by driving out of range"
            )
        if gated * _MIN_GATED_FRACTION.denominator < (
            coverage["total"] * _MIN_GATED_FRACTION.numerator
        ):
            raise ValueError(
                f"the transfer-split check judged only {gated} of "
                f"{coverage['total']} sample(s) "
                f"({coverage['below_floor']} below the lateral-transfer floor); "
                f"that is under the {_MIN_GATED_FRACTION} coverage floor, so this "
                f"trip cannot carry a trip-level verdict on the split. Could not "
                f"conclude -- not an agreement"
            )
        return RecomputedValue(
            value={
                "kind": "rational",
                "num": worst.numerator,
                "den": worst.denominator,
            },
            detail=(
                f"{self.channel}: worst |share - calibrated reference| over "
                f"{gated} gated sample(s) of {coverage['total']} "
                f"({coverage['below_floor']} below the transfer floor) at index "
                f"{worst_index} = {float(worst):.6f} "
                f"({stats.ops} exact rational ops, no solve). "
                f"Agreement with an offline calibration, NOT physical "
                f"admissibility -- see the module header"
            ),
        )
