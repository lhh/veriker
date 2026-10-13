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
import re
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
# `_assert_physically_admissible` and the README.
#
# WHOSE digest: the auditor's. It is the declared input `rigid_body_sha256` in the
# auditor's anchored spec (the declared-inputs contract, REASON_CODES.md UNKNOWN_SPEC_PARAM / MISSING_SPEC_PARAM), not a constant of
# this module: a ROOT (whose vehicle data counts) is stated by the party relying on
# it. In production a fleet or engineering authority would sign each CURRENT
# snapshot of these fields and the auditor would take the digest from that
# signature, rather than state one that says nothing about whether the spec is
# still current for the vehicle it names.
RIGID_BODY_SPEC_FIELDS = (
    "cg_height_m",
    "cg_to_front_axle_m",
    "cg_to_rear_axle_m",
    "gravity_mps2",
    "mass_kg",
    "track_width_m",
    "vehicle_id",
)


# --- declared inputs (the declared-inputs contract, REASON_CODES.md UNKNOWN_SPEC_PARAM / MISSING_SPEC_PARAM) -------------------------
# The auditor's roots and demands are NOT constants of this module. Each is a
# binding param in the auditor's anchored spec; dispatch refuses a binding that
# omits one (MISSING_SPEC_PARAM) or carries a key nobody reads (UNKNOWN_SPEC_PARAM),
# and hands each primitive only the keys it declares in `expects`:
#
#   rigid_body_sha256   ROOT    digest of RIGID_BODY_SPEC_FIELDS the auditor holds
#   split_reference     ROOT    the calibrated front-share table, |ay| -> share
#                               (somebody's calibration -- see channel 4's header)
#   min_transfer_n      DEMAND  the lateral-transfer floor below which a sample is
#                               not judged by the split channel (a noise floor the
#                               auditor chooses; newtons, decimal string)
#   min_gated_fraction  DEMAND  the share of the trip the split channel must judge
#                               to carry a trip-level verdict (a policy line)
#
# Values that must be exact are decimal STRINGS, read with Fraction.
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
CHANNEL_EXPECTS = frozenset({"rigid_body_sha256"})
SPLIT_EXPECTS = frozenset(
    {"rigid_body_sha256", "split_reference", "min_transfer_n", "min_gated_fraction"}
)


# A plain decimal or a ratio of two integers, bounded: no exponent form, because
# Fraction("1e50000000") builds a 50-million-digit integer (measured: > 60 s).
_EXACT_FORM = re.compile(r"-?[0-9]{1,40}(\.[0-9]{1,40})?|[0-9]{1,40}/[0-9]{1,40}")


def _exact(value: object, name: str) -> Fraction:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"{name} must be a decimal string, got {type(value).__name__}")
    if not _EXACT_FORM.fullmatch(value):
        raise ValueError(f"{name}: {value[:50]!r} is not a plain decimal or integer ratio")
    try:
        return Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"{name}: not an exact decimal ({exc})") from None


def pins_from_params(params: dict, keys) -> dict:
    """Validate the declared inputs named in `keys` out of the binding params.
    Raises ValueError on a malformed value; a missing key is refused upstream by
    dispatch and again here."""
    pins: dict = {}
    for key in keys:
        if key not in params:
            raise ValueError(f"declared input {key!r} is not stated; there is no default")
    if "rigid_body_sha256" in keys:
        v = params["rigid_body_sha256"]
        if not isinstance(v, str) or not _SHA256_HEX.fullmatch(v):
            raise ValueError("rigid_body_sha256 must be a lowercase sha256 hex digest")
        pins["rigid_body_sha256"] = v
    if "split_reference" in keys:
        ref = params["split_reference"]
        if not isinstance(ref, dict) or not ref:
            raise ValueError("split_reference must be a non-empty object |ay| -> share")
        table: dict = {}
        for k, v in ref.items():
            ay = _exact(k, f"split_reference key {k!r}")
            if ay < 0 or ay in table:
                raise ValueError(f"split_reference key {k!r} is negative or repeats a key")
            table[ay] = _exact(v, f"split_reference[{k!r}]")
        pins["split_reference"] = table
    if "min_transfer_n" in keys:
        v = _exact(params["min_transfer_n"], "min_transfer_n")
        if v <= 0:
            raise ValueError("min_transfer_n must be > 0")
        pins["min_transfer_n"] = v
    if "min_gated_fraction" in keys:
        v = _exact(params["min_gated_fraction"], "min_gated_fraction")
        if not 0 < v <= 1:
            raise ValueError("min_gated_fraction must be in (0, 1]")
        pins["min_gated_fraction"] = v
    return pins


def _declared(pack_section: dict, keys) -> dict:
    """pins_from_params for the dispatch path: a malformed declared value is the
    AUDITOR's instruction being wrong, reported through the declared refusal class
    (exit 2), never a builtin ValueError that would read as a REJECT of the bundle."""
    from audit_bundle.plugin import DeclaredInputMalformed  # noqa: PLC0415

    try:
        return pins_from_params(pack_section.get("params") or {}, keys)
    except ValueError as exc:
        raise DeclaredInputMalformed(str(exc)) from None


def pins_from_spec(spec_path: Path, type_key: str) -> dict:
    """The declared inputs as the AUDITOR's spec states them for `type_key`. For the
    auditor's own tools and tests; the primitive never reads a spec file, it gets
    its params from dispatch."""
    doc = json.loads(Path(spec_path).read_bytes())
    params = doc["types"][type_key]["comparator"]["params"]
    keys = SPLIT_EXPECTS if type_key == SPLIT else CHANNEL_EXPECTS
    return pins_from_params(params, keys)


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


def _load_exact(bundle_dir: Path, pins: dict) -> tuple:
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
    if actual_sha != pins["rigid_body_sha256"]:
        raise ValueError(
            f"inputs/vehicle_spec.json rigid-body fields digest {actual_sha} "
            f"does not match the verifier-pinned "
            f"{pins['rigid_body_sha256']} -- a vehicle spec that differs "
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
    bundle_dir: Path, channel: str, stats: CheckStats | None = None, *, pins: dict
) -> tuple:
    """Return (max |residual| as Fraction, index of the worst sample).

    Reads ONLY rigid-body geometry from the vehicle spec. Raises on an unknown
    channel rather than defaulting -- a mis-bound spec must fail closed, not
    silently check something else.
    """
    if channel not in _CHANNELS:
        raise ValueError(f"unknown residual channel {channel!r}; known: {_CHANNELS!r}")
    stats = stats if stats is not None else CheckStats()
    vehicle, samples, loads = _load_exact(bundle_dir, pins)

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
# a calibration that somebody produced. Here that is `split_reference`, swept
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
#     sample's measured share was -24.39. the declared input `min_transfer_n`
#     gates it out. The gate is a threshold on a NOISE floor, not a physical
#     constant, which is why the auditor states it (committed spec: 1000 N).

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
# The table is the declared input `split_reference` in the auditor's spec (a ROOT:
# the calibration somebody produced). The committed spec carries the sweep verbatim
# from its first cut: |ay| 0.1 .. 10.0 in 0.1 steps.


def _reference_split(abs_ay: Fraction, table: dict) -> Fraction | None:
    """Calibrated reference share at |ay| (floored to the nearest key at or below),
    or None outside the envelope. `table` is the validated `split_reference`."""
    below = [k for k in table if k <= abs_ay]
    if not below or abs_ay > max(table):
        return None
    return table[max(below)]


def max_split_deviation(
    bundle_dir: Path, stats: CheckStats | None = None, *, pins: dict
) -> tuple:
    """Return (max |published share - reference share|, worst index).

    Maximised over samples whose total lateral transfer clears
    `min_transfer_n`. The auditor's tolerance is applied by the comparator, not
    here.

    Samples outside the calibrated |ay| envelope are SKIPPED, not passed: they
    are counted in `stats.samples` but contribute no excursion, because the
    auditor has no reference there. A bundle whose whole trip sits outside the
    envelope therefore yields zero -- which is why the caller must not read a
    zero as "the split was checked". `gated_sample_count` reports how many
    samples actually carried the check.
    """
    stats = stats if stats is not None else CheckStats()
    vehicle, samples, loads = _load_exact(bundle_dir, pins)
    floor, table = pins["min_transfer_n"], pins["split_reference"]
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
        if magnitude < floor:
            continue
        ay = Fraction(str(sample["ay_mps2"]))
        reference = _reference_split(-ay if ay < 0 else ay, table)
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
# The floor is the declared input `min_gated_fraction` (committed spec: 1/2).


def split_coverage(bundle_dir: Path, *, pins: dict) -> dict:
    """Account for EVERY sample by why the split channel did or did not judge it."""
    vehicle, samples, loads = _load_exact(bundle_dir, pins)
    floor, table = pins["min_transfer_n"], pins["split_reference"]
    gated = below_floor = above_envelope = 0
    for sample, corners in zip(samples, loads):
        fl, fr, rl, rr = (Fraction(str(v)) for v in corners)
        total = (fr - fl) + (rr - rl)
        if (total if total >= 0 else -total) < floor:
            below_floor += 1
            continue
        ay = Fraction(str(sample["ay_mps2"]))
        if _reference_split(-ay if ay < 0 else ay, table) is None:
            above_envelope += 1
            continue
        gated += 1
    return {
        "total": len(samples),
        "gated": gated,
        "below_floor": below_floor,
        "above_envelope": above_envelope,
    }


def gated_sample_count(bundle_dir: Path, *, pins: dict) -> int:
    """How many samples the split channel actually evaluated."""
    return split_coverage(bundle_dir, pins=pins)["gated"]


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
    expects: frozenset[str] = CHANNEL_EXPECTS

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
        pins = _declared(pack_section, self.expects)
        stats = CheckStats()
        worst, worst_index = max_abs_residual(
            inputs.bundle_dir, self.channel, stats, pins=pins
        )
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
    expects: frozenset[str] = CHANNEL_EXPECTS  # restated: this class defines its own recompute
    channel: str = VERTICAL

    def recompute(self, inputs, pack_section: dict):
        return self._certificate(inputs, pack_section)


class PitchResidualRecompute(_ChannelResidualPrimitive):
    """Longitudinal moment balance about the CG. Newton-metres."""

    primitive_id: str = "corner_load_pitch_residual_recompute"
    expects: frozenset[str] = CHANNEL_EXPECTS  # restated: this class defines its own recompute
    channel: str = PITCH

    def recompute(self, inputs, pack_section: dict):
        return self._certificate(inputs, pack_section)


class RollResidualRecompute(_ChannelResidualPrimitive):
    """Lateral moment balance about the CG. Newton-metres."""

    primitive_id: str = "corner_load_roll_residual_recompute"
    expects: frozenset[str] = CHANNEL_EXPECTS  # restated: this class defines its own recompute
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
    expects: frozenset[str] = SPLIT_EXPECTS

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
        pins = _declared(pack_section, self.expects)
        stats = CheckStats()
        worst, worst_index = max_split_deviation(inputs.bundle_dir, stats, pins=pins)
        coverage = split_coverage(inputs.bundle_dir, pins=pins)
        min_gated = pins["min_gated_fraction"]
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
        if gated * min_gated.denominator < (coverage["total"] * min_gated.numerator):
            raise ValueError(
                f"the transfer-split check judged only {gated} of "
                f"{coverage['total']} sample(s) "
                f"({coverage['below_floor']} below the lateral-transfer floor); "
                f"that is under the {min_gated} coverage floor, so this "
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
