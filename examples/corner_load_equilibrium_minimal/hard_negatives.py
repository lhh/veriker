"""hard_negatives.py — AUDITOR-SIDE export of the failure telemetry.

The residual check is a labelling machine. It runs on real-world data, needs
no ground truth, and every sample whose published loads violate equilibrium
beyond the auditor's epsilon is a LABELLED hard negative: the exact input
state that made the deployed model produce a physically inadmissible answer.

That is the thing a tire-twin team cannot otherwise buy at fleet scale. The
alternatives are running the reference solve on cases you GUESSED were hard,
or instrumenting test vehicles -- both expensive, both with poor coverage of
the operational domain the fleet is actually in.

What this emits, per violating sample:
  * the input state (the features the model saw)
  * which conservation law it broke, by how much, and by what multiple of the
    auditor's epsilon
  * the identity of the model version that produced it -- carried as the
    bundle_id plus the sha256 of the anchored spec the verdict was reached
    under, so a negative can never be silently re-attributed to a different
    model build

The last point is what makes the corpus an auditable model-improvement ledger
rather than a pile of CSV: when the next model version ships you can show it
fixed these exact negatives and did not regress the ones it already passed,
and the showing is re-runnable by someone who is not you.

ADMISSION GATE (auditor_entry.admit_for_mining) -- mining runs ONLY on a bundle
that has been verified under the auditor's anchor, and only when every reason
the verifier concluded is an equilibrium-residual mismatch. A bundle rejected
for authenticity, structure, coverage or anchor reasons is REFUSED with exit 2:
its published loads are not established to be the ones the producer emitted, so
no failure in it can be attributed to a model. Without that gate this tool
mined 60 ranked negatives out of a clean bundle whose payload had been edited
after emission, and stamped them with the clean bundle's id. Note the gate is
not "the bundle must pass" -- the bundle worth mining is the one that FAILS on
physics, which is exactly the case admitted here.

Scope limit, stated plainly: this finds samples where the published loads are
NOT PHYSICALLY ADMISSIBLE. A sample can be wrong without being inadmissible
(see the README on what the three residuals do and do not constrain), so an
empty export is not evidence the model is correct on that trip.

Stdlib only. Usage:
    python examples/corner_load_equilibrium_minimal/hard_negatives.py \
        --bundle-dir /tmp/corner_load_drift --out /tmp/negatives.json

Exit codes:
    0  mined (an empty export is a result, not an error)
    2  REFUSED -- the bundle is not a sound basis for attributing failures
"""

from __future__ import annotations

import argparse
import json
import sys
from fractions import Fraction
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from auditor_entry import (  # noqa: E402
    SPEC_PATH as _SPEC_PATH,
    MiningAuthority,
    MiningRefused,
    admit_for_mining,
)
from equilibrium_residual_recompute import (  # noqa: E402
    PITCH,
    ROLL,
    VERTICAL,
    CheckStats,
    _load_exact,
    max_abs_residual,
)

_CHANNEL_UNITS = {VERTICAL: "N", PITCH: "N*m", ROLL: "N*m"}


def _epsilons() -> dict:
    """Read each channel's epsilon from the AUDITOR's committed spec.

    Deliberately not a parameter of this tool: the threshold that decides what
    counts as a hard negative is the same anchored number the verdict used. A
    mining run cannot quietly widen it.
    """
    spec = json.loads(_SPEC_PATH.read_bytes())
    return {
        type_name: Fraction(str(binding["comparator"]["params"]["epsilon"]))
        for type_name, binding in spec["types"].items()
    }


def _per_sample_residuals(bundle_dir: Path):
    """Yield (index, sample, {channel: exact residual}) for the whole trip."""
    vehicle, samples, loads = _load_exact(bundle_dir)
    m = Fraction(vehicle["mass_kg"])
    g = Fraction(vehicle["gravity_mps2"])
    a = Fraction(vehicle["cg_to_front_axle_m"])
    b = Fraction(vehicle["cg_to_rear_axle_m"])
    t = Fraction(vehicle["track_width_m"])
    h = Fraction(vehicle["cg_height_m"])
    weight = m * g
    for index, (sample, corners) in enumerate(zip(samples, loads)):
        fl, fr, rl, rr = (Fraction(str(v)) for v in corners)
        ax = Fraction(sample["ax_mps2"])
        ay = Fraction(sample["ay_mps2"])
        yield (
            index,
            sample,
            corners,
            {
                VERTICAL: fl + fr + rl + rr - weight,
                PITCH: (fl + fr) * a - (rl + rr) * b + m * ax * h,
                ROLL: (fr + rr - fl - rl) * (t / Fraction(2)) - m * ay * h,
            },
        )


def mine(bundle_dir: Path, *, authority: MiningAuthority | None = None) -> dict:
    """Export the violating samples as attributed hard negatives.

    Raises MiningRefused if the bundle is not admissible (see auditor_entry).
    `authority` lets a caller that has already admitted the bundle pass the
    result through rather than verifying it twice; it is never a way to skip
    the gate, because the only thing that produces one is the gate.
    """
    if authority is None:
        authority = admit_for_mining(bundle_dir)
    epsilons = _epsilons()

    negatives = []
    examined = 0
    for index, sample, corners, residuals in _per_sample_residuals(bundle_dir):
        examined += 1
        violations = []
        for channel, residual in residuals.items():
            eps = epsilons[channel]
            magnitude = residual if residual >= 0 else -residual
            if magnitude > eps:
                violations.append(
                    {
                        "channel": channel,
                        "unit": _CHANNEL_UNITS[channel],
                        "residual": float(residual),
                        "epsilon": float(eps),
                        "epsilon_multiple": float(magnitude / eps),
                    }
                )
        if violations:
            negatives.append(
                {
                    "sample_index": index,
                    "input_state": {
                        "t_ms": sample["t_ms"],
                        "ax_mps2": sample["ax_mps2"],
                        "ay_mps2": sample["ay_mps2"],
                    },
                    "published_corner_loads_n": {
                        "FL": corners[0], "FR": corners[1],
                        "RL": corners[2], "RR": corners[3],
                    },
                    "violations": sorted(
                        violations, key=lambda v: -v["epsilon_multiple"]
                    ),
                    "worst_epsilon_multiple": max(
                        v["epsilon_multiple"] for v in violations
                    ),
                }
            )

    negatives.sort(key=lambda n: (-n["worst_epsilon_multiple"], n["sample_index"]))
    return {
        "schema": "corner_load_hard_negatives_v1",
        # Sourced from the anchor that judged and the verdict it reached --
        # not recomputed here. A stamp the exporting tool can produce on its
        # own attests to the tool, never to a verdict.
        "produced_by": authority.as_record(),
        "samples_examined": examined,
        "samples_violating": len(negatives),
        "negatives": negatives,
    }


def audit_cost(bundle_dir: Path, *, authority: MiningAuthority | None = None) -> dict:
    """Worst residual per channel plus the auditor's elementary-op count.

    Lives here rather than in _build_bundle.py because the producer must not
    import the verifier's residual module -- see the note in that file.

    Gated on the same admission as mine(): this prints residual magnitudes, and
    a residual read off an unauthenticated bundle is a number about a file, not
    a number about a model. `auditor_ops` counts the residual arithmetic only,
    so the gate does not enter the produce-vs-check ratio.
    """
    if authority is None:
        admit_for_mining(bundle_dir)
    stats = CheckStats()
    worst = {}
    for channel in (VERTICAL, PITCH, ROLL):
        value, index = max_abs_residual(bundle_dir, channel, stats)
        worst[channel] = {"residual": float(value), "sample_index": index}
    return {"worst": worst, "auditor_ops": stats.ops}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export equilibrium-violating samples as labelled hard negatives"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--out", required=False, type=Path)
    parser.add_argument("--top", type=int, default=5)
    parser.add_argument(
        "--cost", action="store_true",
        help="also print the worst residual per channel and the auditor op count",
    )
    args = parser.parse_args()

    bundle_dir = args.bundle_dir.resolve()
    try:
        authority = admit_for_mining(bundle_dir)
    except MiningRefused as refusal:
        print("REFUSED -- not mined", file=sys.stderr)
        print(f"  {refusal}", file=sys.stderr)
        print(
            "  A hard negative asserts a MODEL produced an inadmissible value. "
            "That cannot be concluded from this bundle.",
            file=sys.stderr,
        )
        return 2

    report = mine(bundle_dir, authority=authority)
    if args.out:
        args.out.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    produced_by = report["produced_by"]
    print(f"bundle              : {produced_by['bundle_id']}")
    print(f"verdict             : {produced_by['verdict_state']} (anchored, re-derivation required)")
    print(f"anchored spec sha256: {produced_by['anchored_spec_sha256'][:16]}...")
    print(
        f"hard negatives      : {report['samples_violating']} of "
        f"{report['samples_examined']} samples"
    )
    for negative in report["negatives"][: args.top]:
        state = negative["input_state"]
        worst = negative["violations"][0]
        print(
            f"  sample {negative['sample_index']:3d}  "
            f"ax={state['ax_mps2']:>6s} ay={state['ay_mps2']:>6s}  "
            f"{worst['channel']:28s} "
            f"{worst['residual']:11.3f} {worst['unit']:3s} "
            f"= {worst['epsilon_multiple']:6.1f}x epsilon"
        )
    if args.cost:
        cost = audit_cost(bundle_dir, authority=authority)
        print("  --- auditor cost to CHECK it ---")
        for channel, info in cost["worst"].items():
            print(f"    {channel:32s} worst {info['residual']:12.6f} "
                  f"at sample {info['sample_index']}")
        print(f"    auditor ops     : {cost['auditor_ops']:,d} (exact rational, no solve)")
    if args.out:
        print(f"written             : {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
