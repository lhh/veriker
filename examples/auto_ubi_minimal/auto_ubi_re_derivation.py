#!/usr/bin/env python3
"""auto_ubi_re_derivation.py — stdlib re-derivation pack for the auto_ubi_minimal domain pilot.

Verifies that per-policyholder rating decisions are derivable from the bundled
raw trip records and the bundled rate table.

the audit-bundle contract §C6 (domain generalization) + AB4 (duplicate-don't-import).
Stdlib only (no third-party dependencies) — contract C5.

Reads from --bundle-dir:
  telematics/trips.jsonl           — the bundled raw trip records
  payload/rate_table.json          — the bundled rate-tier threshold schedule
  payload/rating_decisions.json    — the per-policyholder decisions to re-derive

Re-derivation primitive:
  Re-aggregate telematics features (mileage, hard-brake count,
  harsh-acceleration count, late-night driving fraction) from the bundled
  raw trip records, re-evaluate the bundled rate-table JSON to recompute
  the rating tier and adjustment percentage — assert the bundle payload matches.

Three invariants checked:
  1. All policyholders in rating_decisions are covered by trip records.
  2. Re-aggregated features match the bundled decision fields (total_miles,
     annual_mileage_est, hard_brake_per_mile, harsh_accel_per_mile,
     late_night_fraction) within floating-point tolerance.
  3. Re-derived tier and adjustment_pct match the bundled decision exactly.

Exit 0 on full match; exit 1 on first mismatch with [RE_DERIVATION_MISMATCH]
on stderr.

On a full match the pack prints ONE machine-readable stdout line naming the
claim fields it compared, keyed by bundle-relative file:

    [COMPARED] {"payload/rating_decisions.json": ["[].adjustment_pct", ...]}

The pilot's plugin reports claim-field coverage for exactly those fields —
coverage follows the set this pack accumulates as its comparisons pass, never a constant in the
wrapper. Field paths use the claimset rendering (object keys joined by ".",
every array position "[]").

If telematics/trips.jsonl or payload/rating_decisions.json is absent the bundle
opted out of UBI re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Observation window used when computing annual mileage projection.
# Must match the value in _build_bundle.py.
_OBSERVATION_DAYS = 7
_DAYS_PER_YEAR = 365.25

# Per-field tolerances for re-derived continuous features.
# Values are stored in the bundle at reduced precision (round(x, N)); the
# tolerance covers that rounding gap with a 2x safety margin.
#   annual_mileage_est  : round(x, 1) → max error 0.05 → tol 0.1
#   total_miles         : round(x, 2) → max error 0.005 → tol 0.01
#   hard_brake_per_mile / harsh_accel_per_mile : round(x, 5) → tol 0.0001
#   late_night_fraction : round(x, 4) → tol 0.0001
_FIELD_TOL: dict[str, float] = {
    "total_miles": 0.01,
    "annual_mileage_est": 0.1,
    "hard_brake_per_mile": 0.0001,
    "harsh_accel_per_mile": 0.0001,
    "late_night_fraction": 0.0001,
}


def _load_trips(bundle_dir: Path) -> list[dict] | None:
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    if not trips_path.exists():
        return None
    trips: list[dict] = []
    for lineno, line in enumerate(
        trips_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            trips.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[RE_DERIVATION_MISMATCH] telematics/trips.jsonl line {lineno}: "
                f"JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return trips


def _load_rate_table(bundle_dir: Path) -> dict | None:
    rt_path = bundle_dir / "payload" / "rate_table.json"
    if not rt_path.exists():
        print(
            "[RE_DERIVATION_MISMATCH] payload/rate_table.json absent",
            file=sys.stderr,
        )
        return None
    try:
        return json.loads(rt_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] payload/rate_table.json: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_decisions(bundle_dir: Path) -> list[dict] | None:
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    if not dec_path.exists():
        return None
    try:
        return json.loads(dec_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] payload/rating_decisions.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _validate_trip_types(trips: list[dict]) -> str | None:
    """Trip values are compared as typed JSON, never coerced: the builder and
    the shipping core primitive do not coerce either, so a coercing pack would
    PASS a bundle they refuse (wave-2 red-team finding). Returns an error
    string or None."""
    for i, t in enumerate(trips):
        if not isinstance(t, dict):
            return f"telematics/trips.jsonl row {i}: not an object"
        for key in ("hard_brakes", "harsh_accels"):
            if type(t.get(key)) is not int:
                return f"telematics/trips.jsonl row {i}: {key} must be a JSON integer, got {t.get(key)!r}"
        if type(t.get("distance_miles")) not in (int, float):
            return f"telematics/trips.jsonl row {i}: distance_miles must be a JSON number, got {t.get('distance_miles')!r}"
        if type(t.get("late_night")) is not bool:
            return f"telematics/trips.jsonl row {i}: late_night must be a JSON boolean, got {t.get('late_night')!r}"
    return None


def _aggregate_features(trips: list[dict]) -> dict:
    """Aggregate telematics features from a list of trip dicts (stdlib only)."""
    total_miles = sum(float(t["distance_miles"]) for t in trips)
    total_hard_brakes = sum(int(t["hard_brakes"]) for t in trips)
    total_harsh_accels = sum(int(t["harsh_accels"]) for t in trips)
    late_night_count = sum(1 for t in trips if t["late_night"])
    trip_count = len(trips)
    annual_mileage_est = total_miles * (_DAYS_PER_YEAR / _OBSERVATION_DAYS)
    hard_brake_per_mile = total_hard_brakes / total_miles if total_miles > 0 else 0.0
    harsh_accel_per_mile = total_harsh_accels / total_miles if total_miles > 0 else 0.0
    late_night_fraction = late_night_count / trip_count if trip_count > 0 else 0.0
    return {
        "total_miles": total_miles,
        "annual_mileage_est": annual_mileage_est,
        "hard_brake_per_mile": hard_brake_per_mile,
        "harsh_accel_per_mile": harsh_accel_per_mile,
        "late_night_fraction": late_night_fraction,
        "trip_count": trip_count,
    }


def _classify_tier(features: dict, rate_table: dict) -> tuple[str, int]:
    """Apply rate-table thresholds to features. Returns (tier_name, adjustment_pct)."""
    thresholds = rate_table["tier_thresholds"]
    tiers = rate_table["tiers"]

    is_high_risk = (
        features["hard_brake_per_mile"]
        > thresholds["hard_brake_per_mile_surcharge_threshold"]
        or features["harsh_accel_per_mile"]
        > thresholds["harsh_accel_per_mile_surcharge_threshold"]
        or features["late_night_fraction"]
        > thresholds["late_night_fraction_surcharge_threshold"]
    )
    if is_high_risk:
        return ("high_risk_surcharge", -tiers["high_risk_surcharge"]["surcharge_pct"])

    is_low_mileage = (
        features["annual_mileage_est"] <= thresholds["annual_mileage_low_max"]
    )
    if is_low_mileage:
        return ("low_mileage_discount", tiers["low_mileage_discount"]["discount_pct"])

    return ("standard", tiers["standard"]["discount_pct"])


def _approx_eq(a: float, b: float, tol: float) -> bool:
    return abs(a - b) <= tol


def main() -> int:
    parser = argparse.ArgumentParser(
        description="UBI telematics re-derivation check for auto_ubi_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Optional opt-out — if no trips file present, skip silently
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    dec_path = bundle_dir / "payload" / "rating_decisions.json"

    if not trips_path.exists() and not dec_path.exists():
        return 0

    trips = _load_trips(bundle_dir)
    if trips is None:
        return 1

    rate_table = _load_rate_table(bundle_dir)
    if rate_table is None:
        return 1

    decisions = _load_decisions(bundle_dir)
    if decisions is None and not dec_path.exists():
        return 0
    if decisions is None:
        return 1

    trip_type_error = _validate_trip_types(trips)
    if trip_type_error is not None:
        print(f"[RE_DERIVATION_MISMATCH] {trip_type_error}", file=sys.stderr)
        return 1

    # An empty decisions file with trips present (or both empty) is never a
    # vacuous success: there is nothing to compare, and a bijection over zero
    # rows must not report coverage (wave-2 red-team finding).
    if not isinstance(decisions, list) or not decisions:
        print(
            "[RE_DERIVATION_MISMATCH] payload/rating_decisions.json carries no "
            "decision rows — nothing to re-derive against",
            file=sys.stderr,
        )
        return 1

    # Group trips by policyholder
    trips_by_ph: dict[str, list[dict]] = {}
    for trip in trips:
        try:
            ph_id = trip["policyholder_id"]
        except (KeyError, TypeError) as exc:
            print(
                f"[RE_DERIVATION_MISMATCH] telematics/trips.jsonl: "
                f"malformed trip record (missing policyholder_id): {exc}",
                file=sys.stderr,
            )
            return 1
        trips_by_ph.setdefault(ph_id, []).append(trip)

    # Claim-field coverage: the set of payload/rating_decisions.json paths
    # this run actually compared, ADDED TO as each comparison passes (never a
    # module constant) and printed once from the success return below.
    compared: set[str] = set()
    compared_table: set[str] = set()

    # Invariant 0 (claim-field coverage adoption, 2026-08) — policyholder_id
    # bijection: refuse a DUPLICATE policyholder_id across decision rows (the
    # credit_scoring dict-shadow class of gap — this pack loops over the
    # decisions LIST rather than indexing into a dict, so a duplicate is not
    # silently shadowed, but nothing previously refused it outright), and
    # require the SET of decision policyholder_ids to equal the set of
    # policyholder_ids with trip records (a dropped or invented policyholder
    # is refused rather than silently passing). Runs before the per-decision
    # loop so a bijection violation is reported once, not per offending row.
    seen_ph_ids: set = set()
    for dec in decisions:
        pid = dec.get("policyholder_id") if isinstance(dec, dict) else None
        if pid is None:
            continue
        if pid in seen_ph_ids:
            print(
                f"[RE_DERIVATION_MISMATCH] policyholder_id {pid!r} appears "
                f"in more than one payload/rating_decisions.json row",
                file=sys.stderr,
            )
            return 1
        seen_ph_ids.add(pid)
    if seen_ph_ids != set(trips_by_ph.keys()):
        missing = sorted(set(trips_by_ph.keys()) - seen_ph_ids)
        extra = sorted(seen_ph_ids - set(trips_by_ph.keys()))
        print(
            f"[RE_DERIVATION_MISMATCH] rating_decisions.json policyholder "
            f"set does not match telematics/trips.jsonl policyholder set "
            f"(missing={missing}, extra={extra})",
            file=sys.stderr,
        )
        return 1

    compared.add("[].policyholder_id")

    # Invariant 1 + 2 + 3 — for each bundled decision, re-derive and compare
    for dec in decisions:
        try:
            ph_id: str = dec["policyholder_id"]
            bundled_tier: str = dec["tier"]
            bundled_adj = dec["adjustment_pct"]
            bundled_trip_count = dec["trip_count"]
            # Compared as TYPED JSON numbers, never coerced through float():
            # "107.6" and true are not numbers (wave-2 red-team finding).
            numeric = {}
            for field_name in (
                "total_miles",
                "annual_mileage_est",
                "hard_brake_per_mile",
                "harsh_accel_per_mile",
                "late_night_fraction",
            ):
                value = dec[field_name]
                if type(value) not in (int, float):
                    raise TypeError(f"{field_name} must be a JSON number, got {value!r}")
                numeric[field_name] = float(value)
            if type(bundled_adj) is not int:
                raise TypeError(f"adjustment_pct must be a JSON integer, got {bundled_adj!r}")
            bundled_total_miles = numeric["total_miles"]
            bundled_annual_est = numeric["annual_mileage_est"]
            bundled_hb_per_mile = numeric["hard_brake_per_mile"]
            bundled_ha_per_mile = numeric["harsh_accel_per_mile"]
            bundled_ln_frac = numeric["late_night_fraction"]
        except (KeyError, TypeError, ValueError) as exc:
            print(
                f"[RE_DERIVATION_MISMATCH] payload/rating_decisions.json: "
                f"malformed decision record: {exc}",
                file=sys.stderr,
            )
            return 1

        # Invariant 1 — policyholder must have trip records
        if ph_id not in trips_by_ph:
            print(
                f"[RE_DERIVATION_MISMATCH] policyholder {ph_id!r} appears in "
                f"rating_decisions but has no trip records in telematics/trips.jsonl",
                file=sys.stderr,
            )
            return 1

        ph_trips = trips_by_ph[ph_id]
        features = _aggregate_features(ph_trips)

        # Invariant 1b (claim-field coverage adoption, 2026-08) — trip_count
        # must match the re-aggregation exactly. features["trip_count"] was
        # already computed above for late_night_fraction's denominator but
        # was never compared to the bundled value.
        # Compared as TYPED: a float 12.0 or a string "12" is not the integer
        # the aggregation produces (bool is excluded — it is an int subclass).
        if type(bundled_trip_count) is not int or features["trip_count"] != bundled_trip_count:
            print(
                f"[RE_DERIVATION_MISMATCH] {ph_id}: trip_count mismatch — "
                f"recomputed={features['trip_count']} bundled={bundled_trip_count}",
                file=sys.stderr,
            )
            return 1

        compared.add("[].trip_count")

        # Invariant 2 — re-derived continuous features must match within tolerance
        checks: list[tuple[str, float, float]] = [
            ("total_miles", features["total_miles"], bundled_total_miles),
            ("annual_mileage_est", features["annual_mileage_est"], bundled_annual_est),
            (
                "hard_brake_per_mile",
                features["hard_brake_per_mile"],
                bundled_hb_per_mile,
            ),
            (
                "harsh_accel_per_mile",
                features["harsh_accel_per_mile"],
                bundled_ha_per_mile,
            ),
            ("late_night_fraction", features["late_night_fraction"], bundled_ln_frac),
        ]
        for field_name, recomputed, bundled in checks:
            tol = _FIELD_TOL[field_name]
            if not _approx_eq(recomputed, bundled, tol):
                print(
                    f"[RE_DERIVATION_MISMATCH] {ph_id}: feature {field_name!r} "
                    f"mismatch - recomputed={recomputed:.6f} bundled={bundled:.6f} "
                    f"(delta={abs(recomputed - bundled):.6f} > tol={tol})",
                    file=sys.stderr,
                )
                return 1
            compared.add(f"[].{field_name}")

        # Invariant 3 — re-derived tier and adjustment must match exactly
        recomputed_tier, recomputed_adj = _classify_tier(features, rate_table)
        if recomputed_tier != bundled_tier:
            print(
                f"[RE_DERIVATION_MISMATCH] {ph_id}: tier mismatch — "
                f"recomputed={recomputed_tier!r} bundled={bundled_tier!r}",
                file=sys.stderr,
            )
            return 1
        compared.add("[].tier")
        if recomputed_adj != bundled_adj:
            print(
                f"[RE_DERIVATION_MISMATCH] {ph_id}: adjustment_pct mismatch — "
                f"recomputed={recomputed_adj} bundled={bundled_adj}",
                file=sys.stderr,
            )
            return 1
        compared.add("[].adjustment_pct")
        # The rate-table value that produced this row's adjustment is the
        # other operand of the comparison that just passed: it is bound to
        # payload/rating_decisions.json on every row of its tier. Reported
        # under payload/rate_table.json only once a row of that tier has
        # actually been compared (a fixture without a tier leaves that
        # element unreported → could-not-conclude, honestly).
        compared_table.add(_TIER_TABLE_PATH[recomputed_tier])

    _emit_compared(compared, compared_table)
    return 0


_COMPARED_FILE = "payload/rating_decisions.json"
_COMPARED_TABLE_FILE = "payload/rate_table.json"
# The rate-table field whose value is the recomputed adjustment on each tier —
# the other operand of the per-row adjustment_pct comparison.
_TIER_TABLE_PATH = {
    "high_risk_surcharge": "tiers.high_risk_surcharge.surcharge_pct",
    "low_mileage_discount": "tiers.low_mileage_discount.discount_pct",
    "standard": "tiers.standard.discount_pct",
}


def _emit_compared(compared: set[str], compared_table: set[str]) -> None:
    """Print ONE machine-readable stdout line naming, per claim file, the
    fields this run COMPARED — sets main() added to as each comparison
    passed, so a comparison that is removed or skipped drops out of the line
    and the claimset gate refuses to conclude naming the field. Under
    payload/rate_table.json only the three tier adjustment values appear (each
    once a row of its tier has been compared); the thresholds are inequality
    operands that select a branch, not compared values, and stay residual."""
    print(
        "[COMPARED] "
        + json.dumps(
            {_COMPARED_FILE: sorted(compared), _COMPARED_TABLE_FILE: sorted(compared_table)},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
