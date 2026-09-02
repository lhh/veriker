"""agritech_sensor_recompute.py — verifier-side yield-score re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the agritech_sensor pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence, PRODUCER/CLAIM side, float, unchanged):
    yield_score = round(
        w_soil_moisture * mean(soil_moisture_pct)
        + w_soil_temp   * mean(soil_temp_c)
        + w_npk         * mean(npk_ppm)
        + w_rainfall    * sum(rainfall_mm)
        + bias, 6)

RECOMPUTE side (rational_band, this migration): the same weighted-fusion
formula, computed in EXACT rational arithmetic (Fraction) over the committed
float samples/weights and returned UNROUNDED as
{"kind": "rational", "num", "den"}. Unlike lifesci_binding (int weights +
exactly-representable bias landing on the 0.5 grid), here the products and
sums involve arbitrary committed floats, so the producer's terminal
round(score, 6) IS information-bearing — it is NOT reproduced on the
recompute side; epsilon=1e-6 (the 6dp quantization grain) covers exactly
that terminal rounding, plus the producer's pre-round float error (bounded
by magnitude x ulp x term count, argued negligible against the grain in the
committed spec description).

over inputs/sensor_stream.json (samples) and payload/fusion_weights.json. The
aggregation rule (per-channel mean for moisture/temp/npk, total for rainfall,
linear weighting + bias) is FIXED in this primitive — the
primitive_id ("agritech_sensor_recompute") IS the rule. The auditor's SHA-pinned
spec binds the output type "agritech_yield_score" to this primitive_id and to a
rational_band comparator; a producer cannot weaken the aggregation without
changing the primitive_id, which the anchor would reject.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_yield_score() standalone. This mirrors the
legacy yield_fusion_re_derivation pack's _compute_yield_score EXACTLY, but
re-implemented in-process / stdlib (the legacy plugin shells out via subprocess).
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_yield_score(samples: list, weights: dict) -> float:
    """Canonical yield score. Mirrors the legacy pack's _compute_yield_score:
    per-channel mean for moisture/temp/npk, total for rainfall, linear weighting
    plus bias, total rounded to 6dp. Builder and verifier share this ONE
    definition so the honest claimed score and the re-derivation cannot drift.

    Raises ValueError on empty input.
    """
    n = len(samples)
    if n == 0:
        raise ValueError("sensor_stream has no samples — cannot compute yield_score")

    mean_moisture = sum(s["soil_moisture_pct"] for s in samples) / n
    mean_temp = sum(s["soil_temp_c"] for s in samples) / n
    mean_npk = sum(s["npk_ppm"] for s in samples) / n
    total_rain = sum(s["rainfall_mm"] for s in samples)

    score = (
        weights["w_soil_moisture"] * mean_moisture
        + weights["w_soil_temp"] * mean_temp
        + weights["w_npk"] * mean_npk
        + weights["w_rainfall"] * total_rain
        + weights["bias"]
    )
    return round(score, 6)


def compute_yield_score_exact(samples: list, weights: dict) -> Fraction:
    """EXACT-rational sibling of compute_yield_score(), for the rational_band
    recompute path only — NEVER used to produce the claim (that stays
    compute_yield_score(), byte-identical, above).

    Every committed sample field and weight is an arbitrary (non-integer)
    float; Fraction(x) reads each float's own exact binary64 value (not a
    decimal approximation), so the means/sum/weighted-sum below are exact.
    The result is returned UNROUNDED — no terminal round() here, unlike
    compute_yield_score(). The terminal 6dp round is information-bearing for
    this pilot (unlike lifesci_binding's int-weighted no-op), so it is
    dropped from the recompute side entirely and covered by epsilon instead.

    Raises ValueError on empty input (mirrors compute_yield_score()).
    """
    n = len(samples)
    if n == 0:
        raise ValueError("sensor_stream has no samples — cannot compute yield_score")

    sum_moisture = sum(Fraction(s["soil_moisture_pct"]) for s in samples)
    sum_temp = sum(Fraction(s["soil_temp_c"]) for s in samples)
    sum_npk = sum(Fraction(s["npk_ppm"]) for s in samples)
    total_rain = sum(Fraction(s["rainfall_mm"]) for s in samples)

    mean_moisture = sum_moisture / n
    mean_temp = sum_temp / n
    mean_npk = sum_npk / n

    return (
        Fraction(weights["w_soil_moisture"]) * mean_moisture
        + Fraction(weights["w_soil_temp"]) * mean_temp
        + Fraction(weights["w_npk"]) * mean_npk
        + Fraction(weights["w_rainfall"]) * total_rain
        + Fraction(weights["bias"])
    )


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class AgritechSensorRecompute:
    """Verifier-side primitive for re-deriving the scalar yield_score."""

    primitive_id: str = "agritech_sensor_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute yield_score from inputs/sensor_stream.json + payload/fusion_weights.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the EXACT rational (rational_band comparator);
        no float on this path — compute_yield_score() (float) is the
        producer/claim-side function and is never called here.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        stream_path = bundle_dir / "inputs" / "sensor_stream.json"
        weights_path = bundle_dir / "payload" / "fusion_weights.json"
        if not stream_path.is_file():
            raise FileNotFoundError(
                f"inputs/sensor_stream.json not found in bundle at {bundle_dir}"
            )
        if not weights_path.is_file():
            raise FileNotFoundError(
                f"payload/fusion_weights.json not found in bundle at {bundle_dir}"
            )

        stream_doc = json.loads(stream_path.read_bytes())
        if not isinstance(stream_doc, dict):
            raise ValueError("inputs/sensor_stream.json must be a JSON object")
        samples = stream_doc.get("samples", [])
        if not isinstance(samples, list):
            raise ValueError("inputs/sensor_stream.json 'samples' must be a JSON array")

        weights = json.loads(weights_path.read_bytes())
        if not isinstance(weights, dict):
            raise ValueError("payload/fusion_weights.json must be a JSON object")

        R = compute_yield_score_exact(samples, weights)
        return RecomputedValue(
            value={"kind": "rational", "num": R.numerator, "den": R.denominator},
            detail=(
                f"re-derived yield_score over {len(samples)} sensor sample(s): "
                f"R={R.numerator}/{R.denominator} (~{float(R):.6f})"
            ),
        )
