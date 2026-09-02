"""pharmacophore_recompute.py — verifier-side spatial-fit re-derivation
primitives for the pharmacophore_fit_minimal Axis-2 spec-pinned surface.

RATIONAL_BAND_MIGRATION.md §4b.3 (Tier-2 new-claim slice): a GREENFIELD
spec-pinned surface added to the existing pharmacophore_fit_minimal pilot,
which prior to this file had a legacy full-per-candidate-ledger TypedCheck
(`PharmacophoreFitReDerivationCheck` + `pharmacophore_fit_re_derivation.py`)
but NO `spec_pinned/`, no recompute module, and no spec-pinned tests. This is
the SECOND consumer family of the `rational_sqrt_band` comparator kind (the
first is the FEA pilot's witness+certificate posture). The legacy
full-ledger check is UNTOUCHED — this file is purely additive.

Two claims, two primitive_ids, both `rational_sqrt_band`, epsilon=1e-6:

  1. pharmacophore_best_fit_rmsd_recompute
       -> the aggregate RMSD of the BEST-FIT candidate (the candidate with the
          smallest mean squared feature-pair distance against the
          pharmacophore template).
  2. pharmacophore_best_fit_distance_recompute
       -> the single paired feature distance for that SAME best-fit
          candidate's alphabetically-first pharmacophore_feature_id (tie-break
          identical to the legacy pipeline's `sorted(feature_mapping.keys())`
          ordering — see `_build_bundle.py::_compute_fit`).

REPRESENTATIVE-OUTPUT CHOICE (stated here + in spec_pinned/pharmacophore_fit.
spec.json's description): rather than bind EVERY per-candidate/per-pair
distance as a spec-pinned claim (the legacy full ledger already covers that,
in float, via the untouched `PharmacophoreFitReDerivationCheck`), this
greenfield surface commits to exactly ONE RMSD claim and ONE distance claim:
the best-fit candidate's aggregate RMSD and its first (sorted
pharmacophore_feature_id) paired distance. This keeps the new claim set small
and representative while the legacy check continues to cover the complete
per-candidate ledger.

Re-derivation (EXACT rational, no float on the recompute path):
  For each candidate, for each (pharmacophore_feature_id -> candidate_feature_
  id) pair in its `feature_mapping`, recompute the squared distance
      d_sq = (cx-px)^2 + (cy-py)^2 + (cz-pz)^2
  as an exact `Fraction` — `Fraction(float)` is exact for every binary64
  operand, and the committed positions are float literals in the bundle's
  committed JSON (produced by the same `round(..., 6)` the legacy builder
  already applies at synthesis time, so no additional rounding is introduced
  here). A candidate's mean_sq = sum(d_sq over its pairs) / paired_count is
  an exact Fraction. The best-fit candidate is the one with the SMALLEST
  mean_sq (argmin over exact Fractions — sqrt is monotone, so ranking by
  mean_sq is equivalent to ranking by RMSD without ever taking a sqrt to
  find the ranking); ties broken by ascending compound_id (matches the
  legacy `run_spatial_fit` tie-break — in practice irrelevant here since the
  fixture's per-candidate noise scale strictly increases with candidate
  index, see `_build_bundle.py::_noise_scale_for_index`, but kept so the
  primitive stays correct if the fixture ever changes).

  RMSD claim:      M = mean_sq of the best-fit candidate       -> sqrt_of_rational
  Distance claim:  M = d_sq of that candidate's first (sorted
                   pharmacophore_feature_id) pair                -> sqrt_of_rational

This is a SEPARATE implementation from `_compute_fit` / `run_spatial_fit` in
`_build_bundle.py` (the producer's float pipeline the legacy check replays
and the honest claim in `outputs/*.json` is drawn from); the claim value is
NEVER derived from this exact path. No float arithmetic appears anywhere in
`recompute()` or its helpers.

Stdlib-only (§C5 contract).
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path


def _load_inputs(bundle_dir: Path) -> tuple[list[dict], list[dict]]:
    tmpl = json.loads(
        (bundle_dir / "inputs" / "pharmacophore_template.json").read_bytes()
    )
    conf = json.loads(
        (bundle_dir / "inputs" / "candidate_conformers.json").read_bytes()
    )
    return tmpl["features"], conf["candidates"]


def _exact_pair_distances_sq(
    pharma_features: list[dict], candidate: dict
) -> dict[str, Fraction]:
    """pharmacophore_feature_id -> exact squared distance (Fraction arithmetic)
    for one candidate, over its declared `feature_mapping`."""
    pf_by_id = {pf["feature_id"]: pf for pf in pharma_features}
    cf_by_id = {cf["feature_id"]: cf for cf in candidate["features"]}
    feature_mapping = candidate["feature_mapping"]
    if not isinstance(feature_mapping, dict) or not feature_mapping:
        raise ValueError(
            f"candidate {candidate.get('compound_id')!r} has no non-empty "
            "feature_mapping"
        )
    out: dict[str, Fraction] = {}
    for pf_id, cf_id in feature_mapping.items():
        pf = pf_by_id[pf_id]
        cf = cf_by_id[cf_id]
        dx = Fraction(cf["position"][0]) - Fraction(pf["position"][0])
        dy = Fraction(cf["position"][1]) - Fraction(pf["position"][1])
        dz = Fraction(cf["position"][2]) - Fraction(pf["position"][2])
        out[pf_id] = dx * dx + dy * dy + dz * dz
    return out


def _exact_mean_sq(pair_sq: dict[str, Fraction]) -> Fraction:
    if not pair_sq:
        raise ValueError(
            "candidate has zero paired features — mean squared distance undefined"
        )
    total = Fraction(0)
    for v in pair_sq.values():
        total += v
    return total / len(pair_sq)


def find_best_fit_exact(
    pharma_features: list[dict], candidates: list[dict]
) -> tuple[dict, Fraction, dict[str, Fraction]]:
    """Return (best_candidate, best_mean_sq, best_pair_sq) — the candidate
    with the smallest exact mean-squared distance against the pharmacophore
    template (argmin over Fractions; ties broken by ascending compound_id).
    """
    if not candidates:
        raise ValueError("no candidates to fit")
    best: tuple[tuple[Fraction, str], dict, Fraction, dict[str, Fraction]] | None = None
    for c in candidates:
        pair_sq = _exact_pair_distances_sq(pharma_features, c)
        mean_sq = _exact_mean_sq(pair_sq)
        key = (mean_sq, c["compound_id"])
        if best is None or key < best[0]:
            best = (key, c, mean_sq, pair_sq)
    assert best is not None
    _, c, mean_sq, pair_sq = best
    return c, mean_sq, pair_sq


# ---------------------------------------------------------------------------
# ReDerivationPrimitive classes (registered by verify.py / spec_pinned_check.py
# before BundleVerifier is constructed)
# ---------------------------------------------------------------------------


class PharmacophoreBestFitRmsdRecompute:
    """Verifier-side primitive: re-derives the best-fit candidate's aggregate
    RMSD as an exact rational mean-squared distance (`rational_sqrt_band`
    recompute shape)."""

    primitive_id: str = "pharmacophore_best_fit_rmsd_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        pharma_features, candidates = _load_inputs(bundle_dir)
        best_c, mean_sq, _ = find_best_fit_exact(pharma_features, candidates)
        return RecomputedValue(
            value={
                "kind": "sqrt_of_rational",
                "num": mean_sq.numerator,
                "den": mean_sq.denominator,
            },
            detail=(
                f"best-fit candidate {best_c['compound_id']!r}: exact "
                f"mean-sq={mean_sq}, RMSD~{float(mean_sq) ** 0.5:.9f}"
            ),
        )


class PharmacophoreBestFitDistanceRecompute:
    """Verifier-side primitive: re-derives the best-fit candidate's
    representative (first sorted pharmacophore_feature_id) paired feature
    distance as an exact rational squared distance (`rational_sqrt_band`
    recompute shape)."""

    primitive_id: str = "pharmacophore_best_fit_distance_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        pharma_features, candidates = _load_inputs(bundle_dir)
        best_c, _, pair_sq = find_best_fit_exact(pharma_features, candidates)
        rep_feature_id = sorted(pair_sq.keys())[0]
        d_sq = pair_sq[rep_feature_id]
        return RecomputedValue(
            value={
                "kind": "sqrt_of_rational",
                "num": d_sq.numerator,
                "den": d_sq.denominator,
            },
            detail=(
                f"best-fit candidate {best_c['compound_id']!r}, representative "
                f"pair {rep_feature_id!r}: exact d^2={d_sq}, "
                f"distance~{float(d_sq) ** 0.5:.9f}"
            ),
        )
