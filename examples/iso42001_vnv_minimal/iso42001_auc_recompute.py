"""iso42001_auc_recompute.py — verifier-side V&V-metric re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3).

Domain: ISO/IEC 42001:2023 Annex A.6 (AI System Life Cycle) — sub-control
"AI-System Verification and Validation". An organization running a 42001-
conforming AI Management System reports model-validation metrics (here, a binary
classifier's ROC-AUC) in its V&V records. Today an auditor takes that reported
number on the org's word: the test-set evidence and the metric computation are
not independently re-checkable.

Re-derivation primitive (one sentence):
    recompute ROC-AUC from the declared test set as the Mann-Whitney U statistic:
    AUC = (sum of ranks of positive-class scores - n_pos·(n_pos+1)/2)
          ÷ (n_pos · n_neg), with tie-averaged ranks.

Comparator:   rational_band {"epsilon": 1e-9}

The verifier-side recompute (`recompute()`, below) returns the EXACT rational
AUC as {"kind": "rational", "num", "den"} — tie-averaged ranks are computed as
Fractions (avg_rank = Fraction(i + j, 2) + 1, exact for any integer i, j), so
every intermediate and the final AUC expression stays exact rational
arithmetic; no float on the recompute path. This is a SEPARATE implementation
from `compute_roc_auc` below (which stays the float helper shared with
`_build_bundle.py` for the producer's committed claim); the claim is never
derived from the exact path. The producer's claim is the UNROUNDED float AUC;
the auditor-pinned epsilon covers only the producer's float summation/division
noise (a handful of terms, binary64 ulp — negligible against 1e-9's headroom).

The metric method (tie-aware rank-AUC) is FIXED IN THIS PRIMITIVE — the
primitive_id ("iso42001_auc_recompute") IS the rule. The auditor's SHA-pinned
spec binds the output type "model_validation_auc" to this primitive_id, so a
producer cannot swap in a more flattering AUC definition without changing the
primitive_id, which the anchored spec would reject (fail-closed).

HONEST CLAIM BOUNDARY (non-negotiable):
  This proves the REPORTED AUC is RE-DERIVABLE from the declared (label, score)
  pairs and is tamper-evident under the auditor's pinned method. It does NOT
  prove the model is good, NOT that the test set is representative or correctly
  labelled, and NOT that the organization satisfies the A.6 control (which
  requires the V&V *process*, human judgement, and governance the AIMS owns).
  Internal-consistency / re-derivability is the defensible claim. The data is
  synthetic; this is a demonstration, not a customer deployment.

Stdlib-only (§C5 contract). Reads inputs/test_set.json from the bundle; returns
a RecomputedValue carrying the scalar AUC.
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by _build_bundle.py via direct import)
# ---------------------------------------------------------------------------


def compute_roc_auc(evaluations: list) -> float:
    """Compute ROC-AUC from a list of {"label": 0|1, "score": float} records.

    Uses the rank-based Mann-Whitney U identity with tie-averaged ranks — the
    standard exact AUC for a finite sample, fully deterministic and stdlib-only:

        AUC = (R_pos - n_pos·(n_pos+1)/2) / (n_pos · n_neg)

    where R_pos is the sum of the (1-based, tie-averaged) ascending-score ranks
    of the positive-class items.

    Returns a plain float in [0, 1]; comparison tolerance is declared in the
    auditor's pinned spec (rational_band), not here.

    Raises ValueError on empty input or a degenerate single-class test set
    (n_pos == 0 or n_neg == 0), where AUC is undefined.
    """
    if not evaluations:
        raise ValueError("evaluations list is empty — cannot compute ROC-AUC")

    labels: list[int] = []
    scores: list[float] = []
    for ev in evaluations:
        lbl = int(ev["label"])
        if lbl not in (0, 1):
            raise ValueError(f"label must be 0 or 1, got {lbl!r}")
        labels.append(lbl)
        scores.append(float(ev["score"]))

    n_pos = sum(1 for lb in labels if lb == 1)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError(
            "ROC-AUC undefined for a single-class test set "
            f"(n_pos={n_pos}, n_neg={n_neg})"
        )

    # 1-based ascending ranks with tie-averaging.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    n = len(scores)
    while i < n:
        j = i
        while j + 1 < n and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        # positions i..j (0-based) share an averaged 1-based rank.
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1

    sum_ranks_pos = sum(ranks[idx] for idx, lb in enumerate(labels) if lb == 1)
    auc = (sum_ranks_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    return auc


def _compute_roc_auc_exact(evaluations: list) -> Fraction:
    """EXACT-rational tie-averaged rank-AUC — the `rational_band` recompute
    path. Mirrors `compute_roc_auc`'s sort order and tie-detection logic
    verbatim (same `order`/`i`/`j` scan), but every rank and the final
    expression is a `Fraction`: tie-averaged ranks are half-integers,
    `avg_rank = Fraction(i + j, 2) + 1` is exact for any int i, j, and the
    terminal AUC expression is exact rational division (never reduced to a
    float). This is a SEPARATE implementation from `compute_roc_auc` — the
    two must never be unified, since `compute_roc_auc` is the producer's
    committed-claim float path and this is the auditor's exact re-derivation.

    Raises ValueError under the same conditions as `compute_roc_auc` (empty
    input; degenerate single-class test set).
    """
    if not evaluations:
        raise ValueError("evaluations list is empty — cannot compute ROC-AUC")

    labels: list[int] = []
    scores: list[float] = []
    for ev in evaluations:
        lbl = int(ev["label"])
        if lbl not in (0, 1):
            raise ValueError(f"label must be 0 or 1, got {lbl!r}")
        labels.append(lbl)
        scores.append(float(ev["score"]))

    n_pos = sum(1 for lb in labels if lb == 1)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError(
            "ROC-AUC undefined for a single-class test set "
            f"(n_pos={n_pos}, n_neg={n_neg})"
        )

    # 1-based ascending ranks with tie-averaging, in exact Fractions.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks: list[Fraction] = [Fraction(0)] * len(scores)
    i = 0
    n = len(scores)
    while i < n:
        j = i
        while j + 1 < n and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        # positions i..j (0-based) share an averaged 1-based rank — exact
        # half-integer when the tie run has even length.
        avg_rank = Fraction(i + j, 2) + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1

    sum_ranks_pos = sum(
        (ranks[idx] for idx, lb in enumerate(labels) if lb == 1), Fraction(0)
    )
    auc = (sum_ranks_pos - Fraction(n_pos * (n_pos + 1), 2)) / Fraction(n_pos * n_neg)
    return auc


# ---------------------------------------------------------------------------
# ReDerivationPrimitive class (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


class Iso42001AucRecompute:
    """Verifier-side primitive for re-deriving a reported model-validation AUC."""

    primitive_id: str = "iso42001_auc_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute ROC-AUC from inputs/test_set.json in the bundle, as an
        EXACT rational (`rational_band` recompute shape).

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding.

        Returns a RecomputedValue with
        value={"kind": "rational", "num", "den"} and a human-readable
        detail string. Does NOT compare — the verifier's comparator does
        that. Uses `_compute_roc_auc_exact` (Fraction arithmetic) — NEVER
        `compute_roc_auc` (the producer's float helper) — so the claim is
        never derived from the exact path.
        """
        # Import RecomputedValue lazily so this module stays importable without
        # audit_bundle on sys.path when used standalone in _build_bundle.py.
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        ts_path = bundle_dir / "inputs" / "test_set.json"
        if not ts_path.is_file():
            raise FileNotFoundError(
                f"inputs/test_set.json not found in bundle at {bundle_dir}"
            )
        doc = json.loads(ts_path.read_bytes())
        evaluations = doc.get("evaluations")
        if not isinstance(evaluations, list):
            raise ValueError("inputs/test_set.json must contain an 'evaluations' array")
        auc_exact = _compute_roc_auc_exact(evaluations)
        n_pos = sum(1 for e in evaluations if int(e.get("label", 0)) == 1)
        detail = (
            f"re-derived ROC-AUC over {len(evaluations)} test items "
            f"({n_pos} positive / {len(evaluations) - n_pos} negative) "
            f"via tie-averaged Mann-Whitney rank statistic (exact rational); "
            f"auc~{float(auc_exact):.9f}"
        )
        return RecomputedValue(
            value={
                "kind": "rational",
                "num": auc_exact.numerator,
                "den": auc_exact.denominator,
            },
            detail=detail,
        )
