"""_producer_surrogate.py — PRODUCER-SIDE learned surrogate (the ECU half).

This stands in for the deployed tire digital twin: the cheap, closed-form
approximation that runs in-vehicle because the reference solve
(_producer_solve.py) cannot. It is trained OFFLINE against the reference
solver's outputs and then evaluated per sample with a handful of operations.

The property this pilot exists to exhibit
-----------------------------------------
A physics solve satisfies rigid-body equilibrium BY CONSTRUCTION. A learned
per-corner regressor does not: nothing in an independently-fitted per-corner
model forces the four predicted loads to sum to m*g, or their moments to
balance. In-distribution the fit is good enough that the violation is small.
Out-of-distribution it is not -- and the failure is silent, because the model
reports a number with no indication that the number is unphysical.

Two mechanisms produce that behaviour here, both taken from how real fitted
models fail rather than invented for the demo:

1. BASIS MISSPECIFICATION. The true lateral term carries ay*|ay| (an odd
   function, from roll-angle-dependent stiffness migration). The surrogate's
   basis offers ay**2 (even). Over a symmetric training range the odd part is
   absorbed into the linear coefficient and the residual error grows
   super-linearly once |ay| leaves that range.

2. SATURATION AT THE TRAINING ENVELOPE. Fitted models do not extrapolate:
   tree ensembles cannot leave their training range at all, and networks
   saturate. Each corner here is soft-clamped to the load envelope it was
   trained on, with a per-corner compression factor. Because the four corners
   saturate independently and asymmetrically, the aggregate constraints break.

Per-corner ridge penalties differ (independently trained models), which also
removes the coefficient-cancellation that would otherwise let a shared-basis
linear fit reproduce the constant total exactly.

The fit is solved in exact rationals so the produced bundle is byte-stable.

Stdlib only (contract C5). NOT imported by the verifier -- Gate B.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction


@dataclass
class SurrogateStats:
    """Coarse elementary-operation counter for the inference half."""

    ops: int = 0
    samples: int = 0
    saturated_predictions: int = 0
    fit_ops: int = 0


# Per-corner ridge penalties. Distinct by corner: the four corner models are
# trained as separate artifacts in a real pipeline, and nothing couples their
# hyperparameters.
_RIDGE_LAMBDA = (Fraction(1, 2000), Fraction(1, 700), Fraction(1, 1500), Fraction(1, 400))

# Per-corner envelope compression applied outside the trained load range.
_SATURATION_COMPRESSION = (
    Fraction(11, 20),
    Fraction(3, 5),
    Fraction(1, 2),
    Fraction(13, 20),
)


def _basis(ax: Fraction, ay: Fraction) -> list:
    """Design row. Note ay**2 where the truth carries ay*|ay| -- mechanism 1."""
    return [Fraction(1), ax, ay, ay * ay]


def _solve_spd(matrix: list, rhs: list) -> list:
    """Gaussian elimination with partial pivoting over exact Fractions."""
    n = len(rhs)
    aug = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(aug[r][col]))
        if aug[pivot][col] == 0:
            raise ValueError("singular normal-equations matrix")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = Fraction(1) / aug[col][col]
        for r in range(col + 1, n):
            factor = aug[r][col] * inv
            if factor == 0:
                continue
            for c in range(col, n + 1):
                aug[r][c] -= factor * aug[col][c]
    coeffs = [Fraction(0)] * n
    for r in range(n - 1, -1, -1):
        acc = aug[r][n]
        for c in range(r + 1, n):
            acc -= aug[r][c] * coeffs[c]
        coeffs[r] = acc / aug[r][r]
    return coeffs


@dataclass
class CornerModel:
    coeffs: list
    lo: Fraction
    hi: Fraction
    compression: Fraction


def fit(train_samples: list, train_targets: list, stats=None) -> list:
    """Ridge-fit one model per corner against the reference solver's output.

    `train_targets` is a list of per-sample [FL, FR, RL, RR] reference loads.
    Returns four CornerModel objects.
    """
    rows = [
        _basis(Fraction(s["ax_mps2"]), Fraction(s["ay_mps2"])) for s in train_samples
    ]
    width = 4
    models = []
    for corner in range(4):
        targets = [Fraction(row[corner]).limit_denominator(10**9) for row in train_targets]
        normal = [[Fraction(0)] * width for _ in range(width)]
        rhs = [Fraction(0)] * width
        for row, y in zip(rows, targets):
            for i in range(width):
                rhs[i] += row[i] * y
                for j in range(width):
                    normal[i][j] += row[i] * row[j]
        if stats is not None:
            # 2 ops per rhs term, 2 per normal-matrix term, per training row.
            stats.fit_ops += len(rows) * (width * 2 + width * width * 2)
            stats.fit_ops += width ** 3  # elimination
        lam = _RIDGE_LAMBDA[corner] * len(rows)
        for i in range(1, width):  # never penalise the intercept
            normal[i][i] += lam
        coeffs = _solve_spd(normal, rhs)
        models.append(
            CornerModel(
                coeffs=coeffs,
                lo=min(targets),
                hi=max(targets),
                compression=_SATURATION_COMPRESSION[corner],
            )
        )
    return models


def predict(models: list, samples: list, stats: SurrogateStats) -> list:
    """Per-sample [FL, FR, RL, RR] predictions, each rounded to 6 decimals.

    Rounding is what the ECU would publish and is far coarser than float
    noise, so the emitted bundle is byte-identical across platforms.
    """
    out = []
    for s in samples:
        stats.samples += 1
        ax = Fraction(s["ax_mps2"])
        ay = Fraction(s["ay_mps2"])
        row = _basis(ax, ay)
        corner_values = []
        for corner, model in enumerate(models):
            acc = Fraction(0)
            for c, x in zip(model.coeffs, row):
                acc += c * x
                stats.ops += 2
            # Mechanism 2: soft saturation at the trained load envelope.
            if acc > model.hi:
                acc = model.hi + (acc - model.hi) * model.compression
                stats.saturated_predictions += 1
                stats.ops += 3
            elif acc < model.lo:
                acc = model.lo + (acc - model.lo) * model.compression
                stats.saturated_predictions += 1
                stats.ops += 3
            corner_values.append(_round6(acc))
        out.append(corner_values)
    return out


def _round6(value: Fraction) -> str:
    """Round an exact rational to 6 decimals, half-up, as a decimal string."""
    scaled = value * 10**6
    floor_part = scaled.numerator // scaled.denominator
    remainder = scaled - floor_part
    if remainder >= Fraction(1, 2):
        floor_part += 1
    sign = "-" if floor_part < 0 else ""
    floor_part = abs(floor_part)
    whole, frac = divmod(floor_part, 10**6)
    return f"{sign}{whole}.{frac:06d}"
