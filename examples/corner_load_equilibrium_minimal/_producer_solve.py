"""_producer_solve.py — PRODUCER-SIDE reference solver (the expensive half).

This is the computation that CANNOT run on a vehicle ECU at 1 kHz, and is
therefore the thing a deployed tire digital twin approximates. It is here so
the pilot can (a) generate physically-consistent reference corner loads and
(b) MEASURE the solve/verify compute asymmetry rather than assert it.

Physics
-------
Quasi-static vertical load distribution over four contact patches for a rigid
chassis on a compliant suspension.

Longitudinal (pitch) transfer and total lateral (roll) transfer are fixed by
rigid-body statics:

    Fz_front = m*g*b/L - m*ax*h/L
    Fz_rear  = m*g*a/L + m*ax*h/L
    dY_total = m*ay*h/t

The FRONT/REAR SPLIT of dY_total is NOT fixed by statics. It follows from the
suspension roll-stiffness distribution, which is progressive: the anti-roll
bars stiffen with roll angle, so the split migrates forward as the chassis
rolls. Finding it requires solving

    K0*phi + K2*phi**3 = m_s * ay * h_roll                      (cubic in phi)

by Newton iteration, then evaluating the stiffness-weighted split at the
solved roll angle. THAT is the expensive, IP-bearing, surrogate-approximated
part -- and, importantly, it is invisible to the three equilibrium residuals
the auditor checks (see README "What this does and does not constrain").

Outputs from this module satisfy all three equilibrium conditions to machine
precision BY CONSTRUCTION, because the aggregate quantities are imposed and
only the split is solved for. It is the honest reference.

Op counting: `SolveStats.ops` accumulates elementary float operations so the
pilot can report a measured solve/verify ratio. Counting is deliberately
coarse (one unit per arithmetic op in the hot path); it is an order-of-
magnitude instrument, not a benchmark.

Stdlib only (contract C5). NOT imported by the verifier -- see Gate B note in
_build_bundle.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SolveStats:
    """Coarse elementary-operation counter for the solve half."""

    ops: int = 0
    newton_iterations: int = 0
    samples: int = 0
    max_iterations_used: int = 0
    residual_history: list = field(default_factory=list)


# Newton controls. Fixed iteration cap + fixed tolerance keeps the solve
# deterministic, which keeps the produced bundle byte-stable.
_NEWTON_TOL = 1e-13
_NEWTON_MAX_ITER = 40


def _solve_roll_angle(
    rhs: float, k0: float, k2: float, stats: SolveStats
) -> float:
    """Solve K0*phi + K2*phi**3 = rhs for phi by Newton iteration.

    Monotone increasing in phi for k0, k2 > 0, so Newton from phi=0 converges
    for any finite rhs. Returns the solved roll angle in radians.
    """
    phi = 0.0
    for _ in range(_NEWTON_MAX_ITER):
        stats.newton_iterations += 1
        f = k0 * phi + k2 * phi * phi * phi - rhs          # 5 ops
        df = k0 + 3.0 * k2 * phi * phi                     # 4 ops
        stats.ops += 9
        step = f / df                                       # 1 op
        stats.ops += 1
        phi -= step                                         # 1 op
        stats.ops += 1
        if abs(step) < _NEWTON_TOL:
            break
    return phi


def solve_corner_loads(vehicle: dict, samples: list, stats: SolveStats) -> list:
    """Reference per-sample corner loads [Fz_FL, Fz_FR, Fz_RL, Fz_RR] in N.

    `vehicle` carries exact decimal strings; they are floated here because the
    producer's solver is a float computation (as a real one would be). The
    AUDITOR side never floats anything -- it works in exact rationals.
    """
    m = float(vehicle["mass_kg"])
    g = float(vehicle["gravity_mps2"])
    a = float(vehicle["cg_to_front_axle_m"])
    b = float(vehicle["cg_to_rear_axle_m"])
    t = float(vehicle["track_width_m"])
    h = float(vehicle["cg_height_m"])
    m_s = float(vehicle["sprung_mass_kg"])
    h_roll = float(vehicle["roll_moment_arm_m"])
    k0 = float(vehicle["roll_stiffness_nm_per_rad"])
    k2 = float(vehicle["roll_stiffness_cubic_nm_per_rad3"])
    chi_0 = float(vehicle["front_roll_stiffness_fraction"])
    chi_gain = float(vehicle["front_roll_stiffness_phi_gain"])

    L = a + b
    stats.ops += 1
    W = m * g
    stats.ops += 1

    out = []
    for s in samples:
        stats.samples += 1
        ax = float(s["ax_mps2"])
        ay = float(s["ay_mps2"])

        # --- Aggregates fixed by rigid-body statics (cheap, exact in form) ---
        fz_f = W * b / L - m * ax * h / L                   # 7 ops
        fz_r = W * a / L + m * ax * h / L                   # 7 ops
        dy_total = m * ay * h / t                           # 3 ops
        stats.ops += 17

        # --- The expensive part: solve for roll angle, then the split -------
        rhs = m_s * ay * h_roll                             # 2 ops
        stats.ops += 2
        phi = _solve_roll_angle(rhs, k0, k2, stats)

        # Progressive bars migrate roll stiffness forward with |phi|.
        chi = chi_0 + chi_gain * abs(phi)                   # 2 ops
        stats.ops += 2
        if chi < 0.0:
            chi = 0.0
        elif chi > 1.0:
            chi = 1.0

        dy_f = chi * dy_total                               # 1 op
        dy_r = dy_total - dy_f                              # 1 op
        stats.ops += 2

        fz_fl = fz_f * 0.5 - dy_f                           # 2 ops
        fz_fr = fz_f * 0.5 + dy_f                           # 2 ops
        fz_rl = fz_r * 0.5 - dy_r                           # 2 ops
        fz_rr = fz_r * 0.5 + dy_r                           # 2 ops
        stats.ops += 8

        out.append([fz_fl, fz_fr, fz_rl, fz_rr])

    if stats.samples:
        stats.max_iterations_used = _NEWTON_MAX_ITER
    return out
