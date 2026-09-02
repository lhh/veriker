"""_producer_solve.py — the PRODUCER's structural solver. Verifier-side code
never imports this, and this never imports verifier-side code.

This is the half of the pilot that stands in for the analyst's tool — Abaqus,
Nastran, a research code, an agent that wrote its own solver this morning. The
point of the witness+certificate posture is that the verifier does not care
which: it never runs any of them.

Two INDEPENDENT solvers ship here on purpose:

  * `solve_cg`    — matrix-free-ish conjugate gradient, iterative, converges to
                    a tolerance.
  * `solve_dense` — dense Gaussian elimination with partial pivoting, direct.

They produce DIFFERENT displacement vectors (different arithmetic, different
error), and both satisfy equilibrium. Both therefore pass the SAME auditor
certificate. That is the demonstration: the producer is unconstrained in HOW it
solves, and the verifier's acceptance does not encode a solver choice.

GATE B (PRIMITIVES.md, promotion criteria — producer<->verifier non-tautology): every number the
bundle CLAIMS is computed here. `audit_bundle.rederivation.primitives.*` must
never be imported by this module or by `_build_bundle.py` — the certificate
would then be checking its own output. `tests/test_recipe_producer_verifier_
disjoint.py` fails closed on that edit.

Plane-stress linear-elastic CST triangles, stdlib only (contract C5).
"""

from __future__ import annotations

import math


def _cst_geometry(coords: list[list[float]]) -> tuple[float, list[float], list[float]]:
    """Return (area, b, c) for one CST triangle. b_i = y_j - y_k and
    c_i = x_k - x_j, cyclic over (i, j, k); 2A is the signed determinant."""
    (x1, y1), (x2, y2), (x3, y3) = coords
    two_a = x1 * (y2 - y3) + x2 * (y3 - y1) + x3 * (y1 - y2)
    b = [y2 - y3, y3 - y1, y1 - y2]
    c = [x3 - x2, x1 - x3, x2 - x1]
    return two_a / 2.0, b, c


def _d_matrix(e: float, nu: float) -> list[list[float]]:
    """Plane-stress constitutive matrix."""
    f = e / (1.0 - nu * nu)
    return [[f, f * nu, 0.0], [f * nu, f, 0.0], [0.0, 0.0, f * (1.0 - nu) / 2.0]]


def _b_matrix(area: float, b: list[float], c: list[float]) -> list[list[float]]:
    """Strain-displacement matrix (3 x 6) for a CST triangle."""
    k = 1.0 / (2.0 * area)
    return [
        [k * b[0], 0.0, k * b[1], 0.0, k * b[2], 0.0],
        [0.0, k * c[0], 0.0, k * c[1], 0.0, k * c[2]],
        [k * c[0], k * b[0], k * c[1], k * b[1], k * c[2], k * b[2]],
    ]


def assemble(mesh: dict, material: dict) -> tuple[list[list[float]], list[dict]]:
    """Assemble the global stiffness K and per-element (dofs, D·B) data."""
    nodes, elements = mesh["nodes"], mesh["elements"]
    e, nu, t = material["E"], material["nu"], material["thickness"]
    d = _d_matrix(e, nu)
    n_dofs = len(nodes) * 2
    k_global = [[0.0] * n_dofs for _ in range(n_dofs)]
    element_data = []
    for tri in elements:
        coords = [nodes[i] for i in tri]
        area, b, c = _cst_geometry(coords)
        bm = _b_matrix(area, b, c)
        db = [[sum(d[r][s] * bm[s][col] for s in range(3)) for col in range(6)]
              for r in range(3)]
        ke = [[t * area * sum(bm[s][r] * db[s][col] for s in range(3))
               for col in range(6)] for r in range(6)]
        dofs = [2 * n + k for n in tri for k in (0, 1)]
        for i, gi in enumerate(dofs):
            for j, gj in enumerate(dofs):
                k_global[gi][gj] += ke[i][j]
        element_data.append({"dofs": dofs, "db": db})
    return k_global, element_data


def apply_neumann(f: list[float], neumann: list[dict]) -> None:
    for load in neumann:
        f[2 * load["node"] + (0 if load["dof"] == "x" else 1)] += load["value"]


def apply_dirichlet(k: list[list[float]], f: list[float], dirichlet: list[dict]) -> None:
    """Row/column replacement for prescribed DOFs, values carried to the RHS."""
    n = len(f)
    for bc in dirichlet:
        idx = 2 * bc["node"] + (0 if bc["dof"] == "x" else 1)
        val = float(bc["value"])
        for j in range(n):
            if j != idx:
                f[j] -= k[j][idx] * val
                k[j][idx] = 0.0
                k[idx][j] = 0.0
        k[idx][idx] = 1.0
        f[idx] = val


def solve_cg(k: list[list[float]], f: list[float], tol: float, max_iter: int) -> list[float]:
    """Conjugate gradient — ITERATIVE. One of the two shipped solvers."""
    n = len(f)
    u = [0.0] * n
    r = list(f)
    p = list(r)
    rs = sum(v * v for v in r)
    if rs == 0.0:
        return u
    for _ in range(max_iter):
        kp = [sum(k[i][j] * p[j] for j in range(n)) for i in range(n)]
        denom = sum(p[i] * kp[i] for i in range(n))
        if denom == 0.0:
            break
        alpha = rs / denom
        u = [u[i] + alpha * p[i] for i in range(n)]
        r = [r[i] - alpha * kp[i] for i in range(n)]
        rs_new = sum(v * v for v in r)
        if math.sqrt(rs_new) < tol:
            break
        p = [r[i] + (rs_new / rs) * p[i] for i in range(n)]
        rs = rs_new
    return u


def solve_dense(k: list[list[float]], f: list[float], tol: float, max_iter: int) -> list[float]:
    """Dense Gaussian elimination with partial pivoting — DIRECT, and entirely
    unrelated to `solve_cg`. `tol` / `max_iter` are accepted and ignored so the
    two solvers are interchangeable at the call site.

    Produces a different float vector than CG on the same problem; the auditor
    certificate accepts both, because it checks equilibrium rather than
    reproduction."""
    n = len(f)
    a = [row[:] + [f[i]] for i, row in enumerate(k)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(a[r][col]))
        if abs(a[pivot][col]) == 0.0:
            raise ValueError(f"singular stiffness matrix at column {col}")
        a[col], a[pivot] = a[pivot], a[col]
        inv = 1.0 / a[col][col]
        for r in range(col + 1, n):
            factor = a[r][col] * inv
            if factor != 0.0:
                for cc in range(col, n + 1):
                    a[r][cc] -= factor * a[col][cc]
    u = [0.0] * n
    for row in range(n - 1, -1, -1):
        acc = a[row][n] - sum(a[row][cc] * u[cc] for cc in range(row + 1, n))
        u[row] = acc / a[row][row]
    return u


SOLVERS = {"cg": solve_cg, "dense": solve_dense}


def von_mises(sx: float, sy: float, sxy: float) -> float:
    return math.sqrt(sx * sx - sx * sy + sy * sy + 3.0 * sxy * sxy)


def output_norms(u: list[float], element_data: list[dict]) -> dict:
    """The producer's claimed quantities, recovered from ITS OWN displacement
    solution: max element von-Mises stress, and the two displacement norms."""
    sigma_vm_max = 0.0
    for elem in element_data:
        ue = [u[d] for d in elem["dofs"]]
        sx, sy, sxy = (sum(elem["db"][r][c] * ue[c] for c in range(6)) for r in range(3))
        sigma_vm_max = max(sigma_vm_max, von_mises(sx, sy, sxy))
    return {
        "sigma_vm_max": sigma_vm_max,
        "u_norm_2": math.sqrt(sum(v * v for v in u)),
        "u_norm_inf": max(abs(v) for v in u),
        "n_dofs": len(u),
    }
