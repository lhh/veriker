"""_producer_solve.py — the ANALYST's own plane-stress CST solver.

This module is the producer's half of `fea_vonmises_minimal`. It is a
SEPARATELY MAINTAINED implementation of the algorithm the auditor pinned:
constant-strain-triangle assembly, boundary-condition application, a conjugate-
gradient solve at the committed `tol` / `max_iter`, and element stress recovery.

It must never import `audit_bundle.rederivation.primitives.*`. If it did, the
producer's claimed `sigma_vm_max` would BE the verifier's recompute and the
pilot's PASS would be `f(x) == f(x)`. The rule is enforced two ways: by this
pilot's own AST test, and repo-wide by
`tests/test_recipe_producer_verifier_disjoint.py`, which auto-discovers every
pilot binding a distribution primitive.

WHAT THE DUPLICATION BUYS, precisely. An honest PASS shows the claim was
produced HERE rather than copied from the checker. It does NOT show solver
independence: the auditor pinned this algorithm, so a producer running a
different solver would be running a different method. The solver-independent
posture is a different shape entirely; see
`audit_bundle/rederivation/PRIMITIVES.md` for the certificate family that
carries it.

AND THE TWO COPIES ARE NOT BIT-IDENTICAL — the difference is exact and singular,
measured rather than supposed. `conjugate_gradient` below accumulates its
matrix-vector product in an explicit loop; the verifier's copy writes the same
product as a builtin `sum()` over a generator, and on CPython 3.12 `sum()`
applies compensated (Neumaier) summation while an explicit `+=` fold does not.
From CG iteration 2 onward 8 of this problem's 36 rows differ in their last
bits, and that reaches `sigma_vm_max` as 1.4e-12 (CPython 3.12.3). Everything
else — assembly, the boundary-condition passes, stress recovery — is bit-equal,
verified term by term.

That single difference is why the auditor binds `scalar_epsilon` and not
`exact`: compensated summation is a CPython implementation detail, not a
property of IEEE-754, so an exact comparator would bind the claim to one
interpreter. `test_the_two_implementations_are_not_the_same_arithmetic` in this
pilot's battery keeps the statement measured on whatever interpreter runs it.

Stdlib-only (math).
"""

from __future__ import annotations

import math

# --------------------------------------------------------------------------- #
# Element level
# --------------------------------------------------------------------------- #


def cst_element(p_i, p_j, p_k, youngs_modulus, poisson, thickness):
    """Stiffness, strain-displacement and constitutive matrices for one CST.

    Returns (Ke, B, D, area). Nodes are expected counter-clockwise; `area` is
    taken as the magnitude of the signed area so Ke stays positive
    semi-definite for either winding.
    """
    (xi, yi), (xj, yj), (xk, yk) = p_i, p_j, p_k
    signed_two_area = (xj - xi) * (yk - yi) - (xk - xi) * (yj - yi)
    area = abs(signed_two_area) / 2.0
    if area == 0.0:
        raise ValueError("degenerate CST element (zero area)")

    # Shape-function gradients: dN/dx = b/(2A), dN/dy = c/(2A).
    b = (yj - yk, yk - yi, yi - yj)
    c = (xk - xj, xi - xk, xj - xi)
    scale = 1.0 / (2.0 * area)

    B = [
        [b[0] * scale, 0.0, b[1] * scale, 0.0, b[2] * scale, 0.0],
        [0.0, c[0] * scale, 0.0, c[1] * scale, 0.0, c[2] * scale],
        [
            c[0] * scale,
            b[0] * scale,
            c[1] * scale,
            b[1] * scale,
            c[2] * scale,
            b[2] * scale,
        ],
    ]

    # Plane-stress constitutive matrix.
    lead = youngs_modulus / (1.0 - poisson * poisson)
    D = [
        [lead, lead * poisson, 0.0],
        [lead * poisson, lead, 0.0],
        [0.0, 0.0, lead * (1.0 - poisson) / 2.0],
    ]

    # Ke = A * t * B^T D B, formed via the intermediate DB.
    DB = [[sum(D[r][s] * B[s][col] for s in range(3)) for col in range(6)] for r in range(3)]
    Ke = [
        [area * thickness * sum(B[s][row] * DB[s][col] for s in range(3)) for col in range(6)]
        for row in range(6)
    ]
    return Ke, B, D, area


def _dof_map(triangle):
    out = []
    for node in triangle:
        out.append(2 * node)
        out.append(2 * node + 1)
    return out


# --------------------------------------------------------------------------- #
# System level
# --------------------------------------------------------------------------- #


def assemble(mesh: dict, material: dict):
    """Assemble the global stiffness matrix. Returns (K, element_data)."""
    nodes = mesh["nodes"]
    youngs_modulus = float(material["E"])
    poisson = float(material["nu"])
    thickness = float(material["thickness"])

    ndof = 2 * len(nodes)
    K = [[0.0] * ndof for _ in range(ndof)]
    element_data = []
    for triangle in mesh["elements"]:
        i, j, k = triangle
        Ke, B, D, area = cst_element(
            nodes[i], nodes[j], nodes[k], youngs_modulus, poisson, thickness
        )
        dofs = _dof_map(triangle)
        for local_row, global_row in enumerate(dofs):
            target = K[global_row]
            source = Ke[local_row]
            for local_col, global_col in enumerate(dofs):
                target[global_col] += source[local_col]
        element_data.append((dofs, B, D, area))
    return K, element_data


def _bc_dof(entry) -> int:
    return 2 * int(entry["node"]) + (0 if entry["dof"] == "x" else 1)


def apply_neumann(f: list, neumann) -> None:
    """Accumulate nodal loads into the right-hand side."""
    for entry in neumann:
        f[_bc_dof(entry)] += float(entry["value"])


def apply_dirichlet(K: list, f: list, dirichlet) -> None:
    """Impose prescribed displacements by row/column elimination.

    The known value is moved to the right-hand side before the column is
    cleared. Every prescribed value in this pilot's committed problem is zero,
    so the transfer term is identically zero — it is written out anyway so the
    routine is correct on its own terms rather than only on this fixture.
    """
    ndof = len(f)
    for entry in dirichlet:
        dof = _bc_dof(entry)
        value = float(entry["value"])
        if value != 0.0:
            for row in range(ndof):
                f[row] -= K[row][dof] * value
        for other in range(ndof):
            K[dof][other] = 0.0
            K[other][dof] = 0.0
        K[dof][dof] = 1.0
        f[dof] = value


def conjugate_gradient(K: list, f: list, tol: float, max_iter: int) -> list:
    """Solve K u = f by conjugate gradients, stopping on ||r|| <= tol."""
    ndof = len(f)
    u = [0.0] * ndof
    residual = list(f)
    direction = list(residual)
    rr = 0.0
    for value in residual:
        rr += value * value

    for _step in range(max_iter):
        kd = []
        for row in range(ndof):
            row_values = K[row]
            acc = 0.0
            for col in range(ndof):
                acc += row_values[col] * direction[col]
            kd.append(acc)

        curvature = 0.0
        for idx in range(ndof):
            curvature += direction[idx] * kd[idx]
        if curvature == 0.0:
            break

        step = rr / curvature
        for idx in range(ndof):
            u[idx] += step * direction[idx]
            residual[idx] -= step * kd[idx]

        rr_next = 0.0
        for value in residual:
            rr_next += value * value
        if math.sqrt(rr_next) <= tol:
            break
        blend = rr_next / rr
        for idx in range(ndof):
            direction[idx] = residual[idx] + blend * direction[idx]
        rr = rr_next
    return u


# --------------------------------------------------------------------------- #
# Stress recovery
# --------------------------------------------------------------------------- #


def element_von_mises(u: list, dofs, B, D) -> float:
    """von-Mises stress of one constant-strain element."""
    u_e = [u[d] for d in dofs]
    strain = [sum(B[r][col] * u_e[col] for col in range(6)) for r in range(3)]
    sxx, syy, sxy = (
        sum(D[r][s] * strain[s] for s in range(3)) for r in range(3)
    )
    return math.sqrt(sxx * sxx - sxx * syy + syy * syy + 3.0 * sxy * sxy)


def max_von_mises(u: list, element_data) -> float:
    """The producer's claimed quantity: max element von-Mises stress."""
    peak = 0.0
    for dofs, B, D, _area in element_data:
        stress = element_von_mises(u, dofs, B, D)
        if stress > peak:
            peak = stress
    return peak


def solve(mesh: dict, material: dict, bcs: dict, solver_config: dict):
    """Run the full producer analysis. Returns (u, sigma_vm_max)."""
    K, element_data = assemble(mesh, material)
    f = [0.0] * (2 * len(mesh["nodes"]))
    apply_neumann(f, bcs["neumann"])
    apply_dirichlet(K, f, bcs["dirichlet"])
    u = conjugate_gradient(
        K, f, float(solver_config["tol"]), int(solver_config["max_iter"])
    )
    return u, max_von_mises(u, element_data)
