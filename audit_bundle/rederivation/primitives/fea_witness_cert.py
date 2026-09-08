"""fea_witness_certificate — witness+certificate FEA verification (never solves).

The fused primitive (`fea_vonmises_recompute`) RE-RUNS the producer's solve —
the posture that is unaffordable at a chokepoint and impossible against a
proprietary solver. This primitive is the factored form (graduated from the
E4/E4b spike, the internal design notes
e4_witness_certificate/, merged 2026-07-20): the producer commits the
DISPLACEMENT FIELD as a witness (payload/displacement_field.json), and the
verifier checks the CERTIFICATE — Dirichlet values hold exactly, the
equilibrium residual on the free DOFs of the ORIGINAL assembled K is inside the
auditor-anchored tolerance, and the claimed max von-Mises stress is compared
(by the bound `rational_sqrt_band` comparator) against the stress the witness
algebraically implies. It never runs any solver, so it is solver-independent by
construction: a Gaussian-elimination solve and a CG solve that both satisfy
equilibrium pass the SAME certificate.

EXACTNESS: every bundle input is a JSON number → exact binary64 → exact
`Fraction`. Assembly, the residual, and stress recovery are rational arithmetic
throughout (the only divisions are 2A and 1−ν², both guarded). The claim-band
comparison is the comparator's, decided exactly on squares. The whole check
path has ZERO float ambiguity; the only approximate objects are the two
DECLARED tolerances (equilibrium_tol, epsilon), which are auditor-anchored
data in the binding spec, never producer-committed.

ROW-REPLACEMENT NEVER TRUSTED: Dirichlet DOFs are checked u_i == value exactly;
the residual is evaluated on the FREE DOFs of the ORIGINAL K (full rows,
prescribed columns included). A producer whose solver mishandles nonzero
prescribed values fails equilibrium here even though its own re-run would
"reproduce" (reproduction ≠ physics).

DECLARED SEMANTICS HONORED (spike blind-refutation R4, extended): the input
anchor pins BYTES; it cannot make the checker read them as the documents
declare. So the certificate REFUSES any committed input whose declared
semantics this checker does not implement: material must declare
model=linear_elastic_isotropic + stress_state=plane_stress, mesh must declare
element_type=CST + dim=2 (the mesh guard EXTENDS the spike, which guarded
material only). Physical admissibility (E > 0, t > 0, −1 < ν < 1/2) is
fail-closed — never a certificate over nonsense.

INPUT ANCHOR (spike E4b leg 1): the binding spec's comparator params MAY carry
input_anchor: {role → sha256} over the roles in ROLE_PATHS. Present → the
committed bytes must match or the certificate refuses (the H1 kill shot: an
honest witness for a SUBSTITUTED lighter load case passes unanchored and REDs
anchored). Roles are validated against the COMPUTED role set — an anchor naming
an unknown role is refused, never silently ignored. Absent → unanchored mode:
the certificate degrades to the witness-implied-stress predicate over a
producer-chosen problem, and says so in its detail.

CONDITIONING BOUND δ (spike E4b leg 2): with conditioning_bound=true (which
REQUIRES the full input anchor — δ over a producer-chosen problem answers the
wrong question), the primitive computes
    δ = √(‖Q‖∞) · maxₑ‖D·B_e‖₂ · ‖K_ff⁻¹‖∞ · tol
in exact rational arithmetic, every step an OVERestimate, K_ff symmetry
VERIFIED not assumed, and returns the exact certified interval ε+δ. The
comparator enforces that the producer's COMMITTED certified_interval is >= it
(understated interval = false certificate) while the acceptance criterion stays
ε (δ REPORTS, it never RELAXES — spike blind-refutation R1). The guarantee over
accepted claims: |sigma_vm_max_claim − sigma_vm_max_true| <= the committed
interval. SCALE: the exact rational inverse is a PILOT-SCALE method (O(n³)
rational ops); industrial meshes need a certified λmin route — named, NOT
built (spike bound B-delta-scale).

QUANTITY = PRIMITIVE IDENTITY (rational_band slice, RATIONAL_BAND_SCOPE.md;
REVISED at build time): the witness-implied quantity is part of the PRIMITIVE
IDENTITY — three registered ids (`fea_witness_certificate` → sigma_vm_max,
unchanged; `fea_witness_certificate_u_norm_2`;
`fea_witness_certificate_u_norm_inf`) — NOT a spec param. The first cut put
`quantity` in the binding params and the dispatch layer rejected it at anchor
load: §4a.3 monotone-strictness forbids one primitive_id bound by types with
non-identical comparators (a producer could claim the weaker type — strength
substitution). Making the quantity part of the identity puts the semantic
difference where the substrate can see it; each id is bound by exactly one
type. A params `quantity` key that CONTRADICTS the bound identity is refused
(never silently ignored); absent is the normal case. ALL quantities run the
FULL certificate gates first (anchor, declared semantics, admission,
Dirichlet exact, equilibrium ≤ tol) — a norms claim over a witness that
fails the certificate is refused, never certified. The recompute then returns
the witness-implied quantity: sigma_vm_max → sqrt_of_rational M_max;
u_norm_2 → sqrt_of_rational Σu_i²; u_norm_inf → rational max|u_i|.
SUMMATION DOMAIN: the norms range over ALL DOFs, prescribed included —
matching the producer's committed output_norms semantics (the certificate has
already enforced the prescribed entries exactly, so the true solution shares
them and the error field Δ is exactly zero there).

CONDITIONING BOUND FOR THE NORMS (δ_u): with conditioning_bound=true (full
anchor required, same coupling), δ_u = ‖K_ff⁻¹‖∞ · tol. Chain (every step an
overestimate): Dirichlet exact ⟹ r_F = K_ff·Δ_F exactly; ‖Δ_F‖₂ ≤
‖K_ff⁻¹‖₂·‖r_F‖₂ ≤ ‖K_ff⁻¹‖∞·tol (K_ff symmetry VERIFIED, so ‖·‖₂ = ρ ≤
‖·‖∞; ‖r_F‖₂ ≤ tol is exactly what the residual gate established); Δ is zero
on prescribed DOFs, so ‖Δ‖∞ = ‖Δ_F‖∞ ≤ ‖Δ_F‖₂ and ‖Δ‖₂ = ‖Δ_F‖₂; max_i|·|
is 1-Lipschitz in ‖·‖∞ and ‖·‖₂ is 1-Lipschitz in ‖·‖₂ (reverse triangle).
Hence |norm(u_wit) − norm(u_true)| ≤ δ_u for BOTH norms quantities. The
certified interval ε+δ_u rides the same committed-claim mechanism as the
sigma slice (understated ⇒ RED).

Determinate refusals return {"kind": "refused", "reason_code", "detail"} —
the comparator maps them to a REJECT with a stable machine-readable code.
Raised exceptions (verifier-side malformation) become RECOMPUTE_ERROR at the
dispatch boundary. On THIS substrate both aggregate to REJECT; the split buys
a reason-code ABI, not a verdict distinction.

Stdlib-only (json, math, re, hashlib, fractions) — open tier.
"""

from __future__ import annotations

import hashlib
import math
import re
from fractions import Fraction
from pathlib import Path

from ...admission import admit_bytes
from ...strict_json import strict_json_loads
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive

# ---------------------------------------------------------------------------
# Reason codes (closed set; surfaced verbatim in the comparator's REJECT detail)
# ---------------------------------------------------------------------------
PARAMS_MALFORMED = "FEA_CERT_PARAMS_MALFORMED"
ANCHOR_ROLE_UNDECLARED = "FEA_CERT_ANCHOR_ROLE_UNDECLARED"
CONDITIONING_REQUIRES_FULL_ANCHOR = "FEA_CERT_CONDITIONING_REQUIRES_FULL_ANCHOR"
EVIDENCE_MISSING = "FEA_CERT_EVIDENCE_MISSING"
EVIDENCE_MALFORMED = "FEA_CERT_EVIDENCE_MALFORMED"
INPUT_ANCHOR_MISMATCH = "FEA_CERT_INPUT_ANCHOR_MISMATCH"
INPUT_MALFORMED = "FEA_CERT_INPUT_MALFORMED"
DEGENERATE_ELEMENT = "FEA_CERT_DEGENERATE_ELEMENT"
WITNESS_MALFORMED = "FEA_CERT_WITNESS_MALFORMED"
DIRICHLET_VIOLATION = "FEA_CERT_DIRICHLET_VIOLATION"
RESIDUAL_EXCEEDS_TOL = "FEA_CERT_EQUILIBRIUM_RESIDUAL_EXCEEDS_TOL"
CONDITIONING_UNAVAILABLE = "FEA_CERT_CONDITIONING_UNAVAILABLE"

# The COMPUTED role set: anchor validation, evidence loading, and the
# conditioning/anchor coupling all derive from this ONE mapping (the E3a
# meta-lesson — a binding must be a computed closure, never a hand-enumerated
# subset scattered across call sites). The witness is deliberately NOT an
# anchorable role: it is the producer's asserted solution; anchoring it would
# make the problem fixed-solution.
ROLE_PATHS = {
    "mesh": "inputs/mesh.json",
    "material": "inputs/material.json",
    "bcs": "inputs/bcs.json",
}
WITNESS_RELPATH = "payload/displacement_field.json"
WITNESS_SCHEMA = "fea-displacement-witness-v1"

# Closed-world witness-implied quantities (scope D2, revised): each is the
# identity of ONE registered primitive; the first is the original id's.
QUANTITIES = ("sigma_vm_max", "u_norm_2", "u_norm_inf")

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class _Refusal(Exception):
    """A determinate certificate refusal (the artifact is bad — REJECT)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Strict admission (spike cert_common, unchanged in behaviour): the RES-02
# size/depth gate runs on raw bytes first (admit_bytes), then a strict parse
# rejects NaN/Infinity constants and duplicate object keys — both are
# silent-ambiguity vectors the default json.loads tolerates.
# ---------------------------------------------------------------------------
def parse_json_bytes(data: bytes):
    """Strict parse (duplicate keys, non-finite tokens, oversized ints all
    ValueError). Delegates to `audit_bundle.strict_json`; was a local copy
    until 2026-09-05."""
    return strict_json_loads(data)


def frac(x) -> Fraction:
    """Exact rational from a parsed JSON number. Fraction(float) is exact for
    every binary64; bool is rejected explicitly (int subclass, silent coerce)."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise ValueError(f"not a JSON number: {x!r}")
    if isinstance(x, float) and not math.isfinite(x):
        raise ValueError(f"non-finite number: {x!r}")
    return Fraction(x)


# ---------------------------------------------------------------------------
# Certified conditioning bound (spike delta_bound, ported intact).
# Every step is an OVERestimate — delta too large is honest, delta too small
# would be a false certificate.
# ---------------------------------------------------------------------------
SQRT_SCALE = 1 << 64  # tightness of the rational sqrt overestimate


class ConditioningError(ValueError):
    """The conditioning bound cannot be computed (fail-closed, never PASS)."""


def ceil_sqrt(x: Fraction) -> Fraction:
    """Rational s with s*s >= x >= 0 and s <= sqrt(x) + 1/SQRT_SCALE (certified
    OVERestimate; the postcondition is asserted, never trusted)."""
    if x < 0:
        raise ConditioningError("ceil_sqrt of a negative rational")
    n = x.numerator * SQRT_SCALE * SQRT_SCALE
    d = x.denominator
    r = math.isqrt(n * d)  # sqrt(n/d) == sqrt(n*d)/d
    if r * r < n * d:
        r += 1
    s = Fraction(r, d * SQRT_SCALE)
    if s * s < x:  # postcondition; unreachable, kept as a fail-closed guard
        raise ConditioningError("ceil_sqrt postcondition violated")
    return s


def floor_sqrt(x: Fraction) -> Fraction:
    """Rational s with s*s <= x, s >= 0 — the UNDERestimate partner (spike R7:
    a difference of two ceil'd roots can UNDER-state a gap; bounding a gap needs
    outward rounding on both sides)."""
    if x < 0:
        raise ConditioningError("floor_sqrt of a negative rational")
    n = x.numerator * SQRT_SCALE * SQRT_SCALE
    d = x.denominator
    r = math.isqrt(n * d)
    s = Fraction(r, d * SQRT_SCALE)
    if s * s > x:  # postcondition; kept as a fail-closed guard
        raise ConditioningError("floor_sqrt postcondition violated")
    return s


def sqrt_gap_upper(m_a: Fraction, m_b: Fraction) -> Fraction:
    """Certified UPPER bound on |sqrt(m_a) − sqrt(m_b)| (outward rounding)."""
    hi = max(ceil_sqrt(m_a) - floor_sqrt(m_b), ceil_sqrt(m_b) - floor_sqrt(m_a))
    return hi if hi > 0 else Fraction(0)


def assert_symmetric(A) -> None:
    """K_ff symmetry is LOAD-BEARING (it makes ‖A‖₂ = ρ(A) ≤ ‖A‖∞ valid).
    Verified exactly, never assumed."""
    n = len(A)
    for i in range(n):
        for j in range(i + 1, n):
            if A[i][j] != A[j][i]:
                raise ConditioningError(f"K_ff not symmetric at ({i},{j})")


def norm_inf(A) -> Fraction:
    """Induced infinity norm: max absolute ROW sum."""
    return max(sum(abs(v) for v in row) for row in A)


def norm_1(A) -> Fraction:
    """Induced 1-norm: max absolute COLUMN sum."""
    return max(sum(abs(A[r][c]) for r in range(len(A))) for c in range(len(A[0])))


def spectral_norm_upper(A) -> Fraction:
    """Certified upper bound on ‖A‖₂ via ‖A‖₂ ≤ sqrt(‖A‖₁·‖A‖∞) (Hölder)."""
    return ceil_sqrt(norm_1(A) * norm_inf(A))


def rational_inverse(A):
    """Exact inverse by Gauss-Jordan with partial pivoting on Fractions.
    Singular → ConditioningError (nothing to bound; refuse, never guess)."""
    n = len(A)
    M = [
        list(A[i]) + [Fraction(1) if i == j else Fraction(0) for j in range(n)]
        for i in range(n)
    ]
    for col in range(n):
        piv = None
        for r in range(col, n):
            if M[r][col] != 0:
                piv = r
                break
        if piv is None:
            raise ConditioningError(f"K_ff singular at column {col}")
        M[col], M[piv] = M[piv], M[col]
        pv = M[col][col]
        M[col] = [v / pv for v in M[col]]
        for r in range(n):
            if r != col and M[r][col] != 0:
                fac = M[r][col]
                M[r] = [M[r][c] - fac * M[col][c] for c in range(2 * n)]
    return [row[n:] for row in M]


def kff_inverse_infnorm(K, fixed, n_dofs) -> Fraction:
    """‖K_ff⁻¹‖∞ over the FREE dofs of the ORIGINAL assembled K — the same
    matrix the residual check uses, so the two legs cannot disagree."""
    free = [d for d in range(n_dofs) if d not in fixed]
    if not free:
        raise ConditioningError("no free dofs: nothing to bound")
    Kff = [[K[r][c] for c in free] for r in free]
    assert_symmetric(Kff)
    return norm_inf(rational_inverse(Kff))


# The von-Mises invariant as a QUADRATIC FORM matrix: M(s) = sᵀQs. The delta
# chain needs the form (to bound λmax); the check path uses the scalar
# function; their AGREEMENT is a test cell in the battery.
VM_FORM_Q = [
    [Fraction(1), Fraction(-1, 2), Fraction(0)],
    [Fraction(-1, 2), Fraction(1), Fraction(0)],
    [Fraction(0), Fraction(0), Fraction(3)],
]


def vm_invariant(sx: Fraction, sy: Fraction, sxy: Fraction) -> Fraction:
    """Squared plane-stress von Mises: M = sx² − sx·sy + sy² + 3·sxy² (exact)."""
    return sx * sx - sx * sy + sy * sy + 3 * sxy * sxy


def certified_delta(*, K, fixed, n_dofs, elem_DB, tol: Fraction) -> dict:
    """THE BOUND: δ = √(‖Q‖∞) · maxₑ‖D·B_e‖₂ · ‖K_ff⁻¹‖∞ · tol.

    Guarantee (given: Dirichlet exact, free-dof ‖r‖₂ ≤ tol, K_ff nonsingular +
    symmetric): the TRUE solution's sigma_vm_max differs from the WITNESS's by
    at most δ. Composed with the ε claim band, an accepted claim is within
    ε+δ of the truth."""
    n_inv = kff_inverse_infnorm(K, fixed, n_dofs)
    best = Fraction(0)
    for DB in elem_DB:
        nb = spectral_norm_upper(DB)
        if nb > best:
            best = nb
    q = ceil_sqrt(norm_inf(VM_FORM_Q))
    delta = q * best * n_inv * tol
    return {
        "delta": delta,
        "kff_inverse_infnorm": n_inv,
        "stress_operator_norm": best,
        "vm_form_norm": q,
        "tol": tol,
    }


def witness_norm_inf(u: list) -> Fraction:
    """max_i |u_i| over ALL DOFs, prescribed included (exact rational) — the
    committed output_norms semantics. Module-level so the mutant battery can
    plant a sign-blindness bug (max(u_i) instead of max|u_i|) and measure
    which cell catches it."""
    return max(abs(x) for x in u)


def witness_norm2_sq(u: list) -> Fraction:
    """Σ u_i² over ALL DOFs, prescribed included (exact rational). The
    2-norm claim compares against sqrt of this via rational_sqrt_band."""
    return sum(x * x for x in u)


def certified_delta_u(*, K, fixed, n_dofs, tol: Fraction) -> Fraction:
    """THE NORMS BOUND: δ_u = ‖K_ff⁻¹‖∞ · tol (chain in the module
    docstring; every step an overestimate, K_ff symmetry verified inside
    kff_inverse_infnorm). Valid simultaneously for |max|u_wit,i| −
    max|u_true,i|| and |‖u_wit‖₂ − ‖u_true‖₂| over the ALL-DOF norms,
    because Δ is exactly zero on prescribed DOFs. Module-level so the mutant
    battery can plant a factor-drop bug and measure which cell catches it."""
    return kff_inverse_infnorm(K, fixed, n_dofs) * tol


# ---------------------------------------------------------------------------
# The certificate
# ---------------------------------------------------------------------------
def _param_frac(params: dict, name: str) -> Fraction:
    v = params.get(name)
    try:
        fv = frac(v)
    except ValueError as exc:
        raise _Refusal(PARAMS_MALFORMED, f"param {name}: {exc}") from exc
    if fv <= 0:
        raise _Refusal(PARAMS_MALFORMED, f"param {name} must be > 0")
    return fv


def _load_evidence(bundle_dir: Path) -> dict:
    """role → raw bytes for the three problem inputs + the witness, size/depth
    gated (RES-02) before any parse. Missing or oversized → refusal."""
    blobs: dict[str, bytes] = {}
    for role, rel in {**ROLE_PATHS, "witness": WITNESS_RELPATH}.items():
        path = bundle_dir / rel
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise _Refusal(
                EVIDENCE_MISSING, f"evidence role {role!r} ({rel}): {exc}"
            ) from exc
        verdict = admit_bytes(raw, check_name="fea_witness_cert_admission")
        if verdict is not None:
            raise _Refusal(
                EVIDENCE_MALFORMED,
                f"evidence role {role!r} ({rel}) failed admission: "
                f"{verdict.reasons[0].reason_code if verdict.reasons else 'inadmissible'}",
            )
        blobs[role] = raw
    return blobs


def _validate_anchor(params: dict) -> dict | None:
    """The auditor input anchor from the binding params, validated against the
    COMPUTED role set. Unknown role → refused, never silently ignored."""
    anchor = params.get("input_anchor")
    if anchor is None:
        return None
    if not isinstance(anchor, dict) or not anchor:
        raise _Refusal(PARAMS_MALFORMED, "input_anchor must be a non-empty object")
    for role, digest in anchor.items():
        if role not in ROLE_PATHS:
            raise _Refusal(
                ANCHOR_ROLE_UNDECLARED,
                f"input_anchor names role {role!r} outside the primitive's "
                f"computed role set {sorted(ROLE_PATHS)} (the witness is never "
                "anchorable)",
            )
        if not isinstance(digest, str) or not _SHA256_RE.match(digest):
            raise _Refusal(
                PARAMS_MALFORMED,
                f"input_anchor[{role!r}] must be a lowercase sha256 hex digest",
            )
    return anchor


def _check_declared_semantics(mesh: dict, mat: dict) -> None:
    """The R4 guards (spike blind-refutation R4, EXTENDED to the mesh): the
    anchor pins BYTES; it cannot make the checker read them as the documents
    declare. Refuse any committed input whose declared semantics this checker
    does not implement — otherwise an anchored PASS advertises physics the
    math never honored. Module-level so the mutant battery can plant a
    guard-skip bug and measure which cell catches it."""
    if mesh.get("element_type") != "CST":
        raise _Refusal(
            INPUT_MALFORMED,
            f"mesh.element_type {mesh.get('element_type')!r} != 'CST' (this "
            "certificate implements linear CST triangles only)",
        )
    if mesh.get("dim") != 2:
        raise _Refusal(
            INPUT_MALFORMED,
            f"mesh.dim {mesh.get('dim')!r} != 2 (this certificate implements "
            "2D plane problems only)",
        )
    if mat.get("stress_state") != "plane_stress":
        raise _Refusal(
            INPUT_MALFORMED,
            f"material.stress_state {mat.get('stress_state')!r} != "
            "'plane_stress' (this constitutive block implements plane stress "
            "only)",
        )
    if mat.get("model") != "linear_elastic_isotropic":
        raise _Refusal(
            INPUT_MALFORMED,
            f"material.model {mat.get('model')!r} != 'linear_elastic_isotropic'",
        )


def _enforce_anchor(anchor: dict | None, blobs: dict) -> None:
    """Enforce the auditor input anchor over the committed evidence bytes —
    a module-level function so the mutant battery can plant an
    enforcement-skip bug and measure which cell catches it."""
    if anchor is None:
        return
    for role in sorted(anchor):
        got = hashlib.sha256(blobs[role]).hexdigest()
        if got != anchor[role]:
            raise _Refusal(
                INPUT_ANCHOR_MISMATCH,
                f"anchored role {role!r}: committed {got} != anchored {anchor[role]}",
            )


def run_certificate(
    bundle_dir: Path, params: dict, quantity: str = QUANTITIES[0]
) -> tuple[dict, str]:
    """The full certificate. Returns (value, note) where value is the
    structured RecomputedValue payload; raises _Refusal on any determinate
    refusal. `quantity` is the calling primitive's IDENTITY (module
    docstring), defaulting to the original sigma_vm_max for back-compat.
    Exposed for the overlay builder and the battery."""
    tol = _param_frac(params, "equilibrium_tol")
    eps = _param_frac(params, "epsilon")
    if quantity not in QUANTITIES:
        raise _Refusal(
            PARAMS_MALFORMED,
            f"quantity {quantity!r} not in the closed-world set {list(QUANTITIES)}",
        )
    if "quantity" in params and params["quantity"] != quantity:
        # The quantity is PRIMITIVE IDENTITY; a spec param that contradicts
        # the bound identity is refused, never silently ignored.
        raise _Refusal(
            PARAMS_MALFORMED,
            f"params quantity {params['quantity']!r} contradicts the bound "
            f"primitive's quantity {quantity!r}",
        )
    anchor = _validate_anchor(params)
    conditioning = params.get("conditioning_bound", False)
    if not isinstance(conditioning, bool):
        raise _Refusal(PARAMS_MALFORMED, "conditioning_bound must be a boolean")
    if conditioning and (anchor is None or set(anchor) != set(ROLE_PATHS)):
        raise _Refusal(
            CONDITIONING_REQUIRES_FULL_ANCHOR,
            "conditioning_bound requires input_anchor over every input role "
            f"({sorted(ROLE_PATHS)}); a delta over a producer-chosen problem "
            "is a true bound answering the wrong question",
        )

    blobs = _load_evidence(bundle_dir)

    # --- Input anchor, enforced BEFORE any domain math (H1 kill shot). ---
    _enforce_anchor(anchor, blobs)

    # --- Strict parse. ---
    parsed = {}
    for role, raw in blobs.items():
        try:
            parsed[role] = parse_json_bytes(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise _Refusal(EVIDENCE_MALFORMED, f"{role}: {exc}") from exc

    # --- Mesh (declared semantics honored — R4 extended to the mesh). ---
    mesh = parsed["mesh"]
    if not isinstance(mesh, dict):
        raise _Refusal(INPUT_MALFORMED, "mesh is not an object")
    if mesh.get("schema") != "fea-mesh-v1":
        raise _Refusal(INPUT_MALFORMED, f"mesh.schema {mesh.get('schema')!r}")
    raw_nodes = mesh.get("nodes")
    raw_elems = mesh.get("elements")
    if not isinstance(raw_nodes, list) or len(raw_nodes) < 3:
        raise _Refusal(INPUT_MALFORMED, "mesh.nodes must be a list of >= 3 nodes")
    if not isinstance(raw_elems, list) or not raw_elems:
        # An empty element list would make M_max a max over nothing — a vacuous
        # certificate. Refused, never PASS.
        raise _Refusal(INPUT_MALFORMED, "mesh.elements must be a non-empty list")
    try:
        nodes = []
        for p in raw_nodes:
            if not isinstance(p, list) or len(p) != 2:
                raise ValueError(f"node {p!r} is not [x, y]")
            nodes.append((frac(p[0]), frac(p[1])))
    except ValueError as exc:
        raise _Refusal(INPUT_MALFORMED, f"mesh.nodes: {exc}") from exc
    n_nodes = len(nodes)
    elements = []
    for elem in raw_elems:
        if (
            not isinstance(elem, list)
            or len(elem) != 3
            or any(isinstance(i, bool) or not isinstance(i, int) for i in elem)
            or any(i < 0 or i >= n_nodes for i in elem)
            or len(set(elem)) != 3
        ):
            raise _Refusal(INPUT_MALFORMED, f"element {elem!r} invalid")
        elements.append(tuple(elem))

    # --- Material (declared semantics honored — spike R4). ---
    mat = parsed["material"]
    if not isinstance(mat, dict):
        raise _Refusal(INPUT_MALFORMED, "material is not an object")
    if mat.get("schema") != "fea-material-v1":
        raise _Refusal(INPUT_MALFORMED, f"material.schema {mat.get('schema')!r}")
    _check_declared_semantics(mesh, mat)
    try:
        E = frac(mat.get("E"))
        nu = frac(mat.get("nu"))
        t = frac(mat.get("thickness"))
    except ValueError as exc:
        raise _Refusal(INPUT_MALFORMED, f"material: {exc}") from exc
    # Physical admissibility (spike H5): outside these the stiffness is
    # self-consistent but unphysical — never a certificate over nonsense.
    if E <= 0:
        raise _Refusal(INPUT_MALFORMED, "material: E must be > 0")
    if t <= 0:
        raise _Refusal(INPUT_MALFORMED, "material: thickness must be > 0")
    if not (Fraction(-1) < nu < Fraction(1, 2)):
        raise _Refusal(INPUT_MALFORMED, "material: nu must satisfy -1 < nu < 1/2")

    # --- BCs. ---
    bcs = parsed["bcs"]
    if not isinstance(bcs, dict):
        raise _Refusal(INPUT_MALFORMED, "bcs is not an object")
    if bcs.get("schema") != "fea-bcs-v1":
        raise _Refusal(INPUT_MALFORMED, f"bcs.schema {bcs.get('schema')!r}")
    n_dofs = 2 * n_nodes

    def _dof_entries(kind):
        out = []
        rows = bcs.get(kind)
        if not isinstance(rows, list):
            raise ValueError(f"bcs.{kind} must be a list")
        for bc in rows:
            if not isinstance(bc, dict):
                raise ValueError(f"bcs.{kind} entry {bc!r} not an object")
            node = bc.get("node")
            if isinstance(node, bool) or not isinstance(node, int):
                raise ValueError(f"bcs.{kind} node {node!r} not an int")
            if node < 0 or node >= n_nodes:
                raise ValueError(f"bcs.{kind} node {node} out of range")
            dof_axis = bc.get("dof")
            if dof_axis not in ("x", "y"):
                raise ValueError(f"bcs.{kind} dof {dof_axis!r} not in {{x,y}}")
            out.append(
                (node * 2 + (0 if dof_axis == "x" else 1), frac(bc.get("value")))
            )
        return out

    try:
        dirichlet = _dof_entries("dirichlet")
        neumann = _dof_entries("neumann")
    except ValueError as exc:
        raise _Refusal(INPUT_MALFORMED, f"bcs: {exc}") from exc
    fixed: dict = {}
    for dof, val in dirichlet:
        if dof in fixed and fixed[dof] != val:
            raise _Refusal(
                INPUT_MALFORMED, f"conflicting dirichlet values on dof {dof}"
            )
        fixed[dof] = val
    f = [Fraction(0)] * n_dofs
    for dof, val in neumann:  # loads on one DOF accumulate (producer += semantics)
        f[dof] += val

    # --- Witness. ---
    wit = parsed["witness"]
    if not isinstance(wit, dict) or wit.get("schema") != WITNESS_SCHEMA:
        raise _Refusal(WITNESS_MALFORMED, "witness schema missing/unknown")
    raw_u = wit.get("u")
    if not isinstance(raw_u, list) or len(raw_u) != n_dofs:
        raise _Refusal(
            WITNESS_MALFORMED,
            f"witness u must be a list of length {n_dofs} (got "
            f"{len(raw_u) if isinstance(raw_u, list) else type(raw_u).__name__})",
        )
    try:
        u = [frac(x) for x in raw_u]
    except ValueError as exc:
        raise _Refusal(WITNESS_MALFORMED, f"witness u: {exc}") from exc

    # --- Exact assembly (isotropic plane-stress CST, the ONLY semantics this
    #     primitive implements — anything else was refused above). ---
    denom = 1 - nu * nu
    if denom == 0:  # unreachable given the nu guard; kept fail-closed
        raise _Refusal(INPUT_MALFORMED, "material: 1 - nu^2 == 0")
    co = E / denom
    D = [
        [co, co * nu, Fraction(0)],
        [co * nu, co, Fraction(0)],
        [Fraction(0), Fraction(0), co * (1 - nu) / 2],
    ]
    K = [[Fraction(0)] * n_dofs for _ in range(n_dofs)]
    elem_data = []
    for i, j, k in elements:
        (x1, y1), (x2, y2), (x3, y3) = nodes[i], nodes[j], nodes[k]
        area2 = (x2 - x1) * (y3 - y1) - (x3 - x1) * (y2 - y1)
        if area2 == 0:
            raise _Refusal(DEGENERATE_ELEMENT, f"element ({i},{j},{k}) has zero area")
        A = abs(area2) / 2
        b1, c1 = y2 - y3, x3 - x2
        b2, c2 = y3 - y1, x1 - x3
        b3, c3 = y1 - y2, x2 - x1
        inv2A = 1 / (2 * A)
        B = [
            [b1 * inv2A, Fraction(0), b2 * inv2A, Fraction(0), b3 * inv2A, Fraction(0)],
            [Fraction(0), c1 * inv2A, Fraction(0), c2 * inv2A, Fraction(0), c3 * inv2A],
            [c1 * inv2A, b1 * inv2A, c2 * inv2A, b2 * inv2A, c3 * inv2A, b3 * inv2A],
        ]
        DB = [
            [sum(D[r][m] * B[m][col] for m in range(3)) for col in range(6)]
            for r in range(3)
        ]
        Ke = [
            [A * t * sum(B[m][r] * DB[m][col] for m in range(3)) for col in range(6)]
            for r in range(6)
        ]
        dof_map = [2 * i, 2 * i + 1, 2 * j, 2 * j + 1, 2 * k, 2 * k + 1]
        for a in range(6):
            for b in range(6):
                K[dof_map[a]][dof_map[b]] += Ke[a][b]
        elem_data.append((dof_map, B, DB))

    # --- Certificate: Dirichlet exact. ---
    for dof, val in sorted(fixed.items()):
        if u[dof] != val:
            raise _Refusal(
                DIRICHLET_VIOLATION,
                f"u[{dof}] != prescribed value (exact comparison)",
            )

    # --- Certificate: equilibrium residual on FREE DOFs of the ORIGINAL K
    #     (full rows, prescribed columns included — row replacement never
    #     trusted). Decided exactly: sum(r_i²) <= tol². ---
    r2 = Fraction(0)
    for dof in range(n_dofs):
        if dof in fixed:
            continue
        r = sum(K[dof][jdx] * u[jdx] for jdx in range(n_dofs)) - f[dof]
        r2 += r * r
    if r2 > tol * tol:
        raise _Refusal(
            RESIDUAL_EXCEEDS_TOL,
            f"free-dof residual^2 exceeds tol^2 (ratio ~{float(r2 / (tol * tol)):.3e})",
        )

    # --- Witness-implied quantity, exactly (summation domain: ALL DOFs). ---
    mode = "ANCHORED" if anchor else "UNANCHORED"
    prefix = (
        f"witness certificate ({mode}, {n_dofs - len(fixed)} free dofs): "
        "Dirichlet exact, free-dof equilibrium within tol; "
    )
    if quantity == "sigma_vm_max":
        M_max = None
        for dof_map, B, _DB in elem_data:
            ue = [u[d] for d in dof_map]
            strain = [sum(B[r][col] * ue[col] for col in range(6)) for r in range(3)]
            sx, sy, sxy = (
                sum(D[r][col] * strain[col] for col in range(3)) for r in range(3)
            )
            M = vm_invariant(sx, sy, sxy)
            if M_max is None or M > M_max:
                M_max = M
        value = {
            "kind": "sqrt_of_rational",
            "num": M_max.numerator,
            "den": M_max.denominator,
        }
        note = prefix + f"witness-implied sigma_vm_max ~ {math.sqrt(float(M_max)):.9e}"
    elif quantity == "u_norm_2":
        S = witness_norm2_sq(u)
        value = {
            "kind": "sqrt_of_rational",
            "num": S.numerator,
            "den": S.denominator,
        }
        note = prefix + (
            f"witness-implied u_norm_2 ~ {math.sqrt(float(S)):.9e} (all dofs)"
        )
    else:  # u_norm_inf (closed-world; validated above)
        R = witness_norm_inf(u)
        value = {"kind": "rational", "num": R.numerator, "den": R.denominator}
        note = prefix + f"witness-implied u_norm_inf ~ {float(R):.9e} (all dofs)"

    # --- Certified conditioning bound (requires the full anchor, above). ---
    if conditioning:
        try:
            if quantity == "sigma_vm_max":
                delta = certified_delta(
                    K=K,
                    fixed=fixed,
                    n_dofs=n_dofs,
                    elem_DB=[DB for _dm, _B, DB in elem_data],
                    tol=tol,
                )["delta"]
            else:
                delta = certified_delta_u(K=K, fixed=fixed, n_dofs=n_dofs, tol=tol)
        except ConditioningError as exc:
            # No bound computable => no certificate. Absence is never a PASS.
            raise _Refusal(CONDITIONING_UNAVAILABLE, str(exc)) from exc
        interval = eps + delta
        value["interval_num"] = interval.numerator
        value["interval_den"] = interval.denominator
        note += f"; certified interval eps+delta ~ {float(interval):.9e}"
    return value, note


def certified_interval_ceil_float(
    bundle_dir: Path, params: dict, quantity: str = QUANTITIES[0]
) -> float:
    """The smallest binary64 >= the exact certified interval ε+δ — the number
    an honest producer commits as `certified_interval`. (The comparator accepts
    any committed interval >= the exact one; this is the tightest honest
    choice.) Runs the full certificate, so it inherits every refusal."""
    value, _note = run_certificate(bundle_dir, params, quantity)
    if "interval_num" not in value:
        raise _Refusal(
            PARAMS_MALFORMED,
            "certified_interval_ceil_float requires conditioning_bound=true",
        )
    exact = Fraction(value["interval_num"], value["interval_den"])
    fl = float(exact)
    if Fraction(fl) < exact:
        fl = math.nextafter(fl, math.inf)
    return fl


class FeaWitnessCertificate:
    """The sigma_vm_max certificate — the original primitive, id unchanged.
    The quantity is PRIMITIVE IDENTITY (module docstring): each registered id
    computes exactly one witness-implied quantity, so every id is bound by
    exactly one spec type and §4a.3 monotone-strictness holds by
    construction."""

    primitive_id: str = "fea_witness_certificate"
    primitive_shape: str = "witness + certificate"
    primitive_version: str = "1"
    primitive_tier: str = "C"
    primitive_contract: str = (
        "Given the producer's committed displacement-field witness "
        "(payload/displacement_field.json), check the CERTIFICATE — Dirichlet "
        "values hold exactly and the equilibrium residual on the free DOFs of "
        "the ORIGINAL assembled K is inside the auditor-anchored tolerance — "
        "and return the witness-implied sigma_vm_max, compared by the bound "
        "rational_sqrt_band comparator. Assembly, residual and stress recovery "
        "are exact rational arithmetic throughout."
    )
    primitive_scope_limits: tuple[str, ...] = (
        "It NEVER runs a solver. Solver-independent by construction: a "
        "Gaussian-elimination solve and a CG solve that both satisfy "
        "equilibrium pass the SAME certificate.",
        "Declared semantics are honoured, not assumed: material must declare "
        "model=linear_elastic_isotropic and stress_state=plane_stress, and mesh "
        "must declare element_type=CST and dim=2, or the certificate refuses.",
        "Without the comparator param input_anchor the certificate degrades to "
        "a witness-implied predicate over a PRODUCER-CHOSEN problem, and says "
        "so in its detail.",
        "This source file holds three registered primitives, so a #sha256 pin "
        "on any one of them also pins its two siblings.",
    )
    quantity: str = QUANTITIES[0]

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        params = pack_section.get("params") if isinstance(pack_section, dict) else None
        try:
            value, note = run_certificate(
                inputs.bundle_dir, params or {}, self.quantity
            )
        except _Refusal as r:
            return RecomputedValue(
                value={"kind": "refused", "reason_code": r.code, "detail": r.detail},
                detail=f"certificate refused: {r.code}",
            )
        return RecomputedValue(value=value, detail=note)


class FeaWitnessCertificateUNorm2(FeaWitnessCertificate):
    """‖u‖₂ over ALL DOFs as sqrt_of_rational(Σu_i²) — bound by
    rational_sqrt_band; same certificate gates, δ_u conditioning."""

    primitive_id: str = "fea_witness_certificate_u_norm_2"
    primitive_shape: str = "witness + certificate"
    primitive_version: str = "1"
    primitive_tier: str = "C"
    primitive_contract: str = (
        "The same certificate gates as fea_witness_certificate, returning "
        "||u||_2 over ALL DOFs as sqrt_of_rational(sum of u_i^2), bound by "
        "rational_sqrt_band, under delta_u conditioning."
    )
    primitive_scope_limits: tuple[str, ...] = (
        "It NEVER runs a solver. Solver-independent by construction: a "
        "Gaussian-elimination solve and a CG solve that both satisfy "
        "equilibrium pass the SAME certificate.",
        "Declared semantics are honoured, not assumed: material must declare "
        "model=linear_elastic_isotropic and stress_state=plane_stress, and mesh "
        "must declare element_type=CST and dim=2, or the certificate refuses.",
        "Without the comparator param input_anchor the certificate degrades to "
        "a witness-implied predicate over a PRODUCER-CHOSEN problem, and says "
        "so in its detail.",
        "This source file holds three registered primitives, so a #sha256 pin "
        "on any one of them also pins its two siblings.",
    )
    quantity: str = "u_norm_2"


class FeaWitnessCertificateUNormInf(FeaWitnessCertificate):
    """max|u_i| over ALL DOFs as a plain rational — the rational_band
    consumer; same certificate gates, δ_u conditioning."""

    primitive_id: str = "fea_witness_certificate_u_norm_inf"
    primitive_shape: str = "witness + certificate"
    primitive_version: str = "1"
    primitive_tier: str = "C"
    primitive_contract: str = (
        "The same certificate gates as fea_witness_certificate, returning "
        "max|u_i| over ALL DOFs as a plain rational, bound by rational_band, "
        "under delta_u conditioning."
    )
    primitive_scope_limits: tuple[str, ...] = (
        "It NEVER runs a solver. Solver-independent by construction: a "
        "Gaussian-elimination solve and a CG solve that both satisfy "
        "equilibrium pass the SAME certificate.",
        "Declared semantics are honoured, not assumed: material must declare "
        "model=linear_elastic_isotropic and stress_state=plane_stress, and mesh "
        "must declare element_type=CST and dim=2, or the certificate refuses.",
        "Without the comparator param input_anchor the certificate degrades to "
        "a witness-implied predicate over a PRODUCER-CHOSEN problem, and says "
        "so in its detail.",
        "This source file holds three registered primitives, so a #sha256 pin "
        "on any one of them also pins its two siblings.",
    )
    quantity: str = "u_norm_inf"


register_primitive(FeaWitnessCertificate())
register_primitive(FeaWitnessCertificateUNorm2())
register_primitive(FeaWitnessCertificateUNormInf())
