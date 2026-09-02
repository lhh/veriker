"""audit_bundle/rederivation/comparators.py — the comparator-kind registry.

This is a registry of comparator KINDS, not one scalar comparator pretending to
be universal. Each kind is domain-agnostic — `set`-equality does not know it
compares redactions vs citations; the per-kind `params` (epsilon / profile /
schema) are DATA read from the SHA-pinned, auditor-anchored spec, never code.

Hardening:
  - closed-world params: `text_normalized` profiles and `structured`
    schemas resolve to verifier-IMPLEMENTED allowlisted identifiers
    (_NORMALIZATION_PROFILES / _STRUCTURED_SCHEMAS) — NOT arbitrary per-bundle
    JSON ("code in disguise"). An unknown profile/schema id fails closed.
  - custom comparators: there is NO open `custom:<id>` comparator path.
    A genuinely irreducible domain comparison is expressed as a
    ReDerivationPrimitive that returns a boolean-shaped value compared with
    `exact` — i.e. it lives in the SAME verifier-side, fail-closed-on-unknown
    primitive registry namespace, eliminating the separate governance path.

Auditor annotation — `numeric_model` (optional):
  A comparator's `params` MAY carry an optional `numeric_model` tag from a
  closed-world allowlist (_NUMERIC_MODELS). It is DOCUMENTARY — it does NOT
  change a comparison's pass/fail — but it lets an auditor reading the
  SHA-pinned spec distinguish an INTENTIONALLY tolerant float comparison
  (e.g. `binary64_libm_tolerated`: a tolerance deliberately sized for
  cross-platform libm non-determinism in a transcendental like math.log) from
  an accidental coercion / lazy fudge. It is validated like every other param:
  present-but-unknown fails closed (UnknownComparatorParam); absent is fine
  (back-compatible — existing specs are unaffected). Surfaced in the comparator
  detail so the verdict (and any signed verdict transcript) records the declared
  model. Because it lives in the auditor-anchored spec, a producer cannot author
  or alter it. Endpoint posture (not enforced here): once tolerance-bearing
  specs are migrated, a `scalar_epsilon` with epsilon>0 and NO `numeric_model`
  could be treated as an undocumented-coercion fail-closed signal.

§C9 discipline: error-detail formatters never sorted() adversarial dict keys
(raises TypeError on mixed types); they use insertion-order repr().

Stdlib-only (core verify() path).
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from fractions import Fraction
from typing import Callable

# A comparator: (recomputed, claimed, params) -> (ok, detail).
# Comparators catch their own expected errors and return (False, <detail>) so a
# bad operand is a REJECT, not a crash. A comparator should aim never to raise,
# but cannot defend against every interpreter-level error (e.g. RecursionError
# on a deeply-nested adversarial claimed value, which is not reliably catchable
# mid-recursion). The ENFORCING backstop is the dispatch boundary, which wraps
# every comparator call and records any escaped exception as a fail-closed
# COMPARATOR_ERROR (see dispatch.run_spec_pinned_dispatch).
Comparator = Callable[[object, object, dict], "tuple[bool, str]"]


class UnknownComparatorKind(Exception):
    """Spec names a comparator kind not in the verifier registry (fail-closed)."""


class UnknownComparatorParam(Exception):
    """Spec names a text-normalization profile or structured schema id the
    verifier does not implement (§4a.6 closed-world; fail-closed)."""


# ---------------------------------------------------------------------------
# §4a.6 closed-world allowlists — verifier-implemented identifiers only
# ---------------------------------------------------------------------------


def _normalize_spectra_v1(text: str) -> str:
    """5-rule normalization mirroring the EXTRACTIVE stamper invariant
    (examples/spectra_minimal/span_re_derivation.py::_normalize). Verifier-side
    authority for the `spectra_v1` text-normalization profile."""
    text = unicodedata.normalize("NFC", text)  # Rule 1: NFC
    text = text.casefold()  # Rule 2: casefold
    text = "".join(  # Rule 3: drop punctuation
        ch for ch in text if not unicodedata.category(ch).startswith("P")
    )
    text = re.sub(r"\s+", " ", text)  # Rule 4: collapse whitespace
    return text.strip()  # Rule 5: strip edges


# profile id -> normalization function (verifier-implemented, allowlisted).
_NORMALIZATION_PROFILES: dict[str, Callable[[str], str]] = {
    "spectra_v1": _normalize_spectra_v1,
}


# structured-schema id -> ordered tuple of required field names. Comparison is
# field-wise equality over exactly these fields (verifier-implemented,
# allowlisted; arbitrary per-bundle schemas are rejected, §4a.6).
#
# climate_attribution_v1 (FIX-E, claim-set coverage sweep): originally
# ("vendor_id", "tier", "attributed_kg_co2e") only — attributed_kg_co2e is a
# single product of activity_amount * emission_factor_kg_co2e_per_unit, so
# matching only the product let a claimed record swap in a fictitious
# factor_source label or a different (activity_amount, emission_factor)
# factorization of the SAME product undetected. Extended to bind every
# committed per-vendor field the payload echoes (activity_amount,
# activity_unit, emission_factor_kg_co2e_per_unit, factor_source) so a
# structured-comparator PASS means the claimed record's disclosure-relevant
# fields — not just the arithmetic total — match the committed
# inputs/supplier_chain.json.
_STRUCTURED_SCHEMAS: dict[str, tuple[str, ...]] = {
    "climate_attribution_v1": (
        "vendor_id",
        "tier",
        "activity_amount",
        "activity_unit",
        "emission_factor_kg_co2e_per_unit",
        "factor_source",
        "attributed_kg_co2e",
    ),
}


# numeric_model — optional, documentary auditor annotation on a comparator's
# params (any kind, primarily scalar_epsilon). Closed-world allowlist: a
# present-but-unknown value fails closed at validate_comparator_params; absent is
# fine. Does NOT change pass/fail — it records, in the auditor-anchored spec, the
# intended numeric model so an auditor can tell a reasoned float tolerance from an
# accidental coercion.
#   binary64_exact          — IEEE-754 double; the comparison is expected
#                             bit-exact (use with exact, or scalar_epsilon at a
#                             representation-only tolerance). No transcendental.
#   binary64_libm_tolerated — IEEE-754 double whose recompute calls a libm
#                             transcendental (e.g. math.log/exp/pow) that is not
#                             bit-identical across platforms; the scalar_epsilon
#                             tolerance is a deliberate margin for that wobble.
_NUMERIC_MODELS: frozenset[str] = frozenset(
    {"binary64_exact", "binary64_libm_tolerated"}
)


# ---------------------------------------------------------------------------
# The 5 generic comparator kinds (§3.4)
# ---------------------------------------------------------------------------


def _cmp_scalar_epsilon(a: object, b: object, params: dict) -> tuple[bool, str]:
    try:
        epsilon = float(params["epsilon"])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        return (False, f"scalar_epsilon: bad/missing epsilon param: {exc}")
    # Defence-in-depth: dispatch validates epsilon at parse time, but re-check
    # here so this comparator is sound in isolation — a non-finite epsilon (inf)
    # would pass every delta; a negative one would reject every delta.
    if not math.isfinite(epsilon) or epsilon < 0:
        return (
            False,
            f"scalar_epsilon: epsilon must be finite and >= 0, got {epsilon!r}",
        )
    # Strict type admission: both operands must be JSON numbers (int or float,
    # never bool/str/bytes/Decimal). float() coercion would accept True → 1.0,
    # "1" → 1.0, b"1" → crash-but-caught, Decimal → 1.0, collapsing type-distinct
    # claimed values into a passing comparison. Mirrors _cmp_text_normalized which
    # enforces isinstance(a, str) / isinstance(b, str) before normalising.
    for side, operand in (("re", a), ("claimed", b)):
        if isinstance(operand, bool) or not isinstance(operand, (int, float)):
            return (
                False,
                f"scalar_epsilon: non-numeric operand ({side}={operand!r}, "
                f"type={type(operand).__name__}); int or float required",
            )
    try:
        fa, fb = float(a), float(b)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        return (False, f"scalar_epsilon: non-numeric operand: {exc}")
    if not (math.isfinite(fa) and math.isfinite(fb)):
        return (False, f"scalar_epsilon: non-finite operand re={fa!r} claimed={fb!r}")
    # Optional documentary numeric-model tag (validated at anchor-load); surfaced
    # so the verdict records the declared model. Does not affect pass/fail.
    nm = params.get("numeric_model")
    nm_suffix = f" [numeric_model={nm}]" if isinstance(nm, str) and nm else ""
    delta = abs(fa - fb)
    if delta <= epsilon:
        return (
            True,
            f"scalar_epsilon: delta={delta:.3e} <= epsilon={epsilon:.3e}{nm_suffix}",
        )
    return (
        False,
        f"scalar_epsilon: delta={delta:.3e} > epsilon={epsilon:.3e} "
        f"(re={fa:.15e} claimed={fb:.15e}){nm_suffix}",
    )


def _cmp_exact(a: object, b: object, _params: dict) -> tuple[bool, str]:
    if a == b:
        return (True, "exact: equal")
    return (False, f"exact: re={a!r} != claimed={b!r}")


def _cmp_text_normalized(a: object, b: object, params: dict) -> tuple[bool, str]:
    profile = params.get("profile")
    fn = _NORMALIZATION_PROFILES.get(profile) if isinstance(profile, str) else None
    if fn is None:
        # §4a.6: unknown / arbitrary profile is fail-closed, not interpreted.
        return (
            False,
            f"text_normalized: unknown normalization profile {profile!r} "
            f"(allowlisted: {tuple(_NORMALIZATION_PROFILES)!r})",
        )
    if not isinstance(a, str) or not isinstance(b, str):
        return (
            False,
            f"text_normalized: operands must be strings, got "
            f"re={type(a).__name__} claimed={type(b).__name__}",
        )
    na, nb = fn(a), fn(b)
    if na == nb:
        return (True, f"text_normalized[{profile}]: equal after normalization")
    return (
        False,
        f"text_normalized[{profile}]: re={na!r} != claimed={nb!r}",
    )


def _cmp_set(a: object, b: object, _params: dict) -> tuple[bool, str]:
    try:
        # Order-independent BUT multiplicity-sensitive (multiset / bag equality):
        # ['A','A','B'] != ['A','B','B']. A pure-set comparison would be
        # multiset-BLIND and let a producer claim a different multiset than was
        # recomputed for any output whose values can carry meaningful duplicates.
        # Multiset equality coincides with set equality for duplicate-free
        # operands (every shipped set-bound primitive), so this is strictly
        # safer with no behavior change for them.
        # Elements may be unhashable (list/dict) — _freeze canonicalizes each to
        # a hashable, order-independent key (dict KEY-order is not significant;
        # sequence order IS). No sorted() on adversarial keys (§C9).
        ca = Counter(_freeze(x) for x in a)  # type: ignore[union-attr]
        cb = Counter(_freeze(x) for x in b)  # type: ignore[union-attr]
    except TypeError as exc:
        return (False, f"set: operands not iterable: {exc}")
    if ca == cb:
        return (True, f"set: equal ({sum(ca.values())} element(s), multiset)")
    only_re = ca - cb  # Counter subtraction keeps positive over-counts only.
    only_claimed = cb - ca
    return (
        False,
        f"set: mismatch — only_in_recomputed={_render(only_re)} "
        f"only_in_claimed={_render(only_claimed)}",
    )


def _cmp_structured(a: object, b: object, params: dict) -> tuple[bool, str]:
    schema_id = params.get("schema")
    fields = _STRUCTURED_SCHEMAS.get(schema_id) if isinstance(schema_id, str) else None
    if fields is None:
        # §4a.6: arbitrary per-bundle field-schema is fail-closed.
        return (
            False,
            f"structured: unknown schema id {schema_id!r} "
            f"(allowlisted: {tuple(_STRUCTURED_SCHEMAS)!r})",
        )
    # Operands are lists-of-records; compare field-wise over the allowlisted
    # fields, in list order (the recompute defines order).
    if not isinstance(a, list) or not isinstance(b, list):
        return (
            False,
            f"structured[{schema_id}]: operands must be lists, got "
            f"re={type(a).__name__} claimed={type(b).__name__}",
        )
    if len(a) != len(b):
        return (
            False,
            f"structured[{schema_id}]: record count re={len(a)} != claimed={len(b)}",
        )
    for idx, (ra, rb) in enumerate(zip(a, b)):
        if not isinstance(ra, dict) or not isinstance(rb, dict):
            return (False, f"structured[{schema_id}]: record[{idx}] not an object")
        for f in fields:
            if ra.get(f) != rb.get(f):
                return (
                    False,
                    f"structured[{schema_id}]: record[{idx}].{f}: "
                    f"re={ra.get(f)!r} != claimed={rb.get(f)!r}",
                )
    return (True, f"structured[{schema_id}]: {len(a)} record(s) match")


_ANCHOR_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def _render_frac(x: Fraction) -> str:
    """Detail-string rendering of an exact rational that never raises: a
    committed huge-but-finite integer (e.g. 10**400) is admitted exactly by
    Fraction, but float(x) on it raises OverflowError — a would-be verdict
    would become a COMPARATOR_ERROR (safe direction, but a robustness bug:
    blind-refutation finding 1). Detail strings are evidence, never ABI."""
    try:
        return f"{float(x):.9e}"
    except OverflowError:
        return f"~10^{len(str(abs(x.numerator))) - len(str(x.denominator))}"


def _sqrt_band_contains(M: Fraction, c: Fraction, eps: Fraction) -> bool:
    """|sqrt(M) − c| ≤ eps decided EXACTLY on squares (sqrt is monotone).
    Since sqrt(M) ≥ 0: an all-negative band (c+eps < 0) is empty; the upper
    bound is M ≤ (c+eps)²; the lower bound is vacuous when c−eps ≤ 0, else
    M ≥ (c−eps)². Module-level so the mutant battery can plant a
    band-widening bug and measure which cell catches it."""
    hi = c + eps
    if hi < 0:
        return False  # a negative claim can never match a nonnegative stress
    if M > hi * hi:
        return False
    lo = c - eps
    if lo > 0 and M < lo * lo:
        return False
    return True


def _admit_json_number(
    kind: str, label: str, v: object
) -> tuple[Fraction, None] | tuple[None, str]:
    """Strict numeric admission shared by the band-comparator operand checks:
    int or float only (bool is an int subclass and is rejected; str/None/dict
    would otherwise coerce or crash), finite. Returns (Fraction, None) on
    success — Fraction(float) is exact for every binary64 — else (None, detail)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return (
            None,
            f"{kind}: {label} must be a JSON number, got {type(v).__name__} ({v!r})",
        )
    if isinstance(v, float) and not math.isfinite(v):
        return (None, f"{kind}: {label} is non-finite ({v!r})")
    return (Fraction(v), None)


def _cmp_rational_sqrt_band(a: object, b: object, params: dict) -> tuple[bool, str]:
    """Certificate-shaped band comparator: the recomputed side is an EXACT
    rational M (as {"kind": "sqrt_of_rational", "num", "den"}) produced by a
    certificate primitive, the claimed side is a number c, and acceptance is
    |sqrt(M) − c| ≤ epsilon decided EXACTLY on squares (sqrt is monotone; the
    c−ε ≤ 0 and c+ε < 0 edges are handled explicitly). Zero float ambiguity on
    the accept path — the only approximate object is the declared epsilon,
    which is auditor-anchored data, not implementation slack.

    A recomputed value of {"kind": "refused", "reason_code", "detail"} is a
    DETERMINATE certificate refusal: it maps to (False, <reason>) so the
    artifact REJECTs with a machine-readable reason code rather than crashing
    into a RECOMPUTE_ERROR.

    When the binding declares conditioning_bound, the primitive returns the
    exact certified interval eps+delta as {"interval_num", "interval_den"} and
    the claimed value must be {"value", "certified_interval"}: the claim band
    is still epsilon against "value" (delta REPORTS, it never RELAXES), and
    the COMMITTED certified_interval must be >= the re-derived eps+delta — an
    understated interval is a false certificate (RED); an overstated one is
    honest-but-loose and stays visible to every consumer because it is
    integrity-pinned in the bundle. The claimed key is the GENERIC "value"
    (not a domain field name): the kind serves any sqrt-of-rational claim
    (sigma_vm_max and u_norm_2 both bind it), so its detail strings and
    claimed shape are quantity-neutral."""
    epsilon = params.get("epsilon")
    try:
        eps_bad = (
            isinstance(epsilon, bool)
            or not isinstance(epsilon, (int, float))
            or not math.isfinite(float(epsilon))
            or float(epsilon) <= 0
        )
    except OverflowError:  # huge-int epsilon: not float-representable — refuse
        eps_bad = True
    if eps_bad:
        return (
            False,
            f"rational_sqrt_band: epsilon must be a finite number > 0, got {epsilon!r}",
        )
    eps = Fraction(epsilon)

    if not isinstance(a, dict):
        return (
            False,
            f"rational_sqrt_band: recomputed value must be an object, got "
            f"{type(a).__name__}",
        )
    kind = a.get("kind")
    if kind == "refused":
        return (
            False,
            "rational_sqrt_band: certificate refused — "
            f"{a.get('reason_code')!r}: {a.get('detail')!r}",
        )
    if kind != "sqrt_of_rational":
        return (False, f"rational_sqrt_band: unknown recomputed kind {kind!r}")
    num = a.get("num")
    den = a.get("den")
    for label, v in (("num", num), ("den", den)):
        if isinstance(v, bool) or not isinstance(v, int):
            return (
                False,
                f"rational_sqrt_band: recomputed {label} must be an int, got "
                f"{type(v).__name__}",
            )
    if den <= 0 or num < 0:
        return (
            False,
            f"rational_sqrt_band: recomputed M must satisfy num >= 0, den > 0 "
            f"(got {num}/{den}); sqrt requires a nonnegative operand",
        )
    M = Fraction(num, den)

    expects_interval = params.get("conditioning_bound", False) is True
    has_interval = ("interval_num" in a) or ("interval_den" in a)
    if expects_interval != has_interval:
        return (
            False,
            "rational_sqrt_band: certified-interval presence inconsistent with "
            f"the declared conditioning_bound (declared={expects_interval}, "
            f"recomputed carries interval={has_interval}) — fail-closed",
        )

    # --- Claimed-operand admission (strict; the type-confusion surface). ---
    if expects_interval:
        if not isinstance(b, dict) or set(b) != {"value", "certified_interval"}:
            return (
                False,
                "rational_sqrt_band: with conditioning_bound the claimed value "
                "must be exactly {value, certified_interval}, got "
                f"{type(b).__name__}"
                + (f" with keys {sorted(map(repr, b))}" if isinstance(b, dict) else ""),
            )
        c_raw: object = b["value"]
        i_raw: object = b["certified_interval"]
    else:
        c_raw, i_raw = b, None
    c, err = _admit_json_number("rational_sqrt_band", "claimed value", c_raw)
    if err is not None:
        return (False, err)

    # --- The band, exactly on squares. ---
    in_band = _sqrt_band_contains(M, c, eps)
    try:
        sqrt_note = f"{math.sqrt(float(M)):.9e}"
    except (OverflowError, ValueError):
        sqrt_note = "<unrepresentable>"
    if not in_band:
        return (
            False,
            "rational_sqrt_band: claimed value not within epsilon of sqrt(M) "
            f"(claimed={_render_frac(c)}, sqrt(M)~{sqrt_note}, "
            f"epsilon={_render_frac(eps)})",
        )

    # --- The committed certified interval (delta REPORTS, never relaxes). ---
    if expects_interval:
        inum = a.get("interval_num")
        iden = a.get("interval_den")
        for label, v in (("interval_num", inum), ("interval_den", iden)):
            if isinstance(v, bool) or not isinstance(v, int):
                return (
                    False,
                    f"rational_sqrt_band: recomputed {label} must be an int, got "
                    f"{type(v).__name__}",
                )
        if iden <= 0 or inum <= 0:
            return (
                False,
                "rational_sqrt_band: re-derived certified interval must be > 0 "
                f"(got {inum}/{iden})",
            )
        interval_exact = Fraction(inum, iden)
        i_frac, err = _admit_json_number(
            "rational_sqrt_band", "claimed certified_interval", i_raw
        )
        if err is not None:
            return (False, err)
        if i_frac <= 0:
            return (
                False,
                "rational_sqrt_band: claimed certified_interval must be > 0, "
                f"got {i_raw!r}",
            )
        if i_frac < interval_exact:
            return (
                False,
                "rational_sqrt_band: CERTIFIED_INTERVAL_UNDERSTATED — committed "
                f"interval {_render_frac(i_frac)} < re-derived eps+delta "
                f"{_render_frac(interval_exact)}; an understated interval is a "
                "false certificate",
            )
        return (
            True,
            "rational_sqrt_band: claim within epsilon of recomputed "
            f"sqrt(M)~{sqrt_note}; committed certified interval "
            f"|claim − true| <= {_render_frac(i_frac)} (re-derived eps+delta = "
            f"{_render_frac(interval_exact)})",
        )
    return (
        True,
        "rational_sqrt_band: claim within epsilon="
        f"{_render_frac(eps)} of recomputed sqrt(M)~{sqrt_note} "
        "(no conditioning bound declared: the band covers the RECOMPUTED "
        "value only)",
    )


def _rational_band_contains(R: Fraction, c: Fraction, eps: Fraction) -> bool:
    """|R − c| ≤ eps decided exactly on rationals (no sqrt to eliminate).
    Module-level so the mutant battery can plant a band-widening bug and
    measure which cell catches it."""
    return abs(R - c) <= eps


def _cmp_rational_band(a: object, b: object, params: dict) -> tuple[bool, str]:
    """Certificate-shaped band comparator, the no-sqrt sibling of
    rational_sqrt_band: the recomputed side is an EXACT rational R (as
    {"kind": "rational", "num", "den"}) produced by a certificate primitive,
    the claimed side is a number c, and acceptance is |R − c| ≤ epsilon
    decided exactly on Fractions. R MAY be negative — nothing restricts the
    kind to nonnegative quantities. Zero float ambiguity on the accept path;
    the only approximate object is the declared epsilon (auditor-anchored
    data).

    ORDERING PINNED (scope D8): the recomputed `kind` tag is checked FIRST,
    before any interval-presence/shape logic, so a sqrt_of_rational value
    bound to this kind (a spec-authoring kind×quantity mismatch) is a
    determinate mismatch RED, never a reinterpretation — including in
    conditioning mode with interval fields present.

    A recomputed {"kind": "refused", ...} is a determinate certificate
    refusal → (False, reason). With conditioning_bound the recomputed value
    carries the exact re-derived interval and the claimed value must be
    exactly {"value", "certified_interval"}: acceptance stays epsilon against
    "value" (the bound REPORTS, it never RELAXES) and the COMMITTED interval
    must be >= the re-derived one — an understated interval is a false
    certificate (RED); an overstated one is honest-but-loose and stays
    visible because it is integrity-pinned in the bundle."""
    epsilon = params.get("epsilon")
    try:
        eps_bad = (
            isinstance(epsilon, bool)
            or not isinstance(epsilon, (int, float))
            or not math.isfinite(float(epsilon))
            or float(epsilon) <= 0
        )
    except OverflowError:  # huge-int epsilon: not float-representable — refuse
        eps_bad = True
    if eps_bad:
        return (
            False,
            f"rational_band: epsilon must be a finite number > 0, got {epsilon!r}",
        )
    eps = Fraction(epsilon)

    if not isinstance(a, dict):
        return (
            False,
            f"rational_band: recomputed value must be an object, got "
            f"{type(a).__name__}",
        )
    kind = a.get("kind")
    if kind == "refused":
        return (
            False,
            "rational_band: certificate refused — "
            f"{a.get('reason_code')!r}: {a.get('detail')!r}",
        )
    if kind != "rational":
        return (False, f"rational_band: unknown recomputed kind {kind!r}")
    num = a.get("num")
    den = a.get("den")
    for label, v in (("num", num), ("den", den)):
        if isinstance(v, bool) or not isinstance(v, int):
            return (
                False,
                f"rational_band: recomputed {label} must be an int, got "
                f"{type(v).__name__}",
            )
    if den <= 0:
        return (
            False,
            f"rational_band: recomputed R must satisfy den > 0 (got {num}/{den})",
        )
    R = Fraction(num, den)

    expects_interval = params.get("conditioning_bound", False) is True
    has_interval = ("interval_num" in a) or ("interval_den" in a)
    if expects_interval != has_interval:
        return (
            False,
            "rational_band: certified-interval presence inconsistent with "
            f"the declared conditioning_bound (declared={expects_interval}, "
            f"recomputed carries interval={has_interval}) — fail-closed",
        )

    # --- Claimed-operand admission (strict; the type-confusion surface). ---
    if expects_interval:
        if not isinstance(b, dict) or set(b) != {"value", "certified_interval"}:
            return (
                False,
                "rational_band: with conditioning_bound the claimed value "
                "must be exactly {value, certified_interval}, got "
                f"{type(b).__name__}"
                + (f" with keys {sorted(map(repr, b))}" if isinstance(b, dict) else ""),
            )
        c_raw: object = b["value"]
        i_raw: object = b["certified_interval"]
    else:
        c_raw, i_raw = b, None
    c, err = _admit_json_number("rational_band", "claimed value", c_raw)
    if err is not None:
        return (False, err)

    # --- The band, exactly on rationals. ---
    if not _rational_band_contains(R, c, eps):
        return (
            False,
            "rational_band: claimed value not within epsilon of recomputed R "
            f"(claimed={_render_frac(c)}, R={_render_frac(R)}, "
            f"epsilon={_render_frac(eps)})",
        )

    # --- The committed certified interval (the bound REPORTS, never relaxes). ---
    if expects_interval:
        inum = a.get("interval_num")
        iden = a.get("interval_den")
        for label, v in (("interval_num", inum), ("interval_den", iden)):
            if isinstance(v, bool) or not isinstance(v, int):
                return (
                    False,
                    f"rational_band: recomputed {label} must be an int, got "
                    f"{type(v).__name__}",
                )
        if iden <= 0 or inum <= 0:
            return (
                False,
                "rational_band: re-derived certified interval must be > 0 "
                f"(got {inum}/{iden})",
            )
        interval_exact = Fraction(inum, iden)
        i_frac, err = _admit_json_number(
            "rational_band", "claimed certified_interval", i_raw
        )
        if err is not None:
            return (False, err)
        if i_frac <= 0:
            return (
                False,
                f"rational_band: claimed certified_interval must be > 0, got {i_raw!r}",
            )
        if i_frac < interval_exact:
            return (
                False,
                "rational_band: CERTIFIED_INTERVAL_UNDERSTATED — committed "
                f"interval {_render_frac(i_frac)} < re-derived interval "
                f"{_render_frac(interval_exact)}; an understated interval is a "
                "false certificate",
            )
        return (
            True,
            "rational_band: claim within epsilon of recomputed "
            f"R={_render_frac(R)}; committed certified interval "
            f"|claim − true| <= {_render_frac(i_frac)} (re-derived = "
            f"{_render_frac(interval_exact)})",
        )
    return (
        True,
        "rational_band: claim within epsilon="
        f"{_render_frac(eps)} of recomputed R={_render_frac(R)} "
        "(no conditioning bound declared: the band covers the RECOMPUTED "
        "value only)",
    )


def _freeze(x: object) -> object:
    """Make an element hashable AND canonical for multiset comparison without
    sorting adversarial keys (§C9). Dict KEY-order is NOT significant — a dict
    freezes to a frozenset of (k, frozen(v)) items, which is order-independent
    and hashable without sorting mixed-type keys. Sequence order IS significant
    -> tuple."""
    if isinstance(x, dict):
        return ("__dict__", frozenset((k, _freeze(v)) for k, v in x.items()))
    if isinstance(x, (list, tuple)):
        return ("__seq__", tuple(_freeze(v) for v in x))
    return x


def _render(diff: Counter) -> str:
    """Deterministic-enough rendering of a multiset difference (a Counter) for
    failure detail. Avoids sorted() on adversarial keys (§C9) by rendering each
    element in iteration order, capped; shows ×count when a duplicate matters."""
    items = [f"{x!r}×{c}" if c != 1 else repr(x) for x, c in diff.items()]
    shown = items[:8]
    suffix = "" if len(items) <= 8 else f" …(+{len(items) - 8})"
    return "{" + ", ".join(shown) + suffix + "}"


# The registry. Fail-closed: a kind not present here is rejected at resolve time.
_COMPARATOR_REGISTRY: dict[str, Comparator] = {
    "scalar_epsilon": _cmp_scalar_epsilon,
    "exact": _cmp_exact,
    "text_normalized": _cmp_text_normalized,
    "set": _cmp_set,
    "structured": _cmp_structured,
    "rational_sqrt_band": _cmp_rational_sqrt_band,
    "rational_band": _cmp_rational_band,
}


def comparator_kinds() -> frozenset[str]:
    """The comparator kind names this verifier implements."""
    return frozenset(_COMPARATOR_REGISTRY)


def resolve_comparator(kind: str) -> Comparator:
    """Return the comparator callable for `kind`, or raise UnknownComparatorKind
    (fail-closed; §4a — never default to a permissive comparator)."""
    fn = _COMPARATOR_REGISTRY.get(kind)
    if fn is None:
        raise UnknownComparatorKind(
            f"comparator kind {kind!r} not in verifier registry "
            f"(known: {tuple(_COMPARATOR_REGISTRY)!r})"
        )
    return fn


def validate_comparator_params(kind: str, params: dict) -> None:
    """Fail-closed pre-flight that a comparator's params reference only
    verifier-implemented closed-world identifiers (§4a.6). Called at
    anchor-load so a bad profile/schema is rejected before any dispatch.
    Raises UnknownComparatorKind / UnknownComparatorParam / ValueError."""
    if kind not in _COMPARATOR_REGISTRY:
        raise UnknownComparatorKind(
            f"comparator kind {kind!r} not in verifier registry "
            f"(known: {tuple(_COMPARATOR_REGISTRY)!r})"
        )
    if kind == "scalar_epsilon":
        if "epsilon" not in params:
            raise ValueError("scalar_epsilon requires an 'epsilon' param")
        try:
            eps = float(params["epsilon"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"scalar_epsilon epsilon not numeric: {exc}") from exc
        if not math.isfinite(eps) or eps < 0:
            raise ValueError(
                f"scalar_epsilon epsilon must be finite and >= 0, got {eps!r}"
            )
    elif kind == "text_normalized":
        profile = params.get("profile")
        if not isinstance(profile, str) or profile not in _NORMALIZATION_PROFILES:
            raise UnknownComparatorParam(
                f"text_normalized profile {profile!r} not allowlisted "
                f"(known: {tuple(_NORMALIZATION_PROFILES)!r})"
            )
    elif kind == "structured":
        schema_id = params.get("schema")
        if not isinstance(schema_id, str) or schema_id not in _STRUCTURED_SCHEMAS:
            raise UnknownComparatorParam(
                f"structured schema {schema_id!r} not allowlisted "
                f"(known: {tuple(_STRUCTURED_SCHEMAS)!r})"
            )
    elif kind in ("rational_sqrt_band", "rational_band"):
        # Both certificate-band kinds are GENERIC: only `epsilon` is required.
        # `equilibrium_tol` is a PRIMITIVE param that may share the binding
        # surface — validated if present, but never required here (the
        # primitive requires it itself at run time, fail-closed). Requiring an
        # FEA param in a generic kind was the incoherence the scope's audit
        # fold [A4] removed.
        if "epsilon" not in params:
            raise ValueError(f"{kind} requires an 'epsilon' param")
        for name in ("epsilon", "equilibrium_tol"):
            if name not in params:
                continue
            v = params[name]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(
                    f"{kind} {name} must be a JSON number, got {type(v).__name__}"
                )
            try:
                fv = float(v)
            except OverflowError as exc:
                raise ValueError(f"{kind} {name} not float-representable") from exc
            if not math.isfinite(fv) or fv <= 0:
                raise ValueError(f"{kind} {name} must be finite and > 0, got {fv!r}")
        anchor = params.get("input_anchor")
        if anchor is not None:
            if not isinstance(anchor, dict) or not anchor:
                raise ValueError(f"{kind} input_anchor must be a non-empty object")
            for role, digest in anchor.items():
                if not isinstance(role, str) or not role:
                    raise ValueError(
                        f"{kind} input_anchor role keys must be "
                        f"non-empty strings, got {role!r}"
                    )
                if not isinstance(digest, str) or not _ANCHOR_SHA256_RE.match(digest):
                    raise ValueError(
                        f"{kind} input_anchor[{role!r}] must be a "
                        "lowercase sha256 hex digest"
                    )
        cb = params.get("conditioning_bound", False)
        if not isinstance(cb, bool):
            raise ValueError(
                f"{kind} conditioning_bound must be a boolean, got {type(cb).__name__}"
            )
        if cb and anchor is None:
            raise ValueError(
                f"{kind} conditioning_bound requires input_anchor: a "
                "conditioning bound over a producer-chosen problem is a true "
                "bound answering the wrong question (B-input-provenance)"
            )
    # exact / set take no kind-specific params; nothing to validate there.

    # Optional, kind-independent documentary annotation. If present it MUST be a
    # closed-world value (a typo/garbage tag fails closed, matching the §4a.6
    # discipline for every other param); absent is fine (back-compatible).
    if "numeric_model" in params:
        nm = params["numeric_model"]
        if not isinstance(nm, str) or nm not in _NUMERIC_MODELS:
            raise UnknownComparatorParam(
                f"numeric_model {nm!r} not allowlisted "
                f"(known: {tuple(sorted(_NUMERIC_MODELS))!r})"
            )
