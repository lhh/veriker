"""audit_bundle/rederivation/registry.py — verifier-side primitive registry.

Maps primitive_id -> ReDerivationPrimitive INSTANCE. Primitives are
verifier-DISTRIBUTION code: they self-register at import (audit_bundle.
rederivation.primitives.*) and are NEVER bundle-supplied (§C5/§C6).

A primitive_id named in a pinned spec but absent from this registry is
fail-closed at dispatch (UnknownPrimitive) — the same discipline that holds
`custom` comparators. There is exactly one registry namespace; there is no
separate `custom:<id>` governance path.

Stdlib-only (core verify() path).
"""

from __future__ import annotations


class UnknownPrimitive(Exception):
    """A spec names a primitive_id not in the verifier registry (fail-closed)."""


_PRIMITIVE_REGISTRY: dict[str, object] = {}

_DIST_ROOT = None  # audit_bundle package root, resolved once (lazy, stdlib-safe)


def derive_provenance_of_callable(fn: object) -> dict:
    """Provenance for an ALREADY-BOUND callable — the object the caller holds
    and will invoke.

    R2 (adversarial pass 2026-08-29). `derive_provenance` below performed its
    own `getattr(primitive, "recompute")`, and dispatch performed another at
    invocation. Two attribute reads means a `property`/descriptor can hand
    honest code to the hasher and hostile code to the caller: MEASURED as a
    clean verdict with `digest_status: "matched"` naming a file whose code never
    ran. No `compile()`, no `co_filename` rewrite — plain Python, and the same
    divergence afflicts any lazily-bound `recompute` with no attacker present.

    The fix is to bind ONCE and both hash and invoke that same object. This
    function is the hashing half; dispatch owns the single bind.

    STATED RESIDUAL (unchanged): a caller running its own `compile()` /
    `code.replace(co_filename=…)` can stamp any filename onto the code object,
    so this vets an HONEST implementation's location. The in-bundle-source
    refusal in dispatch is the actual gate.
    """
    try:
        import hashlib
        from pathlib import Path

        code = getattr(fn, "__code__", None)
        if code is None and fn is not None:
            code = getattr(getattr(type(fn), "__call__", None), "__code__", None)
        if code is None or not code.co_filename:
            return {"origin": "unknown", "source": None, "sha256": None}
        src = Path(code.co_filename)
        if not src.is_file():
            return {"origin": "unknown", "source": None, "sha256": None}
        src = src.resolve()
        sha = hashlib.sha256(src.read_bytes()).hexdigest()
        global _DIST_ROOT
        if _DIST_ROOT is None:
            _DIST_ROOT = Path(__file__).resolve().parents[1]
        origin = "distribution" if src.is_relative_to(_DIST_ROOT) else "external"
        return {"origin": origin, "source": str(src), "sha256": sha}
    except Exception:  # noqa: BLE001 — provenance is a disclosure, never a gate
        return {"origin": "unknown", "source": None, "sha256": None}


def derive_provenance(primitive: object) -> dict:
    """Provenance `{origin, source, sha256}` for the verdict face, derived from
    the BOUND `recompute` object THIS primitive instance would actually run —
    NOT from the class at registration.

    Why the instance, at the point of use: dispatch calls
    `primitive.recompute(...)` (an instance attribute), while a class-level
    derivation describes `type(primitive).recompute`. Those diverge whenever an
    instance carries its own `recompute` (a reassigned attr, a callable object),
    so a class-level row can describe code that never runs — a face that lies
    without any attacker (subclass reuse) and a forgery channel with one
    (`inst.recompute = other`). Deriving here, from `getattr(primitive,
    "recompute")`, binds the row to the object dispatch invokes.

    `origin` is "distribution" when that code object's source file resolves
    inside the audit_bundle package, "external" otherwise, and "unknown" when
    no source could be derived. There is deliberately NO `inspect.getfile` /
    `__module__` fallback: `__module__` is caller-settable, and a fallback
    through it laundered an external primitive to "distribution" in one
    assignment. No code object → "unknown" (an honest non-label), never a
    guessed one.

    STATED RESIDUAL: a caller running its own `compile()` / `code.replace(
    co_filename=...)` can still stamp any filename onto the code object, so a
    HOSTILE kit can forge "distribution". This label vets an HONEST kit's code
    location; it is not a defense against arbitrary code (which the trust model
    excludes — the operator vouches for a kit as they vouch for the anchor).
    The in-bundle-source refusal in dispatch is the actual gate; this is
    disclosure.

    Never raises on ordinary failure (returns the unknown row); a
    BaseException (SystemExit/KeyboardInterrupt) from hostile introspection
    propagates to the dispatch per-output guard rather than being swallowed
    here."""
    # ONE implementation: bind once here, delegate to the callable form. A
    # caller that can bind the callable itself (dispatch) MUST use
    # derive_provenance_of_callable and invoke THAT SAME object — see R2.
    return derive_provenance_of_callable(getattr(primitive, "recompute", None))


def register_primitive(primitive: object) -> None:
    """Register a ReDerivationPrimitive instance by its primitive_id. Idempotent
    for an identical id; a conflicting re-registration is a programming error.

    Registration records NO provenance: a row captured here would describe the
    class at load time, but the trustworthy question is what the RESOLVED
    instance runs at dispatch (see `derive_provenance`)."""
    pid = getattr(primitive, "primitive_id", None)
    if not isinstance(pid, str) or not pid:
        raise ValueError(f"primitive {primitive!r} has no string primitive_id")
    # D1: the registry namespace is BARE NAMES only. `@` and `#` are the
    # version/digest sigils of the spec-side reference grammar
    # (`primitive_ref.py`); a primitive that registered itself AS `foo@1` would
    # create a second namespace the resolver cannot reason about, and a ref for
    # `foo` would then miss it. Refuse at registration -- fail-closed, and it
    # keeps "one registry namespace" (module docstring) literally true.
    if any(sig in pid for sig in ("@", "#")):
        raise ValueError(
            f"primitive_id {pid!r} contains a reserved grammar sigil ('@' or "
            "'#'). Registration uses BARE names; version and digest live in the "
            "auditor's spec reference (name[@version][#sha256hex]), never in the "
            "registered id."
        )
    existing = _PRIMITIVE_REGISTRY.get(pid)
    if existing is not None and type(existing) is not type(primitive):
        raise ValueError(
            f"primitive_id {pid!r} already registered to a different class "
            f"({type(existing).__name__} vs {type(primitive).__name__})"
        )
    _PRIMITIVE_REGISTRY[pid] = primitive


def primitive_provenance(primitive_id: str) -> dict:
    """Provenance for a registered primitive, derived from the LIVE resolved
    instance (never a cached registration-time row). Unknown id -> the honest
    'unknown' row."""
    prim = _PRIMITIVE_REGISTRY.get(primitive_id)
    if prim is None:
        return {"origin": "unknown", "source": None, "sha256": None}
    return derive_provenance(prim)


def resolve_primitive(primitive_id: str) -> object:
    """Return the registered primitive instance, or raise UnknownPrimitive."""
    prim = _PRIMITIVE_REGISTRY.get(primitive_id)
    if prim is None:
        raise UnknownPrimitive(
            f"primitive_id {primitive_id!r} not in verifier registry "
            f"(registered: {tuple(_PRIMITIVE_REGISTRY)!r}). A primitive a pinned "
            "spec names but the verifier distribution does not implement is "
            "fail-closed — the verifier never loads a primitive from the bundle."
        )
    return prim


def registered_primitives() -> frozenset[str]:
    return frozenset(_PRIMITIVE_REGISTRY)


def distribution_primitives() -> frozenset[str]:
    """Registered ids whose recompute code resolves INSIDE the audit_bundle
    package — the verifier's OWN method set.

    THE REGISTRY IS NOT THE DISTRIBUTION SET, and conflating them is easy to do
    (measured 2026-08-29 by a full-suite run: seven pilot-local primitives from
    `examples/*` register into this same global namespace as soon as their
    modules import, so an id count taken here is a fact about what has been
    IMPORTED, not about what the verifier ships). Anything asking "what methods
    does this verifier bring" — the primitive book, the declaration property
    tests, the contract ratchet — must ask THIS, not `registered_primitives()`.

    The discriminator is `derive_provenance`'s `origin`, which is the same label
    already published on the verdict face, so the book and the face cannot
    disagree about who owns a method. A pilot-local or auditor-kit primitive is
    "external" and is legitimately outside the distribution set — it declares no
    contract, and its face row says so with a null tier rather than a guess.

    Same stated residual as `derive_provenance`: a hostile kit that rewrites
    `co_filename` can claim "distribution". This is a disclosure boundary, not a
    trust gate."""
    return frozenset(
        pid
        for pid, prim in _PRIMITIVE_REGISTRY.items()
        if derive_provenance(prim).get("origin") == "distribution"
    )


def _ensure_primitives_loaded() -> None:
    """Import the bundled primitive implementations so they self-register.
    Called by the dispatch step before resolution. Import-on-demand keeps the
    registry populated without import-time side effects in this module."""
    from . import primitives  # noqa: F401  (import triggers self-registration)
