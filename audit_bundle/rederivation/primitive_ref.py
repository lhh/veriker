"""audit_bundle/rederivation/primitive_ref.py — versioned primitive references.

D1 (`the audit-bundle contract` §8a). A spec's
`primitive_id` grows an OPTIONAL version and an OPTIONAL auditor-chosen digest
pin:

    name[@version][#sha256hex]

WHY THIS EXISTS. The SHA-anchored spec pins the NAME, not the code. A bare
`primitive_id` therefore says nothing about WHICH implementation ran: ours and a
third party's `fea_vonmises_recompute` are the same string. The version makes
the intended implementation nameable; the digest pin makes it BINDING.

WHAT EACH LEVEL ACTUALLY BUYS — the distinction is load-bearing and is kept
distinct on the face, because collapsing them is the labeling-up defect:

  * bare name       -> UNVERSIONED. Exactly today's guarantee: the verifier runs
                       whatever it has registered under that name.
  * `@version`      -> the code SAYS it is that version. A version attribute is
                       asserted by the code declaring it, so this is a
                       legibility gain, NOT a byte binding. It is not a trust
                       gate on its own.
  * `#sha256`       -> BINDING, within a stated trust model. Compared against
                       the sha of the source file holding the code object
                       dispatch will actually invoke -- the callable dispatch
                       BINDS ONCE and both hashes and calls (R2 below).
                       RESIDUAL, stated here rather than in another file: the
                       filename is taken from `code.co_filename`, which a caller
                       running its own `compile()` / `code.replace(...)` can
                       stamp. The pin therefore vets an HONEST implementation's
                       bytes; it is not a defense against arbitrary hostile
                       code, and the in-bundle-source refusal in dispatch
                       remains the actual gate. This matters because D1's stated
                       motivation is third-party implementations, which is
                       exactly where `co_filename` is not vouched for.

Pinning is OPTIONAL and auditor-selectable by design (ADR R2): mandatory pinning
would weld a spec to one implementation and foreclose independent conforming
implementations -- which is also the product's stated answer to monoculture
risk. Two modes, and the face records which one ran.

CAPABILITY HONESTY -- READ THIS BEFORE DESCRIBING THE FEATURE. As of
2026-08-29, **ZERO of the 27 registered primitives declare `primitive_version`**
(verified by executing the registry). So `name@version` against ANY built-in
refuses with `PRIMITIVE_VERSION_UNDECLARED`, and `version_status: "matched"` is
unreachable outside a test fixture. That refusal is CORRECT -- the verifier
cannot establish a version the code does not state, and assuming a match would
be the fail-open choice -- but it means the two modes are not equally live at
the public cut:

    #sha256 pin  -> LIVE. Works against any primitive with a derivable source.
    @version     -> REFUSES against every built-in until `primitive_version` is
                    backfilled across the 27 primitives (tracked as an ADR §9
                    item, not assumed).

Do not describe `@version` as working today. The accepting GRAMMAR is what
shipped, and shipping it before the cut is the point: a released verifier that
REJECTS `@` would strand every later versioned spec on the copy auditors
already hold.

BACKWARD COMPATIBILITY IS THE POINT. A bare id stays valid and means
unversioned, so no shipped spec changes meaning and no anchor is reissued. What
gates the public cut is that the SHIPPED verifier ACCEPTS this grammar: a
release that rejects `@` would strand every later versioned spec on the copy
auditors already downloaded.

R2 -- WHY THE CALLABLE IS BOUND ONCE. An earlier cut hashed
`getattr(primitive, "recompute")` inside provenance and separately invoked
`primitive.recompute(...)` at dispatch. Two attribute reads, so a `property` or
descriptor hands honest code to the hasher and hostile code to the caller:
MEASURED as a clean verdict with `digest_status: "matched"` naming a file whose
code never ran, using plain Python and no forgery at all. The same divergence
afflicts any lazily-bound `recompute` with no attacker present. Dispatch now
binds once; never re-read the attribute between hashing and invoking.

DIGEST GRANULARITY (disclosed, not smoothed). `derive_provenance` hashes the
resolved SOURCE FILE, not the primitive's own source segment. Two shipped files
hold more than one primitive (`fea_witness_cert.py` holds 3, `gaci_composite.py`
holds 2), so a pin on one of those also pins its siblings: editing any of them
breaks all their pins. Accepted -- the file is the unit whose bytes determine
behaviour and the failure direction is CLOSED (an unrelated edit refuses),
never open. A per-primitive segment hash would let an edit to shared
module-level code inside the same file escape the pin, which is strictly worse.

Stdlib-only (core verify() path, S0 limitation #4). No `re`: the hex check is a
character-set walk.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .registry import (
    UnknownPrimitive,
    derive_provenance,
    derive_provenance_of_callable,
    resolve_primitive,
)

__all__ = [
    "MalformedPrimitiveRef",
    "PrimitiveRef",
    "PrimitiveRefViolation",
    "SIGILS",
    "parse_primitive_ref",
    "resolve_primitive_ref",
]

#: The two grammar sigils. Measured 2026-08-29 against all 88 distinct
#: `primitive_id` strings in the shipped fleet: the charset is `[a-z0-9_]`
#: exactly and ZERO contain either sigil, so a bare id can never be misparsed
#: as versioned or pinned.
SIGILS = ("@", "#")

#: Sentinel for "the caller did not bind the callable". Distinct from None,
#: because None is itself a legitimate (unhashable) bound value that must be
#: refused rather than silently re-derived. See R2 in resolve_primitive_ref.
_UNBOUND = object()

_HEX = frozenset("0123456789abcdefABCDEF")


class MalformedPrimitiveRef(ValueError):
    """A `primitive_id` string that does not parse. Raised at LOAD.

    Refuse, never demote: a malformed ref must never fall back to an
    unversioned/unpinned resolution, because that fallback is precisely how a
    producer would strip a pin the auditor wrote.
    """


class PrimitiveRefViolation(Exception):
    """A ref parsed, resolved to a registered primitive, and then FAILED its
    auditor-declared version or digest constraint. Fail-closed at dispatch."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(f"{reason_code}: {detail}")
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class PrimitiveRef:
    """A parsed reference. `raw` is excluded from equality so a ref compares by
    MEANING, not by the bytes it happened to be written as."""

    name: str
    version: str | None = None
    digest: str | None = None
    raw: str = field(default="", compare=False)

    @property
    def is_pinned(self) -> bool:
        return self.digest is not None


def _is_sha256_hex(s: str) -> bool:
    """64 hex chars. Matches the existing `pinned_inputs` convention
    (`[0-9a-fA-F]{64}`) rather than inventing a stricter sibling."""
    return len(s) == 64 and all(c in _HEX for c in s)


def parse_primitive_ref(raw: object) -> PrimitiveRef:
    """Parse `name[@version][#sha256hex]`. Fail-closed on anything else.

    Order is fixed: the digest sigil binds LAST, so `name#sha@version` is a
    parse error rather than a silently-accepted reordering.
    """
    if not isinstance(raw, str) or not raw:
        raise MalformedPrimitiveRef(
            f"primitive_id must be a non-empty string, got {raw!r}"
        )
    # No whitespace or control characters anywhere. Cheap, and it removes a
    # whole class of look-alike ids before any structural parsing.
    for ch in raw:
        if ch.isspace() or ord(ch) < 0x20:
            raise MalformedPrimitiveRef(
                f"primitive_id {raw!r} contains whitespace or a control character"
            )

    left, hsep, digest_part = raw.partition("#")
    digest: str | None = None
    if hsep:
        if not digest_part:
            raise MalformedPrimitiveRef(
                f"primitive_id {raw!r} has an empty digest after '#'"
            )
        if not _is_sha256_hex(digest_part):
            raise MalformedPrimitiveRef(
                f"primitive_id {raw!r}: digest must be exactly 64 hex characters "
                f"(got {len(digest_part)} chars). A '#' after the digest, or a "
                "digest written before the version, parses here as a malformed "
                "digest -- the grammar is name[@version][#sha256hex]."
            )
        digest = digest_part.lower()

    name, asep, version_part = left.partition("@")
    version: str | None = None
    if asep:
        if not version_part:
            raise MalformedPrimitiveRef(
                f"primitive_id {raw!r} has an empty version after '@'"
            )
        if any(s in version_part for s in SIGILS):
            raise MalformedPrimitiveRef(
                f"primitive_id {raw!r}: version {version_part!r} contains a "
                "grammar sigil ('@' or '#')"
            )
        version = version_part

    if not name:
        raise MalformedPrimitiveRef(f"primitive_id {raw!r} has an empty name")

    return PrimitiveRef(name=name, version=version, digest=digest, raw=raw)


def resolve_primitive_ref(
    ref: PrimitiveRef, resolver: object = None, bound_recompute: object = _UNBOUND
) -> tuple[object, dict]:
    """Resolve a parsed ref to a registered primitive, enforcing its version and
    digest constraints.

    Returns `(primitive, record)`. The record is the FACE: it keeps the three
    states distinguishable --

        version_status: "unversioned" | "matched"
        digest_status:  "unpinned"    | "matched"

    -- so a reader can never mistake "the auditor pinned nothing" for "the
    auditor pinned this and it matched".

    Raises `UnknownPrimitive` (name not registered, unchanged behaviour) or
    `PrimitiveRefViolation` (registered, but the constraint failed).

    `resolver` is the NAME->instance lookup, defaulting to
    `registry.resolve_primitive`. It is injectable ON PURPOSE: dispatch passes
    its own module-level `resolve_primitive` so that fault injection
    (`monkeypatch.setattr(dispatch, "resolve_primitive", ...)`) still reaches
    resolution. That seam is what proves dispatch is LIVE -- a silently skipped
    step is otherwise indistinguishable from a passing one -- so routing around
    it would quietly disable the substrate's own liveness controls. An earlier
    cut of D1 did exactly that and broke 10 dispatch tests; this parameter is
    the fix, and `test_fault_injection_seam_is_preserved` is the regression.
    """
    resolve = resolve_primitive if resolver is None else resolver
    primitive = resolve(ref.name)  # fail-closed on unknown name

    # R3: `getattr` only suppresses AttributeError. A descriptor raising
    # anything else propagated out of dispatch entirely -- no DispatchFailure
    # recorded, the cardinality guard skipped, contradicting the "every
    # per-output evaluation is wrapped" contract. Refuse instead of escaping.
    try:
        declared = getattr(primitive, "primitive_version", None)
    except Exception as exc:  # noqa: BLE001 - a raising descriptor is fail-closed
        raise PrimitiveRefViolation(
            "PRIMITIVE_VERSION_UNREADABLE",
            f"reading `primitive_version` from the resolved primitive "
            f"{ref.name!r} raised {type(exc).__name__}. A primitive whose own "
            "version cannot be read is not one the verifier can reason about.",
        ) from exc
    if not isinstance(declared, str) or not declared:
        declared = None

    record: dict = {
        "name": ref.name,
        "version_requested": ref.version,
        "version_declared": declared,
        "version_status": "unversioned",
        "digest_requested": ref.digest,
        "digest_observed": None,
        "digest_status": "unpinned",
    }

    if ref.version is not None:
        if declared is None:
            raise PrimitiveRefViolation(
                "PRIMITIVE_VERSION_UNDECLARED",
                f"spec pins primitive {ref.name!r} at version {ref.version!r}, but "
                "the registered implementation declares no `primitive_version`. "
                "The verifier cannot establish that the resolved code is the "
                "version the auditor asked for, so it refuses rather than "
                "assuming an undeclared version matches.",
            )
        if declared != ref.version:
            raise PrimitiveRefViolation(
                "PRIMITIVE_VERSION_MISMATCH",
                f"spec pins primitive {ref.name!r} at version {ref.version!r}, "
                f"but the registered implementation declares {declared!r}.",
            )
        record["version_status"] = "matched"

    if ref.digest is not None:
        # R2: hash the callable the caller ALREADY BOUND and will invoke, not a
        # second `getattr` that a property/descriptor can answer differently.
        if bound_recompute is _UNBOUND:
            observed = derive_provenance(primitive).get("sha256")
        else:
            observed = derive_provenance_of_callable(bound_recompute).get("sha256")
        if not isinstance(observed, str) or not observed:
            raise PrimitiveRefViolation(
                "PRIMITIVE_DIGEST_UNAVAILABLE",
                f"spec pins primitive {ref.name!r} to digest {ref.digest!r}, but "
                "no source digest could be derived from the resolved instance "
                "(provenance origin 'unknown'). An unhashable primitive must "
                "never satisfy a pin by default.",
            )
        record["digest_observed"] = observed
        if observed.lower() != ref.digest:
            raise PrimitiveRefViolation(
                "PRIMITIVE_DIGEST_MISMATCH",
                f"spec pins primitive {ref.name!r} to digest {ref.digest!r}, but "
                f"the resolved instance's source hashes to {observed!r}. Note "
                "the digest covers the whole SOURCE FILE, so an edit to a "
                "sibling primitive in the same file also breaks this pin (a "
                "closed failure direction, disclosed in the module docstring).",
            )
        record["digest_status"] = "matched"

    return primitive, record


# Re-exported so callers importing this module get the fail-closed unknown-name
# exception from one place.
UnknownPrimitive = UnknownPrimitive
