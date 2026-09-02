"""tests/test_primitive_declarations.py — the primitive face, as a PROPERTY.

Every registered re-derivation primitive declares four things beside its id:

    primitive_version        contract revision (see below)
    primitive_shape          the taxonomy name the book groups it under
    primitive_tier           "A" | "B" | "C"
    primitive_contract       the declared behaviour the version NAMES
    primitive_scope_limits   what it does NOT cover

WHAT `primitive_version` MEANS, because the distinction is load-bearing. It is a
**contract revision**, not our release counter: `climate_emission_recompute@1`
says "revision 1 of the declared behaviour named `climate_emission_recompute`",
a claim ANY conforming implementation may make. A vendor-owned release counter
would be a number only one party can supply, which welds a spec to one
implementation — the thing optional-rather-than-mandatory digest pinning exists
to avoid. So the version is a monotonic integer over `primitive_contract`, and
`#sha256` remains the separate, binding, byte-level pin.

Versions are numbered from FIRST PUBLIC DECLARATION, not reconstructed
retroactively — some of these primitives were revised during the promotion loop
before any version was published, and `@1` does not claim otherwise.

UNIVERSAL, DELIBERATELY. There is no primitive COUNT here and no id list: the
open drop ships a subset of the internal registry (the `gaci_*` primitives are
publish-excluded and `primitives/__init__.py` is transformed to drop their
self-registration), so a pinned denominator in a SHIPPED test is a test that
fails on the customer's first `pytest`. The exact roster, versions and
source digests are pinned in `tests/test_primitive_contract_ratchet.py`, which
is internal-only for that reason. Same split as
`test_primitive_ref_versioning.py` / `test_primitive_ref_denominator_ratchet.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.rederivation import registry  # noqa: E402
from audit_bundle.rederivation.primitive_ref import (  # noqa: E402
    PrimitiveRefViolation,
    parse_primitive_ref,
    resolve_primitive_ref,
)

TIERS = ("A", "B", "C")


def _registry() -> dict[str, object]:
    return {pid: registry.resolve_primitive(pid) for pid in _ids()}


def _ids() -> list[str]:
    """The verifier's OWN methods, not everything in the registry.

    THE REGISTRY IS GLOBAL AND SHARED. Pilots and auditor kits register into it
    too — measured 2026-08-29 by a full-suite run, where seven pilot-local
    `examples/*` primitives appeared here and failed every assertion below. They
    SHOULD fail it: a kit is under no obligation to declare a contract in our
    book, and its face row says so with a null tier rather than a guess.
    Requiring a declaration of them would be requiring third parties to document
    themselves in our documentation."""
    registry._ensure_primitives_loaded()
    return sorted(registry.distribution_primitives())


def test_distribution_set_is_not_empty() -> None:
    """Non-vacuity. Every test below iterates the distribution set; if it were
    empty they would all pass while asserting nothing."""
    assert _ids(), "empty distribution set — the parametrized checks would be vacuous"


def test_a_kit_primitive_is_not_required_to_declare_anything() -> None:
    """The scoping above, asserted rather than just commented.

    A primitive registered from OUTSIDE the distribution is a kit's or a pilot's,
    and it is legitimately absent from every requirement in this file. If this
    ever fails, the scope has silently widened into demanding that third-party
    implementations document themselves in our book."""

    class _KitPrimitive:
        primitive_id = "kit_only_recompute"

        def recompute(self, inputs, pack_section):  # pragma: no cover - never run
            raise AssertionError("not invoked")

    registry._ensure_primitives_loaded()
    registry.register_primitive(_KitPrimitive())
    try:
        assert "kit_only_recompute" in registry.registered_primitives()
        assert "kit_only_recompute" not in registry.distribution_primitives()
        assert "kit_only_recompute" not in _ids()
    finally:
        registry._PRIMITIVE_REGISTRY.pop("kit_only_recompute", None)


@pytest.mark.parametrize("pid", _ids())
def test_declares_a_contract_revision(pid: str) -> None:
    prim = _registry()[pid]
    version = getattr(prim, "primitive_version", None)
    assert isinstance(version, str) and version, (
        f"{pid} declares no primitive_version. An undeclared version makes "
        "`name@version` refuse with PRIMITIVE_VERSION_UNDECLARED against this "
        "primitive — correct, but it means the version half of the reference "
        "grammar does not work here."
    )
    assert version.isdigit() and not version.startswith("0"), (
        f"{pid} declares primitive_version={version!r}. A contract revision is a "
        "monotonic integer: the comparison is exact string equality, so a "
        "dotted/semver spelling promises range semantics the resolver does not "
        "implement, and a leading zero gives one revision two spellings."
    )


@pytest.mark.parametrize("pid", _ids())
def test_declares_a_published_tier(pid: str) -> None:
    tier = getattr(_registry()[pid], "primitive_tier", None)
    assert tier in TIERS, (
        f"{pid} declares primitive_tier={tier!r}, not one of {TIERS}. The tier is "
        "what stops a declared version from reading as standardization: it tells "
        "an auditor whether they are looking at a citable standard (A), a "
        "reference implementation (B), or a certificate checker that never "
        "solves (C)."
    )


@pytest.mark.parametrize("pid", _ids())
def test_declares_the_behaviour_its_version_names(pid: str) -> None:
    prim = _registry()[pid]
    contract = getattr(prim, "primitive_contract", None)
    assert isinstance(contract, str) and len(contract.strip()) >= 40, (
        f"{pid} declares no usable primitive_contract. The version is a POINTER "
        "to this text; without it `@1` names nothing and the reader is back to "
        "reading the source to learn what the method does."
    )
    limits = getattr(prim, "primitive_scope_limits", None)
    assert isinstance(limits, tuple) and limits, (
        f"{pid} declares no primitive_scope_limits. Scope limits must travel "
        "WITH the code — a method whose limits live only in a document the "
        "reader was not given has not declared them."
    )
    assert all(isinstance(x, str) and x.strip() for x in limits), (
        f"{pid} has an empty or non-string entry in primitive_scope_limits"
    )
    shape = getattr(prim, "primitive_shape", None)
    assert isinstance(shape, str) and shape.strip(), (
        f"{pid} declares no primitive_shape. The shipped docstrings cite the "
        "book by SHAPE, so an undeclared shape leaves those citations resolving "
        "to a book that does not group this primitive anywhere."
    )


def test_no_two_distribution_primitives_share_a_contract() -> None:
    """A contract is per-id. Two ids sharing one text means either a duplicate
    method under two names, or — the real hazard — a SUBCLASS that inherited its
    parent's declaration and is therefore describing the wrong quantity. Three
    `fea_witness_certificate*` primitives are subclasses of one base class, so
    this is a live trap, not a hypothetical."""
    reg = _registry()
    seen: dict[str, str] = {}
    for pid in sorted(reg):
        contract = getattr(reg[pid], "primitive_contract", "")
        if contract in seen:
            pytest.fail(
                f"{pid} and {seen[contract]} declare an IDENTICAL "
                f"primitive_contract. If {pid} is a subclass, it inherited the "
                "declaration and is describing its parent's behaviour."
            )
        seen[contract] = pid


@pytest.mark.parametrize("pid", _ids())
def test_declared_version_resolves_and_a_wrong_one_refuses(pid: str) -> None:
    """The declaration is LIVE, not decorative: the resolver reads it."""
    declared = getattr(_registry()[pid], "primitive_version")

    _, record = resolve_primitive_ref(parse_primitive_ref(f"{pid}@{declared}"))
    assert record["version_status"] == "matched"
    assert record["version_declared"] == declared

    wrong = f"{int(declared) + 1}"
    with pytest.raises(PrimitiveRefViolation) as exc:
        resolve_primitive_ref(parse_primitive_ref(f"{pid}@{wrong}"))
    assert exc.value.reason_code == "PRIMITIVE_VERSION_MISMATCH"

    # A bare id must still mean UNVERSIONED. Backfilling versions must not
    # silently upgrade what an existing unversioned spec asserts.
    _, bare = resolve_primitive_ref(parse_primitive_ref(pid))
    assert bare["version_status"] == "unversioned"
