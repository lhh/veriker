"""D1 — versioned primitive_id (`name@version`) + OPTIONAL auditor-selectable
digest pinning.

PROVENANCE, stated precisely because a blanket "written first" claim was called
out as unfalsifiable: everything ABOVE the "Liveness seam" section was written
before the implementation and was RED. The liveness-seam tests at the bottom
were added AFTER, as a regression for a defect the implementation introduced --
they narrate the first cut, so they cannot predate it. The red-team regressions
in tests/test_primitive_ref_redteam_regressions.py were committed RED in their
own commit, where the ordering IS falsifiable from git.

Scoping artifact: the internal design notes
the internal design notes
Decision of record: the audit-bundle contract §8a/D1.

Grammar under test:  name[@version][#sha256hex]

The three states must be DISTINGUISHABLE on the face (collapsing "unversioned"
into "matched" is the labeling-up defect from Stage 1):
    unversioned / version-matched / digest-pinned-and-matched
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from audit_bundle.rederivation import registry
from audit_bundle.rederivation.primitive_ref import (
    MalformedPrimitiveRef,
    PrimitiveRef,
    PrimitiveRefViolation,
    parse_primitive_ref,
    resolve_primitive_ref,
)

HEX64 = "a" * 64
HEX64_B = "b" * 64


# ---------------------------------------------------------------------------
# Parsing — the grammar
# ---------------------------------------------------------------------------


def test_bare_name_is_unversioned_and_unpinned():
    """The backward-compatibility contract: a bare id stays valid and means
    UNVERSIONED. This is what lets the 105 migration touch points stay untouched
    at the cut."""
    ref = parse_primitive_ref("bom_recompute")
    assert ref == PrimitiveRef(name="bom_recompute", version=None, digest=None)
    assert ref.raw == "bom_recompute"


def test_versioned_name():
    ref = parse_primitive_ref("bom_recompute@1")
    assert ref.name == "bom_recompute"
    assert ref.version == "1"
    assert ref.digest is None


def test_version_and_digest():
    ref = parse_primitive_ref(f"bom_recompute@1#{HEX64}")
    assert ref.name == "bom_recompute"
    assert ref.version == "1"
    assert ref.digest == HEX64


def test_digest_without_version():
    """OR, not AND (Stage 3): a pin is honoured on its own. Requiring a version
    before checking the sha would hand the attacker a deletion -- drop the
    version, the sha stops being checked."""
    ref = parse_primitive_ref(f"bom_recompute#{HEX64}")
    assert ref.name == "bom_recompute"
    assert ref.version is None
    assert ref.digest == HEX64


def test_uppercase_digest_normalized_to_lower():
    """Matches the existing pinned_inputs convention [0-9a-fA-F]{64}."""
    ref = parse_primitive_ref(f"bom_recompute#{'A' * 64}")
    assert ref.digest == "a" * 64


@pytest.mark.parametrize(
    "raw,why",
    [
        ("", "empty ref"),
        ("@1", "empty name"),
        (f"#{HEX64}", "empty name with digest"),
        ("bom_recompute@", "empty version"),
        ("bom_recompute#", "empty digest"),
        ("bom_recompute@1@2", "two version sigils"),
        (f"bom_recompute#{HEX64}@1", "digest before version (wrong order)"),
        ("bom_recompute#deadbeef", "digest not 64 chars"),
        ("bom_recompute#" + "z" * 64, "64 chars but not hex"),
        ("bom_recompute#" + "a" * 63, "63 hex chars"),
        ("bom_recompute#" + "a" * 65, "65 hex chars"),
        ("bom recompute", "whitespace in name"),
        ("bom_recompute@ 1", "whitespace in version"),
        ("bom_recompute@1 ", "trailing whitespace in version"),
        (" bom_recompute", "leading whitespace"),
        ("bom_recompute\n@1", "control char in name"),
    ],
)
def test_malformed_refs_are_refused_not_demoted(raw, why):
    """Refuse, never demote (Stage 3). A malformed ref must raise at LOAD, never
    silently fall back to an unversioned/unpinned resolution -- that fallback is
    exactly how a producer would strip a pin."""
    with pytest.raises(MalformedPrimitiveRef):
        parse_primitive_ref(raw)


def test_non_string_refused():
    for bad in (None, 1, [], {}, b"bom_recompute"):
        with pytest.raises(MalformedPrimitiveRef):
            parse_primitive_ref(bad)


# ---------------------------------------------------------------------------
# Registration — the sigils may never enter the registry namespace
# ---------------------------------------------------------------------------


class _Dummy:
    primitive_id = "d1_test_dummy"
    primitive_version = "1"

    def recompute(self, *a, **k):  # pragma: no cover - never invoked
        return None


def _make(pid, version=None):
    obj = _Dummy()
    obj.primitive_id = pid
    if version is None:
        # a primitive that declares NO version
        try:
            del obj.primitive_version
        except AttributeError:
            pass
        obj.__dict__.pop("primitive_version", None)
        obj.primitive_version = None
    else:
        obj.primitive_version = version
    return obj


@pytest.mark.parametrize("bad_pid", ["foo@1", "foo#" + HEX64, "foo@", "foo#"])
def test_registration_refuses_sigils_in_the_id(bad_pid):
    """One namespace, not two. A primitive that registers itself AS `foo@1`
    would create a second namespace the resolver cannot reason about."""
    with pytest.raises(ValueError):
        registry.register_primitive(_make(bad_pid, "1"))


# ---------------------------------------------------------------------------
# Resolution — the three distinguishable states
# ---------------------------------------------------------------------------


@pytest.fixture
def registered():
    """Register a dummy into an ISOLATED registry so the real one is untouched.

    `_ensure_primitives_loaded` is import-once: once
    `audit_bundle.rederivation.primitives` is in sys.modules, self-registration
    has already happened and re-calling it will NOT repopulate a cleared
    registry. So load FIRST, then snapshot -- otherwise this fixture's teardown
    restores an empty registry and poisons every later test in the session.
    """
    registry._ensure_primitives_loaded()
    saved = dict(registry._PRIMITIVE_REGISTRY)

    def _reg(pid, version):
        obj = _make(pid, version)
        registry._PRIMITIVE_REGISTRY[pid] = obj
        return obj

    yield _reg
    registry._PRIMITIVE_REGISTRY.clear()
    registry._PRIMITIVE_REGISTRY.update(saved)


def test_unversioned_resolution_reports_unversioned_not_matched(registered):
    """The labeling-up guard: an unversioned ref must NOT report a match. A
    `version_status` of "matched" claims the auditor pinned something."""
    registered("d1_x", "3")
    prim, rec = resolve_primitive_ref(parse_primitive_ref("d1_x"))
    assert rec["version_status"] == "unversioned"
    assert rec["digest_status"] == "unpinned"
    assert rec["version_requested"] is None


def test_version_match(registered):
    registered("d1_x", "3")
    _, rec = resolve_primitive_ref(parse_primitive_ref("d1_x@3"))
    assert rec["version_status"] == "matched"
    assert rec["version_requested"] == "3"
    assert rec["version_declared"] == "3"


def test_version_mismatch_refuses(registered):
    registered("d1_x", "3")
    with pytest.raises(PrimitiveRefViolation) as exc:
        resolve_primitive_ref(parse_primitive_ref("d1_x@4"))
    assert exc.value.reason_code == "PRIMITIVE_VERSION_MISMATCH"


def test_version_requested_but_undeclared_refuses(registered):
    """Fail-closed: the spec asks for v2, the code cannot say what it is. This
    must REFUSE, never pass on the theory that an undeclared version matches
    anything."""
    registered("d1_x", None)
    with pytest.raises(PrimitiveRefViolation) as exc:
        resolve_primitive_ref(parse_primitive_ref("d1_x@2"))
    assert exc.value.reason_code == "PRIMITIVE_VERSION_UNDECLARED"


def test_unknown_name_still_unknown_primitive(registered):
    """Unchanged fail-closed behaviour for an unregistered name."""
    with pytest.raises(registry.UnknownPrimitive):
        resolve_primitive_ref(parse_primitive_ref("d1_absent"))


def test_unknown_name_with_version_does_not_leak_into_lookup(registered):
    """Lookup is by NAME. `d1_absent@1` must not be looked up as the literal
    string `d1_absent@1`."""
    with pytest.raises(registry.UnknownPrimitive) as exc:
        resolve_primitive_ref(parse_primitive_ref("d1_absent@1"))
    assert "d1_absent" in str(exc.value)


# ---------------------------------------------------------------------------
# Digest pinning — bound to the code object dispatch will actually invoke
# ---------------------------------------------------------------------------


def _real_sha_of(prim):
    return registry.derive_provenance(prim)["sha256"]


def test_digest_match_uses_the_resolved_instances_source(registered):
    """The pin compares against derive_provenance's sha -- the file holding the
    code dispatch will invoke, not the class at registration."""
    registry._ensure_primitives_loaded()
    prim = registry._PRIMITIVE_REGISTRY["bom_recompute"]
    sha = _real_sha_of(prim)
    assert sha is not None
    _, rec = resolve_primitive_ref(parse_primitive_ref(f"bom_recompute#{sha}"))
    assert rec["digest_status"] == "matched"
    assert rec["digest_observed"] == sha


def test_digest_mismatch_refuses(registered):
    registry._ensure_primitives_loaded()
    with pytest.raises(PrimitiveRefViolation) as exc:
        resolve_primitive_ref(parse_primitive_ref(f"bom_recompute#{HEX64_B}"))
    assert exc.value.reason_code == "PRIMITIVE_DIGEST_MISMATCH"


def test_digest_unavailable_refuses(registered):
    """provenance origin "unknown" (no derivable source) with a pin present must
    REFUSE. Passing here would let an unhashable primitive silently satisfy a
    pin."""
    obj = registered("d1_nosrc", "1")
    obj.recompute = "not a callable with a code object"
    with pytest.raises(PrimitiveRefViolation) as exc:
        resolve_primitive_ref(parse_primitive_ref(f"d1_nosrc#{HEX64}"))
    assert exc.value.reason_code == "PRIMITIVE_DIGEST_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Non-vacuity (Stage 2) — the pin check must not pass vacuously
# ---------------------------------------------------------------------------


def test_removing_the_pin_changes_the_face(registered):
    """Mutation control: strip the pin, the face must STOP claiming pinned.
    A `digest_status` that reads "matched" regardless of whether a pin was
    supplied is a vacuous check."""
    registry._ensure_primitives_loaded()
    prim = registry._PRIMITIVE_REGISTRY["bom_recompute"]
    sha = _real_sha_of(prim)

    _, pinned = resolve_primitive_ref(parse_primitive_ref(f"bom_recompute#{sha}"))
    _, bare = resolve_primitive_ref(parse_primitive_ref("bom_recompute"))

    assert pinned["digest_status"] == "matched"
    assert bare["digest_status"] == "unpinned"
    assert pinned != bare, "the face must differ when a pin is present"


def test_removing_the_version_changes_the_face(registered):
    registered("d1_x", "3")
    _, versioned = resolve_primitive_ref(parse_primitive_ref("d1_x@3"))
    _, bare = resolve_primitive_ref(parse_primitive_ref("d1_x"))
    assert versioned["version_status"] == "matched"
    assert bare["version_status"] == "unversioned"
    assert versioned != bare


# ---------------------------------------------------------------------------
# Backward compatibility over the COMMITTED denominator (Stage 2: 88 ids / 27 primitives)
# ---------------------------------------------------------------------------


def test_every_registered_primitive_still_resolves_bare():
    """Every registered primitive keeps resolving by bare name. If this breaks,
    the "no spec file changes" property of D1 is false.

    NO COUNT FLOOR HERE. An earlier version asserted `>= 24`, a number taken
    from the INTERNAL fleet. The OSS drop ships a subset, so a fleet-calibrated
    floor is a test that fails on the customer's first pytest -- measured: this
    module's sibling failed in a real `--dest` export at 46 ids against a floor
    of 80. The universal property holds at any fleet size; the EXACT denominator
    is an internal fact and lives in the internal-only ratchet
    (tests/test_primitive_ref_denominator_ratchet.py, excluded from the drop).
    """
    registry._ensure_primitives_loaded()
    names = sorted(registry._PRIMITIVE_REGISTRY)
    assert names, "registry is empty — the property below would be vacuous"
    for name in names:
        ref = parse_primitive_ref(name)
        assert ref.version is None and ref.digest is None
        prim, rec = resolve_primitive_ref(ref)
        assert prim is registry._PRIMITIVE_REGISTRY[name]
        assert rec["version_status"] == "unversioned"


def test_every_primitive_id_in_every_shipped_spec_parses_unchanged():
    """The real fleet, not a fixture: every primitive_id string in every spec
    JSON must parse as a BARE name -- proving the migration is genuinely
    optional and no shipped spec changes meaning."""
    root = Path(__file__).resolve().parents[1]
    seen = set()
    for spec in sorted(root.glob("examples/*/**/*.json")):
        try:
            text = spec.read_text(encoding="utf-8")
        except OSError:
            continue
        if '"primitive_id"' not in text:
            continue
        import json

        def walk(o):
            if isinstance(o, dict):
                pid = o.get("primitive_id")
                if isinstance(pid, str):
                    seen.add(pid)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(json.loads(text))
    # Non-vacuity, not a fleet-calibrated floor (see the note above).
    assert seen, "no primitive_id found in any spec JSON — this test is vacuous"
    for pid in sorted(seen):
        ref = parse_primitive_ref(pid)
        assert ref.name == pid, f"{pid!r} must parse as a bare name"
        assert ref.version is None and ref.digest is None


# ---------------------------------------------------------------------------
# Liveness seam — regression for a defect this build introduced and fixed
# ---------------------------------------------------------------------------


def test_fault_injection_seam_is_preserved(monkeypatch):
    """`resolve_primitive_ref` must resolve through an INJECTABLE resolver.

    Dispatch tests fault-inject via `monkeypatch.setattr(dispatch,
    "resolve_primitive", ...)`. The first cut of D1 called
    `registry.resolve_primitive` directly, which routed around that patch and
    silently disabled the seam that proves dispatch is live -- 10 dispatch tests
    caught it. A skipped step is otherwise indistinguishable from a passing one,
    so this seam is a substrate control, not a test convenience.
    """
    sentinel = _make("d1_injected", "9")
    called = {}

    def fake_resolver(name):
        called["name"] = name
        return sentinel

    prim, rec = resolve_primitive_ref(
        parse_primitive_ref("d1_injected@9"), resolver=fake_resolver
    )
    assert prim is sentinel
    assert called["name"] == "d1_injected", "resolver must receive the parsed NAME"
    assert rec["version_status"] == "matched"


def test_injected_resolver_still_enforces_the_pin():
    """The seam must not become a bypass: an injected resolver is still subject
    to version and digest enforcement."""
    sentinel = _make("d1_injected", "9")
    with pytest.raises(PrimitiveRefViolation) as exc:
        resolve_primitive_ref(
            parse_primitive_ref("d1_injected@8"), resolver=lambda _n: sentinel
        )
    assert exc.value.reason_code == "PRIMITIVE_VERSION_MISMATCH"
