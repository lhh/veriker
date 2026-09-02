"""tests/test_primitive_ref_properties.py — hypothesis properties for the D1
primitive-reference grammar (`name[@version][#sha256hex]`).

Kept in its own module so a missing optional dependency skips ONLY these; the
negative controls live in test_primitive_ref_mutants.py and never skip.

The load-bearing property is §C9 NEVER-RAISE on the fail-closed path: for ANY
input whatsoever, `parse_primitive_ref` either returns a PrimitiveRef or raises
MalformedPrimitiveRef. Anything else -- a TypeError from a formatter, an
IndexError from a partition, a hostile `__str__` propagating out -- is a crash
in a refusal path, which is how a fail-closed check becomes a fail-open one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from audit_bundle.rederivation.primitive_ref import (  # noqa: E402
    SIGILS,
    MalformedPrimitiveRef,
    PrimitiveRef,
    parse_primitive_ref,
)

HEX = "0123456789abcdef"

#: NON-VACUITY LEDGER. A property test in which every generated input is
#: REJECTED passes trivially -- every body returns at the `except` and asserts
#: nothing. These counters are asserted at the end of the module so the suite
#: fails if the strategies ever drift into generating only-invalid (or
#: only-valid) inputs. This is the "name what would make the probe vacuous and
#: check that too" rule applied to the probe itself.
_SEEN = {"accepted": 0, "rejected": 0, "versioned": 0, "pinned": 0}

# Straddle the grammar boundary on purpose: uniform random text is ~never
# ref-shaped and would test one refusal branch every time.
_names = st.text(st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=12)
_versions = st.text(st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=6)
_hexes = st.text(alphabet=HEX, min_size=60, max_size=68)


@st.composite
def _refs(draw):
    """Assembled ref-shaped strings — most valid, some subtly not."""
    name = draw(_names)
    out = name
    if draw(st.booleans()):
        out += "@" + draw(_versions)
    if draw(st.booleans()):
        out += "#" + draw(_hexes)
    return out


@settings(max_examples=500, deadline=None)
@given(st.one_of(_refs(), st.text(max_size=40), st.binary(max_size=20), st.none()))
def test_parse_never_raises_anything_but_malformed(raw):
    """§C9: the refusal path must never crash. Any input -> PrimitiveRef or
    MalformedPrimitiveRef, nothing else."""
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef:
        _SEEN["rejected"] += 1
        return
    _SEEN["accepted"] += 1
    if ref.version is not None:
        _SEEN["versioned"] += 1
    if ref.digest is not None:
        _SEEN["pinned"] += 1
    assert isinstance(ref, PrimitiveRef)


@settings(max_examples=500, deadline=None)
@given(st.one_of(_refs(), st.text(max_size=40)))
def test_accepted_refs_have_a_clean_name(raw):
    """An accepted ref's NAME never contains a sigil. If it could, a name would
    be able to impersonate a versioned/pinned ref (or vice versa) and the
    registry namespace would no longer be flat."""
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef:
        return
    assert ref.name
    for sig in SIGILS:
        assert sig not in ref.name
    if ref.version is not None:
        assert ref.version
        for sig in SIGILS:
            assert sig not in ref.version
    if ref.digest is not None:
        assert len(ref.digest) == 64
        assert all(c in HEX for c in ref.digest)


@settings(max_examples=400, deadline=None)
@given(st.one_of(_refs(), st.text(max_size=40)))
def test_parse_is_idempotent_on_its_own_raw(raw):
    """Re-parsing an accepted ref's raw text yields an equal ref. A parser whose
    output changes on reparse cannot be reasoned about at two call sites (load
    and dispatch both parse)."""
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef:
        return
    assert parse_primitive_ref(ref.raw) == ref


@settings(max_examples=400, deadline=None)
@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1, max_size=20))
def test_every_sigil_free_name_parses_bare(name):
    """The backward-compatibility property, stated as a law rather than a
    fixture: any id drawn from the fleet's measured charset [a-z0-9_] parses as
    a BARE name -- unversioned, unpinned, meaning unchanged."""
    ref = parse_primitive_ref(name)
    assert ref == PrimitiveRef(name=name, version=None, digest=None)


@settings(max_examples=300, deadline=None)
@given(_names, _versions)
def test_a_version_can_never_smuggle_a_second_sigil(name, version):
    """Reordering / doubling the sigils must refuse, never silently re-associate
    (`a#sha@1` must not parse as name=a, version=1)."""
    raw = f"{name}@{version}"
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef:
        return
    # If it parsed, the split is exactly at the FIRST '@' and nothing moved.
    assert raw == f"{ref.name}@{ref.version}"


def test_the_property_run_was_not_vacuous():
    """The guard on the guards. If the strategies ever stop producing ACCEPTED
    refs -- including versioned and pinned ones -- every property above passes
    by returning early at its `except`, and the module measures nothing.

    SELF-CONTAINED BY CONSTRUCTION. An earlier version read a module-global
    counter accumulated by the tests above, which made it order-dependent: under
    `-k` selection or xdist distribution a worker receiving only this test reads
    zeros and the non-vacuity claim silently becomes a flake -- in a repo whose
    standing tripwire is exactly order-dependent full-suite failures under `-n`.
    This version draws its own sample.
    """
    seen = {"accepted": 0, "rejected": 0, "versioned": 0, "pinned": 0}
    sha = "a" * 64
    corpus = [
        "bom_recompute", "bom_recompute@1", f"bom_recompute#{sha}",
        f"bom_recompute@1#{sha}", "bom_recompute@", "bom_recompute#",
        "bom recompute", "", "@1", "x@1@2", f"x#{sha}@1",
    ]
    for raw in corpus:
        try:
            ref = parse_primitive_ref(raw)
        except MalformedPrimitiveRef:
            seen["rejected"] += 1
            continue
        seen["accepted"] += 1
        if ref.version is not None:
            seen["versioned"] += 1
        if ref.digest is not None:
            seen["pinned"] += 1
    for k, v in seen.items():
        assert v > 0, f"the vacuity corpus never produced a {k!r} outcome: {seen}"

    # And the accumulated ledger from the property run, WHEN it ran in this
    # process (informational: zero is legitimate under -k / xdist).
    if any(_SEEN.values()):
        assert _SEEN["accepted"] > 0, f"property run accepted nothing: {_SEEN}"
        assert _SEEN["rejected"] > 0, f"property run rejected nothing: {_SEEN}"
