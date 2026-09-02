"""Atheris harness: coverage-guided byte fuzz of the D1 primitive-reference
grammar (`name[@version][#sha256hex]`).

Targets `parse_primitive_ref` -- the parse boundary that every anchored spec's
`primitive_id` now crosses at LOAD and again at dispatch.

The §C9 contract is that a fail-closed refusal path NEVER raises anything other
than its own refusal type. A TypeError out of an error formatter, an IndexError
out of a partition, or a hostile `__str__` propagating out of a detail string
turns a refusal into a crash -- and a crashed verifier is a verifier that
concluded nothing while looking like it ran. Measured precedent in this repo:
`sorted()` on mixed-type keys, `json.dumps` on a decoder object and `len()` on
an unsized object all raised out of fail-closed paths under atheris.

Oracle (intentionally narrow):
  1. parse_primitive_ref(s) either returns a PrimitiveRef or raises
     MalformedPrimitiveRef -- never anything else.
  2. An ACCEPTED ref is structurally sound: non-empty sigil-free name, a
     non-empty sigil-free version if present, and a 64-char lowercase-hex digest
     if present.
  3. Parsing is idempotent on its own `raw` (load and dispatch both parse; a
     parser whose output moves on reparse cannot be reasoned about).

We deliberately do NOT cross-check acceptance against an independent
re-implementation of the grammar -- that would either drift from the production
parser or just call it (tautological). The invariants above are properties, not
a second parser.

The hand-written complements are tests/test_primitive_ref_properties.py
(hypothesis, with a non-vacuity ledger) and tests/test_primitive_ref_mutants.py
(expected-reason probe battery).

Run a bounded session:
    .venv/bin/python tests/fuzz/atheris_primitive_ref.py \
        -max_total_time=120 \
        tests/fuzz/corpus/primitive_ref/
"""

from __future__ import annotations

import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

with atheris.instrument_imports():
    from audit_bundle.rederivation.primitive_ref import (  # noqa: F401
        SIGILS,
        MalformedPrimitiveRef,
        PrimitiveRef,
        parse_primitive_ref,
    )

_HEXLOWER = frozenset("0123456789abcdef")


def _check(raw: object) -> None:
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef:
        return  # the only permitted refusal

    # Oracle 2 — an accepted ref is structurally sound.
    assert isinstance(ref, PrimitiveRef), type(ref)
    assert ref.name, "accepted ref with an empty name"
    for sig in SIGILS:
        assert sig not in ref.name, f"sigil {sig!r} inside accepted name {ref.name!r}"
    if ref.version is not None:
        assert ref.version, "accepted ref with an empty version"
        for sig in SIGILS:
            assert sig not in ref.version, f"sigil in version {ref.version!r}"
    if ref.digest is not None:
        assert len(ref.digest) == 64, f"digest length {len(ref.digest)}"
        assert all(c in _HEXLOWER for c in ref.digest), "digest not lowercase hex"

    # Oracle 3 — idempotent on its own raw.
    assert parse_primitive_ref(ref.raw) == ref, "parse is not idempotent"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Two shapes per input: a raw decode, and a ref-SHAPED assembly. Uniform
    # random bytes are ~never ref-shaped, so without the second shape the
    # digest and version branches would almost never be reached.
    _check(fdp.ConsumeUnicodeNoSurrogates(64))

    name = fdp.ConsumeUnicodeNoSurrogates(12)
    parts = [name]
    if fdp.ConsumeBool():
        parts.append("@" + fdp.ConsumeUnicodeNoSurrogates(6))
    if fdp.ConsumeBool():
        parts.append("#" + fdp.ConsumeUnicodeNoSurrogates(70))
    _check("".join(parts))


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
