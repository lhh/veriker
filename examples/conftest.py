"""Refuse to collect more than one pilot battery into a single process.

Each `examples/<pilot>/tests/` battery prepends its own pilot directory to
`sys.path` at import time, and pilot-local module names repeat across the fleet:
110 pilots ship a `_build_bundle.py`, 107 a `verify.py`, 45 a
`spec_pinned_check.py`, and fifteen further stems (`_producer_solve`,
`ed25519_authority`, `workpaper_attestation_binding`, `spec_conformance`, ...)
sit in more than one. Collected into ONE interpreter those names resolve to
whichever pilot reached `sys.modules` first.

The result is not a clean error. It is a number that looks measured: `pytest
examples/` reports 140 failures and 4 collection errors here, of which 125 and
all 4 are the collision. It also runs the other way -- a pilot's test can PASS
against another pilot's module. `fea_vonmises_minimal`'s
`test_the_two_implementations_are_not_the_same_arithmetic`, whose whole job is
ruling out producer==verifier, was reaching `witness_cert_minimal`'s producer;
it raised only because the two return different shapes.

So the combined invocation is refused here rather than left to mislead. Run one
pilot at a time, or use the runner that does it for you:

    python scripts/run_example_batteries.py
    pytest examples/<pilot>/tests

Lifting this would mean removing the batteries' reliance on a shared `sys.path`
across 69 battery files -- a real option, but a refactor, not a config change.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_EXAMPLES = Path(__file__).resolve().parent


def _pilot_of(path: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(_EXAMPLES)
    except ValueError:
        return None
    return rel.parts[0] if rel.parts else None


def _selected_pilots(config) -> set[str] | None:
    """The pilots this invocation selects, or None if it spans all of them.

    Decided from the invocation's own arguments rather than from collection
    traversal: the collision manifests as an ImportError DURING collection,
    which interrupts the session before any post-collection hook runs, and a
    traversal hook sees sibling directories that the run never actually
    collects.
    """
    pilots: set[str] = set()
    for raw in config.args:
        arg = Path(str(raw).split("::", 1)[0])
        if not arg.is_absolute():
            arg = Path(str(config.rootpath)) / arg
        try:
            arg = arg.resolve()
        except OSError:
            continue
        if arg == _EXAMPLES or arg in _EXAMPLES.parents:
            return None  # spans the whole fleet
        pilot = _pilot_of(arg)
        if pilot:
            pilots.add(pilot)
    return pilots


def pytest_configure(config):
    selected = _selected_pilots(config)
    if selected is not None and len(selected) <= 1:
        return
    named = (
        "the whole examples/ tree" if selected is None else ", ".join(sorted(selected))
    )
    raise pytest.UsageError(
        f"refusing to collect more than one pilot battery in one process ({named}). "
        "Pilot-local module names repeat across the fleet and every battery puts "
        "its own directory on sys.path, so a combined run resolves imports "
        "against whichever pilot was collected first -- silently, in both "
        "directions. Run one pilot per process:\n"
        "    python scripts/run_example_batteries.py\n"
        "    pytest examples/<pilot>/tests"
    )
