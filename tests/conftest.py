"""Root-suite conftest — tiering markers applied by filename, not by editing 170 files.

Two tiers (measured 2026-08-20 on master bcc5ed88a, 8 workers, --dist loadfile):

  core   (-m "not pilot")      3.3k tests, ~110s wall (~25s without the OSS
                                boundary gate), 255s serial. Substrate: the
                                verifier, dsse, manifest, ratchets, lints, CLI,
                                c18/c19/fuzz/discharge/effect_runtime.
  pilot  (-m pilot)            1.2k tests, ~1,340s serial, ~84% of suite time.
                                Each file builds ONE examples/<pilot>/ bundle and
                                runs the verifier on it — integration coverage
                                that is redundant across pilots for substrate
                                changes and only changes when that pilot does.

The `pilot` marker is derived from the file name so a new pilot test is tiered
automatically. Selection recipes (see README "Running Tests"):

  pytest -m "not pilot"                       # every commit
  pytest -k <pilot>                           # the pilot you touched
  pytest -m "slow or not slow"                # landing: everything (land-and-reap)

The `slow` marker (pyproject addopts excludes it by default) is orthogonal and
unchanged: the mesh pilot + the digital-thread probe battery are both slow AND pilot.

`heavy_pilot` (Max, 2026-08-20): a pilot whose suite costs more than the rest of
the run is worth — DESELECTED from every invocation, including landing, unless
`--run-heavy-pilots` is passed. It is one pilot of ~100; its substrate
contracts are covered by the other 99. Currently: the mesh pilot suite
(~220s solo, 3 subprocess builds/verifies of a 1,440-anchor bundle; was the
wall-clock floor of the landing run). Run it on demand by passing
`--run-heavy-pilots -m ""` and that suite's test file to pytest.
"""

from __future__ import annotations

import re

import pytest

# A file is a pilot-integration test when its SUBJECT is one examples/<pilot>/
# directory. Substrate tests that merely use a pilot bundle as a fixture
# (test_unsafe_pack_execution_gate, test_cli_library_verdict_divergence, the
# *_ratchet files, ...) stay in core on purpose — they assert substrate
# contracts, and they are cheap.
_PILOT_FILE_PATTERNS = (
    re.compile(r"^test_.+_(minimal|spec_pinned|premium|pilot)\.py$"),
    re.compile(r"^test_recipe_.+_promoted\.py$"),
    re.compile(r"^test_gaci_.+\.py$"),
)
# Pilot-subject files whose names do not follow the _minimal/_spec_pinned
# convention. Keep this list short; prefer naming new files conventionally.
_PILOT_FILES_EXPLICIT = frozenset(
    {
    }
)
# Substrate files that the `_premium` suffix pattern would otherwise catch.
_CORE_PREFIX_OVERRIDES = ("test_emitter_premium",)


def is_pilot_test_file(basename: str) -> bool:
    if basename.startswith(_CORE_PREFIX_OVERRIDES):
        return False
    if basename in _PILOT_FILES_EXPLICIT:
        return True
    return any(p.match(basename) for p in _PILOT_FILE_PATTERNS)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-heavy-pilots",
        action="store_true",
        default=False,
        help="also run tests marked heavy_pilot (deselected by default, even at landing)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    for item in items:
        if is_pilot_test_file(item.path.name):
            item.add_marker(pytest.mark.pilot)
    if config.getoption("--run-heavy-pilots"):
        return
    kept, heavy = [], []
    for item in items:
        (heavy if item.get_closest_marker("heavy_pilot") else kept).append(item)
    if heavy:
        config.hook.pytest_deselected(items=heavy)
        items[:] = kept
