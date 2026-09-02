"""tests/test_public_exemplar_batteries.py — run the public exemplars' own
batteries from the collected suite.

WHY THIS FILE EXISTS. `pyproject.toml` sets `testpaths = ["tests"]`, so a
battery living at `examples/<pilot>/tests/` is NEVER collected by a default
`pytest` run — internally or in the open drop, whose public pyproject carries
the same setting. Those batteries are where a pilot's evidence lives: its mutant
control, its tolerance bracket, its producer/verifier disjointness check. A
README sentence like "the suite keeps that negative result" is a claim about
code, and until this file the code was not run.

The gap is fleet-wide, not local: measured 2026-08-29, 48 pilot directories ship
an `examples/*/tests/` package and the default suite executed none of them. This
file deliberately does NOT try to close all 48 — adopting batteries of unknown
state and unknown runtime wholesale is its own change, with its own audit. It
closes the gap for the ADR D7 public exemplars, which exist precisely so that a
primitive shipping in the open verifier has a public bundle exercising it. A
public exemplar whose controls are never executed would be the same defect one
level up.

The named residual: every other pilot battery in `examples/` remains
uncollected. That is a real, open hole and is recorded here rather than in a
tracker nobody greps.

Mechanism: a subprocess `pytest` per exemplar, because the batteries are
separate `tests` packages that cannot share the root suite's namespace (see the
`--import-mode=importlib` note in pyproject).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _PKG_ROOT / "examples"

#: The ADR D7 de-branded public exemplars. Each exists because a primitive ships
#: in the open verifier with no public pilot binding it.
PUBLIC_EXEMPLARS = (
    "event_log_replay_minimal",
    "fea_vonmises_minimal",
    "span_claim_minimal",
)

_COUNT_RE = re.compile(r"(\d+) passed")


@pytest.mark.parametrize("pilot", PUBLIC_EXEMPLARS)
def test_public_exemplar_battery_is_green(pilot):
    battery = _EXAMPLES / pilot / "tests"
    assert battery.is_dir(), f"{pilot} ships no tests/ battery"

    env = dict(os.environ)
    # Mid-run .pyc written into a bundle that ships .py makes sibling parity
    # tests fail order-dependently; keep the subprocess from writing any.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(battery), "-q", "-p", "no:cacheprovider"],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
        env=env,
    )
    assert proc.returncode == 0, (
        f"{pilot} battery is RED:\n{proc.stdout[-4000:]}\n{proc.stderr[-2000:]}"
    )

    # A battery that collected nothing exits 0 under some configurations, which
    # would make this whole file a green no-op. Require that it actually ran.
    match = _COUNT_RE.search(proc.stdout)
    assert match and int(match.group(1)) > 0, (
        f"{pilot} battery reported no passing tests — it may have collected "
        f"nothing:\n{proc.stdout[-2000:]}"
    )
