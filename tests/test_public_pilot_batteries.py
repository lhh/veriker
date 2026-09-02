"""Run the remaining PUBLIC pilots' own batteries from the collected suite.

`pyproject.toml` sets `testpaths = ["tests"]` -- in the internal tree and in the
open drop alike -- so a battery living at `examples/<pilot>/tests/` is never
collected by a plain `pytest` run. Measured 2026-08-29: 48 pilots shipped such a
battery and the default suite executed none of them.

Two runners already closed part of that: `test_public_exemplar_batteries.py` (the
ADR D7 de-branded exemplars) and `test_tautology_split_batteries.py` (the four
producer/verifier splits). This file closes the rest of the PUBLIC surface -- the
thirteen shipped pilots whose batteries no runner reached.

WHAT THIS IS AND IS NOT. Checked all thirteen READMEs on 2026-08-30: none claims
the collected suite enforces its battery, and each documents an explicit
`python -m pytest examples/<pilot>/tests/...` path that does work. So this is
MISSING COVERAGE, not a false claim -- a quality gap, not a truthfulness one.
Recorded plainly because the wider finding this descends from was framed as
"every 'the suite keeps that' README claim was about code nobody ran", and for
these thirteen that half did not reproduce.

State when adopted: all thirteen green, in-tree and inside a real `--dest`
export, 118 tests, none slower than 1.8s -- which is why they land as one batch
rather than split.

THE RESIDUAL, stated rather than filed somewhere nobody greps: 49 pilots ship a
battery in-tree, 20 of them ship in the open drop. With this file every one of
those 20 runs. The other 29 are internal-only pilots and remain uncollected;
`test_every_shipped_battery_has_a_runner` below makes that gap impossible to
grow on the public side without a red test.
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

#: Public pilots whose battery no other runner reaches. Alphabetical; the list
#: is the unit of review, so keep it boring.
PUBLIC_PILOTS = (
    "agritech_sensor_minimal",
    "citation_integrity_minimal",
    "fintech_audit_minimal",
    "iso42001_dataquality_minimal",
    "iso42001_impact_fairness_minimal",
    "iso42001_vnv_minimal",
    "lifesci_binding_minimal",
    "payroll_acting_discretion_minimal",
    "payroll_no_cliff_minimal",
    "payroll_reconciliation_minimal",
    "refinement_discharge_minimal",
    "secops_alert_minimal",
    "witness_cert_minimal",
)

_COUNT_RE = re.compile(r"(\d+) passed")


@pytest.mark.parametrize("pilot", PUBLIC_PILOTS)
def test_public_pilot_battery_is_green(pilot: str) -> None:
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
    # Deliberately a property (>0) and not the exact count measured on adoption:
    # a per-pilot denominator baked into a SHIPPED test is the kind that fails a
    # customer's first pytest for reasons that are not their problem.
    match = _COUNT_RE.search(proc.stdout)
    assert match and int(match.group(1)) > 0, (
        f"{pilot} battery reported no passing tests -- it may have collected "
        f"nothing:\n{proc.stdout[-2000:]}"
    )


def _runner_covered_pilots() -> set[str]:
    """Every pilot named by any battery runner, imported rather than restated.

    Re-declaring the sibling lists here would drift, and the completeness check
    below would then quietly pass on a pilot nobody actually runs.
    """
    covered = set(PUBLIC_PILOTS)
    from tests.test_public_exemplar_batteries import PUBLIC_EXEMPLARS
    from tests.test_tautology_split_batteries import SPLIT_PILOTS

    return covered | set(PUBLIC_EXEMPLARS) | set(SPLIT_PILOTS)


def test_every_shipped_battery_has_a_runner() -> None:
    """In the DROP, every shipped battery must be run by some runner.

    This is the anti-rot half. Adding a public pilot with a battery and
    forgetting to wire it is exactly how the original 48-pilot gap accumulated;
    here that mistake is a red test in the shipped repo rather than a silent
    hole.

    Skipped in the internal tree, where 29 internal-only pilots ship batteries
    that are deliberately not wired -- asserting totality there would either be
    a lie or force a second exemption list to rot.
    """
    if (_PKG_ROOT / "release").is_dir():
        pytest.skip(
            "internal tree: 29 internal-only pilot batteries remain uncollected "
            "by design (see this module's docstring). The totality check is a "
            "property of the open drop, where every shipped battery is wired."
        )
    shipped = {p.parent.name for p in _EXAMPLES.glob("*/tests") if p.is_dir()}
    assert shipped, "no pilot batteries found at all -- the check is vacuous"
    unwired = sorted(shipped - _runner_covered_pilots())
    assert not unwired, (
        "these pilots ship a tests/ battery that no runner executes, so their "
        f"controls are never run: {unwired}"
    )
