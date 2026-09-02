"""Run the batteries of the four pilots whose producer/verifier split landed
2026-08-29, FROM THE COLLECTED SUITE.

`pyproject.toml` sets `testpaths = ["tests"]`, so nothing under
`examples/*/tests/` is collected by a plain `pytest` run. Four pilots gained a
mutant control proving their verifier no longer re-derives with the producer's
own function -- and every one of those controls would have sat in a directory
the suite never visits. A ratchet nobody runs is not a ratchet, which is the
same defect as a README promising a battery that is never collected.

So: run them here as subprocesses, and fail if any battery fails.

Kept deliberately separate from any public-exemplar battery runner so the two
can land independently without colliding on one file.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _PKG_ROOT / "examples"

# The pilots whose recompute path was split from the producer helper.
SPLIT_PILOTS = (
    "caselaw_citation_gate",
    "caselaw_citation_gate_minimal",
    "iso42001_event_log_minimal",
    "iso42001_external_reporting_minimal",
)

# The mutant control each battery must carry. Named explicitly so deleting the
# control is a failure here, not a silent loss of the only thing pinning the
# split.
REQUIRED_CONTROL = {
    "caselaw_citation_gate": "test_verifier_path_is_independent_of_the_producer_helper",
    "caselaw_citation_gate_minimal": "test_verifier_path_is_independent_of_the_producer_helper",
    "iso42001_event_log_minimal": "test_verifier_chain_fold_is_independent_of_the_producer_helper",
    "iso42001_external_reporting_minimal": "test_count_leg_is_independent_of_the_producer_helper",
}


@pytest.mark.parametrize("pilot", SPLIT_PILOTS)
def test_split_pilot_battery_is_green(pilot: str) -> None:
    battery = _EXAMPLES / pilot / "tests"
    assert battery.is_dir(), f"{pilot} has no tests/ directory"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(battery), "-q"],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 0, (
        f"{pilot} battery failed:\n{proc.stdout[-4000:]}\n{proc.stderr[-2000:]}"
    )


@pytest.mark.parametrize("pilot", SPLIT_PILOTS)
def test_split_pilot_still_carries_its_mutant_control(pilot: str) -> None:
    """The battery being green is not enough: the control must still exist.

    Without this, deleting the mutant control leaves a green battery and the
    producer/verifier split silently unpinned.
    """
    wanted = REQUIRED_CONTROL[pilot]
    battery = _EXAMPLES / pilot / "tests"
    found = any(wanted in f.read_text(encoding="utf-8") for f in battery.glob("test_*.py"))
    assert found, f"{pilot} lost its mutant control {wanted!r}"
