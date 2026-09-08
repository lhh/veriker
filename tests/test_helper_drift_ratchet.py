"""Ratchet on the duplicated-helper-drift defect class.

The class: a SECOND hand-rolled copy of a helper that lost the FIRST copy's
hardening. Found three times (2026-08-22 rederive/ vs l_consume, 2026-08-29
revocation._b64url_nopad_decode vs pae, 2026-09-03 hand-rolled provenance vs
S1). It recurred because the 2026-08-29 audit's detector was never committed.

Three tests. The SELF-VALIDATION one is the load-bearing half: a detector that
silently stops firing turns this ratchet into green dead code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECTOR = REPO / "tools" / "helper_drift.py"

#: `tools/` is internal-only and is not part of the OSS export, so in a
#: consumer's clone the detector is absent and these tests cannot run. Skipping
#: on absence alone would let the ratchet silently evaporate from OUR tree too,
#: so `test_the_detector_is_present_in_the_internal_tree` below fails loudly
#: whenever the internal markers are there and the detector is not.
_INTERNAL_TREE = (REPO / "release" / "oss_export.py").is_file()

#: Applied per-test, NEVER as a module-level `pytestmark`: a blanket mark also
#: skips the miss-direction guard below, which disarms the very check that is
#: supposed to notice the detector going missing.
_needs_detector = pytest.mark.skipif(
    not DETECTOR.is_file(),
    reason="tools/helper_drift.py is internal-only; not present in an OSS export",
)

# Frozen 2026-09-04. Each entry is (weaker_module, function). Adding to this
# list requires justifying why the weaker copy is correct where it sits: the
# stricter copy is NOT automatically the right one. Read the caller first --
# in a prior instance the stricter copy returned None, and both callers read
# None as "legacy bundle, clean PASS", so the stricter copy was the fail-open.
KNOWN: set[tuple[str, str]] = {
    ("audit_bundle/rederivation/primitives/anticheat_adjudication.py", "_evaluate_rule"),
    ("audit_bundle/rederivation/primitives/healthcare_diagnosis.py", "_load_rules"),
    ("audit_bundle/plugins/reference/aigov_rederivation.py", "_verify"),
    ("audit_bundle/_degradation.py", "_node_at"),
}


def _run(*targets: Path) -> list[dict]:
    out = REPO / "build" / "helper_drift.json"
    out.parent.mkdir(exist_ok=True)
    env = {**os.environ, "HELPER_DRIFT_JSON": str(out), "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run([sys.executable, str(DETECTOR), *map(str, targets)],
                   check=True, capture_output=True, env=env, cwd=REPO)
    return json.loads(out.read_text())


@_needs_detector
def test_detector_fires_on_a_known_weak_pair(tmp_path):
    """SELF-VALIDATION. A downgrade strips the docstring that explains the
    guard, so RAW source similarity collapses (the real b64url pair scores
    0.258). If this stops firing, the ratchet below is dead code, not a pass."""
    (tmp_path / "hardened.py").write_text(
        'import re\n'
        'def parse_token(s):\n'
        '    """Long docstring explaining exactly why the alphabet guard\n'
        '    exists, which a downgrade characteristically deletes."""\n'
        '    if len(s) % 4 == 1:\n'
        '        raise ValueError("bad length")\n'
        '    if re.fullmatch(r"[A-Za-z0-9_-]*", s) is None:\n'
        '        raise LookupError("outside the alphabet")\n'
        '    return s.encode()\n'
    )
    (tmp_path / "copy.py").write_text(
        'def _parse_token(s):\n'
        '    """Parse a token."""\n'
        '    if len(s) % 4 == 1:\n'
        '        raise ValueError("bad length")\n'
        '    return s.encode()\n'
    )
    hits = _run(tmp_path)
    assert hits, "detector found no downgrade in a fixture built to contain one"
    hit = hits[0]
    assert hit["softn"] == "_parse_token", hit
    assert "LookupError" in hit["hexc"] and "LookupError" not in hit["sexc"], hit


@_needs_detector
def test_no_new_helper_downgrades_in_the_substrate():
    """Ratchet: no NEW same-name copy may ship with a strictly weaker guard set."""
    hits = _run(REPO / "audit_bundle")
    found = {(str(Path(h["soft"]).relative_to(REPO)), h["softn"]) for h in hits}
    new = found - KNOWN
    assert not new, (
        "new duplicated-helper downgrade(s):\n  "
        + "\n  ".join(f"{m}::{f}" for m, f in sorted(new))
        + "\nEither bind the copy to the hardened original (a parity test, NOT "
          "de-duplication -- the isolation contract is often real), or add it "
          "to KNOWN with the reason the weaker copy is correct where it sits."
    )


@pytest.mark.skipif(not _INTERNAL_TREE, reason="only meaningful in the internal tree")
def test_the_detector_is_present_in_the_internal_tree():
    """Controls the MISS direction of the skip above.

    Without this, deleting tools/helper_drift.py would turn both ratchet tests
    into a green skip rather than a failure -- the exact shape of a guard that
    stops guarding without anyone noticing."""
    assert DETECTOR.is_file(), (
        f"{DETECTOR} is missing from an internal tree (release/oss_export.py is "
        f"present). The helper-drift ratchet is inert without it."
    )
