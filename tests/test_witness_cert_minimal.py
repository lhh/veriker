"""tests/test_witness_cert_minimal.py — the re-derivation-surface pin for
examples/witness_cert_minimal.

WHY THIS FILE EXISTS AT THE ROOT. The pilot ships a full battery at
examples/witness_cert_minimal/tests/, and `pyproject` sets
testpaths = ["tests"], so nothing there is collected by a plain pytest run.
scripts/run_example_batteries.py discovers it (it globs examples/*/tests), but
no test and no CI step invokes that script, so the battery runs only when
somebody runs it by hand. These two tests are the ones that must not depend on
that, so they live where the suite already looks.

WHAT THEY PIN. witness_cert_minimal is the PUBLIC example for the three
`fea_witness_certificate` primitives, and its whole argument is that the
verifier never solves -- it checks a certificate over the producer's committed
witness. Until 2026-08-31 its verifier set no `require_rederivation`, so a
bundle carrying no re-derivation at all verified CLEAN: measured at exit 0
PASS with `manifest.outputs` emptied, the three `outputs/*.json` deleted and
their `manifest.files` entries removed. What remained was byte-integrity over
files the producer itself chose -- exactly the posture this pilot exists to
argue is not enough.

The §4a.4 coverage invariant already caught the cheap version of that
(delete the declaration, leave the files -> COVERAGE_MISMATCH). It counts
files present at `outputs/*.json`, a path the PRODUCER controls, so deleting
them too left it nothing to count. That is the gap `require_rederivation=True`
closes and these tests hold.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "witness_cert_minimal"


def _build(out_dir: Path, solver: str = "cg") -> Path:
    subprocess.run(
        [
            sys.executable,
            str(_PILOT_DIR / "_build_bundle.py"),
            "--out-dir",
            str(out_dir),
            "--solver",
            solver,
        ],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    return out_dir


def _verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PILOT_DIR / "verify.py"), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _strip_every_rederivation(bundle: Path) -> Path:
    """Remove the declaration, the claimed-value files, and their manifest
    entries -- so the §4a.4 coverage invariant has nothing present to count and
    `require_rederivation` is the only thing left standing between this bundle
    and a green verdict."""
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["outputs"] = []
    manifest["files"] = {
        k: v for k, v in manifest["files"].items() if not k.startswith("outputs/")
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    for stale in (bundle / "outputs").glob("*"):
        stale.unlink()
    return bundle


def test_a_bundle_that_rederives_nothing_is_could_not_conclude(tmp_path) -> None:
    bundle = _strip_every_rederivation(_build(tmp_path / "stripped"))
    result = _verify(bundle)
    assert result.returncode == 2, (
        "a bundle carrying no re-derivation at all verified as "
        f"exit {result.returncode}; byte-integrity over producer-chosen files "
        "is not what this pilot certifies"
    )
    combined = result.stdout + result.stderr
    assert "could not conclude" in combined.lower()
    assert "VERIFIER_INCOMPLETE" in combined


@pytest.mark.parametrize("solver", ["cg", "dense"])
def test_the_flag_does_not_break_either_solver(tmp_path, solver: str) -> None:
    """CONTROL. The pilot's headline is that two unrelated solvers produce
    different witnesses and pass the SAME certificate. A strictness flag that
    quietly cost the demonstration would be a worse defect than the one it
    closes, so both arms are held green here and not only in the uncollected
    battery."""
    result = _verify(_build(tmp_path / f"clean_{solver}", solver))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
