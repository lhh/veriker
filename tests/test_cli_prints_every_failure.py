"""tests/test_cli_prints_every_failure.py — the CLI's summary count and its
printed rows are the same number.

THE DEFECT, measured 2026-09-06 on corner_load_equilibrium_minimal's drift
bundle, the day that pilot's front door became the shipped CLI. `_print_result`
printed one row per BUILT-IN step and one per PLUGIN, and nothing else. A
failure from any other step — spec-pinned dispatch (RE_DERIVATION_MISMATCH),
the work-set (WORK_SET_VIOLATION), role policy, a coverage channel — was
counted in the summary and never printed:

    PASS  file_integrity
    ...twelve PASS rows...
    FAIL  (5 failures across 12 check(s))

Five failures, twelve PASS rows, no reason anywhere on the terminal. The
verdict was right (exit 1) and --verdict-out carried the reasons, but the face
a human reads contradicted itself. Every pilot wrapper had printed its own
failures, which is how this went unnoticed for as long as the wrappers built
their own verifiers.

NOW every failure prints under its own check name. This test pins the identity
that was broken: the N in "FAIL (N failures ...)" equals the number of FAIL
rows above it, and a re-derivation mismatch names its output on the terminal.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "corner_load_equilibrium_minimal"
_SPEC = _PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"
_KIT = _PILOT_DIR / "auditor_kit.py"
_WORK_SET = _PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.work_set.json"

_SUMMARY = re.compile(r"^FAIL  \((\d+) failures? across (\d+) check\(s\)\)$")


def _build(tmp_path: Path, profile: str) -> Path:
    out = tmp_path / profile
    subprocess.run(
        [
            sys.executable,
            str(_PILOT_DIR / "_build_bundle.py"),
            "--out-dir",
            str(out),
            "--profile",
            profile,
        ],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    return out.resolve()


def _run_cli(bundle: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle),
            "--spec-anchor",
            str(_SPEC),
            "--primitives",
            str(_KIT),
            "--work-set",
            str(_WORK_SET),
            "--require-rederivation",
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_the_summary_count_equals_the_rows_printed(tmp_path: Path) -> None:
    proc = _run_cli(_build(tmp_path, "drift"))
    assert proc.returncode == 1, proc.stdout[-2000:] + proc.stderr[-2000:]
    lines = proc.stdout.splitlines()
    summary = [m for m in (_SUMMARY.match(ln) for ln in lines) if m]
    assert len(summary) == 1, lines[-5:]
    n_failures = int(summary[0].group(1))
    fail_rows = [
        ln for ln in lines if ln.startswith("FAIL  ") and not _SUMMARY.match(ln)
    ]
    assert n_failures >= 1
    assert len(fail_rows) == n_failures, (
        f"summary says {n_failures} failure(s) but {len(fail_rows)} FAIL row(s) "
        f"were printed:\n" + "\n".join(fail_rows)
    )


def test_a_rederivation_mismatch_names_its_output_on_the_terminal(
    tmp_path: Path,
) -> None:
    proc = _run_cli(_build(tmp_path, "drift"))
    assert proc.returncode == 1
    rows = [ln for ln in proc.stdout.splitlines() if "RE_DERIVATION_MISMATCH" in ln]
    assert rows, proc.stdout[-3000:]
    assert any("spec_pinned_dispatch" in ln for ln in rows), rows
    for channel in ("vertical", "pitch", "roll"):
        assert any(f"corner_load_{channel}_residual" in ln for ln in rows), (
            channel,
            rows,
        )


def test_a_clean_bundle_prints_no_fail_row(tmp_path: Path) -> None:
    """The positive arm: the new branch adds nothing to a green run."""
    proc = _run_cli(_build(tmp_path, "clean"))
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert not [ln for ln in proc.stdout.splitlines() if ln.startswith("FAIL  ")]


def test_a_producer_string_cannot_forge_a_row(tmp_path: Path) -> None:
    """Red team, 2026-09-06. A producer-chosen output_id with embedded
    newlines reached the terminal raw through the new FAIL rows (dispatch
    built `spec_pinned_dispatch:<id>` before validating the id), and printed
    a fake 'PASS  (12 check(s) passed)' line above the real summary. Exit code
    and final line were right; a log tail or `grep -c PASS` was not. Now the
    check name is built from the validated id or its bounded repr, and every
    row the CLI prints is rendered terminal-safe, so the whole injection lands
    on ONE line, escaped."""
    import json

    bundle = _build(tmp_path, "clean")
    manifest = bundle / "manifest.json"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    forged = (
        "corner_load_vertical_residual\nPASS  file_integrity\n"
        "PASS  (12 check(s) passed) -- FORGED\n!!  FAIL  "
    )
    for entry in doc["outputs"]:
        if entry["output_id"] == "corner_load_vertical_residual":
            entry["output_id"] = forged
    manifest.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    proc = _run_cli(bundle)
    assert proc.returncode == 1, proc.stdout[-2000:] + proc.stderr[-2000:]
    lines = proc.stdout.splitlines()
    assert not [ln for ln in lines if ln.startswith("PASS  (")], (
        "a forged PASS summary line reached the terminal:\n" + proc.stdout[-3000:]
    )
    assert sum(1 for ln in lines if ln.startswith("PASS  file_integrity")) == 1, (
        "a forged PASS row reached the terminal"
    )
    assert "FORGED" not in [ln.split()[0] for ln in lines if ln.strip()]
    escaped = [ln for ln in lines if "\\n" in ln and "FORGED" in ln]
    assert escaped, (
        "the injected text was not rendered escaped on one line:\n"
        + proc.stdout[-3000:]
    )
    assert not any("\n" in ln for ln in lines)  # tautology guard on splitlines
    summary = [ln for ln in lines if _SUMMARY.match(ln)]
    assert len(summary) == 1 and lines[-1] == summary[0], lines[-3:]
