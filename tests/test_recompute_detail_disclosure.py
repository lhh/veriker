"""tests/test_recompute_detail_disclosure.py — a PASSING primitive's detail
reaches the verdict face.

THE GAP, measured 2026-09-06 converting corner_load_equilibrium_minimal's front
door to the shipped CLI. `RecomputedValue.detail` reached exactly one place: the
RE_DERIVATION_MISMATCH failure message. A primitive that PASSED said nothing on
the face, so the one statement a green run most needs — how much of the input
the rule actually judged ("94 of 120 samples", the rest below the transfer
floor) — was visible only because that pilot's wrapper recomputed and printed
it by hand, and was invisible through `veriker/cli/verify.py` entirely. A coverage
number nobody sees is not a disclosure.

NOW. Dispatch hands each passing output's non-empty detail out through
`recompute_details_out`; the verifier discloses it as
`recompute_detail: <output_id!r>: <detail>` on `completeness.disclosures`; the
CLI prints the rows beside `acceptance` and `type_selection`. Disclosure, never
a gate: the text is the auditor's primitive's own, but it quotes producer data,
so it is reported and not trusted, and no verdict moves on it.

Controls: (a) empty detail = no row (a primitive that says nothing gets no
row minted for it); (b) rows are minted for PASSING outputs only — a
mismatching output's detail stays in its failure message and does not also
appear as a row that could read as a clean statement.

Driven on corner_load_equilibrium_minimal because it is the pilot whose
primitives carry a coverage statement; the mechanism under test is
distribution code (dispatch / verifier / CLI), not the pilot's.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "corner_load_equilibrium_minimal"
for _p in (str(_PKG_ROOT), str(_PILOT_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import auditor_entry as _entry  # noqa: E402  (corner_load's library constructor)
from audit_bundle.plugin import RecomputedValue  # noqa: E402
from audit_bundle.rederivation.registry import resolve_primitive  # noqa: E402

_PREFIX = "recompute_detail: "
_SPLIT_ID = "corner_load_transfer_split_residual"
_SPLIT_PRIMITIVE = "corner_load_transfer_split_recompute"


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


def _rows(result) -> dict[str, str]:
    """output_id -> detail, parsed from the disclosure rows."""
    rows: dict[str, str] = {}
    for d in result.completeness.disclosures:
        if not d.startswith(_PREFIX):
            continue
        body = d[len(_PREFIX) :]
        oid_repr, _, detail = body.partition(": ")
        rows[oid_repr] = detail
    return rows


def test_every_passing_output_discloses_its_primitives_detail(tmp_path: Path) -> None:
    clean = _build(tmp_path, "clean")
    verifier, _ = _entry.build_verifier(clean)
    result = verifier.verify(clean)
    assert result.ok, [f.detail for f in result.failures]
    rows = _rows(result)
    assert set(rows) == {
        repr("corner_load_vertical_residual"),
        repr("corner_load_pitch_residual"),
        repr("corner_load_roll_residual"),
        repr(_SPLIT_ID),
    }, rows
    assert "gated sample(s) of 120" in rows[repr(_SPLIT_ID)]


def test_empty_detail_mints_no_row_and_moves_no_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control (a). Silence the split primitive's detail only: its row goes
    away, the other three stay, and the verdict is unchanged — the row is a
    disclosure of what the primitive said, not a check."""
    clean = _build(tmp_path, "clean")
    verifier, _ = _entry.build_verifier(clean)  # loads the kit → registers
    primitive = resolve_primitive(_SPLIT_PRIMITIVE)
    original = primitive.recompute

    def _silent(inputs, pack_section):
        got = original(inputs, pack_section)
        return RecomputedValue(value=got.value, detail="")

    monkeypatch.setattr(primitive, "recompute", _silent)
    result = verifier.verify(clean)
    assert result.ok, [f.detail for f in result.failures]
    rows = _rows(result)
    assert repr(_SPLIT_ID) not in rows, rows
    assert len(rows) == 3, rows


def test_rows_are_minted_for_passing_outputs_only(tmp_path: Path) -> None:
    """Control (b). On the drift bundle the residual channels MISMATCH; their
    detail lives in the failure message and must not also appear as a row."""
    drift = _build(tmp_path, "drift")
    verifier, _ = _entry.build_verifier(drift)
    result = verifier.verify(drift)
    assert not result.ok
    mismatched = {
        f.detail.split("output ", 1)[1].split(" ", 1)[0].rstrip(",")
        for f in result.failures
        if f.reason_code == "RE_DERIVATION_MISMATCH"
    }
    assert mismatched, [f.reason_code for f in result.failures]
    rows = _rows(result)
    assert not (set(rows) & mismatched), (
        f"a mismatching output also got a recompute_detail row: {set(rows) & mismatched}"
    )


def test_the_cli_prints_the_rows(tmp_path: Path) -> None:
    """The shipped CLI renders the rows on the terminal and carries them in
    --verdict-out, so a relying party sees them without a wrapper."""
    clean = _build(tmp_path, "clean")
    face_path = tmp_path / "face.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(clean),
            "--spec-anchor",
            str(_entry.SPEC_PATH),
            "--primitives",
            str(_entry.KIT_PATH),
            "--work-set",
            str(_entry.WORK_SET_PATH),
            "--require-rederivation",
            "--verdict-out",
            str(face_path),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    printed = [ln for ln in proc.stdout.splitlines() if "recompute_detail" in ln]
    assert len(printed) == 4, proc.stdout
    face = json.loads(face_path.read_text(encoding="utf-8"))
    disclosed = [
        d
        for d in face["verdict"]["completeness"]["disclosures"]
        if d.startswith(_PREFIX)
    ]
    assert len(disclosed) == 4, disclosed
