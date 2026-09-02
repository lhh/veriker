"""tests/test_cli_work_set.py — the shipped CLI can hold an auditor work-set.

Before `--work-set` existed the shipped CLI could anchor a bundle
(`--spec-anchor`) and load the auditor's primitives (`--primitives`) but had
no way to say WHICH outputs must arrive and WHICH rule judges each — the
`BundleVerifier(work_set=...)` argument was reachable from a pilot's own
verify.py and from the library, never from `python -m veriker.cli.verify`. Measured
2026-09-01 on climate_emission_minimal: an EXTRA output under a valid anchored
type, carrying the true value, verified at exit 0 through the CLI while the
same bundle through the pilot's wrapper (which holds a set) was refused. The
public entry point verified the extra-output hole at exit 0.

The work-set file is the OPERATOR's declaration, held the way the anchor and
the kit are held:

    {"pins": {"<output_id>": "<type_key>", ...},
     "withheld": {"<output_id>": "<WITHHELD_REASON>"},   # optional
     "source": "<free text for the face>"}               # optional

It is always declared SELF_AUTHORED: the CLI reads bytes, it cannot verify a
claim that the enumeration was derived from some anchored artifact, so it does
not accept one (the closed-universe rule that a provenance class is never
labelled up). The file's own sha256 goes on the face's `cli_gates` row.

Every verdict here is read from `--verdict-out`, never from stdout, except the
one cell whose subject IS what stdout prints.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_CLIMATE_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"
_CLIMATE_SPECS = (
    _CLIMATE_DIR / "spec_pinned" / "climate.spec.json",
    _CLIMATE_DIR / "spec_pinned" / "climate_emission.spec.json",
)
_CLIMATE_KIT = _CLIMATE_DIR / "auditor_kit.py"
_CLIMATE_PINS = {
    "climate_total_scope3": "climate_total_scope3",
    "climate_attribution_by_vendor": "climate_attribution",
}

PASS, FAIL, COULD_NOT_CONCLUDE = 0, 1, 2
_ARG_CODE = "WORK_SET_ARG_INVALID"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def climate_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("cli_ws_climate") / "bundle"
    subprocess.run(
        [sys.executable, str(_CLIMATE_DIR / "_build_bundle.py"), "--out-dir", str(out)],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    return out


def _write_work_set(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path


def _run_cli(bundle_dir: Path, verdict_out: Path, *extra: str):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle_dir),
            "--verdict-out",
            str(verdict_out),
            *extra,
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert verdict_out.exists(), (
        f"--verdict-out was not written (exit {proc.returncode})\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    return proc, json.loads(verdict_out.read_text(encoding="utf-8"))


def _anchored(bundle: Path, out: Path, work_set: Path | None, *extra: str):
    args = [
        "--spec-anchor",
        *map(str, _CLIMATE_SPECS),
        "--primitives",
        str(_CLIMATE_KIT),
        *extra,
    ]
    if work_set is not None:
        args += ["--work-set", str(work_set)]
    return _run_cli(bundle, out, *args)


def _reasons(face: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def walk(v):
        for r in v.get("reasons") or ():
            out.append((r.get("check_name"), r.get("code")))
        for leg in v.get("legs") or ():
            walk(leg)

    if face.get("verdict"):
        walk(face["verdict"])
    return out


def _gate(face: dict, name: str) -> dict | None:
    return next((g for g in face.get("cli_gates") or () if g.get("gate") == name), None)


def _disclosures(face: dict) -> list[str]:
    v = face.get("verdict") or {}
    c = v.get("completeness") or {}
    return list(c.get("disclosures") or ())


def _manifest(bundle: Path) -> dict:
    return json.loads((bundle / "manifest.json").read_bytes())


def _write_manifest(bundle: Path, manifest: dict) -> None:
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True)
    )


def _copy(clean: Path, tmp_path: Path, name: str) -> Path:
    bundle = tmp_path / name
    shutil.copytree(clean, bundle)
    return bundle


def _plant_total_decoy(bundle: Path) -> None:
    """An extra output under the scalar-total type carrying the TRUE total —
    it re-derives cleanly, so only a held work-set can refuse it."""
    honest = bundle / "outputs" / "climate_total_scope3.json"
    decoy = bundle / "outputs" / "climate_total_scope3_again.json"
    decoy.write_bytes(honest.read_bytes())
    manifest = _manifest(bundle)
    manifest["files"]["outputs/climate_total_scope3_again.json"] = hashlib.sha256(
        decoy.read_bytes()
    ).hexdigest()
    manifest["outputs"].append(
        {
            "conforms_to": "spec/climate.spec.json",
            "output_id": "climate_total_scope3_again",
            "type": "climate_total_scope3",
        }
    )
    _write_manifest(bundle, manifest)


# ---------------------------------------------------------------------------
# 1. Capability: the honest bundle, the face, and the terminal
# ---------------------------------------------------------------------------


def test_honest_bundle_passes_with_a_work_set_and_the_face_records_it(
    climate_bundle: Path, tmp_path
) -> None:
    ws = _write_work_set(tmp_path / "ws.json", {"pins": _CLIMATE_PINS})
    proc, face = _anchored(climate_bundle, tmp_path / "v.json", ws)
    assert proc.returncode == PASS, (proc.stdout, proc.stderr)

    gate = _gate(face, "work_set")
    assert gate is not None, face.get("cli_gates")
    assert gate["status"] == "APPLIED"
    assert gate["sha256"] == hashlib.sha256(ws.read_bytes()).hexdigest()
    assert gate["provenance"] == "SELF_AUTHORED"
    assert gate["n_expected"] == 2 and gate["n_withheld"] == 0
    assert isinstance(gate["universe_sha"], str) and len(gate["universe_sha"]) == 64

    rows = [d for d in _disclosures(face) if d.startswith("type_selection:")]
    assert len(rows) == 1 and "WORK-SET APPLIED" in rows[0], rows
    assert gate["universe_sha"] in rows[0]


def test_the_terminal_prints_the_type_selection_row(
    climate_bundle: Path, tmp_path
) -> None:
    """The JSON is not what the human reads. A green run is exactly when the
    reader needs to see that a set was applied, and by which authority."""
    ws = _write_work_set(tmp_path / "ws.json", {"pins": _CLIMATE_PINS})
    proc, _ = _anchored(climate_bundle, tmp_path / "v.json", ws)
    assert proc.returncode == PASS
    assert "type_selection" in proc.stdout and "WORK-SET APPLIED" in proc.stdout, (
        proc.stdout
    )


def test_without_the_flag_the_face_says_selection_was_the_producers(
    climate_bundle: Path, tmp_path
) -> None:
    """The unconfigured case is a DISCLOSURE, never a refusal — and the
    terminal must say so too, or an anchored run with no set prints the same
    wall of PASS as one with a set."""
    proc, face = _anchored(climate_bundle, tmp_path / "v.json", None)
    assert proc.returncode == PASS, (proc.stdout, proc.stderr)
    assert _gate(face, "work_set") is None
    rows = [d for d in _disclosures(face) if d.startswith("type_selection:")]
    assert len(rows) == 1 and "NO auditor work-set" in rows[0], rows
    assert "NO auditor work-set" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# 2. The hole, and the flag closing it
# ---------------------------------------------------------------------------


def test_an_extra_output_is_exit_0_without_a_set_and_a_reject_with_one(
    climate_bundle: Path, tmp_path
) -> None:
    bundle = _copy(climate_bundle, tmp_path, "decoy")
    _plant_total_decoy(bundle)

    # The measured hole — pinned so the flag's value stays falsifiable. If the
    # fallback ever closes this generically, delete the first half and the
    # unconfigured paragraph in _step_anchored_type_coverage_guard together.
    proc, face = _anchored(bundle, tmp_path / "no_set.json", None)
    assert proc.returncode == PASS, (proc.stdout, proc.stderr)
    assert "WORK_SET_VIOLATION" not in face["reason_codes"]

    ws = _write_work_set(tmp_path / "ws.json", {"pins": _CLIMATE_PINS})
    proc, face = _anchored(bundle, tmp_path / "with_set.json", ws)
    assert proc.returncode == FAIL, (proc.returncode, proc.stdout, proc.stderr)
    assert ("spec_pinned_dispatch:work_set", "WORK_SET_VIOLATION") in _reasons(face)
    assert face["verdict"]["state"] == "REJECT"


def test_a_withheld_output_is_excused_but_delivering_it_is_refused(
    climate_bundle: Path, tmp_path
) -> None:
    ws = _write_work_set(
        tmp_path / "ws.json",
        {
            "pins": {
                **_CLIMATE_PINS,
                "climate_total_scope3_again": "climate_total_scope3",
            },
            "withheld": {"climate_total_scope3_again": "WITHHELD_BY_AUDITOR"},
        },
    )
    proc, face = _anchored(climate_bundle, tmp_path / "absent.json", ws)
    assert proc.returncode == PASS, (proc.stdout, proc.stderr)
    assert _gate(face, "work_set")["n_withheld"] == 1

    bundle = _copy(climate_bundle, tmp_path, "arrives_anyway")
    _plant_total_decoy(bundle)
    proc, face = _anchored(bundle, tmp_path / "present.json", ws)
    assert proc.returncode == FAIL, (proc.stdout, proc.stderr)
    assert ("spec_pinned_dispatch:work_set", "WORK_SET_VIOLATION") in _reasons(face)


# ---------------------------------------------------------------------------
# 3. Operator errors — exit 2, never a claim about the bundle
# ---------------------------------------------------------------------------


def _assert_arg_error(proc, face, *, detail_fragment: str | None = None) -> None:
    assert proc.returncode == COULD_NOT_CONCLUDE, (
        proc.returncode,
        proc.stdout,
        proc.stderr,
    )
    assert _ARG_CODE in face["reason_codes"], face["reason_codes"]
    gate = _gate(face, "work_set_arg")
    assert gate is not None and gate["status"] == "ERROR"
    assert gate["reason_code"] == _ARG_CODE
    assert face.get("verdict") is None, "no verdict about the bundle may exist"
    assert _ARG_CODE in proc.stderr
    if detail_fragment is not None:
        assert detail_fragment in proc.stderr, proc.stderr


def test_a_work_set_inside_the_bundle_is_refused(
    climate_bundle: Path, tmp_path
) -> None:
    """The set is the auditor's authority over the producer; read out of the
    bundle it is authored by the party it constrains. Same rule, same
    outcome, as --spec-anchor and --primitives."""
    bundle = _copy(climate_bundle, tmp_path, "self_set")
    inside = _write_work_set(bundle / "ws.json", {"pins": _CLIMATE_PINS})
    manifest = _manifest(bundle)
    manifest["files"]["ws.json"] = hashlib.sha256(inside.read_bytes()).hexdigest()
    _write_manifest(bundle, manifest)

    proc, face = _anchored(bundle, tmp_path / "v.json", inside)
    _assert_arg_error(proc, face, detail_fragment="INSIDE")


def test_a_symlinked_work_set_that_resolves_inside_the_bundle_is_refused(
    climate_bundle: Path, tmp_path
) -> None:
    bundle = _copy(climate_bundle, tmp_path, "linked_set")
    inside = _write_work_set(bundle / "ws.json", {"pins": _CLIMATE_PINS})
    manifest = _manifest(bundle)
    manifest["files"]["ws.json"] = hashlib.sha256(inside.read_bytes()).hexdigest()
    _write_manifest(bundle, manifest)
    link = tmp_path / "outside_looking.json"
    link.symlink_to(inside)

    proc, face = _anchored(bundle, tmp_path / "v.json", link)
    _assert_arg_error(proc, face, detail_fragment="INSIDE")


@pytest.mark.parametrize(
    "doc, fragment",
    [
        ({"pins": {}}, "empty"),
        ({"pins": ["climate_total_scope3"]}, "pins"),
        ({"pins": {"climate_total_scope3": 7}}, "pins"),
        (
            {"pins": _CLIMATE_PINS, "withheld": {"nobody": "WITHHELD_BY_AUDITOR"}},
            "nobody",
        ),
        (
            {"pins": _CLIMATE_PINS, "withheld": {"climate_total_scope3": "BECAUSE"}},
            "BECAUSE",
        ),
        ({"pins": _CLIMATE_PINS, "provenance": "EXTERNAL_STRUCTURE"}, "provenance"),
        ({"pins": _CLIMATE_PINS, "witheld": {}}, "witheld"),
        ({"pin": _CLIMATE_PINS}, "pins"),
        ([], "object"),
    ],
)
def test_a_malformed_work_set_document_is_refused(
    climate_bundle: Path, tmp_path, doc, fragment
) -> None:
    """Closed schema: an unknown key is refused rather than ignored, because a
    misspelled `withheld` silently ignored would turn an excused absence into
    a required delivery — or the reverse — with nothing on the face. A
    `provenance` key is refused specifically: the CLI cannot verify a
    derivation claim, so the document may not make one."""
    ws = _write_work_set(tmp_path / "ws.json", doc)
    proc, face = _anchored(climate_bundle, tmp_path / "v.json", ws)
    _assert_arg_error(proc, face, detail_fragment=fragment)


def test_an_unreadable_or_non_json_work_set_is_refused(
    climate_bundle: Path, tmp_path
) -> None:
    missing = tmp_path / "nope.json"
    proc, face = _anchored(climate_bundle, tmp_path / "v1.json", missing)
    _assert_arg_error(proc, face)

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    proc, face = _anchored(climate_bundle, tmp_path / "v2.json", bad)
    _assert_arg_error(proc, face)

    dup = tmp_path / "dup.json"
    dup.write_text(
        '{"pins": {"climate_total_scope3": "climate_total_scope3", '
        '"climate_total_scope3": "climate_attribution"}}',
        encoding="utf-8",
    )
    proc, face = _anchored(climate_bundle, tmp_path / "v3.json", dup)
    _assert_arg_error(proc, face)


def test_work_set_without_an_anchor_is_refused(climate_bundle: Path, tmp_path) -> None:
    """Dispatch does not engage without the auditor's anchor, so a set passed
    alone could never be applied — and a work_set row on the face of such a
    run would say it was held for nothing. Refused, like the
    --spec-anchor/--unsafe-run-bundle-pack pair; not warned."""
    ws = _write_work_set(tmp_path / "ws.json", {"pins": _CLIMATE_PINS})
    proc, face = _run_cli(climate_bundle, tmp_path / "v.json", "--work-set", str(ws))
    _assert_arg_error(proc, face, detail_fragment="--spec-anchor")


def test_the_gate_row_status_is_read_off_the_verdict(
    climate_bundle: Path, tmp_path
) -> None:
    """The loader writes HELD; APPLIED is earned from the core's own
    `type_selection:` row after verify() ran. The two faces cannot disagree
    because one is derived from the other."""
    ws = _write_work_set(tmp_path / "ws.json", {"pins": _CLIMATE_PINS})
    proc, face = _anchored(climate_bundle, tmp_path / "v.json", ws)
    assert proc.returncode == PASS
    row = next(d for d in _disclosures(face) if d.startswith("type_selection:"))
    assert "WORK-SET APPLIED" in row
    assert _gate(face, "work_set")["status"] == "APPLIED"

    # A refused document never reaches HELD, let alone APPLIED.
    bad = _write_work_set(tmp_path / "bad.json", {"pins": {}})
    proc, face = _anchored(climate_bundle, tmp_path / "v2.json", bad)
    assert _gate(face, "work_set") is None and _gate(face, "work_set_arg") is not None


def test_a_directory_or_fifo_or_oversized_work_set_is_refused_without_reading(
    climate_bundle: Path, tmp_path
) -> None:
    """The package's own rule: a FIFO with no writer BLOCKS a plain read
    forever (a hang before any verdict), and a size cap enforced after
    read_bytes() has already materialised the file caps nothing. The loader
    opens no-follow/non-blocking, fstat-checks the fd, and bounds the size
    before it reads a byte."""
    d = tmp_path / "a_dir"
    d.mkdir()
    proc, face = _anchored(climate_bundle, tmp_path / "v1.json", d)
    _assert_arg_error(proc, face)

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "ws.fifo"
        os.mkfifo(fifo)
        proc, face = _anchored(climate_bundle, tmp_path / "v2.json", fifo)
        _assert_arg_error(proc, face)

    big = tmp_path / "big.json"
    with big.open("wb") as fh:
        fh.truncate(64 * 2**20 + 1)  # sparse: one byte over the cap, no I/O
    proc, face = _anchored(climate_bundle, tmp_path / "v3.json", big)
    _assert_arg_error(proc, face, detail_fragment="cap")


def test_work_set_is_a_bundle_only_flag(tmp_path) -> None:
    """`--kit` judges a kit, not a bundle; a work-set there would be accepted
    and never applied, and a green exit would read as the set having held."""
    ws = _write_work_set(tmp_path / "ws.json", {"pins": _CLIMATE_PINS})
    out = tmp_path / "v.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--kit",
            str(_CLIMATE_KIT),
            "--work-set",
            str(ws),
            "--verdict-out",
            str(out),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == COULD_NOT_CONCLUDE, (proc.stdout, proc.stderr)
    assert "INPUT_MODE_INVALID" in proc.stderr and "--work-set" in proc.stderr, (
        proc.stderr
    )


def test_help_documents_the_flag() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "veriker.cli.verify", "--help"],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 0
    assert "--work-set" in proc.stdout
