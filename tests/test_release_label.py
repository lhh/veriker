"""The release label travels with the artifact, from ONE source.

`audit_bundle/_version.py` is the single source of `__version__` and
`RELEASE_STATUS`. Everything that states a version reads it: the adjacent
pyproject (dynamic version), the CLI's verdict face and first terminal line,
SECURITY.md's commitment. This file SHIPS, so it reads only what ships; the
export-asset half (the public pyproject asset, the public README's literal
console blocks, the never-ship-the-rc-string scan) lives in
`tests/test_release_label_assets.py`, which the export excludes.

The framing rule these cells pin (Veriker launch-risk position, 2026-06-11):
an experimental verifier must SAY so on every surface a verdict can be
forwarded from, and the internal `1.0.0rc1` string must never reach a public
asset while the status is experimental.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle import RELEASE_STATUS, __version__  # noqa: E402
from audit_bundle import _version as _version_mod  # noqa: E402

_ADJACENT_PYPROJECT = _PKG_ROOT / "pyproject.toml"
_SECURITY = _PKG_ROOT / "SECURITY.md"
_CLIMATE_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"

_BANNER = f"veriker {__version__} ({RELEASE_STATUS})"
_PEP440_0X = re.compile(r"\A0\.\d+\.\d+\Z")
_COMMITMENT = "no production, verified, or 1.0 claim"  # matched case-insensitively


# --------------------------------------------------------------------------
# 1. One source
# --------------------------------------------------------------------------


def test_the_version_is_zero_x_and_the_status_is_experimental() -> None:
    assert _PEP440_0X.match(__version__), __version__
    assert RELEASE_STATUS == "experimental"
    assert __version__ == _version_mod.__version__
    assert RELEASE_STATUS == _version_mod.RELEASE_STATUS


def test_the_adjacent_pyproject_reads_the_version_from_the_one_source() -> None:
    """The pyproject next to this package — the internal one here, the public
    `veriker` one in the drop — declares no literal version."""
    pyproject = _ADJACENT_PYPROJECT
    doc = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert "version" not in doc["project"], f"{pyproject.name} pins a literal version"
    assert "version" in doc["project"].get("dynamic", []), pyproject.name
    attr = doc["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert attr == "audit_bundle._version.__version__", attr


def test_the_version_module_is_import_free() -> None:
    """setuptools reads it by AST literal evaluation and the offline CLI's
    stdlib import boundary must not widen: no imports at all."""
    src = (_PKG_ROOT / "audit_bundle" / "_version.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(import|from)\s", src, re.MULTILINE), src


# --------------------------------------------------------------------------
# 2. The verdict face and the terminal
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def climate_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("label_climate") / "bundle"
    subprocess.run(
        [sys.executable, str(_CLIMATE_DIR / "_build_bundle.py"), "--out-dir", str(out)],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    return out


def test_the_face_and_the_first_terminal_line_carry_the_label(
    climate_bundle: Path, tmp_path
) -> None:
    out = tmp_path / "face.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(climate_bundle),
            "--verdict-out",
            str(out),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    # Unanchored on an Axis-2 bundle: could-not-conclude. The label must be
    # there regardless of the verdict — that is the point of a label.
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    face = json.loads(out.read_text(encoding="utf-8"))
    assert face["verifier_version"] == __version__
    assert face["release_status"] == RELEASE_STATUS
    assert proc.stdout.splitlines()[0] == _BANNER, proc.stdout.splitlines()[:3]


def test_the_label_is_on_the_face_even_when_an_operator_error_stops_the_run(
    tmp_path,
) -> None:
    out = tmp_path / "face.json"
    proc = subprocess.run(
        [sys.executable, "-m", "veriker.cli.verify", "--verdict-out", str(out)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 2
    face = json.loads(out.read_text(encoding="utf-8"))
    assert face["verifier_version"] == __version__
    assert face["release_status"] == RELEASE_STATUS
    assert proc.stdout.splitlines()[0] == _BANNER, proc.stdout.splitlines()[:3]


# --------------------------------------------------------------------------
# 3. SECURITY.md says the same thing (it ships at the same path)
# --------------------------------------------------------------------------


def test_security_md_carries_the_audit_commitment_and_named_credit() -> None:
    text = _SECURITY.read_text(encoding="utf-8")
    assert _COMMITMENT in text.lower()
    assert "named credit" in text.lower()
