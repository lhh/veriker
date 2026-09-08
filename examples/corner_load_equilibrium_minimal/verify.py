"""verify.py — corner_load_equilibrium_minimal: the production command, prefilled.

This front door holds NO verification logic. It runs the same shipped CLI a
relying party runs, with this pilot's three auditor-held inputs filled in, and
prints that command before the verdict so a reader sees exactly what they
would have to hold themselves:

    the anchored spec   spec_pinned/corner_load_equilibrium.spec.json
    the primitive kit   auditor_kit.py
    the work-set        spec_pinned/corner_load_equilibrium.work_set.json

Which files are whose. The PRODUCER's are the twin and its bundle writer:
_producer_solve.py, _producer_surrogate.py, _build_bundle.py. The AUDITOR's
are the three inputs above plus the tooling around them: auditor_entry.py
(the one library constructor the miner uses), hard_negatives.py, and this
file. In production the two halves live on different machines under
different owners. Here they share a folder so the demo is one command; the
folder is the demo's compromise, not the product's shape.

Why the CLI and not the library. A front door that built its own verifier
next to the producer's code taught that producer and verifier share a
process. The CLI refuses an anchor or kit path that resolves inside the
bundle, records the anchor's provenance on the face, names which auditor rule
judged which claim, and can say "could not conclude" (exit 2) when nothing was
re-derived. Anything this pilot needs that the CLI cannot express is a CLI gap
to close, not a reason to reach around it: the split channel's coverage line
("judged 94 of 120 samples") used to be printed here by hand, and now rides
the CLI's recompute_detail rows for every pilot.

Usage:
    python examples/corner_load_equilibrium_minimal/verify.py --bundle-dir <path>

Exit codes (the CLI's, passed through unchanged):
    0  PASS
    1  FAIL   -- a check concluded against the bundle, or it is not a bundle
    2  ERROR  -- could not conclude (incl. nothing re-derived, unusable inputs)
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]
for _p in (str(_PKG_ROOT), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ONE definition of the auditor's inputs, shared with the miner's library
# constructor so the two tools cannot hold different anchors.
from auditor_entry import KIT_PATH, SPEC_SOURCES, WORK_SET_PATH  # noqa: E402


def command(bundle_dir: Path) -> list[str]:
    """The exact argv this front door runs: the shipped CLI with the auditor's
    three inputs prefilled. Importable so a test can re-run precisely what
    was printed and compare verdicts."""
    return [
        sys.executable,
        "-m",
        "veriker.cli.verify",
        "--bundle-dir",
        str(bundle_dir),
        "--spec-anchor",
        *[str(p) for p in SPEC_SOURCES],
        "--primitives",
        str(KIT_PATH),
        "--work-set",
        str(WORK_SET_PATH),
        "--require-rederivation",
    ]


def display(argv: list[str]) -> str:
    """The command as a reader would type it: `python` for the interpreter,
    paths under the package root made relative to it (the subprocess runs
    from there), everything else verbatim and shell-quoted."""
    shown: list[str] = []
    for i, arg in enumerate(argv):
        if i == 0:
            shown.append("python")
            continue
        try:
            shown.append(str(Path(arg).relative_to(_PKG_ROOT)))
        except ValueError:
            shown.append(arg)
    return "$ " + " ".join(shlex.quote(x) for x in shown)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="corner_load_equilibrium_minimal audit bundle verifier "
        "(the shipped CLI, with this pilot's auditor inputs prefilled)"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    argv = command(args.bundle_dir.resolve())
    print(display(argv), flush=True)
    env = dict(os.environ)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    # cwd = package root: `-m veriker.cli.verify` resolves from there in this tree,
    # and from the installed package in the public drop (the export rewrites
    # the module path). stdout/stderr are inherited, not captured: the CLI's
    # face IS this front door's output, unedited.
    proc = subprocess.run(argv, cwd=_PKG_ROOT, env=env, check=False)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
