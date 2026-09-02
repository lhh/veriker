#!/usr/bin/env python3
"""Run every pilot's `tests/` battery, ONE PILOT PER PROCESS.

Why a runner exists at all
--------------------------
`testpaths = ["tests"]` constrains default discovery to the root suite, so the
pilot batteries under `examples/*/tests/` are never collected by a plain
`pytest` run. They are not decorative -- they are the per-pilot tamper batteries
-- but nothing executes them, so nothing notices when one rots.

The obvious repair, adding `examples` to `testpaths`, is wrong, and the config
comment beside `testpaths` says why: the batteries are written to be invoked one
pilot at a time. Each battery prepends its own pilot directory to `sys.path` at
import, and pilot-local module names repeat across the fleet -- 110 pilots ship
a `_build_bundle.py`, 107 a `verify.py`, 45 a `spec_pinned_check.py`, and 15
further stems sit in more than one pilot. Collected into ONE process they
resolve against whichever pilot reached `sys.modules` first. That is not a
theoretical hazard: `pytest examples/` reports 140 failures and 4 collection
errors here, of which 125 and all 4 are the collision rather than a defect in
any pilot.

Running each battery in its own interpreter makes the pilot directory
unambiguous for the duration, which is the condition every battery was written
under. It is also the only invocation whose failures mean what they say.

Usage
-----
    python scripts/run_example_batteries.py               # every battery
    python scripts/run_example_batteries.py --only soc2   # substring filter
    python scripts/run_example_batteries.py --list        # names only

Exit code is 0 only when every battery that ran passed.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

#: `__doc__` is None under `python -OO`, which strips docstrings.
_SUMMARY = "Run every pilot's tests/ battery, one pilot per process."

_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _ROOT / "examples"


def batteries(only: str | None) -> list[Path]:
    found = sorted(p for p in _EXAMPLES.glob("*/tests") if p.is_dir())
    if only:
        found = [p for p in found if only in p.parent.name]
    return found


def run_one(battery: Path, extra: list[str]) -> tuple[bool, str, float]:
    started = time.monotonic()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(battery),
            "-q",
            "-p",
            "no:cacheprovider",
            *extra,
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
    )
    elapsed = time.monotonic() - started
    tail = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    summary = tail[-1] if tail else f"(no output, exit {proc.returncode})"
    # pytest exits 5 when a battery collects nothing; that is a real defect in a
    # directory that exists, not a pass.
    return proc.returncode == 0, summary, elapsed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=_SUMMARY)
    ap.add_argument("--only", help="substring filter on the pilot directory name")
    ap.add_argument("--list", action="store_true", help="list the batteries and exit")
    ap.add_argument(
        "pytest_args", nargs="*", help="extra arguments forwarded to each pytest run"
    )
    args = ap.parse_args(argv)

    found = batteries(args.only)
    if not found:
        print("no pilot batteries matched", file=sys.stderr)
        return 1
    if args.list:
        for b in found:
            print(b.parent.name)
        return 0

    width = max(len(b.parent.name) for b in found)
    failed: list[str] = []
    for b in found:
        ok, summary, elapsed = run_one(b, args.pytest_args)
        mark = "ok  " if ok else "FAIL"
        print(
            f"{mark} {b.parent.name:<{width}}  {summary}  [{elapsed:.1f}s]", flush=True
        )
        if not ok:
            failed.append(b.parent.name)

    print(f"\n{len(found) - len(failed)}/{len(found)} pilot batteries green")
    if failed:
        print("failing: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
