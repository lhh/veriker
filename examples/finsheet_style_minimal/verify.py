"""verify.py — finsheet_style_minimal bundle verifier (anchored by default).

The anchor is built from the AUDITOR's committed spec via
SpecAnchor.from_files(..., forbid_within=bundle_dir); require_rederivation=True
so a bundle that re-derives nothing is a could-not-conclude; the work-set is
derived from the anchored spec so the producer does not choose which claims
arrive. Construction lives in auditor_entry.build_verifier — the harness uses
the same one.

Usage:
    python examples/finsheet_style_minimal/verify.py --bundle-dir <path> [--spec <auditor spec>]

--spec defaults to the committed demo spec (spec_pinned/finsheet_demo.spec.json).
The harness passes the per-question spec it generated into its own run
directory, outside the bundle.

Exit codes:
    0  PASS   -- both arms re-derived the claim
    1  FAIL   -- a check concluded against the bundle (per-arm lines on stderr)
    2  ERROR  -- could not conclude
"""

from __future__ import annotations

import argparse
import sys

sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from auditor_entry import DEMO_SPEC, build_verifier, read_outcomes  # noqa: E402
from audit_bundle.rederivation.spec_binding import AnchorConstructionError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="finsheet_style_minimal audit bundle verifier"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument(
        "--spec",
        type=Path,
        default=DEMO_SPEC,
        help="auditor's committed spec (outside the bundle)",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()
    spec_path: Path = args.spec.resolve()

    try:
        verifier, _anchor = build_verifier(bundle_dir, spec_path)
    except AnchorConstructionError as exc:
        print("ERROR  could not conclude", file=sys.stderr)
        print(f"  AUDITOR_INPUTS_UNUSABLE: {exc}", file=sys.stderr)
        return 2

    result = verifier.verify(bundle_dir)
    outcome = read_outcomes(result)
    code = outcome["exit_code"]

    if result.ok:
        print("PASS")
    else:
        print("FAIL" if code == 1 else "ERROR  could not conclude", file=sys.stderr)
    for oid, row in outcome["outputs"].items():
        line = f"  {oid:<20} {row['state']}"
        if row["reason_code"]:
            line += f"  {row['reason_code']}: {row['detail']}"
        print(line, file=sys.stderr if not result.ok else sys.stdout)
    for f in outcome["other_failures"]:
        print(
            f"  [{f['check_name']}] {f['reason_code']}: {f['detail']}", file=sys.stderr
        )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
