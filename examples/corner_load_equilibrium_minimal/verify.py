"""verify.py — corner_load_equilibrium_minimal bundle verifier.

Anchored by default: the SpecAnchor is built from the COMMITTED auditor spec
bytes via SpecAnchor.from_files(..., forbid_within=bundle_dir), so a producer
who ships a weakened spec/ copy yields a SHA the anchor does not list and
dispatch fails closed.

The verifier is constructed in auditor_entry.build_verifier, which hard_negatives.py
also calls -- one anchored configuration for both auditor-side tools, so a
hardening here cannot fail to reach the mining path.

require_rederivation=True: this bundle exists FOR its re-derivation property.
A bundle that re-derives nothing must be a could-not-conclude ERROR (exit 2),
not a quiet PASS -- deleting manifest.outputs is otherwise a way to make
dispatch inert and still print PASS.

Usage:
    python examples/corner_load_equilibrium_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS
    1  FAIL   -- a check concluded against the bundle
    2  ERROR  -- could not conclude (incl. nothing re-derived)
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

from auditor_entry import build_verifier  # noqa: E402
from audit_bundle.rederivation.kit import KitConstructionError  # noqa: E402
from audit_bundle.rederivation.spec_binding import AnchorConstructionError  # noqa: E402
from audit_bundle.verdict import exit_code  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="corner_load_equilibrium_minimal audit bundle verifier"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # The auditor's two inputs -- the kit and the anchor -- are built before any
    # verdict exists, and BOTH refuse a path inside the bundle under audit.
    # Pointing --bundle-dir at the pilot root reaches exactly that: the refusal
    # is the guard working, but it says nothing about an artifact, so it is an
    # operator error. It must route to could-not-conclude like every other
    # could-not-conclude -- not to an uncaught KitConstructionError traceback
    # exiting 1, which is what it did until 2026-08-31. build_verifier itself
    # still RAISES: admit_for_mining is its other caller and turns the same
    # condition into MiningRefused, which is that tool's own contract.
    try:
        verifier, _anchor = build_verifier(bundle_dir)
    except (KitConstructionError, AnchorConstructionError) as exc:
        print("ERROR  could not conclude", file=sys.stderr)
        print(f"  AUDITOR_INPUTS_UNUSABLE: {exc}", file=sys.stderr)
        return 2

    result = verifier.verify(bundle_dir)

    code = exit_code(result)

    # WHICH CLAIMS WERE REQUIRED AND WHICH RULE JUDGED EACH, on the terminal,
    # not only in the verdict object. A green run is exactly when this matters:
    # the fallback coverage accounting establishes that every anchored rule was
    # reached, never that each output was judged by its OWN rule or that no
    # claim was dropped or smuggled, and a reader who sees a bare "PASS" has no
    # way to tell those apart. The work-set row names the universe_sha and the
    # provenance of the set that was applied. veriker/cli/verify.py already prints
    # selected disclosure prefixes for the same reason -- the JSON is not what
    # the human reads.
    for row in getattr(result.completeness, "disclosures", ()) or ():
        if row.startswith("type_selection:"):
            print(f"  {row}")

    if result.ok:
        print("PASS")
        return 0

    # ADR BI-1 tri-state: a could-not-conclude is a statement about the
    # VERIFIER, not an accusation against the artifact. Say which one.
    print("FAIL" if code == 1 else "ERROR  could not conclude", file=sys.stderr)
    for failure in result.failures:
        print(
            f"  [{failure.check_name}] {failure.reason_code}: {failure.detail}",
            file=sys.stderr,
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
