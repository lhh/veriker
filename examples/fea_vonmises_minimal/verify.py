"""verify.py — the AUDITOR entry point for fea_vonmises_minimal.

    python examples/fea_vonmises_minimal/verify.py [--bundle-dir DIR]

The bundle under audit is `bundle/`; the auditor's spec is its SIBLING in
`spec_pinned/`, never inside it. Point --bundle-dir at the pilot root instead and
verification is refused, not weakened — the anchor would then resolve inside the
directory it is meant to judge.

Anchored by default and by construction: the SpecAnchor is built from the
auditor's OWN committed `spec_pinned/fea_vonmises.spec.json` bytes via the
blessed `SpecAnchor.from_files`, with `forbid_within=bundle_dir`.

No primitive is registered here. `fea_vonmises_recompute` ships in the verifier
distribution and resolves purely by the core registry's auto-registration, so
this pilot is reachable by the bare CLI as well:

    python -m veriker.cli.verify --bundle-dir DIR \
        --spec-anchor examples/fea_vonmises_minimal/spec_pinned/fea_vonmises.spec.json

WHAT IS AND IS NOT PROVEN. A PASS certifies that the four files the re-derivation
consumes are byte-for-byte the ones the auditor pinned, and that re-running the
pinned CST solve over them reproduces the producer's claimed `sigma_vm_max`
within the authority-pinned epsilon. It does NOT certify that the structure is
adequate — no allowable, margin of safety or load-case coverage is evaluated. It
also does not certify solver independence: the auditor pinned this algorithm, and
re-running it is the claim. The solver-independent posture is a different shape;
see `audit_bundle/rederivation/PRIMITIVES.md`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.rederivation.spec_binding import (  # noqa: E402
    AnchorConstructionError,
    SpecAnchor,
)
from audit_bundle.verifier import BundleVerifier  # noqa: E402

_SPEC_SRC = _HERE / "spec_pinned" / "fea_vonmises.spec.json"


def build_anchor(bundle_dir: Path) -> SpecAnchor:
    """The auditor's anchor, from the auditor's committed spec bytes."""
    return SpecAnchor.from_files([_SPEC_SRC], forbid_within=bundle_dir)


def make_verifier(bundle_dir: Path) -> BundleVerifier:
    """The auditor's verifier, STRICT about re-derivation actually happening.

    `require_rederivation=True` is not optional decoration on a pilot whose
    now DEFENCE IN
    DEPTH rather than the sole guard: deleting the three-line `outputs` array
    from manifest.json used to make the whole spec-pinned dispatch inert --
    every pinned byte still matched, every plugin still passed, and this entry
    point printed PASS having re-derived nothing. The SS4a.4 coverage invariant
    now fires on that bundle in the substrate itself (COVERAGE_MISMATCH).

    That closes the CHEAPEST member of the omission class, not the class. The
    invariant triggers on files present at `outputs/*.json`, a path the
    PRODUCER controls, so a producer who deletes the declaration AND relocates
    the files -- rename `outputs/` to `results/`, nest them a directory
    deeper, change the extension -- again presents a bundle with nothing for
    coverage to count. Measured 2026-08-29: forged claim + delete + rename
    `outputs/`->`results/` reads exit 0 PASS on four permissive anchored
    pilots. On THIS pilot that restage is refused, and this flag is why.
    Keep it.
    """
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=build_anchor(bundle_dir),
        require_rederivation=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a fea_vonmises_minimal bundle")
    ap.add_argument(
        "--bundle-dir",
        type=Path,
        default=_HERE / "bundle",
        help="the PRODUCER's bundle (default: the committed bundle/ subdir)",
    )
    args = ap.parse_args()
    bundle_dir = args.bundle_dir.resolve()
    try:
        verifier = make_verifier(bundle_dir)
    except AnchorConstructionError as exc:
        # The tri-state matters here. An unusable anchor is an OPERATOR error --
        # no verdict about the artifact was formed -- so it must route to
        # could-not-conclude (exit 2), never to a REJECT (exit 1). Pointing
        # --bundle-dir at the pilot root reaches exactly this path, because the
        # auditor's spec would then resolve INSIDE the directory under audit.
        print("COULD NOT CONCLUDE")
        print(f"  ANCHOR_UNUSABLE: {exc}")
        return 2
    result = verifier.verify(bundle_dir)
    if result.ok:
        print("PASS")
        return 0

    # Tri-state, mirroring veriker/cli/verify.py: a bundle that only failed to let the
    # verifier CONCLUDE anything is could-not-conclude (exit 2); a REJECT
    # dominates it, because "this artifact is bad" outranks "I could not tell".
    codes = {failure.reason_code for failure in result.failures}
    could_not_conclude = codes == {"VERIFIER_INCOMPLETE"}
    print("COULD NOT CONCLUDE" if could_not_conclude else "FAIL")
    for failure in result.failures:
        print(f"  [{failure.check_name}] {failure.reason_code}: {failure.detail}")
    return 2 if could_not_conclude else 1


if __name__ == "__main__":
    raise SystemExit(main())
