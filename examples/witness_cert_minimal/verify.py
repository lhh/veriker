"""verify.py — the AUDITOR entry point for witness_cert_minimal.

    python examples/witness_cert_minimal/verify.py [--bundle-dir DIR]

The bundle under audit is `bundle/`; the auditor's spec is its SIBLING in
`spec_pinned/`, never inside it. Point --bundle-dir at the pilot root instead
and verification is refused, not weakened — the anchor would then resolve inside
the directory it is meant to judge.

Anchored by default and by construction: the SpecAnchor is built from the
auditor's OWN committed `spec_pinned/witness_cert.spec.json` bytes via the
blessed `SpecAnchor.from_files`, with `forbid_within=bundle_dir` so a spec taken
from inside the bundle under audit is refused rather than trusted.

No primitive is registered here. The three certificate primitives
(`fea_witness_certificate` and its two norm siblings) ship in the verifier
distribution, so this pilot is reachable by the bare CLI as well:

    python -m veriker.cli.verify --bundle-dir DIR \
        --spec-anchor examples/witness_cert_minimal/spec_pinned/witness_cert.spec.json

WHAT IS AND IS NOT PROVEN. A PASS certifies that the committed inputs are the
anchored ones, that the producer's witness satisfies the prescribed
displacements exactly and the free-DOF equilibrium of the original stiffness
within the anchored tolerance, and that each claimed quantity lies within the
certified interval of the quantity the witness algebraically implies. It does
NOT certify that the structure is adequate — no allowable, margin of safety, or
load-case adequacy is evaluated here. Faithfulness of the claim, not fitness of
the design.
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
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from audit_bundle.verdict import exit_code  # noqa: E402

_SPEC_SRC = _HERE / "spec_pinned" / "witness_cert.spec.json"


def build_anchor(bundle_dir: Path) -> SpecAnchor:
    """The auditor's anchor, from the auditor's committed spec bytes."""
    return SpecAnchor.from_files([_SPEC_SRC], forbid_within=bundle_dir)


def make_verifier(bundle_dir: Path) -> BundleVerifier:
    """The auditor's verifier, STRICT about re-derivation actually happening.

    `require_rederivation=True` is load-bearing on this pilot specifically
    because of what it claims. The whole point here is that the verifier never
    solves: it checks a certificate over the producer's committed witness. If
    the certificate never runs, the remaining verdict is byte-integrity over
    files the producer chose — which is precisely the posture this pilot exists
    to argue is insufficient.

    Measured 2026-08-31, before this flag: empty `manifest.outputs`, drop the
    three `outputs/*.json` and their `manifest.files` entries, and this entry
    point printed PASS having re-derived nothing. The §4a.4 coverage invariant
    catches the CHEAPEST version (delete the declaration, leave the files —
    COVERAGE_MISMATCH), but it counts files present at `outputs/*.json`, a path
    the PRODUCER controls, so removing them too leaves it nothing to count. This
    flag is what makes that a could-not-conclude instead of a PASS.
    """
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=build_anchor(bundle_dir),
        require_rederivation=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a witness_cert_minimal bundle")
    ap.add_argument(
        "--bundle-dir",
        type=Path,
        default=_HERE / "bundle",
        help="the PRODUCER's bundle (default: the committed bundle/ subdir)",
    )
    args = ap.parse_args()
    bundle_dir = args.bundle_dir.resolve()
    result = make_verifier(bundle_dir).verify(bundle_dir)
    code = exit_code(result)
    if result.ok:
        print("PASS")
        return 0
    _BANNER = "FAIL" if code == 1 else "ERROR  could not conclude"
    print(_BANNER)
    for failure in result.failures:
        print(f"  [{failure.check_name}] {failure.reason_code}: {failure.detail}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
