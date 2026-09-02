"""verify.py — content_provenance_minimal domain pilot bundle verifier.

SCOPE BOUNDARY — READ BEFORE PROCEEDING:
This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.

Honest claim:
  A published content artifact carries a producer-signed manifest binding it to
  its producer identity and generation inputs; the verifier re-confirms the
  artifact's bytes match the signed hash and the provenance chain is intact.
  Any post-signing alteration fails closed.  Synthetic producer key; local-only demo.

the audit-bundle contract §C5 (auditor independence).  Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required by the caller.

Registers two plugins:
  FileIntegrityManySmall               §C9 — per-file SHA walk with named reason codes
  ContentProvenanceReDerivationCheck   §C6 — content provenance re-derivation

Usage:
    python examples/content_provenance_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# §C5 auditor-independence: locate pkg root relative to this file so the
# script is runnable from any cwd without external PYTHONPATH configuration.
# Layout: examples/content_provenance_minimal/verify.py → parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ContentProvenanceReDerivationCheck lives alongside this script (AB4).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.verifier import BundleVerifier
from audit_bundle.verdict import exit_code  # noqa: E402
from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Content provenance audit bundle verifier "
            "(AUDIT_BUNDLE_CONTRACT §C5 + §C6)"
        )
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    plugins = [
        FileIntegrityManySmall(),
        ContentProvenanceReDerivationCheck(),
    ]
    verifier = BundleVerifier(plugins=plugins)
    result = verifier.verify(bundle_dir)

    code = exit_code(result)

    if result.ok:
        print(
            "PASS — content provenance verified: artifact bytes match producer-signed manifest; "
            "provenance chain intact.  (NOT truth-detection; unaltered false content also passes.)"
        )
        # The claim-field coverage receipt rides the verdict's Completeness
        # disclosures; print it so a CLI user sees what the green verdict
        # accounted for (and what it did not), not only the word PASS.
        for line in result.completeness.disclosures:
            if line.startswith("claimset:"):
                print(f"  {line}")
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
