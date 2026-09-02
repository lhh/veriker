"""verify.py — pii_redaction_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required by the caller.

Registers three plugins:
  FileIntegrityManySmall              §C9 — per-file SHA walk
  PIIRedactionReDerivationCheck       §C6 — constrained-Viterbi re-derivation
  DispatchRecordWellformedCheck       §C15 — op-kind well-formedness
    (op_kinds_admitted=frozenset({"REDACT", "COMPUTE"}) admits the new
     REDACT op kind introduced by this domain pilot)

Usage:
    python examples/pii_redaction_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier
from audit_bundle.verdict import exit_code  # noqa: E402
from PIIRedactionReDerivationCheck import PIIRedactionReDerivationCheck


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PII-redaction-minimal audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5)"
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
        PIIRedactionReDerivationCheck(),
        DispatchRecordWellformedCheck(
            op_kinds_admitted=frozenset({"REDACT", "COMPUTE"})
        ),
        StampLatticeCheck(),
    ]
    verifier = BundleVerifier(plugins=plugins)
    result = verifier.verify(bundle_dir)

    code = exit_code(result)

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
