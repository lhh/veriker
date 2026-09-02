"""verify.py — pandemic_benefit_eligibility_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone script
from any working directory; inserts the v-kernel-audit-bundle package root into
sys.path so no PYTHONPATH manipulation is required.

The narrow, honest claim:
"A deterministic benefit-eligibility decision and benefit amount can be independently
re-derived and signed from the applicant's attested attributes and the published rule set
BEFORE disbursement — the exact pre-payment check that was skipped. Synthetic rules and
records; no CRA/Service Canada integration; not a fraud detector."

Registers four plugins:
  SpecShaPinCheck                       §C1  — eligibility_rules.json + key SHA-pinned
  FileIntegrityManySmall                §C9  — per-file SHA walk over manifest.files
  PandemicEligibilityReDerivationCheck  §C6/§C16 — verifier-computed eligibility re-derivation
  CoverageSumInvariantCheck             §C4  — n_eligible == n_issued (approved) + n_withheld (denied)

Usage:
    python examples/pandemic_benefit_eligibility_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# §C5 auditor-independence. Layout: examples/<pilot>/verify.py → parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck
from audit_bundle.verifier import BundleVerifier
from audit_bundle.coverage.sum_invariant_plugin import CoverageSumInvariantCheck
from audit_bundle.verdict import exit_code  # noqa: E402
from PandemicEligibilityReDerivationCheck import PandemicEligibilityReDerivationCheck


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pandemic benefit eligibility audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5). "
            "Honest claim: a deterministic benefit-eligibility decision and benefit amount can "
            "be independently re-derived and signed from the applicant's attested attributes "
            "and the published rule set BEFORE disbursement — the exact pre-payment check that "
            "was skipped. Synthetic rules and records; no CRA/Service Canada integration; not a "
            "fraud detector."
        )
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    plugins = [
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        PandemicEligibilityReDerivationCheck(),
        CoverageSumInvariantCheck(),
    ]
    verifier = BundleVerifier(plugins=plugins)
    result = verifier.verify(bundle_dir)

    code = exit_code(result)

    if result.ok:
        print("PASS")
        print(
            "Honest claim: A deterministic benefit-eligibility decision and benefit amount can be "
            "independently re-derived and signed from the applicant's attested attributes and the "
            "published rule set BEFORE disbursement — the exact pre-payment check that was skipped. "
            "Synthetic rules and records; no CRA/Service Canada integration; not a fraud detector."
        )
        return 0

    # ADR BI-1 tri-state: a could-not-conclude is a statement about the
    # VERIFIER, not an accusation against the artifact. Say which one.
    print("FAIL" if code == 1 else "ERROR  could not conclude", file=sys.stderr)
    for failure in result.failures:
        print(f"  [{failure.check_name}] {failure.reason_code}: {failure.detail}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
