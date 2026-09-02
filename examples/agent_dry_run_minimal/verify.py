"""verify.py — agent_dry_run_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone script from any
working directory.

Registers four plugins:
  SpecShaPinCheck            §C1 — tool-schema + ladder-spec SHA pinning
  FileIntegrityManySmall     §C9 — per-file SHA walk over manifest.files
  AgentDryRunCheck           §C6/§C16 — the verifier re-derives every verdict, the per-sink
                                       aggregate table and the coverage row from the
                                       COMMITTED INPUTS, and rejects on any disagreement
  CoverageSumInvariantCheck  §C4 — n_eligible == n_issued + n_withheld

A PASS here means the counterfactual re-derives. It does NOT mean the bundle is anchored:
`spec/` must be compared against a copy from OUTSIDE the bundle, and anchoring on the
bundle's own `spec/` copy is the same fail-open as no anchor at all. See
`disclosures/anchor_status.json` in the bundle.

Usage:
    python examples/agent_dry_run_minimal/verify.py --bundle-dir <path>

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

from audit_bundle.coverage.sum_invariant_plugin import CoverageSumInvariantCheck  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.reference.AgentDryRunCheck import AgentDryRunCheck  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from audit_bundle.verdict import exit_code  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Agent dry-run audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5)"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    plugins = [
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        AgentDryRunCheck(),
        CoverageSumInvariantCheck(),
    ]
    result = BundleVerifier(plugins=plugins).verify(args.bundle_dir.resolve())

    code = exit_code(result)

    if result.ok:
        print("PASS — the counterfactual re-derives from the committed inputs.")
        print("      NOT a statement about anchoring: see disclosures/anchor_status.json.")
        return 0
    _BANNER = "FAIL" if code == 1 else "ERROR  could not conclude"
    print(f"{_BANNER} — {result}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
