"""verify.py — verify the refinement_discharge_minimal bundle through the SAME
default plugin set the bare CLI verifier (`veriker/cli/verify.py`) uses.

The DISCHARGE path adds no custom TypedCheck — S2 / C16
(`RefinementDischargeCheck`) is already substrate, wired into the default
post-W3 plugin set: file-integrity + spec-pin + the C14/C15/C16 trio with the
verifier key + Z3 invoker wired by `default_post_w3_plugin_set()` (the same
helper veriker/cli/verify.py calls). Zero pilot-specific verification code touches the
discharge path, and that headline claim is runnable with no pilot code at all:

    python veriker/cli/verify.py --bundle-dir examples/refinement_discharge_minimal/bundle

One pilot-level check DOES run here (not in the bare-CLI path):
`AttributionBindingCheck` (FIX-B, claim-set coverage sweep) binds
payload/attribution.json to the discharged recheck_context and the pinned
allocation table — without it the human-facing attribution was fully
decoupled from the numbers Z3 discharged.

This wrapper exists for the pilot four-gate and to print a focused PASS/FAIL.

Usage (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/refinement_discharge_minimal/verify.py \
        --bundle-dir examples/refinement_discharge_minimal/bundle

Exit codes:
  0  PASS
  1  FAIL (one or more checks failed) or missing verifier key
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins import default_post_w3_plugin_set  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

_PILOT_DIR = Path(__file__).resolve().parent
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from AttributionBindingCheck import AttributionBindingCheck  # noqa: E402
from audit_bundle.verdict import exit_code  # noqa: E402


def verify(bundle_dir: Path) -> int:
    if not os.environ.get("VKERNEL_VERIFIER_HMAC_KEY"):
        print(
            "ERROR: export VKERNEL_VERIFIER_HMAC_KEY first "
            '(e.g. "demo-vkernel-verifier-secret-0123456789abcdef"). The S2 '
            "discharge status is verifier-signed; without the key the C16 check "
            "fails closed (DISCHARGE_STATUS_FORGED).",
            file=sys.stderr,
        )
        return 1

    # default_post_w3_plugin_set() loads VKERNEL_VERIFIER_HMAC_KEY + a Z3 invoker
    # internally — the SAME wiring veriker/cli/verify.py uses (C15 well-formedness, C14
    # lattice, C16 refinement-discharge). FileIntegrity + SpecShaPin are the
    # universal precondition plugins.
    plugins = [
        FileIntegrityManySmall(),
        SpecShaPinCheck(),
        *default_post_w3_plugin_set(),
        # FIX-B binding leg: payload/attribution.json ↔ discharged context ↔
        # pinned allocation table (the C16 leg alone never opened the payload).
        AttributionBindingCheck(),
    ]
    result = BundleVerifier(plugins=plugins).verify(bundle_dir)

    code = exit_code(result)

    if result.ok:
        print(f"PASS — {bundle_dir}")
        print(
            "  S2 / C16 refinement_discharge: verifier-signed 'discharged' "
            "admitted; Z3 re-run agrees (re-discharged)"
        )
        print(
            "  rd_attribution_binding: payload/attribution.json equals the "
            "re-discharged context and the pinned allocation table"
        )
        return 0

    _BANNER = "FAIL" if code == 1 else "ERROR  could not conclude"
    print(f"{_BANNER} — {bundle_dir}")
    for f in result.failures:
        print(f"  [{f.check_name}] {f.reason_code}: {f.detail}")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the refinement_discharge_minimal bundle (S2 / C16)"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    return verify(args.bundle_dir.resolve())


if __name__ == "__main__":
    sys.exit(main())
