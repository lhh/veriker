"""PayrollReDerivationCheck — TypedCheck plugin for payroll re-derivation (C6).

Wraps payroll_re_derivation.py via subprocess, mirroring the
re_derivation_invocation pattern in audit_bundle/plugins/re_derivation_invocation.py.

§C6 (domain-agnostic re-derivation substrate).
name='payroll_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PayrollReDerivationCheck:
    name: str = "payroll_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"data/", "payload/paychecks.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "payroll_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "payroll_re_derivation.py not found alongside "
                    "PayrollReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        events_path = bundle_dir / "data" / "pay_events.csv"
        # FIX-E: the committed disbursement ledger — "actually disbursed"
        # evidence issued_net_cents is now bound to (see payroll_re_derivation.py).
        disbursements_path = bundle_dir / "data" / "disbursements.csv"
        ledger_path = bundle_dir / "payload" / "paychecks.json"
        if not events_path.exists() or not ledger_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail="data/pay_events.csv or payload/paychecks.json absent — nothing to re-derive",
                files_audited=(),
            )

        audited = (str(events_path), str(disbursements_path), str(ledger_path))

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="RE_DERIVATION_TIMEOUT",
                detail="payroll_re_derivation.py exceeded 60 s timeout",
                files_audited=audited,
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail="payroll_re_derivation.py exited 0 — every paycheck and clawback re-derived",
                files_audited=audited,
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="RE_DERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=audited,
        )


register_typed_check("payroll_re_derivation")
