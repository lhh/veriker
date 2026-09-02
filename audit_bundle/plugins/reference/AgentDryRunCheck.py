"""AgentDryRunCheck — TypedCheck plugin for the agent dry-run domain (C6 + C16).

Wraps agent_dry_run_pack.py via subprocess. The wrapped pack re-derives every verdict face,
the per-sink aggregate table and the coverage row from the bundle's COMMITTED INPUTS and
rejects the bundle if any of them disagrees with what the bundle claims.

This is the whole point of the artifact. A dry-run number the reader has to trust is a
dashboard; a dry-run number the reader recomputes is evidence.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate) and the §C16
principle that the verifier — never the dispatcher — sets the verdict.
name='agent_dry_run'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class AgentDryRunCheck:
    name: str = "agent_dry_run"
    applies_to_files: frozenset[str] = frozenset(
        {"payload/verdicts.jsonl", "payload/aggregate.json", "coverage/dry_run_coverage.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # SAFE-BY-ORIGIN: __file__-rooted = verifier-distribution code, NOT bundle-supplied,
        # so this runs ungated by design.
        pack_path = Path(__file__).parent / "agent_dry_run_pack.py"
        audited = (
            str(bundle_dir / "payload" / "verdicts.jsonl"),
            str(bundle_dir / "payload" / "aggregate.json"),
            str(bundle_dir / "coverage" / "dry_run_coverage.json"),
        )
        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail="agent_dry_run_pack.py not found alongside plugin; pilot opted out",
                files_audited=(),
            )
        missing = [
            rel
            for rel in (
                "payload/verdicts.jsonl",
                "payload/aggregate.json",
                "coverage/dry_run_coverage.json",
                "spec/ladder_spec.json",
            )
            if not (bundle_dir / rel).exists()
        ]
        if missing:
            # NOT a pass. A bundle that claims this check and does not carry what the check
            # reads is a claim nothing verified — could-not-conclude, never OK.
            return PluginResult(
                ok=False,
                reason_code="DRY_RUN_ARTIFACTS_ABSENT",
                detail=f"typed check claimed but these are missing: {missing}",
                files_audited=(),
                incomplete=True,
            )

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="RE_DERIVATION_TIMEOUT",
                detail="agent_dry_run_pack.py exceeded 300 s timeout",
                files_audited=audited,
                incomplete=True,
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(
                    "every verdict face, the per-sink aggregate table and the coverage row "
                    "re-derive from the committed inputs"
                ),
                files_audited=audited,
            )

        return PluginResult(
            ok=False,
            reason_code="RE_DERIVATION_MISMATCH",
            detail=(result.stderr or b"").decode("utf-8", errors="replace")[:1024],
            files_audited=audited,
        )


register_typed_check("agent_dry_run")
