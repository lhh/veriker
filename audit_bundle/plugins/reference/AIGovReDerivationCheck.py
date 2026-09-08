"""AIGovReDerivationCheck — TypedCheck plugin for AI-governance control re-derivation.

Wraps aigov_rederivation.py via subprocess. The same re-derivation plumbing shipped
for span (C6), SMT (C16), and SOC 2 controls (control_rederivation), pointed at
EU AI Act / ISO 42001 high-risk-AI obligations. The wrapped pack re-derives, for every
attestation, the verdict the verifier itself computes from the CAPTURED registry, and
rejects the bundle if any attestation is unsigned, cites a control or test_fn the pinned
library does not contain, binds an evidence hash that does not match the captured object,
claims a verdict the verifier does not re-derive, or carries an observed_at that does not
bind to the evidence object's own captured_at (OBSERVED_AT_EVIDENCE_MISMATCH /
OBSERVED_AT_EVIDENCE_UNBOUND / OBSERVED_AT_UNPARSEABLE — the pack's module docstring
states the honesty-rail scope of that binding; the pack and control_rederivation are
held to the same reason-code vocabulary by tests/test_reference_pack_parity.py).

Implements the audit-bundle contract §C6 (domain-agnostic re-derivation) and the §C16
principle that the verifier — never the dispatcher/collector — sets the verdict.
name='aigov_rederivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.reference._vacuity import is_vacuous


class AIGovReDerivationCheck:
    name: str = "aigov_rederivation"
    applies_to_files: frozenset[str] = frozenset({"payload/control_attestations.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # SAFE-BY-ORIGIN: __file__-rooted = verifier-distribution code, NOT
        # bundle-supplied, so this runs ungated by design (unlike
        # re_derivation_invocation's bundle pack, which requires permit_execution).
        # Relocating this to a bundle_dir path REQUIRES adding the gate —
        # tests/test_bundle_exec_gate_structural.py enforces it.
        pack_path = Path(__file__).parent / "aigov_rederivation.py"
        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail="aigov_rederivation.py not found alongside plugin; pilot opted out",
                files_audited=(),
            )

        attestations_path = bundle_dir / "payload" / "control_attestations.json"
        if not attestations_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail="payload/control_attestations.json absent — no control verdicts to re-derive",
                files_audited=(),
            )

        # VACUITY GATE — "a script exited 0" is not "a script checked
        # something". The re-derivation script below iterates this payload and
        # returns 0; an EMPTY collection iterates zero times, so without this a
        # producer shipping an empty file gets a RE_DERIVED verdict and full
        # re-derivation coverage over nothing (measured 2026-08-16: exit 0
        # under --require-rederivation with a clean verdict face). Shared with
        # the sibling checks via _vacuity so the guard cannot drift apart
        # again — SensorReDerivationCheck's NO_TRACES arm is the original.
        if is_vacuous(attestations_path):
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_ATTESTATIONS",
                detail="payload/control_attestations.json declares no control verdicts — nothing to re-derive",
                files_audited=(),
            )

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
                detail="aigov_rederivation.py exceeded 60 s timeout",
                files_audited=(str(attestations_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail="every AI-governance verdict signed, control+test_fn pinned, evidence-bound, and re-derived",
                files_audited=(str(attestations_path),),
                # Verifier-side re-derivation coverage — consumed by
                # _step_rederivation_surface_guard so this check's bundles are
                # not labelled "the verifier re-derived nothing".
                verified_rederivations=frozenset({"aigov_rederivation"}),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="RE_DERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(attestations_path),),
        )


register_typed_check("aigov_rederivation")
