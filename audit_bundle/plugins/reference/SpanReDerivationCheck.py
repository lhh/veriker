"""SpanReDerivationCheck — TypedCheck plugin for text-output span re-derivation (C6).

DEPRECATED (2026-05-24, L8 keel LOCKED). Superseded by the substrate plugin
audit_bundle/plugins/fragment_attestation.py, which attests canonical
manifest.fragment_anchors on the DEFAULT verify path (every bundle), not just
pilots that ship a payload/spans.json. Kept for backward compatibility with
bundles already carrying the pilot-private spans.json shape.

Wraps span_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

Implements the audit-bundle contract §C6 (text-output generalization caveat).
name='span_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.reference._vacuity import is_vacuous


class SpanReDerivationCheck:
    name: str = "span_re_derivation"
    # exact-path-only: the former {"payload/"} was a trailing-slash
    # pseudo-prefix the verifier consumed by exact match, so it never matched
    # a real path (inert). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # SAFE-BY-ORIGIN: __file__-rooted = verifier-distribution code, NOT
        # bundle-supplied, so this runs ungated by design (unlike
        # re_derivation_invocation's bundle pack, which requires permit_execution).
        # Relocating this to a bundle_dir path REQUIRES adding the gate —
        # tests/test_bundle_exec_gate_structural.py enforces it.
        pack_path = Path(__file__).parent / "span_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "span_re_derivation.py not found alongside SpanReDerivationCheck.py; "
                    "domain pilot opted out of C6"
                ),
                files_audited=(),
            )

        spans_path = bundle_dir / "payload" / "spans.json"
        if not spans_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/spans.json absent — no span records to re-derive",
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
        if is_vacuous(spans_path):
            return PluginResult(
                ok=True,
                reason_code="NO_SPANS",
                detail="payload/spans.json declares no span records — nothing to re-derive",
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
                detail="span_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(spans_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail="span_re_derivation.py exited 0 — all spans verified",
                files_audited=(str(spans_path),),
                # Verifier-side re-derivation coverage: this arm really
                # recomputed and compared, via the SAFE-BY-ORIGIN __file__-rooted
                # script above (verifier-distribution code, not bundle-supplied).
                # Consumed by _step_rederivation_surface_guard so a bundle this
                # check covers is never labelled "the verifier re-derived
                # nothing" nor failed under --require-rederivation.
                verified_rederivations=frozenset({"span_re_derivation"}),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="RE_DERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(spans_path),),
        )


register_typed_check("span_re_derivation")
