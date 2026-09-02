"""YieldFusionReDerivationCheck — TypedCheck plugin for agritech yield-score re-derivation.

Wraps yield_fusion_re_derivation.py via subprocess, following the
re_derivation_invocation pattern from audit_bundle/plugins/.

§C6 (domain-agnostic re-derivation substrate).
name='yield_fusion_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Emit codes:
  RE_DERIVED                 — ok path, subprocess exited 0
  RE_DERIVATION_MISMATCH     — fail path, subprocess exited non-zero (numeric
                               re-derivation mismatch, or any un-subcoded failure)
  YIELD_ATTRIBUTION_MISMATCH — fail path, forecast's field_id/sensor_id/
                               window_start/window_end does not bind to the
                               matching fields in inputs/sensor_stream.json
                               (or one side omits a binding field) — an
                               attribution/scope-misbinding gap, distinct from
                               a numeric re-derivation mismatch
  RE_DERIVATION_TIMEOUT      — fail path, subprocess exceeded 60 s
  NO_PACK                    — skip, pack not found (ok=True, advisory)
  NO_INPUTS                  — skip, bundle inputs absent (ok=True, advisory)

NOTE: since 2026-08-30 BundleVerifier._step_typed_check_plugins PROPAGATES a
failing plugin's own reason_code onto the verdict face, alongside check_name
and detail (see audit_bundle/verifier.py). So the dedicated sub-code above is
visible BOTH to a direct plugin.check() caller and to a BundleVerifier
consumer, as the top-level reason_code. The pack's own "[YIELD_REDER_FAIL]"
marker still travels inside `detail`; the battery asserts on both.

Before that change the verifier overwrote the code with the literal
"plugin_failed", and this file's battery asserted on a substring that never
matched ("YIELD_REDERIV" is not a substring of "YIELD_REDER_FAIL"), so the
test was carried entirely by the "PLUGIN_FAILED" arm and passed with this
plugin DELETED. Measured, then fixed, 2026-08-30.
"""

from __future__ import annotations

import re

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.re_derivation_invocation import classify_pack_failure

#: The pack prints "[YIELD_REDER_FAIL] <SUB_CODE>: <message>" at line start;
#: the message is where producer-controlled values land. Anchoring on the
#: marker makes POSITION authoritative, and the allowlist + singleton rule
#: below makes a producer-injected second marker line ambiguous rather than
#: decisive.
_SUB_CODE_RE = re.compile(r"^\[YIELD_REDER_FAIL\]\s+([A-Z0-9_]+):", re.MULTILINE)
_PACK_SUB_CODES = frozenset({"YIELD_ATTRIBUTION_MISMATCH"})


class YieldFusionReDerivationCheck:
    name: str = "yield_fusion_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/sensor_stream.json",
            "payload/fusion_weights.json",
            "payload/yield_forecast.json",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "yield_fusion_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "yield_fusion_re_derivation.py not found alongside "
                    "YieldFusionReDerivationCheck.py; pilot opted out of C6"
                ),
                files_audited=(),
            )

        stream_path = bundle_dir / "inputs" / "sensor_stream.json"
        forecast_path = bundle_dir / "payload" / "yield_forecast.json"
        weights_path = bundle_dir / "payload" / "fusion_weights.json"

        if not stream_path.exists() or not forecast_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_INPUTS",
                detail=(
                    "inputs/sensor_stream.json or payload/yield_forecast.json "
                    "absent — no sensor records to re-derive"
                ),
                files_audited=(),
            )

        files_audited = (str(stream_path), str(forecast_path), str(weights_path))

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
                detail="yield_fusion_re_derivation.py exceeded 60 s timeout",
                files_audited=files_audited,
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail="yield_fusion_re_derivation.py exited 0 — yield forecast verified",
                files_audited=files_audited,
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        # The pack's own error text carries a dedicated sub-code as a prefix
        # (e.g. "YIELD_ATTRIBUTION_MISMATCH: ...") for failure kinds that are
        # distinguishable from a plain numeric re-derivation mismatch. Surface
        # that sub-code as THIS plugin's reason_code when present; fall back to
        # the generic mismatch code otherwise. A BundleVerifier consumer sees it
        # on the verdict face, because the verifier propagates a failing
        # plugin's reason_code (see NOTE above) -- this comment used to say the
        # opposite, 90 lines below the NOTE it points at.
        # Promote the pack's sub-code ONLY when it sits where the PACK puts
        # it -- immediately after its own "[YIELD_REDER_FAIL] " marker at the
        # start of a line -- and only when exactly one allowlisted sub-code is
        # named. The previous form was a bare `sub_code in stderr_snippet`
        # substring test over a string the pack interpolates PRODUCER values
        # into ('{field}' mismatch, the sensor values), so a producer who put
        # the literal "YIELD_ATTRIBUTION_MISMATCH" in a payload field could
        # choose this plugin's reason code -- and since 2026-08-30 that code
        # reaches the verdict face. Same defect class as the unbounded regex
        # in a sibling pilot's citation wrapper, found in the same pass.
        # A pack that DIED compared nothing: route it to a could-not-conclude
        # leg BEFORE promoting any sub-code, so a traceback never surfaces as
        # a comparator refusal.
        _crash_code, _incomplete = classify_pack_failure(stderr_snippet)
        if _incomplete:
            return PluginResult(
                ok=False,
                reason_code=_crash_code,
                incomplete=True,
                detail=stderr_snippet,
                files_audited=files_audited,
            )
        named = {c for c in _SUB_CODE_RE.findall(stderr_snippet)} & _PACK_SUB_CODES
        reason_code = named.pop() if len(named) == 1 else "RE_DERIVATION_MISMATCH"
        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=stderr_snippet,
            files_audited=files_audited,
        )


register_typed_check("yield_fusion_re_derivation")
