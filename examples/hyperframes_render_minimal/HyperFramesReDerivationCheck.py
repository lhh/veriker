"""HyperFramesReDerivationCheck — TypedCheck plugin for HyperFrames render re-derivation.

Wraps hyperframes_re_derivation.py via subprocess, mirroring the AudioReDerivationCheck
and BuildPyReDerivationCheck patterns. Distinguishes toolchain mismatch
(HYPERFRAMES_TOOLCHAIN_MISMATCH) from re-derivation mismatch
(RE_DERIVATION_MISMATCH) so the two failure modes don't get conflated
in failure detail.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='hyperframes_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.re_derivation_invocation import classify_pack_failure
from audit_bundle.claimset import opaque_keys_for_paths


def _compared_from_stdout(stdout: bytes) -> frozenset[str]:
    """The bundle-relative files the pack reported BYTE-COMPARING, from its
    last `[COMPARED] <json list>` stdout line. Absent or malformed → empty
    set → this check reports no claimset coverage (could-not-conclude under a
    declaration), never a guessed constant."""
    compared: frozenset[str] = frozenset()
    for line in (stdout or b"").decode("utf-8", errors="replace").splitlines():
        if line.startswith("[COMPARED] "):
            try:
                rels = json.loads(line[len("[COMPARED] ") :])
            except ValueError:
                continue
            if isinstance(rels, list) and all(isinstance(r, str) for r in rels):
                compared = frozenset(rels)
    return compared

class HyperFramesReDerivationCheck:
    name: str = "hyperframes_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "source/index.html",
        "source/hyperframes.json",
        "source/package.json",
        "payload/output.mp4",
        "spec/tooling.json",
    })

    # Re-render budget: blank scaffold renders ~8s; we allow up to 120s to absorb
    # cold-cache npx package resolution + first-run Chrome download cycles.
    _TIMEOUT_SECONDS = 120

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "hyperframes_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "hyperframes_re_derivation.py not found alongside "
                    "HyperFramesReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        mp4_path = bundle_dir / "payload" / "output.mp4"
        index_path = bundle_dir / "source" / "index.html"
        spec_path = bundle_dir / "spec" / "tooling.json"
        if not (mp4_path.exists() and index_path.exists() and spec_path.exists()):
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/output.mp4, source/index.html, or spec/tooling.json "
                    "absent — no HyperFrames render to re-derive"
                ),
                files_audited=(),
            )

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=self._TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="RE_DERIVATION_TIMEOUT",
                detail=(
                    f"hyperframes_re_derivation.py exceeded "
                    f"{self._TIMEOUT_SECONDS} s timeout"
                ),
                files_audited=(str(mp4_path), str(index_path), str(spec_path)),
                # ran cleanly, could not conclude — an environment limit is
                # never a refusal of the artifact (and never a battery "flip")
                incomplete=True,
            )

        if result.returncode == 0:
            # Claimset coverage accounting: report the opaque key whose
            # DECLARED path is payload/output.mp4 (never a constant key);
            # the MP4 is already in files_audited. ONLY on a full pass.
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(
                    "hyperframes_re_derivation.py exited 0 — bundled MP4 sha256 == "
                    "committed sha256 == re-rendered MP4 sha256"
                ),
                files_audited=(str(mp4_path), str(index_path), str(spec_path)),
                verified_claim_fields=opaque_keys_for_paths(
                    getattr(manifest, "claimset", None), _compared_from_stdout(result.stdout)
                ),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        # Surface toolchain-mismatch vs re-derivation-mismatch via reason_code
        if "HYPERFRAMES_TOOLCHAIN_MISMATCH" in stderr_snippet:
            reason = "HYPERFRAMES_TOOLCHAIN_MISMATCH"
        elif "HYPERFRAMES_TOOLCHAIN_MISSING" in stderr_snippet:
            reason = "HYPERFRAMES_TOOLCHAIN_MISSING"
        else:
            reason = "RE_DERIVATION_MISMATCH"
        # A toolchain that is missing or not the pinned version is an
        # ENVIRONMENT condition: the pack never read the artifact, so this is
        # could-not-conclude (clean-ERROR), not a refusal — and the tamper
        # battery scores it INCONCLUSIVE rather than crediting a flip.
        environmental = reason != "RE_DERIVATION_MISMATCH"
        return PluginResult(
            ok=False,
            reason_code=reason,
            detail=stderr_snippet,
            files_audited=(str(mp4_path), str(index_path), str(spec_path)),
            incomplete=environmental,
        )


register_typed_check("hyperframes_re_derivation")
