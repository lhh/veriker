"""BuildReDerivationCheck — TypedCheck plugin for deterministic build/recipe re-derivation.

Wraps build_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='build_re_derivation'
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

class BuildReDerivationCheck:
    name: str = "build_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "sources/",
        "recipe/build_recipe.json",
        "payload/artifacts/",
    })

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "build_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "build_re_derivation.py not found alongside BuildReDerivationCheck.py; "
                    "domain pilot opted out"
                ),
                files_audited=(),
            )

        recipe_path = bundle_dir / "recipe" / "build_recipe.json"
        sources_dir = bundle_dir / "sources"
        artifacts_dir = bundle_dir / "payload" / "artifacts"

        if not recipe_path.exists() or not sources_dir.is_dir() or not artifacts_dir.is_dir():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "recipe/build_recipe.json, sources/, or payload/artifacts/ absent — "
                    "no build to re-derive"
                ),
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
                detail="build_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(recipe_path),),
            )

        if result.returncode == 0:
            # Claimset coverage accounting: the pack prints the files it
            # byte-compared ([COMPARED] line). Report the opaque key(s) whose
            # DECLARED path is in that set (never a constant key — coverage
            # follows what the pack reported comparing), and list those files
            # so the gate's file-audit fold can see the report names them. Reported ONLY on a full pass; the NO_PACK / NO_PAYLOAD
            # early-outs report nothing and surface as could-not-conclude.
            compared = _compared_from_stdout(result.stdout)
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail="build_re_derivation.py exited 0 — final artifact bytes match",
                files_audited=(str(recipe_path), *(str(bundle_dir / rel) for rel in sorted(compared))),
                verified_claim_fields=opaque_keys_for_paths(
                    getattr(manifest, "claimset", None), compared
                ),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        # A pack that DIED (uncaught exception) compared nothing, so it must
        # not report RE_DERIVATION_MISMATCH -- "the recompute ran and
        # DISAGREED". classify_pack_failure routes a traceback to a
        # could-not-conclude leg instead, which is what the claim-field
        # ratchet needs to stop crediting a crash as proven coverage.
        _code, _incomplete = classify_pack_failure(stderr_snippet)
        return PluginResult(
            ok=False,
            reason_code=_code,
            incomplete=_incomplete,
            detail=stderr_snippet,
            files_audited=(str(recipe_path),),
        )


register_typed_check("build_re_derivation")
