"""BuildPyReDerivationCheck — TypedCheck plugin for deterministic Python compiler re-derivation.

Wraps build_py_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

The substrate claim: V-Kernel re-derivation extends to **actual deterministic
compilation** — re-compiling committed .py sources with py_compile under
SOURCE_DATE_EPOCH=0 + PycInvalidationMode.CHECKED_HASH yields byte-identical
.pyc output, anchored by the recipe's `cache_tag` (interpreter family + version).

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='build_py_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import re

import subprocess
import sys
import json
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.re_derivation_invocation import classify_pack_failure

_CODE_RE = re.compile(r"^\[BUILD_PY_REDER_FAIL\]\s+([A-Z0-9_]+):", re.MULTILINE)
_PACK_CODES = frozenset({"BUILD_PY_TOOLCHAIN_MISMATCH"})
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

class BuildPyReDerivationCheck:
    name: str = "build_py_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "sources/",
        "recipe/build_recipe.json",
        "payload/artifacts/",
    })

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "build_py_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "build_py_re_derivation.py not found alongside BuildPyReDerivationCheck.py; "
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
                    "no compiled artifacts to re-derive"
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
                detail="build_py_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(recipe_path),),
            )

        if result.returncode == 0:
            # Claimset coverage accounting: the pack byte-compared every
            # recipe source's recompiled .pyc against the bundled one. Report
            # the opaque keys whose DECLARED path is among those compared
            # files (never a constant key), and list the compared files for
            # the gate's file-audit fold. Reported ONLY on a full pass.
            compared = _compared_from_stdout(result.stdout)
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(
                    "build_py_re_derivation.py exited 0 — "
                    "all .pyc bytes match re-compiled output"
                ),
                files_audited=(str(recipe_path), *(str(bundle_dir / rel) for rel in sorted(compared))),
                verified_claim_fields=opaque_keys_for_paths(
                    getattr(manifest, "claimset", None), compared
                ),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Classify by the code the PACK named, at the position the pack prints
        # it: "[BUILD_PY_REDER_FAIL] <CODE>: <message>" at line start. The
        # previous form was a bare substring test over a snippet the pack
        # interpolates producer-controlled recipe values into, so a producer
        # could select this plugin's reason code by embedding the literal --
        # and since 2026-08-30 that code reaches the verdict face. Singleton
        # rule: an injected second marker line is ambiguous, not decisive.
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
                files_audited=(str(recipe_path),),
            )
        named = {c for c in _CODE_RE.findall(stderr_snippet)} & _PACK_CODES
        reason_code = named.pop() if len(named) == 1 else "RE_DERIVATION_MISMATCH"

        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=stderr_snippet,
            files_audited=(str(recipe_path),),
        )


register_typed_check("build_py_re_derivation")
