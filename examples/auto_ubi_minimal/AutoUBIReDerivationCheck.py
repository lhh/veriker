"""AutoUBIReDerivationCheck — TypedCheck plugin for UBI telematics re-derivation (C6).

Wraps auto_ubi_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='auto_ubi_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.re_derivation_invocation import classify_pack_failure


def _claim_fields_from_stdout(stdout: bytes, claimset: object) -> frozenset[str]:
    """The claim-field elements the pack reported COMPARING, from its single
    `[COMPARED] {"<bundle-relative file>": ["<field path>", ...]}` stdout line,
    rendered against the bundle's OWN declaration: a path under a file becomes
    "<declared payload key>:<path>" only for a file the declaration names under
    `claim_files`. Exactly one well-formed line is required — none, several, or
    malformed → nothing reported (could-not-conclude under a declaration),
    never a guessed constant."""
    lines = [
        line
        for line in (stdout or b"").decode("utf-8", errors="replace").splitlines()
        if line.startswith("[COMPARED] ")
    ]
    if len(lines) != 1:
        return frozenset()
    try:
        compared = json.loads(lines[0][len("[COMPARED] ") :])
    except ValueError:
        return frozenset()
    if not (
        isinstance(compared, dict)
        and all(
            isinstance(k, str) and isinstance(v, list) and all(isinstance(p, str) for p in v)
            for k, v in compared.items()
        )
    ):
        return frozenset()
    if not compared or not isinstance(claimset, dict):
        return frozenset()
    claim_files = claimset.get("claim_files")
    if not isinstance(claim_files, dict):
        return frozenset()
    elements: set[str] = set()
    for key, rel in claim_files.items():
        if not isinstance(rel, str):
            continue
        for path in compared.get(Path(rel).as_posix(), ()):
            elements.add(f"{key}:{path}")
    return frozenset(elements)


class AutoUBIReDerivationCheck:
    name: str = "auto_ubi_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"telematics/", "payload/rating_decisions.json", "payload/rate_table.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "auto_ubi_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "auto_ubi_re_derivation.py not found alongside "
                    "AutoUBIReDerivationCheck.py; domain pilot opted out of "
                    "UBI re-derivation"
                ),
                files_audited=(),
            )

        dec_path = bundle_dir / "payload" / "rating_decisions.json"
        if not dec_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/rating_decisions.json absent — no UBI rating "
                    "decisions to re-derive"
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
                detail="auto_ubi_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(dec_path),),
            )

        if result.returncode == 0:
            if not result.stdout or b"[COMPARED] " not in result.stdout:
                # Exit 0 without the line means the pack compared nothing
                # (its opt-out branches). Could-not-conclude, never a
                # "verified" leg.
                return PluginResult(
                    ok=True,
                    incomplete=True,
                    reason_code="RE_DERIVATION_NOT_COMPARED",
                    detail=(
                        "auto_ubi_re_derivation.py exited 0 without a [COMPARED] "
                        "line — nothing was compared; could not conclude"
                    ),
                    files_audited=(str(dec_path),),
                )
            # Claimset coverage accounting: report exactly the claim fields
            # the pack's [COMPARED] line says it bound on this run (rendered
            # against the bundle's declared payload key) — ONLY on the full
            # re-derivation pass. The NO_PACK / NO_PAYLOAD early-outs above
            # compare nothing and report nothing, so under a declared
            # claimset they surface as could-not-conclude, never a silent
            # pass. payload/rating_decisions.json is already in files_audited.
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(
                    "auto_ubi_re_derivation.py exited 0 — all UBI telematics "
                    "rating invariants verified"
                ),
                files_audited=(str(dec_path), str(bundle_dir / "payload" / "rate_table.json")),
                verified_claim_fields=_claim_fields_from_stdout(
                    result.stdout, getattr(manifest, "claimset", None)
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
            files_audited=(str(dec_path),),
        )


register_typed_check("auto_ubi_re_derivation")
