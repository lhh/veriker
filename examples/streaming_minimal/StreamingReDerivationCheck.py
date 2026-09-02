"""StreamingReDerivationCheck — TypedCheck plugin for event-time tumbling-window re-derivation.

Wraps streaming_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='streaming_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Reason codes emitted:
  RE_DERIVED                           — re-derivation matched checkpoint exactly
  RE_DERIVATION_MISMATCH               — per-window aggregate or count differs from checkpoint
  STREAMING_LATE_EVENT_POLICY_VIOLATED — late_event_policy in spec is not "drop"
  RE_DERIVATION_TIMEOUT                — subprocess exceeded 60 s timeout
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
    """The claim-field elements the pack reported COMPARING, from its last
    `[COMPARED] {"<bundle-relative file>": ["<field path>", ...]}` stdout
    line, rendered against the bundle's OWN declaration: a path under a file
    becomes "<declared payload key>:<path>" only for a file the declaration
    names under `claim_files`. Absent or malformed line, or a file the
    declaration does not name → nothing reported for it (could-not-conclude
    under a declaration), never a guessed constant."""
    lines = [
        line
        for line in (stdout or b"").decode("utf-8", errors="replace").splitlines()
        if line.startswith("[COMPARED] ")
    ]
    # Exactly one line, well-formed — anything else (none, several, malformed)
    # reports nothing rather than picking one.
    if len(lines) != 1:
        return frozenset()
    try:
        compared = json.loads(lines[0][len("[COMPARED] ") :])
    except ValueError:
        return frozenset()
    if not (
        isinstance(compared, dict)
        and all(
            isinstance(k, str)
            and isinstance(v, list)
            and all(isinstance(p, str) for p in v)
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


class StreamingReDerivationCheck:
    name: str = "streaming_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"events/", "payload/checkpoint.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "streaming_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "streaming_re_derivation.py not found alongside "
                    "StreamingReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        stream_path = bundle_dir / "events" / "stream.jsonl"
        checkpoint_path = bundle_dir / "payload" / "checkpoint.json"

        if not stream_path.exists() or not checkpoint_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "events/stream.jsonl or payload/checkpoint.json absent "
                    "— no streaming output to re-derive"
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
                detail="streaming_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(stream_path), str(checkpoint_path)),
            )

        if result.returncode == 0:
            # Claimset coverage accounting: report exactly the claim fields
            # the pack's [COMPARED] line says it bound on this run — ONLY on
            # the full re-derivation pass. The NO_PACK / NO_PAYLOAD
            # early-outs above compare nothing and report nothing, so under
            # a declared claimset they surface as could-not-conclude, never
            # a silent pass. payload/checkpoint.json is already in
            # files_audited.
            if not result.stdout or b"[COMPARED] " not in result.stdout:
                # Defensive: _verify() has no opt-out branch today (every
                # non-error exit is a full compare, so this line is
                # currently unreachable), kept for parity with the audited
                # credit_scoring shape and as a guard against a future
                # regression that adds one — an exit 0 with no [COMPARED]
                # line must never read as "re-derived successfully".
                return PluginResult(
                    ok=True,
                    incomplete=True,
                    reason_code="RE_DERIVATION_NOT_COMPARED",
                    detail=(
                        "streaming_re_derivation.py exited 0 without a "
                        "[COMPARED] line — nothing was compared; could not "
                        "conclude"
                    ),
                    files_audited=(str(stream_path), str(checkpoint_path)),
                )
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(
                    "streaming_re_derivation.py exited 0 — all per-window aggregate "
                    "states verified against bundled checkpoint"
                ),
                files_audited=(str(stream_path), str(checkpoint_path)),
                verified_claim_fields=_claim_fields_from_stdout(
                    result.stdout, getattr(manifest, "claimset", None)
                ),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Distinguish late-event-policy violation from general mismatch
        if "STREAMING_LATE_EVENT_POLICY_VIOLATED" in stderr_snippet:
            reason_code = "STREAMING_LATE_EVENT_POLICY_VIOLATED"
        else:
            reason_code = "RE_DERIVATION_MISMATCH"

        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=stderr_snippet,
            files_audited=(str(stream_path), str(checkpoint_path)),
        )


register_typed_check("streaming_re_derivation")
