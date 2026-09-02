"""ContentProvenanceReDerivationCheck — TypedCheck plugin for content provenance domain.

Wraps content_provenance_re_derivation.py via subprocess (AB4 — duplicate-don't-import).
Emits CONTENT_PROVENANCE_VERIFIED on pass; CONTENT_PROVENANCE_ALTERED /
CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH / CONTENT_PROVENANCE_STATUS_MISMATCH on
failure; RE_DERIVATION_NOT_COMPARED (incomplete, could-not-conclude) when the
pack exits 0 without its [COMPARED] line.

The check:
  1. Re-hashes artifact/content.txt and asserts the SHA matches the producer-signed
     manifest and the payload's committed content_sha.
  2. Re-computes the producer HMAC over the content bytes + the manifest core
     (every manifest field except the signature) and asserts it matches the
     hmac field in artifact/provenance.json.
  3. Asserts the payload's OWN producer_hmac claim (payload/provenance_result.json)
     also equals the re-derived HMAC — a distinct committed value from
     artifact/provenance.json, independently bound (CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH).
  4. Asserts the provenance chain (producer_id + generation_inputs) is intact.
  5. Asserts the payload's stated provenance_status equals the re-derived one.

Claim-field coverage: on the full-compare pass the plugin reports
`verified_claim_fields` for exactly the fields the pack's `[COMPARED]` stdout
line names (rendered against the bundle's declared payload key), never a
constant in this wrapper.

SCOPE BOUNDARY:
This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.

§C6 (re-derivation) + §C5 (auditor independence).
name='content_provenance_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

# §C5 auditor-independence: locate pkg root relative to this file.
# Layout: examples/content_provenance_minimal/ContentProvenanceReDerivationCheck.py
#         → parents[2] = pkg root
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))


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


class ContentProvenanceReDerivationCheck:
    name: str = "content_provenance_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"payload/"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "content_provenance_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    "content_provenance_re_derivation.py not found alongside "
                    "ContentProvenanceReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        payload_path = bundle_dir / "payload" / "provenance_result.json"
        if not payload_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PAYLOAD",
                detail="payload/provenance_result.json absent — no provenance result to re-derive",
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
                reason_code="CONTENT_PROVENANCE_ALTERED",
                detail="content_provenance_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(payload_path),),
            )

        if result.returncode == 0:
            if not result.stdout or b"[COMPARED] " not in result.stdout:
                # Exit 0 without the line means the pack compared nothing
                # (its payload-absent opt-out). Could-not-conclude, never a
                # "verified" leg.
                return PluginResult(
                    ok=True,
                    incomplete=True,
                    reason_code="RE_DERIVATION_NOT_COMPARED",
                    detail=(
                        "content_provenance_re_derivation.py exited 0 without a "
                        "[COMPARED] line — nothing was compared; could not conclude"
                    ),
                    files_audited=(str(payload_path),),
                )
            # Claimset coverage accounting: exactly the fields the pack's
            # [COMPARED] line says it bound on this run, rendered against the
            # bundle's declared payload key — ONLY on the full-compare pass.
            # The NO_PACK / NO_PAYLOAD early-outs above report nothing, so under
            # a declared claimset they surface as could-not-conclude, never a
            # silent pass. payload/provenance_result.json is in files_audited.
            return PluginResult(
                ok=True,
                reason_code="CONTENT_PROVENANCE_VERIFIED",
                detail=(
                    "content_provenance_re_derivation.py exited 0 — "
                    "content_sha, provenance_sha, producer_hmac, provenance chain "
                    "and provenance_status all verified"
                ),
                files_audited=(str(payload_path),),
                verified_claim_fields=_claim_fields_from_stdout(
                    result.stdout, getattr(manifest, "claimset", None)
                ),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        if "CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH" in stderr_snippet:
            reason = "CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH"
        elif "CONTENT_PROVENANCE_STATUS_MISMATCH" in stderr_snippet:
            reason = "CONTENT_PROVENANCE_STATUS_MISMATCH"
        else:
            reason = "CONTENT_PROVENANCE_ALTERED"
        return PluginResult(
            ok=False,
            reason_code=reason,
            detail=stderr_snippet,
            files_audited=(str(payload_path),),
        )


register_typed_check("content_provenance_re_derivation")
