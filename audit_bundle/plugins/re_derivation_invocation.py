"""audit_bundle/plugins/re_derivation_invocation.py — TypedCheck: re-derivation invocation (C6).

Implements the audit-bundle contract §C6 (generic shape).
Invokes a domain-specific re-derivation pack script (e.g. energy_score_pack.py
or span_re_derivation.py) from the bundle's re_derive/ directory.  The pack is
responsible for recomputing values from raw inputs and asserting they match the
bundled outputs; this plugin only invokes it.

⚠️  SECURITY — this check runs BUNDLE-SUPPLIED Python in the verifier process.
A re-derivation pack ships inside the (potentially untrusted) bundle; invoking
it is arbitrary local code execution. For untrusted bundles this is unsafe — a
malicious pack can read/write files, spawn subprocesses, or simply `exit(0)`
without re-deriving anything (the producer would be grading its own homework).
The SAFE re-derivation path is spec-pinned dispatch (audit_bundle/rederivation/):
recompute primitives are verifier-distribution code, registry-resident, never
bundle-supplied — see that package's THREAT_MODEL.md.

Because of that, `permit_execution` is a REQUIRED keyword with no default: every
construction site must state the trust decision explicitly. veriker/cli/verify.py wires
it to the opt-in `--unsafe-run-bundle-pack` flag (default OFF), so the default
verify path NEVER executes a bundle pack. See SECURITY.md
"Code execution in the verify path".

If no pack is present the domain pilot opted out of C6 → ok, NO_PACK.
Stdlib only.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

# Emitted when a pack is present but execution was not permitted (the safe
# default). COULD-NOT-CONCLUDE semantics: the result carries incomplete=True
# (never a silent RE_DERIVED), so verify() records a clean-ERROR leg — the core
# property is unverified, not passed. This is NOT a REJECT (the artifact is not
# shown bad); it composes ERROR (exit 2). Mirrors the register_receipt_verifier
# "NOT_EVALUATED" posture.
NOT_EXECUTED_REASON: str = "RE_DERIVATION_NOT_EXECUTED"


class ReDerivationInvocationCheck:
    name: str = "re_derivation_invocation"
    # exact-path-only: the former {"re_derive/"} trailing-slash pseudo-prefix
    # was inert (consumed by exact match, never matched a real path). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, pack_filename: str, *, permit_execution: bool) -> None:
        # permit_execution is REQUIRED (no default): invoking a bundle-supplied
        # pack runs arbitrary local code in the verifier process, so the trust
        # decision must be stated at every call site rather than inherited.
        self.pack_filename = pack_filename
        self.permit_execution = permit_execution

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = bundle_dir / "re_derive" / self.pack_filename

        if not pack_path.exists():
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="NO_PACK",
                detail=(
                    f"re-derivation pack {self.pack_filename!r} not found in "
                    f"re_derive/; domain pilot opted out of C6"
                ),
                files_audited=(),
            )

        if not self.permit_execution:
            return PluginResult(
                ok=True,
                # incomplete=True: present-but-unverified is COULD-NOT-CONCLUDE,
                # not a pass. verify() records a clean-ERROR leg so a LIBRARY
                # consumer (not just the CLI) sees the bundle's core property was
                # left unverified — closes the verdict-laundering seam (ADV-01):
                # ok=True alone made BundleVerifier.verify() return OK while the
                # CLI gated exit 2. The CLI's RE_DERIVATION_NOT_EXECUTED gate now
                # derives from this verdict (one semantics, not two).
                incomplete=True,
                reason_code=NOT_EXECUTED_REASON,
                detail=(
                    f"re-derivation pack {self.pack_filename!r} present but NOT "
                    f"executed (safe default): invoking it runs bundle-supplied "
                    f"Python in the verifier process, unsafe for untrusted "
                    f"bundles. Re-derivation was NOT verified — do not read a "
                    f"PASS verdict as covering it. Use spec-pinned dispatch "
                    f"(manifest.outputs + auditor SpecAnchor) for safe "
                    f"re-derivation, or pass --unsafe-run-bundle-pack to execute "
                    f"on a trusted producer / disposable host."
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
                detail=(
                    f"re-derivation pack {self.pack_filename!r} exceeded 60 s timeout"
                ),
                files_audited=(str(pack_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(f"re-derivation pack {self.pack_filename!r} exited 0"),
                files_audited=(str(pack_path),),
                # REPORTING ONLY — never treated as re-derivation coverage.
                # This records that the pack ran to a clean exit, which is all
                # this plugin can observe: per the SECURITY note at the top of
                # this file a pack can `exit(0)` without re-deriving anything.
                # _step_rederivation_surface_guard names the run in its
                # disclosure and still reports NO_RE_DERIVATION_PERFORMED.
                verified_rederivation_packs=frozenset({self.pack_filename}),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        # A pack that DIED compared nothing; only a pack that refused did.
        reason_code, incomplete = classify_pack_failure(stderr_snippet)
        return PluginResult(
            ok=False,
            reason_code=reason_code,
            incomplete=incomplete,
            detail=stderr_snippet,
            files_audited=(str(pack_path),),
        )



#: Marker of an UNCAUGHT Python exception on a pack's stderr. A pack that died
#: this way did not compare anything, so reporting its failure as
#: RE_DERIVATION_MISMATCH -- whose documented meaning is "the recompute ran and
#: DISAGREED" (audit_bundle/rederivation/reason_codes.py) -- states something no
#: execution supports, and credits the claim-field ratchet with coverage that
#: was never proven.
_TRACEBACK_MARKER = "Traceback (most recent call last):"


def classify_pack_failure(stderr_snippet: str) -> "tuple[str, bool]":
    """(reason_code, incomplete) for a pack that exited non-zero.

    A crashed pack is a COULD-NOT-CONCLUDE, not a REJECT: it has shown nothing
    about the artifact. It therefore returns `incomplete=True`, which routes
    through Verdict.incomplete (clean-ERROR, exit 2) rather than the REJECT
    path -- fail-closed either way, but honestly labelled.

    A non-zero exit with no traceback is the pack's own refusal, and keeps
    RE_DERIVATION_MISMATCH.

    The detection is one-directional on purpose: producer bytes reaching stderr
    could contain the marker and downgrade a real mismatch to
    could-not-conclude. That direction withdraws a claim rather than
    manufacturing one, so it is the safe way to be wrong.
    """
    if _TRACEBACK_MARKER in stderr_snippet:
        return "RE_DERIVATION_NOT_COMPARED", True
    return "RE_DERIVATION_MISMATCH", False

register_typed_check("re_derivation_invocation")
