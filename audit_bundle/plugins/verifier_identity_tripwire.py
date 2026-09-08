"""C18 verifier-identity tripwire plugin.

This plugin's PASS verdict is NOT a trust assertion about the running
verifier identity. Host-side digest verification (veriker/cli/host_digest_verify.py:
cosign manifest / crane digest against the TUF-fetched expected digest) is
the actual trust mechanism. The in-container self-check is a LOGGING-ONLY
tripwire signal that surfaces VERIFIER_IDENTITY_DIVERGENCE onto the verdict
face (``Completeness.disclosures``) when the producer-reported self-check
diverged from the bundled official digest.

Per the audit-bundle contract §C18, the plugin implements step 1 (structural
integrity) and step 2 (tripwire signal surfacing) of the verifier-identity
verification logic.

This framing defends against a compromised container runtime that returns a
spoofed self-reported digest: the tripwire surfaces the divergence to
consumers via the verdict's disclosure channel, while the host-side check
(above) is what actually establishes trust.

READ-ONLY INVARIANT (2026-06-10): verify() never writes inside bundle_dir.
An earlier revision appended the tripwire event to ``bundle_dir/events.jsonl``;
that predated the conservation gate, whose on-disk ∪ declared universe now
classifies a verifier-written ``events.jsonl`` as UNOWNED surplus — so the
write flipped a green bundle RED on re-verification (verifier self-poisoning,
breaking re-run determinism). The signal now rides ``PluginResult.disclosures``
→ ``Completeness.disclosures``, the same verdict-face channel the C19
assurance residuals use, which reaches library consumers as well as the CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle.extensions.c18_verifier_identity import (
    REASON_BLOCK_MALFORMED,
    self_check_tripwire,
    verify_verifier_identity_structural,
)
from audit_bundle.plugin import PluginResult


# Disclosure kind surfaced on the verdict face on tripwire fire. (Historic
# name retained: pre-read-only revisions emitted this as an events.jsonl row
# kind; it is now the machine-greppable token inside the disclosure string.)
EVENT_KIND_VERIFIER_IDENTITY_DIVERGENCE = "VERIFIER_IDENTITY_DIVERGENCE"


class VerifierIdentityTripwireCheck:
    """C18 verifier_identity structural verifier + self-check tripwire signal.

    Returns PluginResult per the audit-bundle contract §C18:

      - Bundle with NO verifier_identity field (legacy / pre-C18):
            ok=True, detail='no verifier_identity field present (pre-C18 bundle)'

      - Structural verification fails (e.g. malformed OCI digest):
            ok=False, reason_code=<first reason>, detail=<descriptive>

      - Structural verification passes AND verifier_self_check_status == 'failed':
            * Surfaces a VERIFIER_IDENTITY_DIVERGENCE disclosure on the result
              (→ Verdict.completeness.disclosures); bundle_dir is NOT written
            * RETURNS ok=True with detail naming the disclosure
            * CRITICAL: ok=True even when tripwire fires, because the
              tripwire is a LOGGING-ONLY SIGNAL. The trust assertion is made
              host-side and consumer-side, not here — the plugin DOES NOT
              block on tripwire fire.

      - Structural verification passes AND status ∈ {'passed', 'skipped'}:
            ok=True, detail names the status with the tripwire-not-trust caveat.
    """

    name: str = "verifier_identity_tripwire"
    applies_to_files: frozenset[str] = frozenset()  # operates on manifest fields

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # Step 1: structural verification (no network, no TUF fetch).
        reasons = verify_verifier_identity_structural(bundle_dir, manifest)

        # Step 1a: legacy bundle (no verifier_identity field) — clean PASS.
        state, block = _locate_verifier_identity(manifest)
        if state == VI_MALFORMED:
            # Present but unparseable — never the legacy path (row 20).
            return PluginResult(
                ok=False,
                reason_code=REASON_BLOCK_MALFORMED,
                detail=(
                    "evidence.verifier_identity is present but is not an "
                    "object; a malformed block is a producer-authored fact "
                    "about this bundle, not an absent one"
                ),
                files_audited=tuple(),
            )
        if state == VI_ABSENT:
            return PluginResult(
                ok=True,
                reason_code=None,
                detail="no verifier_identity field present (pre-C18 bundle)",
                files_audited=tuple(),
            )

        # Step 1b: structural verification surfaced reason codes — FAIL.
        if reasons:
            return PluginResult(
                ok=False,
                reason_code=reasons[0],
                detail=(
                    f"verifier_identity structural verification failed: "
                    f"reasons={reasons}"
                ),
                files_audited=tuple(),
            )

        # Step 2: self-check tripwire signal (logging-only).
        status = block.get("verifier_self_check_status")
        if status == "failed":
            # Tripwire FIRES: surface VERIFIER_IDENTITY_DIVERGENCE on the
            # verdict face. CRITICAL: still returns ok=True — the plugin does
            # NOT block — and bundle_dir is NOT written (read-only invariant).
            tripwire_result = self_check_tripwire(
                running_oci_digest=None,  # producer-supplied; substrate cannot recompute here
                bundled_oci_digest=block.get("verifier_oci_digest", ""),
            )
            disclosure = (
                f"{self.name}: {EVENT_KIND_VERIFIER_IDENTITY_DIVERGENCE} — "
                + json.dumps(
                    {
                        "reported_self_check_status": status,
                        "verifier_oci_digest": block.get("verifier_oci_digest", ""),
                        "verifier_release_id": block.get("verifier_release_id", ""),
                        "tripwire_result": tripwire_result,
                        "note": (
                            "Producer-reported self_check_status=failed. This is a "
                            "TRIPWIRE signal, NOT a trust assertion. Run the host-side "
                            "digest check (host_digest_verify) to investigate. The full "
                            "4-step consumer flow (receipts.vkernel.dev) is pre-ceremony "
                            "and not yet live."
                        ),
                    },
                    sort_keys=True,
                )
            )
            return PluginResult(
                ok=True,  # LOGGING-ONLY signal — do NOT block
                reason_code=None,
                detail=(
                    "tripwire fired — verifier_self_check_status='failed' surfaced "
                    "as a VERIFIER_IDENTITY_DIVERGENCE disclosure on the verdict "
                    "face. The tripwire is a signal, not a trust assertion."
                ),
                files_audited=tuple(),
                disclosures=(disclosure,),
            )

        # status in {'passed', 'skipped'} — clean PASS.
        return PluginResult(
            ok=True,
            reason_code=None,
            detail=(
                f"verifier_identity structurally valid; self-check "
                f"status={status!r} (tripwire signal, not trust assertion)"
            ),
            files_audited=tuple(),
        )


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------



# --- Tri-state locator (THREAT_MODEL row 20) -------------------------------
# ABSENT may pass; MALFORMED must never share a return value with ABSENT.
# `_extract_verifier_identity_block` returned `dict | None` and collapsed both
# into None, while every caller reads None as "legacy pre-C18 bundle -> clean
# PASS". A producer therefore skipped every C18 structural check by making the
# field any non-dict, and the gradient rewarded it: a well-formed-but-INCOMPLETE
# block drew 7 blocking reasons, a MALFORMED one passed clean.
#
# This helper is HAND-DUPLICATED into plugins/verifier_identity_tripwire.py (to
# avoid an import cycle through the plugin loader). Nothing but
# tests/c18/test_c18_malformed_block_tristate.py::
# test_the_two_hand_maintained_copies_agree holds the copies in agreement —
# they have drifted before. Change both, or the guard fails.
VI_FOUND = "FOUND"
VI_ABSENT = "ABSENT"
VI_MALFORMED = "MALFORMED"


def _locate_verifier_identity(manifest: object) -> tuple[str, dict | None]:
    """Locate `evidence.verifier_identity`, distinguishing three outcomes.

    Returns ``(VI_FOUND, block)`` / ``(VI_ABSENT, None)`` / ``(VI_MALFORMED,
    None)``.

    ABSENT means the producer said nothing — a legacy bundle, which passes.
    MALFORMED means the producer said something the verifier cannot parse. That
    is a determinate finding about the artifact's own bytes, not an incapacity,
    so it is REJECT-side (precedent: CLAIMED_VALUE_MALFORMED, MalformedSpec —
    NOT the operator-omission rows 10/17).

    `None` is treated as ABSENT, not MALFORMED: a dataclass field declared
    ``verifier_identity: dict | None = None`` legitimately means "unset".
    Every OTHER non-dict value is a producer statement that failed to parse.
    """
    # Attribute style (BundleManifest dataclass and friends).
    evidence = getattr(manifest, "evidence", None)
    if evidence is not None and not isinstance(evidence, dict):
        vi = getattr(evidence, "verifier_identity", None)
        if isinstance(vi, dict):
            return VI_FOUND, vi
        if vi is not None:
            return VI_MALFORMED, None

    # Dict style (raw JSON manifest).
    if isinstance(manifest, dict):
        if "evidence" in manifest:
            evidence = manifest["evidence"]
            if isinstance(evidence, dict):
                if "verifier_identity" in evidence:
                    vi = evidence["verifier_identity"]
                    if isinstance(vi, dict):
                        return VI_FOUND, vi
                    if vi is not None:
                        return VI_MALFORMED, None
            elif evidence is not None:
                # The same degradation ONE LEVEL UP: an unparseable `evidence`
                # hides verifier_identity just as effectively.
                return VI_MALFORMED, None

    # Top-level fallback.
    vi = getattr(manifest, "verifier_identity", None)
    if isinstance(vi, dict):
        return VI_FOUND, vi
    if vi is not None:
        return VI_MALFORMED, None

    return VI_ABSENT, None
