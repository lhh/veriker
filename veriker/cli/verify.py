"""veriker/cli/verify.py — top-level verifier CLI (Canary 4 + W3 + post-W3 + C18 + C19).

Usage
-----
    python veriker/cli/verify.py --bundle-dir <path> [--c18-check]

Constructs a default plugin set conditional on what the bundle directory
contains, runs BundleVerifier.verify(), and prints one line per check.

Default plugins include the post-W3 substrate-extension plugins (C14 stamp
lattice, C15 typed-dispatch-record well-formedness, C16 refinement discharge
verifier-set discipline). They are no-op on W3-baseline bundles whose
dispatch_records is empty/absent — see the audit-bundle contract §§C14–C16.

Third-party imports limited to cryptography, jcs, nexi_methodology so offline
auditor independence (§C5) holds.

This CLI is a SEPARATE artifact from the substrate verifier at
audit_bundle/verifier.py. Its C18 + C19 extension checks are implemented with
the standard library only (raw json.loads + re + hashlib — no import of
audit_bundle.extensions.*), so that extension surface can be audited in
isolation. The file as a whole is NOT stdlib-only: it imports the audit_bundle
substrate (and through it cryptography + jcs) to run the core verification.
Hold that distinction — "stdlib-only" describes the extension-check code in
this file, not the binary as a whole. The two-verifier split is deliberate and
load-bearing.

Both the C18 and C19 checks are structural-integrity checks on already-fetched
bundle bytes — no network, no out-of-band fetch. A PASS verdict here is a
STRUCTURAL pass; it does not by itself assert trust. A full trust assertion
also needs the 4-step consumer flow (cosign verify-blob + slsa-verifier
verify-image + vkernel-manifest-verify + cosign manifest host-side); the
vkernel-* commands in steps 3-4 are key-signing-ceremony deliverables that are
not yet built, so that chain is synthetic until the ceremony ships. This
offline CLI is the only shipped verifier binary today.

Exit codes: 0 = PASS, 1 = REJECT (artifact rejected), 2 = ERROR (verifier
could not conclude — e.g. an internal error, or a present-but-unverified claim
that must not ride a green exit code). Both 1 and 2 are non-zero, so a caller
keying on `exit != 0` reads either as "not certified".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

# Suppress .pyc generation: the verifier imports plugin modules from inside
# the bundle directory it's verifying (e.g. examples/<pilot>/SpanReDerivation
# Check.py). Without this, CPython drops __pycache__/<mod>.pyc into the bundle,
# which then fails file_integrity_many_small on subsequent runs.
sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402


def _find_pkg_root() -> Path:
    """The directory that CONTAINS `audit_bundle/`, found by walking up.

    Must NOT be a hardcoded parent depth. This file lives at `veriker/cli/verify.py`
    internally but the OSS export relocates it to `veriker/cli/verify.py`, so a
    fixed `parents[1]` resolves to `<drop>/veriker` — which holds no
    `audit_bundle` — and a direct script invocation dies with
    `ModuleNotFoundError` (measured against a real export of master,
    2026-08-29; it accounted for 14 of the drop's 25 test failures). The
    documented entry points `veriker` and `python -m veriker` import through the
    package rather than running this file, which is why the breakage stayed
    invisible.

    Searching the filesystem keeps this correct under ANY relocation, and keeps
    the layout knowledge in one place instead of splitting it between this file
    and an export-time rewrite that would drift.

    Falls back to the historical `parents[1]` so behaviour is unchanged if the
    package is ever laid out in a way the search cannot see; the import below
    then fails loudly, exactly as it does today.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "audit_bundle" / "__init__.py").is_file():
            return candidate
    return here.parents[1]


_PKG_ROOT = _find_pkg_root()
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.bundle_manifest import (  # noqa: E402
    BundleManifest,
    ManifestError,
    is_post_cutover,
)
from audit_bundle.dsse.pae import b64url_nopad_decode  # noqa: E402
from audit_bundle.fragments.fragment_id import BadFragmentID  # noqa: E402
from audit_bundle.manifest_three_set import (  # noqa: E402
    BadVisibilityPolicy,
    ThreeSetMismatch,
)
from audit_bundle.output_modes.mode import BadOutputMode  # noqa: E402
from audit_bundle.source_registry.properties import BadPublicationClass  # noqa: E402
from audit_bundle.verifier import BundleVerifier, VerifyResult, _load_manifest  # noqa: E402
from audit_bundle.verdict import VERIFIER_INCOMPLETE, VerdictState  # noqa: E402

# Verdict-face prefix for the acceptance-rule rows (audit_bundle.verifier).
# Defined here, above its first use in the summary renderer, rather than
# beside the other disclosure prefixes 400 lines down.
_ACCEPTANCE_PREFIX = "acceptance: "
_TYPE_SELECTION_PREFIX = "type_selection: "
from audit_bundle.admission import admit_bytes  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.monotone_growth import MonotoneGrowthCheck  # noqa: E402
from audit_bundle.plugins.falsification_negative_test import (  # noqa: E402
    FalsificationNegativeTestCheck,
)  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.plugins.fragment_attestation import FragmentAttestationCheck  # noqa: E402
from audit_bundle.coverage.sum_invariant_plugin import CoverageSumInvariantCheck  # noqa: E402
from audit_bundle.plugins.source_attributes_consistency import (  # noqa: E402
    SourceAttributesConsistencyCheck,
)  # noqa: E402
from audit_bundle.plugins.three_set_sum_invariant import ThreeSetSumInvariantCheck  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)  # noqa: E402
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.plugins.refinement_discharge import RefinementDischargeCheck  # noqa: E402

# Optional extension-receipt handlers. A manifest may carry extension_receipts
# (see bundle_manifest.register_receipt_verifier); handlers self-register on
# import. The base verifier registers none — a deployment that ships an extension
# handler imports it here-or-elsewhere so it registers. Importing the bootstrap
# is best-effort: when it is absent, no extra handlers register and any extension
# receipt is reported NOT EVALUATED rather than silently passed.
try:  # noqa: E402
    import audit_bundle._receipt_handlers  # noqa: F401
except ImportError:
    pass

# Domain-pilot plugins — imported eagerly so register_typed_check() at module
# bottom runs and the names are visible to validate_manifest §5. Instances are
# constructed in _build_plugins() only when manifest.typed_checks names them.
# Relocated out of examples/ into audit_bundle/plugins/reference/ so the open
# verifier no longer imports from the emitter-bearing example tree (OSS split).
from audit_bundle.plugins.reference.SpanReDerivationCheck import SpanReDerivationCheck  # noqa: E402
from audit_bundle.plugins.reference.SensorReDerivationCheck import (  # noqa: E402
    SensorReDerivationCheck,
)  # noqa: E402
from audit_bundle.plugins.reference.ControlReDerivationCheck import (  # noqa: E402
    ControlReDerivationCheck,
)  # noqa: E402
from audit_bundle.plugins.reference.AgentDryRunCheck import AgentDryRunCheck  # noqa: E402
from audit_bundle.plugins.reference.AIGovReDerivationCheck import (  # noqa: E402
    AIGovReDerivationCheck,
)  # noqa: E402

# Built-in verification steps executed by BundleVerifier before plugin dispatch.
_BUILTIN_STEPS: tuple[str, ...] = (
    "file_integrity",
    "spec_sha_pinning",
    "cross_refs",
)


def _bundle_pack_files(bundle_dir: Path) -> list[Path]:
    """Re-derivation pack scripts present under re_derive/ (sorted, may be empty).

    A *_pack.py is bundle-supplied Python that ReDerivationInvocationCheck would
    execute. Used both to decide whether to construct that check and to emit the
    not-executed disclosure when the unsafe flag is off.
    """
    re_derive = bundle_dir / "re_derive"
    if not re_derive.is_dir():
        return []
    return sorted(re_derive.glob("*_pack.py"))


def _build_plugins(
    bundle_dir: Path,
    manifest: BundleManifest,
    *,
    permit_pack_execution: bool = False,
) -> list:
    """Construct the default plugin set conditional on bundle_dir contents.

    Domain-pilot plugins (span_re_derivation, sensor_re_derivation) are
    constructed only when manifest.typed_checks names them — this keeps the
    BundleVerifier CC2 cross-check happy (every claimed name has an instance)
    without running domain re-derivation against bundles that don't claim it.
    """
    plugins: list = [
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        # L8 fragment attestation — DEFAULT verify path, every bundle (no-op
        # NO_ANCHORS pass when the manifest carries no fragment_anchors). Closes
        # the "fragment anchors are informational" gap: an attestable anchor
        # (one carrying a content_selector.exact quote claim) whose cited span
        # does not match its source snapshot (under the versioned text
        # normalization — case/punctuation/whitespace-insensitive) fails closed.
        #
        FragmentAttestationCheck(),
    ]

    # MonotoneGrowthCheck — only when previous_corpus/ is present.
    prev_corpus = bundle_dir / "previous_corpus"
    if prev_corpus.exists():
        corpus_dir = bundle_dir / "corpus"
        cur_jsonl = sorted(corpus_dir.glob("*.jsonl")) if corpus_dir.is_dir() else []
        prev_jsonl = sorted(prev_corpus.glob("*.jsonl")) if prev_corpus.is_dir() else []
        plugins.append(
            MonotoneGrowthCheck(
                current_version=cur_jsonl[0].name if cur_jsonl else "corpus.jsonl",
                prior_version=prev_jsonl[0].name if prev_jsonl else "corpus.jsonl",
            )
        )

    # FalsificationNegativeTestCheck — only when falsification_rules/ is present.
    if (bundle_dir / "falsification_rules").exists():
        plugins.append(FalsificationNegativeTestCheck())

    # ReDerivationInvocationCheck — executes BUNDLE-SUPPLIED Python (arbitrary
    # local code execution) ONLY under the opt-in --unsafe-run-bundle-pack flag
    # (permit_execution). Constructed when a pack is present so the manifest's
    # typed_checks claim has its CC2 instance; with the flag OFF (the default)
    # the check does NOT execute the pack and returns RE_DERIVATION_NOT_EXECUTED
    # (rendered NOT-RUN — re-derivation not verified). The safe re-derivation
    # path is spec-pinned dispatch (manifest.outputs + auditor SpecAnchor). See
    # SECURITY.md "Code execution in the verify path".
    #
    # Dispatch carve-out (CLI/library convergence, 2026-06-12): when the manifest
    # declares `outputs`, spec-pinned dispatch is the safe re-derivation path and
    # a pack shipped alongside it is a redundant unsafe artifact (the pilots carry
    # it for the --unsafe path). Constructing the check there would only emit a
    # SPURIOUS RE_DERIVATION_NOT_EXECUTED leg that drives an anchored verifier to
    # ERROR even though dispatch verified re-derivation. So skip it UNLESS the
    # manifest explicitly claims `re_derivation_invocation` (then the producer is
    # asking for the pack to be evaluated and CC2 requires the instance). This
    # mirrors the core `_step_rederivation_pack_guard` dispatch exemption, so the
    # CLI and a library verify() converge on a pack+dispatch bundle.
    pack_files = _bundle_pack_files(bundle_dir)
    _dispatch_covers = bool(getattr(manifest, "outputs", ()) or ())
    _pack_claimed = "re_derivation_invocation" in getattr(manifest, "typed_checks", ())
    if pack_files and (not _dispatch_covers or _pack_claimed):
        plugins.append(
            ReDerivationInvocationCheck(
                pack_filename=pack_files[0].name,
                permit_execution=permit_pack_execution,
            )
        )

    # Phase-0 cutover (2026-05-04): wire VKERNEL_VERIFIER_HMAC_KEY through
    # the post-W3 plugins so v0.2 reason codes (STAMP_UPGRADE_OUT_OF_ORDER,
    # STAMP_UPGRADE_DISCHARGE_LINK_BROKEN, WASM_TRACE_SIGNATURE_INVALID,
    # DISCHARGE_STATUS_VERIFIER_DIVERGENCE, ...) are reachable. Without
    # this, the FAIL-CLOSED branch eats every stamp_upgrade /
    # execution_trace / discharge-bearing record. Resolved via the same
    # helper that wires default_post_w3_plugin_set().
    from audit_bundle.plugins import _load_verifier_recheck_key  # noqa: E402

    _recheck_key = _load_verifier_recheck_key()
    # The None fallback is NOT a silent downgrade: when signed smt-z3 records
    # are present and no Z3 backend exists on this host,
    # RefinementDischargeCheck returns Z3_RECHECK_NOT_AVAILABLE
    # (incomplete=True → clean-ERROR, exit 2). Availability discipline,
    # RES-01 hardening 2026-06-11.
    try:
        from audit_bundle.discharge.z3_runner import pick_default_invoker  # noqa: E402

        _z3_invoker = pick_default_invoker()
    except Exception:
        _z3_invoker = None

    plugins.extend(
        [
            CoverageSumInvariantCheck(),
            SourceAttributesConsistencyCheck(),
            ThreeSetSumInvariantCheck(),
            # Post-W3 substrate extensions (C14/C15/C16). No-op on W3-baseline bundles
            # whose dispatch_records is empty/absent. Order: C15 well-formedness before
            # C14 lattice (lattice reads stamp_observed shape) before C16 refinement.
            DispatchRecordWellformedCheck(recheck_key=_recheck_key),
            StampLatticeCheck(recheck_key=_recheck_key),
            RefinementDischargeCheck(
                recheck_key=_recheck_key,
                recheck_invoker=_z3_invoker,
            ),
        ]
    )

    # Domain-pilot plugins — only when claimed in manifest.typed_checks.
    claimed = set(manifest.typed_checks)
    if "span_re_derivation" in claimed:
        plugins.append(SpanReDerivationCheck())
    if "sensor_re_derivation" in claimed:
        plugins.append(SensorReDerivationCheck())
    if "control_rederivation" in claimed:
        plugins.append(ControlReDerivationCheck())
    if "aigov_rederivation" in claimed:
        plugins.append(AIGovReDerivationCheck())
    # PRESENCE-triggered, not claim-triggered. Same root cause as red-team A1 above: a
    # cross-check that only fires for names listed in manifest.typed_checks is one an
    # attacker simply omits. Measured on this pilot 2026-08-18 (battery fault M1): a bundle
    # with a forged payload/aggregate.json that drops "agent_dry_run" from typed_checks
    # passed this CLI with exit 0, because the plugin was never constructed and nothing
    # re-derived. Carrying the artifacts IS the obligation, so the artifacts trigger it.
    # ANY of them, never ALL of them. The first version of this trigger was an AND of
    # verdicts.jsonl and aggregate.json, and a red-team pass broke it the same day: forge one
    # artifact, DELETE the other, drop the typed_checks claim, repair the surviving hash —
    # both triggers defeated at once, the plugin never constructed, 20 DENY verdicts rewritten
    # to ADMIT, exit 0. Nothing else in the default plugin set reads these paths.
    #
    # The lesson is narrower and worse than "use OR": that AND was written as the fix for the
    # battery's M1 finding, and it was validated only against M1 — which drops the CLAIM while
    # keeping both files. A fix tested only against the case that motivated it is untested.
    _DRY_RUN_ARTIFACTS = (
        "payload/verdicts.jsonl",
        "payload/aggregate.json",
        "coverage/dry_run_coverage.json",
    )
    _dry_run_artifacts_present = any(
        (bundle_dir / rel).exists() for rel in _DRY_RUN_ARTIFACTS
    )
    if "agent_dry_run" in claimed or _dry_run_artifacts_present:
        plugins.append(AgentDryRunCheck())

    return plugins


def _print_result(result: VerifyResult, plugins: list) -> None:
    """Print one line per check (built-in steps + each plugin), then summary."""
    failed: dict[str, list] = {}
    for f in result.failures:
        failed.setdefault(f.check_name, []).append(f)

    rows: list[tuple[str, str, str]] = []

    for step in _BUILTIN_STEPS:
        if step in failed:
            for f in failed[step]:
                rows.append(("FAIL", step, f"[{f.reason_code}] {f.detail}"))
        else:
            rows.append(("PASS", step, ""))

    for plugin in plugins:
        key = f"typed_check_plugins:{plugin.name}"
        label = f"plugin:{plugin.name}"
        if key in failed:
            for f in failed[key]:
                rows.append(("FAIL", label, f"[{f.reason_code}] {f.detail}"))
        elif (
            plugin.name == "re_derivation_invocation"
            and getattr(plugin, "permit_execution", True) is False
        ):
            # Pack present but not executed (safe default — executing it is
            # arbitrary local code execution). NOT a PASS: re-derivation was not
            # verified. Loud row, but never fails the otherwise-valid bundle.
            rows.append(
                (
                    "NOT-RUN",
                    label,
                    "[RE_DERIVATION_NOT_EXECUTED] bundle pack present, NOT "
                    "executed; re-derivation NOT verified — do not read the "
                    "verdict as covering it. Pass --unsafe-run-bundle-pack to "
                    "execute (trusted producer / disposable host), or migrate "
                    "to spec-pinned dispatch.",
                )
            )
        else:
            rows.append(("PASS", label, ""))

    col = max((len(name) for _, name, _ in rows), default=0)
    for status, name, detail in rows:
        line = f"{status}  {name:<{col}}"
        if detail:
            line += f"  {detail}"
        print(line)

    # WHICH ACCEPTANCE RULES THIS RUN APPLIED, above the summary line.
    # Printed for a PASS as well as a FAIL, because the case that needs saying
    # out loud is the green one: coverage triggers on the producer-controlled
    # outputs/ path, so a bundle that relocated it collects a clean PASS having
    # compared nothing. Before this, that run and an honestly-covered run
    # printed byte-identical output.
    completeness = getattr(result, "completeness", None)
    acceptance = [
        d
        for d in (getattr(completeness, "disclosures", None) or ())
        if d.startswith(_ACCEPTANCE_PREFIX)
    ]
    if acceptance:
        print()
        for d in acceptance:
            body = d[len(_ACCEPTANCE_PREFIX) :]
            marker = "!!" if "NOT APPLIED" in body else "  "
            print(f"{marker}  acceptance  {body}")

    # WHICH CLAIMS WERE REQUIRED AND WHICH RULE JUDGED EACH — or that nobody
    # said. Same reasoning as the acceptance rows: the JSON carries this, the
    # terminal is what the human reads, and an anchored run with no work-set
    # printed the same wall of PASS as one with a set. "NO auditor work-set"
    # is the unconfigured fallback and gets the loud marker on purpose.
    selection = [
        d
        for d in (getattr(completeness, "disclosures", None) or ())
        if d.startswith(_TYPE_SELECTION_PREFIX)
    ]
    if selection:
        if not acceptance:
            print()
        for d in selection:
            body = d[len(_TYPE_SELECTION_PREFIX) :]
            marker = (
                "!!" if "NO auditor work-set" in body or "NOT APPLIED" in body else "  "
            )
            print(f"{marker}  type_selection  {body}")

    print()
    n_not_run = sum(1 for status, _, _ in rows if status == "NOT-RUN")
    n_pass = sum(1 for status, _, _ in rows if status == "PASS")
    if not result.ok:
        n = len(result.failures)
        print(f"FAIL  ({n} failure{'s' if n != 1 else ''} across {len(rows)} check(s))")
    elif n_not_run:
        # Claimed-but-NOT-RUN re-derivation is NOT a pass — re-derivation is the
        # core property of this verifier. The process boundary maps it to ERROR
        # (exit 2, "could not conclude"); the summary must not read as PASS.
        print(
            f"INCOMPLETE  ({n_pass} check(s) passed; {n_not_run} NOT-RUN — "
            "re-derivation NOT evaluated; verdict is NOT OK)"
        )
    else:
        print(f"PASS  ({n_pass} check(s) passed)")


# =============================================================================
# DSSE sidecar guard — Option A (re-derivation only; fail-closed on sealed bundles)
# =============================================================================
# Post-cutover bundles carry a bundle.dsse.json sidecar whose payload is
# signed with Ed25519. stdlib has no Ed25519 verifier, so this offline tool
# CANNOT check the signature. The only safe outcome: return verified=False with
# code DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO and a pointer to the shipped library
# verification primitives (audit_bundle.dsse.envelope.verify_envelope +
# set_closure.snapshot_and_compare), which require the caller-injected,
# out-of-band C18 public-key allowlist.
#
# Import allowlist (NON-NEGOTIABLE):
#   audit_bundle.bundle_manifest.is_post_cutover  — stdlib-pure membership test
#   audit_bundle.dsse.pae.b64url_nopad_decode     — stdlib base64 only
# DO NOT import audit_bundle.dsse.envelope, audit_bundle.dsse.header,
# cryptography, jcs, or rfc8785 here.

_DSSE_SIDECAR_FILENAME = "bundle.dsse.json"

_DSSE_SUBSTRATE_VERIFIER_HINT = (
    "This offline tool (veriker/cli/verify.py) is stdlib-only and CANNOT check the "
    "Ed25519 signature on a sealed (post-cutover DSSE) bundle. A sealed bundle "
    "MUST pass the signature check (and DSSE set-closure) before any trust "
    "assertion is made.\n"
    "\n"
    "Verifying a sealed bundle requires the public-key allowlist (kid -> 32-byte "
    "Ed25519 pubkey). The allowlist is distributed out-of-band and is NEVER "
    "contained in the bundle, so this distribution ships the verification "
    "PRIMITIVES as a library, not a turnkey CLI (the trust root must be injected "
    "by the integrator):\n"
    "\n"
    "  from pathlib import Path\n"
    "  from audit_bundle.dsse.envelope import verify_envelope\n"
    "  from audit_bundle.dsse.set_closure import snapshot_and_compare\n"
    "\n"
    "  sidecar = (Path(bundle_dir) / 'bundle.dsse.json').read_bytes()\n"
    "  sig = verify_envelope(sidecar, allowlist)   # allowlist: {kid: pubkey_raw32}\n"
    "  assert sig.ok, sig.reason_code               # Ed25519 over the DSSE PAE\n"
    "  # then confirm the signed expected file set matches the bundle on disk:\n"
    "  closure = snapshot_and_compare(Path(bundle_dir), expected_files)\n"
    "  assert closure.ok, closure                   # no surplus/missing/unstable\n"
)


def _dsse_sidecar_offline_check(
    bundle_dir: Path,
) -> tuple[bool, str | None, str]:
    """Check whether bundle_dir contains a post-cutover DSSE-sealed sidecar.

    Returns (sealed, reason_code, detail):
      - sealed=False, reason_code=None  → no sealed sidecar detected; proceed normally.
      - sealed=True, reason_code='DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO'
                                 → post-cutover sealed bundle; offline tool cannot
                                   verify Ed25519; overall verified MUST be False.

    SECURITY INVARIANTS (Option A, D4-safe):
      * Reads ONLY the sidecar payload's schema_version, never manifest.json, for
        the cutover decision.
      * If the sidecar is malformed/unreadable → fails closed (sealed=True, same code).
      * The schema_version value is used ONLY for the is_post_cutover() membership
        test — never for feature-gating or routing beyond this single bail decision.
      * Stdlib-only: json + base64 via b64url_nopad_decode. No signature check.
    """
    sidecar = bundle_dir / _DSSE_SIDECAR_FILENAME
    if not sidecar.is_file():
        # No sidecar → not a sealed bundle; legacy path unaffected.
        return False, None, "no DSSE sidecar present"

    # --- D4-safe read: decode payload bytes and parse schema_version only ---
    try:
        envelope = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        # Malformed sidecar → fail closed; do not pass an unreadable envelope.
        return (
            True,
            "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO",
            f"bundle.dsse.json unreadable or invalid JSON ({exc}); "
            f"failing closed. {_DSSE_SUBSTRATE_VERIFIER_HINT}",
        )

    payload_b64 = envelope.get("payload")
    if not isinstance(payload_b64, str):
        return (
            True,
            "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO",
            "bundle.dsse.json missing or non-string 'payload' field; "
            f"failing closed. {_DSSE_SUBSTRATE_VERIFIER_HINT}",
        )

    try:
        payload_bytes = b64url_nopad_decode(payload_b64)
        payload_obj = json.loads(payload_bytes)
    except Exception as exc:  # noqa: BLE001
        return (
            True,
            "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO",
            f"bundle.dsse.json payload not decodable ({exc}); "
            f"failing closed. {_DSSE_SUBSTRATE_VERIFIER_HINT}",
        )

    schema_version = payload_obj.get("schema_version", "")
    if not isinstance(schema_version, str):
        schema_version = ""

    # Membership test only — opaque string tag, no ordering.
    if not is_post_cutover(schema_version):
        # Sidecar present but schema_version is NOT a post-cutover tag.
        # Treat as legacy (no sealed guard fires).
        return (
            False,
            None,
            f"sidecar schema_version {schema_version!r} is not post-cutover",
        )

    # Post-cutover confirmed: stdlib cannot check Ed25519 → MUST fail closed.
    return (
        True,
        "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO",
        f"bundle sealed with DSSE (schema_version={schema_version!r}); "
        "Ed25519 signature UNCHECKED — stdlib verifier has no Ed25519 support. "
        f"{_DSSE_SUBSTRATE_VERIFIER_HINT}",
    )


# =============================================================================
# C18 stdlib-only structural extension
# =============================================================================
# This separate offline-only verifier tool is the documented happy path.
# Stdlib-only is load-bearing here: this section uses raw json.loads + re +
# hashlib and does NOT import audit_bundle.extensions.c18_verifier_identity
# (which carries python-tuf deps on the substrate-verifier path), so the
# extension surface stays auditable without pulling in those deps.
#

_C18_OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_C18_REQUIRED_FIELDS = (
    "verifier_release_id",
    "verifier_oci_digest",
    "verifier_self_check_status",
    "release_manifest_url",
    "release_manifest_hash",
    "scitt_statement_hash",
    "sigstore_bundle_hash",
    "rekor_inclusion_proof",
)
_C18_REQUIRED_REKOR_KEYS = ("leaf_index", "tree_size", "hashes", "root_hash")
_C18_ALLOWED_SELF_CHECK_STATUS = frozenset({"passed", "failed", "skipped"})


def _c18_extract_verifier_identity(manifest_json: dict) -> dict | None:
    """Extract bundle.evidence.verifier_identity from raw manifest JSON.

    Stdlib-only path: takes the parsed manifest dict (raw json.loads), no
    substrate-extension imports.
    """
    evidence = manifest_json.get("evidence")
    if not isinstance(evidence, dict):
        return None
    vi = evidence.get("verifier_identity")
    return vi if isinstance(vi, dict) else None


def _c18_is_hex(s) -> bool:
    if not isinstance(s, str) or not s:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _c18_structural_check(bundle_dir: Path) -> tuple[bool, str | None, str]:
    """Run C18 structural checks against bundle_dir/manifest.json.

    Returns (ok, reason_code_or_None, detail). Stdlib-only:
    json.loads + re.match + hashlib.sha256.
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.is_file():
        return False, "C18_MANIFEST_MISSING", f"no manifest.json in {bundle_dir}"

    try:
        manifest_json = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, "C18_MANIFEST_INVALID_JSON", str(exc)

    block = _c18_extract_verifier_identity(manifest_json)
    if block is None:
        # Legacy / pre-C18 bundle. Clean PASS — C18 structural hint not emitted.
        return True, None, "no verifier_identity field (pre-C18 bundle)"

    # 1. All required fields present when block present.
    for field in _C18_REQUIRED_FIELDS:
        if field not in block:
            return (
                False,
                "VERIFIER_IDENTITY_FIELD_MISSING",
                f"required field {field!r} missing from verifier_identity",
            )

    # 2. OCI digest shape.
    oci = block.get("verifier_oci_digest", "")
    if not isinstance(oci, str) or not _C18_OCI_DIGEST_PATTERN.match(oci):
        return (
            False,
            "VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED",
            f"verifier_oci_digest {oci!r} not sha256:<64hex>",
        )

    # 3. Rekor inclusion proof shape.
    proof = block.get("rekor_inclusion_proof")
    if not isinstance(proof, dict):
        return (
            False,
            "VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED",
            "rekor_inclusion_proof not a dict",
        )
    for key in _C18_REQUIRED_REKOR_KEYS:
        if key not in proof:
            return (
                False,
                "VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED",
                f"rekor_inclusion_proof missing required key {key!r}",
            )
    if not (
        isinstance(proof.get("leaf_index"), int)
        and isinstance(proof.get("tree_size"), int)
        and isinstance(proof.get("hashes"), list)
        and all(isinstance(h, str) for h in proof.get("hashes", []))
        and _c18_is_hex(proof.get("root_hash", ""))
    ):
        return (
            False,
            "VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED",
            "rekor_inclusion_proof types/values malformed",
        )

    # 4. self_check_status enum — mode-from-producer hardening: refuse to
    # silently accept an unknown status.
    status = block.get("verifier_self_check_status")
    if status not in _C18_ALLOWED_SELF_CHECK_STATUS:
        return (
            False,
            "VERIFIER_SELF_CHECK_UNKNOWN_STATUS",
            f"verifier_self_check_status={status!r} not in "
            f"{sorted(_C18_ALLOWED_SELF_CHECK_STATUS)!r}",
        )

    # 5. release_manifest_hash recomputation (stdlib hashlib) when file bundled.
    release_manifest_path = bundle_dir / "release_manifest.json"
    if release_manifest_path.is_file():
        try:
            actual = hashlib.sha256(release_manifest_path.read_bytes()).hexdigest()
        except OSError as exc:
            return (
                False,
                "VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH",
                f"cannot read release_manifest.json: {exc}",
            )
        declared = block.get("release_manifest_hash", "")
        if declared not in (f"sha256:{actual}", actual):
            return (
                False,
                "VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH",
                f"declared {declared!r} != computed sha256:{actual}",
            )

    return True, None, "verifier_identity structurally valid"


_C18_NEXT_STEPS_HINT = """\
NEXT STEPS (out-of-band; required for trust assertion):
  1. cosign verify-blob --bundle <sigstore-bundle> \\
       --certificate-identity 'https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/<tag>' \\
       --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\
       <image-digest>
  2. slsa-verifier verify-image <image-digest> \\
       --source-uri github.com/<org>/<repo> \\
       --source-tag <tag> --source-commit <SHA>
  3. vkernel-manifest-verify --release <tag> --tuf-trust-bundle ./trust/   # (substrate-verifier path; NOT stdlib; NOT YET BUILT — key-signing-ceremony deliverable)
  4. cosign manifest <image-tag>   # host-side digest verification per CV4 (vkernel-host-digest-verify wrapper: script exists, not yet a packaged binary)
"""


def _c19_extract_cross_host_edges(manifest_json: dict) -> list | None:
    """Extract causal_chain.cross_host_authenticators from raw manifest JSON.

    Returns the edge list (possibly empty) when the key is present, else None.
    Stdlib-only path: operates on the parsed manifest dict (raw json.loads).
    """
    cc = manifest_json.get("causal_chain")
    if not isinstance(cc, dict):
        return None
    edges = cc.get("cross_host_authenticators")
    return edges if isinstance(edges, list) else None


def _c19_crosshost_structural_check(bundle_dir: Path) -> tuple[bool, str | None, str]:
    """A1 fix — fail closed when a bundle carries cross-host edges this CLI can't verify.

    Root cause of red-team A1: this generic offline CLI never instantiates any
    cross-host authenticator check (`_build_plugins` constructs none), and the
    substrate CC2 cross-check only fires for names *listed in*
    `manifest.typed_checks` — which an attacker simply omits. The result was a
    PASS on a bundle carrying a fully fabricated
    `causal_chain.cross_host_authenticators` edge (fake sigs, attacker-chosen
    hosts, an ack the receiver never produced).

    Cross-org COSE_Sign1 verification requires cbor2/pycose + the verifier-pinned
    CrossOrgKeyPolicy + the stateful PeerReview walk — none of which is available
    on this stdlib-only path (importing a second COSE implementation here is the
    exact two-verifier drift that produced these findings). So when cross-host
    edges are PRESENT we fail closed and route the consumer to the verifier that
    actually checks them (the per-domain pilot harness / substrate verifier,
    e.g. `examples/<pilot>/verify.py`), rather than silently greenlight them.

    Returns (ok, reason_code_or_None, detail).
    """
    manifest_path = bundle_dir / "manifest.json"
    try:
        manifest_json = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, "C19_MANIFEST_UNREADABLE", str(exc)

    edges = _c19_extract_cross_host_edges(manifest_json)
    if not edges:
        # Key absent or empty list → nothing to verify; clean structural pass.
        return True, None, "no cross_host_authenticators edges"

    return (
        False,
        "CROSS_HOST_EDGES_PRESENT_UNVERIFIED",
        (
            f"{len(edges)} cross_host_authenticators edge(s) present but this "
            "offline stdlib verifier does not verify cross-host edges (no COSE "
            "verification / pinned cross-org policy / stateful PeerReview walk "
            "on this path). Cross-host edges MUST be verified by the substrate "
            "verifier or the per-domain pilot harness (examples/<pilot>/verify.py), "
            "which run the COSE_Sign1 + kid->host bind + counter/replay checks. "
            "Failing closed rather than passing unverified cross-org evidence."
        ),
    )


#: C17/C20 reserved fields that v0.3 PARSES but does not VERIFY (M0 stubs).
_RESERVED_UNVERIFIED_FIELDS = ("attested_serving", "semantic_fidelity")


def _print_reserved_unverified_note(bundle_dir: Path) -> None:
    """Red-team B-4 — disclose that present reserved fields are not yet verified.

    A SUBSTANTIVE/adversarial value in these fields is already rejected upstream
    (exit 1) by bundle_manifest._validate_schema_reserved_blocks_v03, which locks
    each to its reservation shape ({reserved_for_v0_4: True, mode?}). So whatever
    reaches here is a CONFORMANT reservation placeholder — schema-valid, but the
    reserved CAPABILITY is not active at v0.3. This NOTE discloses that, so a
    consumer cannot read the reservation marker as a verified attestation.
    Non-fatal (the placeholder is legitimate; legit pilots bell/eidas/ibm carry
    it). No-op when none present.
    """
    try:
        mf = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    present = [f for f in _RESERVED_UNVERIFIED_FIELDS if f in mf]
    if not present:
        return
    print()
    print(
        "NOTE  reserved fields present but NOT VERIFIED at v0.3 "
        f"(parsed reservation only, enforcement is future S17/S20 work): "
        f"{', '.join(present)}. Do NOT treat these as verified on the strength "
        "of the PASS verdict."
    )


_RECEIPT_PASS_DISCLOSURE_SEP = ": PASS — "

# Prefix BundleVerifier._step_rederivation_surface_guard stamps on the verdict
# face when NOTHING in the bundle was re-derived. Matched (not re-decided) here
# so stdout and --verdict-out report the same single core determination.
_RE_DERIVATION_SURFACE_PREFIX = "re_derivation_surface: "


def _extension_receipt_disposition(kind: str, result) -> tuple[str, str | None, str]:
    """Read the per-kind extension-receipt disposition verify() already recorded.

    PRESENTATION ONLY — the handler executed exactly ONCE, inside
    BundleVerifier._step_extension_receipts against that run's registry
    snapshot. Re-executing it here (the pre-2026-06-11 behaviour) was a second
    acquisition of the same input: --verdict-out then mixed the canonical
    verdict (execution #1) with cli_gates (execution #2), so a stateful or
    non-deterministic handler — or a registry change between the two passes —
    produced an artifact that disagreed with itself (same class as the RES-04
    double manifest read, on the configuration axis).

    Reconstruction, all from the verdict face:
      reason leg check_name == "extension_receipt:<kind>":
        code VERIFIER_INCOMPLETE → NOT_EVALUATED (no handler in this build)
        any other code           → FAIL (that code is the receipt reason)
      Completeness.disclosures "extension_receipt:<kind>: PASS — <detail>"
                                  → PASS
      none of the above           → UNACCOUNTED: verify() never recorded a
        disposition for a receipt that is present in the manifest (e.g. an
        upstream crash-ERROR short-circuited the receipt step). Fail-closed
        could-not-conclude (exit 2), never a silent pass.
    """
    check = f"extension_receipt:{kind}"
    for r in result.reasons:
        if getattr(r, "check_name", "") == check:
            if r.code == VERIFIER_INCOMPLETE:
                return ("NOT_EVALUATED", None, r.detail)
            return ("FAIL", r.code, r.detail)
    prefix = f"{check}{_RECEIPT_PASS_DISCLOSURE_SEP}"
    completeness = getattr(result, "completeness", None)
    for d in getattr(completeness, "disclosures", None) or ():
        if d.startswith(prefix):
            return ("PASS", None, d[len(prefix) :])
    return (
        "UNACCOUNTED",
        "EXTENSION_RECEIPT_UNACCOUNTED",
        f"verify() recorded no disposition for extension receipt {kind!r} "
        "(the receipt step was likely not reached — e.g. upstream "
        "crash-ERROR); the verifier COULD NOT CONCLUDE on it",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veriker",
        description=(
            "Verify a veriker audit bundle against its built-in checks "
            "and typed-check plugins."
        ),
    )
    parser.add_argument(
        "--bundle-dir",
        # Conditionally required: exactly one of --bundle-dir / --kit. argparse
        # cannot express "exactly one of", so the check lives in
        # `_select_input_mode` and both halves of it (neither, both) map to one
        # operator error.
        dest="bundle_dir",
        metavar="PATH",
        default=None,
        help=(
            "Path to the unpacked audit bundle directory (must contain "
            "manifest.json). Exactly one of --bundle-dir / --kit."
        ),
    )
    parser.add_argument(
        "--c18-check",
        dest="c18_check",
        action="store_true",
        default=None,  # tri-state: None = auto-detect on bundle contents
        help=(
            "Run C18 structural checks on bundle.evidence.verifier_identity. "
            "Default: AUTO-ON when verifier_identity field present; OFF for "
            "legacy bundles. Uses the stdlib-only extension path."
        ),
    )
    parser.add_argument(
        "--no-c18-check",
        dest="c18_check",
        action="store_false",
        help="Force-disable C18 structural checks even when verifier_identity present.",
    )
    parser.add_argument(
        "--verdict-out",
        dest="verdict_out",
        metavar="PATH",
        default=None,
        help=(
            "Write the machine-readable verdict face to PATH as JSON: exit "
            "code, state, reason codes, the canonical verdict structure "
            "(reasons/legs/completeness incl. disclosures), CLI gate results, "
            "and the input manifest sha256. UNSIGNED operational artifact — "
            "trust derives from deterministic re-execution of this verifier, "
            "not from the file."
        ),
    )
    parser.add_argument(
        "--unsafe-run-bundle-pack",
        dest="unsafe_run_bundle_pack",
        action="store_true",
        default=False,
        help=(
            "UNSAFE: execute a bundle-supplied re_derive/*_pack.py in the "
            "verifier process (arbitrary local code execution). OFF by default. "
            "Only for bundles from a TRUSTED producer or on a DISPOSABLE host. "
            "Never use on untrusted bundles — prefer spec-pinned dispatch. "
            "DO NOT COMBINE WITH --spec-anchor: packs run in "
            "_step_typed_check_plugins, BEFORE _step_spec_pinned_dispatch reads "
            "outputs/, so a pack with write access to the sealed snapshot can "
            "write the answer dispatch is about to check and manufacture both a "
            "green verdict and MEASURED re-derivation coverage. That ordering "
            "residual was dead while the CLI could not supply an anchor at all; "
            "adding --spec-anchor made it reachable. Retiring permit_execution "
            "closes it; until then the two flags together are unsound."
        ),
    )
    parser.add_argument(
        "--spec-anchor",
        dest="spec_anchor",
        nargs="+",
        metavar="SPEC.json",
        default=None,
        help=(
            "AUDITOR AUTHORITY for spec-pinned dispatch. One or more binding "
            "spec files YOU control (your committed copies — e.g. the pilot's "
            "spec_pinned/*.spec.json), from which the verifier builds a "
            "SpecAnchor of {spec_id: sha256(file bytes)}. A bundle that declares "
            "manifest.outputs cannot be dispatched without this: with no anchor "
            "the producer's own manifest would select the authority it is judged "
            "against, so the verifier refuses and records a VERIFIER_INCOMPLETE "
            "leg under check_name `spec_pinned_dispatch:anchor` (exit 2 — could "
            "not conclude, NOT a REJECT of the bundle). Point this at YOUR copy "
            "of the spec: a path resolving inside --bundle-dir is REFUSED "
            "(SPEC_ANCHOR_ARG_INVALID, exit 2), because a spec read out of the "
            "bundle is authored by the party it is meant to constrain and makes "
            "the comparison a tautology — measured, a fully forged bundle "
            "verifies at exit 0 that way. A spec whose (spec_id, SHA) is not "
            "listed here is not authoritative, so a producer who ships a "
            "weakened substitute fails closed (exit 1). CAVEAT — combining this "
            "with --unsafe-run-bundle-pack re-activates a documented ordering "
            "residual: packs run BEFORE dispatch reads outputs/, so a pack can "
            "write the very answer dispatch then agrees with. Do not pass both."
        ),
    )
    parser.add_argument(
        "--primitives",
        dest="primitives",
        nargs="+",
        metavar="KIT.py",
        default=None,
        help=(
            "AUDITOR-SIDE PRIMITIVE KIT for spec-pinned dispatch: one or more "
            "Python registration modules YOU hold (e.g. a pilot's "
            "auditor_kit.py) whose import-time effect is register_primitive() "
            "calls, loaded before verification so the verifier can re-derive a "
            "bundle whose pinned spec names a primitive that does not ship in "
            "the distribution registry. Together with --spec-anchor this is "
            "the complete auditor kit: the anchor bytes plus the primitive "
            "registrations. A KIT IS CODE, NOT DATA — it executes in this "
            "process with this process's authority; point this only at your "
            "committed, reviewed copy, exactly as you hold the anchor. A path "
            "resolving inside --bundle-dir is REFUSED (PRIMITIVES_ARG_INVALID, "
            "exit 2): a primitive read out of the bundle is authored by the "
            "party it constrains and recompute-against-it is a tautology. A "
            "kit module that registers nothing is refused (a silent no-op kit "
            "reads as protection). The verdict face records each kit module's "
            "{path, sha256, registered[]} and, per resolved primitive, a "
            "registry-derived {origin, source, sha256} provenance row — an "
            "output judged by kit code is never byte-identical on the face to "
            "one judged by distribution code. Without this flag an unknown "
            "primitive_id remains fail-closed (UNKNOWN_PRIMITIVE): the "
            "verifier never loads a primitive from the bundle."
        ),
    )
    parser.add_argument(
        "--work-set",
        dest="work_set",
        metavar="WORK_SET.json",
        default=None,
        help=(
            "AUDITOR WORK-SET for spec-pinned dispatch: a JSON document YOU "
            "hold naming the COMPLETE set of outputs the bundle must deliver, "
            "each pinned to the anchored type key that judges it — "
            '{"pins": {"<output_id>": "<type_key>", ...}, '
            '"withheld": {"<output_id>": "<reason>"}, "source": "<text>"} '
            "(withheld and source optional; reason is one of "
            "NOT_PRODUCED_THIS_PERIOD / WITHHELD_BY_AUDITOR). Under dispatch "
            "the producer's remaining freedom is WHICH of your rules judges "
            "WHICH claim: retype an output onto a sibling type, drop a claim "
            "and substitute a decoy, pop a spec_files key to shrink the "
            "coverage denominator, or declare an EXTRA output under a valid "
            "type that nobody asked for — measured, that last one verified at "
            "exit 0 through this CLI while the same bundle was refused by a "
            "wrapper holding a set. With a work-set the bundle must deliver "
            "exactly this multiset of output_ids, each under its pinned type; "
            "a named output that does not arrive, an output you never named, "
            "or a duplicate is WORK_SET_VIOLATION (REJECT, exit 1). Without "
            "the flag the verdict face says selection was the producer's "
            "(`type_selection: NO auditor work-set`) and the generic "
            "anchored-type coverage fallback applies. Meaningful only with "
            "--spec-anchor (dispatch does not engage without one). The "
            "document is ALWAYS recorded as SELF_AUTHORED — this tool reads "
            "bytes and cannot verify a claim that the set was derived from an "
            "anchored artifact, so a `provenance` key is refused, as is any "
            "other unknown key (a misspelled `withheld` silently ignored "
            "would turn an excused absence into a required delivery with "
            "nothing on the face). A path resolving inside --bundle-dir is "
            "REFUSED (WORK_SET_ARG_INVALID, exit 2): the set is the auditor's "
            "authority over the producer. Its sha256 goes on the verdict face."
        ),
    )
    parser.add_argument(
        "--kit",
        dest="kit",
        nargs="+",
        metavar="KIT.py",
        default=None,
        help=(
            "KIT INSPECTION MODE — no bundle. Load the given auditor primitive "
            "kit(s) and report what each one DECLARES (its module-level "
            "KIT_NAME / KIT_VERSION / KIT_REGISTERS) against what it actually "
            "registered. Exactly one of --bundle-dir / --kit is given, and the "
            "bundle-only flags are REFUSED here rather than ignored. Exit 0 = "
            "the declared set equals the registered set, or there was nothing "
            "to compare — the kit declared no manifest (`manifest: absent`) or "
            "no readable KIT_REGISTERS (`manifest: unchecked`); 1 = the "
            "declared and registered sets disagree in either direction (an id "
            "registered but not declared, or declared but never registered); "
            "2 = a kit could not be loaded. NOTHING REQUIRES A KIT TO DECLARE "
            "A MANIFEST: a kit that declares none exits 0, so this reports a "
            "disagreement when a kit VOLUNTEERS a comparable claim — it does "
            "not establish that a kit declared what it adds. Deleting a "
            "KIT_REGISTERS line moves a run from 1 to 0; visibly (the row and "
            "the summary both say how many kits declared nothing), but it is "
            "not refused. "
            "A KIT IS CODE, NOT DATA — this mode EXECUTES it with this "
            "process's authority exactly as --primitives does, so point it only "
            "at your committed, reviewed copy. The manifest is LEGIBILITY, NOT "
            "A DEFENCE: what it catches is a kit whose declaration and "
            "behaviour have drifted apart, never a kit that misdeclares on "
            "purpose."
        ),
    )
    parser.add_argument(
        "--require-rederivation",
        dest="require_rederivation",
        action="store_true",
        default=False,
        help=(
            "STRICT: fail (exit 2, could-not-conclude) when the VERIFIER "
            "re-derived nothing — no spec-pinned dispatch output agreed, no "
            "fragment anchor was attested, and no domain re-derivation check "
            "reported. On an Axis-2 bundle this flag is near-useless without "
            "--spec-anchor: with no auditor authority dispatch refuses before "
            "any recompute, so nothing can report coverage. Executing a "
            "bundle-supplied re_derive pack does NOT by "
            "itself satisfy this: RE_DERIVED is decided on the pack's exit "
            "status, which a pack that re-derives nothing can return. Caveat "
            "when you also pass --unsafe-run-bundle-pack: the pack runs before "
            "dispatch reads outputs/, so a pack CAN satisfy this flag "
            "indirectly by writing the answer it was supposed to check. OFF by "
            "default: such a bundle still verifies OK, but its "
            "verdict face carries a NO_RE_DERIVATION_PERFORMED disclosure "
            "naming the absence. Turn this on when re-derivation is the "
            "property you are relying on and an integrity-only PASS is not "
            "acceptable. Reports only THAT something was re-derived, never "
            "that it was what the bundle claims."
        ),
    )
    parser.add_argument(
        "--unsafe-in-place",
        dest="unsafe_in_place",
        action="store_true",
        default=False,
        help=(
            "UNSAFE: skip the sealed snapshot and read bundle_dir live during "
            "verification. The verdict's coherence under mid-run mutation then "
            "rests on YOU having sealed the directory (no concurrent writer, "
            "no regeneration job); the verdict face carries a disclosure "
            "saying so. Default OFF: verify() copies the bundle to a "
            "verifier-private directory first, so the verdict is computed "
            "over one immutable artifact (set TMPDIR for large bundles)."
        ),
    )
    return parser


class SpecAnchorArgError(Exception):
    """--spec-anchor was given but an operator-side spec file is unusable.

    An OPERATOR error, not a bundle property: no verdict about the bundle was
    formed when this fires (the manifest may have been read for admission, but
    nothing about the bundle's validity was concluded), so it maps to exit 2
    (could not conclude), never exit 1.
    """


def _build_spec_anchor(paths: list[str], bundle_dir: Path):
    """Build the auditor's SpecAnchor from AUDITOR-SIDE committed spec bytes.

    Thin shim over `SpecAnchor.from_files(paths, forbid_within=bundle_dir)` —
    the ONE blessed construction (auditor-entry ADR D2), so the CLI, the pilot
    wrappers, and a library consumer anchored on the same files reach the SAME
    authority (CLI/library verdict divergence is a known failure class here —
    tests/test_cli_library_verdict_divergence.py). All refusal semantics live
    in the library: a path resolving INSIDE bundle_dir (symlinks followed both
    sides) is refused because an anchor read out of the bundle is authored by
    the party it constrains — measured 2026-08-17 on examples/bom_minimal, a
    fully forged bundle verified at exit 0 / state OK / zero reason codes that
    way, with --require-rederivation SATISFIED. Documenting the hazard in
    --help was the prior control and was not enough.

    Import is LAZY (inside the function) so a plain verify of a bundle that
    declares no outputs does not pull the rederivation package in at all, and
    the stdlib-only import closure of the default path is unchanged
    (tests/test_stdlib_import_boundary.py).

    Returns (SpecAnchor, provenance) where provenance is the anchor's attested
    [{spec_id, sha256, source}, ...] rows, recorded on the verdict face — a
    verdict that cannot say WHOSE authority it applied cannot be audited (the
    same reasoning that put the NO_RE_DERIVATION_PERFORMED disclosure on the
    face).
    """
    from audit_bundle.rederivation.spec_binding import (
        AnchorConstructionError,
        SpecAnchor,
    )

    try:
        anchor = SpecAnchor.from_files(paths, forbid_within=bundle_dir)
    except AnchorConstructionError as exc:
        raise SpecAnchorArgError(str(exc)) from exc
    return anchor, [dict(row) for row in anchor.provenance or ()]


def _load_primitive_kit_arg(paths: list[str], bundle_dir: Path) -> list[dict]:
    """Load the auditor's primitive kit from AUDITOR-SIDE registration modules.

    Thin shim over `load_primitive_kit(paths, forbid_within=bundle_dir)` — the
    ONE blessed loading path, so the CLI, a pilot wrapper calling the library,
    and a harness loading the same kit reach the SAME registrations under the
    SAME refusal semantics (all of which live in the library: in-bundle
    containment, read-once/compile-from-those-bytes, no-op-kit refusal,
    same-path-different-bytes refusal).

    Import is LAZY (inside the function) for the same reason _build_spec_anchor's
    is: a plain verify of a bundle that declares no outputs must not pull the
    rederivation package in at all (tests/test_stdlib_import_boundary.py).

    Returns the kit provenance rows [{path, sha256, registered[]}...] recorded
    on the verdict face's cli_gates. Raises PrimitiveKitArgError on any
    unusable kit — an OPERATOR error, exit 2, never a claim about the bundle.
    """
    from audit_bundle.rederivation.kit import (
        KitConstructionError,
        load_primitive_kit,
    )

    try:
        rows = load_primitive_kit(paths, forbid_within=bundle_dir)
    except KitConstructionError as exc:
        raise PrimitiveKitArgError(str(exc)) from exc
    return [dict(row) for row in rows]


class PrimitiveKitArgError(Exception):
    """--primitives was given but an operator-side kit module is unusable.

    An OPERATOR error, not a bundle property: no verdict about the bundle was
    formed when this fires, so it maps to exit 2 (could not conclude), never
    exit 1."""


class WorkSetArgError(Exception):
    """--work-set was given but the operator-side document is unusable.

    An OPERATOR error, not a bundle property: the document is the auditor's
    own declaration, so its being unreadable, malformed, self-inconsistent,
    or read out of the bundle says nothing about the artifact. Exit 2, never
    exit 1."""


#: The work-set document's closed schema. An unknown key is REFUSED, never
#: ignored: a misspelled `withheld` silently dropped would turn an excused
#: absence into a required delivery (or the reverse) with nothing on the face.
#: `provenance` is deliberately absent — see _load_work_set_arg.
_WORK_SET_KEYS = frozenset({"pins", "withheld", "source"})


def _load_work_set_arg(raw_path: str, bundle_dir: Path):
    """Build the auditor's WorkSet from an OPERATOR-SIDE document.

    Same containment rule as the anchor and the kit, for the same reason: the
    set is the auditor's authority over the producer, and a set read out of
    the bundle is authored by the party it constrains (an extra output the
    producer both declared and named in "the auditor's" set is not a
    finding). Symlinks are followed on both sides.

    ALWAYS SELF_AUTHORED. The CLI reads bytes; it cannot verify a claim that
    the enumeration was derived from some anchored artifact, so the document
    may not make one (the closed-universe rule that a provenance class is
    never labelled up). A harness that derives its set from a spec it also
    anchors — corner_load's auditor_entry does — uses the library and names
    the spec's sha itself.

    Parsed with the strict loader (duplicate keys refused; an ordinary
    json.loads would keep one occurrence, and which one is parser-defined).
    Import is LAZY for the same reason _build_spec_anchor's is.

    Returns (WorkSet, cli_gates row). Raises WorkSetArgError on any unusable
    document — an OPERATOR error, exit 2, never a claim about the bundle.
    """
    from audit_bundle._total_binding import (
        MAX_RAW_BYTES,
        TotalBindingError,
        strict_loads,
    )
    from audit_bundle.bundle_manifest import open_regular_fd_nofollow
    from audit_bundle.work_set import WorkSet, WorkSetError

    path = Path(raw_path)
    try:
        forbid_root = Path(bundle_dir).resolve()
        resolved = path.resolve()
    except (OSError, ValueError) as exc:
        # ValueError covers an embedded NUL and (as UnicodeEncodeError) a code
        # point the filesystem encoding cannot hold — neither is an OSError,
        # and letting either escape would report an OPERATOR's bad path as a
        # VERIFIER_INTERNAL_ERROR with no work_set_arg row on the face.
        raise WorkSetArgError(
            f"--work-set path {raw_path!r} could not be resolved: {exc}"
        ) from exc
    if resolved == forbid_root or forbid_root in resolved.parents:
        raise WorkSetArgError(
            f"--work-set path {raw_path!r} resolves INSIDE the bundle "
            f"({resolved}). The work-set is the auditor's authority over the "
            "producer; taking it from the bundle lets the producer name the "
            "set of work it is then judged to have delivered. Point this at "
            "YOUR copy, outside the bundle directory."
        )
    # Read the way the package reads every untrusted-shaped path: no-follow,
    # non-blocking, regular-file-checked ON THE OPEN FD (a FIFO with no writer
    # blocks a plain read_bytes() forever — a hang before any verdict, so
    # fail-closed never fires), and size-bounded BEFORE the bytes are
    # materialised (strict_loads' cap is enforced before PARSING, which is
    # after a read_bytes() has already allocated the whole file).
    try:
        fd = open_regular_fd_nofollow(resolved)
    except OSError as exc:
        raise WorkSetArgError(
            f"--work-set path {raw_path!r} could not be opened as a regular file: {exc}"
        ) from exc
    try:
        size = os.fstat(fd).st_size
        if size > MAX_RAW_BYTES:
            raise WorkSetArgError(
                f"--work-set {raw_path!r} is {size} bytes, over the "
                f"{MAX_RAW_BYTES}-byte cap; refusing to read it"
            )
        chunks: list[bytes] = []
        remaining = MAX_RAW_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise WorkSetArgError(
            f"--work-set path {raw_path!r} could not be read: {exc}"
        ) from exc
    finally:
        os.close(fd)
    if len(raw) > MAX_RAW_BYTES:
        raise WorkSetArgError(
            f"--work-set {raw_path!r} grew past the {MAX_RAW_BYTES}-byte cap "
            "while being read; refusing it"
        )
    try:
        doc = strict_loads(raw)
    except (TotalBindingError, ValueError) as exc:
        raise WorkSetArgError(
            f"--work-set {raw_path!r} is not strict JSON (duplicate keys, "
            f"NaN/Infinity and oversized documents are refused): {exc}"
        ) from exc
    if not isinstance(doc, dict):
        raise WorkSetArgError(
            f"--work-set {raw_path!r} must be a JSON object, got {type(doc).__name__}"
        )
    unknown = sorted(k for k in doc if k not in _WORK_SET_KEYS)
    if unknown:
        raise WorkSetArgError(
            f"--work-set {raw_path!r} carries unknown key(s) {unknown}; the "
            "document is the closed schema {pins, withheld?, source?} and an "
            "unknown key is refused rather than ignored. A `provenance` key in "
            "particular is refused: every --work-set is recorded as "
            "SELF_AUTHORED because this tool cannot verify a derivation claim."
        )
    pins = doc.get("pins")
    if not isinstance(pins, dict) or not pins:
        raise WorkSetArgError(
            f"--work-set {raw_path!r}: 'pins' must be a non-empty object "
            f"mapping output_id -> type_key, got "
            f"{'an empty object' if pins == {} else type(pins).__name__}"
        )
    withheld = doc.get("withheld", {})
    if not isinstance(withheld, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in withheld.items()
    ):
        raise WorkSetArgError(
            f"--work-set {raw_path!r}: 'withheld' must be an object mapping "
            "output_id -> reason (both strings)"
        )
    source = doc.get("source", f"--work-set {path.name} (operator-supplied document)")
    if not isinstance(source, str) or not source:
        raise WorkSetArgError(
            f"--work-set {raw_path!r}: 'source' must be a non-empty string"
        )
    try:
        work_set = WorkSet.declare(
            pins, source=source, provenance="SELF_AUTHORED", withheld=withheld
        )
    except WorkSetError as exc:
        raise WorkSetArgError(f"--work-set {raw_path!r}: {exc}") from exc
    # HELD, not APPLIED: nothing has been applied yet. The status is revised
    # from the VERDICT after verify() runs (see _main) — a literal "APPLIED"
    # written before the verifier was even constructed was the same false
    # face the work-set landing had already corrected once on the core row.
    row = {
        "gate": "work_set",
        "status": "HELD",
        "reason_code": None,
        "path": str(resolved),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "provenance": "SELF_AUTHORED",
        "universe_sha": work_set.universe_sha,
        "n_expected": work_set.n_expected,
        "n_withheld": work_set.n_withheld,
    }
    return work_set, row


def _verifier_version() -> str:
    """The verifier's version, from the ONE source (`audit_bundle/_version.py`)
    both pyprojects also read. This used to read the adjacent pyproject.toml
    directly, but the public drop ships a different pyproject.toml with a
    different version number — reading the shared module avoids that drift."""
    try:
        from audit_bundle._version import __version__

        return str(__version__)
    except Exception:  # noqa: BLE001 — version is metadata, never gates a verdict
        return "unknown"


def _release_status() -> str:
    """`experimental` until the public README's 1.0 gate is met: a completed
    third-party audit with findings fixed, and the signing ceremony. Stamped
    on every verdict face so a forwarded verdict carries the label the README
    does."""
    try:
        from audit_bundle._version import RELEASE_STATUS

        return str(RELEASE_STATUS)
    except Exception:  # noqa: BLE001
        return "unknown"


def _banner() -> str:
    return f"veriker {_verifier_version()} ({_release_status()})"


def _verdict_to_jsonable(v) -> dict:
    """Serialize the canonical Verdict structure verbatim — same field names as
    audit_bundle.verdict (no parallel vocabulary for consumers to cross-map)."""
    return {
        "state": v.state.value,
        "error_kind": v.error_kind.value if v.error_kind is not None else None,
        "reasons": [
            {"code": r.code, "check_name": r.check_name, "detail": r.detail}
            for r in v.reasons
        ],
        "legs": [_verdict_to_jsonable(leg) for leg in v.legs],
        "completeness": (
            None
            if v.completeness is None
            else {
                "layers": list(v.completeness.layers),
                "deep_validation": v.completeness.deep_validation,
                "disclosures": list(v.completeness.disclosures),
            }
        ),
    }


_EXIT_STATE = {0: "OK", 1: "REJECT", 2: "ERROR"}


def _work_set_status_from_verdict(result) -> str:
    """The work_set gate row's status, read off the core verdict's
    `type_selection:` disclosure — the one place the decision was made.
    APPLIED when the core says the set was applied; HELD_NOT_APPLIED when the
    core says it held one it could not apply; HELD when dispatch recorded no
    selection row at all (nothing was applied, and the face must not say
    otherwise)."""
    rows = [
        d
        for d in (
            getattr(getattr(result, "completeness", None), "disclosures", None) or ()
        )
        if d.startswith(_TYPE_SELECTION_PREFIX)
    ]
    for d in rows:
        if "NOT APPLIED" in d:
            return "HELD_NOT_APPLIED"
    for d in rows:
        if "WORK-SET APPLIED" in d:
            return "APPLIED"
    return "HELD"


def main() -> int:
    """Differentiated CLI boundary (ADR D8): exit 0 = OK, 1 = REJECT (artifact bad),
    2 = ERROR (verifier could not conclude). Any unanticipated escape from the verify
    pipeline (e.g. a RecursionError / unhashable-schema TypeError / source_attributes
    AttributeError that slipped a narrow guard) is caught here and reported as a
    VERIFIER_INTERNAL_ERROR with exit 2 — never a traceback, never exit 0."""
    parser = _build_parser()
    args = parser.parse_args()
    # First line of every run, before any gate can end it: WHICH verifier and
    # under WHAT release posture. The README's literal console blocks carry
    # the same line (tests/test_release_label.py).
    print(_banner())
    # Machine-readable verdict face, accumulated by _main as gates fire and
    # written below on EVERY path (early REJECT, ERROR, internal error) when
    # --verdict-out was given. UNSIGNED operational artifact: trust derives
    # from deterministic re-execution of this verifier, not from the file
    # (the signed objects are the bundle's own evidence, not this output).
    face: dict = {
        "verifier": "veriker/cli/verify.py",
        "verifier_version": _verifier_version(),
        # The label travels with the artifact: a verdict someone forwards
        # must say what the README says. See audit_bundle/_version.py.
        "release_status": _release_status(),
        "assurance_mode": "offline_stdlib",
        "note": (
            "Unsigned operational artifact. Trust derives from deterministic "
            "re-execution of the verifier on the bundle, not from this file."
        ),
        "input_manifest_sha256": None,
        # WHAT this run judged, so a consumer never has to infer it from which
        # fields happen to be populated. `bundle` for a --bundle-dir run,
        # `kit` for a --kit run — and on a --kit run exit 1 is a statement
        # about the KIT, which is the artifact that mode was pointed at.
        "subject": None,
        "reason_codes": [],
        "cli_gates": [],
        "verdict": None,
    }
    try:
        code = _main(args, face)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:  # noqa: BLE001 — fail-closed: CLI never tracebacks
        print(
            f"ERROR  verifier_internal  [VERIFIER_INTERNAL_ERROR] "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        face["reason_codes"].append("VERIFIER_INTERNAL_ERROR")
        code = 2
    face["exit_code"] = code
    face["state"] = _EXIT_STATE[code]
    if args.verdict_out:
        try:
            Path(args.verdict_out).write_text(
                json.dumps(face, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            # The caller asked for the artifact; failing to produce it must not
            # ride whatever exit code the verdict earned (a consumer keying on
            # the file would read a stale/absent one against a green exit).
            print(
                f"ERROR  verdict_out  [VERDICT_OUT_WRITE_FAILED] {exc}",
                file=sys.stderr,
            )
            return 2
    return code


#: Flags that only mean something against a bundle. In --kit mode they are
#: REFUSED, never ignored: a silently-accepted `--require-rederivation --kit X`
#: exiting 0 would tell an operator that re-derivation was required and
#: satisfied, on a run that read no bundle at all. Each entry carries its own
#: "was this actually given" predicate because the flags do not share a default
#: (--c18-check is tri-state, the rest are store_true or a list).
_BUNDLE_ONLY_FLAGS = (
    ("primitives", "--primitives", lambda v: bool(v)),
    ("spec_anchor", "--spec-anchor", lambda v: bool(v)),
    ("work_set", "--work-set", lambda v: bool(v)),
    ("require_rederivation", "--require-rederivation", lambda v: v is True),
    ("unsafe_run_bundle_pack", "--unsafe-run-bundle-pack", lambda v: v is True),
    ("unsafe_in_place", "--unsafe-in-place", lambda v: v is True),
    ("c18_check", "--c18-check/--no-c18-check", lambda v: v is not None),
)


def _select_input_mode(args) -> str | None:
    """Return an error detail, or None when exactly one coherent mode is given."""
    if args.bundle_dir and args.kit:
        return (
            "--bundle-dir and --kit name two different subjects (a bundle vs a "
            "kit) and exactly one can be judged per run. Pass one."
        )
    if not args.bundle_dir and not args.kit:
        return (
            "nothing to verify: pass --bundle-dir PATH to verify an audit "
            "bundle, or --kit KIT.py to inspect an auditor primitive kit."
        )
    if args.kit:
        given = [
            flag
            for dest, flag, was_given in _BUNDLE_ONLY_FLAGS
            if was_given(getattr(args, dest, None))
        ]
        if given:
            return (
                f"--kit mode reads no bundle, so {', '.join(given)} cannot mean "
                "anything here. Refused rather than ignored: a bundle-only flag "
                "that silently does nothing lets a green exit be read as that "
                "flag having been satisfied."
            )
    return None


def _print_kit_result(rows: list[dict]) -> None:
    """Human output for --kit mode.

    `_print_result` is coupled to `_BUILTIN_STEPS` and a `VerifyResult`; kit
    mode has neither, so this is its own small printer rather than a
    generalisation of that one."""
    display: list[tuple[str, str, str]] = []
    for row in rows:
        decl = row.get("manifest_declaration") or {}
        name = decl.get("name") or "(unnamed)"
        version = decl.get("version")
        label = f"{name}@{version}" if version else name
        display.append(("LOADED", "kit", f"{label}  {row['path']}"))
        display.append(("", "sha256", row["sha256"]))
        display.append(("", "registered", ", ".join(row["registered"])))
        declared = decl.get("registers")
        display.append(("", "declared", ", ".join(declared) if declared else "(none)"))
        codes = " ".join(f"[{c}]" for c in row.get("manifest_reason_codes") or ())
        detail = " ".join(p for p in (codes, row.get("manifest_note") or "") if p)
        display.append((row["manifest"].upper(), "manifest", detail))

    col = max((len(n) for _, n, _ in display), default=0)
    for status, name, detail in display:
        line = f"{status:<8}  {name:<{col}}"
        if detail:
            line += f"  {detail}"
        print(line.rstrip())

    print()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["manifest"]] = counts.get(row["manifest"], 0) + 1
    if counts.get("mismatch"):
        print(
            f"MISMATCH  ({counts['mismatch']} of {len(rows)} kit(s) declare a set "
            "that is not what they registered)"
        )
    else:
        # Never a bare "PASS": a kit with no manifest was compared to nothing,
        # and saying so is the entire point of the `absent` label.
        print(
            f"OK  ({len(rows)} kit(s) loaded — {counts.get('match', 0)} "
            f"declaration(s) matched, {counts.get('absent', 0)} with no "
            f"manifest, {counts.get('unchecked', 0)} declaring nothing checkable)"
        )


def _main_kit(args, face: dict) -> int:
    """`veriker --kit KIT.py` — judge a KIT, with no bundle in the picture.

    The verdict face is already bundle-independent (`input_manifest_sha256`
    defaults to None, `--verdict-out` is written on every path, the tri-state
    exit contract belongs to this CLI rather than to the verifier), so this mode
    reuses it unchanged. `verdict` stays None because no bundle verdict was
    formed; the exit code speaks about the KIT, and `subject` says so.
    """
    from audit_bundle.rederivation.kit import (
        NO_BUNDLE,
        KitConstructionError,
        load_primitive_kit,
    )

    face["subject"] = "kit"
    # ONE KIT AT A TIME. `load_primitive_kit` raises on the first unusable entry
    # and returns nothing, so a single broken kit late in the list discarded
    # every row already gathered — including a MISMATCH on an earlier kit, which
    # is the finding the operator most needed. Loading per path keeps each kit's
    # result whatever its neighbours do. Registrations are process-global either
    # way, so this changes no semantics, only what survives to be reported.
    # NO_BUNDLE, never a path that merely happens to contain nothing: the
    # containment refusal is recorded INAPPLICABLE rather than trivially
    # satisfied (see kit._NoBundle).
    rows: list[dict] = []
    load_errors: list[tuple[str, str]] = []
    for path in args.kit:
        try:
            rows.extend(load_primitive_kit([path], forbid_within=NO_BUNDLE))
        except KitConstructionError as exc:
            # Same code as the --primitives path: it is the same loader failing
            # the same way, and an operator-side unusable kit is exit 2 in both
            # modes.
            print(f"ERROR  kit_arg  [PRIMITIVES_ARG_INVALID] {exc}", file=sys.stderr)
            load_errors.append((str(path), str(exc)))

    face["cli_gates"].append(
        {
            "gate": "primitive_kit",
            "status": "ERROR" if load_errors else "LOADED",
            "reason_code": "PRIMITIVES_ARG_INVALID" if load_errors else None,
            "kit_modules": rows,
            "load_errors": [{"path": pth, "detail": d} for pth, d in load_errors],
        }
    )
    codes: list[str] = []
    for row in rows:
        for code in row.get("manifest_reason_codes") or ():
            if code not in codes:
                codes.append(code)
    by_status: dict[str, int] = {}
    for row in rows:
        by_status[row["manifest"]] = by_status.get(row["manifest"], 0) + 1
    face["cli_gates"].append(
        {
            "gate": "kit_manifest",
            # MATCH is claimed only when EVERY kit declared a set and it was the
            # set it registered. A kit that declared nothing was compared to
            # nothing, so the aggregate never reads as a pass on its behalf:
            # ABSENT when no kit declared anything comparable, PARTIAL when some
            # did and some did not.
            "status": (
                "MISMATCH"
                if codes
                else (
                    "MATCH"
                    if rows and by_status.get("match") == len(rows)
                    else ("ABSENT" if not by_status.get("match") else "PARTIAL")
                )
            ),
            "reason_code": codes[0] if codes else None,
            "reason_codes": codes,
            "by_status": by_status,
        }
    )
    face["reason_codes"].extend(codes)
    if rows:
        _print_kit_result(rows)
    # ERROR outranks REJECT: a kit that could not be loaded means this run could
    # not conclude about it, whatever the kits either side of it reported. The
    # mismatch rows are still on the face and still printed.
    if load_errors:
        face["reason_codes"].append("PRIMITIVES_ARG_INVALID")
        return 2
    return 1 if codes else 0


def _main(args, face: dict) -> int:
    mode_error = _select_input_mode(args)
    if mode_error is not None:
        print(f"ERROR  input_mode  [INPUT_MODE_INVALID] {mode_error}", file=sys.stderr)
        face["reason_codes"].append("INPUT_MODE_INVALID")
        face["cli_gates"].append(
            {
                "gate": "input_mode",
                "status": "ERROR",
                "reason_code": "INPUT_MODE_INVALID",
                "detail": mode_error,
            }
        )
        return 2
    if args.kit:
        return _main_kit(args, face)

    face["subject"] = "bundle"
    bundle_dir = Path(args.bundle_dir).resolve()

    if not bundle_dir.is_dir():
        print(f"ERROR: not a directory: {bundle_dir}", file=sys.stderr)
        face["reason_codes"].append("BUNDLE_DIR_NOT_FOUND")
        return 1
    if not (bundle_dir / "manifest.json").exists():
        print(f"ERROR: no manifest.json in {bundle_dir}", file=sys.stderr)
        face["reason_codes"].append("MANIFEST_MISSING")
        return 1

    # Input-admission (ADR D9) BEFORE any json.loads on this path: a deeply-nested or
    # oversized manifest is rejected here (exit 1) rather than RecursionError-ing inside
    # _load_manifest / the DSSE / C18 readers (which the main() boundary would otherwise
    # have to catch as a VERIFIER ERROR, exit 2).
    try:
        _raw_manifest = (bundle_dir / "manifest.json").read_bytes()
    except OSError:
        _raw_manifest = b""
    face["input_manifest_sha256"] = hashlib.sha256(_raw_manifest).hexdigest()
    _adm = admit_bytes(_raw_manifest, check_name="manifest_admission")
    if _adm is not None:
        r = _adm.reasons[0]
        print(f"FAIL  manifest_admission  [{r.code}] {r.detail}", file=sys.stderr)
        face["reason_codes"].append(r.code)
        return 1

    # ------------------------------------------------------------------
    # DSSE sidecar guard — ALWAYS-ON, fail-closed (Option A)
    # ------------------------------------------------------------------
    # Runs before manifest validation so a post-cutover sealed bundle is
    # detected and surfaced even if the manifest is otherwise structurally
    # valid. stdlib has no Ed25519; we MUST NOT emit verified=True for a
    # sealed bundle. The check reads ONLY the sidecar payload's
    # schema_version (D4-safe: never manifest.json for this decision).
    _dsse_sealed, _dsse_reason, _dsse_detail = _dsse_sidecar_offline_check(bundle_dir)
    face["cli_gates"].append(
        {
            "gate": "dsse_sidecar_guard",
            "status": "FAIL" if _dsse_sealed else "PASS",
            "reason_code": _dsse_reason,
        }
    )
    if _dsse_sealed:
        face["reason_codes"].append(_dsse_reason)
        print()
        print(
            f"FAIL  dsse_sidecar_guard  [{_dsse_reason}] {_dsse_detail}",
            file=sys.stderr,
        )
        print()
        print(
            "OFFLINE VERIFICATION: FAIL — sealed bundle requires substrate verifier "
            f"for Ed25519 check. Reason: {_dsse_reason}",
            file=sys.stderr,
        )
        # We may still run the inner re-derivation checks below as
        # defense-in-depth, but the overall verdict is ALWAYS False for a
        # sealed bundle. If manifest validation also fails we exit 1 early
        # (correct — sealed bundle is always FAIL).

    # Load the manifest for plugin construction / C18 / receipt dispatch below.
    # The DEEP manifest invariants (schema_version, SHA integrity, snapshots/policy,
    # source attributes, retrieval traces, per_output_manifests, output_mode_signal,
    # OF1) are NO LONGER validated here: BundleVerifier.verify() now subsumes them
    # (ADR D5 — verify() is complete-by-construction), so a deep-validation failure
    # surfaces through the verdict below (a REJECT → exit 1) for CLI and library
    # consumers alike, rather than only on this CLI fast-path.
    try:
        manifest = _load_manifest(bundle_dir)
    except (
        ManifestError,
        BadFragmentID,
        BadOutputMode,
        ThreeSetMismatch,
        BadVisibilityPolicy,
        BadPublicationClass,
    ) as exc:
        print(
            f"FAIL  manifest_validation  [{type(exc).__name__}] {exc}",
            file=sys.stderr,
        )
        face["reason_codes"].append(type(exc).__name__)
        return 1

    plugins = _build_plugins(
        bundle_dir,
        manifest,
        permit_pack_execution=args.unsafe_run_bundle_pack,
    )
    # Auditor authority for spec-pinned dispatch (Axis 1). Built from
    # OPERATOR-side spec bytes; a construction error here is the operator's, not
    # the bundle's, so it exits 2 (could not conclude) and never 1.
    spec_anchor = None
    # UNSOUND COMBINATION — refused, not warned. Packs execute inside
    # _step_typed_check_plugins, which runs BEFORE _step_spec_pinned_dispatch
    # reads outputs/ (audit_bundle/verifier.py, and the SECOND RESIDUAL note in
    # plugins/REASON_CODES.md). A pack with write access to the sealed snapshot
    # can therefore write outputs/<id>.json and have dispatch "agree" with it,
    # manufacturing a green verdict AND measured re-derivation coverage from
    # producer-supplied code. While the CLI could not supply an anchor this was
    # dead code through the shipped tool; --spec-anchor makes it live. Measured
    # 2026-08-17: no shipped pilot is both pack-bearing and CLI-dispatchable
    # (the 4 pack pilots all bind pilot-local primitives), so refusing costs
    # nothing today — but the offline tool ships for arbitrary third-party
    # bundles, where the combination is constructible. Fail closed rather than
    # rely on the operator reading a --help caveat.
    if args.spec_anchor and args.unsafe_run_bundle_pack:
        _detail = (
            "--spec-anchor and --unsafe-run-bundle-pack are mutually exclusive. "
            "A bundle-supplied pack runs BEFORE spec-pinned dispatch reads "
            "outputs/, so it can write the answer dispatch would then check — "
            "the resulting exit 0 (with re-derivation coverage recorded) is "
            "producer code reporting on itself. Re-run with --spec-anchor alone "
            "for an auditor-side re-derivation, or with --unsafe-run-bundle-pack "
            "alone if you intend to execute the producer's pack on a disposable "
            "host and read the result as the producer's own claim."
        )
        print(
            f"ERROR  spec_anchor_arg  [SPEC_ANCHOR_PACK_CONFLICT] {_detail}",
            file=sys.stderr,
        )
        face["reason_codes"].append("SPEC_ANCHOR_PACK_CONFLICT")
        face["cli_gates"].append(
            {
                "gate": "spec_anchor_arg",
                "status": "ERROR",
                "reason_code": "SPEC_ANCHOR_PACK_CONFLICT",
            }
        )
        return 2
    # Auditor-side primitive kit (the second half of the auditor's kit; the
    # anchor below is the first). Loaded BEFORE the verifier is constructed so
    # dispatch resolves against the completed registry. A kit failure is the
    # operator's, not the bundle's: exit 2, nothing concluded.
    if args.primitives:
        try:
            _kit_rows = _load_primitive_kit_arg(list(args.primitives), bundle_dir)
        except PrimitiveKitArgError as exc:
            print(
                f"ERROR  primitives_arg  [PRIMITIVES_ARG_INVALID] {exc}",
                file=sys.stderr,
            )
            face["reason_codes"].append("PRIMITIVES_ARG_INVALID")
            face["cli_gates"].append(
                {
                    "gate": "primitives_arg",
                    "status": "ERROR",
                    "reason_code": "PRIMITIVES_ARG_INVALID",
                }
            )
            return 2
        # WHOSE CODE this run could judge with, on the face. The core verdict
        # additionally carries per-RESOLVED-primitive provenance rows
        # (primitive_provenance disclosure) whenever dispatch engages; this
        # cli_gates row records what was LOADED, including a kit the bundle
        # never exercised (an operator pointing the wrong kit at a bundle
        # should be able to see that from the face).
        # Status is LOADED, deliberately NOT "PASS": loading a kit is not a
        # re-derivation, and "PASS" on a green face invited the reading that the
        # kit's primitive covered something. Whether a loaded primitive was
        # actually USED is the `primitive_provenance` disclosure on the core
        # verdict (a resolved primitive appears there; a loaded-but-unused one
        # does not) — loaded-vs-used are different facts, kept as different
        # fields.
        face["cli_gates"].append(
            {
                "gate": "primitive_kit",
                "status": "LOADED",
                "reason_code": None,
                "kit_modules": _kit_rows,
            }
        )
    try:
        if args.spec_anchor:
            spec_anchor, _anchor_provenance = _build_spec_anchor(
                list(args.spec_anchor), bundle_dir
            )
            # WHOSE authority produced this verdict. Without these rows a
            # self-anchored green (operator pointed --spec-anchor into the
            # bundle) was byte-indistinguishable from a real one on the face;
            # that path is now refused outright, but the face must still SAY
            # what it applied rather than leave the reader to assume. On a
            # bundle that declares outputs (the case an anchor is FOR), the core
            # verdict also carries these rows as a spec_anchor_provenance
            # disclosure, so a library consumer reaches the same authority
            # record; on an outputs-free bundle dispatch is inert and this
            # cli_gates row is the only trace (an anchor there does nothing).
            face["cli_gates"].append(
                {
                    "gate": "spec_anchor",
                    "status": "PASS",
                    "reason_code": None,
                    "anchored_specs": _anchor_provenance,
                }
            )
    except SpecAnchorArgError as exc:
        print(
            f"ERROR  spec_anchor_arg  [SPEC_ANCHOR_ARG_INVALID] {exc}", file=sys.stderr
        )
        face["reason_codes"].append("SPEC_ANCHOR_ARG_INVALID")
        face["cli_gates"].append(
            {
                "gate": "spec_anchor_arg",
                "status": "ERROR",
                "reason_code": "SPEC_ANCHOR_ARG_INVALID",
            }
        )
        return 2
    work_set = None
    _work_set_row = None
    if args.work_set:
        try:
            if not args.spec_anchor:
                # A set can only be applied where dispatch engages, and
                # dispatch does not engage without an auditor anchor. Accepting
                # the flag alone would put a work_set row on the face of a run
                # that could never have applied it. Refused, like the
                # --spec-anchor/--unsafe-run-bundle-pack pair — not warned.
                raise WorkSetArgError(
                    "--work-set requires --spec-anchor: the set pins each "
                    "output to an ANCHORED type, and spec-pinned dispatch does "
                    "not engage without the auditor's anchor, so the set could "
                    "never be applied. Pass both."
                )
            work_set, _work_set_row = _load_work_set_arg(args.work_set, bundle_dir)
        except WorkSetArgError as exc:
            print(f"ERROR  work_set_arg  [WORK_SET_ARG_INVALID] {exc}", file=sys.stderr)
            face["reason_codes"].append("WORK_SET_ARG_INVALID")
            face["cli_gates"].append(
                {
                    "gate": "work_set_arg",
                    "status": "ERROR",
                    "reason_code": "WORK_SET_ARG_INVALID",
                }
            )
            return 2
        # WHAT SET was applied, by sha, so a green face names the denominator
        # it was judged against rather than leaving the reader to infer one.
        # The core verdict carries the same universe_sha on its
        # `type_selection:` disclosure row whenever dispatch engages.
        face["cli_gates"].append(_work_set_row)
    verifier = BundleVerifier(
        plugins=plugins,
        spec_anchor=spec_anchor,
        work_set=work_set,
        unsafe_in_place=args.unsafe_in_place,
        # Strictness lives in the CORE verdict, not in a CLI-side exit-code
        # patch: --require-rederivation makes verify() itself record the
        # clean-ERROR leg, so a library consumer constructing BundleVerifier
        # the same way reaches the SAME verdict (CLI/library divergence is a
        # known failure class here — tests/test_cli_library_verdict_divergence).
        require_rederivation=args.require_rederivation,
    )

    try:
        result = verifier.verify(bundle_dir)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        face["reason_codes"].append("BUNDLE_FILE_NOT_FOUND")
        return 1

    # The work_set gate row's status is read OFF THE VERDICT, never asserted
    # by the loader: the core's `type_selection:` disclosure is the one place
    # the decision was made (APPLIED, or HELD but NOT APPLIED when the set
    # could not be applied), and the two faces must not disagree.
    if _work_set_row is not None:
        _work_set_row["status"] = _work_set_status_from_verdict(result)

    # Tri-state (ADR D8): an ERROR verdict means the verifier could not conclude
    # (a VERIFIER_* reason) — distinct from a REJECT. It maps to exit 2, never 0/1.
    verifier_errored = getattr(result, "state", None) is VerdictState.ERROR

    face["verdict"] = _verdict_to_jsonable(result)
    face["reason_codes"].extend(r.code for r in result.reasons)

    _print_result(result, plugins)

    # ----------------------------------------------------------------------
    # Re-derivation SURFACE disclosure (nothing was re-derived at all)
    # ----------------------------------------------------------------------
    # PRESENTATION ONLY — the decision was made ONCE, in
    # BundleVerifier._step_rederivation_surface_guard, and is read back off the
    # verdict face (same discipline as the extension-receipt loop above: never
    # re-derive a disposition the core already recorded, or --verdict-out and
    # stdout can disagree). Without this the JSON carries the disclosure and the
    # terminal shows a clean wall of PASS lines — and the terminal is what the
    # human reads. Under --require-rederivation the core records a
    # clean-ERROR leg, which maps the exit to 2 UNLESS a REJECT dominates it
    # (compose is REJECT-dominant) — see the `_gated` note below, which is why
    # the printed word is not simply a function of the flag.
    _surface_disclosure = next(
        (
            d
            for d in getattr(result.completeness, "disclosures", None) or ()
            if d.startswith(_RE_DERIVATION_SURFACE_PREFIX)
        ),
        None,
    )
    if _surface_disclosure is not None:
        body = _surface_disclosure[len(_RE_DERIVATION_SURFACE_PREFIX) :]
        # Loudness is driven by the VERDICT, not by the flag that requested it.
        # Keying the printed severity off `args.require_rederivation` let the
        # two disagree — print ERROR, return 0 — the moment anything else
        # decided the leg.
        #
        # Reading the recorded leg alone is still not enough: `compose` is
        # REJECT-dominant, so a bundle that is BOTH rejected and strict-gated
        # (e.g. any migrated pilot under this CLI — AnchorViolation REJECT plus
        # the surface leg) carries the leg while the process exits 1. Printing
        # "ERROR" there would name a could-not-conclude on a run the exit code
        # calls artifact-bad. So require the leg AND the composed ERROR state:
        # the word on screen then matches the exit code on every path.
        _leg_recorded = any(
            r.check_name == "re_derivation_surface" for r in result.reasons
        ) or any(
            r.check_name == "re_derivation_surface"
            for leg in result.legs
            for r in leg.reasons
        )
        _gated = _leg_recorded and verifier_errored
        # Three states, not two, so the JSON face cannot contradict itself: a
        # strict run that a REJECT dominates still HAS the leg in
        # verdict.reasons, and reporting the gate as plain NOT_COVERED there
        # told a cli_gates consumer "advisory" while a verdict.reasons consumer
        # read "could-not-conclude leg recorded".
        _gate_status = (
            "ERROR" if _gated else "GATED_SUBSUMED" if _leg_recorded else "NOT_COVERED"
        )
        face["reason_codes"].append(BundleVerifier.NO_RE_DERIVATION_KIND)
        face["cli_gates"].append(
            {
                "gate": "re_derivation_surface",
                "status": _gate_status,
                "reason_code": BundleVerifier.NO_RE_DERIVATION_KIND,
            }
        )
        print()
        if _gated:
            print(f"ERROR  re_derivation_surface  {body}", file=sys.stderr)
        elif _leg_recorded:
            print(
                f"NOTE (gated; subsumed by REJECT)  re_derivation_surface  {body}",
                file=sys.stderr,
            )
        else:
            print(f"NOTE  re_derivation_surface  {body}")

    # ----------------------------------------------------------------------
    # C18 stdlib-only structural extension
    # ----------------------------------------------------------------------
    # Auto-on when bundle has verifier_identity field; explicit --c18-check
    # / --no-c18-check overrides. A STRUCTURAL pass here is NOT a trust
    # assertion — the 4-step consumer flow at receipts.vkernel.dev asserts
    # trust.
    run_c18 = args.c18_check
    if run_c18 is None:
        try:
            mf = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
            run_c18 = _c18_extract_verifier_identity(mf) is not None
        except (OSError, json.JSONDecodeError):
            run_c18 = False

    # A sealed bundle is ALWAYS failed, regardless of any plugin results.
    overall_ok = result.ok and not _dsse_sealed
    if run_c18:
        c18_ok, c18_reason, c18_detail = _c18_structural_check(bundle_dir)
        face["cli_gates"].append(
            {
                "gate": "c18_structural",
                "status": "PASS" if c18_ok else "FAIL",
                "reason_code": c18_reason,
            }
        )
        if not c18_ok:
            face["reason_codes"].append(c18_reason)
        if c18_ok:
            print()
            print(f"PASS  c18_structural  {c18_detail}")
            print()
            print("OFFLINE STRUCTURAL VERIFICATION: PASS")
            print(_C18_NEXT_STEPS_HINT)
        else:
            print()
            print(
                f"FAIL  c18_structural  [{c18_reason}] {c18_detail}",
                file=sys.stderr,
            )
            print()
            print(
                f"OFFLINE STRUCTURAL VERIFICATION: FAIL — reason: {c18_reason}",
                file=sys.stderr,
            )
            overall_ok = False

    # ----------------------------------------------------------------------
    # C19 cross-host edge guard (red-team A1 fix) — ALWAYS-ON, fail-closed
    # ----------------------------------------------------------------------
    # No opt-out flag: opting out of a security guard is itself the footgun A1
    # exploited. If the bundle carries cross_host_authenticators edges, this
    # offline stdlib CLI hard-FAILs and routes to the verifier that actually
    # checks them. Bundles with no such edges are unaffected.
    c19_ok, c19_reason, c19_detail = _c19_crosshost_structural_check(bundle_dir)
    face["cli_gates"].append(
        {
            "gate": "c19_cross_host",
            "status": "PASS" if c19_ok else "FAIL",
            "reason_code": c19_reason,
        }
    )
    if not c19_ok:
        face["reason_codes"].append(c19_reason)
        print()
        print(
            f"FAIL  c19_cross_host  [{c19_reason}] {c19_detail}",
            file=sys.stderr,
        )
        overall_ok = False

    # ----------------------------------------------------------------------
    # Pluggable extension-receipt verification
    # ----------------------------------------------------------------------
    # The manifest may carry extension_receipts: {kind: assembly}. Each kind was
    # dispatched ONCE — inside BundleVerifier._step_extension_receipts, against
    # that run's registry snapshot — and its disposition recorded on the verdict
    # face (FAIL/NOT_EVALUATED as reason legs, PASS as a prefixed disclosure).
    # This loop is presentation + exit-code mapping over those recorded
    # dispositions; it never re-executes a handler, so the printed lines and
    # the canonical verdict in --verdict-out come from the SAME handler run.
    # A kind with NO handler is a claim that is PRESENT but UNVERIFIED by this
    # build: the verifier COULD NOT CONCLUDE on it, so it is gated as ERROR
    # (exit 2) — NOT a green verdict with a prose caveat, which a consumer
    # keying on the exit code would read as covered (trust laundering; cf. S1
    # "the verifier itself is forbidden from short-cutting"). This mirrors the
    # re_derivation_invocation NOT-RUN posture below.
    # No-op (and unaffected) for every bundle that carries no extension receipts.
    extension_not_evaluated = False
    receipts = (
        manifest.extension_receipts
        if isinstance(manifest.extension_receipts, dict)
        else {}
    )
    for kind in sorted(receipts):
        status, reason, detail = _extension_receipt_disposition(kind, result)
        face["cli_gates"].append(
            {
                "gate": f"extension_receipt:{kind}",
                "status": status,
                "reason_code": (
                    "EXTENSION_RECEIPT_NOT_EVALUATED"
                    if status == "NOT_EVALUATED"
                    else reason
                ),
            }
        )
        if status == "NOT_EVALUATED":
            face["reason_codes"].append("EXTENSION_RECEIPT_NOT_EVALUATED")
        elif status != "PASS":
            face["reason_codes"].append(reason)
        if status == "PASS":
            print()
            print(f"PASS  extension_receipt:{kind}  {detail}")
        elif status == "NOT_EVALUATED":
            print()
            print(
                f"ERROR  extension_receipt:{kind}  [EXTENSION_RECEIPT_NOT_EVALUATED] "
                f"{detail}. The claim is PRESENT but UNVERIFIED by this build — the "
                "verifier COULD NOT CONCLUDE on it. Do NOT accept a green verdict as "
                f"covering it; verify with a build that registers a handler for "
                f"{kind!r}.",
                file=sys.stderr,
            )
            extension_not_evaluated = True
        elif status == "UNACCOUNTED":
            print()
            print(
                f"ERROR  extension_receipt:{kind}  [{reason}] {detail}",
                file=sys.stderr,
            )
            extension_not_evaluated = True
        else:
            print()
            print(
                f"FAIL  extension_receipt:{kind}  [{reason}] {detail}",
                file=sys.stderr,
            )
            overall_ok = False

    # ----------------------------------------------------------------------
    # Reserved-but-unverified field disclosure (red-team B-4 confused-deputy)
    # ----------------------------------------------------------------------
    # C17 (attested_serving) and C20 (semantic_fidelity) are M0 stubs at v0.3:
    # the manifest PARSES them but no plugin verifies them. SUBSTANTIVE/adversarial
    # values (fabricated TEE measurement, semantic_fidelity=ENTAILMENT) do NOT ride
    # along green — they are rejected upstream (exit 1) by bundle_manifest.
    # _validate_schema_reserved_blocks_v03, which schema-locks each field to its
    # reservation shape. What survives to here is a conformant reservation marker;
    # this NOTE discloses that the reserved CAPABILITY is not yet verified so the
    # PASS verdict cannot be read as covering it. Actual verification of these
    # fields is future S17/S20 work.
    _print_reserved_unverified_note(bundle_dir)

    # ----------------------------------------------------------------------
    # Re-derivation coverage is GATING (it is the core property this verifier
    # exists to prove). A bundle that CLAIMS re_derivation_invocation but whose
    # pack was NOT executed in safe mode has had its core property left
    # unverified — the verifier COULD NOT CONCLUDE. That is ERROR (exit 2), not
    # a green OK: returning exit 0 here would overclaim coverage to any consumer
    # that keys on the exit code. --unsafe-run-bundle-pack (trusted/disposable
    # host) or migration to spec-pinned dispatch makes re-derivation actually run.
    #
    # Dispatch carve-out (CLI/library convergence, 2026-06-12): when the manifest
    # declares `outputs`, spec-pinned dispatch already verified re-derivation the
    # safe way (and any mismatch is a REJECT in the verdict above). A pack shipped
    # alongside dispatch is then a redundant unsafe artifact (the pilots carry it
    # for the --unsafe path), NOT present-but-unverified — so it does not gate.
    # This mirrors the core `_step_rederivation_pack_guard` exemption exactly, so
    # the CLI and a library `verify()` reach the SAME verdict on a pack+dispatch
    # bundle (the residual the red-team TOCTOU sweep would otherwise leave open).
    dispatch_covers_rederivation = bool(getattr(manifest, "outputs", ()) or ())
    rederivation_not_run = not dispatch_covers_rederivation and any(
        getattr(p, "name", "") == "re_derivation_invocation"
        and getattr(p, "permit_execution", True) is False
        for p in plugins
    )
    if rederivation_not_run:
        face["reason_codes"].append("RE_DERIVATION_NOT_EXECUTED")
        face["cli_gates"].append(
            {
                "gate": "re_derivation",
                "status": "NOT_EVALUATED",
                "reason_code": "RE_DERIVATION_NOT_EXECUTED",
            }
        )
        print()
        print(
            "ERROR  re_derivation  [RE_DERIVATION_NOT_EXECUTED] re-derivation is "
            "the core verified property and was NOT evaluated in safe mode (bundle "
            "pack not executed). Verifier COULD NOT CONCLUDE — do NOT accept. "
            "Re-run with --unsafe-run-bundle-pack on a trusted/disposable host, or "
            "migrate the bundle to spec-pinned dispatch.",
            file=sys.stderr,
        )

    # Exit-code map (ADR D8): 2 = ERROR (verifier could not conclude) dominates;
    # else 1 = REJECT (artifact bad); else 0 = OK. Old scripts keying on `exit != 0`
    # stay correct — both REJECT and ERROR are non-zero (not certified).
    # A present-but-unverified extension_receipt is could-not-conclude, same class
    # as a claimed-but-NOT-RUN re-derivation: neither may ride a green exit code.
    # (Substantive C17/C20 reserved-field values are handled earlier — rejected at
    # manifest parse, exit 1 — so they need no branch here.)
    if verifier_errored or rederivation_not_run or extension_not_evaluated:
        return 2
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
