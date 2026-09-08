"""Host-side container-image digest verification for the audit-bundle verifier.

Wrapper around `cosign manifest` + `crane digest` that verifies the running
verifier image's identity from the HOST, outside any compromised container
runtime. A malicious container runtime (e.g. a tampered containerd / dockerd
runtime API sitting below the verifier's trust boundary) can return a spoofed
self-reported digest, so the in-container self-check is treated as a logging-
only tripwire signal. The actual trust mechanism is this host-side comparison
of the registry-reported digest (via cosign + crane) against the expected
digest pinned in the TUF-fetched release manifest.

Status (v0.1.0, pre-ceremony) — READ THIS BEFORE RELYING ON THE PASS BELOW:
the C18 TUF roots shipped in this tree are still synthetic (bootstrap root with
empty signatures + ``TBD-*`` placeholder digests) and no hardware-signed release
has been cut, so the host-side PASS flow below is NOT yet runnable end-to-end
against a genuine release — the TUF fetch fail-closes (exit 4) on the bootstrap
root. This wrapper becomes live at the C18 key ceremony + first signed release.
The shipped, working verifier today is the offline ``veriker/cli/verify.py`` (bundle
validity); this host-side identity check is the future ceremony deliverable.
See SECURITY.md -> "Verifier-identity trust boundary (C18)".

User-facing output deliberately avoids asserting trust via the in-container
self-check (the self-check is a signal, not a verdict); the strings below are
phrased as 'Reported' vs 'Official' and PASS / DIVERGENCE:

  - 'Reported (cosign): sha256:<...>'
  - 'Reported (crane):  sha256:<...>'
  - 'Official (TUF):     sha256:<...>'
  - 'HOST-SIDE DIGEST VERIFICATION: PASS — running image identity bound to
     TUF-pinned release manifest'
  - 'DIVERGENCE — investigate.' on mismatch

This is the consumer-side host wrapper. The substrate TUF client it invokes
is not stdlib-only; this wrapper drives it via subprocess against the cosign +
crane binaries, which are user prerequisites provisioned by the consumer
environment.

Exit codes:
  0 — match
  2 — any pair differs (cosign vs crane vs TUF)
  3 — cosign or crane missing on PATH
  4 — TUF fetch failed / release manifest unavailable
  5 — STH gossip structural divergence detected (--sth-gossip extension)
  6 — STH gossip requested but could NOT be cryptographically verified
      (structural pre-check only; signature/witness verification is v0.4)
  7 — Rekor inclusion verification requested (--rekor-bundle) and FAILED, or
      could not be cryptographically evaluated (fail-closed) — including when
      the Rekor log key could not be resolved from the sigstore-trust-root role
      (REKOR_LOG_KEY_UNRESOLVED / _DIGEST_MISMATCH / _TYPE_MISMATCH), when the
      logged statement is not the release's image-binding attestation
      (REKOR_PREDICATE_TYPE_MISMATCH), or when the bundle cannot be parsed
      within the verifier's bounds (a depth-bombed file is exit 7, not a
      traceback)
  1 — an uncaught Python exception (not a verdict: no verifier output line
      names it; treat as could-not-conclude and report it as a bug)
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
import subprocess  # noqa: S404 — invoked only against cosign + crane binaries
import sys
from pathlib import Path

# Default image registry pin (the published verifier image repository).
DEFAULT_IMAGE_REPO = "ghcr.io/veriker/veriker"

EXIT_OK = 0
EXIT_DIGEST_MISMATCH = 2
EXIT_PREREQ_MISSING = 3
EXIT_TUF_FETCH_FAILED = 4
EXIT_STH_GOSSIP_FAILED = 5
EXIT_STH_GOSSIP_NOT_VERIFIED = 6
EXIT_REKOR_INCLUSION_FAILED = 7


def _which(binary: str) -> str | None:
    """Locate `binary` on PATH; return None if absent."""
    return shutil.which(binary)


def _run_cosign_manifest(cosign: str, image_tag: str) -> tuple[bool, str, str]:
    """Run `cosign manifest <image_tag>`; return (ok, digest_or_empty, stderr).

    cosign manifest emits the JSON OCI manifest; we extract the manifest's
    SHA-256 digest from the registry-side `Docker-Content-Digest` header
    or from cosign's output line `Digest: sha256:...`.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [cosign, "manifest", image_tag],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc)
    if result.returncode != 0:
        return False, "", result.stderr
    # cosign manifest emits the manifest JSON to stdout. Some cosign versions
    # also emit the digest on a header line. Try both.
    for line in result.stdout.splitlines():
        if line.startswith("Digest:") and "sha256:" in line:
            return True, line.split("sha256:", 1)[1].strip().split()[0].rstrip(), ""
        if line.startswith("sha256:"):
            return True, line.strip(), ""
    # Fall back: hash the manifest JSON itself (this is what crane digest does).
    # We don't reimplement that here — return failure with a useful message.
    return (
        False,
        "",
        "cosign manifest output did not contain a 'Digest:' or 'sha256:' line",
    )


def _run_crane_digest(crane: str, image_tag: str) -> tuple[bool, str, str]:
    """Run `crane digest <image_tag>`; return (ok, digest_or_empty, stderr).

    crane digest emits the content-addressed image digest to stdout (single
    line: `sha256:<hex>`).
    """
    try:
        result = subprocess.run(  # noqa: S603
            [crane, "digest", image_tag],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc)
    if result.returncode != 0:
        return False, "", result.stderr
    digest = result.stdout.strip()
    if digest.startswith("sha256:") and len(digest) == 7 + 64:
        return True, digest, ""
    return False, "", f"crane digest returned unexpected output: {digest!r}"


def _fetch_tuf_expected_digest(
    release: str, trust_dir: Path, feed_url: str | None = None
) -> tuple[bool, str, str]:
    """Fetch the expected OCI image digest via the substrate TUF client.

    Returns (ok, digest_or_empty, err). The substrate-verifier path is not
    stdlib-only — this wrapper accepts that dependency boundary.
    """
    try:
        from audit_bundle.extensions.c18_tuf_client import (
            TUFClientError,
            fetch_release_manifest,
        )
    except ImportError as exc:
        return (
            False,
            "",
            f"substrate TUF client unavailable: {exc}",
        )
    try:
        kwargs = {"release_version": release, "trust_dir": trust_dir}
        if feed_url is not None:
            kwargs["feed_url"] = feed_url
        result = fetch_release_manifest(**kwargs)
    except TUFClientError as exc:
        return False, "", f"TUF fetch failed: {exc}"
    except Exception as exc:  # noqa: BLE001 — surface any unexpected error
        return False, "", f"TUF fetch unexpected error: {exc}"

    # MANIFEST.txt is a text key=value file; parse for image_digest.
    target_path = result.get("target_path")
    if not target_path or not Path(target_path).is_file():
        return False, "", "TUF target file missing"
    try:
        content = Path(target_path).read_text(encoding="utf-8")
    except OSError as exc:
        return False, "", f"cannot read TUF target: {exc}"
    for line in content.splitlines():
        if line.startswith("image_digest="):
            digest = line.split("=", 1)[1].strip()
            if digest.startswith("sha256:") and len(digest) == 7 + 64:
                return True, digest, ""
    return False, "", "TUF release manifest does not contain image_digest=sha256:<...>"


def _print_side_by_side(
    cosign_digest: str,
    crane_digest: str,
    tuf_digest: str,
    *,
    match: bool,
) -> None:
    """Render the side-by-side Reported/Official digest comparison.

    User-facing language is consistently 'Reported' / 'Official' / 'PASS' /
    'DIVERGENCE' so the output never asserts trust via the in-container
    self-check.
    """
    print(f"Reported (cosign): {cosign_digest or '(unavailable)'}")
    print(f"Reported (crane):  {crane_digest or '(unavailable)'}")
    print(f"Official (TUF):    {tuf_digest or '(unavailable)'}")
    if match:
        print()
        print(
            "HOST-SIDE DIGEST VERIFICATION: PASS — running image identity "
            "bound to TUF-pinned release manifest"
        )
    else:
        print()
        print("DIVERGENCE — investigate.", file=sys.stderr)


def _check_sth_gossip_structure(
    sth_gossip_path: Path,
    *,
    release: str,
    trust_dir: Path,
) -> tuple[list[str], bool, str]:
    """Run the STH-gossip structural pre-check.

    Returns (reason_codes, cryptographically_verified, err).

    IMPORTANT: ``cryptographically_verified`` is always False at v0.3 — the
    underlying helper performs no signature/witness/consistency cryptographic
    verification (see c18_tuf_client.check_sth_gossip_structure). This wrapper
    has no inclusion-proof source wired, so it passes an empty proof and the
    helper runs the signature-PRESENCE check only. An empty reason-set therefore
    means "no structural divergence detected", NOT "verified" — the caller
    must surface that distinction and must not report a cryptographic PASS.
    """
    try:
        from audit_bundle.extensions.c18_tuf_client import check_sth_gossip_structure  # type: ignore[attr-defined]
    except ImportError:
        # Extension absent: we verified nothing. Report not-verified, no err.
        return [], False, "check_sth_gossip_structure extension not available"

    try:
        sth_json = json.loads(sth_gossip_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], False, f"cannot read gossiped STH at {sth_gossip_path}: {exc}"

    # No bundle rekor_inclusion_proof is available to this host wrapper, so the
    # structural cross-check is skipped and only the signature-presence shape
    # check runs. This is NOT cryptographic verification.
    try:
        result = check_sth_gossip_structure(sth_json, {})
    except Exception as exc:  # noqa: BLE001
        return [], False, f"check_sth_gossip_structure raised: {exc}"
    return list(result.reasons), bool(result.cryptographically_verified), ""


@dataclass(frozen=True)
class RekorInclusionResult:
    """Outcome of the Rekor leg. ``ok`` requires all THREE: proof, checkpoint, binding.

    ``inclusion_ok`` / ``checkpoint_ok`` are the two cryptographic legs; ``bound_via`` /
    ``bound_to`` name what the logged leaf committed to and which held digest it matched.
    ``err`` non-empty means the leg could not be evaluated at all (extension absent,
    unreadable bundle) — could-not-conclude, distinct from a determinate failure.
    """

    ok: bool
    inclusion_ok: bool
    checkpoint_ok: bool | None
    reasons: tuple[str, ...]
    err: str
    bound_via: str | None = None
    bound_to: str | None = None


def _rekor_could_not_evaluate(err: str) -> RekorInclusionResult:
    return RekorInclusionResult(False, False, None, (), err)


# Rekor log key provenance — refusal codes (the leg cannot be evaluated without
# a key the verifier holds; none of these ever falls back to a constant).
REKOR_LOG_KEY_UNRESOLVED = "REKOR_LOG_KEY_UNRESOLVED"
REKOR_LOG_KEY_DIGEST_MISMATCH = "REKOR_LOG_KEY_DIGEST_MISMATCH"
REKOR_LOG_KEY_TYPE_MISMATCH = "REKOR_LOG_KEY_TYPE_MISMATCH"

#: in-toto predicateType the release IMAGE-BINDING attestation carries. Kept as a
#: literal here because this module is stdlib-only at import; the substrate's copy
#: is `audit_bundle.extensions.rekor_anchor.IMAGE_BINDING_PREDICATE_TYPE` and the
#: consumer battery asserts the two (and the producer's literal) are equal.
IMAGE_BINDING_PREDICATE_TYPE = "https://vkernel.dev/predicates/release-image-binding/v1"

#: Default `sigstore-trust-root` entry: the production Rekor v1 log key (P-256).
DEFAULT_REKOR_LOG_KEY_TARGET = "rekor.pub"


@dataclass(frozen=True)
class RekorLogKeyResolution:
    """The Rekor log key this run trusts, and where it came from.

    ``key`` is None iff ``reason_code`` is set: the role could not be fetched, does not
    pin the entry, its digest disagrees with the served bytes, or the PEM loads as
    a class the role document does not declare. ``provenance`` is printed on the
    face so a reader knows WHICH pinned key vouched for the checkpoint.
    """

    key: object | None
    provenance: str
    reason_code: str | None
    detail: str


def _resolve_rekor_log_key(
    trust_dir: Path, *, feed_url: str | None, entry: str
) -> RekorLogKeyResolution:
    """Resolve the Rekor log key from the `sigstore-trust-root` role — never a constant.

    The role document (through the TUF chain, strict) pins the entry's digest and
    `type`; the key BYTES are a target of the same repository
    (`sigstore-trust-root/keys/<entry>`), hash-pinned by the targets metadata and
    required to hash to the role's declared digest
    (`c18_tuf_client.fetch_sigstore_trust_root_key`). The loaded key's class must
    match the declared type: `ecdsa-public-key-pem` -> P-256 (Rekor v1),
    `ed25519-public-key-pem` -> Ed25519 (Rekor v2). ONE key per run, chosen by the
    operator (`--rekor-log-key-target`): the bundle's `logId` is producer bytes and
    does not get to pick which log vouches for it.

    Every failure is a typed refusal with its own code; there is no fallback to
    `rekor_anchor.REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM` (documented real bytes kept
    for tests; the CLI no longer reads them).
    """
    try:
        from audit_bundle.extensions import c18_tuf_client as _tc
        from audit_bundle.extensions import rekor_anchor as _ra
    except ImportError as exc:
        return RekorLogKeyResolution(
            key=None,
            provenance="",
            reason_code="REKOR_LOG_KEY_UNRESOLVED",
            detail=f"substrate extension unavailable ({exc})",
        )
    kwargs = {"trust_dir": trust_dir}
    if feed_url is not None:
        kwargs["feed_url"] = feed_url
    try:
        fetched = _tc.fetch_sigstore_trust_root_key(entry, **kwargs)
    except _tc.TUFTrustRootKeyDigestMismatch as exc:
        return RekorLogKeyResolution(
            key=None, provenance="", reason_code="REKOR_LOG_KEY_DIGEST_MISMATCH", detail=str(exc)
        )
    except _tc.TUFClientError as exc:
        return RekorLogKeyResolution(
            key=None, provenance="", reason_code="REKOR_LOG_KEY_UNRESOLVED", detail=str(exc)
        )
    except Exception as exc:  # noqa: BLE001 — surface, never launder into a key
        return RekorLogKeyResolution(
            key=None,
            provenance="",
            reason_code="REKOR_LOG_KEY_UNRESOLVED",
            detail=f"unexpected error resolving key: {exc}",
        )
    try:
        key = _ra.load_rekor_log_public_key(fetched["key_bytes"])
    except _ra.RekorAnchorError as exc:
        return RekorLogKeyResolution(
            key=None, provenance="", reason_code="REKOR_LOG_KEY_UNRESOLVED", detail=str(exc)
        )
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed  # noqa: PLC0415

    loaded_class = "ed25519" if isinstance(key, _ed.Ed25519PublicKey) else "ec-p256"
    declared_class = _tc.SIGSTORE_LOG_KEY_TYPES.get(fetched["declared_type"])
    if loaded_class != declared_class:
        return RekorLogKeyResolution(
            key=None,
            provenance="",
            reason_code="REKOR_LOG_KEY_TYPE_MISMATCH",
            detail=
            f"sigstore-trust-root entry {entry!r} declares type "
            f"{fetched['declared_type']!r} ({declared_class}) but the pinned PEM "
            f"loads as {loaded_class}; the document says what the key is, the bytes "
            "do not get to decide (fail-closed).",
        )
    signers = ",".join(fetched.get("role_signed_by", ())) or "NONE"
    provenance = (
        f"sigstore-trust-root role target {entry!r} (type "
        f"{fetched['declared_type']}, {fetched['declared_sha256']}) via TUF chain at "
        f"{fetched['feed_url']}; role document 2-of-3 signed_by={signers}"
    )
    return RekorLogKeyResolution(key, provenance, None, "")


def _verify_rekor_inclusion(
    rekor_bundle_path: Path,
    expected_subject_digests: frozenset[str],
    *,
    rekor_log_key: object,
    expected_predicate_type: str | None,
) -> RekorInclusionResult:
    """Cryptographically verify that the Rekor entry is in the log AND commits to the release digest.

    Consumes the cosign ``.sigstore-bundle.json`` (the
    ``application/vnd.dev.sigstore.bundle.v0.3+json`` format emitted by the
    release sigstore-sign job), extracts its embedded Rekor tlog entry, and runs
    all three legs, fail-closed:

      1. re-derive the RFC 6962 inclusion proof for the entry's canonicalized
         body — binds the logged leaf to the checkpoint's root;
      2. verify the checkpoint's signature against ``rekor_log_key`` — the key the
         VERIFIER resolved from the ``sigstore-trust-root`` role
         (``_resolve_rekor_log_key``), never read from the bundle and never a
         compile-time constant — and bind that signed root to the proof root; only
         this leg ties the root to Rekor's genuine tree head;
      3. **bind the logged leaf to the release digest**: decode the entry body, derive the
         digest(s) it commits to by entry kind (``rekor_anchor.rekor_body_subject_digests``),
         and require one of them to be in ``expected_subject_digests`` — the set the
         VERIFIER holds (the TUF-fetched release image digest), never anything read
         from the bundle.

    Legs 1 and 2 alone prove "these bytes are in the public log", which every genuine
    public entry satisfies; before leg 3 existed, any stranger's Sigstore bundle
    verified our release. Leg 3 proves the entry NAMES the release digest — a public
    value — not WHO logged it: the signing identity in the entry is out of scope here
    (`cosign verify-blob --certificate-identity` is that check), so "commits to" is the
    claim, never "is ours". A binding failure is reported under its own reason code so
    it is never mistaken for a broken proof. An empty ``expected_subject_digests`` can
    never bind (no vacuous pass).

    This is the consumer-side crypto lane (deferred import of ``cryptography``-
    bearing ``rekor_anchor``), kept off the stdlib-only core per the two-verifier
    boundary. A missing extension or a malformed bundle returns a non-empty ``err``
    — could-not-conclude, never a silent pass.
    """
    try:
        from audit_bundle.extensions import rekor_anchor as _ra
    except ImportError as exc:
        return _rekor_could_not_evaluate(f"rekor_anchor extension unavailable ({exc})")

    try:
        bundle = json.loads(rekor_bundle_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        # RecursionError: a depth-bombed file is could-not-evaluate (exit 7),
        # never a traceback after the digest PASS line (fresh-pass witness
        # `w_rekor.py B`, 2026-09-02).
        return _rekor_could_not_evaluate(
            f"cannot read sigstore bundle at {rekor_bundle_path}: {type(exc).__name__}: {exc}"
        )
    if not isinstance(bundle, dict):
        return _rekor_could_not_evaluate("sigstore bundle is not a JSON object")

    if rekor_log_key is None:
        return _rekor_could_not_evaluate("no Rekor log key resolved (caller error)")
    try:
        anchor, leaf_preimage = _ra.rekor_anchor_from_sigstore_bundle(bundle)
        verdict = _ra.verify_anchor(
            anchor, leaf_preimage, rekor_log_pubkey=rekor_log_key  # type: ignore[arg-type]
        )
    except _ra.RekorAnchorError as exc:
        return _rekor_could_not_evaluate(f"malformed Rekor anchor: {exc}")
    except (RecursionError, MemoryError) as exc:
        return _rekor_could_not_evaluate(
            f"sigstore bundle exceeds the verifier's parsing bounds: {type(exc).__name__}"
        )

    reasons = list(verdict.reasons)

    # Leg 3: the leaf's CONTENT must commit to a digest the verifier holds.
    bound_via: str | None = None
    bound_to: str | None = None
    try:
        body = json.loads(leaf_preimage.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        body = None
    if not isinstance(body, dict):
        reasons.append(_ra.REASON_BODY_UNPARSEABLE)
    else:
        dsse_payload = _ra.sigstore_bundle_dsse_payload(bundle)
        digests, via, reason = _ra.rekor_body_subject_digests(body, dsse_payload)
        if reason is not None:
            reasons.append(reason)
        else:
            matched = sorted(digests & expected_subject_digests)
            if not matched:
                reasons.append(_ra.REASON_SUBJECT_NOT_BOUND)
            elif expected_predicate_type is not None and (
                dsse_payload is None
                or _ra.intoto_predicate_type(dsse_payload) != expected_predicate_type
            ):
                # A statement that merely NAMES the digest among its subjects (an
                # SBOM attestation, a stranger's statement), or an entry kind that
                # carries no statement at all, is not the release's image-binding
                # attestation. `None` means the caller binds ANY statement naming
                # the digest (the generic subject-binding batteries); the release
                # consumer passes the predicate the job emits.
                reasons.append(_ra.REASON_PREDICATE_TYPE_MISMATCH)
            else:
                bound_via, bound_to = via, matched[0]

    ok = verdict.ok and bound_to is not None
    return RekorInclusionResult(
        ok,
        verdict.inclusion_verified,
        verdict.checkpoint_verified,
        tuple(reasons),
        "",
        bound_via,
        bound_to,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Host-side digest verification for v-kernel-audit-bundle. "
            "This is the actual trust mechanism for verifier identity; the "
            "in-container self-check is a tripwire signal only."
        ),
    )
    parser.add_argument(
        "--release",
        required=True,
        help="Release version, e.g. v0.3.0",
    )
    parser.add_argument(
        "--tuf-trust-bundle",
        type=Path,
        required=True,
        dest="trust_dir",
        help="Path to local TUF trust dir (contains bundled root.json)",
    )
    parser.add_argument(
        "--tuf-feed-url",
        default=None,
        help=(
            "TUF feed base URL (default: the substrate's DEFAULT_TUF_FEED_URL). The "
            "release manifest, the sigstore-trust-root role and its key targets are "
            "all fetched from this one repository through the bundled root."
        ),
    )
    parser.add_argument(
        "--rekor-log-key-target",
        default=DEFAULT_REKOR_LOG_KEY_TARGET,
        metavar="ENTRY",
        help=(
            "Which sigstore-trust-root entry pins the Rekor log key this run trusts "
            "(default 'rekor.pub', the production Rekor v1 P-256 log). A Rekor v2 "
            "Ed25519 log is pinned by the ceremony as its own entry (type "
            "ed25519-public-key-pem) and selected here. ONE key per run: the bundle "
            "never chooses which log vouches for it."
        ),
    )
    parser.add_argument(
        "--image-repo",
        default=DEFAULT_IMAGE_REPO,
        help=("OCI image repo (default: ghcr.io/veriker/veriker)."),
    )
    parser.add_argument(
        "--sth-gossip",
        type=Path,
        default=None,
        help=(
            "Optional path to a gossiped STH JSON. When provided, the verifier "
            "additionally cross-checks the bundle's Rekor inclusion proof "
            "against the gossiped STH."
        ),
    )
    parser.add_argument(
        "--rekor-bundle",
        type=Path,
        default=None,
        help=(
            "Optional path to the release's IMAGE-BINDING Sigstore bundle "
            "(`v-kernel-audit-bundle-<release>.image-binding.sigstore-bundle.json`, "
            "a cosign attest-blob over the image manifest bytes, so its logged "
            "in-toto subject IS the image digest; the statement must carry the "
            "release-image-binding predicateType). The verifier re-derives the "
            "entry's RFC 6962 Rekor inclusion proof, verifies the log checkpoint "
            "signature against the Rekor log key resolved from the sigstore-trust-root "
            "TUF role (--rekor-log-key-target), and requires the logged "
            "entry to commit to the TUF-pinned release image digest (fail-closed; "
            "exit 7). The per-artifact `sign-blob` bundles (SBOM, provenance, "
            "SCITT statement) commit to THOSE files' digests, not the image's, "
            "and will exit 7 here by design."
        ),
    )
    args = parser.parse_args(argv)

    image_tag = f"{args.image_repo}:{args.release}"

    # Locate cosign + crane.
    cosign = _which("cosign")
    crane = _which("crane")
    if cosign is None or crane is None:
        missing = [b for b, p in [("cosign", cosign), ("crane", crane)] if p is None]
        print(
            f"ERROR: required binaries missing on PATH: {missing}. "
            f"Install per receipts.vkernel.dev/c18_install_prereqs.md.",
            file=sys.stderr,
        )
        return EXIT_PREREQ_MISSING

    # Run cosign manifest.
    cosign_ok, cosign_digest, cosign_err = _run_cosign_manifest(cosign, image_tag)
    if not cosign_ok:
        print(f"ERROR: cosign manifest failed: {cosign_err}", file=sys.stderr)
        return EXIT_DIGEST_MISMATCH

    # Run crane digest.
    crane_ok, crane_digest, crane_err = _run_crane_digest(crane, image_tag)
    if not crane_ok:
        print(f"ERROR: crane digest failed: {crane_err}", file=sys.stderr)
        return EXIT_DIGEST_MISMATCH

    # Fetch TUF expected digest.
    tuf_ok, tuf_digest, tuf_err = _fetch_tuf_expected_digest(
        args.release,
        args.trust_dir,
        args.tuf_feed_url,
    )
    if not tuf_ok:
        print(f"ERROR: TUF fetch failed: {tuf_err}", file=sys.stderr)
        _print_side_by_side(cosign_digest, crane_digest, "", match=False)
        return EXIT_TUF_FETCH_FAILED

    # Normalize digests for comparison (cosign may emit 'sha256:' prefix or
    # bare hex; crane always emits 'sha256:' prefix).
    def _norm(d: str) -> str:
        return d if d.startswith("sha256:") else f"sha256:{d}"

    c_norm = _norm(cosign_digest)
    cr_norm = _norm(crane_digest)
    t_norm = _norm(tuf_digest)

    match = c_norm == cr_norm == t_norm
    _print_side_by_side(c_norm, cr_norm, t_norm, match=match)

    if not match:
        return EXIT_DIGEST_MISMATCH

    # Optional STH gossip cross-check.
    if args.sth_gossip is not None:
        reasons, crypto_verified, sth_err = _check_sth_gossip_structure(
            args.sth_gossip,
            release=args.release,
            trust_dir=args.trust_dir,
        )
        if reasons:
            # A real structural divergence was detected.
            print(
                f"ERROR: STH-gossip structural divergence detected: "
                f"reasons={reasons} err={sth_err}",
                file=sys.stderr,
            )
            return EXIT_STH_GOSSIP_FAILED
        if not crypto_verified:
            # No divergence found, but nothing was cryptographically verified.
            # Do NOT report a PASS — that would launder an unverified state
            # through exit 0. Surface the unverified status and exit non-zero
            # because the user explicitly requested the gossip check.
            detail = f" ({sth_err})" if sth_err else ""
            print(
                "STH-gossip: NOT CRYPTOGRAPHICALLY VERIFIED — structural "
                "pre-check only; no signature, witness co-signature, or "
                "consistency-proof verification is performed at v0.3"
                f"{detail}. No structural divergence was detected.",
                file=sys.stderr,
            )
            return EXIT_STH_GOSSIP_NOT_VERIFIED
        print("STH-gossip cross-check: VERIFIED")

    # Optional Rekor transparency-log inclusion verification (real, cryptographic).
    if args.rekor_bundle is not None:
        # The ONLY digest the Rekor leaf may bind to is the one the verifier holds:
        # the TUF-pinned release image digest (already equal to cosign + crane above).
        # Nothing read from the bundle enters this set.
        # The log key is VERIFIER-HELD: resolved from the sigstore-trust-root role
        # through the TUF chain (digest + type pinned by the ceremony), never read
        # from the bundle, never a constant. Unresolvable => the leg cannot run.
        key_res = _resolve_rekor_log_key(
            args.trust_dir, feed_url=args.tuf_feed_url, entry=args.rekor_log_key_target
        )
        if key_res.key is None:
            print(
                f"Rekor inclusion: NOT VERIFIED — [{key_res.reason_code}] {key_res.detail} "
                "Fail-closed: without a Rekor log key pinned by the sigstore-trust-root "
                "role, the checkpoint cannot be attributed to any log.",
                file=sys.stderr,
            )
            return EXIT_REKOR_INCLUSION_FAILED
        print(f"Rekor log key: {key_res.provenance}")
        rekor = _verify_rekor_inclusion(
            args.rekor_bundle,
            frozenset({t_norm}),
            rekor_log_key=key_res.key,
            expected_predicate_type=IMAGE_BINDING_PREDICATE_TYPE,
        )
        if rekor.err:
            # Could not evaluate (extension absent / unreadable bundle). Do NOT
            # launder an unverified state through exit 0 — the user asked for it.
            print(
                f"Rekor inclusion: NOT VERIFIED — {rekor.err}. Fail-closed: the "
                "release entry's transparency-log inclusion could not be "
                "cryptographically checked.",
                file=sys.stderr,
            )
            return EXIT_REKOR_INCLUSION_FAILED
        if not rekor.ok:
            legs = (
                f"inclusion_proof={'ok' if rekor.inclusion_ok else 'FAILED'} "
                f"checkpoint={'ok' if rekor.checkpoint_ok else 'FAILED'} "
                f"subject_binding={'ok' if rekor.bound_to else 'FAILED'}"
            )
            print(
                f"Rekor inclusion: FAILED — reasons={list(rekor.reasons)} [{legs}]. "
                "The supplied bundle does not prove that THIS release is in the "
                "transparency log: either the entry is not provably included under "
                "the pinned log key, or the logged entry does not commit to the "
                f"release image digest {t_norm}.",
                file=sys.stderr,
            )
            return EXIT_REKOR_INCLUSION_FAILED
        print(
            "Rekor inclusion cross-check: VERIFIED — logged entry commits to release "
            f"image digest {rekor.bound_to} via {rekor.bound_via}; RFC 6962 inclusion "
            "proof re-derived; log checkpoint signed by the role-pinned Rekor log key. "
            "(Proves the entry NAMES the release digest, a public value — not who "
            "logged it: the signing identity in the entry is NOT checked here; use "
            "cosign verify-blob --certificate-identity for that.)"
        )

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
