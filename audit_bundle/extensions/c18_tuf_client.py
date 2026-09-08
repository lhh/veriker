"""C18 TUF client — substrate-verifier-side trust-bundle fetch + validation.

Wraps `python-tuf >= 6.0` to fetch + validate the v-kernel-audit-bundle TUF
feed at `manifest.vkernel.dev/v0.3.0.json`. The TUF root is EMBEDDED at compile
time under `audit_bundle/extensions/_tuf_root/root.json` — bundled into the OCI
image by the Nix flake so first-trust does not depend on a network fetch at
consumer-verify time. This closes the TUF first-trust MITM threat.

This module lives on the SUBSTRATE-VERIFIER side. It is NOT stdlib-only — it
imports `python-tuf >= 6.0` + `cryptography`. The stdlib-only verifier path
lives at `veriker/cli/verify.py` and does NOT import this module; that two-verifier
boundary is deliberate.

Enforced TUF discipline:

  - Threshold ≥2-of-3 root signers
  - Root expiration ≤90d from issue date
  - Snapshot expiration ≤7d
  - Timestamp expiration ≤24h
  - Monotonic version checks; fail-CLOSED on version decrease
  - Consistent-snapshots invariant; fail-CLOSED on missing inclusion proof
  - Fulcio + CTFE + Rekor pubkeys live in a SEPARATE `sigstore-trust-root`
    TUF role with its own rotation cadence

Typed exceptions:

  TUFRootExpired                   — root.json expires before now()
  TUFRootSignatureThresholdNotMet  — fewer than threshold valid signatures
  TUFSnapshotStale                 — snapshot expiration past max-staleness
  TUFTimestampStale                — timestamp expiration past 24h
  TUFVersionRollback               — newer version on disk than what feed offers
  TUFConsistentSnapshotMissing     — consistent-snapshot pair absent from target
  TUFTargetUnknownPayloadType      — fetched target carries unrecognized payload_type
  TUFRootKeyPrivateMaterialOnDisk  — defensive check; private key bytes under _tuf_root/

The `audit_bundle/extensions/c18_verifier_identity.py` module catches these and
emits reason codes into the bundle event log.


"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from audit_bundle.iso8601 import parse_iso8601_utc
from audit_bundle.strict_json import strict_json_loads
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterator
    # python-tuf APIs are imported lazily; see _import_python_tuf below


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

#: Default TUF feed URL (the actual hosting endpoint for v0.3 releases).
DEFAULT_TUF_FEED_URL = "https://manifest.vkernel.dev/v0.3.0"

#: Bundled root.json — embedded in the OCI image at compile time.
_EMBEDDED_ROOT_PATH = Path(__file__).parent / "_tuf_root" / "root.json"

#: Max-staleness windows. Bounds how stale fetched TUF metadata may be before
#: it is rejected (freeze-attack protection).
MAX_TIMESTAMP_STALENESS_HOURS = 24
MAX_SNAPSHOT_STALENESS_DAYS = 7
MAX_ROOT_EXPIRY_DAYS = 90

#: Minimum threshold for root signatures: require ≥2-of-3 so one compromised
#: root key cannot mint a valid root on its own.
MIN_ROOT_THRESHOLD = 2
MIN_ROOT_KEY_COUNT = 3

#: TUF role names. The `sigstore-trust-root` role is kept SEPARATE from the
#: release role so the two can rotate on independent cadences.
ROLE_VKERNEL_RELEASE = "vkernel-release"
ROLE_SIGSTORE_TRUST_ROOT = "sigstore-trust-root"
ROLE_PLUGIN_ALLOWLIST = "plugin-allowlist"
#: Verifier-side revocation-root role. SEPARATE from the C18 release role AND
#: the sigstore-trust-root role (its own rotation cadence). Signs the revocation
#: list consumed by audit_bundle/revocation.py via an injected resolver.
ROLE_REVOCATION_ROOT = "revocation-root"

#: payload_type declared by the C18 release-manifest target itself (the
#: image_digest pin list). Declared in the SIGNED targets metadata's `custom`
#: field, so it rides the TUF targets-role signature.
RELEASE_MANIFEST_PAYLOAD_TYPE = "application/vnd.nexi.vkernel.release-manifest"

#: The three C18 role documents are TARGETS of the same TUF repository as the
#: release manifest (2026-09-02). Each rides the root-anchored targets /
#: snapshot / timestamp chain, hash-pinned and payload-typed, and is only then
#: structurally validated. Before this they were `json.loads` of a bundled file
#: behind a `TBD` regex; whoever could write that file owned the role.
ROLE_TARGET_NAMES: dict[str, str] = {
    ROLE_SIGSTORE_TRUST_ROOT: f"{ROLE_SIGSTORE_TRUST_ROOT}/sigstore_trust_root.json",
    ROLE_PLUGIN_ALLOWLIST: f"{ROLE_PLUGIN_ALLOWLIST}/plugin_allowlist.json",
    ROLE_REVOCATION_ROOT: f"{ROLE_REVOCATION_ROOT}/revocation_root.json",
}
#: One payload type PER role document. The fetch requires the signed
#: `custom.payload_type` to EQUAL the role's own type — membership in an
#: allowlist is not enough (a role document served under a sibling role's type
#: is a substitution, and the role_name check inside the document is the
#: second, independent, line).
ROLE_TARGET_PAYLOAD_TYPES: dict[str, str] = {
    role: f"application/vnd.nexi.c18.{role}+json" for role in ROLE_TARGET_NAMES
}

#: The `sigstore-trust-root` role document pins DIGESTS of key files
#: (`targets.<entry>.expected_sha256_at_v0_3_cut`), never bytes. The bytes are
#: themselves targets of the same repository, under `sigstore-trust-root/keys/`,
#: with their own exact payload type — so a key rides the chain hash-pinned by
#: the targets metadata AND must hash to the digest the (2-of-3-signed,
#: ceremony-filled) role document declares. `fetch_sigstore_trust_root_key` is
#: the consumer; `veriker/cli/host_digest_verify.py` resolves its Rekor log key with it.
SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE = (
    "application/vnd.nexi.c18.sigstore-trust-root.key+pem"
)

#: `type` values a `sigstore-trust-root` entry may carry for a LOG KEY, and the
#: key class each admits. A PEM that loads as the other class is refused: the
#: document says what the key is, the bytes do not get to decide.
SIGSTORE_LOG_KEY_TYPES: dict[str, str] = {
    "ecdsa-public-key-pem": "ec-p256",
    "ed25519-public-key-pem": "ed25519",
}


def sigstore_trust_root_key_target_name(entry: str) -> str:
    """TUF target name carrying the bytes of one `sigstore-trust-root` entry."""
    return f"{ROLE_SIGSTORE_TRUST_ROOT}/keys/{entry}"

#: Acceptable payload_type values. Since 2026-09-02 every fetch requires the
#: EXACT type its target must carry (`_fetch_verified_target(expected_payload_type=…)`);
#: this set is the documented vocabulary, not the gate. A target whose signed
#: `custom.payload_type` is absent or differs from the expected one is rejected
#: (TUFTargetUnknownPayloadType) — absence must not evade the gate.
ACCEPTABLE_PAYLOAD_TYPES = frozenset(
    {
        RELEASE_MANIFEST_PAYLOAD_TYPE,
        "application/vnd.in-toto+json",
        "application/vnd.cyclonedx+json",
        "application/vnd.spdx+json",
        "application/vnd.dev.sigstore.bundle+json",
        "application/vnd.slsa.provenance+json",
        *ROLE_TARGET_PAYLOAD_TYPES.values(),
        SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE,
    }
)


# -----------------------------------------------------------------------------
# Typed exceptions (caught by c18_verifier_identity.py)
# -----------------------------------------------------------------------------


class TUFClientError(RuntimeError):
    """Base class for all C18 TUF-client errors."""


class TUFRootExpired(TUFClientError):
    """Bundled root.json has expired; the bundle cannot proceed without an
    out-of-band re-pin of a fresh root."""


class TUFRootSignatureThresholdNotMet(TUFClientError):
    """root.json carries fewer than `threshold` valid signatures; fail-CLOSED
    (threshold ≥2-of-3 always)."""


class TUFSnapshotStale(TUFClientError):
    """snapshot.json expiration is past MAX_SNAPSHOT_STALENESS_DAYS; fail-CLOSED
    (freeze-attack protection)."""


class TUFTimestampStale(TUFClientError):
    """timestamp.json expiration is past MAX_TIMESTAMP_STALENESS_HOURS;
    fail-CLOSED (freeze-attack protection)."""


class TUFVersionRollback(TUFClientError):
    """Feed offers a version-number LOWER than what the substrate has cached;
    fail-CLOSED (rollback protection)."""


class TUFConsistentSnapshotMissing(TUFClientError):
    """Consistent-snapshot pair absent from fetched target; fail-CLOSED."""


class TUFTargetUnknownPayloadType(TUFClientError):
    """Fetched target's payload_type is not in the fail-closed
    ACCEPTABLE_PAYLOAD_TYPES allowlist."""


class TUFRootKeyPrivateMaterialOnDisk(TUFClientError):
    """Defensive: a file under `_tuf_root/` looks like it contains an Ed25519
    or RSA PRIVATE key. The substrate ships only PUBLIC key material; this
    is a hard-stop for the bundle (commit reviewer error)."""


class TUFRoleSeparationViolation(TUFClientError):
    """The `sigstore-trust-root` role is supposed to be distinct from the
    C18 release role. This exception fires if a fetched metadata file
    conflates them."""


class TUFTrustRootKeyUnpinned(TUFClientError):
    """The `sigstore-trust-root` role document does not pin the requested key
    entry (absent entry, malformed / unfilled digest, or a `type` that is not a
    log-key type). Fail-closed: an unpinned key is not trust material."""


class TUFTrustRootKeyDigestMismatch(TUFClientError):
    """The key bytes fetched through the chain do not hash to the digest the
    `sigstore-trust-root` role document declares for that entry. The served
    bytes are what the feed signed; the role's pin is the ceremony's authority
    and the two disagree — refuse."""


class TUFRevocationRootSignatureInvalid(TUFClientError):
    """The revocation-root role document carries fewer than `threshold` DISTINCT
    role keyids with a valid Ed25519 signature over `rfc8785.dumps(signed)`.
    Presence of a signature blob is not a signature; this is the check the
    fetch's presence assert defers to, verified at the consumer."""


class TUFRevocationRootSignerUnpinned(TUFClientError):
    """The revocation-root role document's `pinned_revocation_list_signer_fingerprint`
    does not name an Ed25519 key under `signed.keys`, so no revocation list can be
    attributed to a signer the role vouches for. Fail-closed."""


class TUFBootstrapPlaceholderPresent(TUFClientError):
    """A trust-loader was asked to load role material that still carries
    UNFILLED ceremony bootstrap state — an empty root signature (``sig == ""``)
    or a ``TBD-*`` placeholder value — without the caller opting into bootstrap
    mode. A real verifier MUST refuse unsigned / placeholder trust anchors;
    this fail-closed default keeps the protection always-on at the API
    boundary, not only in the release gate. Callers that genuinely need the
    raw bootstrap material (e.g. the v0.4 root-seed path) must call the
    explicitly-named ``*_bootstrap_unverified`` loaders in
    ``c18_tuf_bootstrap`` — which acknowledge in the call site that the
    material is NOT verified trust."""


# -----------------------------------------------------------------------------
# Bootstrap-placeholder fail-closed checks (shared by the trust-loaders)
# -----------------------------------------------------------------------------

#: An UNFILLED ceremony placeholder iff the whole string VALUE begins with the
#: TBD sentinel — bare or ``sha256:``-prefixed. Anchored at the start so honest
#: descriptive PROSE that merely names the sentinel mid-sentence does NOT trip
#: the check. Mirrors the release marker-gate's pattern exactly so the runtime
#: loader and the release gate agree on what "filled" means.
_PLACEHOLDER_VALUE_RE = re.compile(r"^(sha256:)?TBD")


def _iter_string_values(node: Any, path: str = "") -> "Iterator[tuple[str, str]]":
    """Yield (json_path, value) for every string VALUE in parsed JSON.

    Object KEYS are never yielded — only values — so a placeholder token in a
    key name or mid-sentence in prose cannot be mistaken for an unfilled field.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _iter_string_values(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_string_values(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def _assert_no_unfilled_placeholders(
    doc: dict[str, Any], source: Path, *, allow: bool
) -> None:
    """Fail closed if any VALUE in `doc` is an unfilled `TBD-*` ceremony
    placeholder, unless the caller explicitly opted into bootstrap mode."""
    if allow:
        return
    offenders = [
        f"{jpath}={value!r}"
        for jpath, value in _iter_string_values(doc)
        if _PLACEHOLDER_VALUE_RE.match(value)
    ]
    if offenders:
        raise TUFBootstrapPlaceholderPresent(
            f"{source.name} carries unfilled TBD-* ceremony placeholder(s) in "
            f"value position(s): {offenders}. The C18 key ceremony has not "
            "filled production values — refusing to treat this as verified "
            "trust material. Use the c18_tuf_bootstrap.*_bootstrap_unverified "
            "loaders ONLY for the documented v0.4 bootstrap/dev path."
        )


def _assert_root_signatures_filled(
    root_meta: dict[str, Any], source: Path, *, allow: bool
) -> None:
    """Fail closed if a root-role file carries an empty/absent signature set,
    unless the caller explicitly opted into bootstrap mode. This is the
    *presence* of a non-empty signature blob, NOT cryptographic verification
    (python-tuf performs the cryptographic check downstream); an empty `sig`
    means the key ceremony has not run at all."""
    if allow:
        return
    sigs = root_meta.get("signatures")
    if not sigs:
        raise TUFBootstrapPlaceholderPresent(
            f"{source.name} has no signatures block — the C18 key ceremony has "
            "not run. Use the c18_tuf_bootstrap.*_bootstrap_unverified loaders "
            "ONLY for the documented bootstrap-seed path."
        )
    empty = [
        i
        for i, sig in enumerate(sigs)
        if not (isinstance(sig, dict) and sig.get("sig"))
    ]
    if empty:
        raise TUFBootstrapPlaceholderPresent(
            f"{source.name} carries EMPTY root signature(s) at index {empty} — "
            "the C18 key ceremony has not run. Refusing an unsigned root. Use "
            "the c18_tuf_bootstrap.*_bootstrap_unverified loaders ONLY for the "
            "documented bootstrap-seed path."
        )


# -----------------------------------------------------------------------------
# python-tuf lazy import
# -----------------------------------------------------------------------------


def _import_python_tuf() -> dict[str, Any]:
    """Lazily import python-tuf to keep this module importable in stdlib-only
    environments (where the import would fail). Returns the necessary
    classes/functions. Raises ImportError with a clear remediation string
    if python-tuf is not installed.
    """
    try:
        from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp  # type: ignore[import-not-found]
        from tuf.ngclient import Updater  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "python-tuf >= 6.0 is required for the substrate verifier. "
            "Install via `pip install tuf>=6.0` or via the Nix flake's "
            "audit_bundle_deps. The offline-only veriker/cli/verify.py does NOT need "
            "python-tuf — use that path for a stdlib-only audit."
        ) from exc
    return {
        "Metadata": Metadata,
        "Root": Root,
        "Snapshot": Snapshot,
        "Targets": Targets,
        "Timestamp": Timestamp,
        "Updater": Updater,
    }


# -----------------------------------------------------------------------------
# Bundled root.json loader + defensive checks
# -----------------------------------------------------------------------------


def _load_bundled_root_impl(
    root_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Shared core for :func:`load_bundled_root` (strict) and the bootstrap
    variant in ``c18_tuf_bootstrap``.

    ``allow_placeholders`` skips ONLY the two bootstrap fail-closed asserts
    (signature-blob presence + no unfilled ``TBD-*`` values); every other
    structural/defensive check below runs unconditionally. Production code MUST
    NOT call this directly — use the strict public :func:`load_bundled_root`.
    """
    path = root_path or _EMBEDDED_ROOT_PATH
    if not path.is_file():
        raise TUFClientError(
            f"Bundled TUF root.json missing at {path}. The OCI image build "
            "MUST embed the root.json into _tuf_root/ at compile time. "
            "Re-build the image."
        )

    _assert_no_private_key_material(path.parent)

    try:
        root_meta = strict_json_loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise TUFClientError(
            f"Bundled root.json at {path} is not strict JSON: {exc}"
        ) from exc

    _assert_root_threshold(root_meta)
    _assert_root_not_expired(root_meta)
    _assert_root_expiry_within_window(root_meta)
    _assert_root_signatures_filled(root_meta, path, allow=allow_placeholders)
    _assert_no_unfilled_placeholders(root_meta, path, allow=allow_placeholders)

    return root_meta


def load_bundled_root(root_path: Path | None = None) -> dict[str, Any]:
    """Load + STRUCTURALLY pre-check the bundled root.json (STRICT).

    ⚠️ This does NOT *cryptographically* verify the root — it does not check
    that ``signatures[]`` validate against the root keys (python-tuf performs
    that downstream when the caller drives the full protocol via
    fetch_release_manifest(), which seeds these bytes through
    ``Updater(bootstrap=...)``; ngclient then rejects an under-signed root). A
    successful return is NOT a cryptographic trust-anchor validation.

    Always fails closed: a root with EMPTY ``signatures[]`` (pre-ceremony
    bootstrap) or any ``TBD-*`` value is REJECTED with
    TUFBootstrapPlaceholderPresent. There is NO opt-out parameter on this
    production loader. The deliberately-unverified bootstrap-seed variant lives
    in ``c18_tuf_bootstrap.load_bundled_root_bootstrap_unverified`` (v0.4
    root-seed / dev path only).

    Structural/defensive pre-checks performed here:
      - File exists and is readable JSON
      - No private-key material under _tuf_root/ (TUFRootKeyPrivateMaterialOnDisk)
      - root role DECLARES threshold ≥2-of-3 with that many resolvable keyids
        (a declaration check — NOT a count of valid signatures)
      - Expiration present, not past, and ≤ MAX_ROOT_EXPIRY_DAYS out
      - Non-empty signature blobs present and no TBD-* placeholder values
    """
    return _load_bundled_root_impl(root_path, allow_placeholders=False)


def _assert_no_private_key_material(tuf_root_dir: Path) -> None:
    """Scan _tuf_root/ for anything that looks like private key material.

    Defensive: private-half key material MUST never be committed under
    _tuf_root/ (the substrate ships only PUBLIC keys).
    """
    private_key_markers = (
        b"BEGIN PRIVATE KEY",
        b"BEGIN ENCRYPTED PRIVATE KEY",
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"BEGIN ED25519 PRIVATE KEY",
    )
    for child in tuf_root_dir.rglob("*"):
        if not child.is_file():
            continue
        try:
            head = child.read_bytes()[:4096]
        except OSError:
            continue
        for marker in private_key_markers:
            if marker in head:
                raise TUFRootKeyPrivateMaterialOnDisk(
                    f"File {child} appears to contain {marker.decode()} — "
                    "PRIVATE key material MUST NOT be committed under "
                    "audit_bundle/extensions/_tuf_root/. Remove it before "
                    "committing. The substrate ships only PUBLIC keys."
                )


def _assert_root_threshold(root_meta: dict[str, Any]) -> None:
    """Assert the root role DECLARES threshold ≥2-of-3.

    Structural only: checks the declared threshold integer, the keyid count, and
    that each keyid resolves into signed.keys. It does NOT count or verify the
    cryptographic signatures in root_meta["signatures"] — that is python-tuf's
    job downstream (see load_bundled_root). A root with empty signatures passes
    this check.
    """
    signed = root_meta.get("signed", {})
    roles = signed.get("roles", {})
    keys = signed.get("keys", {})
    root_role = roles.get("root")
    if not isinstance(root_role, dict):
        raise TUFRootSignatureThresholdNotMet(
            "root.json missing roles.root — cannot validate threshold."
        )
    threshold = root_role.get("threshold", 0)
    keyids = root_role.get("keyids", [])
    if not isinstance(threshold, int) or threshold < MIN_ROOT_THRESHOLD:
        raise TUFRootSignatureThresholdNotMet(
            f"root role threshold = {threshold!r}; minimum required = "
            f"{MIN_ROOT_THRESHOLD}."
        )
    if not isinstance(keyids, list) or len(keyids) < MIN_ROOT_KEY_COUNT:
        raise TUFRootSignatureThresholdNotMet(
            f"root role has {len(keyids)} keyids; minimum required = "
            f"{MIN_ROOT_KEY_COUNT}."
        )
    if len(set(keyids)) != len(keyids) or len(set(keyids)) < MIN_ROOT_KEY_COUNT:
        raise TUFRootSignatureThresholdNotMet(
            f"root role keyids must be {MIN_ROOT_KEY_COUNT} distinct keys; got "
            f"{keyids!r} (a repeated keyid satisfies the count with one key)."
        )
    # Each keyid must resolve to a key in `signed.keys`.
    for keyid in keyids:
        if keyid not in keys:
            raise TUFRootSignatureThresholdNotMet(
                f"keyid {keyid} referenced by root role is missing from "
                "signed.keys map — malformed root.json."
            )


def _assert_root_not_expired(root_meta: dict[str, Any]) -> None:
    """Fail-CLOSED if bundled root.json has already expired.

    Wall-clock BY DESIGN (uninjected, unrecorded): this is the verifier's own
    supply-chain freshness check, not a verdict surface — the question is "is
    this root fresh NOW", and python-tuf's authoritative protocol checks
    downstream use the host clock with no injection seam, so injecting only
    this pre-check would split the clock within one validation pass. See
    SECURITY.md "Clocks and determinism (replay map)"."""
    expires_str = root_meta.get("signed", {}).get("expires")
    if not expires_str:
        raise TUFRootExpired("root.json missing signed.expires field.")
    try:
        expires = parse_iso8601_utc(expires_str)
    except ValueError as exc:
        raise TUFRootExpired(
            f"root.json signed.expires {expires_str!r} not ISO 8601 UTC: {exc}"
        ) from exc
    if expires <= datetime.now(timezone.utc):
        raise TUFRootExpired(
            f"Bundled root.json expired at {expires.isoformat()}. An "
            "out-of-band re-pin of a fresh root is required."
        )


def _assert_root_expiry_within_window(root_meta: dict[str, Any]) -> None:
    """Fail-CLOSED if root expiration is MORE than MAX_ROOT_EXPIRY_DAYS out.

    A too-long expiry weakens the rotation discipline, so root expiration is
    capped at MAX_ROOT_EXPIRY_DAYS (90d). The cap is on expiry-minus-issue-time;
    for v0.3 we approximate by asserting expiry ≤ now + 90d at load time.

    Wall-clock BY DESIGN — same posture as _assert_root_not_expired (supply-
    chain freshness, not a verdict surface; see SECURITY.md "Clocks and
    determinism (replay map)"). This cap is rotation hygiene, not a trust gate.
    """
    expires_str = root_meta["signed"]["expires"]
    try:
        expires = parse_iso8601_utc(expires_str)
    except ValueError as exc:
        raise TUFRootExpired(
            f"root.json signed.expires {expires_str!r} not ISO 8601 UTC: {exc}"
        ) from exc
    now = datetime.now(timezone.utc)
    days_to_expiry = (expires - now).days
    if days_to_expiry > MAX_ROOT_EXPIRY_DAYS:
        raise TUFRootExpired(
            f"Bundled root.json expires {days_to_expiry}d from now — exceeds "
            f"the {MAX_ROOT_EXPIRY_DAYS}d cap. Re-issue with a shorter expiration."
        )


# -----------------------------------------------------------------------------
# TUF feed update + role-scoped target fetch
# -----------------------------------------------------------------------------


def _target_payload_type(target_info) -> str | None:
    """Extract the signed `custom.payload_type` from a python-tuf TargetFile.

    python-tuf parses length+hashes as first-class fields; the TUF-spec
    `custom` object lands in `unrecognized_fields` (older releases) or a
    `custom` attribute (newer). Returns None when absent/malformed — the
    caller treats None as unknown (fail-closed).
    """
    custom = getattr(target_info, "custom", None)
    if custom is None:
        unrec = getattr(target_info, "unrecognized_fields", None) or {}
        custom = unrec.get("custom")
    if not isinstance(custom, dict):
        return None
    pt = custom.get("payload_type")
    return pt if isinstance(pt, str) else None


def _open_updater(
    *,
    feed_url: str,
    trust_dir: Path | None,
    allow_ephemeral_trust_dir: bool,
    caller: str,
):
    """Seed a trust dir with the bundled root, drive `ngclient.Updater.refresh()`,
    enforce the declared staleness windows on the fetched metadata, and return
    the refreshed updater. Shared by every fetcher: the release manifest and the
    three role documents ride ONE chain.

    `trust_dir` MUST be a PERSISTENT directory: TUF rollback/freeze protection
    depends on persisting the last-seen timestamp/snapshot/targets versions
    across invocations. A fresh ephemeral dir per call cannot detect a rollback
    to a previously-valid (older, still-signed) version. If `trust_dir is None`
    the call FAILS CLOSED unless `allow_ephemeral_trust_dir=True` is set
    explicitly (one-shot / test use only).
    """
    # Fail closed on a missing trust dir FIRST — a pure-argument check that
    # needs neither python-tuf nor the bundled root, so a caller with no
    # persistent trust dir gets the same typed refusal in every environment.
    #
    if trust_dir is None:
        if not allow_ephemeral_trust_dir:
            raise TUFClientError(
                f"{caller} requires a PERSISTENT trust_dir: TUF "
                "rollback/freeze protection depends on persisting last-seen "
                "metadata versions across calls. A fresh dir per call cannot "
                "detect rollback to an older, still-validly-signed version. "
                "Pass trust_dir=<stable path> (e.g. host_digest_verify's "
                "--tuf-trust-bundle), or set allow_ephemeral_trust_dir=True ONLY "
                "for one-shot/test use where rollback protection is not required."
            )
        from tempfile import mkdtemp

        trust_dir = Path(mkdtemp(prefix="vkernel_tuf_"))

    tuf = _import_python_tuf()

    # Bundled root.json — embedded at compile time. These bytes are the pinned
    # trust anchor passed to ngclient as `bootstrap` (see below).
    bundled_root = load_bundled_root()
    bundled_root_bytes = json.dumps(bundled_root).encode("utf-8")

    metadata_dir = trust_dir / "metadata"
    targets_dir = trust_dir / "targets"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    targets_dir.mkdir(parents=True, exist_ok=True)

    # Seed the trust dir with bundled root.json (back-compat with tuf<7 layout).
    (metadata_dir / "root.json").write_bytes(bundled_root_bytes)

    try:
        # `bootstrap=` MUST be passed by keyword: it is optional in tuf 6.x but a
        # REQUIRED keyword-only argument in tuf 7.0+. Passing it satisfies the
        # whole declared `tuf>=6.0` range. Omitting it raised TypeError on 7.0,
        # which fail-closed every fetch and meant ngclient's protocol checks
        # (rollback / threshold-on-rotation / consistent-snapshot) never ran.
        #
        updater = tuf["Updater"](
            metadata_dir=str(metadata_dir),
            metadata_base_url=f"{feed_url}/metadata",
            target_dir=str(targets_dir),
            target_base_url=f"{feed_url}/targets",
            bootstrap=bundled_root_bytes,
        )
        updater.refresh()
    except Exception as exc:  # python-tuf raises a wide variety of exceptions
        # Translate python-tuf's exceptions into our typed surface.
        msg = str(exc).lower()
        if "expired" in msg and "snapshot" in msg:
            raise TUFSnapshotStale(str(exc)) from exc
        if "expired" in msg and "timestamp" in msg:
            raise TUFTimestampStale(str(exc)) from exc
        if "expired" in msg and "root" in msg:
            raise TUFRootExpired(str(exc)) from exc
        if "version" in msg and ("rollback" in msg or "decrease" in msg):
            raise TUFVersionRollback(str(exc)) from exc
        if "consistent" in msg and "snapshot" in msg:
            raise TUFConsistentSnapshotMissing(str(exc)) from exc
        raise TUFClientError(f"TUF refresh failed: {exc}") from exc

    _enforce_metadata_windows(metadata_dir)
    return updater


def _metadata_expires(metadata_dir: Path, name: str) -> datetime:
    """`signed.expires` of a refreshed metadata file ngclient wrote to the trust dir."""
    path = metadata_dir / name
    try:
        doc = strict_json_loads(path.read_text(encoding="utf-8"))
        return parse_iso8601_utc(doc["signed"]["expires"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TUFClientError(
            f"refreshed {name} unreadable after ngclient refresh at {path}: {exc}"
        ) from exc


def _enforce_metadata_windows(metadata_dir: Path) -> None:
    """Cap how far ahead the fetched timestamp / snapshot may expire.

    python-tuf rejects EXPIRED metadata; it accepts whatever expiry the
    publisher signed. `MAX_TIMESTAMP_STALENESS_HOURS` / `MAX_SNAPSHOT_STALENESS_DAYS`
    are the client's own ceiling on that window — the freeze-attack bound the
    module docstring has listed under "Enforced TUF discipline" since v0.3. Until
    2026-09-02 both constants were read by nothing (a review checkpoint marked
    the row PASS by citing the constant's existence). A feed that signs a
    30-day snapshot is a feed a stale mirror can serve for 30 days; refuse it.
    """
    now = datetime.now(timezone.utc)
    ts_expires = _metadata_expires(metadata_dir, "timestamp.json")
    if ts_expires - now > timedelta(hours=MAX_TIMESTAMP_STALENESS_HOURS):
        raise TUFTimestampStale(
            f"timestamp.json expires {ts_expires.isoformat()}, more than "
            f"MAX_TIMESTAMP_STALENESS_HOURS={MAX_TIMESTAMP_STALENESS_HOURS}h ahead; "
            "a long-lived timestamp defeats freeze detection (fail-closed)."
        )
    snap_expires = _metadata_expires(metadata_dir, "snapshot.json")
    if snap_expires - now > timedelta(days=MAX_SNAPSHOT_STALENESS_DAYS):
        raise TUFSnapshotStale(
            f"snapshot.json expires {snap_expires.isoformat()}, more than "
            f"MAX_SNAPSHOT_STALENESS_DAYS={MAX_SNAPSHOT_STALENESS_DAYS}d ahead; "
            "a long-lived snapshot defeats freeze detection (fail-closed)."
        )
    # The FETCHED root (python-tuf may have rotated past the bundled one) is held
    # to the same ≤90d cap `load_bundled_root` puts on the bundled copy; until
    # 2026-09-02 only the bundled root was capped, so a served long-lived root
    # rotation rode the chain unrefused.
    root_expires = _metadata_expires(metadata_dir, "root.json")
    if root_expires - now > timedelta(days=MAX_ROOT_EXPIRY_DAYS):
        raise TUFRootExpired(
            f"fetched root.json expires {root_expires.isoformat()}, more than "
            f"MAX_ROOT_EXPIRY_DAYS={MAX_ROOT_EXPIRY_DAYS}d ahead; a long-lived root "
            "defeats the rotation discipline (fail-closed)."
        )


def _fetch_verified_target(
    updater, target_name: str, *, expected_payload_type: str, feed_url: str
) -> tuple[bytes, Any]:
    """Resolve, type-check, download and hash-verify ONE target through ngclient.

    Returns `(bytes, target_info)`. The signed `custom.payload_type` must EQUAL
    `expected_payload_type` (absent counts as wrong: omission must not evade the
    gate); the bytes are the hash-pinned target ngclient downloaded (a tampered
    CDN copy fails inside `download_target`).
    """
    target_info = updater.get_targetinfo(target_name)
    if target_info is None:
        raise TUFConsistentSnapshotMissing(
            f"Target {target_name!r} not in TUF feed at {feed_url}. "
            "Either it has not yet landed or the feed is split-viewed."
        )
    payload_type = _target_payload_type(target_info)
    if payload_type != expected_payload_type:
        raise TUFTargetUnknownPayloadType(
            f"Target {target_name!r} declares payload_type={payload_type!r}; "
            f"this target MUST declare exactly {expected_payload_type!r} in its "
            "signed targets metadata (exact match, not allowlist membership)."
        )
    try:
        cached_path = updater.download_target(target_info)
        data = Path(cached_path).read_bytes()
    except Exception as exc:  # hash mismatch / length mismatch / transport
        raise TUFClientError(
            f"TUF target {target_name!r} download failed verification: {exc}"
        ) from exc
    return data, target_info, cached_path


def fetch_release_manifest(
    *,
    release_version: str,
    feed_url: str = DEFAULT_TUF_FEED_URL,
    trust_dir: Path | None = None,
    allow_ephemeral_trust_dir: bool = False,
) -> dict[str, Any]:
    """Fetch the C18 release manifest from the TUF feed.

    Uses python-tuf's `ngclient.Updater` for full TUF protocol enforcement
    (consistent snapshots; monotonic version; threshold ≥2-of-3 root
    signatures), plus the client's own ≤24h timestamp / ≤7d snapshot windows
    (`_enforce_metadata_windows`). Returns the parsed target file contents.

    `trust_dir` MUST be persistent — see `_open_updater`.

    Raises TUFRootExpired / TUFSnapshotStale / TUFTimestampStale /
    TUFVersionRollback / TUFConsistentSnapshotMissing as appropriate.
    """
    updater = _open_updater(
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
        caller="fetch_release_manifest",
    )
    target_name = f"{ROLE_VKERNEL_RELEASE}/{release_version}/MANIFEST.txt"
    # The release manifest must declare ITS OWN payload type — exactly. Until
    # 2026-09-02 this site accepted any of the six documented types, so a
    # manifest declaring an SPDX type passed.
    _data, target_info, cached_path = _fetch_verified_target(
        updater,
        target_name,
        expected_payload_type=RELEASE_MANIFEST_PAYLOAD_TYPE,
        feed_url=feed_url,
    )
    return {
        "target_name": target_name,
        "target_path": cached_path,
        "target_info": {
            "length": target_info.length,
            "hashes": dict(target_info.hashes),
        },
        "feed_url": feed_url,
        "release_version": release_version,
    }


def _fetch_role_document(
    role: str,
    *,
    feed_url: str,
    trust_dir: Path | None,
    allow_ephemeral_trust_dir: bool,
    caller: str,
) -> dict[str, Any]:
    """TUF-fetch one C18 role document and parse it (no structural validation here)."""
    updater = _open_updater(
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
        caller=caller,
    )
    target_name = ROLE_TARGET_NAMES[role]
    data, target_info, _ = _fetch_verified_target(
        updater,
        target_name,
        expected_payload_type=ROLE_TARGET_PAYLOAD_TYPES[role],
        feed_url=feed_url,
    )
    try:
        doc = strict_json_loads(data)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TUFClientError(
            f"{role} role document fetched via TUF is not strict JSON: {exc}"
        ) from exc
    if not isinstance(doc, dict):
        raise TUFClientError(f"{role} role document is not a JSON object.")
    return {
        "document": doc,
        "target_name": target_name,
        "feed_url": feed_url,
        "target_info": {
            "length": target_info.length,
            "hashes": dict(target_info.hashes),
        },
        "authenticated_by": (
            f"TUF chain from bundled root: targets/snapshot/timestamp at {feed_url}, "
            f"payload_type={ROLE_TARGET_PAYLOAD_TYPES[role]}"
        ),
    }


# -----------------------------------------------------------------------------
# Separate-role fetchers (each role rotates on its own cadence)
# -----------------------------------------------------------------------------


_BUNDLED_SIGSTORE_TRUST_ROOT_PATH = (
    Path(__file__).parent / "_tuf_root" / "sigstore_trust_root.json"
)
_BUNDLED_PLUGIN_ALLOWLIST_PATH = (
    Path(__file__).parent / "_tuf_root" / "plugin_allowlist.json"
)
_BUNDLED_REVOCATION_ROOT_PATH = (
    Path(__file__).parent / "_tuf_root" / "revocation_root.json"
)


def validate_sigstore_trust_root_document(
    role: dict[str, Any],
    *,
    source: str,
    strict: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Structural validation of a `sigstore-trust-root` role DOCUMENT (already
    obtained — via the TUF chain by `fetch_sigstore_trust_root`, or from the
    bundled bootstrap file by `c18_tuf_bootstrap`).

    Since 2026-09-02 the document has the SAME signed shape as `revocation-root`:
    `signed.targets` (the Fulcio / CTFE / Rekor entries with their digest pins and
    key types), `signed.keys` + `signed.roles[sigstore-trust-root]` (three
    distinct Ed25519 approver keys, threshold 2, keyid = sha256 of the key),
    `signed.expires`, `rotation_policy`, and `signatures` over `rfc8785(signed)`.
    Until then it was flat, unsigned JSON: the Rekor log key's pin, bytes and
    declared type were authenticated by the release TARGETS key alone (threshold
    1 in the bundled root) while the prose called the pin "2-of-3, ceremony-
    filled" — the exact class the revocation root had been fixed for one seam
    over (fresh pass, process lens, 2026-09-02). `strict=False` skips ONLY the
    signature-presence and unfilled-``TBD-*`` asserts and the keyid-derivation
    rule; role separation, required targets, quorum shape and expiry always run.
    Signature VERIFICATION is `verify_role_document_signatures` (the strict
    fetcher runs it after this)."""
    path = Path(source)
    if not isinstance(role, dict):
        raise TUFClientError("sigstore-trust-root document is not a JSON object.")
    role_name = role.get("role_name")
    if role_name != ROLE_SIGSTORE_TRUST_ROOT:
        raise TUFRoleSeparationViolation(
            f"sigstore-trust-root file declares role_name={role_name!r}; "
            f"expected {ROLE_SIGSTORE_TRUST_ROOT!r}. Role separation "
            "broken — refusing to proceed."
        )
    signed = role.get("signed")
    if not isinstance(signed, dict):
        raise TUFClientError(
            "sigstore-trust-root file missing a `signed` object (the role document "
            "is a signed 2-of-3 document; its targets live under signed.targets)."
        )
    targets = signed.get("targets")
    if not isinstance(targets, dict):
        raise TUFClientError("sigstore-trust-root file: signed.targets is not an object.")
    required = {"fulcio.pub", "ctfe.pub", "rekor.pub", "sigstore_root_threshold.json"}
    missing = required - set(targets.keys())
    if missing:
        raise TUFClientError(
            f"sigstore-trust-root missing required targets: {missing}. "
            "The role MUST enumerate Fulcio + CTFE + Rekor pubkeys plus the "
            "rotation-policy doc."
        )
    expires_dt, max_days = _validate_role_quorum(
        role, role_name=ROLE_SIGSTORE_TRUST_ROOT, strict=strict
    )
    _grade_role_expiry(role, expires_dt, max_days, path=path, strict=strict, now=now)
    return role


def _fetch_sigstore_trust_root_impl(
    bundled_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Read the BUNDLED role file and validate it. Used ONLY by the bootstrap
    module (``c18_tuf_bootstrap.fetch_sigstore_trust_root_bootstrap_unverified``);
    the strict public fetcher goes through the TUF chain, never this file."""
    path = bundled_path or _BUNDLED_SIGSTORE_TRUST_ROOT_PATH
    if not path.is_file():
        raise TUFClientError(
            f"sigstore-trust-root role file missing at {path}. The OCI image "
            "build MUST embed this at compile time."
        )
    try:
        role = strict_json_loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise TUFClientError(
            f"sigstore-trust-root role file at {path} is not strict JSON: {exc}"
        ) from exc
    return validate_sigstore_trust_root_document(
        role, source=str(path), strict=not allow_placeholders
    )


def fetch_sigstore_trust_root(
    *,
    feed_url: str = DEFAULT_TUF_FEED_URL,
    trust_dir: Path | None = None,
    allow_ephemeral_trust_dir: bool = False,
) -> dict[str, Any]:
    """Fetch the `sigstore-trust-root` role document THROUGH THE TUF CHAIN (STRICT).

    The document is a target of the release repository (`ROLE_TARGET_NAMES`),
    authenticated by the root-anchored targets / snapshot / timestamp chain,
    hash-pinned, required to carry exactly its own payload type, and only then
    structurally validated (`validate_sigstore_trust_root_document`, strict —
    a signed document carrying an unfilled ``TBD-*`` value is still refused).

    This role is SEPARATE from the C18 release role, with a distinct rotation
    cadence (Sigstore key-rotation announcements vs C18 release cuts). A role
    separation violation raises `TUFRoleSeparationViolation`.

    There is NO local-path input: until 2026-09-02 this function accepted
    `bundled_path` and returned whatever JSON was there behind a ``TBD`` regex.
    The bundled copy is reachable only through
    ``c18_tuf_bootstrap.fetch_sigstore_trust_root_bootstrap_unverified``.
    Returns an envelope `{"document", "target_name", "feed_url", "target_info",
    "authenticated_by"}` so the value itself says which chain authenticated it,
    unlike the bare dict the bootstrap loaders return.
    """
    fetched = _fetch_role_document(
        ROLE_SIGSTORE_TRUST_ROOT,
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
        caller="fetch_sigstore_trust_root",
    )
    validate_sigstore_trust_root_document(
        fetched["document"],
        source=ROLE_TARGET_NAMES[ROLE_SIGSTORE_TRUST_ROOT],
        strict=True,
    )
    # The chain authenticates the BYTES (targets key, threshold 1). The document's
    # own 2-of-3 is what makes the pin the ceremony's, not one targets key's.
    fetched["role_signed_by"] = verify_role_document_signatures(
        fetched["document"], role_name=ROLE_SIGSTORE_TRUST_ROOT
    )
    return fetched


_SHA256_PIN_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fetch_sigstore_trust_root_key(
    entry: str,
    *,
    feed_url: str = DEFAULT_TUF_FEED_URL,
    trust_dir: Path | None = None,
    allow_ephemeral_trust_dir: bool = False,
) -> dict[str, Any]:
    """Fetch the BYTES of one `sigstore-trust-root` key entry through the TUF chain.

    The role document (`fetch_sigstore_trust_root`, strict) pins
    `targets[entry].expected_sha256_at_v0_3_cut` and `targets[entry].type`. The
    bytes live at target `sigstore-trust-root/keys/<entry>` with payload type
    `SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE`, hash-pinned by the targets metadata
    (ngclient) — and are ADDITIONALLY required to hash to the role document's
    declared digest. Two pins: the feed's (targets key), and the one inside the
    role document, whose own 2-of-3 signatures the strict role fetch verifies
    (`role_signed_by` on the envelope). Until 2026-09-02 the role document was
    unsigned, so both pins rode the targets key.

    Refuses (typed, never a fallback): an entry the role does not name, a digest
    that is not `sha256:<64 hex>` (the strict role fetch already refuses `TBD`),
    a `type` outside `SIGSTORE_LOG_KEY_TYPES`, a wrong payload type on the key
    target, and a digest disagreement. Returns an envelope
    `{key_bytes, entry, declared_type, declared_sha256, target_name, feed_url,
    role, authenticated_by}` so the value says where the key came from. It does
    NOT load or type-check the key object — the consumer does that against
    `declared_type` (`veriker/cli/host_digest_verify.py::_resolve_rekor_log_key`).
    """
    role = fetch_sigstore_trust_root(
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
    )
    targets = role["document"]["signed"].get("targets", {})
    pinned = targets.get(entry) if isinstance(targets, dict) else None
    if not isinstance(pinned, dict):
        raise TUFTrustRootKeyUnpinned(
            f"sigstore-trust-root role names no entry {entry!r} (entries: "
            f"{sorted(targets) if isinstance(targets, dict) else '?'}); an unpinned "
            "key is not trust material."
        )
    declared_sha = pinned.get("expected_sha256_at_v0_3_cut")
    if not isinstance(declared_sha, str) or not _SHA256_PIN_RE.match(declared_sha):
        raise TUFTrustRootKeyUnpinned(
            f"sigstore-trust-root entry {entry!r} carries no sha256:<64 hex> pin "
            f"(expected_sha256_at_v0_3_cut={declared_sha!r})."
        )
    declared_type = pinned.get("type")
    if declared_type not in SIGSTORE_LOG_KEY_TYPES:
        raise TUFTrustRootKeyUnpinned(
            f"sigstore-trust-root entry {entry!r} has type={declared_type!r}; a log "
            f"key entry must be one of {sorted(SIGSTORE_LOG_KEY_TYPES)}."
        )
    updater = _open_updater(
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
        caller="fetch_sigstore_trust_root_key",
    )
    target_name = sigstore_trust_root_key_target_name(entry)
    data, target_info, _ = _fetch_verified_target(
        updater,
        target_name,
        expected_payload_type=SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE,
        feed_url=feed_url,
    )
    import hashlib  # noqa: PLC0415 — stdlib

    actual_sha = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual_sha != declared_sha:
        raise TUFTrustRootKeyDigestMismatch(
            f"sigstore-trust-root entry {entry!r} declares {declared_sha}; the key "
            f"bytes served at {target_name!r} hash to {actual_sha}. The role's pin is "
            "the ceremony's authority and the feed disagrees with it (fail-closed)."
        )
    return {
        "key_bytes": data,
        "entry": entry,
        "declared_type": declared_type,
        "declared_sha256": declared_sha,
        "target_name": target_name,
        "feed_url": feed_url,
        "role": role,
        "role_signed_by": tuple(role.get("role_signed_by", ())),
        "authenticated_by": (
            f"TUF chain from bundled root: targets/snapshot/timestamp at {feed_url}, "
            f"payload_type={SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE}; bytes equal the "
            f"sigstore-trust-root role document digest {declared_sha} for entry "
            f"{entry!r} (type {declared_type}); role document's own 2-of-3 verified "
            f"(signed_by={','.join(role.get('role_signed_by', ()))})"
        ),
    }


def validate_plugin_allowlist_document(
    role: dict[str, Any], *, source: str, strict: bool = True
) -> dict[str, Any]:
    """Structural validation of a `plugin-allowlist` role DOCUMENT (already
    obtained). `strict=False` skips ONLY the unfilled-``TBD-*`` assert; role
    separation + registry allowlist + required entry fields always run."""
    path = Path(source)
    role_name = role.get("role_name")
    if role_name != ROLE_PLUGIN_ALLOWLIST:
        raise TUFRoleSeparationViolation(
            f"plugin-allowlist file declares role_name={role_name!r}; "
            f"expected {ROLE_PLUGIN_ALLOWLIST!r}."
        )

    registry_allowlist = role.get("registry_org_allowlist", [])
    if registry_allowlist != ["ghcr.io/veriker/"]:
        raise TUFRoleSeparationViolation(
            f"plugin-allowlist registry_org_allowlist = {registry_allowlist!r}; "
            "expected exactly ['ghcr.io/veriker/']. Cross-registry plugin "
            "loading requires a separate posture decision."
        )

    entries = role.get("entries", {})
    required_fields = {
        "oci_artifact",
        "oci_digest_at_v0_3_cut",
        "cosign_cert_identity",
        "slsa_provenance_digest_at_v0_3_cut",
    }
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            raise TUFClientError(
                f"plugin-allowlist entry {name!r} malformed (not a dict)"
            )
        missing = required_fields - set(entry.keys())
        if missing:
            raise TUFClientError(
                f"plugin-allowlist entry {name!r} missing fields: {missing}. "
                "Each plugin MUST enumerate (oci_artifact, oci_digest, "
                "cosign_cert_identity, slsa_provenance_digest)."
            )
    _assert_no_unfilled_placeholders(role, path, allow=not strict)
    return role


def _fetch_plugin_allowlist_impl(
    bundled_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Read the BUNDLED role file and validate it. Bootstrap module ONLY."""
    path = bundled_path or _BUNDLED_PLUGIN_ALLOWLIST_PATH
    if not path.is_file():
        raise TUFClientError(
            f"plugin-allowlist role file missing at {path}. The OCI image "
            "build MUST embed this at compile time."
        )
    try:
        role = strict_json_loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise TUFClientError(
            f"plugin-allowlist role file at {path} is not strict JSON: {exc}"
        ) from exc
    return validate_plugin_allowlist_document(
        role, source=str(path), strict=not allow_placeholders
    )


def fetch_plugin_allowlist(
    *,
    feed_url: str = DEFAULT_TUF_FEED_URL,
    trust_dir: Path | None = None,
    allow_ephemeral_trust_dir: bool = False,
) -> dict[str, Any]:
    """Fetch the `plugin-allowlist` role document THROUGH THE TUF CHAIN (STRICT).

    Every plugin loaded by the substrate verifier MUST appear in this
    TUF-distributed allowlist by OCI digest; `c18_plugin_oci_loader` consumes
    the returned dict. Authenticated by the root-anchored chain, hash-pinned,
    exact payload type, then `validate_plugin_allowlist_document` (strict).
    No local-path input (see `fetch_sigstore_trust_root`). Returns an envelope
    `{"document", "target_name", "feed_url", "target_info", "authenticated_by"}`
    — the value itself says which chain authenticated it, unlike the bare dict
    the `*_bootstrap_unverified` loaders return.
    """
    fetched = _fetch_role_document(
        ROLE_PLUGIN_ALLOWLIST,
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
        caller="fetch_plugin_allowlist",
    )
    validate_plugin_allowlist_document(
        fetched["document"],
        source=ROLE_TARGET_NAMES[ROLE_PLUGIN_ALLOWLIST],
        strict=True,
    )
    # Stated on the value, not in prose: this role has NO consumer in the shipped
    # tree (census 2026-09-02: nothing under audit_bundle/ or cli/ constructs
    # `PluginOCILoader` or imports a plugin by name at runtime; `veriker/cli/verify.py`
    # builds its plugin set from the distribution's registered classes). The
    # loader class is the INTENDED consumer and takes this envelope's `document`;
    # wiring it in is a posture decision (which host-side step admits plugins),
    # not something to invent here.
    fetched["consumer"] = (
        "NONE in the shipped tree (2026-09-02): no shipped path loads plugins from "
        "OCI; c18_plugin_oci_loader.PluginOCILoader is the intended consumer and "
        "takes this envelope's `document` as its `allowlist`."
    )
    # Also stated on the value: unlike sigstore-trust-root and revocation-root,
    # this document carries NO signatures of its own, so it is authenticated by
    # the release targets key alone (threshold 1 in the bundled root). Signing it
    # is part of wiring its consumer, not something to do ahead of one.
    fetched["role_signed_by"] = ()
    fetched["signatures"] = (
        "NONE: the plugin-allowlist document is unsigned; authenticated by the "
        "TUF targets key only (threshold 1), no 2-of-3 of its own."
    )
    return fetched


def _validate_role_quorum(
    role: dict[str, Any], *, role_name: str, strict: bool
) -> tuple[datetime, int]:
    """The 2-of-3 quorum block every signed role document carries (`signed.keys`,
    `signed.roles[role_name]`, `rotation_policy`, `signed.expires`). Shared by the
    `revocation-root` and `sigstore-trust-root` validators so the two roles are
    held to ONE rule. Returns `(expires_dt, max_validity_days)`; the caller grades
    the expiry after its ceremony asserts. See `validate_revocation_root_document`
    for what each check refuses and why."""
    signed = role.get("signed")
    if not isinstance(signed, dict):
        raise TUFClientError(f"{role_name} file missing a `signed` object.")
    roles = signed.get("roles")
    if not isinstance(roles, dict):
        raise TUFClientError(f"{role_name} file: signed.roles is not an object.")
    rr = roles.get(role_name)
    if not isinstance(rr, dict):
        raise TUFClientError(
            f"{role_name} file missing signed.roles[{role_name!r}]."
        )
    if rr.get("threshold") != 2:
        raise TUFClientError(
            f"{role_name} threshold={rr.get('threshold')!r}; must be 2 "
            "(2-of-3 distinct approvers per C18 root discipline)."
        )
    keyids = rr.get("keyids", [])
    if (
        not isinstance(keyids, list)
        or not all(isinstance(k, str) for k in keyids)
        or len(keyids) != 3
        or len(set(keyids)) != 3
    ):
        raise TUFClientError(
            f"{role_name} must enumerate exactly 3 distinct keyids; got {keyids!r}."
        )
    keys = signed.get("keys")
    if not isinstance(keys, dict):
        raise TUFClientError(f"{role_name} file: signed.keys is not an object.")
    publics_seen: dict[str, str] = {}
    for kid in keyids:
        key = keys.get(kid)
        if not isinstance(key, dict):
            raise TUFClientError(
                f"{role_name} keyid {kid!r} not under signed.keys."
            )
        if key.get("keytype") != "ed25519":
            raise TUFClientError(
                f"{role_name} keyid {kid!r} keytype={key.get('keytype')!r}; "
                "expected 'ed25519'."
            )
        keyval = key.get("keyval")
        pub = keyval.get("public", "") if isinstance(keyval, dict) else ""
        if not isinstance(pub, str) or len(pub) != 64:
            raise TUFClientError(
                f"{role_name} keyid {kid!r} public is {len(pub) if isinstance(pub, str) else 'not a string of'} hex chars, "
                "expected 64 (Ed25519 raw 32-byte)."
            )
        try:
            pub_raw = bytes.fromhex(pub)
        except ValueError as exc:
            raise TUFClientError(
                f"{role_name} keyid {kid!r} public is not valid hex."
            ) from exc
        # Three DISTINCT keys, not three distinct labels: the threshold counts keys.
        if pub.lower() in publics_seen:
            raise TUFClientError(
                f"{role_name} keyids {publics_seen[pub.lower()]!r} and {kid!r} "
                "carry the SAME public key; the role needs three distinct keys, "
                "and one key under two labels is a 1-of-3 role."
            )
        publics_seen[pub.lower()] = kid
        if strict:
            derived = hashlib.sha256(pub_raw).hexdigest()
            if kid != derived:
                raise TUFClientError(
                    f"{role_name} keyid {kid!r} is not the sha256 of its own "
                    f"public key ({derived}); a keyid is the hash of the key it "
                    "names, never a free label (refused, not renamed)."
                )

    rotation = role.get("rotation_policy")
    if not isinstance(rotation, dict):
        raise TUFClientError(f"{role_name} file: rotation_policy is not an object.")
    max_days = rotation.get("max_validity_days")
    if not isinstance(max_days, int) or max_days > 90:
        raise TUFClientError(
            f"{role_name} rotation_policy.max_validity_days={max_days!r}; "
            "must be an int <= 90 (mirrors C18 release-root rotation discipline)."
        )
    expires = signed.get("expires")
    if not isinstance(expires, str):
        raise TUFClientError(f"{role_name} signed.expires missing or not a string.")
    try:
        expires_dt = parse_iso8601_utc(expires)
    except ValueError as exc:
        raise TUFClientError(
            f"{role_name} signed.expires={expires!r} is not ISO-8601 UTC: {exc}"
        ) from exc

    return expires_dt, max_days


def validate_revocation_root_document(
    role: dict[str, Any],
    *,
    source: str,
    strict: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Structural validation of a `revocation-root` role DOCUMENT (already
    obtained). `strict=False` skips ONLY the two bootstrap asserts (signature
    presence + no unfilled ``TBD-*``) and the keyid-derivation rule; role name,
    2-of-3 threshold, Ed25519 keyids, three DISTINCT keys, rotation policy and
    expiry always run.

    `now` is the instant the expiry is graded against (strict only). A consumer
    that grades a revocation LIST against an injected `verifier_now` passes the
    same instant here so one run has ONE clock; None means the wall clock.

    Strict documents must satisfy `keyid == sha256(keyval.public raw32).hex()`
    for every role keyid — the same rule the DSSE allowlist applies (a
    mislabeled entry is refused, never renamed). Until 2026-09-02 a keyid was a
    free label, so ONE private key listed under two labels satisfied a 2-of-3
    threshold (fresh-pass witness `w_dsse.py A`).

    A malformed shape (a list where an object is required) is a `TUFClientError`
    on the DOCUMENT, never an AttributeError blamed on the verifier."""
    path = Path(source)
    if not isinstance(role, dict):
        raise TUFClientError("revocation-root document is not a JSON object.")
    role_name = role.get("role_name")
    if role_name != ROLE_REVOCATION_ROOT:
        raise TUFRoleSeparationViolation(
            f"revocation-root file declares role_name={role_name!r}; "
            f"expected {ROLE_REVOCATION_ROOT!r}. Role separation broken — "
            "refusing to proceed."
        )
    expires_dt, max_days = _validate_role_quorum(
        role, role_name=ROLE_REVOCATION_ROOT, strict=strict
    )
    _grade_role_expiry(role, expires_dt, max_days, path=path, strict=strict, now=now)
    return role


def _grade_role_expiry(
    role: dict[str, Any],
    expires_dt: datetime,
    max_days: int,
    *,
    path: Path,
    strict: bool,
    now: datetime | None,
) -> None:
    """Ceremony asserts, then (strict) the expiry graded against `now` — after
    the asserts, so pre-ceremony material is named as such rather than as merely
    stale. Until 2026-09-02 an expired revocation root rode the chain as verified
    trust material (measured: expires=2019-01-01 was returned by
    fetch_revocation_root)."""
    # Placeholders first: an unfilled ``TBD-*`` names the ceremony that has not
    # run more precisely than "empty signatures" does.
    _assert_no_unfilled_placeholders(role, path, allow=not strict)
    _assert_root_signatures_filled(role, path, allow=not strict)
    if strict:
        if now is None:
            now = datetime.now(timezone.utc)
        if expires_dt <= now:
            raise TUFRootExpired(
                f"{role.get('role_name')} signed.expires={role['signed'].get('expires')!r} "
                f"is not after the verifier clock {now.isoformat()}; an expired role "
                "document is not trust material (fail-closed)."
            )
        if expires_dt - now > timedelta(days=max_days):
            raise TUFClientError(
                f"{role.get('role_name')} signed.expires={role['signed'].get('expires')!r} "
                f"is more than the role's own rotation_policy.max_validity_days={max_days} ahead."
            )


def verify_role_document_signatures(
    role: dict[str, Any], *, role_name: str
) -> tuple[str, ...]:
    """Verify a signed role document's OWN 2-of-3 signatures (`revocation-root`,
    `sigstore-trust-root`) (Ed25519 over
    `rfc8785.dumps(signed)`, hex `sig`). Returns the tuple of keyids whose
    signatures validated, counting each DISTINCT PUBLIC KEY once — two role
    keyids that carry the same key bytes are one signer — or raises
    `TUFRevocationRootSignatureInvalid` when fewer keys than the role's
    `threshold` signed.

    What this proves, exactly: that `threshold` of the keys THE DOCUMENT LISTS
    signed the document. The key list rides the same bytes as the signatures, so
    this is not an authority beyond whoever holds or serves the document (the
    auditor's own file, or the release targets key on the chain); it is the
    ceremony's approver quorum made checkable, given that holder.

    Why here and not in python-tuf: the document is a TARGET of the release
    repository (authenticated as bytes by the targets role, threshold 1 in the
    bundled root), not TUF metadata. Nothing else verifies these signatures, and a
    role whose 2-of-3 is presence-checked only is a 1-of-1 role under the release
    targets key. Lazy imports keep this module importable without `cryptography`.
    """
    import rfc8785  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey,
    )

    signed = role.get("signed") if isinstance(role, dict) else None
    if not isinstance(signed, dict):
        raise TUFRevocationRootSignatureInvalid(f"{role_name} has no `signed` object")
    roles = signed.get("roles")
    rr = roles.get(role_name) if isinstance(roles, dict) else None
    if not isinstance(rr, dict):
        raise TUFRevocationRootSignatureInvalid(
            f"{role_name} has no signed.roles[{role_name!r}] object"
        )
    threshold = rr.get("threshold")
    role_keyids = rr.get("keyids")
    keys = signed.get("keys")
    if not isinstance(role_keyids, list) or not isinstance(keys, dict):
        raise TUFRevocationRootSignatureInvalid(
            f"{role_name} signed.roles[...].keyids must be a list and signed.keys an object"
        )
    try:
        message = rfc8785.dumps(signed)
    except Exception as exc:  # noqa: BLE001 — a non-canonicalisable doc is invalid
        raise TUFRevocationRootSignatureInvalid(
            f"{role_name} `signed` is not RFC 8785 canonicalisable: {exc}"
        ) from exc
    valid: list[str] = []
    keys_counted: set[str] = set()  # lowercase hex publics that already signed
    signatures = role.get("signatures")
    for sig in signatures if isinstance(signatures, list) else []:
        if not isinstance(sig, dict):
            continue
        keyid = sig.get("keyid")
        sig_hex = sig.get("sig")
        if not isinstance(keyid, str) or keyid not in role_keyids or keyid in valid:
            continue  # only role keyids count, each label once
        key = keys.get(keyid)
        if not isinstance(key, dict) or not isinstance(sig_hex, str):
            continue
        if key.get("keytype") != "ed25519":
            continue
        keyval = key.get("keyval")
        pub_hex = keyval.get("public", "") if isinstance(keyval, dict) else ""
        if not isinstance(pub_hex, str) or pub_hex.lower() in keys_counted:
            continue  # the SAME key under a second label is not a second signer
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(bytes.fromhex(sig_hex), message)
        except (ValueError, InvalidSignature):
            continue
        valid.append(keyid)
        keys_counted.add(pub_hex.lower())
    if not isinstance(threshold, int) or len(keys_counted) < threshold:
        raise TUFRevocationRootSignatureInvalid(
            f"{role_name} carries {len(keys_counted)} valid signature(s) from "
            f"distinct role KEYS ({valid}); threshold is {threshold!r}. An "
            "under-signed role document is not trust material (fail-closed)."
        )
    return tuple(valid)


def verify_revocation_root_signatures(role: dict[str, Any]) -> tuple[str, ...]:
    """`verify_role_document_signatures` for the `revocation-root` role."""
    return verify_role_document_signatures(role, role_name=ROLE_REVOCATION_ROOT)


def revocation_root_resolver_from_document(
    role: dict[str, Any], *, source: str, verifier_now: int | None = None
) -> tuple[Any, dict[str, str]]:
    """Build the `revocation_root_resolver` that `audit_bundle.revocation.load_revocation_list`
    takes, from a revocation-root role DOCUMENT — strict structural validation, then
    the document's own 2-of-3 signatures, then the pinned list signer.

    The resolver admits EXACTLY ONE `root_kid`: `signed.pinned_revocation_list_signer_fingerprint`,
    which must name an Ed25519 key under `signed.keys` (it may be one of the three
    root keyids or a fourth listed key). Any other kid — including the other root
    keyids — raises, so a list signed by a key the role did not designate is refused
    by `load_revocation_list`. Deny-by-default over the whole key map.

    Returns `(resolver, provenance)`; `provenance` names the source, the signing
    keyids that validated, the pinned signer and the expiry, for the verdict face.
    Raises the typed `TUF*` exceptions; a caller maps them to its own refusal.

    `verifier_now` (unix seconds) is the instant the document's expiry is graded
    against — pass the same clock the revocation LIST is graded against so one
    run has one clock. None means the wall clock.
    """
    now_dt = (
        datetime.fromtimestamp(verifier_now, tz=timezone.utc)
        if verifier_now is not None
        else None
    )
    validate_revocation_root_document(role, source=source, strict=True, now=now_dt)
    signers = verify_revocation_root_signatures(role)
    signed = role["signed"]
    pinned = signed.get("pinned_revocation_list_signer_fingerprint")
    key = signed.get("keys", {}).get(pinned) if isinstance(pinned, str) else None
    if not isinstance(key, dict) or key.get("keytype") != "ed25519":
        raise TUFRevocationRootSignerUnpinned(
            f"revocation-root pinned_revocation_list_signer_fingerprint={pinned!r} is "
            "not an ed25519 key under signed.keys; no list signer is pinned."
        )
    try:
        pub_raw32 = bytes.fromhex(key.get("keyval", {}).get("public", ""))
    except ValueError as exc:
        raise TUFRevocationRootSignerUnpinned(
            f"pinned list signer {pinned!r} public is not hex"
        ) from exc
    if len(pub_raw32) != 32:
        raise TUFRevocationRootSignerUnpinned(
            f"pinned list signer {pinned!r} public is {len(pub_raw32)} bytes, not 32"
        )

    def resolver(root_kid: str) -> bytes:
        if root_kid != pinned:
            raise KeyError(
                f"revocation list root_kid {root_kid!r} is not the pinned "
                f"revocation-list signer {pinned!r} (deny-by-default)"
            )
        return pub_raw32

    provenance = {
        "source": source,
        "signed_by": ",".join(signers),
        "threshold": str(signed["roles"][ROLE_REVOCATION_ROOT]["threshold"]),
        "pinned_list_signer": pinned,
        "expires": str(signed.get("expires")),
    }
    return resolver, provenance


def _fetch_revocation_root_impl(
    bundled_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Read the BUNDLED role file and validate it. Bootstrap module ONLY."""
    path = bundled_path or _BUNDLED_REVOCATION_ROOT_PATH
    if not path.is_file():
        raise TUFClientError(
            f"revocation-root role file missing at {path}. The OCI image build "
            "MUST embed this at compile time (pyproject package-data)."
        )
    try:
        role = strict_json_loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise TUFClientError(
            f"revocation-root role file at {path} is not strict JSON: {exc}"
        ) from exc
    return validate_revocation_root_document(
        role, source=str(path), strict=not allow_placeholders
    )


def fetch_revocation_root(
    *,
    feed_url: str = DEFAULT_TUF_FEED_URL,
    trust_dir: Path | None = None,
    allow_ephemeral_trust_dir: bool = False,
) -> dict[str, Any]:
    """Fetch the `revocation-root` role document THROUGH THE TUF CHAIN (STRICT).

    SEPARATE from the C18 release role AND the sigstore-trust-root role (its
    own rotation cadence). The root pubkeys it carries are the trust anchor for
    the verifier-side revocation list consumed by `audit_bundle/revocation.py`
    via an injected resolver. Authenticated by the root-anchored chain,
    hash-pinned, exact payload type, then `validate_revocation_root_document`
    (strict: 2-of-3 distinct Ed25519 keyids, rotation ≤90d, ISO expiry,
    non-empty signatures, expiry graded against now, no ``TBD-*``). No local-path
    input. Returns the same provenance envelope as `fetch_sigstore_trust_root`.
    """
    fetched = _fetch_role_document(
        ROLE_REVOCATION_ROOT,
        feed_url=feed_url,
        trust_dir=trust_dir,
        allow_ephemeral_trust_dir=allow_ephemeral_trust_dir,
        caller="fetch_revocation_root",
    )
    validate_revocation_root_document(
        fetched["document"], source=ROLE_TARGET_NAMES[ROLE_REVOCATION_ROOT], strict=True
    )
    fetched["role_signed_by"] = verify_role_document_signatures(
        fetched["document"], role_name=ROLE_REVOCATION_ROOT
    )
    return fetched


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# STH-gossip cross-check (Rekor split-view detection)
# -----------------------------------------------------------------------------


REASON_STH_GOSSIP_SIGNATURE_INVALID = "STH_GOSSIP_SIGNATURE_INVALID"
REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED = "STH_GOSSIP_CONSISTENCY_PROOF_FAILED"
REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES = (
    "STH_GOSSIP_INCLUSION_PROOF_DIVERGES_FROM_GOSSIPED_STH"
)


class SthGossipResult(NamedTuple):
    """Outcome of :func:`check_sth_gossip_structure`.

    ``reasons`` lists the structural divergences detected (empty == none found).
    ``cryptographically_verified`` reports whether the STH's signature was
    actually verified against a pinned key. At v0.3 this is ALWAYS ``False``:
    no signature, witness co-signature, or RFC-6962 consistency-proof
    verification is performed (see the function docstring). An empty
    ``reasons`` with ``cryptographically_verified is False`` therefore means
    "no structural divergence detected" — it does NOT mean the STH was
    verified. Callers must not treat that state as a cryptographic PASS.
    """

    reasons: list[str]
    cryptographically_verified: bool


def check_sth_gossip_structure(
    sth_json: dict,
    rekor_inclusion_proof: dict,
) -> SthGossipResult:
    """Structural pre-check of a gossiped STH against a Rekor inclusion proof.

    NOTE: this is deliberately named ``check_..._structure``, not ``verify_*``.
    It performs structural/shape comparison only and does NOT cryptographically
    verify anything at v0.3 (see below). The ``verify_*`` name is reserved for
    the future witness-key verification path.

    Intended end-state: detect a Rekor split-view (the log serving different
    states to the bundle producer and to a monitor) by cryptographically
    verifying a witness-co-signed STH against a pinned witness key.

    THIS v0.3 IMPLEMENTATION DOES NOT DO THAT. It performs only structural /
    shape comparisons and explicitly does NOT perform any cryptographic
    verification. Specifically, at v0.3 this function does NOT:
      - verify the STH ``signature`` against any key (it only checks that a
        signature field is present — the byte value is never inspected);
      - verify a witness/monitor co-signature against a pinned witness key
        (no witness key is pinned yet — that is v0.4 work, gated on
        second-monitor outreach + a pinned Cloudflare-monitor witness key);
      - verify an RFC-6962 consistency proof (the ``consistency_proof`` field,
        when present, is only shape-checked).

    What it DOES check (structural only, and only when a non-empty
    ``rekor_inclusion_proof`` is supplied):
      - ``sth_json`` carries a ``signed_tree_head``/``sth`` object with
        ``tree_size`` and ``root_hash``, and a ``signature`` field is present;
      - the STH ``tree_size`` is not OLDER than the inclusion-proof tree_size
        (an older STH is a split-view signal → INCLUSION_PROOF_DIVERGES);
      - at equal tree sizes, the ``root_hash`` values match
        (mismatch → CONSISTENCY_PROOF_FAILED);
      - the ``consistency_proof`` field, if present, is well-formed.

    Returns an :class:`SthGossipResult`. ``cryptographically_verified`` is
    always ``False`` until the witness-key verification path lands (v0.4); an
    empty ``reasons`` means only that no structural divergence was found, NOT
    that the STH was verified. Callers must surface the unverified status to
    the user and must not report a cryptographic PASS on this result.
    """
    reasons: list[str] = []
    # No cryptographic verification path is wired at v0.3 — see docstring.
    cryptographically_verified = False

    sth = sth_json.get("signed_tree_head") or sth_json.get("sth") or sth_json
    if not isinstance(sth, dict):
        return SthGossipResult(
            [REASON_STH_GOSSIP_SIGNATURE_INVALID], cryptographically_verified
        )

    required = ("tree_size", "root_hash")
    for k in required:
        if k not in sth:
            reasons.append(REASON_STH_GOSSIP_SIGNATURE_INVALID)
            return SthGossipResult(reasons, cryptographically_verified)

    # Signature PRESENCE check only — the signature bytes are never verified
    # against a key at v0.3 (see docstring). A present-but-bogus signature
    # passes this shape check; that is why an empty reason-set is NOT a
    # cryptographic PASS.
    if "signature" not in sth and "signed_signature" not in sth:
        reasons.append(REASON_STH_GOSSIP_SIGNATURE_INVALID)

    if not rekor_inclusion_proof:
        # Empty inclusion proof — caller passed the STH alone; no structural
        # cross-check is possible. Return the presence-check result as-is.
        return SthGossipResult(reasons, cryptographically_verified)

    sth_tree_size = sth.get("tree_size")
    proof_tree_size = rekor_inclusion_proof.get("tree_size")
    if not isinstance(sth_tree_size, int) or not isinstance(proof_tree_size, int):
        reasons.append(REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES)
        return SthGossipResult(reasons, cryptographically_verified)

    if sth_tree_size < proof_tree_size:
        # The gossiped STH is OLDER than the inclusion proof — Rekor served a
        # newer log state to the bundle producer than to the monitor. Split-
        # view attack signal.
        reasons.append(REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES)

    # Consistency proof structural check (when present).
    consistency = sth.get("consistency_proof")
    if sth_tree_size == proof_tree_size:
        # Degenerate case — same tree size; root hashes must match.
        if sth.get("root_hash") != rekor_inclusion_proof.get("root_hash"):
            reasons.append(REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED)
    elif consistency is not None:
        if not isinstance(consistency, list) or not all(
            isinstance(h, str) for h in consistency
        ):
            reasons.append(REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED)

    return SthGossipResult(reasons, cryptographically_verified)


__all__ = [
    "ROLE_TARGET_NAMES",
    "ROLE_TARGET_PAYLOAD_TYPES",
    "SIGSTORE_LOG_KEY_TYPES",
    "SIGSTORE_TRUST_ROOT_KEY_PAYLOAD_TYPE",
    "TUFRevocationRootSignatureInvalid",
    "TUFRevocationRootSignerUnpinned",
    "TUFTrustRootKeyDigestMismatch",
    "TUFTrustRootKeyUnpinned",
    "revocation_root_resolver_from_document",
    "verify_revocation_root_signatures",
    "fetch_sigstore_trust_root_key",
    "sigstore_trust_root_key_target_name",
    "validate_plugin_allowlist_document",
    "validate_revocation_root_document",
    "validate_sigstore_trust_root_document",
    "ACCEPTABLE_PAYLOAD_TYPES",
    "DEFAULT_TUF_FEED_URL",
    "MAX_ROOT_EXPIRY_DAYS",
    "RELEASE_MANIFEST_PAYLOAD_TYPE",
    "MAX_SNAPSHOT_STALENESS_DAYS",
    "MAX_TIMESTAMP_STALENESS_HOURS",
    "MIN_ROOT_KEY_COUNT",
    "MIN_ROOT_THRESHOLD",
    "REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED",
    "REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES",
    "REASON_STH_GOSSIP_SIGNATURE_INVALID",
    "ROLE_PLUGIN_ALLOWLIST",
    "ROLE_REVOCATION_ROOT",
    "ROLE_SIGSTORE_TRUST_ROOT",
    "ROLE_VKERNEL_RELEASE",
    "SthGossipResult",
    "TUFBootstrapPlaceholderPresent",
    "TUFClientError",
    "TUFConsistentSnapshotMissing",
    "TUFRoleSeparationViolation",
    "TUFRootExpired",
    "TUFRootKeyPrivateMaterialOnDisk",
    "TUFRootSignatureThresholdNotMet",
    "TUFSnapshotStale",
    "TUFTargetUnknownPayloadType",
    "TUFTimestampStale",
    "TUFVersionRollback",
    "check_sth_gossip_structure",
    "fetch_plugin_allowlist",
    "fetch_release_manifest",
    "fetch_revocation_root",
    "fetch_sigstore_trust_root",
    "load_bundled_root",
]
