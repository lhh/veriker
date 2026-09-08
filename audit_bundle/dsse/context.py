"""Open-drop constructor for the DSSE verification context `BundleVerifier.verify(dsse=)` takes.

`audit_bundle.verifier` reads a `DsseVerifyContext` PROTOCOL (allowlist, verifier_now,
revocation_list, require_dsse, allow_legacy) and never constructs one. Until this
module existed the only concrete constructor was in `audit_bundle.orchestrator_turn`
(excluded from the open drop) and the emitter's in-process self-check, so no shipped
path could run the sealing lane: `veriker/cli/verify.py` printed
`DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO` on every sealed bundle and told the reader to
write the wiring themselves.

`build_dsse_context` builds the context from AUDITOR-HELD inputs only:

  * an allowlist file `{kid: b64url-nopad pubkey_raw32}` (the C18-distributed
    verifier allowlist; each kid must equal `kid_from_raw32(pubkey)`);
  * a signed revocation list (`vkernel_revocations.json`);
  * a revocation ROOT — the `revocation-root` role document, either an auditor-held
    file or fetched through the TUF chain (`c18_tuf_client.fetch_revocation_root`) —
    strict-validated, its own 2-of-3 Ed25519 signatures verified, and its pinned
    list signer the ONLY kid the resolver admits
    (`c18_tuf_client.revocation_root_resolver_from_document`);
  * the verifier's clock.

Every path is resolved (symlinks followed) and REFUSED inside the bundle under
verdict: trust material read out of the artifact it constrains is the measured
tautology (`SpecAnchor.from_files(forbid_within=...)`, row 14). Every failure is a
`DsseContextError` — operator material that cannot be used, never a REJECT of the
bundle — which the CLI maps to `DSSE_CONTEXT_ARG_INVALID`, exit 2.

This module imports `cryptography` and `rfc8785` transitively (`audit_bundle.revocation`)
and `audit_bundle.extensions` lazily; it is NOT on the stdlib-only import path and
must only ever be imported lazily by `veriker/cli/verify.py`
(`tests/test_stdlib_import_boundary.py`, `tests/c18/test_cli_verify_c18_extension.py`).
"""

from __future__ import annotations

import base64
import binascii
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from audit_bundle.admission import InputInadmissible, admit_json_file
from audit_bundle.dsse.pae import kid_from_raw32
from audit_bundle.revocation import (
    RevocationList,
    RevocationListInvalid,
    load_revocation_list,
)

__all__ = [
    "DsseContextError",
    "OpenDsseVerifyContext",
    "RevocationRootFile",
    "RevocationRootTuf",
    "build_dsse_context",
    "load_allowlist_file",
]


class DsseContextError(Exception):
    """Auditor-held DSSE material could not be used (unreadable, malformed, inside the
    bundle, under-signed, expired, unpinned). Operator error: no verdict about the
    bundle was formed."""


@dataclass(frozen=True)
class OpenDsseVerifyContext:
    """A concrete `DsseVerifyContext` (structural match of the core Protocol).

    `provenance` is not read by the gate; it is printed on the CLI face so a reader
    knows where the allowlist, the revocation root and the list came from.
    """

    allowlist: Mapping[str, bytes]
    verifier_now: int
    revocation_list: RevocationList | None
    require_dsse: bool
    allow_legacy: bool
    provenance: tuple[str, ...]


@dataclass(frozen=True)
class RevocationRootFile:
    """An auditor-held copy of the `revocation-root` role document."""

    path: Path


@dataclass(frozen=True)
class RevocationRootTuf:
    """The `revocation-root` role document fetched through the TUF chain."""

    trust_dir: Path
    feed_url: str | None = None


def _resolve_outside(
    path: Path, *, forbid_within: Path | None, what: str, kind: str = "file"
) -> Path:
    """Resolve an auditor-held path (symlinks followed) and refuse it inside the
    bundle under verdict. `kind` is "file" or "dir" (the TUF trust directory)."""
    try:
        # A trust DIRECTORY may not exist yet (the TUF client creates it); a file must.
        resolved = path.resolve(strict=(kind != "dir"))
    except OSError as exc:
        raise DsseContextError(f"{what} {path} is not readable: {exc}") from exc
    if forbid_within is not None:
        try:
            root = forbid_within.resolve(strict=False)
        except OSError:
            root = forbid_within
        if resolved == root or root in resolved.parents:
            raise DsseContextError(
                f"{what} {path} resolves inside the bundle under verdict ({root}); "
                "trust material read out of the artifact it constrains is a "
                "tautology (refused, symlinks followed)."
            )
    if kind == "dir":
        if resolved.exists() and not resolved.is_dir():
            raise DsseContextError(f"{what} {path} exists and is not a directory")
    elif not resolved.is_file():
        raise DsseContextError(f"{what} {path} is not a regular file")
    return resolved


def load_allowlist_file(path: Path, *, forbid_within: Path | None = None) -> dict[str, bytes]:
    """`{kid: b64url-nopad pubkey_raw32}` → `{kid: pubkey_raw32}`; every kid must equal
    `kid_from_raw32(pubkey)` (a mislabeled entry is refused, never renamed)."""
    resolved = _resolve_outside(path, forbid_within=forbid_within, what="--dsse-allowlist")
    # Auditor-held, but still read through the admission-bounded loader: a
    # depth-bombed trust file must be a cheap refusal, never a RecursionError.
    try:
        doc = admit_json_file(resolved, check_name="dsse_allowlist_admission")
    except InputInadmissible as exc:
        raise DsseContextError(f"--dsse-allowlist {path}: not admissible JSON: {exc}") from exc
    if not isinstance(doc, dict) or not doc:
        raise DsseContextError(f"--dsse-allowlist {path}: must be a non-empty JSON object")
    out: dict[str, bytes] = {}
    for kid, val in doc.items():
        if not isinstance(kid, str) or not isinstance(val, str):
            raise DsseContextError(f"--dsse-allowlist {path}: entry {kid!r} is not str->str")
        try:
            raw = base64.urlsafe_b64decode(val + "=" * ((4 - len(val) % 4) % 4))
        except (binascii.Error, ValueError) as exc:
            raise DsseContextError(
                f"--dsse-allowlist {path}: entry {kid!r} is not base64url: {exc}"
            ) from exc
        if len(raw) != 32:
            raise DsseContextError(
                f"--dsse-allowlist {path}: entry {kid!r} decodes to {len(raw)} bytes, not 32"
            )
        if kid_from_raw32(raw) != kid:
            raise DsseContextError(
                f"--dsse-allowlist {path}: kid {kid!r} is not kid_from_raw32 of its key "
                f"({kid_from_raw32(raw)!r}); refusing a mislabeled entry"
            )
        out[kid] = raw
    return out


def _revocation_root_document(
    source: RevocationRootFile | RevocationRootTuf, *, forbid_within: Path | None
) -> tuple[dict[str, Any], str]:
    """The role document plus a source label. File form: read + containment. Chain
    form: `fetch_revocation_root` (strict) — the envelope's `document`."""
    if isinstance(source, RevocationRootFile):
        resolved = _resolve_outside(
            source.path, forbid_within=forbid_within, what="--dsse-revocation-root"
        )
        try:
            doc = admit_json_file(resolved, check_name="dsse_revocation_root_admission")
        except InputInadmissible as exc:
            raise DsseContextError(
                f"--dsse-revocation-root {source.path}: not admissible JSON: {exc}"
            ) from exc
        if not isinstance(doc, dict):
            raise DsseContextError(
                f"--dsse-revocation-root {source.path}: not a JSON object"
            )
        return doc, f"file {resolved}"
    from audit_bundle.extensions import c18_tuf_client as _tc  # noqa: PLC0415

    # The trust directory is auditor-held too, and the TUF client WRITES fetched
    # metadata under it: a trust dir inside the artifact under verdict is both a
    # tautology and a write into the thing being judged. Same refusal as the files.
    trust_dir = _resolve_outside(
        source.trust_dir,
        forbid_within=forbid_within,
        what="--dsse-revocation-root-tuf",
        kind="dir",
    )
    kwargs: dict[str, Any] = {"trust_dir": trust_dir}
    if source.feed_url is not None:
        kwargs["feed_url"] = source.feed_url
    try:
        fetched = _tc.fetch_revocation_root(**kwargs)
    except _tc.TUFClientError as exc:
        raise DsseContextError(
            f"--dsse-revocation-root-tuf: {type(exc).__name__}: {exc}"
        ) from exc
    return fetched["document"], f"TUF chain ({fetched['authenticated_by']})"


def build_dsse_context(
    *,
    allowlist_path: Path,
    revocation_list_path: Path,
    revocation_root: RevocationRootFile | RevocationRootTuf,
    verifier_now: int,
    forbid_within: Path | None,
    require_dsse: bool = True,
    allow_legacy: bool = False,
    max_backdate_s: int = 300,
) -> OpenDsseVerifyContext:
    """Build the context from auditor-held inputs. See the module docstring.

    `verifier_now` is the ONE clock of the run: the revocation root's expiry, the
    list's window and every `not_after` are graded against it. It may not sit more
    than `max_backdate_s` behind the wall clock — a backdated clock un-revokes a
    key (`not_after` in its future) and un-stales an expired list, so the operator
    may pin the instant at or after now, never before (fresh-pass witnesses
    `w_dsse.py B`, `C`, 2026-09-02). Moving the clock forward only ever refuses more.
    """
    if not isinstance(verifier_now, int) or isinstance(verifier_now, bool):
        raise DsseContextError("verifier_now must be an int (unix seconds)")
    wall_now = int(time.time())
    if verifier_now < wall_now - max_backdate_s:
        raise DsseContextError(
            f"verifier_now={verifier_now} is {wall_now - verifier_now}s behind the "
            f"wall clock ({wall_now}); a backdated verifier clock un-revokes keys and "
            f"un-stales lists, so --dsse-now may be at most {max_backdate_s}s in the "
            "past (pin it at or after now)"
        )
    allowlist = load_allowlist_file(allowlist_path, forbid_within=forbid_within)
    doc, root_source = _revocation_root_document(revocation_root, forbid_within=forbid_within)
    from audit_bundle.extensions import c18_tuf_client as _tc  # noqa: PLC0415

    try:
        resolver, root_prov = _tc.revocation_root_resolver_from_document(
            doc, source=root_source, verifier_now=verifier_now
        )
    except _tc.TUFClientError as exc:
        raise DsseContextError(
            f"revocation root ({root_source}): {type(exc).__name__}: {exc}"
        ) from exc
    list_path = _resolve_outside(
        revocation_list_path, forbid_within=forbid_within, what="--dsse-revocation-list"
    )
    # Bounds first (depth / size / cardinality), then the signature-checking
    # loader on the same bytes: a depth-bombed list is a typed refusal, never a
    # RecursionError out of `json.loads` (fresh pass, process lens, 2026-09-02).
    try:
        admit_json_file(list_path, check_name="dsse_revocation_list_admission")
    except InputInadmissible as exc:
        raise DsseContextError(
            f"--dsse-revocation-list {revocation_list_path}: not admissible JSON: {exc}"
        ) from exc
    try:
        rev_list = load_revocation_list(
            list_path.read_bytes(), revocation_root_resolver=resolver
        )
    except (OSError, RevocationListInvalid, RecursionError) as exc:
        raise DsseContextError(
            f"--dsse-revocation-list {revocation_list_path}: {exc}"
        ) from exc
    provenance = (
        f"allowlist: file {allowlist_path.resolve()} ({len(allowlist)} kid(s))",
        f"revocation root: {root_source}; signed_by={root_prov['signed_by']} "
        f"threshold={root_prov['threshold']} pinned_list_signer="
        f"{root_prov['pinned_list_signer']} expires={root_prov['expires']}",
        f"revocation list: file {list_path} sha256={rev_list.revocation_list_hash} "
        f"issued_at={rev_list.issued_at} expires={rev_list.expires} "
        f"entries={len(rev_list.entries)}",
        f"verifier_now: {verifier_now}",
    )
    return OpenDsseVerifyContext(
        allowlist=allowlist,
        verifier_now=verifier_now,
        revocation_list=rev_list,
        require_dsse=require_dsse,
        allow_legacy=allow_legacy,
        provenance=provenance,
    )


ResolverType = Callable[[str], bytes]
