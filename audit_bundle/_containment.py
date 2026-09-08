"""audit_bundle._containment — the ONE rule for "this producer-named path stays
inside this root, and points at something a blocking read can safely open".

Before 2026-09-05 the package held that rule five ways (plus three copies in
the standalone reference packs): the strongest, ``bundle_manifest._safe_bundle_path``,
resolved the join, asserted containment, then ``lstat``-classified the object
so a FIFO, socket, device or directory planted at a manifest-declared path
could not hang a blocking ``read_bytes`` (a DoS that lands BEFORE any verdict,
so fail-closed never fires). The other four — ``_safepath.resolve_within`` (the
promoted primitives), two sites in ``rederivation/dispatch.py`` (pinned inputs,
claimed-value outputs) and the emitter's write-side check — carried only the
containment half. Every one of them reads a path the producer named.

This module is a leaf (``os``, ``stat``, ``pathlib`` only) so any layer can
import it without a cycle. The callers keep their own vocabulary: they catch
:class:`ContainmentError`, read ``.reason``, and raise their own exception.

Contract of :func:`contain`:

* ``root / rel`` is resolved (every component, symlinks followed, ``..``
  collapsed, an absolute ``rel`` discarding ``root``) and must stay under
  ``root.resolve()`` — else ``reason="escape"``;
* a ``rel`` the filesystem cannot represent (embedded NUL, lone surrogate)
  is ``reason="unrepresentable"`` — not a crash;
* with ``require_regular=True`` (the default, for READERS) the UNRESOLVED
  join is ``lstat``-ed: a directory, FIFO, socket or device is
  ``reason="not_regular"``; an in-tree symlink whose contained target is a
  regular file is tolerated (the strict-SHA walk pins the dereferenced bytes;
  readers that must not follow even a contained link layer ``O_NOFOLLOW`` on
  top); an ABSENT object passes through unchanged — absence is the caller's
  ``exists()`` concern, so a "file missing" verdict keeps its own code;
* with ``require_regular=False`` (WRITERS, before the object exists) only
  containment is checked.

Stdlib only (§C5 core verify() path).
"""

from __future__ import annotations

import os
import stat as _stat
from pathlib import Path

__all__ = ["ContainmentError", "contain"]


class ContainmentError(ValueError):
    """``reason`` is one of ``"escape"``, ``"unrepresentable"``,
    ``"not_regular"``, ``"unstatable"``."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def contain(root: Path, rel: str, *, require_regular: bool = True) -> Path:
    """Resolve ``rel`` under ``root`` and return the resolved path, or raise
    :class:`ContainmentError`. See the module docstring for the contract."""
    root_resolved = root.resolve()
    try:
        candidate = (root / rel).resolve()
    except (ValueError, UnicodeEncodeError) as exc:
        # NUL byte -> ValueError; lone surrogate -> UnicodeEncodeError. Both
        # escaped an `except OSError` at one site as a verifier crash.
        raise ContainmentError(
            "unrepresentable",
            f"path {rel!r} is not representable on this filesystem ({exc})",
        ) from None
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        raise ContainmentError(
            "escape",
            f"path {rel!r} resolves outside {root_resolved} ({candidate}) — "
            "refusing (path containment)",
        ) from None
    if not require_regular:
        return candidate
    try:
        st = os.lstat(root / rel)
    except (FileNotFoundError, NotADirectoryError):
        return candidate  # absence is the caller's concern
    except OSError as exc:
        raise ContainmentError(
            "unstatable",
            f"path {rel!r} could not be stat'd ({type(exc).__name__}: {exc})",
        ) from None
    mode = st.st_mode
    if _stat.S_ISLNK(mode):
        # Contained (proved above); the target must itself be a regular file.
        if candidate.is_file():
            return candidate
        raise ContainmentError(
            "not_regular",
            f"path {rel!r} is a symlink to a non-regular object ({candidate}); "
            "a producer-named path must resolve to a regular file",
        )
    if _stat.S_ISDIR(mode):
        raise ContainmentError(
            "not_regular",
            f"path {rel!r} resolves to a directory ({candidate}); "
            "a producer-named path must point at a regular file",
        )
    if not _stat.S_ISREG(mode):
        raise ContainmentError(
            "not_regular",
            f"path {rel!r} is a non-regular file ({candidate}); a FIFO, socket, "
            "or device would block or mislead a blocking read",
        )
    return candidate
