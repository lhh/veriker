"""audit_bundle.digest — the ONE sha256 helper for files and bytes.

Before 2026-09-05 the package defined ``sha256_file`` five times in three
shapes: ``read_bytes()`` in one call (three copies), a streamed read (one), and
a streamed read that returned the digest of the EMPTY string when the file was
absent (``orchestrator_turn``, closed tier, not part of the open drop). That last
shape is the fail-open of this class:
a missing artifact digests to ``e3b0c442…`` and agrees with any manifest that
declares the empty digest — absence reads as agreement. Nothing held the five
in agreement, and the difference only shows on the path nobody tests: the file
that is not there.

Contract:

* :func:`sha256_file` streams the file (64 KiB chunks; a large artifact is
  never materialised twice) and RAISES ``FileNotFoundError`` / ``OSError`` on
  absence or unreadability. Absence is the caller's verdict to make, with its
  own reason code, never a digest;
* :func:`sha256_bytes` is ``hashlib.sha256(data).hexdigest()``, named once so
  the ratchet can count it.

The standalone reference packs keep their own ``sha256_file`` (import-nothing
contract), pinned across packs by ``tests/test_reference_pack_parity.py``.

Stdlib only (§C5 core verify() path).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

__all__ = ["sha256_bytes", "sha256_file"]

_CHUNK = 65536


def sha256_bytes(data: bytes) -> str:
    """Hex sha256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Hex sha256 of the file at ``path``, streamed. Raises on absence."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()
