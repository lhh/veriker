"""_safepath — bundle-path containment for verifier-side re-derivation primitives.

A promoted primitive runs on the SAFE spec-pinned path: no subprocess, no
bundle-supplied code. But "bundle data, not code" is only safe if bundle DATA
cannot steer arbitrary filesystem reads. Some recipes name the files a primitive
must read (build's recipe inputs, scrabble's resolved wordlist_file). Those names
are bundle-controlled, so a hostile bundle could request ``../../etc/passwd`` or
an absolute path and turn a read-bytes into an arbitrary-file oracle on the
VERIFIER's machine.

``resolve_within`` is the single audited containment rule those call sites share.
It mirrors the dispatch.py output-id defense (resolve, then assert the resolved
path stays inside the declared root) so there is ONE definition of "inside the
bundle" rather than per-primitive ad-hoc checks. It fails CLOSED: any path that
resolves outside the root raises ValueError, which the primitive surfaces as a
RECOMPUTE_ERROR rather than reading the out-of-tree file.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from pathlib import Path

from ..._containment import contain


def resolve_within(root: Path, rel: str) -> Path:
    """Join ``rel`` under ``root`` and return the resolved path, refusing escape
    AND any object a blocking read cannot safely open.

    ``rel`` is bundle-controlled (it comes from recipe/timeline data). Since
    2026-09-05 this is the package-wide rule in ``audit_bundle._containment``:
    the join is resolved and asserted to stay inside ``root``; a NUL / lone
    surrogate is refused; and the unresolved join is ``lstat``-classified so a
    directory, FIFO, socket or device at the named path is refused BEFORE the
    caller's ``read_bytes`` can block on it (that half used to live only in the
    manifest walk's ``_safe_bundle_path``). Every refusal is a ``ValueError``
    (``ContainmentError`` subclasses it), which the primitive surfaces as a
    RECOMPUTE_ERROR rather than reading the out-of-bundle or unreadable object.
    """
    return contain(root, rel)
