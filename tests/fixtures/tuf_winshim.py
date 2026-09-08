"""Windows test-env shim: python-tuf 7.0's Updater.__init__ symlinks
metadata/root.json -> root_history/{v}.root.json. Windows blocks os.symlink
without privilege/developer-mode. The substrate runs in a Linux OCI image, so
this is a TEST-ENV concern only (NOT a C18 finding). We replace the symlink with
a faithful file-copy so the protocol state machine runs unchanged.

Import this module (call install()) before constructing any Updater on Windows.
"""

from __future__ import annotations

import os
import shutil

import tuf.ngclient.updater as _u


def install() -> None:
    def _copy_root(self) -> None:  # type: ignore[no-untyped-def]
        linkname = os.path.join(self._dir, "root.json")
        version = self._trusted_set.root.version
        current = os.path.join(self._dir, "root_history", f"{version}.root.json")
        shutil.copyfile(current, linkname)

    _u.Updater._update_root_symlink = _copy_root  # type: ignore[assignment]
