"""Skip markers for the tests that need an optional extra.

The core package declares NO dependencies -- `pip install veriker` installs
veriker and nothing else, which is what makes the README's "offline, stdlib-only"
badge checkable rather than merely stated. Everything third-party lives in an
extra (`crypto`, `c19`, `hostverify`) or in `dev`.

That means a lean install must SKIP the slices that need those packages, not fail
them. Two ways to do it, and the choice matters:

  * `pytest.importorskip("x")` at module level -- correct only when EVERY test in
    the file needs `x`. Used where that holds.
  * the markers below -- for the common case where a file is a mix. Most of these
    files have a majority of tests that pass fine on a lean install; skipping the
    whole module would silently retire that coverage, which is the more expensive
    mistake. Measured 2026-09-03: test_conservation_gate.py is 3 dependent of 33,
    test_dsse_pae_golden.py 1 of 21.

`find_spec` is used rather than a try/import so the check costs nothing and does
not leave a half-initialised module behind on failure.
"""

from __future__ import annotations

import importlib.util

import pytest


def _missing(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is None
    except (ImportError, ValueError):
        # a namespace-package parent that cannot be resolved reads as missing
        return True


def requires(module: str, extra: str):
    """Skip the decorated test when `module` is absent.

    `extra` names the install that provides it, so the skip reason tells the
    reader how to turn the test on instead of leaving them to guess.
    """
    return pytest.mark.skipif(
        _missing(module),
        reason=f"needs {module} — install {extra}",
    )


requires_cryptography = requires("cryptography", "veriker[crypto]")
requires_rfc8785 = requires("rfc8785", "veriker[crypto]")
requires_cbor2 = requires("cbor2", "veriker[c19]")
requires_pycose = requires("pycose", "veriker[dev]")
requires_z3 = requires("z3", "veriker[dev]")
requires_openpyxl = requires("openpyxl", "veriker[dev]")
