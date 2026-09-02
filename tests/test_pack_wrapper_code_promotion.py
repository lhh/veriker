"""A pack wrapper's reason code must be the PACK's, never the producer's.

Both defects pinned here were found by a fresh-context red-team pass on
2026-08-31, immediately after `_step_typed_check_plugins` started propagating
`PluginResult.reason_code` onto the verdict face. Neither was reachable before
that: while the boundary overwrote every failing plugin's code with the literal
"plugin_failed", a wrapper's choice of code was inert. Making the code visible
is what made these live, so the guards belong with the propagation.

1. PRODUCER-CHOSEN CODE. Three wrappers promote a "[CODE]" token out of their
   pack's stderr -- and the pack interpolates bundle-supplied values into that
   same stream. An unbounded scan therefore let a PRODUCER name the reason code
   on the verdict face, including "[RE_DERIVED]" on a FAILING verify().

2. CRASHED PACK REPORTED AS A DISAGREEMENT. Every wrapper mapped any non-zero
   exit to RE_DERIVATION_MISMATCH, whose documented meaning is "the recompute
   ran and DISAGREED". A pack that died on an uncaught exception compared
   nothing, and the claim-field ratchet credited that as proven coverage.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from audit_bundle.plugins.re_derivation_invocation import classify_pack_failure


# --- 2. a crash is not a disagreement ---------------------------------------


def test_a_refusing_pack_keeps_the_mismatch_code():
    code, incomplete = classify_pack_failure(
        "[FP_ML_REDER_FAIL] value mismatch: derived=1.0 bundled=2.0"
    )
    assert code == "RE_DERIVATION_MISMATCH"
    assert incomplete is False


def test_a_crashed_pack_is_could_not_conclude_not_a_mismatch():
    """The pack died before comparing anything, so it must not report that a
    comparison happened and disagreed."""
    code, incomplete = classify_pack_failure(
        'Traceback (most recent call last):\n'
        '  File "pack.py", line 14, in <module>\n'
        '    _ = _BAND_ORDER[doc["band"]]\n'
        "KeyError: 'band'\n"
    )
    assert code == "RE_DERIVATION_NOT_COMPARED"
    assert incomplete is True, (
        "a crashed pack must route to the clean-ERROR (could-not-conclude) leg, "
        "not the REJECT leg -- otherwise the claim-field ratchet scores it as "
        "'a comparator refused the mutated value'"
    )


def test_the_crash_code_is_scored_as_plumbing_by_the_ratchet():
    """The two halves have to agree, or the fix above buys nothing."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from claimset_ratchet import _PLUMBING_CODES

    assert "RE_DERIVATION_NOT_COMPARED" in _PLUMBING_CODES
    assert "RE_DERIVATION_MISMATCH" not in _PLUMBING_CODES


# --- 1. the promoted code is allowlisted and unambiguous ---------------------
#
# DISCOVERED, not named. Pilot directory names are not written here: several are
# partner-held and the OSS export refuses a shipping test that names one. Ranging
# over every wrapper that declares an allowlist is also the stronger test -- a
# new wrapper joins the battery by existing.


def _wrappers():
    """(path, module) for every pack wrapper that declares a promotion allowlist."""
    import importlib.util

    root = Path(__file__).resolve().parents[1] / "examples"
    out = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "_PACK_CODES" not in text and "_PACK_SUB_CODES" not in text:
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:  # noqa: BLE001 - a wrapper we cannot import is not ours to test
            continue
        codes = getattr(mod, "_PACK_CODES", None) or getattr(mod, "_PACK_SUB_CODES", None)
        rx = getattr(mod, "_CODE_RE", None) or getattr(mod, "_SUB_CODE_RE", None)
        if codes and rx is not None:
            out.append((path, rx, frozenset(codes)))
    return out


def _line(rx, code: str, tail: str = "the real failure") -> str:
    """One stderr line in THIS wrapper's own format.

    Wrappers differ: some scan for a bare "[CODE]" anywhere in the snippet,
    others anchor on their pack's own "[PACK_MARKER] CODE:" prefix at line
    start. A battery that assumed one format would silently pass the other by
    matching nothing -- so the line is built from the wrapper's own pattern.
    """
    pat = rx.pattern
    if pat.startswith(r"^\["):
        marker = pat[3 : pat.index(r"\]")]
        return f"[{marker}] {code}: {tail}"
    return f"[{code}] {tail}"


def _promote(rx, codes, stderr: str) -> str:
    named = {c for c in rx.findall(stderr)} & codes
    return named.pop() if len(named) == 1 else "RE_DERIVATION_MISMATCH"


def test_at_least_one_wrapper_is_discovered():
    """NON-VACUITY. A battery that ranges over an empty set passes for free --
    and this one discovers its subjects, so an import change could silently
    empty it."""
    assert _wrappers(), "no pack wrapper with a promotion allowlist was discovered"


@pytest.mark.parametrize("case", _wrappers(), ids=lambda c: c[0].stem)
def test_a_producer_cannot_invent_a_code(case):
    """A token outside the wrapper's allowlist contributes nothing, so a
    producer who controls bytes on the pack's stderr cannot name the code that
    reaches the verdict face -- including the vocabulary's own success token."""
    path, rx, codes = case
    real = sorted(codes)[0]
    for injected in ("RE_DERIVED", "PASS", "OK", "SIGNED_OFF_NO_EXCEPTIONS"):
        # the injected token goes where PRODUCER bytes actually land: ahead of
        # the pack's own code, on the same line
        stderr = f"[{injected}] " + _line(rx, real)
        got = _promote(rx, codes, stderr)
        # THE SECURITY PROPERTY: the producer's token never becomes the code.
        assert got != injected, (
            f"{path.name}: producer token {injected!r} reached the verdict face"
        )
        # ...and the outcome is one of the two SAFE ones. Which one depends on
        # the wrapper's format, and both are fail-closed: a bare-bracket scanner
        # ignores the out-of-allowlist token and still promotes the pack's real
        # code; a marker-anchored one sees producer bytes at line start, matches
        # nothing, and degrades to the generic mismatch. Asserting `== real` for
        # both would fail the anchored wrappers for being MORE conservative.
        assert got in (real, "RE_DERIVATION_MISMATCH"), (
            f"{path.name}: injection produced {got!r}, neither the pack's code "
            f"nor a safe degradation"
        )


@pytest.mark.parametrize("case", _wrappers(), ids=lambda c: c[0].stem)
def test_a_producer_naming_a_REAL_code_is_ambiguous_not_decisive(case):
    """The residual axis: a producer who names a claim after a GENUINE code
    contributes a second allowlisted token. Ambiguity must degrade to the
    generic mismatch rather than let either side win. Skipped where a wrapper
    allowlists only one code -- there is no second token to inject."""
    path, rx, codes = case
    if len(codes) < 2:
        pytest.skip(f"{path.name} allowlists one code; ambiguity is unreachable")
    a, b = sorted(codes)[:2]
    got = _promote(rx, codes, _line(rx, a) + "\n" + _line(rx, b))
    assert got == "RE_DERIVATION_MISMATCH", f"{path.name}: ambiguity picked {got}"


@pytest.mark.parametrize("case", _wrappers(), ids=lambda c: c[0].stem)
def test_the_pack_names_its_own_code(case):
    """PRECISION CONTROL. The guard must not cost the honest single-code case --
    an earlier `^`-anchored attempt blocked the attack by breaking this."""
    path, rx, codes = case
    real = sorted(codes)[0]
    assert _promote(rx, codes, _line(rx, real)) == real, (
        f"{path.name}: honest single code was not promoted"
    )


@pytest.mark.parametrize("case", _wrappers(), ids=lambda c: c[0].stem)
def test_every_allowlisted_code_is_one_some_pack_actually_emits(case):
    """MISS-DIRECTION CONTROL. An allowlist that has drifted past the pack's
    real vocabulary is a standing hole, exactly like a stale ratchet entry:
    it widens what a producer can select from."""
    path, _rx, codes = case
    pack_text = "\n".join(
        f.read_text(encoding="utf-8", errors="replace")
        for f in sorted(path.parent.glob("*.py"))
    )
    missing = sorted(c for c in codes if f"[{c}]" not in pack_text and f'"{c}"' not in pack_text)
    assert not missing, f"{path.name}: allowlisted but never emitted: {missing}"
