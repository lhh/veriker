"""The payload lever: deleting the evidence must not delete the failure.

MEASURED 2026-08-31, before the fix in this commit: 31 of 51 plugin-bound
pilots returned exit 0 PASS on a bundle with `payload/` deleted and its
`manifest.files` entries dropped. The producer removes the very files the
checks read, and the verdict face says PASS.

The mechanism was 105 `PluginResult(ok=True, reason_code="NO_...")` opt-out
branches across 54 files under `examples/`. Each one reports an ABSENCE of
checking as OK. `gxp_part11_minimal` is the shape at its clearest: it FAILS
on a complete bundle (its signature is unverifiable without a key, failing
closed, correct) and PASSED once its single payload file was removed —
deleting the evidence deleted the failure.

`PluginResult.incomplete` already existed for exactly this and is checked
BEFORE `.ok`, so the conversion is `ok=True` -> `ok=False, incomplete=True`
with the reason_code and detail untouched. The verdict becomes a clean-ERROR
leg (exit 2, could-not-conclude), which is the honest reading: the artifact
was not shown bad, and it was not checked either.

This file is the BEHAVIOURAL pin. It runs the attack rather than reading the
source, because a source pattern is not a measurement — the same defect class
has been mis-measured by grep repeatedly in this tree. The source ratchet at
the bottom is a regression tripwire only, and says so.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _PKG_ROOT / "examples"

# A spread across the 31 measured-vulnerable pilots, not just the two that
# motivated the fix (a fix tested only against its motivating case measures
# one pilot, not a class). Chosen to span the shapes: single-payload-file and
# many-payload-file, green-on-clean and red-on-clean, plugin wrappers with and
# without a local re-derivation pack.
# Filtered to what is present on disk. The OSS drop ships a SUBSET of the
# fleet, and its scrubber rewrites some pilot names in source on the way out
# (a run against a real --dest export produced a parametrisation for a pilot
# directory that does not exist there). Both make a hardcoded list wrong in the
# drop, so the list is the INTERNAL intent and the filter is what executes.
_CANDIDATES = [
    "bom_minimal",  # motivating case 1: clean 0, attacked was 0
    "kg_minimal",
    "scrabble_minimal",
    "pii_redaction_minimal",  # 4 payload files
]
_PILOTS = [
    p
    for p in _CANDIDATES
    if (_EXAMPLES / p / "_build_bundle.py").is_file()
    and (_EXAMPLES / p / "verify.py").is_file()
]

# Internally every candidate must be present; a silent shrink to one pilot
# would turn the class measurement back into a single-case measurement.
_INTERNAL_TREE = (_PKG_ROOT / "release" / "oss_export.py").is_file()

# Pilots whose clean bundle verifies green in a bare environment. The attack
# assertion alone would still pass if the fix were a blunt "always refuse", so
# these pin the other direction: a COMPLETE bundle must stay green.
_CLEAN_GREEN = set(_PILOTS) - {"gxp_part11_minimal"}


def test_parametrisation_is_not_vacuous() -> None:
    """Guard the guard: internally this must range over the whole named set."""
    if _INTERNAL_TREE:
        assert _PILOTS == _CANDIDATES, (
            "a named pilot went missing from the internal tree, so the class "
            f"measurement silently shrank. expected={_CANDIDATES} got={_PILOTS}"
        )
    else:
        assert _PILOTS, "no candidate pilot survived the filter — nothing is measured"


def _pilot_env(pilot_dir: Path) -> dict[str, str]:
    """Env keys a pilot documents in its README export block.

    Seven pilots need an HMAC key and are not broken without one; read the
    README rather than calling them red. Only literal assignments are taken —
    a `$(cat ...)` value is left unset, which is why gxp_part11_minimal is
    expected red on a clean bundle here.
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    readme = pilot_dir / "README.md"
    if readme.exists():
        for m in re.finditer(
            r'export\s+(VKERNEL_[A-Z0-9_]+)="([^"$]+)"',
            readme.read_text(errors="ignore"),
        ):
            env[m.group(1)] = m.group(2)
    return env


def _run(script: Path, args: list[str], env: dict[str, str]) -> tuple[int, str]:
    """Exit code AND combined output — the cause has to be assertable.

    An exit code alone cannot tell a refusal produced by the converted opt-out
    branch from a refusal produced by anything else (a rewritten manifest, an
    unrelated guard). A partial revert would keep the code and lose the cause.
    """
    proc = subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        env=env,
        cwd=str(_PKG_ROOT),
        timeout=300,
    )
    return proc.returncode, (proc.stdout + proc.stderr).decode(errors="replace")


def _strip_payload(bundle: Path) -> int:
    """Delete payload/ and drop its manifest.files entries. Returns files removed."""
    payload = bundle / "payload"
    rels = sorted(str(p.relative_to(bundle)) for p in payload.rglob("*") if p.is_file())
    shutil.rmtree(payload)
    mpath = bundle / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    files = manifest.get("files")
    if isinstance(files, dict):
        for key in [k for k in files if k.split("/")[0] == "payload"]:
            files.pop(key)
    elif isinstance(files, list):
        manifest["files"] = [
            e
            for e in files
            if str(e.get("path", e) if isinstance(e, dict) else e).split("/")[0]
            != "payload"
        ]
    mpath.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return len(rels)


@pytest.mark.parametrize("pilot", _PILOTS)
def test_deleted_payload_is_never_exit_zero(pilot: str, tmp_path: Path) -> None:
    pilot_dir = _EXAMPLES / pilot
    env = _pilot_env(pilot_dir)
    verify = pilot_dir / "verify.py"

    clean = tmp_path / "clean"
    build_code, build_out = _run(
        pilot_dir / "_build_bundle.py", ["--out-dir", str(clean)], env
    )
    assert build_code == 0, (
        f"{pilot}: bundle build failed — the attack below would be vacuous.\n{build_out[-600:]}"
    )

    clean_exit, _ = _run(verify, ["--bundle-dir", str(clean)], env)
    if pilot in _CLEAN_GREEN:
        assert clean_exit == 0, (
            f"{pilot}: COMPLETE bundle no longer verifies green (exit {clean_exit}). "
            "The opt-out conversion must refuse an absent payload, not every bundle."
        )
    elif pilot == "gxp_part11_minimal":
        # The inversion case, ASSERTED rather than left in a comment. Without
        # the two $(cat ...) HMAC keys this pilot fails CLOSED on a complete
        # bundle. Measured exit 1 on 2026-08-31, before and after the fix. If
        # this ever becomes 2, the clean/attacked comparison below stops
        # distinguishing anything and the inversion is no longer being pinned.
        assert clean_exit == 1, (
            f"{pilot}: expected the complete bundle to REJECT (exit 1) in a "
            f"key-less environment, got {clean_exit}. The inversion this pilot "
            "is here to demonstrate is no longer being measured."
        )

    attacked = tmp_path / "attacked"
    shutil.copytree(clean, attacked)
    removed = _strip_payload(attacked)
    assert removed > 0, (
        f"{pilot}: no payload files to delete, so this parametrisation asserts "
        "nothing. Drop the pilot from _CANDIDATES or pick a different lever."
    )

    attacked_exit, attacked_out = _run(verify, ["--bundle-dir", str(attacked)], env)
    assert attacked_exit != 0, (
        f"{pilot}: deleting {removed} payload file(s) and their manifest.files "
        f"entries still returned exit 0 PASS. An absence of checking is being "
        f"reported as OK (clean bundle exits {clean_exit})."
    )
    # Exit 1 is ADMITTED: a pilot that grows a genuine REJECT on a deleted
    # payload has a stronger verifier, and pinning 2 exactly would fail that
    # improvement. What must never happen is 0, and an exit 2 must actually be
    # a could-not-conclude rather than an exit code arriving from elsewhere.
    assert attacked_exit in (1, 2), (
        f"{pilot}: expected REJECT (1) or could-not-conclude (2), got "
        f"{attacked_exit}.\n{attacked_out[-600:]}"
    )
    if attacked_exit == 2:
        assert "could not conclude" in attacked_out, (
            f"{pilot}: exit 2 without a could-not-conclude leg — the refusal did "
            f"not come from where this test claims.\n{attacked_out[-600:]}"
        )


# ---------------------------------------------------------------------------
# Regression tripwire (NOT a measurement)
# ---------------------------------------------------------------------------

# The two branches deliberately left un-converted. Both were decided on their
# own semantics, and both were MEASURED before being left alone:
#
#   digital-thread pilot SimBundleReverifyCheck  NO_CROSS_REF (branch 2, no sim_bundle_path)
#     STILL DEFERRED, but the original rationale for deferring it was WRONG and
#     is corrected here rather than quietly dropped. It claimed "the entries
#     carry an opaque-SHA binding that IS checked". Measured 2026-08-31:
#       - the SHA comparison lives INSIDE `for entry in cross_ref_entries`, and
#         this branch returns precisely when that list is EMPTY, so on the
#         deferred path the plugin hashes nothing;
#       - that pilot's own built bundle carries 3 entries and 0 with
#         `sim_bundle_path`, so the honest shipped bundle takes this branch on
#         EVERY run — the plugin named sim_bundle_reverify re-verifies nothing;
#       - the only other consumer, digital_thread_re_derivation.py:395-425,
#         SHAPE-checks `sim_bundle_sha` (asserts it is a string) and never
#         compares its value against anything.
#     So this is an absence reported as OK, not a mode. It is NOT converted here
#     only because doing so turns a green shipped pilot's default verdict to
#     exit 2, which is a product decision and not this commit's to make. Tracked
#     as open, same shape as the four pilots that declare an assurance profile
#     nothing grades. (Branch 1 of the same file, spec/sim_binding_manifest.json
#     absent, IS a plain file-absence and WAS converted.)
#
#   spectra ThreeSetReDerivationCheck  NO_OUTPUTS
#     manifest.per_output_manifests empty — the bundle makes no three-set claim
#     at all. This is the DECLARATION lever (empty the declaration so dispatch
#     goes inert), not the payload lever this file measures; spectra_minimal
#     ships no payload/ directory and is immune to the lever above by
#     construction. It needs its own measurement and its own commit, and is
#     named here so the deferral is visible rather than silent.
_DEFERRED = {
}

_OPT_OUT = re.compile(
    r'PluginResult\(\n(?P<i>[ ]+)ok=True,\n(?P=i)reason_code="(NO_[A-Z0-9_]+)"'
)


def test_no_new_absence_reported_as_ok() -> None:
    """A source tripwire so the class does not silently regrow.

    This is deliberately NOT the measurement — a filename or source pattern has
    given the wrong answer for this defect class more than once, and a wrapper
    refactored one file over would slip straight past it. The behavioural test
    above is what establishes the property. This only catches a NEW opt-out
    branch pasted in the old shape, which is how the 105 accumulated.
    """
    found: dict[str, int] = {}
    for path in sorted(_EXAMPLES.rglob("*.py")):
        n = len(_OPT_OUT.findall(path.read_text(errors="ignore")))
        if n:
            found[str(path.relative_to(_PKG_ROOT))] = n

    # Only the deferrals that EXIST here. Both deferred files are internal-only
    # (one PARTNER_HELD, one a product pilot), so an exact-equality compare
    # against the internal set fails deterministically in a --dest export —
    # measured: it did, on a customer's first pytest, which is the same defect
    # the preceding commit repaired for a different test.
    expected = {k: v for k, v in _DEFERRED.items() if (_PKG_ROOT / k).is_file()}

    assert found == expected, (
        "PluginResult(ok=True, reason_code='NO_...') set changed. An absence of "
        "checking reported as OK is the defect this file exists for: convert it "
        "to ok=False, incomplete=True (reason_code and detail unchanged), or, if "
        "the branch genuinely is not an absence, add it to _DEFERRED with the "
        f"reason. expected={expected} found={found}"
    )
