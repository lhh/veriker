"""No domain-prefixed universal spelling may come back into the fleet.

WHAT THIS RATCHETS, AND WHERE IT DELIBERATELY DOES NOT SIT.

The first attempt at this guard hung a `KIT_REASON_CODES` declaration off the
kit face and compared it against the entry module's SOURCE TEXT. That was
reverted (see the revert commit for the ten-shape evasion measurement); the
short version is that a kit registers PRIMITIVES, primitives do not emit
reason codes, so there was no emission to observe and the only thing left to
compare a declaration against was text.

The obvious repair is to move the check to where emissions actually happen --
`_step_typed_check_plugins`, where a real `PluginResult.reason_code` is in
scope. Two findings stopped that, both measured rather than argued:

1. RETRACTED -- THE VALUE IS NO LONGER INERT. This finding used to read "the
   value is inert": a probe plugin emitting ten different codes produced an
   IDENTICAL verdict map, because `_step_typed_check_plugins` wrote the
   literal "plugin_failed" over the plugin's code and kept only `detail`. The
   pin that recorded it said to re-open the question rather than edit the
   assertion if it ever failed. It failed, by design, when the discard was
   fixed: the ran-and-failed arm now propagates `PluginResult.reason_code`
   onto the verdict face verbatim. `test_the_boundary_propagates_the_plugins_-
   reason_code` below pins the NEW behaviour on all three arms, so neither the
   propagation nor the two deliberate generic arms can drift unnoticed.

   This retraction does NOT restore the case for moving the ratchet into the
   verifier -- finding 2 was always the load-bearing one and is untouched.

2. THE INPUTS ARE ALL VERIFIER-HELD. The emitted code is a literal in
   distribution or pilot code; the producer cannot influence it, and the
   bundle is not an input to this check at all. An all-VERIFIER check is
   internal consistency of the VERIFIER -- operator hygiene, not evidence
   about any bundle. Putting a row on the verdict face would say something
   about the bundle that this check does not know, and would appear on every
   bundle any such plugin ever verified. That is the same category error as
   the reverted kit check, one layer down. So the ratchet lives in tests/ and
   the shipped verifier is untouched by it.

SCOPE, stated so it is not over-read: this catches DRIFT -- an author
reintroducing a domain prefix -- and it is complete against that, because it
reads every string constant in the tree by AST rather than matching an
emission idiom. It is not an adversary control. Someone who wants to hide a
code can assemble it at runtime, and no static pass sees that. The threat here
is a colleague's habit, not an attacker, because every input is our own code.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from audit_bundle.plugin import PluginResult
from audit_bundle.rederivation.reason_codes import classify
from audit_bundle.verifier import BundleVerifier, PluginFailed

_REPO = pathlib.Path(__file__).resolve().parent.parent

#: WIDENED 2026-08-30 by the fresh-context pass. The first list was
#: ("examples", "audit_bundle", "veriker", "release", "tests") and a planted
#: `PluginResult(False, "ACME_REDERIVED", ...)` in `redteam/` was simply not
#: seen -- no trick, just the wrong directory. These six were live, populated,
#: and several of them already import PluginResult. A ratchet's blind spot does
#: not have to be clever to be a blind spot.
#:
#: `test_every_python_root_is_scanned` below keeps this honest: it fails when a
#: NEW top-level directory containing .py files appears and is neither scanned
#: nor deliberately listed as skipped.
_SCANNED_ROOTS = (
    "examples", "audit_bundle", "veriker", "release", "tests",
    "redteam", "redteam_streamB", "redteam_streamD", "scripts", "spikes",
    "receipts_site",
)

#: Top-level directories with .py files that are deliberately NOT scanned.
#: Empty today, and kept as an explicit seam so that skipping something later is
#: a decision someone writes down rather than an omission nobody notices.
_DELIBERATELY_UNSCANNED: frozenset[str] = frozenset()

#: The ONLY files allowed to contain a collapsible spelling, each because it is
#: definitionally about those spellings. Kept as a file set rather than
#: (file, code) pairs on purpose: adding a fixture to the vocabulary test is
#: routine and should not require editing this list, which is how allowlists
#: acquire the pressure that loosens them.
#:
#: `test_the_allowlist_has_not_rotted` controls the MISS direction -- an
#: allowlist entry that no longer needs to be here must be deleted, or the
#: entry silently becomes a blanket permission over a file that has since
#: grown real emitters.
_ALLOWED = {
    # The definition table itself. It CONTAINS the old spellings by
    # construction -- `_FAMILY_SUFFIXES` and `_BARE_ALIASES` are the mapping
    # FROM them -- and a tree-wide rewriter that does not exclude this file
    # rewrites the vocabulary out of the vocabulary module.
    "audit_bundle/rederivation/reason_codes.py",
    # Its test fixtures, which must state the old spellings to assert they
    # collapse.
    "tests/test_reason_code_vocabulary.py",
}


#: Sentinel key under which `_collapsible_by_file` records files it could not
#: parse, so a scan failure surfaces as a test failure instead of as coverage.
_UNPARSEABLE = "<unparseable>"


#: Never product source. A gitignored virtualenv under examples/ put thousands
#: of third-party modules in front of this walk: measured 2026-08-31, these
#: tests ran 34.3s with one present and 8.2s without, same verdict both times.
#: DIRECTORY components only -- a source file named `venv_setup.py` must still
#: be scanned. Held identical to the copies in release/reason_code_census.py and
#: tests/test_oss_release_boundary.py by tests/test_scan_prune_parity.py.
#: A directory IS a virtualenv when it is exactly `venv` or starts with the
#: dotted `.venv` (`.venv`, `.venv-py312`). Deliberately NOT a bare `venv`
#: prefix: that pruned `examples/venvoy/` in review, and over-pruning a guard's
#: walk is how the guard goes blind. Erring toward scanning is the safe
#: direction -- an unusually-named venv costs seconds, a pruned source file
#: costs coverage.
_VENV_DIR_EXACT = ("venv",)
_VENV_DIR_PREFIXES = (".venv",)


def _is_venv_dir(name: str) -> bool:
    return name in _VENV_DIR_EXACT or name.startswith(_VENV_DIR_PREFIXES)


def _in_pruned_dir(path) -> bool:
    return any(_is_venv_dir(part) for part in path.parts[:-1])


def _collapsible_by_file() -> dict[str, set[str]]:
    """Every string constant in the tree that `classify` maps, by file.

    By AST over every `ast.Constant`, NOT by matching `reason_code="LIT"`. The
    first census did it by regex on that idiom and was wrong by 19 codes: a
    code reaches a reader through a re-derivation script's stderr text, a
    positionally-passed helper argument, or a variable, just as surely as
    through the keyword -- and `audit_bundle/rederivation/dispatch.py` builds
    every one of its failures positionally.
    """
    found: dict[str, set[str]] = {}
    for root in _SCANNED_ROOTS:
        root_dir = _REPO / root
        if not root_dir.exists():
            continue
        for path in sorted(root_dir.rglob("*.py")):
            if _in_pruned_dir(path):
                continue
            rel = path.relative_to(_REPO).as_posix()
            try:
                tree = ast.parse(path.read_text(errors="ignore"))
            except (OSError, SyntaxError, ValueError) as exc:
                # NOT swallowed. A file the scanner cannot read is a file the
                # scanner cannot vouch for, and silently dropping it is how a
                # guard reports CLEAN over ground it never covered. Recorded
                # under a sentinel key that `test_no_unparseable_file_is_-
                # silently_skipped` asserts is empty.
                found.setdefault(_UNPARSEABLE, set()).add(f"{rel}: {exc!r}")
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and classify(node.value)
                ):
                    found.setdefault(rel, set()).add(node.value)
    return found


def test_no_collapsible_spelling_outside_the_allowlist():
    """THE RATCHET. 156 domain-prefixed spellings were collapsed onto four
    canonical codes; this is what stops the 157th."""
    offenders = {
        rel: sorted(codes)
        for rel, codes in _collapsible_by_file().items()
        if rel not in _ALLOWED and rel != _UNPARSEABLE
    }
    assert not offenders, (
        "domain-prefixed re-derivation spellings are back:\n"
        + "\n".join(f"  {rel}: {codes}" for rel, codes in sorted(offenders.items()))
        + "\nEmit one of the four canonical codes from "
        "audit_bundle/rederivation/reason_codes.py; the domain is carried by the "
        "check_name on the face. If the code names a condition the four "
        "cannot express, it is RETAINED -- make classify() return None for it "
        "and add the case to tests/test_reason_code_vocabulary.py."
    )


@pytest.mark.parametrize("rel", sorted(_ALLOWED))
def test_the_allowlist_has_not_rotted(rel):
    """MISS-DIRECTION CONTROL. An allowlisted file that no longer contains a
    collapsible spelling must leave the list. Otherwise the entry stops being
    an exemption for a known reason and becomes a permanent hole over whatever
    that file grows into next."""
    found = _collapsible_by_file()
    assert rel in found, (
        f"{rel} is allowlisted but contains no collapsible spelling any more. "
        f"Delete it from _ALLOWED -- a stale entry is a standing exemption."
    )


def test_the_ratchet_fires_on_a_planted_code(tmp_path, monkeypatch):
    """MUTANT CONTROL. A detector never shown a positive case is not evidence.

    Plant a plugin file emitting ACME_REDERIVED -- the exact shape the reverted
    kit check could be walked past -- and the scan must name it. Planted
    POSITIONALLY, because that is one of the four shapes the source-text reader
    was completely blind to, and because dispatch.py emits that way for real.
    """
    # Assembled from fragments that do NOT individually classify, so this file
    # does not itself trip the ratchet above and therefore does not need to be
    # allowlisted. A guard that exempts its own file is the shape that hides
    # things; there is no self-exemption here.
    planted = "ACME_" + "REDERIV" + "ED"
    assert classify(planted) is not None, "the planted code must be collapsible"
    root = tmp_path / "examples" / "planted_minimal"
    root.mkdir(parents=True)
    (root / "planted_check.py").write_text(
        "from audit_bundle.plugin import PluginFailed, PluginResult\n"
        "def check(bundle_dir, manifest):\n"
        f"    return PluginResult(False, {planted!r}, 'detail', ())\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tests.test_reason_code_emission_ratchet._REPO", tmp_path, raising=False
    )
    monkeypatch.setattr(
        "tests.test_reason_code_emission_ratchet._SCANNED_ROOTS",
        ("examples",),
        raising=False,
    )
    found = _collapsible_by_file()
    assert found == {"examples/planted_minimal/planted_check.py": {planted}}, (
        f"the ratchet did not see a planted positional emission: {found}"
    )


# --- the pin on why this file is not in verifier.py --------------------------


class _Probe:
    """A typed-check plugin whose only variable is the reason code it emits."""

    name = "probe"

    def __init__(self, code: str, ok: bool) -> None:
        self._code, self._ok = code, ok

    def check(self, bundle_dir, manifest):  # noqa: ANN001, ARG002
        return PluginResult(
            ok=self._ok, reason_code=self._code, detail="probe detail",
            files_audited=(),
        )


def _verdict_map(verdict) -> str:
    """The FULL observable face. 'Caught' is a verdict-map diff, never a
    keyword search -- a keyword list has reported caught mutants as missed."""
    return repr(
        (
            verdict.state.name,
            sorted(
                (f.check_name, f.reason_code, f.detail) for f in verdict.failures
            ),
            sorted(verdict.completeness.disclosures),
        )
    )


def _pin_bundle(tmp_path):
    """A minimal bundle whose manifest CLAIMS the typed check "probe", so the
    same fixture exercises the wired arms and the declared-but-unwired arm."""
    import hashlib
    import json

    bundle = tmp_path / "bundle"
    (bundle / "corpus").mkdir(parents=True)
    content = b"synthetic corpus entry"
    (bundle / "corpus" / "entry0.txt").write_bytes(content)
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "legacy",
                "bundle_id": "reason-code-boundary-pin",
                "created_at": "2026-01-01T00:00:00Z",
                "files": {"corpus/entry0.txt": hashlib.sha256(content).hexdigest()},
                "spec_files": {},
                "cross_refs": {},
                "payload": {},
                "typed_checks": ["probe"],
                "per_output_manifests": [],
            }
        ),
        encoding="utf-8",
    )
    return bundle


class _Exploder:
    """A plugin that raises PluginFailed -- the crash arm."""

    name = "probe"

    def check(self, bundle_dir, manifest):  # noqa: ANN001, ARG002
        raise PluginFailed("probe blew up")


@pytest.mark.parametrize("ok", [True, False])
def test_the_boundary_propagates_the_plugins_reason_code(tmp_path, ok):
    """MEASURED, and pinned so it cannot change unnoticed.

    REPLACES `test_the_boundary_discards_the_plugins_reason_code`, whose
    docstring said to re-open the question rather than edit its assertion when
    the discard was fixed. It was fixed; this is the re-opened answer.

    `_step_typed_check_plugins` has THREE failure arms and they are pinned
    separately, because they are deliberately not alike:

      * ran-and-DISAGREED -> the plugin's OWN reason_code reaches the face.
        This is the fix: a code a reader can act on, instead of a constant.
      * raised PluginFailed -> generic "plugin_failed". There is no result
        object to read a code from, so there is nothing to propagate.
      * declared-but-UNWIRED -> generic "plugin_failed". No plugin exists;
        keeping it generic is deliberate. A specific code here would be a
        claim about a check that never ran.

    On the ok=True arm no failure is emitted at all, so no code is observable
    -- that half is unchanged from the old pin and is asserted here too.
    """
    bundle = _pin_bundle(tmp_path)

    # NB the baseline code must NOT be success-class: a failing plugin
    # emitting RE_DERIVED now falls back to "plugin_failed" (see the
    # degenerate loop below), so using it here would compare two fallbacks and
    # the ok=False arm would silently stop testing propagation.
    baseline = _verdict_map(
        BundleVerifier(plugins=[_Probe("BASELINE_MISMATCH", ok)]).verify(bundle)
    )
    for code in ("ACME_" + "REDERIV" + "ED", "RE_DERIVATION_MISMATCH", "MADE_UP"):
        other = _verdict_map(
            BundleVerifier(plugins=[_Probe(code, ok)]).verify(bundle)
        )
        if ok:
            assert other == baseline, (
                f"a PASSING plugin's reason_code {code!r} moved the verdict map; "
                f"a passing check emits no failure, so no code should be observable"
            )
        else:
            assert other != baseline, (
                f"reason_code {code!r} no longer moves the verdict map (ok=False). "
                f"The boundary has gone back to discarding the plugin's code -- "
                f"re-open whether this ratchet belongs in the verifier."
            )

    if not ok:
        # the code is on the face VERBATIM, not merely "different"
        for code in ("RE_DERIVATION_MISMATCH", "CONFIDENCE_COVERAGE_GAP"):
            v = BundleVerifier(plugins=[_Probe(code, False)]).verify(bundle)
            assert code in {f.reason_code for f in v.failures}, (
                f"{code!r} did not reach the verdict face verbatim: "
                f"{[f.reason_code for f in v.failures]}"
            )
        # ...and a result that carries no usable code falls back to the
        # generic marker rather than printing a SUCCESS-class token as a
        # FAILURE's reason. Every axis below was measured passing STRAIGHT
        # THROUGH onto the face by a fresh-context red-team pass on 2026-08-31,
        # when this guard was a single `== "PASS"` equality: case, surrounding
        # whitespace, and the re-derivation vocabulary's own RE_DERIVED --
        # which reads "the recompute ran and AGREED" and was therefore printed
        # as the reason for a REJECT.
        for degenerate in (
            "", "PASS", "  PASS  ", "pass", "Pass", "PASS\n",
            "RE_DERIVED", "OK", "SUCCESS", "VERIFIED", "VALID",
        ):
            v = BundleVerifier(plugins=[_Probe(degenerate, False)]).verify(bundle)
            assert "plugin_failed" in {f.reason_code for f in v.failures}, (
                f"a failing plugin emitting {degenerate!r} must fall back to "
                f"plugin_failed; got {[f.reason_code for f in v.failures]}"
            )


def test_the_crash_arm_stays_generic(tmp_path):
    """A plugin that RAISES has no result object, so there is no code to
    propagate. Pinned so a later refactor cannot invent one."""
    bundle = _pin_bundle(tmp_path)
    v = BundleVerifier(plugins=[_Exploder()]).verify(bundle)
    codes = {f.reason_code for f in v.failures}
    assert "plugin_failed" in codes, codes


def test_the_declared_but_unwired_arm_stays_generic(tmp_path):
    """A manifest that CLAIMS a check no plugin implements fails closed under
    the same check_name a real failure uses. Keeping the code generic here is
    deliberate: a specific code would be a claim about a check that never ran,
    and it is what makes a check_name-only assertion a tautology (see
    `_check_ran_and_failed` in the pilot batteries -- assert on the detail's
    "reported failure" marker too)."""
    bundle = _pin_bundle(tmp_path)
    v = BundleVerifier(plugins=[]).verify(bundle)  # manifest claims "probe"
    unwired = [
        f for f in v.failures if f.check_name == "typed_check_plugins:probe"
    ]
    assert unwired, [f.check_name for f in v.failures]
    assert {f.reason_code for f in unwired} == {"plugin_failed"}, unwired


def test_no_unparseable_file_is_silently_skipped():
    """A file the scanner cannot parse is ground it did not cover.

    The first version of `_collapsible_by_file` did `except (OSError,
    SyntaxError, ValueError): continue`, so an unreadable file vanished from
    the scan and the ratchet reported CLEAN over it. The fresh-context pass
    planted a syntactically-broken file carrying a collapsible code and the
    ratchet stayed green. Failures are now recorded and asserted empty.
    """
    unparseable = sorted(_collapsible_by_file().get(_UNPARSEABLE, ()))
    assert not unparseable, (
        "the reason-code scan could not parse these files, so it cannot vouch "
        "for them:\n  " + "\n  ".join(unparseable)
    )


def test_every_python_root_is_scanned():
    """COVERAGE OF THE COVERAGE. A ratchet is only as wide as its root list.

    The first root list missed six live, populated directories -- `redteam/`,
    `scripts/`, `spikes/` and friends, several already importing PluginResult
    -- so a plain unadorned `PluginResult(False, "ACME_REDERIVED", ...)` in any
    of them was invisible. Nothing about that needed cleverness; it needed a
    directory nobody had listed. This test fails when a NEW top-level directory
    with .py files in it is neither scanned nor deliberately skipped, so the
    next one is a decision instead of an omission.
    """
    with_python = {
        entry.name
        for entry in _REPO.iterdir()
        if entry.is_dir()
        and not entry.name.startswith((".", "_"))
        and any(entry.rglob("*.py"))
    }
    unaccounted = with_python - set(_SCANNED_ROOTS) - _DELIBERATELY_UNSCANNED
    assert not unaccounted, (
        f"top-level directories containing .py files that the reason-code "
        f"ratchet neither scans nor deliberately skips: {sorted(unaccounted)}. "
        f"Add each to _SCANNED_ROOTS, or to _DELIBERATELY_UNSCANNED with a "
        f"reason."
    )
