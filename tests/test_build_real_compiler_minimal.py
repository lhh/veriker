"""Round-trip integration test for examples/build_real_compiler_minimal.

Test flow:
  1. Build a clean bundle from the synthetic Python sources into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True (ROUND-TRIP test).
  4. PRIMARY TAMPER: mutate sources/mod_a.py content; re-align its SHA in
     manifest.files so FileIntegrityManySmall passes; assert
     RE_DERIVATION_MISMATCH (the re-derived .pyc differs from bundled).
  5. BONUS TAMPER: mutate recipe cache_tag to a fake value that does not match
     runtime; re-align recipe SHA; assert BUILD_PY_TOOLCHAIN_MISMATCH.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "build_real_compiler_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Imports (after sys.path setup)
# ---------------------------------------------------------------------------

from examples.build_real_compiler_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from BuildPyReDerivationCheck import BuildPyReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        FileIntegrityManySmall(),
        BuildPyReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# ROUND-TRIP — build + verify on a clean bundle
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """Build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "brc_bundle"
    build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, (
        "expected ok=True; failures: "
        + ", ".join(
            f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures
        )
    )


# ---------------------------------------------------------------------------
# PRIMARY TAMPER — mutate sources/mod_a.py content
#
# Re-aligns the mod_a.py SHA in manifest.files so FileIntegrityManySmall
# passes.  The bundled mod_a.pyc was compiled from the original source;
# re-compiling from the mutated source produces different .pyc bytes.
# BuildPyReDerivationCheck catches this exclusively.
# ---------------------------------------------------------------------------


def test_tamper_source_fails_rederivation(tmp_path: Path) -> None:
    """Mutating sources/mod_a.py must trigger RE_DERIVATION_MISMATCH.

    The bundled mod_a.pyc encodes the original source bytes. After the mutation,
    re-compiling with py_compile yields different .pyc bytes (different source
    hash in the CHECKED_HASH header). The SHA in manifest.files is re-aligned
    so file_integrity_many_small passes and the re-derivation plugin is the
    exclusive failure path.
    """
    bundle_dir = tmp_path / "brc_bundle_tamper"
    build(bundle_dir)

    # Mutate: append a constant to mod_a.py
    mod_a_path = bundle_dir / "sources" / "mod_a.py"
    original = mod_a_path.read_bytes()
    mutated = original + b"\n# tampered line\nEXTRA_CONSTANT = 9999\n"
    mod_a_path.write_bytes(mutated)

    # Re-align manifest SHA so FileIntegrityManySmall does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["sources/mod_a.py"] = _sha256(mutated)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after mutating sources/mod_a.py"
    )
    # Accept RE_DERIVATION_MISMATCH or BUILD_PY_REDER substring in combined output
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BUILD_PY_REDER" in combined, (
        f"expected BUILD_PY_REDER or RE_DERIVATION_MISMATCH in failures; "
        f"got: {result.failures}"
    )


# ---------------------------------------------------------------------------
# BONUS TAMPER — toolchain mismatch via fake cache_tag
#
# Mutates the recipe's declared cache_tag to a value that cannot match any
# real runtime (fake-cache-tag-3000).  Re-aligns the recipe SHA so
# FileIntegrityManySmall passes.  BuildPyReDerivationCheck should fire with
# BUILD_PY_TOOLCHAIN_MISMATCH before even attempting re-compilation.
# ---------------------------------------------------------------------------


def test_tamper_cache_tag_fails_toolchain_mismatch(tmp_path: Path) -> None:
    """Faking recipe.cache_tag must trigger BUILD_PY_TOOLCHAIN_MISMATCH.

    The verifier checks cache_tag first, before compiling anything.  A
    mismatch exits early with BUILD_PY_TOOLCHAIN_MISMATCH so the caller
    knows they have the wrong interpreter version, not a source drift.
    """
    bundle_dir = tmp_path / "brc_bundle_toolchain"
    build(bundle_dir)

    # Mutate recipe: replace cache_tag with a fake value
    recipe_path = bundle_dir / "recipe" / "build_recipe.json"
    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    recipe["cache_tag"] = "fake-cache-tag-3000"
    recipe_bytes = json.dumps(recipe, indent=2, sort_keys=True).encode("utf-8")
    recipe_path.write_bytes(recipe_bytes)

    # Re-align manifest SHA for recipe/build_recipe.json
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["recipe/build_recipe.json"] = _sha256(recipe_bytes)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after faking recipe.cache_tag"
    )
    # Accept BUILD_PY_TOOLCHAIN_MISMATCH or BUILD_PY_REDER substring in combined output
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BUILD_PY_TOOLCHAIN_MISMATCH" in combined or "BUILD_PY_REDER" in combined, (
        f"expected BUILD_PY_TOOLCHAIN_MISMATCH or BUILD_PY_REDER in failures; "
        f"got: {result.failures}"
    )

# ---------------------------------------------------------------------------
# Claimset coverage — opaque (whole-file) artifact claims (port 2b)
# ---------------------------------------------------------------------------


def test_build_real_compiler_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its artifact claim(s) as opaque_claim_files: the
    verdict carries the coverage receipt (3 whole-file element(s), all
    covered, none withheld), and dropping the re-derivation plugin turns the
    formerly-silent scope gap into could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "bundle"
    build(bundle_dir)

    verdict = _make_verifier().verify(bundle_dir)
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert len(lines) == 1, verdict.completeness.disclosures
    assert "n_universe=3 n_covered=3(self-reported) n_withheld=0" in lines[0]
    assert lines[0].endswith("n_opaque=3")

    bare = BundleVerifier(plugins=[FileIntegrityManySmall()]).verify(bundle_dir)
    assert bare.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "3 of 3" in r.detail
        for r in bare.reasons
    ), [(r.code, r.detail) for r in bare.reasons]


def test_build_real_compiler_minimal_claimset_ratchet_all_artifacts_flip(tmp_path: Path) -> None:
    """Evidence-grade leg (registered prediction P2/P3 of the port-2b
    scoping): every declared probe of every opaque artifact — first, middle
    and last byte, truncation, extension — flips the verdict via the pilot's
    own comparator: never via file-sha, never at byte 0 alone (a format
    sniff), never by length-blindness."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle_dir = tmp_path / "bundle"
    build(bundle_dir)
    report = run_claimset_ratchet(
        bundle_dir,
        _make_verifier,
        tmp_path / "ratchet_scratch",
        # Deny-by-default scoring: name the code THIS pilot's comparator
        # emits when it refuses a value, so a flip caused by anything else
        # (a crash, an unwired check, a timeout, a code nobody classified)
        # scores INCONCLUSIVE instead of being credited as coverage.
        comparator_codes={"RE_DERIVATION_MISMATCH"},
    )
    assert report.baseline_state == "OK"
    assert not report.survived, [(o.element, o.detail) for o in report.survived]
    assert not report.inconclusive, [(o.element, o.detail) for o in report.inconclusive]
    assert not report.skipped
    assert {o.element for o in report.flipped} == {'mod_a', 'mod_b', 'mod_c'}
    for outcome in report.flipped:
        assert dict(outcome.positions) == {
            "first": "FLIPPED",
            "middle": "FLIPPED",
            "last": "FLIPPED",
            "truncate": "FLIPPED",
            "append": "FLIPPED",
        }, outcome.positions
        assert "BAD_FILE_SHA" not in outcome.reason_codes
        # the pilot's OWN comparator refused it — the pack's COMPARISON
        # discriminant is in the verdict detail (the failure tag alone is
        # shared by environment errors), not merely "some non-plumbing code"
        assert any("BUILD_PY_REDER_FAIL" in d and "RE_DERIVATION_MISMATCH for" in d for _, d in outcome.reasons), outcome.reasons

