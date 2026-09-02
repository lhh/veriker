"""Round-trip integration test for examples/build_minimal/verify.py.

Test flow:
  1. Build a clean bundle from the synthetic sources + recipe into a temp dir.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test (re-derivation): keep source SHA aligned with manifest by
     mutating the bundled artifact bytes instead — file_integrity catches
     that, so to isolate the RE_DERIVATION_MISMATCH path we tamper a
     source file AND update its manifest SHA so file_integrity passes;
     then build_re_derivation sees the divergence.
  5. Tamper test (file integrity): mutate a source file in place without
     manifest update — file_integrity_many_small catches the SHA mismatch.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "build_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.build_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from BuildReDerivationCheck import BuildReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        FileIntegrityManySmall(),
        BuildReDerivationCheck(),
    ])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "build_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_source_no_manifest_update_fails_file_integrity(tmp_path: Path) -> None:
    """Mutating a source file in place must trigger file_integrity SHA mismatch."""
    bundle_dir = tmp_path / "build_bundle_tamper_a"
    build(bundle_dir)

    # Mutate sources/a.txt without updating the manifest entry.
    src = bundle_dir / "sources" / "a.txt"
    src.write_bytes(b"tampered alpha source\n")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating sources/a.txt without manifest update"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    # FileIntegrityManySmall fires a SHA-mismatch reason code; accept any of
    # the conventional spellings used by the substrate plugin.
    assert (
        "SHA" in combined or "INTEGRITY" in combined or "FILE_HASH" in combined
    ), f"expected file-integrity SHA-mismatch failure; got: {result.failures}"


def test_tamper_source_with_aligned_manifest_fails_re_derivation(tmp_path: Path) -> None:
    """Mutating source AND updating the manifest SHA isolates the RE_DERIVATION_MISMATCH path.

    Without the manifest update, file_integrity catches the tamper first
    (covered by the previous test). To exercise build_re_derivation, we
    re-align manifest.files["sources/a.txt"] to the tampered SHA so file
    integrity passes; the recipe then re-executes against the tampered source
    and produces a gzip artifact with different bytes than the bundled one.
    """
    bundle_dir = tmp_path / "build_bundle_tamper_b"
    build(bundle_dir)

    src = bundle_dir / "sources" / "a.txt"
    tampered = b"tampered alpha source\nextra line\n"
    src.write_bytes(tampered)

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["sources/a.txt"] = _sha256(tampered)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False once the recipe re-execution diverges from bundled artifact"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BUILD_REDERIV" in combined or "BUILD_REDER_FAIL" in combined, (
        f"expected RE_DERIVATION_MISMATCH or BUILD_REDER_FAIL; got: {result.failures}"
    )

# ---------------------------------------------------------------------------
# Claimset coverage — opaque (whole-file) artifact claims (port 2b)
# ---------------------------------------------------------------------------


def test_build_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its artifact claim(s) as opaque_claim_files: the
    verdict carries the coverage receipt (1 whole-file element(s), all
    covered, none withheld), and dropping the re-derivation plugin turns the
    formerly-silent scope gap into could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "bundle"
    build(bundle_dir)

    verdict = _make_verifier().verify(bundle_dir)
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert len(lines) == 1, verdict.completeness.disclosures
    assert "n_universe=1 n_covered=1(self-reported) n_withheld=0" in lines[0]
    assert lines[0].endswith("n_opaque=1")

    bare = BundleVerifier(plugins=[FileIntegrityManySmall()]).verify(bundle_dir)
    assert bare.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "1 of 1" in r.detail
        for r in bare.reasons
    ), [(r.code, r.detail) for r in bare.reasons]


def test_build_minimal_claimset_ratchet_all_artifacts_flip(tmp_path: Path) -> None:
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
    assert {o.element for o in report.flipped} == {'artifact'}
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
        assert any("BUILD_REDER_FAIL" in d and "byte mismatch" in d for _, d in outcome.reasons), outcome.reasons


def test_build_minimal_toolchain_absent_is_could_not_conclude_not_green(
    tmp_path: Path, monkeypatch
) -> None:
    """P6 (port-2b scoping): an environment where the re-derivation pack
    cannot run must refuse to conclude (clean-ERROR, exit 2 — NOT a REJECT),
    and the claimset gate must name the artifact. Simulated by hiding the pack
    file from the plugin without touching any pinned bundle byte.

    TWO independent layers now refuse, and the tail of this test pins the
    second. The claimset declaration is the first: the early-out reports no
    coverage, so the gate names the uncovered 'artifact' field. The plugin's
    own NO_PACK early-out is the second: it returned ok=True until
    2026-08-31, so with the declaration removed this very environment
    verified GREEN — an absence of checking read as OK. That early-out now
    returns incomplete=True, so the refusal no longer depends on the pilot
    having adopted a claimset."""
    from audit_bundle.verdict import VerdictState

    bundle_dir = tmp_path / "bundle"
    build(bundle_dir)
    real_exists = Path.exists

    def _no_pack(self):
        if self.name == "build_re_derivation.py":
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", _no_pack)
    verdict = _make_verifier().verify(bundle_dir)
    assert verdict.state is VerdictState.ERROR, (
        verdict.state,
        [(r.code, r.detail[:120]) for r in verdict.reasons],
    )
    assert any(
        r.check_name == "claimset_coverage" and "'artifact'" in r.detail
        for r in verdict.reasons
    ), [(r.code, r.detail[:120]) for r in verdict.reasons]
    # Layer two, measured with layer one removed: strip the claimset
    # declaration and the same environment must STILL refuse. Before
    # 2026-08-31 this line read `.ok is True` — that green was the silent
    # fail-open P6 names, and it is what the incomplete=True conversion
    # closed. Naming the leg keeps this from passing for the wrong reason:
    # the refusal has to come from the PLUGIN, not from a residual
    # claimset_coverage reason the pop failed to remove.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m.pop("claimset")
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
    undeclared = _make_verifier().verify(bundle_dir)
    assert undeclared.state is VerdictState.ERROR, (
        undeclared.state,
        [(r.code, r.detail[:120]) for r in undeclared.reasons],
    )
    assert not any(
        r.check_name == "claimset_coverage" for r in undeclared.reasons
    ), "claimset leg survived the pop — layer two is not what is being measured"
    # NB the incomplete leg carries the plugin's DETAIL but drops its
    # reason_code (verifier.py builds "plugin <id> could not conclude: <detail>"),
    # so NO_PACK itself is not assertable here — match the detail instead.
    assert any(
        r.code == "VERIFIER_INCOMPLETE"
        and r.check_name == "typed_check_plugins:build_re_derivation"
        and "build_re_derivation.py not found" in r.detail
        for r in undeclared.reasons
    ), [(r.code, r.check_name, r.detail[:160]) for r in undeclared.reasons]
