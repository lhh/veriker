"""Round-trip integration test for examples/hyperframes_render_minimal/verify.py.

Test flow:
  1. Build a clean bundle by rendering the fixture composition.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True (ROUND-TRIP test).
  4. PRIMARY TAMPER: mutate source/index.html (replace the title string);
     re-align its SHA in manifest.files so FileIntegrityManySmall passes;
     assert RE_DERIVATION_MISMATCH because the re-rendered MP4 sha
     differs from the committed sha.
  5. SPEC TAMPER: append whitespace to spec/tooling.json without realigning
     manifest.spec_files; assert SPEC_SHA_MISMATCH from SpecShaPinCheck.

Skipped when node ≥ 22 or ffmpeg is not on PATH — the re-derivation pack
needs them to actually re-render. Sketch pilot, third-party tooling
dependency by design.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "hyperframes_render_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Tool-availability gate — skip module if external tools missing
# ---------------------------------------------------------------------------


def _have_tool(cmd: list[str]) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_HAVE_NODE = _have_tool(["node", "--version"])
_HAVE_FFMPEG = _have_tool(["ffmpeg", "-version"])
_HAVE_NPX = _have_tool(["npx", "--version"])

# QUARANTINED as `heavy_pilot` (Max, 2026-09-05) — deselected by default,
# INCLUDING at landing; opt back in with
#   pytest --run-heavy-pilots tests/test_hyperframes_render_minimal.py -m ""
#
# Two reasons, and the second is the load-bearing one:
#
#   1. COST. All six tests call `_fresh_bundle()`, i.e. a full
#      `npx hyperframes render` each — six node+ffmpeg renders per suite run.
#
#   2. IT CANNOT CURRENTLY PASS, and quarantine does NOT fix that. The pilot
#      shells out to `npx hyperframes@latest`, so the renderer updates
#      underneath a test that compares the rendered MP4 against a COMMITTED
#      sha. Measured on master 2026-09-05 (a clean `master` worktree, nothing
#      of ours merged): 3 of 6 RED with
#      `RE_DERIVATION_MISMATCH: re-derived 62b0529a..., committed 1f1683bb...`.
#      This would have gone red on its own schedule. The real fix is to pin a
#      hyperframes version or stop byte-comparing the render; until one of
#      those happens the pilot is unpinnable, and this marker only stops it
#      breaking the landing gate for every other branch.
#
# The file-level mark is honest ONLY because every test here genuinely needs
# the render — no cheap static check is being silently retired with it. Check
# that again before widening this marker to another file.
pytestmark = [
    pytest.mark.heavy_pilot,
    pytest.mark.skipif(
        not (_HAVE_NODE and _HAVE_FFMPEG and _HAVE_NPX),
        reason="hyperframes_render_minimal needs node, npx, and ffmpeg on PATH",
    ),
]


# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.hyperframes_render_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from HyperFramesReDerivationCheck import HyperFramesReDerivationCheck  # noqa: E402


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        HyperFramesReDerivationCheck(),
    ])


# One render per module (2026-08-20). Every test needs a clean bundle and each
# `build()` is a full `npx hyperframes render` (~5-7s); the render is
# deterministic (identical output_mp4_sha across builds) and the bundle is
# self-contained (a copied bundle verifies clean), so build once and copy.
# Verifies still re-render — that IS the re-derivation under test and is
# untouched; this only removes the five redundant producer-side renders
# (~30s of the file's ~118s solo; the file was the landing run's last worker).
_CLEAN_BUILD: Path | None = None


@pytest.fixture(scope="module", autouse=True)
def _build_once(tmp_path_factory: pytest.TempPathFactory):
    global _CLEAN_BUILD
    _CLEAN_BUILD = tmp_path_factory.mktemp("hf_clean") / "bundle"
    build(_CLEAN_BUILD)
    yield
    _CLEAN_BUILD = None


def _fresh_bundle(bundle_dir: Path) -> Path:
    """A pristine copy of the module's one clean build, at bundle_dir."""
    assert _CLEAN_BUILD is not None, "module build fixture did not run"
    shutil.copytree(_CLEAN_BUILD, bundle_dir)
    return bundle_dir


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "hf_bundle"
    _fresh_bundle(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_index_html_fails_rederivation(tmp_path: Path) -> None:
    """Mutating source/index.html with SHA-realignment must trigger
    RE_DERIVATION_MISMATCH.

    The fixture title 'V-Kernel + HyperFrames' is replaced with
    'V-Kernel and HyperFrames'. File integrity SHA is re-aligned so
    FileIntegrityManySmall does not fire first. Re-derivation re-renders
    from the mutated HTML, producing a different MP4 (different text →
    different pixel bytes → different sha256), and the bundled
    payload/output.mp4 (still from the original HTML) no longer matches.
    """
    bundle_dir = tmp_path / "hf_bundle_html_tamper"
    _fresh_bundle(bundle_dir)

    # Tamper: edit source/index.html
    index_path = bundle_dir / "source" / "index.html"
    text = index_path.read_text(encoding="utf-8")
    mutated = text.replace("V-Kernel + HyperFrames", "V-Kernel and HyperFrames")
    assert mutated != text, "fixture title string not found — test fixture drift"
    index_path.write_text(mutated, encoding="utf-8")

    # Re-align manifest SHA so file_integrity_many_small does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["source/index.html"] = _sha256_file(index_path)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after mutating source/index.html"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "RE_DERIVATION_MISMATCH" in combined, (
        f"expected RE_DERIVATION_MISMATCH in failures; "
        f"got: {result.failures}"
    )


def test_tamper_tooling_spec_fails_spec_sha(tmp_path: Path) -> None:
    """Appending whitespace to spec/tooling.json without realigning
    manifest.spec_files must trigger a spec-SHA failure from SpecShaPinCheck.

    json.loads ignores trailing whitespace so the parsed spec is unchanged
    and re-derivation could still succeed — but the bundle's integrity
    contract requires manifest-pinned SHAs to match on-disk bytes exactly.
    """
    bundle_dir = tmp_path / "hf_bundle_spec_tamper"
    _fresh_bundle(bundle_dir)

    spec_path = bundle_dir / "spec" / "tooling.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after appending whitespace to spec/tooling.json"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), (
        f"expected spec-SHA-mismatch indicator in failures; "
        f"got: {result.failures}"
    )

# ---------------------------------------------------------------------------
# Claimset coverage — opaque (whole-file) artifact claims (port 2b)
# ---------------------------------------------------------------------------


def test_hyperframes_render_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its artifact claim(s) as opaque_claim_files: the
    verdict carries the coverage receipt (1 whole-file element(s), all
    covered, none withheld), and dropping the re-derivation plugin turns the
    formerly-silent scope gap into could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "bundle"
    _fresh_bundle(bundle_dir)

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


def test_hyperframes_render_minimal_claimset_ratchet_all_artifacts_flip(tmp_path: Path) -> None:
    """Evidence-grade leg (registered prediction P2/P3 of the port-2b
    scoping): every declared probe of every opaque artifact — first, middle
    and last byte, truncation, extension — flips the verdict via the pilot's
    own comparator: never via file-sha, never at byte 0 alone (a format
    sniff), never by length-blindness."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle_dir = tmp_path / "bundle"
    _fresh_bundle(bundle_dir)
    def _repin_committed_digest(copy_dir: Path) -> None:
        """What a producer legitimately re-pins on their own bundle: the
        committed digest of the artifact they ship. With this hook the only
        thing left to catch a tampered delivery is the RE-RENDER comparing
        against the bundled bytes — a digest pin alone would be credited
        otherwise (process-lens finding 3)."""
        from claimset_ratchet import write_manifest_canonical  # noqa: E402

        mp = copy_dir / "manifest.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["payload"]["output_mp4_sha256"] = hashlib.sha256(
            (copy_dir / "payload" / "output.mp4").read_bytes()
        ).hexdigest()
        write_manifest_canonical(copy_dir, m)

    report = run_claimset_ratchet(
        bundle_dir,
        _make_verifier,
        tmp_path / "ratchet_scratch",
        repin=_repin_committed_digest,
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
    assert {o.element for o in report.flipped} == {'output'}
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
        # either render-derived discriminant (committed != re-derived, or
        # bundled != re-rendered) — both exist only AFTER a render ran;
        # toolchain / timeout failures carry neither
        assert any(
            "HYPERFRAMES_REDER_FAIL" in d
            and ("re-derived sha" in d or "re-rendered sha" in d)
            for _, d in outcome.reasons
        ), outcome.reasons


def test_tamper_bundled_mp4_with_repinned_manifest_fails(tmp_path: Path) -> None:
    """The executed P3 witness: flip one byte in the DELIVERED MP4 and re-pin
    everything a producer legitimately re-pins — its manifest.files sha AND
    the committed digest in manifest.payload. Before the pack bound the
    bundled artifact this verified green; now the RE-RENDER refuses it (a
    digest pin the producer controls cannot be the thing that catches it)."""
    bundle_dir = tmp_path / "bundle"
    _fresh_bundle(bundle_dir)
    mp4 = bundle_dir / "payload" / "output.mp4"
    raw = bytearray(mp4.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    mp4.write_bytes(bytes(raw))
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m["files"]["payload/output.mp4"] = hashlib.sha256(bytes(raw)).hexdigest()
    # the producer also re-pins the committed digest they control — the
    # render is what must catch the tampered delivery
    m["payload"]["output_mp4_sha256"] = hashlib.sha256(bytes(raw)).hexdigest()
    mp.write_text(json.dumps(m, indent=2), encoding="utf-8")

    verdict = _make_verifier().verify(bundle_dir)
    assert verdict.ok is False
    assert any(
        "RE_DERIVATION_MISMATCH" in (r.detail or "")
        and ("re-derived sha" in (r.detail or "") or "re-rendered sha" in (r.detail or ""))
        for r in verdict.reasons
    ), [(r.code, r.detail[:160]) for r in verdict.reasons]

