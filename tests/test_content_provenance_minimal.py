"""Round-trip integration test for examples/content_provenance_minimal/verify.py.

Test flow:
  1. Build a clean bundle via _build_bundle.py into a temp directory.
  2. Run verify.py via subprocess from a separate cwd (clean working dir).
  3. Assert exit 0 and 'PASS' in stdout.
  4. Tamper the content file on disk (flip one byte).
  5. Re-run verify.py.
  6. Assert exit 1 and CONTENT_PROVENANCE_ALTERED or BAD_FILE_SHA in stderr.

SCOPE BOUNDARY TEST:
  test_false_content_passes_provenance_check — an artifact with a factually false
  claim but unaltered, correctly-signed bytes PASSES (result.ok is True).
  This is correct by design: the check is provenance, not truth.

The bundle is constructed from _build_bundle.py so the test exercises the full
production build path.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_BUILD_PY = _PKG_ROOT / "examples" / "content_provenance_minimal" / "_build_bundle.py"
_VERIFY_PY = _PKG_ROOT / "examples" / "content_provenance_minimal" / "verify.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_bundle(out_dir: Path) -> subprocess.CompletedProcess:
    """Run _build_bundle.py to generate a clean bundle into out_dir."""
    return subprocess.run(
        [sys.executable, str(_BUILD_PY), "--out-dir", str(out_dir)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _run_verify(
    bundle_dir: Path, cwd: Path | None = None
) -> subprocess.CompletedProcess:
    """Invoke verify.py as a subprocess from cwd (defaults to bundle_dir.parent)."""
    effective_cwd = cwd if cwd is not None else bundle_dir.parent
    return subprocess.run(
        [sys.executable, str(_VERIFY_PY), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        text=True,
        cwd=str(effective_cwd),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Bundle built once per module from _build_bundle.py; must not be mutated."""
    dest = tmp_path_factory.mktemp("content_prov_clean_bundle")
    result = _build_bundle(dest)
    assert result.returncode == 0, (
        f"_build_bundle.py failed (exit {result.returncode})\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    return dest


@pytest.fixture
def tampered_content_bundle(tmp_path: Path) -> Path:
    """Fresh bundle with the content file's first byte flipped."""
    bundle = tmp_path / "bundle"
    result = _build_bundle(bundle)
    assert result.returncode == 0, (
        f"_build_bundle.py failed while setting up tamper fixture\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    content_path = bundle / "artifact" / "content.txt"
    original = bytearray(content_path.read_bytes())
    original[0] = (original[0] + 1) % 256  # flip one byte
    content_path.write_bytes(bytes(original))
    return bundle


# ---------------------------------------------------------------------------
# Happy-path: clean bundle
# ---------------------------------------------------------------------------


def test_clean_bundle_build_exits_zero(tmp_path: Path) -> None:
    """_build_bundle.py must exit 0 for a fresh build."""
    result = _build_bundle(tmp_path / "bundle")
    assert result.returncode == 0, (
        f"expected exit 0; got {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )


def test_clean_bundle_verify_exits_zero(clean_bundle: Path, tmp_path: Path) -> None:
    """verify.py must exit 0 for an untampered bundle."""
    proc = _run_verify(clean_bundle, cwd=tmp_path)
    assert proc.returncode == 0, (
        f"expected exit 0; got {proc.returncode}\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_clean_bundle_prints_pass(clean_bundle: Path, tmp_path: Path) -> None:
    """'PASS' must appear in stdout for a clean bundle."""
    proc = _run_verify(clean_bundle, cwd=tmp_path)
    assert "PASS" in proc.stdout, (
        f"expected 'PASS' in stdout; got: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_clean_bundle_has_expected_files(clean_bundle: Path) -> None:
    """Bundle must contain the three committed files."""
    assert (clean_bundle / "artifact" / "content.txt").exists()
    assert (clean_bundle / "artifact" / "provenance.json").exists()
    assert (clean_bundle / "payload" / "provenance_result.json").exists()
    assert (clean_bundle / "manifest.json").exists()


def test_clean_bundle_payload_fields(clean_bundle: Path) -> None:
    """payload/provenance_result.json must have the required fields."""
    payload = json.loads(
        (clean_bundle / "payload" / "provenance_result.json").read_bytes()
    )
    assert "content_sha" in payload
    assert "provenance_sha" in payload
    assert "producer_id" in payload
    assert "generation_inputs" in payload
    assert "producer_hmac" in payload
    assert "provenance_status" in payload
    assert payload["provenance_status"] == "CONTENT_PROVENANCE_VERIFIED"
    assert payload["producer_hmac"].startswith("hmac-sha256:")


def test_clean_bundle_provenance_manifest_fields(clean_bundle: Path) -> None:
    """artifact/provenance.json must have required provenance manifest fields."""
    manifest = json.loads((clean_bundle / "artifact" / "provenance.json").read_bytes())
    assert manifest["schema"] == "content-provenance-v1"
    assert "producer_id" in manifest
    assert "content_sha" in manifest
    assert "generation_inputs" in manifest
    assert "producer_hmac" in manifest
    assert manifest["producer_hmac"].startswith("hmac-sha256:")


# ---------------------------------------------------------------------------
# SCOPE BOUNDARY TEST — false content passes (by design)
# ---------------------------------------------------------------------------


def test_false_content_passes_provenance_check(tmp_path: Path) -> None:
    """SCOPE BOUNDARY: A factually false but unaltered, correctly-signed artifact PASSES.

    This is the explicit scope-boundary test.  The synthetic news article in the
    bundle contains a fabricated claim ("Scientists Announce Breakthrough...").
    The content is factually false, but the bytes are unaltered since producer signing
    and the HMAC is valid.  The provenance check MUST return result.ok is True.

    This documents that the check is provenance, not truth.  A false article signed
    by its AI producer PASSES — that is by design and out of scope of this substrate.

    The content_sha matches, the producer_hmac is valid, the provenance chain is
    intact.  The verifier has no knowledge of factual accuracy — that is a separate
    domain-specific concern requiring a fact-checking layer.
    """
    # Add the pilot and pkg root to sys.path for the Python API call
    sys.path.insert(0, str(_PKG_ROOT))
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))

    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier
    from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck

    # Build a clean bundle — the article is factually fabricated (see _build_bundle.py)
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, (
        f"_build_bundle.py failed in scope-boundary test\n"
        f"stdout: {r.stdout!r}\nstderr: {r.stderr!r}"
    )

    # Confirm the content contains the fabricated claim (it's a false statement)
    content = (bundle / "artifact" / "content.txt").read_bytes().decode("utf-8")
    assert (
        "battery" in content.lower()
        or "breakthrough" in content.lower()
        or "synthetic" in content.lower()
    ), "Expected fabricated battery/breakthrough claim in synthetic content"
    # The note in the article itself declares it's fabricated
    assert (
        "SYNTHETIC" in content
        or "fabricated" in content.lower()
        or "demo" in content.lower()
    ), "Expected demo/synthetic disclaimer in content"

    # Verify via Python API — MUST PASS despite the false claim
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall(), ContentProvenanceReDerivationCheck()]
    )
    result = verifier.verify(bundle)

    # THIS ASSERTION IS THE SCOPE BOUNDARY:
    # A factually false but unaltered, correctly-signed content artifact PASSES.
    # The verifier proves provenance, not truth.
    assert result.ok is True, (
        "SCOPE BOUNDARY FAILED: Expected result.ok is True for a false-but-unaltered "
        "correctly-signed artifact.  The provenance check must PASS for unaltered content "
        "regardless of factual accuracy — truth-detection is out of scope.\n"
        f"Failures: {result.failures!r}"
    )


# ---------------------------------------------------------------------------
# Tamper path: content file byte flipped
# ---------------------------------------------------------------------------


def test_tampered_content_exits_one(tampered_content_bundle: Path) -> None:
    """verify.py must exit 1 when the content file is modified on disk."""
    proc = _run_verify(tampered_content_bundle)
    assert proc.returncode == 1, (
        f"expected exit 1; got {proc.returncode}\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_tampered_content_does_not_print_pass(tampered_content_bundle: Path) -> None:
    """'PASS' must not appear in stdout for a tampered bundle."""
    proc = _run_verify(tampered_content_bundle)
    assert "PASS" not in proc.stdout, (
        f"'PASS' must not appear in stdout for a tampered bundle; got: {proc.stdout!r}"
    )


def test_tampered_content_reports_mismatch_reason(
    tampered_content_bundle: Path,
) -> None:
    """stderr must include either BAD_FILE_SHA or CONTENT_PROVENANCE_ALTERED for a tampered file.

    FileIntegrityManySmall (pass-2) emits BAD_FILE_SHA when the content hash
    no longer matches the manifest.  ContentProvenanceReDerivationCheck emits
    CONTENT_PROVENANCE_ALTERED when the SHA or HMAC does not match.
    Either or both may appear.
    """
    proc = _run_verify(tampered_content_bundle)
    combined = (proc.stdout + proc.stderr).upper()
    assert "BAD_FILE_SHA" in combined or "CONTENT_PROVENANCE_ALTERED" in combined, (
        f"expected BAD_FILE_SHA or CONTENT_PROVENANCE_ALTERED in output;\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_forged_payload_hmac_honest_manifest_sha_fails(tmp_path: Path) -> None:
    """FIX-E — strongest producer: forge ONLY payload's producer_hmac claim,
    re-sha manifest.files to match, leave artifact/provenance.json honest.

    This is the confirmed defect this fix closes: content_provenance_re_derivation.py
    used to extract payload/provenance_result.json's own `producer_hmac` field
    (`committed_producer_hmac`) and never reference it again — the only HMAC
    comparison ran against artifact/provenance.json's producer_hmac, a DIFFERENT
    committed file. A producer could replace the payload's own signature claim
    with any garbage string and the bundle still PASSed.

    The attack modeled here is the strongest version: the producer also
    re-computes payload/provenance_result.json's own SHA-256 and rewrites
    manifest.json's files[] entry to match the forged bytes, so
    file_integrity_many_small's per-file SHA walk sees a self-consistent bundle
    and does NOT flag BAD_FILE_SHA. artifact/provenance.json (and its own
    producer_hmac field) is left completely untouched and honest. The ONLY
    thing wrong with this bundle is the payload's own producer_hmac claim.

    Must FAIL closed with CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH — and
    file_integrity_many_small must NOT be the plugin that catches it (proving
    the new check, not the pre-existing SHA walk, is what closes the gap).
    """
    sys.path.insert(0, str(_PKG_ROOT))
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))

    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier
    from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck

    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, (
        f"_build_bundle.py failed while setting up forged-hmac fixture\n"
        f"stdout: {r.stdout!r}\nstderr: {r.stderr!r}"
    )

    # --- Forge ONLY the payload's own producer_hmac claim. ---
    payload_path = bundle / "payload" / "provenance_result.json"
    payload = json.loads(payload_path.read_bytes())
    real_payload_hmac = payload["producer_hmac"]
    forged_hmac = "hmac-sha256:" + ("0" * 64)
    assert forged_hmac != real_payload_hmac, "forged hmac must differ from the real one"
    payload["producer_hmac"] = forged_hmac
    payload_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    payload_path.write_bytes(payload_bytes)

    # --- artifact/provenance.json is left completely untouched — still honest. ---
    provenance_path = bundle / "artifact" / "provenance.json"
    provenance = json.loads(provenance_path.read_bytes())
    assert provenance["producer_hmac"] != forged_hmac, (
        "artifact/provenance.json must stay honest — only the payload is forged"
    )

    # --- Strongest producer: re-sha manifest.files to hide the tamper from the
    # per-file SHA walk (file_integrity_many_small / verifier step 1). ---
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/provenance_result.json"] = hashlib.sha256(
        payload_bytes
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall(), ContentProvenanceReDerivationCheck()]
    )
    result = verifier.verify(bundle)

    assert result.ok is False, (
        "Expected result.ok is False for a bundle with a forged payload "
        "producer_hmac claim (artifact manifest honest, manifest.files re-shaed); "
        "got True — the payload's own signature claim was never checked"
    )
    # The verifier wraps every typed-check-plugin failure's top-level reason_code
    # and propagated onto the face since 2026-08-30 (audit_bundle/verifier.py) — the specific
    # code this fix introduces surfaces only inside `detail`, not `reason_code`.
    # See ContentProvenanceReDerivationCheck.py / content_provenance_re_derivation.py.
    combined_detail = " ".join(f.detail for f in result.failures).upper()
    assert "CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH" in combined_detail, (
        f"expected CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH in failure detail; "
        f"got {result.failures!r}"
    )
    assert "BAD_FILE_SHA" not in combined_detail, (
        "BAD_FILE_SHA must NOT fire — manifest.files was re-shaed to match the "
        "forged payload bytes; this attack is only caught by the payload-hmac "
        "re-derivation check, not the per-file SHA walk"
    )


def test_forged_payload_hmac_via_verify_py_subprocess(tmp_path: Path) -> None:
    """Same forged-payload attack as above, driven through verify.py as an
    end-user would run it, asserting the CLI-level exit code and stderr.
    """
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0

    payload_path = bundle / "payload" / "provenance_result.json"
    payload = json.loads(payload_path.read_bytes())
    payload["producer_hmac"] = "hmac-sha256:" + ("f" * 64)
    payload_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    payload_path.write_bytes(payload_bytes)

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/provenance_result.json"] = hashlib.sha256(
        payload_bytes
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    proc = _run_verify(bundle)
    assert proc.returncode == 1, (
        f"expected exit 1 for forged payload producer_hmac; got {proc.returncode}\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )
    assert "PASS" not in proc.stdout
    assert "CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH" in proc.stderr, (
        f"expected CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH in stderr; "
        f"got: {proc.stderr!r}"
    )
    assert "BAD_FILE_SHA" not in proc.stdout.upper() + proc.stderr.upper(), (
        "the per-file SHA walk must not be what catches this attack"
    )


def test_tampered_content_result_ok_is_false(tmp_path: Path) -> None:
    """Direct API: BundleVerifier.verify() must return result.ok is False for tampered content.

    This test exercises the Python API directly (not subprocess) to assert
    result.ok is False with a meaningful reason_code present in the failures list.
    """
    sys.path.insert(0, str(_PKG_ROOT))
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))

    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier
    from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck

    # Build a fresh bundle
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0

    # Tamper the content
    content_path = bundle / "artifact" / "content.txt"
    original = bytearray(content_path.read_bytes())
    original[0] = (original[0] + 1) % 256
    content_path.write_bytes(bytes(original))

    # Verify via Python API
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall(), ContentProvenanceReDerivationCheck()]
    )
    result = verifier.verify(bundle)

    assert result.ok is False, (
        "Expected result.ok is False for a tampered-content bundle; got True"
    )
    reason_codes = {f.reason_code for f in result.failures}
    reason_codes_upper = {rc.upper() for rc in reason_codes}
    assert reason_codes_upper & {
        "BAD_FILE_SHA",
        "CONTENT_PROVENANCE_ALTERED",
        "PLUGIN_FAILED",
    }, f"Expected a tamper-indicating reason code in failures; got {reason_codes!r}"


# ---------------------------------------------------------------------------
# Claimset coverage (claim-field coverage gate adoption, 2026-08)
# ---------------------------------------------------------------------------


def _pilot_imports():
    sys.path.insert(0, str(_PKG_ROOT))
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier
    from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck

    return FileIntegrityManySmall, BundleVerifier, ContentProvenanceReDerivationCheck


def _make_verifier():
    FileIntegrityManySmall, BundleVerifier, Check = _pilot_imports()
    return BundleVerifier(plugins=[FileIntegrityManySmall(), Check()])


def _make_pre_adoption_verifier():
    """The plugin as it shipped BEFORE the claimset adoption: same pack, same
    verdict, no coverage reported — the honest control for "what the gate
    would have said over the pre-wave plugin"."""
    import dataclasses

    FileIntegrityManySmall, BundleVerifier, Check = _pilot_imports()

    class _PreAdoptionCheck(Check):
        def check(self, bundle_dir: Path, manifest):
            return dataclasses.replace(
                super().check(bundle_dir, manifest), verified_claim_fields=frozenset()
            )

    return BundleVerifier(plugins=[FileIntegrityManySmall(), _PreAdoptionCheck()])


def _repin_payload(bundle: Path, payload: dict) -> None:
    payload_path = bundle / "payload" / "provenance_result.json"
    payload_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    payload_path.write_bytes(payload_bytes)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/provenance_result.json"] = hashlib.sha256(
        payload_bytes
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


_COVERED = {
    "provenance_result:content_sha",
    "provenance_result:generation_inputs.model_id",
    "provenance_result:generation_inputs.note",
    "provenance_result:generation_inputs.prompt_sha",
    "provenance_result:generation_inputs.temperature",
    "provenance_result:producer_hmac",
    "provenance_result:producer_id",
    "provenance_result:provenance_sha",
    "provenance_result:provenance_status",
}


def test_content_provenance_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its claimset: the verdict carries the coverage receipt
    (9 observed fields, all bound by the re-derivation pack, none withheld).
    The honest control is the PRE-ADOPTION plugin (same pack, coverage
    stripped): could-not-conclude naming "9 of 9" under the declaration, and
    GREEN with the declaration removed — the formerly-silent scope gap on
    record."""
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr

    verdict = _make_verifier().verify(bundle)
    assert verdict.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in verdict.failures
    ]
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert len(lines) == 1, verdict.completeness.disclosures
    assert "n_universe=9 n_covered=9(self-reported) n_withheld=0" in lines[0]
    assert "withheld_reasons={}" in lines[0]
    assert lines[0].endswith("n_opaque=0")

    pre = _make_pre_adoption_verifier().verify(bundle)
    assert pre.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "9 of 9" in r.detail for r in pre.reasons
    ), [(r.code, r.detail) for r in pre.reasons]

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("claimset")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    undeclared = _make_pre_adoption_verifier().verify(bundle)
    assert undeclared.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in undeclared.failures
    ]
    assert any(
        d.startswith("claimset: not declared") for d in undeclared.completeness.disclosures
    )


def test_content_provenance_claimset_ratchet_all_fields_flip(tmp_path: Path) -> None:
    """Evidence-grade leg: a producer-consistent mutation of every covered
    field flips the verdict via the pack's OWN comparison (never via file-sha —
    the battery re-pins): producer_hmac under the payload-HMAC tag,
    provenance_status under the status tag, everything else under ALTERED."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr
    report = run_claimset_ratchet(
        bundle,
        _make_verifier,
        tmp_path / "ratchet_scratch",
        # Deny-by-default scoring: name the code THIS pilot's comparator
        # emits when it refuses a value, so a flip caused by anything else
        # (a crash, an unwired check, a timeout, a code nobody classified)
        # scores INCONCLUSIVE instead of being credited as coverage.
        comparator_codes={
            "CONTENT_PROVENANCE_ALTERED",
            "CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH",
            "CONTENT_PROVENANCE_STATUS_MISMATCH",
        },
    )
    assert report.baseline_state == "OK"
    assert not report.survived, [(o.element, o.detail) for o in report.survived]
    assert not report.skipped, [(o.element, o.detail) for o in report.skipped]
    assert not report.inconclusive, [(o.element, o.detail) for o in report.inconclusive]
    assert {o.element for o in report.flipped} == _COVERED
    assert report.excused == ()
    for outcome in report.flipped:
        assert "BAD_FILE_SHA" not in outcome.reason_codes
        if outcome.element.endswith(":producer_hmac"):
            tag = "CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH"
        elif outcome.element.endswith(":provenance_status"):
            tag = "CONTENT_PROVENANCE_STATUS_MISMATCH"
        else:
            tag = "CONTENT_PROVENANCE_ALTERED"
        assert any(tag in detail for _code, detail in outcome.reasons), (
            outcome.element,
            outcome.reasons,
        )


def test_content_provenance_status_is_bound(tmp_path: Path) -> None:
    """Positive control for the field bound inside the adoption: before this
    wave the pack never read provenance_status — the field a downstream
    consumer reads. A payload stating any status other than the re-derived one
    (everything else honest, file sha re-pinned) is refused."""
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr
    payload = json.loads((bundle / "payload" / "provenance_result.json").read_bytes())
    assert payload["provenance_status"] == "CONTENT_PROVENANCE_VERIFIED"
    payload["provenance_status"] = "CONTENT_PROVENANCE_PENDING_REVIEW"
    _repin_payload(bundle, payload)

    result = _make_verifier().verify(bundle)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "CONTENT_PROVENANCE_STATUS_MISMATCH" in combined, combined
    assert "BAD_FILE_SHA" not in combined
    assert not any(
        d.startswith("claimset: receipt_sha=") for d in result.completeness.disclosures
    )


def test_content_provenance_absent_payload_field_is_refused(tmp_path: Path) -> None:
    """Absence is not null: a payload that drops a covered field entirely is
    refused by the pack (KeyError → fail closed), and the gate's universe
    shrinks with it — never a silent pass over a field nothing compared."""
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr
    payload = json.loads((bundle / "payload" / "provenance_result.json").read_bytes())
    del payload["producer_id"]
    _repin_payload(bundle, payload)

    result = _make_verifier().verify(bundle)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "missing field 'producer_id'" in combined, combined


# ---------------------------------------------------------------------------
# Red-team findings on the adoption (2026-08-21) — witnesses
# ---------------------------------------------------------------------------


def _resign_manifest(bundle: Path, mutate) -> None:
    """Rewrite artifact/provenance.json via `mutate(manifest_dict)` WITHOUT the
    key (the signature field is left as it was), recompute provenance_sha in
    the payload honestly, re-pin both files — the no-key identity swap."""
    prov_path = bundle / "artifact" / "provenance.json"
    prov = json.loads(prov_path.read_bytes())
    mutate(prov)
    prov_bytes = json.dumps(prov, indent=2, sort_keys=True).encode("utf-8")
    prov_path.write_bytes(prov_bytes)
    payload = json.loads((bundle / "payload" / "provenance_result.json").read_bytes())
    payload["provenance_sha"] = hashlib.sha256(prov_bytes).hexdigest()
    payload["producer_id"] = prov["producer_id"]
    payload["generation_inputs"] = prov["generation_inputs"]
    payload["producer_hmac"] = prov["producer_hmac"]
    _repin_payload(bundle, payload)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["artifact/provenance.json"] = hashlib.sha256(prov_bytes).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def test_identity_swap_without_key_is_refused(tmp_path: Path) -> None:
    """Red-team witness: the signature used to cover the content bytes only, so
    producer_id / generation_inputs / created_at in artifact/provenance.json
    were rewritable with NO key — payload recomputed honestly, everything
    re-pinned, verdict OK with a full receipt. The signature now covers the
    manifest core; the swap is refused at the HMAC check."""
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr

    def _swap(prov: dict) -> None:
        prov["producer_id"] = "Newsroom/human-desk-v9"
        prov["generation_inputs"] = {
            "model_id": "human-authored",
            "note": "human-reviewed",
            "prompt_sha": "sha256:" + "0" * 64,
            "temperature": 0.0,
        }
        prov["created_at"] = "2020-01-01T00:00:00Z"

    _resign_manifest(bundle, _swap)
    result = _make_verifier().verify(bundle)
    assert result.ok is False, "identity swap without the key verified OK"
    combined = " ".join(f.detail for f in result.failures)
    assert "Producer HMAC mismatch" in combined, combined
    assert "BAD_FILE_SHA" not in combined


def test_manifest_content_sha_field_is_bound(tmp_path: Path) -> None:
    """Red-team witness: the manifest's OWN content_sha field was never read.
    A manifest naming other content (re-signed with the in-repo key, so the
    HMAC check passes) is refused because the field must name the re-hashed
    published bytes."""
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(
        "content_provenance__build_for_test", _BUILD_PY
    )
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)

    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr
    content_bytes = (bundle / "artifact" / "content.txt").read_bytes()

    def _lie(prov: dict) -> None:
        prov["content_sha"] = "sha256:" + "deadbeef" * 8
        core = {k: v for k, v in prov.items() if k != "producer_hmac"}
        prov["producer_hmac"] = "hmac-sha256:" + mod._producer_hmac(
            mod._SYNTHETIC_PRODUCER_KEY, mod._signing_input(content_bytes, core)
        )

    _resign_manifest(bundle, _lie)
    result = _make_verifier().verify(bundle)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "names content other than the published bytes" in combined, combined


def test_generation_inputs_comparison_is_type_strict(tmp_path: Path) -> None:
    """Red-team witness: Python == let a payload temperature of `true` equal a
    manifest temperature of `1` (and 1.0 equal 1). The comparison is canonical
    JSON now, so a type substitution in the payload is refused."""
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr
    payload = json.loads((bundle / "payload" / "provenance_result.json").read_bytes())
    prov = json.loads((bundle / "artifact" / "provenance.json").read_bytes())
    assert prov["generation_inputs"]["temperature"] == 0.7
    # Make the manifest say 1 (re-signed with the key — the attack is on the
    # payload side) and the payload say true: == calls them equal.
    content_bytes = (bundle / "artifact" / "content.txt").read_bytes()
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))
    import importlib.util as ilu

    spec = ilu.spec_from_file_location("content_provenance__build_for_test2", _BUILD_PY)
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def _one(p: dict) -> None:
        p["generation_inputs"]["temperature"] = 1
        core = {k: v for k, v in p.items() if k != "producer_hmac"}
        p["producer_hmac"] = "hmac-sha256:" + mod._producer_hmac(
            mod._SYNTHETIC_PRODUCER_KEY, mod._signing_input(content_bytes, core)
        )

    _resign_manifest(bundle, _one)
    payload = json.loads((bundle / "payload" / "provenance_result.json").read_bytes())
    payload["generation_inputs"]["temperature"] = True
    assert payload["generation_inputs"]["temperature"] == 1  # the Python == trap
    _repin_payload(bundle, payload)

    result = _make_verifier().verify(bundle)
    assert result.ok is False, "true == 1 was absorbed"
    combined = " ".join(f.detail for f in result.failures)
    # the plugin truncates the pack's stderr to 512 chars; the discriminating
    # words are the section header and the two differing renderings
    assert "generation_inputs in payload" in combined, combined
    assert '"temperature": true' in combined, combined


def test_deleted_comparison_is_could_not_conclude(tmp_path: Path) -> None:
    """The drift test — the one executable check that separates an ACCUMULATED
    `[COMPARED]` line from a constant. Copy the pilot directory to scratch,
    delete ONE comparison from the copied pack (producer_id: its `!=` check
    AND its `compared.add`), import the copied plugin (which runs the copied
    pack, `Path(__file__).parent`), forge that field in a fresh bundle, re-pin
    the file sha, and verify with the copied plugin in the pilot's wired set:
    the verdict must refuse to conclude NAMING the field — never stay OK. A
    pack that prints a constant list is OK here with a full receipt; that is
    the defect this test exists to make self-detecting. The control: the real
    plugin refuses the same forgery with the pack's own tag."""
    import importlib.util
    import shutil

    src_dir = _PKG_ROOT / "examples" / "content_provenance_minimal"
    copy_dir = tmp_path / "pilot_copy"
    shutil.copytree(
        src_dir,
        copy_dir,
        ignore=shutil.ignore_patterns("__pycache__", "tests", "bundle", "*.pyc"),
    )
    pack = copy_dir / "content_provenance_re_derivation.py"
    text = pack.read_text(encoding="utf-8")
    start_marker = "    # --- Assert provenance chain: producer_id ---"
    end_marker = '    compared.add("producer_id")\n'
    assert text.count(start_marker) == 1 and text.count(end_marker) == 1
    start = text.index(start_marker)
    end = text.index(end_marker) + len(end_marker)
    pack.write_text(text[:start] + text[end:], encoding="utf-8")

    spec = importlib.util.spec_from_file_location(
        "content_provenance_check_drift_copy",
        copy_dir / "ContentProvenanceReDerivationCheck.py",
    )
    assert spec is not None and spec.loader is not None
    drift_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(drift_mod)
    FileIntegrityManySmall, BundleVerifier, RealCheck = _pilot_imports()

    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, r.stderr
    payload = json.loads(
        (bundle / "payload" / "provenance_result.json").read_text(encoding="utf-8")
    )
    payload["producer_id"] = "forged-newsroom"
    _repin_payload(bundle, payload)

    drifted = BundleVerifier(
        plugins=[FileIntegrityManySmall(), drift_mod.ContentProvenanceReDerivationCheck()]
    ).verify(bundle)
    assert drifted.ok is False
    assert any(
        r.check_name == "claimset_coverage"
        and "1 of 9" in r.detail
        and "provenance_result:producer_id" in r.detail
        for r in drifted.reasons
    ), [(r.code, r.detail) for r in drifted.reasons]

    control = BundleVerifier(plugins=[FileIntegrityManySmall(), RealCheck()]).verify(bundle)
    assert control.ok is False
    assert any(
        "CONTENT_PROVENANCE_ALTERED" in f.detail and "producer_id" in f.detail
        for f in control.failures
    ), [f.detail for f in control.failures]
