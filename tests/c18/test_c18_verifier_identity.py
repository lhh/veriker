"""Unit tests for audit_bundle.extensions.c18_verifier_identity (c18-011).

Tests per S18 PRD c18-011: 8 scenarios covering structural verification +
tripwire signal semantics. All tests stdlib-only (no third-party deps).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from audit_bundle.extensions.c18_verifier_identity import (
    REASON_BLOCK_MALFORMED,
    REASON_FIELD_MISSING,
    REASON_OCI_DIGEST_MALFORMED,
    REASON_RELEASE_MANIFEST_MISMATCH,
    REASON_SELF_CHECK_UNKNOWN_STATUS,
    TRIPWIRE_IS_NOT_TRUST_ASSERTION,
    self_check_tripwire,
    verify_verifier_identity_structural,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


# SHAPE-valid placeholder ONLY (red-team B-2): the C18 check validates the
# STRUCTURE of rekor_inclusion_proof (key/type shape), NOT the proof itself —
# there is no Merkle-inclusion fold or signed-tree-head compare. These hashes
# are arbitrary placeholders, not a cryptographically valid Rekor proof;
# "VALID" here means "shape-valid." Do not read this fixture's passing as
# evidence the verifier checks transparency-log inclusion (it does not).
VALID_REKOR_PROOF = {
    "leaf_index": 12345,
    "tree_size": 67890,
    "hashes": [
        "abc123" * 10 + "abcd",  # shape-only placeholder, not a real Merkle hash
        "def456" * 10 + "def4",
    ],
    "root_hash": "0123456789abcdef" * 4,
}


def _valid_identity_block(**overrides) -> dict:
    """Build a valid verifier_identity block with optional overrides."""
    block = {
        "verifier_release_id": "v0.3.0",
        "verifier_oci_digest": "sha256:" + "a" * 64,
        "verifier_self_check_status": "passed",
        "release_manifest_url": "https://manifest.vkernel.dev/v0.3.0.json",
        "release_manifest_hash": "sha256:" + "0" * 64,
        "scitt_statement_hash": "sha256:" + "1" * 64,
        "sigstore_bundle_hash": "sha256:" + "2" * 64,
        "rekor_inclusion_proof": VALID_REKOR_PROOF.copy(),
    }
    block.update(overrides)
    return block


def _manifest_with(block: dict | None) -> dict:
    """Wrap a verifier_identity block (or None) in a bundle manifest shape."""
    if block is None:
        return {"evidence": {}}
    return {"evidence": {"verifier_identity": block}}


# -----------------------------------------------------------------------------
# Module-level invariants
# -----------------------------------------------------------------------------


def test_tripwire_constant_is_true():
    """TRIPWIRE_IS_NOT_TRUST_ASSERTION must be True (c18-CKP-FINAL linting beacon)."""
    assert TRIPWIRE_IS_NOT_TRUST_ASSERTION is True


# -----------------------------------------------------------------------------
# verify_verifier_identity_structural tests
# -----------------------------------------------------------------------------


def test_legacy_bundle_pre_c18_passes_cleanly(tmp_path: Path):
    """Test 1: empty bundle (legacy — no verifier_identity field) → PASS empty list."""
    manifest = _manifest_with(None)
    reasons = verify_verifier_identity_structural(tmp_path, manifest)
    assert reasons == []


def test_valid_full_identity_passes(tmp_path: Path):
    """Test 2: valid full identity → PASS empty list."""
    manifest = _manifest_with(_valid_identity_block())
    reasons = verify_verifier_identity_structural(tmp_path, manifest)
    assert reasons == [], f"unexpected reasons: {reasons}"


def test_oci_digest_malformed(tmp_path: Path):
    """Test 3: OCI digest malformed → FAIL with VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED."""
    block = _valid_identity_block(verifier_oci_digest="not-a-real-digest")
    manifest = _manifest_with(block)
    reasons = verify_verifier_identity_structural(tmp_path, manifest)
    assert REASON_OCI_DIGEST_MALFORMED in reasons


def test_self_check_status_unknown_fails(tmp_path: Path):
    """Test 4: self_check_status='unknown' → FAIL with VERIFIER_SELF_CHECK_UNKNOWN_STATUS.

    Closes Pass-1 tightening item 13 (mode-from-producer hardening).
    """
    block = _valid_identity_block(verifier_self_check_status="unknown")
    manifest = _manifest_with(block)
    reasons = verify_verifier_identity_structural(tmp_path, manifest)
    assert REASON_SELF_CHECK_UNKNOWN_STATUS in reasons


def test_missing_rekor_inclusion_proof_fails(tmp_path: Path):
    """Test 5: missing rekor_inclusion_proof → FAIL with VERIFIER_IDENTITY_FIELD_MISSING
    (the field is absent from the block at all)."""
    block = _valid_identity_block()
    del block["rekor_inclusion_proof"]
    manifest = _manifest_with(block)
    reasons = verify_verifier_identity_structural(tmp_path, manifest)
    assert any(REASON_FIELD_MISSING in r for r in reasons)


def test_release_manifest_hash_mismatch(tmp_path: Path):
    """Test 6: release_manifest_hash != recomputed → FAIL with
    VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH."""
    # Write a release_manifest.json to the bundle dir; declared hash is wrong.
    actual_content = b'{"hello": "world"}'
    (tmp_path / "release_manifest.json").write_bytes(actual_content)
    actual_hash = hashlib.sha256(actual_content).hexdigest()
    # Declare a DIFFERENT hash.
    wrong_hash = "sha256:" + "9" * 64
    assert wrong_hash != f"sha256:{actual_hash}"
    block = _valid_identity_block(release_manifest_hash=wrong_hash)
    manifest = _manifest_with(block)
    reasons = verify_verifier_identity_structural(tmp_path, manifest)
    assert REASON_RELEASE_MANIFEST_MISMATCH in reasons


# -----------------------------------------------------------------------------
# self_check_tripwire tests
# -----------------------------------------------------------------------------


def test_tripwire_reports_divergence():
    """Test 7: tripwire reports divergence → divergence=True; logs nothing (caller's job)."""
    result = self_check_tripwire(
        running_oci_digest="sha256:" + "a" * 64,
        bundled_oci_digest="sha256:" + "b" * 64,
    )
    assert result["divergence"] is True
    assert result["reported_digest"] == "sha256:" + "a" * 64
    assert result["official_digest"] == "sha256:" + "b" * 64
    # Note text must NOT say "passed" / "verified" / "trusted" (CV4 UX-trap closure).
    note = result["note"].lower()
    for forbidden in ("self-check passed", "verified", "trusted", "authentic"):
        assert forbidden not in note, f"forbidden phrase {forbidden!r} in tripwire note"


def test_tripwire_reports_match():
    """Test 8: tripwire reports match → divergence=False; note explicitly says NOT a trust assertion."""
    digest = "sha256:" + "c" * 64
    result = self_check_tripwire(running_oci_digest=digest, bundled_oci_digest=digest)
    assert result["divergence"] is False
    assert result["reported_digest"] == digest
    assert result["official_digest"] == digest
    # Even on MATCH, the note must clarify this is NOT a trust assertion.
    note = result["note"].lower()
    assert "not a trust assertion" in note or "not proof" in note, (
        f"note must caveat NOT-a-trust-assertion: {note!r}"
    )


def test_tripwire_running_digest_none_yields_skip():
    """Bonus: running_oci_digest=None (substrate cannot determine) → divergence=False,
    SKIPPED tripwire signal."""
    result = self_check_tripwire(
        running_oci_digest=None,
        bundled_oci_digest="sha256:" + "d" * 64,
    )
    assert result["divergence"] is False
    assert result["reported_digest"] is None
    assert "skipped" in result["note"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ---------------------------------------------------------------------------
# The retired extractor
#
# `_extract_verifier_identity_block` (a c18 copy and a hand-duplicated tripwire
# mirror) was the fail-open pair: the copies drifted, and both callers read
# None as "legacy bundle, clean PASS". The tri-state `_locate_verifier_identity`
# replaced it in every caller, and `tests/c18/test_cli_verify_c18_tristate.py`
# holds the three locator copies (extension, tripwire, CLI) in agreement. The
# dead pair was deleted on 2026-09-05 (DUPLICATION_CENSUS §8); the test below
# keeps the ORIGINAL intent — a malformed inner block never skips the
# structural check — on the live path.
# ---------------------------------------------------------------------------

from types import SimpleNamespace  # noqa: E402

_IDENT = {"verifier_oci_digest": "sha256:" + "a" * 64,
          "verifier_self_check_status": "passed"}


def test_malformed_inner_block_does_not_skip_structural_checks():
    """The fail-open this fix closes: a present-but-non-dict
    evidence.verifier_identity must not resolve to None (read as 'legacy
    bundle, clean PASS') when a real block is reachable."""
    manifest = SimpleNamespace(
        evidence=SimpleNamespace(verifier_identity="not-a-dict"),
        verifier_identity=_IDENT,
    )

    # And the structural check is no longer skipped. Before the original fix
    # this returned [] — an empty reason list is a clean PASS, i.e. the
    # malformed block silently disabled every C18 check.
    reasons = verify_verifier_identity_structural(Path("."), manifest)
    assert reasons, "structural check still skipped — the fail-open is back"

    # STRENGTHENED 2026-08-29 (tri-state, THREAT_MODEL row 20). This assertion
    # was `any(r.startswith(REASON_FIELD_MISSING))`, which specified the reason
    # CLASS for an input that now refuses earlier and harder.
    #
    # The original fix made a non-dict at the canonical location fall THROUGH to
    # the top-level fallback ("strictly more checking, never less"). That closes
    # the skip when a fallback exists, and leaves it open when one does not —
    # attribute-style garbage with no fallback still resolved to None -> clean
    # PASS. It also silently prefers whichever of two contradictory producer
    # statements happens to parse, which is choosing the producer's most
    # favourable reading.
    #
    # The tri-state locator refuses instead: present-but-unparseable is its own
    # outcome, never absent, wherever it appears. That subsumes the fall-through
    # (no skip in either case) AND closes the no-fallback leg. This test's
    # INTENT — "the structural check is not silently skipped" — is unchanged and
    # asserted above; only the reason class moved, and it moved stricter.
    #
    # A legitimate `verifier_identity: dict | None = None` dataclass default is
    # still ABSENT, not malformed, so the ordinary fallback path is untouched
    # (covered by "None block + top-level block" in the parity cases above).
    assert any(r.startswith(REASON_BLOCK_MALFORMED) for r in reasons), reasons
    assert not any(r.startswith(REASON_FIELD_MISSING) for r in reasons), (
        "row 20: MALFORMED must not be reported in the missing-field vocabulary"
    )
