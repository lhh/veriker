"""Round-trip integration test for examples/fp_ml_minimal.

Test flow:
  1. ROUND-TRIP: Build a clean bundle, run the verifier, assert result.ok is True.
  2. TAMPER-1 (exceeds ε): Mutate W[0][0] by +1e-3 in weights/model.json,
     re-align the manifest SHA so FileIntegrityManySmall passes, and assert
     the verifier returns ok=False with RE_DERIVATION_MISMATCH (or
     FP_ML_REDERIVATION_TOLERANCE_VIOLATED) in the failures, because the
     per-logit delta (~5.88e-3) far exceeds ε=1e-9.
  3. TAMPER-2 (within ε — BONUS): Mutate W[0][0] by +1e-12 in weights/model.json,
     re-align the manifest SHA, and assert the verifier returns ok=True because
     the perturbation (1e-12) is absorbed by float32 truncation (delta=0 after snap)
     and is strictly less than ε=1e-9.  This proves tolerance is a real bound,
     not a permission slip.
  4. TAMPER-3 (input_idx permutation — identity binding): Swap the input_idx
     values of two records in payload/predictions.json, leaving every logit
     and predicted_class byte untouched, then re-align the manifest SHA for
     the rewritten file. This attributes one input's inference result to a
     different input's identity purely via array-position trust. Assert the
     verifier returns ok=False with FP_ML_INPUT_IDX_MISMATCH in the failures.

Logit delta reference (from weight deltas analysis):
  Tamper-1 delta W[0][0] = +1e-3   →  max logit delta ≈ 5.88e-3  (>> ε=1e-9)
  Tamper-2 delta W[0][0] = +1e-12  →  max logit delta = 0.0       (< ε=1e-9)
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
_FP_ML_MINIMAL = _PKG_ROOT / "examples" / "fp_ml_minimal"

# Ensure the pilot directory is importable (for FpMlReDerivationCheck).
if str(_FP_ML_MINIMAL) not in sys.path:
    sys.path.insert(0, str(_FP_ML_MINIMAL))
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ---------------------------------------------------------------------------
# Imports (after sys.path is set)
# ---------------------------------------------------------------------------

from examples.fp_ml_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from FpMlReDerivationCheck import FpMlReDerivationCheck  # type: ignore[import]  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[FileIntegrityManySmall(), FpMlReDerivationCheck()])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tamper_weight_and_realign(bundle_dir: Path, delta: float) -> None:
    """Mutate W[0][0] by +delta in model.json and re-align manifest SHA."""
    model_path = bundle_dir / "weights" / "model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    original_w00 = model["W"][0][0]
    model["W"][0][0] = original_w00 + delta
    tampered_bytes = (json.dumps(model, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    model_path.write_bytes(tampered_bytes)

    # Re-align manifest SHA so FileIntegrityManySmall passes
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["weights/model.json"] = _sha256(tampered_bytes)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _swap_prediction_input_idx_and_realign(bundle_dir: Path, i: int, j: int) -> None:
    """Swap the input_idx values of records i and j in predictions.json.

    Every logit and predicted_class byte is left untouched — only the
    identity-binding field moves — then the manifest SHA for the rewritten
    file is re-aligned so FileIntegrityManySmall still passes.
    """
    predictions_path = bundle_dir / "payload" / "predictions.json"
    predictions = json.loads(predictions_path.read_text(encoding="utf-8"))
    predictions[i]["input_idx"], predictions[j]["input_idx"] = (
        predictions[j]["input_idx"],
        predictions[i]["input_idx"],
    )
    tampered_bytes = (
        json.dumps(predictions, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    predictions_path.write_bytes(tampered_bytes)

    # Re-align manifest SHA so FileIntegrityManySmall passes
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/predictions.json"] = _sha256(tampered_bytes)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Test 1: Happy-path round-trip
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build an fp_ml_minimal bundle and verify it passes all checks."""
    bundle_dir = tmp_path / "fp_ml_bundle"
    build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected ok=True; failures: " + ", ".join(
        f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures
    )


def test_fp_ml_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its claimset: the verdict carries the coverage
    receipt identity (3 fields, all covered, none withheld), and dropping the
    re-derivation plugin turns the formerly-silent scope gap into
    could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "fp_ml_bundle"
    build(bundle_dir)

    verdict = _make_verifier().verify(bundle_dir)
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert (
        len(lines) == 1
        and "n_universe=3 n_covered=3(self-reported) n_withheld=0" in lines[0]
    )

    # Without the comparator wired, the declared claimset must refuse to
    # conclude — the exact laundering the pre-claimset fleet shipped.
    bare = BundleVerifier(plugins=[FileIntegrityManySmall()]).verify(bundle_dir)
    assert bare.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "3 of 3" in r.detail
        for r in bare.reasons
    )


def test_fp_ml_minimal_claimset_ratchet_all_fields_flip(tmp_path: Path) -> None:
    """Evidence-grade leg: a producer-consistent mutation of every covered
    claim field flips the verdict via the comparator (never via file-sha).
    Registered prediction P2 of the port scoping: the July fixes hold at
    field granularity."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle_dir = tmp_path / "fp_ml_bundle"
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
    assert not report.skipped
    assert not report.survived, [o.element for o in report.survived]
    assert {o.element for o in report.flipped} == {
        "predictions:[].input_idx",
        "predictions:[].logits[]",
        "predictions:[].predicted_class",
    }
    for outcome in report.flipped:
        assert "BAD_FILE_SHA" not in outcome.reason_codes


# ---------------------------------------------------------------------------
# Test 2: Tamper-1 — mutate W[0][0] by +1e-3 (far exceeds ε=1e-9)
#
# Max logit delta ≈ 5.88e-3, which is ~5.88×10^6 × ε.  Verification must
# fail with RE_DERIVATION_MISMATCH (or FP_ML_REDERIVATION_TOLERANCE_VIOLATED).
# The failure detail string must include the actual delta.
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_tamper_exceeds_tolerance(tmp_path: Path) -> None:
    """Mutating W[0][0] by +1e-3 must cause RE_DERIVATION_MISMATCH.

    The per-logit delta for this weight change is approximately 5.88e-3,
    which exceeds ε=1e-9 by ~5.88 million times.  We re-align the manifest
    SHA so FileIntegrityManySmall passes; the failure must come exclusively
    from FpMlReDerivationCheck.
    """
    bundle_dir = tmp_path / "fp_ml_tamper1"
    build(bundle_dir)

    # Tamper: W[0][0] += 1e-3 (ε-exceeding delta)
    _tamper_weight_and_realign(bundle_dir, delta=1e-3)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected verification to fail after +1e-3 weight mutation"
    )

    # Collect all reason codes and detail text
    failure_text = " ".join(
        f"{f.reason_code} {f.detail}" for f in result.failures
    ).upper()

    # The plugin's own reason code reaches the verdict face directly since
    # 2026-08-30 (the verifier no longer overwrites it with "plugin_failed"),
    # and the pack's [FP_ML_REDER_FAIL] marker travels in the detail. Assert
    # BOTH -- the code on the face and the pack's own marker -- instead of a
    # four-way `or` whose PLUGIN_FAILED arm accepted a failure from any check.
    assert "RE_DERIVATION_MISMATCH" in failure_text, (
        "Expected RE_DERIVATION_MISMATCH in failures; "
        "got: "
        + str([(f.check_name, f.reason_code, f.detail[:80]) for f in result.failures])
    )

    # The detail string from fp_ml_re_derivation.py must mention the actual delta
    assert "DELTA" in failure_text, (
        "Expected failure detail to include 'delta' (actual delta value); "
        "got: " + str([(f.reason_code, f.detail) for f in result.failures])
    )


# ---------------------------------------------------------------------------
# Test 3: Tamper-2 (BONUS) — mutate W[0][0] by +1e-12 (within ε=1e-9)
#
# +1e-12 is absorbed by float32 truncation: after struct.pack/unpack the
# snapped value equals the original W[0][0]=0.5 exactly, so the logit
# delta is 0.0, which is strictly less than ε=1e-9.
# Verification MUST PASS — this proves tolerance is a real quantified bound.
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_tamper_within_tolerance_passes(tmp_path: Path) -> None:
    """Mutating W[0][0] by +1e-12 must NOT cause verification to fail.

    The +1e-12 perturbation is absorbed by float32 truncation at the
    serialization boundary (struct.pack('f', 0.5 + 1e-12) == struct.pack('f', 0.5)).
    The logit delta is 0.0, strictly less than ε=1e-9.

    This is the BONUS tamper test that proves tolerance is REAL: if the
    substrate accepted ε as a blanket permission slip, it would be
    meaningless.  The tight ε=1e-9 is chosen to match float32 truncation
    noise, not to allow unchecked drift.

    Expected: result.ok is True (verification passes).
    """
    bundle_dir = tmp_path / "fp_ml_tamper2"
    build(bundle_dir)

    # Tamper: W[0][0] += 1e-12 (ε-respecting delta)
    _tamper_weight_and_realign(bundle_dir, delta=1e-12)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, (
        "Expected ok=True for +1e-12 weight mutation (within ε=1e-9); "
        "failures: "
        + ", ".join(
            f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures
        )
    )


# ---------------------------------------------------------------------------
# Test 4: Tamper-3 — swap input_idx between two records (identity binding)
#
# The strongest producer of this class: logits and predicted_class are left
# byte-for-byte identical for every record; only the input_idx field on two
# records is swapped. A checker that trusts array position (bundled_
# predictions[i] compared to feature_vectors[i] purely by loop index) would
# report full re-derivation success even though input 0's inference result
# is now attributed to input 1's identity (and vice versa). The fixed
# checker must catch this via the explicit input_idx == i binding check.
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_tamper_input_idx_swap_fails(tmp_path: Path) -> None:
    """Swapping input_idx between two prediction records must be caught.

    This is a pure identity-binding attack: no logit, no predicted_class,
    and no feature vector is touched. Only the input_idx values of records
    0 and 1 in payload/predictions.json are swapped, then the manifest SHA
    for that file is re-aligned so FileIntegrityManySmall still passes. A
    checker that compares bundled_predictions[i] to a recomputation over
    feature_vectors[i] using the loop index alone — never reading
    input_idx — would report full re-derivation success. The fixed checker
    must fail with FP_ML_INPUT_IDX_MISMATCH.
    """
    bundle_dir = tmp_path / "fp_ml_tamper3"
    build(bundle_dir)

    # Tamper: swap input_idx of records 0 and 1 (logits/predicted_class untouched)
    _swap_prediction_input_idx_and_realign(bundle_dir, 0, 1)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected verification to fail after swapping input_idx between "
        "two prediction records"
    )

    failure_text = " ".join(
        f"{f.reason_code} {f.detail}" for f in result.failures
    ).upper()

    assert "FP_ML_INPUT_IDX_MISMATCH" in failure_text, (
        "Expected FP_ML_INPUT_IDX_MISMATCH in failures; "
        "got: "
        + str([(f.check_name, f.reason_code, f.detail) for f in result.failures])
    )
