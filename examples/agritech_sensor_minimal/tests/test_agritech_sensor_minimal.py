"""Round-trip integration test for examples/agritech_sensor_minimal.

Test flow:
  1. Build a clean bundle into a temp directory.
  2. Run the verifier with the pilot's plugin set — assert result.ok is True.
  3. Tamper test A: mutate a sensor reading so the re-derivation diverges.
     Assert result.ok is False with RE_DERIVATION_MISMATCH in failures.
  4. Tamper test B: mutate the yield_score in yield_forecast.json directly.
     Assert result.ok is False with RE_DERIVATION_MISMATCH in failures.
  5. Check fragment anchors are present in the manifest (48 samples).
  6. Tamper test C (FIX-E, claim-set coverage sweep): relabel the forecast's
     field_id + shift its window WITHOUT touching yield_score — an honest
     score computed from field A's real data, misattributed to a different
     field/period. Assert result.ok is False with YIELD_ATTRIBUTION_MISMATCH
     in failures (via the wrapped `detail` — BundleVerifier reports the
     top-level reason_code, propagated since 2026-08-30).
  7. Unit-level coverage of yield_fusion_re_derivation._verify() directly:
     honest pass, attribution mismatch, fail-closed on a missing binding
     field, and fail-closed on a missing/non-integer num_samples.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[3]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "agritech_sensor_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.agritech_sensor_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from YieldFusionReDerivationCheck import YieldFusionReDerivationCheck  # noqa: E402
import yield_fusion_re_derivation as _pack  # noqa: E402  (direct pack unit tests)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            YieldFusionReDerivationCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "agritech_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True on clean bundle; failures: {result.failures}"
    )


def test_manifest_has_48_fragment_anchors(tmp_path: Path) -> None:
    """The manifest must contain exactly 48 TimestampSampleFragment anchors."""
    bundle_dir = tmp_path / "agritech_bundle_frags"
    build(bundle_dir)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})
    assert len(anchors) == 48, f"expected 48 fragment anchors; got {len(anchors)}"
    # Spot-check: every anchor must have kind=timestamp_sample
    for name, frag in anchors.items():
        assert frag.get("kind") == "timestamp_sample", (
            f"anchor {name!r} has kind={frag.get('kind')!r}, expected 'timestamp_sample'"
        )


def _check_ran_and_failed(result, check_name: str, marker: str) -> bool:
    """Did `check_name` actually RUN and report `marker`, as opposed to being
    declared-but-unwired? A declared-but-unwired check fails CLOSED under the
    SAME check_name, so matching check_name alone is a tautology that passes
    with the plugin deleted; "reported failure" is the substring only the
    ran-and-disagreed arm of _step_typed_check_plugins writes."""
    for f in result.failures:
        if (
            f.check_name == check_name
            and "reported failure" in f.detail
            and marker in f.detail.upper()
        ):
            return True
    return False


_YIELD_CHECK = "typed_check_plugins:yield_fusion_re_derivation"


def test_tamper_sensor_reading_fails(tmp_path: Path) -> None:
    """Mutating a sensor reading must trigger RE_DERIVATION_MISMATCH."""
    bundle_dir = tmp_path / "agritech_bundle_tamper_a"
    build(bundle_dir)

    # Tamper: corrupt first sample's soil_moisture_pct
    stream_path = bundle_dir / "inputs" / "sensor_stream.json"
    stream = json.loads(stream_path.read_text(encoding="utf-8"))
    original = stream["samples"][0]["soil_moisture_pct"]
    stream["samples"][0]["soil_moisture_pct"] = original + 50.0  # large delta
    stream_path.write_text(json.dumps(stream, indent=2), encoding="utf-8")

    # NOTE: we do NOT update the manifest SHA, so FileIntegrityManySmall
    # will catch this as BAD_FILE_SHA.  The point is: the bundle is corrupted
    # and the verifier must report ok=False.
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, "expected ok=False after tampering sensor reading"
    # This tamper does NOT re-pin the manifest, so the file-integrity walk is
    # what must catch it -- assert exactly that, on the reason CODE. The old
    # form was a four-way `or` over `reason_code + detail`, three arms of which
    # could never match: "YIELD_REDERIV" is not a substring of the pack's
    # "[YIELD_REDER_FAIL]" (REDER_ then F, not I), and neither "MANIFEST_SHA"
    # nor "YIELD_SCORE MISMATCH" is emitted on this path. A disjunct that
    # cannot fire is not a weaker check, it is no check.
    codes = {f.reason_code.upper() for f in result.failures}
    assert "BAD_FILE_SHA" in codes, (
        f"expected the un-re-pinned tamper to be caught by the file-integrity "
        f"walk; got: {result.failures}"
    )


def test_tamper_yield_score_direct_fails(tmp_path: Path) -> None:
    """Mutating yield_score in yield_forecast.json (but not sensor_stream)
    must trigger RE_DERIVATION_MISMATCH via the re-derivation plugin."""
    bundle_dir = tmp_path / "agritech_bundle_tamper_b"
    build(bundle_dir)

    # Tamper: overwrite yield_score in the forecast payload.
    # Also update the manifest SHA so FileIntegrityManySmall passes — this
    # forces the test to exercise the re-derivation plugin specifically.
    forecast_path = bundle_dir / "payload" / "yield_forecast.json"
    forecast = json.loads(forecast_path.read_text(encoding="utf-8"))
    forecast["yield_score"] = 9999.0
    forecast["confidence_band"] = [9999.0 * 0.9, 9999.0 * 1.1]
    forecast_bytes = json.dumps(forecast, indent=2).encode("utf-8")
    forecast_path.write_bytes(forecast_bytes)

    # Patch manifest SHA so integrity check passes; re-derivation must catch it
    import hashlib

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/yield_forecast.json"] = hashlib.sha256(
        forecast_bytes
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, "expected ok=False after tampering yield_score directly"
    # The manifest IS re-pinned here, so nothing but the re-derivation plugin
    # can catch this -- and the assertion must say so. The old form
    # ("YIELD_REDERIV" or "PLUGIN_FAILED" in reason_code + detail) was carried
    # ENTIRELY by the PLUGIN_FAILED arm: "YIELD_REDERIV" never matched the
    # pack's "[YIELD_REDER_FAIL]" marker, and PLUGIN_FAILED matched ANY plugin
    # failure from ANY check -- it would have passed with this plugin swapped
    # for an unrelated broken one. Require the named check to have RUN and
    # DISAGREED, and the code to reach the face.
    assert _check_ran_and_failed(result, _YIELD_CHECK, "YIELD_REDER_FAIL"), (
        f"expected {_YIELD_CHECK} to run and report YIELD_REDER_FAIL; "
        f"got: {result.failures}"
    )
    assert "RE_DERIVATION_MISMATCH" in {f.reason_code for f in result.failures}, (
        f"expected the plugin's own reason code on the verdict face; "
        f"got: {[f.reason_code for f in result.failures]}"
    )


def test_sensor_stream_field_id_preserved(tmp_path: Path) -> None:
    """The sensor_stream.json must carry the expected field_id."""
    bundle_dir = tmp_path / "agritech_bundle_meta"
    build(bundle_dir)
    stream = json.loads(
        (bundle_dir / "inputs" / "sensor_stream.json").read_text(encoding="utf-8")
    )
    assert stream["field_id"] == "field_A_synthetic"
    assert stream["sensor_id"] == "composite_field_A"
    assert len(stream["samples"]) == 48


# ---------------------------------------------------------------------------
# FIX-E — attribution / scope-misbinding (claim-set coverage sweep)
# ---------------------------------------------------------------------------
#
# Confirmed finding: yield_fusion_re_derivation.py::_verify() compared only
# yield_score / confidence_band / (loosely) num_samples. The forecast's
# claimed field_id, sensor_id, and window_start/window_end were never
# cross-checked against inputs/sensor_stream.json's own copies of those
# fields — a producer could honestly compute the score from field A's real
# data but attribute/timestamp the forecast to field B or a different
# reporting period. Fixed by binding those four fields with equality,
# fail-closed on either side omitting one.


def test_tamper_forecast_attribution_mismatch_fails(tmp_path: Path) -> None:
    """Strongest producer: relabel the forecast to a DIFFERENT field_id and a
    SHIFTED reporting window, leaving yield_score/confidence_band/num_samples
    completely untouched (an honest score, misattributed). Must FAIL via the
    new attribution binding — the numeric re-derivation alone cannot catch
    this, since nothing numeric changed."""
    bundle_dir = tmp_path / "agritech_bundle_tamper_attr"
    build(bundle_dir)

    forecast_path = bundle_dir / "payload" / "yield_forecast.json"
    forecast = json.loads(forecast_path.read_text(encoding="utf-8"))
    forecast["field_id"] = "field_B_synthetic"
    forecast["window_start"] = "2026-06-01T00:00:00Z"
    forecast["window_end"] = "2026-06-02T23:00:00Z"
    forecast_bytes = json.dumps(forecast, indent=2).encode("utf-8")
    forecast_path.write_bytes(forecast_bytes)

    # Re-sha manifest.files so FileIntegrityManySmall passes cleanly and the
    # test exercises the re-derivation plugin's attribution binding, not a
    # generic file-integrity catch.
    import hashlib

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/yield_forecast.json"] = hashlib.sha256(
        forecast_bytes
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after relabeling forecast attribution "
        "(score/confidence_band/num_samples untouched)"
    )
    # BundleVerifier wraps every failing plugin as reason_code="plugin_failed"
    # and keeps only `detail` (audit_bundle/verifier.py _step_typed_check_plugins);
    # the dedicated sub-code survives there as a prefix.
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "YIELD_ATTRIBUTION_MISMATCH" in combined, (
        f"expected YIELD_ATTRIBUTION_MISMATCH in failures; got: {result.failures}"
    )


def test_pack_verify_honest_bundle_returns_none(tmp_path: Path) -> None:
    """Direct unit check: an untampered bundle's attribution fields already
    match, so the new binding check must not false-positive on the honest
    path — _verify() returns None."""
    bundle_dir = tmp_path / "agritech_bundle_pack_honest"
    build(bundle_dir)
    assert _pack._verify(bundle_dir) is None


def test_pack_verify_attribution_mismatch_field_id(tmp_path: Path) -> None:
    """Direct unit check on _verify(): a lone field_id relabel (nothing else
    touched) is caught with the dedicated YIELD_ATTRIBUTION_MISMATCH code."""
    bundle_dir = tmp_path / "agritech_bundle_pack_attr"
    build(bundle_dir)
    forecast_path = bundle_dir / "payload" / "yield_forecast.json"
    forecast = json.loads(forecast_path.read_text(encoding="utf-8"))
    forecast["field_id"] = "field_B_synthetic"
    forecast_path.write_text(json.dumps(forecast, indent=2), encoding="utf-8")

    error = _pack._verify(bundle_dir)
    assert error is not None and "YIELD_ATTRIBUTION_MISMATCH" in error, (
        f"expected YIELD_ATTRIBUTION_MISMATCH; got: {error!r}"
    )


def test_pack_verify_fails_closed_on_missing_binding_field(tmp_path: Path) -> None:
    """Direct unit check: a forecast that OMITS a binding field (rather than
    mismatching it) must fail closed, not be silently skipped."""
    bundle_dir = tmp_path / "agritech_bundle_pack_missing_binding"
    build(bundle_dir)
    forecast_path = bundle_dir / "payload" / "yield_forecast.json"
    forecast = json.loads(forecast_path.read_text(encoding="utf-8"))
    del forecast["window_start"]
    forecast_path.write_text(json.dumps(forecast, indent=2), encoding="utf-8")

    error = _pack._verify(bundle_dir)
    assert error is not None and "YIELD_ATTRIBUTION_MISMATCH" in error, (
        f"expected fail-closed YIELD_ATTRIBUTION_MISMATCH; got: {error!r}"
    )


def test_pack_verify_fails_closed_on_missing_num_samples(tmp_path: Path) -> None:
    """Direct unit check: num_samples is a required, exact-equality field
    (the builder always sets it == len(samples)) — omitting it must fail
    closed rather than being silently skipped, as it previously was."""
    bundle_dir = tmp_path / "agritech_bundle_pack_missing_numsamples"
    build(bundle_dir)
    forecast_path = bundle_dir / "payload" / "yield_forecast.json"
    forecast = json.loads(forecast_path.read_text(encoding="utf-8"))
    del forecast["num_samples"]
    forecast_path.write_text(json.dumps(forecast, indent=2), encoding="utf-8")

    error = _pack._verify(bundle_dir)
    assert error is not None and "num_samples" in error, (
        f"expected a num_samples fail-closed error; got: {error!r}"
    )


def test_pack_verify_fails_closed_on_wrong_num_samples(tmp_path: Path) -> None:
    """Direct unit check: num_samples must equal len(samples) exactly."""
    bundle_dir = tmp_path / "agritech_bundle_pack_wrong_numsamples"
    build(bundle_dir)
    forecast_path = bundle_dir / "payload" / "yield_forecast.json"
    forecast = json.loads(forecast_path.read_text(encoding="utf-8"))
    forecast["num_samples"] = 47
    forecast_path.write_text(json.dumps(forecast, indent=2), encoding="utf-8")

    error = _pack._verify(bundle_dir)
    assert error is not None and "num_samples mismatch" in error, (
        f"expected a num_samples mismatch error; got: {error!r}"
    )
