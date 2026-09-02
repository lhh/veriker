"""Round-trip integration test for examples/streaming_minimal/verify.py.

Test flow:
  1. (test_clean_bundle_passes) Build a clean bundle into a temp directory.
     Run the verifier with the pilot's plugin set. Assert result.ok is True.

  2. (test_tamper_event_timestamp_fails_rederivation) Mutate event 599's
     timestamp_ms from 59900 to 60000, pushing it from window 0 into window 1.
     Re-align events/stream.jsonl SHA in manifest.files so FileIntegrityManySmall
     passes. Assert STREAMING_REDERIV substring appears in failures — caught
     exclusively by StreamingReDerivationCheck.

  3. (test_tamper_spec_segmentation_fails_spec_sha) Append trailing whitespace
     to spec/segmentation.json (SHA changes; parsed JSON is identical). Do NOT
     realign manifest.spec_files SHA. Assert SpecShaPinCheck catches the divergence
     — SPEC_SHA_MISMATCH or missing_spec_blob substring in failures.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "streaming_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.streaming_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from StreamingReDerivationCheck import StreamingReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            SpecShaPinCheck(),
            FileIntegrityManySmall(),
            StreamingReDerivationCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "streaming_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, f"expected ok=True; failures: {result.failures}"


def test_tamper_event_timestamp_fails_rederivation(tmp_path: Path) -> None:
    """Pushing event 599's timestamp from 59900 to 60000 must trigger
    RE_DERIVATION_MISMATCH.

    Event 599 sits at the boundary: timestamp_ms=59900 puts it in window 0
    [0, 60000). Bumping to 60000 moves it into window 1 [60000, ...), changing:
      - window 0: count 600→599, aggregate -300→-393  (loses value 93)
      - window 1: count 400→401, aggregate -200→-107  (gains value 93)

    The events/stream.jsonl SHA in manifest.files is re-aligned so
    FileIntegrityManySmall passes. The failure is caught exclusively by
    StreamingReDerivationCheck.
    """
    bundle_dir = tmp_path / "streaming_bundle_tamper"
    build(bundle_dir)

    stream_path = bundle_dir / "events" / "stream.jsonl"

    # Read all lines, find event 599, mutate its timestamp_ms
    lines = stream_path.read_text(encoding="utf-8").splitlines(keepends=True)

    mutated = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        ev = json.loads(stripped)
        if ev.get("event_id") == 599:
            assert ev["timestamp_ms"] == 59900, (
                f"expected event 599 timestamp_ms=59900, got {ev['timestamp_ms']}"
            )
            ev["timestamp_ms"] = 60000  # push into window 1
            lines[i] = json.dumps(ev, separators=(",", ":")) + "\n"
            mutated = True
            break

    assert mutated, "event 599 not found in stream.jsonl"
    tampered_bytes = "".join(lines).encode("utf-8")
    stream_path.write_bytes(tampered_bytes)

    # Re-align manifest SHA so FileIntegrityManySmall does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["events/stream.jsonl"] = hashlib.sha256(
        tampered_bytes
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after pushing event 599 across window boundary"
    )
    # Accept RE_DERIVATION_MISMATCH reason_code or [STREAMING_REDER_FAIL] in detail
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "STREAMING_REDERIV" in combined or "STREAMING_REDER_FAIL" in combined, (
        f"expected RE_DERIVATION_MISMATCH or STREAMING_REDER_FAIL in failures; "
        f"got: {result.failures}"
    )


def test_tamper_spec_segmentation_fails_spec_sha(tmp_path: Path) -> None:
    """Mutate spec/segmentation.json with a SHA-changing-but-semantics-preserving
    edit (trailing whitespace; ignored by json.loads). manifest.spec_files SHA is
    NOT realigned, so SpecShaPinCheck catches the divergence in isolation —
    re-derivation still passes because parsed JSON is identical.
    """
    bundle_dir = tmp_path / "streaming_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "segmentation.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after tampering spec/segmentation.json without realigning manifest.spec_files"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), f"expected spec-SHA-mismatch indicator in failures; got: {result.failures}"


# ---------------------------------------------------------------------------
# Claimset coverage (claim-field coverage gate adoption, 2026-08)
# ---------------------------------------------------------------------------


class _PreAdoptionCheck(StreamingReDerivationCheck):
    """The plugin as it shipped BEFORE the claimset adoption: same pack, same
    verdict, no coverage reported. Used as the honest control for "what the
    gate would have said over the pre-adoption plugin"."""

    def check(self, bundle_dir: Path, manifest):
        import dataclasses

        return dataclasses.replace(
            super().check(bundle_dir, manifest), verified_claim_fields=frozenset()
        )


def _pre_adoption_plugins():
    return [
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        _PreAdoptionCheck(),
    ]


def _repin(bundle_dir: Path, rel: str) -> None:
    """Re-pin one file's sha in manifest.files — what every producer re-pins."""
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def test_streaming_minimal_claimset_receipt_on_verdict(tmp_path: Path) -> None:
    """The pilot declares its claimset: the verdict carries the coverage
    receipt identity (4 fields, all bound by streaming_re_derivation.py — no
    residual), and dropping the coverage report turns the formerly-silent
    scope gap into could-not-conclude instead of a green PASS."""
    bundle_dir = tmp_path / "streaming_bundle"
    build(bundle_dir)

    verdict = _make_verifier().verify(bundle_dir)
    assert verdict.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in verdict.failures
    ]
    lines = [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]
    assert len(lines) == 1, verdict.completeness.disclosures
    assert "n_universe=4 n_covered=4(self-reported) n_withheld=0" in lines[0]
    assert "withheld_reasons={}" in lines[0]
    assert lines[0].endswith("n_opaque=0")

    # The honest control is the PRE-ADOPTION plugin: the same pack, wired,
    # reporting no coverage (exactly what shipped before this adoption). Under
    # the declaration that lane is could-not-conclude naming "4 of 4"; with
    # the declaration removed, the same lane is GREEN — the formerly-silent
    # scope gap, on record. (A lane that drops the plugin entirely is not a
    # control: typed_checks names it, so that lane was never green.)
    pre = BundleVerifier(plugins=_pre_adoption_plugins()).verify(bundle_dir)
    assert pre.ok is False
    assert any(
        r.check_name == "claimset_coverage" and "4 of 4" in r.detail
        for r in pre.reasons
    ), [(r.code, r.detail) for r in pre.reasons]

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("claimset")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    undeclared = BundleVerifier(plugins=_pre_adoption_plugins()).verify(bundle_dir)
    assert undeclared.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in undeclared.failures
    ]
    assert any(
        d.startswith("claimset: not declared")
        for d in undeclared.completeness.disclosures
    )


def test_streaming_minimal_claimset_ratchet_all_covered_fields_flip(
    tmp_path: Path,
) -> None:
    """Evidence-grade leg: a value mutation of every covered claim field flips
    the verdict via the pack's OWN comparison (never via file-sha — the
    battery re-pins). All four elements are covered; there is no residual."""
    sys.path.insert(0, str(_PKG_ROOT / "tests"))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    bundle_dir = tmp_path / "streaming_bundle"
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
    assert not report.skipped, [(o.element, o.detail) for o in report.skipped]
    assert not report.inconclusive, [(o.element, o.detail) for o in report.inconclusive]
    assert {o.element for o in report.flipped} == {
        "checkpoint:[].aggregate",
        "checkpoint:[].event_count",
        "checkpoint:[].window_end_ms",
        "checkpoint:[].window_start_ms",
    }
    assert report.excused == ()
    for outcome in report.flipped:
        assert "BAD_FILE_SHA" not in outcome.reason_codes
        assert any(
            "[STREAMING_REDER_FAIL]" in detail for _code, detail in outcome.reasons
        ), (outcome.element, outcome.reasons)


# ---------------------------------------------------------------------------
# Fresh-context adversarial pass witnesses (§11) — a green battery is not the
# end of an adoption; these try what the per-cell ratchet does not: a
# duplicate row, a deleted (not merely null) key, and a forged INPUT with the
# payload honestly recomputed. The pack's opt-out-under-declaration case (the
# fourth named attack) has no witness here: streaming_re_derivation.py's
# _verify() has no opt-out branch — every non-error exit is a full compare.
# ---------------------------------------------------------------------------


def test_streaming_minimal_duplicate_window_row_is_refused(tmp_path: Path) -> None:
    """Red-team witness: replace the honest window 1 with a second copy of
    window 0 (array length unchanged, still 2). The comparator is positional
    (zip over document order, not id-indexed), so there is no dict-shadowing
    hole to place a forged row behind — the duplicate itself IS the mismatch
    at index 1."""
    bundle_dir = tmp_path / "streaming_dup_row"
    build(bundle_dir)

    checkpoint_path = bundle_dir / "payload" / "checkpoint.json"
    windows = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    assert len(windows) == 2
    forged = [windows[0], dict(windows[0])]
    checkpoint_path.write_text(json.dumps(forged, indent=2), encoding="utf-8")
    _repin(bundle_dir, "payload/checkpoint.json")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "[STREAMING_REDER_FAIL]" in combined and "window index 1" in combined, (
        combined
    )


def test_streaming_minimal_deleted_key_is_refused_not_vacuous(tmp_path: Path) -> None:
    """Claims-lens witness: DELETE (not null) the 'aggregate' key from window
    0. Every field in this schema is a required int, never legitimately
    null, so the derived value is never None and `d_val != b_val` cannot
    become a vacuous None == None comparison the way credit_scoring's
    optional apr_pct once could."""
    bundle_dir = tmp_path / "streaming_deleted_key"
    build(bundle_dir)

    checkpoint_path = bundle_dir / "payload" / "checkpoint.json"
    windows = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    del windows[0]["aggregate"]
    checkpoint_path.write_text(json.dumps(windows, indent=2), encoding="utf-8")
    _repin(bundle_dir, "payload/checkpoint.json")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False
    combined = " ".join(f.detail for f in result.failures)
    assert "[STREAMING_REDER_FAIL]" in combined and "aggregate" in combined, combined


def test_streaming_minimal_forged_input_honestly_recomputed_stays_ok(
    tmp_path: Path,
) -> None:
    """Documents the stated README limit, with an executable witness: forge
    events/stream.jsonl (event 0's value), recompute payload/checkpoint.json
    HONESTLY against the forgery, re-pin both files. Unlike
    credit_scoring_minimal (which binds applicants/ to a registered bureau
    snapshot), this bundle carries no second, independently sourced copy of
    the event stream to check events/stream.jsonl against — the comparator
    binds the payload to the events, never the events to anything outside
    the bundle. The verdict stays OK with a receipt IDENTICAL to the honest
    one (the receipt is an accounting identity over covered/residual
    elements, not a value fingerprint) — a genuine, unresolved scope limit
    of this claim-field coverage gate, not a defect this adoption can fix
    without inventing an artifact the bundle's data model does not have."""
    import re

    honest_bundle = tmp_path / "streaming_honest"
    build(honest_bundle)
    honest_result = _make_verifier().verify(honest_bundle)
    honest_receipt = next(
        d for d in honest_result.completeness.disclosures if d.startswith("claimset:")
    )

    bundle_dir = tmp_path / "streaming_forged_input"
    build(bundle_dir)
    stream_path = bundle_dir / "events" / "stream.jsonl"
    lines = [
        line
        for line in stream_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = [json.loads(line) for line in lines]
    events[0]["value"] = 99999
    new_stream = "\n".join(json.dumps(e, separators=(",", ":")) for e in events) + "\n"
    stream_path.write_text(new_stream, encoding="utf-8")

    from examples.streaming_minimal._build_bundle import _run_windowing, _SPEC

    windows = _run_windowing(events, _SPEC)
    checkpoint_path = bundle_dir / "payload" / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(windows, indent=2), encoding="utf-8")

    _repin(bundle_dir, "events/stream.jsonl")
    _repin(bundle_dir, "payload/checkpoint.json")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is True, [
        f"[{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    ]
    forged_receipt = next(
        d for d in result.completeness.disclosures if d.startswith("claimset:")
    )

    # receipt_sha is the same because it is an accounting identity (which
    # elements are covered / excused), not a fingerprint of field values.
    def _strip_sha(s: str) -> str:
        return re.sub(r"receipt_sha=[0-9a-f]+", "receipt_sha=<redacted>", s)

    assert _strip_sha(forged_receipt) == _strip_sha(honest_receipt)


def test_deleted_comparison_is_could_not_conclude(tmp_path: Path) -> None:
    """The drift test: copy the pilot directory to scratch, delete ONE
    comparison from the copied pack (drop `event_count` from the per-window
    key tuple — its `!=` check and its `compared.add` go together), import
    the copied plugin (it runs the copied pack via `Path(__file__).parent`),
    forge that field in a fresh bundle, re-pin, verify with the copied plugin
    in the pilot's wired set: the verdict must refuse to conclude NAMING the
    field, never stay OK. Control: the real plugin refuses the forgery under
    the pack's own tag."""
    import importlib.util
    import shutil

    src_dir = _PKG_ROOT / "examples" / "streaming_minimal"
    copy_dir = tmp_path / "pilot_copy"
    shutil.copytree(
        src_dir, copy_dir, ignore=shutil.ignore_patterns("__pycache__", "tests", "*.pyc")
    )
    pack = copy_dir / "streaming_re_derivation.py"
    text = pack.read_text(encoding="utf-8")
    old = '("window_start_ms", "window_end_ms", "aggregate", "event_count")'
    assert text.count(old) == 1
    pack.write_text(
        text.replace(old, '("window_start_ms", "window_end_ms", "aggregate")'),
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "streaming_check_drift_copy", copy_dir / "StreamingReDerivationCheck.py"
    )
    assert spec is not None and spec.loader is not None
    drift_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(drift_mod)

    bundle = tmp_path / "bundle"
    build(bundle)
    cp_path = bundle / "payload" / "checkpoint.json"
    rows = json.loads(cp_path.read_text(encoding="utf-8"))
    rows[0]["event_count"] = int(rows[0]["event_count"]) + 7
    cp_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    _repin(bundle, "payload/checkpoint.json")

    drifted = BundleVerifier(
        plugins=[
            SpecShaPinCheck(),
            FileIntegrityManySmall(),
            drift_mod.StreamingReDerivationCheck(),
        ]
    ).verify(bundle)
    assert drifted.ok is False
    assert any(
        r.check_name == "claimset_coverage"
        and "1 of 4" in r.detail
        and "checkpoint:[].event_count" in r.detail
        for r in drifted.reasons
    ), [(r.code, r.detail) for r in drifted.reasons]

    control = _make_verifier().verify(bundle)
    assert control.ok is False
    assert any("[STREAMING_REDER_FAIL]" in f.detail for f in control.failures), [
        f.detail for f in control.failures
    ]


def test_checkpoint_fields_are_compared_as_typed_json(tmp_path: Path) -> None:
    """`false` is not `0`, `-300.0` is not `-300`, `6e4` is not `60000`: a
    retyped checkpoint cell is refused under the pack's own tag, never
    absorbed by Python equality (found by the wave-2 red-team lens)."""
    bundle = tmp_path / "bundle"
    build(bundle)
    cp_path = bundle / "payload" / "checkpoint.json"
    honest = json.loads(cp_path.read_text(encoding="utf-8"))
    for key, forged in (
        ("window_start_ms", False),
        ("aggregate", float(honest[0]["aggregate"])),
        ("event_count", float(honest[0]["event_count"])),
    ):
        rows = json.loads(json.dumps(honest))
        rows[0][key] = forged
        cp_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        _repin(bundle, "payload/checkpoint.json")
        result = _make_verifier().verify(bundle)
        assert result.ok is False, (key, forged)
        assert any(
            "[STREAMING_REDER_FAIL]" in f.detail and key in f.detail for f in result.failures
        ), [(key, forged, f.detail) for f in result.failures]
