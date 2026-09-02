"""tests/test_streaming_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/streaming_minimal.

Representative output: the per-window aggregate list in payload/checkpoint.json
(the ordered list of window dicts {window_start_ms, window_end_ms, aggregate,
event_count}), recomputed by replaying the committed event stream
(events/stream.jsonl) through event-time tumbling-window aggregation per the
committed windowing spec (spec/segmentation.json: window_size_ms + aggregator +
late_event_policy). Comparator: `exact` (no params; ordered-list element-wise
equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (perturb one window's aggregate) -> FAIL
     (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate one event's value so its window aggregate differs)
     -> FAIL (RE_DERIVATION_MISMATCH); manifest SHA re-aligned so FileIntegrity
     does not fire first.
  4. No auditor anchor while the bundle declares outputs -> could-not-
     conclude (AnchorNotSupplied -> VERIFIER_INCOMPLETE, clean-ERROR;
     never a REJECT — nothing was shown about the bundle).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id,
     but a DIFFERENT primitive_id -> different bytes -> different SHA). For an
     `exact` comparator there is no epsilon to weaken, so the anchor defense is
     demonstrated via a substituted-spec SHA the anchor does not list ->
     fail-closed (AnchorViolation).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "streaming_minimal"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# The pilot's recompute module + spec-pinned harness are loaded by path so this
# test does not depend on cwd.
_load("streaming_recompute", _PILOT_DIR / "streaming_recompute.py")
_spc = _load("streaming_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a per-window aggregate list with the first window's aggregate
    # perturbed by 1 — a different ordered list than the honest re-derivation.
    honest = _spc._honest_aggregates(_spc.build_spec_pinned(tmp_path / "honest"))
    assert len(honest) >= 1
    tampered = copy.deepcopy(honest)
    tampered[0]["aggregate"] = tampered[0]["aggregate"] + 1
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED event stream so one window's
    # aggregate re-derives differently than the (honest) claimed value. Re-align
    # the manifest SHA so FileIntegrity (step-2/3) does not fire first — isolate
    # the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    stream_path = bundle_dir / "events" / "stream.jsonl"
    raw = stream_path.read_bytes()
    lines = raw.splitlines()
    # Mutate the first event's value (event_id=0, timestamp_ms=0 -> window 0) so
    # window 0's summed aggregate changes; the claimed checkpoint stays honest.
    first = json.loads(lines[0])
    first["value"] = first["value"] + 1000
    lines[0] = json.dumps(first, separators=(",", ":")).encode("utf-8")
    new_bytes = b"\n".join(lines) + b"\n"
    stream_path.write_bytes(new_bytes)

    # events/stream.jsonl is recorded in manifest.files; re-align its SHA so
    # FileIntegrity does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["events/stream.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")

    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_no_anchor_fails_closed(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    result = _spc.make_verifier(anchor=None).verify(bundle_dir)
    assert not result.ok
    # AnchorNotSupplied, split out of AnchorViolation (auditor-entry ADR): "no
    # auditor anchor was supplied" is the VERIFIER's own incapacity, so the
    # verdict is a clean-ERROR (could-not-conclude) leg and NEVER a REJECT —
    # nothing was shown about the bundle. The artifact-side anchor failure (a
    # spec whose SHA the anchor does not list) keeps AnchorViolation + REJECT;
    # see the substituted/weakened-spec test in this file.
    assert result.state.value == "ERROR", (result.state, _reason_codes(result))
    _anchor = [
        r for r in result.reasons if r.check_name == "spec_pinned_dispatch:anchor"
    ]
    assert [r.code for r in _anchor] == ["VERIFIER_INCOMPLETE"], [
        (r.check_name, r.code) for r in result.reasons
    ]
    assert "no auditor SpecAnchor was supplied" in _anchor[0].detail, _anchor[0].detail


def test_substituted_spec_fails_closed(tmp_path):
    # §4a attack (exact-comparator variant): producer ships a spec the auditor did
    # NOT anchor. Same spec_id, but a DIFFERENT primitive_id -> different bytes ->
    # different SHA. The auditor anchor is computed from the COMMITTED spec, so the
    # substituted spec's SHA is not anchored -> fail-closed (no `exact` epsilon to
    # weaken; the anchor defense is the SHA the anchor does not list).
    other_spec = json.dumps(
        {
            "spec_id": "streaming.v1",
            "types": {
                "streaming_window_aggregates": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=["tampered"],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
