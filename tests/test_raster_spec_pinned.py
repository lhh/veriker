"""tests/test_raster_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/raster_minimal.

Representative output: the in_polygon_cell_count integer in payload/zonal_result.json,
recomputed by ray-casting point-in-polygon over the committed int8 raster grid
(raster/grid.bin, 32x32 little-endian signed) and the polygon vertices in
spec/zonal_query.json — each cell center (c+0.5, r+0.5) tested against the polygon
via a horizontal-ray crossing count, in-polygon cells counted. Comparator: `exact`
(no params; integer equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (count off by one) -> FAIL (RE_DERIVATION_MISMATCH).
  3. Tampered input (shrink the committed polygon so the ray-cast re-derives a
     DIFFERENT count than the honest claimed value) -> FAIL
     (RE_DERIVATION_MISMATCH). The polygon lives in spec/zonal_query.json, which
     FileIntegrity Pass-3 skips, so no manifest SHA re-align is needed for it;
     for completeness we also demonstrate a raster/grid.bin mutation path with
     its manifest SHA re-aligned does NOT change the count (count is geometric),
     so the polygon mutation is the load-bearing input tamper.
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

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "raster_minimal"
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
_load("raster_recompute", _PILOT_DIR / "raster_recompute.py")
_spc = _load("raster_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims an in_polygon_cell_count off by one — a different integer
    # than the honest re-derivation.
    honest = _spc._honest_count(_spc.build_spec_pinned(tmp_path / "honest"))
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=honest + 1
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then shrink the COMMITTED polygon so the ray-cast re-derives a
    # different in_polygon_cell_count than the (honest) claimed value. The polygon
    # is in spec/zonal_query.json, which FileIntegrity Pass-3 skips, so the
    # re-derivation mismatch is isolated.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    spec_path = bundle_dir / "spec" / "zonal_query.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    # Shrink the L-shape's tall-left rectangle bottom edge from row 28 -> row 8,
    # removing many in-polygon cells -> the count changes.
    spec["polygon"] = [
        [4, 4],
        [20, 4],
        [20, 12],
        [12, 12],
        [12, 8],
        [4, 8],
    ]
    # spec_files records this under its basename and FileIntegrity skips spec/; the
    # spec-pinned verifier reads the polygon live from the committed bytes, so the
    # re-derivation diverges from the honest claim. Re-align the spec_files SHA so
    # the auditor's spec/zonal_query.json record stays internally consistent.
    new_spec_bytes = json.dumps(spec, indent=2).encode("utf-8")
    spec_path.write_bytes(new_spec_bytes)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["spec_files"]["zonal_query.json"] = hashlib.sha256(new_spec_bytes).hexdigest()
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
            "spec_id": "raster.v1",
            "types": {
                "raster_in_polygon_cell_count": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=-1,
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
