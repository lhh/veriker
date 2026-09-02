"""tests/test_ml_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/ml_minimal.

Representative output: the list of predicted class indices (the integer argmax per
input sample) drawn from payload/predictions.json, recomputed in-process by
re-executing an integer-only linear classifier over the committed weights
(weights/model.json) and inputs (inputs/features.json): logits[k] = sum(W[k][j]*x[j])
+ b[k], predicted_class = argmax(logits) with lowest-index tie-break. Comparator:
`exact` (no params; ordered-list element-wise equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (a flipped class index in the claimed list) -> FAIL
     (RE_DERIVATION_MISMATCH).
  3. Tampered input (mutate a feature sample so its argmax flips) -> FAIL
     (RE_DERIVATION_MISMATCH); manifest SHA re-aligned so FileIntegrity does not
     fire first.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "ml_minimal"
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
_load("ml_recompute", _PILOT_DIR / "ml_recompute.py")
_spc = _load("ml_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a class list with one index flipped to a different valid class
    # — a different ordered list than the honest re-derivation.
    honest = _spc._honest_classes(_spc.build_spec_pinned(tmp_path / "honest"))
    assert len(honest) >= 1
    tampered = list(honest)
    tampered[0] = (tampered[0] + 1) % 3  # n_classes == 3; force a different index
    assert tampered != honest
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "RE_DERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb ONE committed feature sample so its argmax flips —
    # the re-derivation diverges from the (honest) claimed class list. Re-align the
    # manifest SHA so FileIntegrity (step-2/3) does not fire first.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")

    model = json.loads((bundle_dir / "weights" / "model.json").read_bytes())
    features_path = bundle_dir / "inputs" / "features.json"
    feature_vectors = json.loads(features_path.read_bytes())

    from ml_recompute import compute_prediction_classes  # noqa: PLC0415

    honest_classes = compute_prediction_classes(model, feature_vectors)

    # Find a replacement feature vector for sample 0 whose argmax differs from the
    # honest class, by sweeping a single feature coordinate over a wide range.
    n_features = int(model["n_features"])
    target_idx = 0
    found = False
    for coord in range(n_features):
        for val in range(-100, 101):
            trial = list(feature_vectors)
            sample = list(trial[target_idx])
            sample[coord] = val
            trial[target_idx] = sample
            new_classes = compute_prediction_classes(model, trial)
            if new_classes[target_idx] != honest_classes[target_idx]:
                feature_vectors = trial
                found = True
                break
        if found:
            break
    assert found, "could not find a feature perturbation that flips the argmax"

    new_bytes = (
        json.dumps(feature_vectors, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    features_path.write_bytes(new_bytes)

    # inputs/features.json is recorded in manifest.files; re-align its SHA so
    # FileIntegrity does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/features.json"] = hashlib.sha256(new_bytes).hexdigest()
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
            "spec_id": "ml.v1",
            "types": {
                "ml_prediction_classes": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[0],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
