"""spec_pinned_check.py — self-contained Axis-2 spec-pinned dispatch for
pharmacophore_fit_minimal.

RATIONAL_BAND_MIGRATION.md §4b.3: a GREENFIELD Tier-2 new-claim slice added to
the existing pharmacophore_fit_minimal pilot. This is ADDITIVE: the legacy
bundle (_build_bundle.py + PharmacophoreFitReDerivationCheck.py +
pharmacophore_fit_re_derivation.py) and its verify.py / root-level test
(tests/test_pharmacophore_fit_minimal.py) are UNTOUCHED — the spec-pinned
bundle is built to a fresh directory here, so no committed manifest anywhere
in this pilot gains an `outputs` array from this file alone.

What it demonstrates:
  - The auditor pins the binding (type -> primitive_id + comparator) in a
    SHA-anchored spec (spec_pinned/pharmacophore_fit.spec.json).
  - The verifier re-derives TWO representative outputs IN-PROCESS via the
    registered primitives (pure stdlib — fractions only) as EXACT rationals,
    and compares with the `rational_sqrt_band` comparator (epsilon=1e-6 each).
    No subprocess, no bundle-supplied code. This is the SECOND consumer
    family of `rational_sqrt_band` (the first is the FEA pilot's
    witness+certificate posture).
  - Honest bundle -> PASS; tampered claimed value(s) or tampered input ->
    FAIL (RE_DERIVATION_MISMATCH); no auditor anchor -> fail-closed
    (AnchorViolation); a rebound output type (work-set pin violation) ->
    fail-closed (ROLE_POLICY_VIOLATION); a dropped, extra or duplicated
    output -> fail-closed (WORK_SET_VIOLATION).

The legacy builder runs the full float `run_spatial_fit` pipeline to stage
inputs/ + payload/spatial_fit_result.json (the complete per-candidate
ledger); the spec-pinned claims are the auditor's own recompute of TWO
representative quantities drawn from that SAME float pipeline's output for
the best-fit (rank-1) candidate: its aggregate RMSD, and its first
(alphabetically-sorted pharmacophore_feature_id) paired distance. See
pharmacophore_recompute.py's module docstring for the full representative-
output-choice rationale.

Usage:
    python examples/pharmacophore_fit_minimal/spec_pinned_check.py
        # build a spec-pinned bundle in a temp dir + verify under the anchor
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util as _ilu
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


def _load_legacy_build():
    """Load the pilot's legacy `build()` by PATH under a pilot-unique module
    name. A bare `import _build_bundle` would collide across pilots in a
    shared interpreter (every pilot ships a _build_bundle.py)."""
    spec = _ilu.spec_from_file_location(
        "pharmacophore_fit_minimal__legacy_build_bundle", _HERE / "_build_bundle.py"
    )
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build


_build_legacy_bundle = _load_legacy_build()

_RMSD_OUTPUT_ID = "pharmacophore_best_fit_rmsd"
_RMSD_TYPE_KEY = "pharmacophore_best_fit_rmsd"
_DIST_OUTPUT_ID = "pharmacophore_best_fit_distance"
_DIST_TYPE_KEY = "pharmacophore_best_fit_distance"
_SPEC_SRC = _HERE / "spec_pinned" / "pharmacophore_fit.spec.json"
_SPEC_BASENAME = _SPEC_SRC.name


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _best_fit_ledger_entry(out_dir: Path) -> dict:
    """Read the legacy builder's payload and return the rank==1 ledger entry
    (the best-fit candidate) — the SAME float pipeline result the honest
    claims are drawn from."""
    result = json.loads((out_dir / "payload" / "spatial_fit_result.json").read_bytes())
    for entry in result["ledger"]:
        if entry.get("rank") == 1:
            return entry
    raise AssertionError("no rank==1 entry in spatial_fit_result.json ledger")


def build_spec_pinned(
    out_dir: Path,
    *,
    rmsd_claimed_override: object = None,
    distance_claimed_override: object = None,
    spec_bytes_override: bytes | None = None,
    swap_output_types: bool = False,
) -> Path:
    """Build a spec-pinned pharmacophore_fit bundle in out_dir. Reuses the
    legacy builder for inputs/ + payload/, then overlays the Axis-2 shape: an
    auditor spec under spec/, two producer claimed-value files under
    outputs/, two manifest.outputs entries, and a typed_checks set matching
    the spec-pinned verifier's plugin set.

    The *_override hooks let tests inject attacks (tampered claim(s), weak
    spec, rebound output type).

    Returns the bundle directory.
    """
    out_dir = out_dir.resolve()
    _build_legacy_bundle(out_dir)

    spec_dir = out_dir / "spec"
    outputs_dir = out_dir / "outputs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # --- Auditor spec under spec/<basename> (committed bytes unless overridden). ---
    spec_bytes = (
        spec_bytes_override
        if spec_bytes_override is not None
        else _SPEC_SRC.read_bytes()
    )
    (spec_dir / _SPEC_BASENAME).write_bytes(spec_bytes)

    # --- Honest claimed values = the producer's own float pipeline (the
    # legacy builder already ran it to produce payload/spatial_fit_result.json).
    best = _best_fit_ledger_entry(out_dir)
    rmsd_claimed: object = best["rmsd"]
    dist_claimed: object = best["pair_records"][0]["distance"]
    if rmsd_claimed_override is not None:
        rmsd_claimed = rmsd_claimed_override
    if distance_claimed_override is not None:
        dist_claimed = distance_claimed_override

    rmsd_bytes = json.dumps({"value": rmsd_claimed}, indent=2).encode("utf-8")
    dist_bytes = json.dumps({"value": dist_claimed}, indent=2).encode("utf-8")
    (outputs_dir / f"{_RMSD_OUTPUT_ID}.json").write_bytes(rmsd_bytes)
    (outputs_dir / f"{_DIST_OUTPUT_ID}.json").write_bytes(dist_bytes)

    rmsd_type = _DIST_TYPE_KEY if swap_output_types else _RMSD_TYPE_KEY
    dist_type = _RMSD_TYPE_KEY if swap_output_types else _DIST_TYPE_KEY

    # --- Overlay the manifest: outputs[] + spec_files + files + typed_checks. ---
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"outputs/{_RMSD_OUTPUT_ID}.json"] = _sha256(rmsd_bytes)
    manifest["files"][f"outputs/{_DIST_OUTPUT_ID}.json"] = _sha256(dist_bytes)
    # Rebuild spec_files to carry ONLY the auditor spec (the anchor is keyed on
    # spec_id -> sha of this file).
    manifest["spec_files"] = {_SPEC_BASENAME: _sha256(spec_bytes)}
    # Drop the legacy PHARMACOPHORE_FIT dispatch_records row: it carries §C15/
    # §C14 obligations (DispatchRecordWellformedCheck / StampLatticeCheck) that
    # this spec-pinned surface does not wire (only FileIntegrityManySmall +
    # step-5 dispatch). Leaving the row in would make the verifier correctly
    # refuse with VERIFIER_INCOMPLETE for an obligation this surface never
    # intended to audit — this overlay is scoped to the two spec-pinned claims.
    manifest.pop("dispatch_records", None)
    manifest["outputs"] = [
        {
            "output_id": _RMSD_OUTPUT_ID,
            "type": rmsd_type,
            "conforms_to": f"spec/{_SPEC_BASENAME}",
        },
        {
            "output_id": _DIST_OUTPUT_ID,
            "type": dist_type,
            "conforms_to": f"spec/{_SPEC_BASENAME}",
        },
    ]
    # The spec-pinned verifier runs FileIntegrityManySmall + step-5 dispatch
    # only; typed_checks must match the registered plugin set.
    manifest["typed_checks"] = ["file_integrity_many_small"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_dir


def anchor_from_committed_spec():
    """Build the auditor SpecAnchor from the COMMITTED source spec bytes."""
    from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: PLC0415

    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: _sha256(raw)})


# §4a.3/[A3] work-set pins: pin each output_id to its intended type so a
# producer cannot rebind an output_id's declared type to the sibling type
# (both types share the SAME comparator kind+params — rational_sqrt_band,
# epsilon=1e-6 — so monotone-strictness alone would not catch a type swap
# between them; the work-set's per-output pin is the defense for THAT
# rebinding attack, and its bijection for the drop/extra/duplicate ones).
_PINS = {
    _RMSD_OUTPUT_ID: _RMSD_TYPE_KEY,
    _DIST_OUTPUT_ID: _DIST_TYPE_KEY,
}


def _work_set():
    """The auditor WORK-SET over _PINS: both claims must arrive, exactly once,
    each under its pinned type; anything else declared is refused
    (WORK_SET_VIOLATION). SELF_AUTHORED — hand-written here, not enumerated
    from an artifact the anchor pins."""
    from audit_bundle.work_set import WorkSet  # noqa: PLC0415

    return WorkSet.declare(
        _PINS,
        source="pharmacophore_fit_minimal spec_pinned_check: the two "
        "representative claims (best-fit RMSD, best-fit first paired distance)",
        provenance="SELF_AUTHORED",
    )


def make_verifier(anchor=None, *, work_set="default"):
    """Construct the spec-pinned verifier: FileIntegrity + step-5 dispatch
    under the auditor anchor + the auditor work-set. Registers the in-dir
    primitives first. Pass work_set=None for the unconfigured (fallback-only)
    verifier the rebinding-through cell needs."""
    if work_set == "default":
        work_set = _work_set()
    from audit_bundle.plugins.file_integrity_many_small import (  # noqa: PLC0415
        FileIntegrityManySmall,
    )
    from audit_bundle.rederivation.registry import register_primitive  # noqa: PLC0415
    from audit_bundle.verifier import BundleVerifier  # noqa: PLC0415
    from pharmacophore_recompute import (  # noqa: PLC0415
        PharmacophoreBestFitDistanceRecompute,
        PharmacophoreBestFitRmsdRecompute,
    )

    register_primitive(PharmacophoreBestFitRmsdRecompute())
    register_primitive(PharmacophoreBestFitDistanceRecompute())
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor,
        work_set=work_set,
    )


def main() -> int:
    argparse.ArgumentParser(
        description="Build + spec-pinned-verify the pharmacophore_fit_minimal exemplar"
    ).parse_args()
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = build_spec_pinned(Path(td) / "bundle")
        anchor = anchor_from_committed_spec()
        result = make_verifier(anchor).verify(bundle_dir)
        if result.ok:
            print("PASS  pharmacophore_fit_minimal  (spec-pinned dispatch)")
            return 0
        print(
            "FAIL  pharmacophore_fit_minimal  (spec-pinned dispatch)", file=sys.stderr
        )
        for f in result.failures:
            print(f"    [{f.check_name}] {f.reason_code}: {f.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
