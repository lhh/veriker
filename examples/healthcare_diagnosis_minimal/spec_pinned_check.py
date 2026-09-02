"""spec_pinned_check.py — self-contained Axis-2 spec-pinned dispatch for healthcare_diagnosis_minimal.

Per-dir migration of the healthcare_diagnosis_minimal pilot onto the disclosed
spec-pinned, auditor-anchored, in-process recompute-then-compare method (S0). This
is ADDITIVE: the legacy bundle (_build_bundle.py + HealthcareDiagnosisReDerivationCheck.py
+ re_derive/healthcare_diagnosis_pack.py) and its verify.py / test are untouched, and
no committed manifest gains an `outputs` array — the spec-pinned bundle is built to a
fresh temp directory here, so the substrate's "0 committed manifests declare outputs"
inertness invariant is preserved.

What it demonstrates:
  - The auditor pins the binding (type -> primitive_id + comparator) in a
    SHA-anchored spec (spec_pinned/healthcare_diagnosis.spec.json).
  - The verifier re-derives the representative output (the ordered list of icd10_code
    values from payload/diagnosis.json — categorical codes only, no confidence float)
    IN-PROCESS via the registered primitive, and compares with the generic `exact`
    comparator (element-wise list equality). No subprocess, no bundle-supplied code.
  - Honest bundle -> PASS; tampered claimed value or tampered input -> FAIL
    (RE_DERIVATION_MISMATCH); no auditor anchor -> fail-closed (AnchorViolation).

TIER-2 CONFIDENCE SLICE (rational-band wave, RATIONAL_BAND_MIGRATION.md §4b.2):
`build_spec_pinned` ALSO overlays one `healthcare_diagnosis_confidence` output per
FIRED candidate (output_id "confidence:<icd10_code>") whenever that type is present
in the spec bytes in use — the same "overlay only when the type is present" pattern
the other multi-leg pilots use. Because this
is additive-by-presence, the pre-existing tests in
tests/test_healthcare_diagnosis_spec_pinned.py now implicitly also build and verify
the confidence outputs, with no change to their bodies (a deliberate, reported
harness extension — see that test file's module docstring). Each honest confidence
claim is read directly from payload/diagnosis.json's own "confidence" field — i.e.
straight off the producer's OWN float pipeline (_build_bundle.py's
round(severity_sum * confidence_weight, 6)), never from the new exact primitive.

Usage:
    python examples/healthcare_diagnosis_minimal/spec_pinned_check.py
        # build a spec-pinned bundle in a temp dir + verify under the anchor
"""

from __future__ import annotations

import argparse
import hashlib
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

# Legacy builder (lays down inputs/payload/re_derive/manifest) + the shared
# canonical compute function (imported standalone — no audit_bundle needed).
# Load the pilot's legacy builder by PATH under a pilot-unique module name.
# A bare `import _build_bundle` collides across pilots in a shared interpreter
# (every pilot ships a _build_bundle.py), caching the wrong builder.
import importlib.util as _ilu  # noqa: E402


def _load_legacy_build():
    _s = _ilu.spec_from_file_location(
        "healthcare_diagnosis_minimal__legacy_build_bundle", _HERE / "_build_bundle.py"
    )
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return _m.build


def _load_legacy_build_module():
    """Same loader, but returns the whole module (not just .build) — used to
    read the fixture's _RULES constant so the confidence work-set pins are
    derived from the SAME source-of-truth list, not a hand-duplicated one."""
    _s = _ilu.spec_from_file_location(
        "healthcare_diagnosis_minimal__legacy_build_bundle_mod",
        _HERE / "_build_bundle.py",
    )
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return _m


_build_legacy_bundle = _load_legacy_build()
from healthcare_diagnosis_recompute import compute_icd10_codes  # noqa: E402

_OUTPUT_ID = "healthcare_diagnosis_codes"
_TYPE_KEY = "healthcare_diagnosis_codes"
_CONFIDENCE_TYPE_KEY = "healthcare_diagnosis_confidence"
_CONFIDENCE_OUTPUT_PREFIX = "confidence:"
_SPEC_SRC = _HERE / "spec_pinned" / "healthcare_diagnosis.spec.json"
_SPEC_BASENAME = _SPEC_SRC.name


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _honest_codes(out_dir: Path) -> list[str]:
    """Auditor-side canonical recompute of the honest icd10_code list from the
    built bundle's committed inputs."""
    symptoms = json.loads((out_dir / "inputs" / "symptoms.json").read_bytes())
    rules = json.loads((out_dir / "inputs" / "rules.json").read_bytes())
    return compute_icd10_codes(symptoms, rules)


def build_spec_pinned(
    out_dir: Path,
    *,
    claimed_override: object = None,
    spec_bytes_override: bytes | None = None,
    confidence_overrides: "dict[str, object] | None" = None,
    omit_confidence_codes: "list[str] | tuple[str, ...] | None" = None,
    extra_confidence_outputs: "dict[str, object] | None" = None,
    type_overrides: "dict[str, str] | None" = None,
) -> Path:
    """Build a spec-pinned healthcare-diagnosis bundle in out_dir. Reuses the legacy
    builder for inputs/payload, then overlays the beta shape: an auditor spec under
    spec/, one producer claimed-value file per output under outputs/, matching
    manifest.outputs entries, and a typed_checks set matching the spec-pinned
    verifier's plugin set.

    The legacy builder is called with an explicit temp out_dir (NOT in-place), so it
    writes only the 4 generated artifacts and never re-enumerates the pilot dir —
    the committed pilot stays free of an outputs[] array.

    Tier-2 confidence slice (RATIONAL_BAND_MIGRATION.md §4b.2): when the spec bytes
    in use declare the `healthcare_diagnosis_confidence` type, one output
    "confidence:<icd10_code>" is ALSO overlaid per candidate the legacy builder's
    own payload/diagnosis.json shows as FIRED — claimed straight from that file's
    "confidence" field (the producer's own float pipeline; never the new exact
    primitive). This follows the shared
    "overlay only when the type is present" convention, so a battery spec variant
    that drops the confidence type builds a codes-only bundle.

    The *_override / *_codes / *_outputs hooks let tests inject attacks:
      claimed_override        — tamper the codes claim (back-compat, unchanged).
      spec_bytes_override     — substitute the whole spec (back-compat, unchanged).
      confidence_overrides    — {output_id: claimed_value} to tamper one or more
                                 confidence claims (output_id = "confidence:<code>").
      omit_confidence_codes   — icd10_codes to SELF-CONSISTENTLY drop from the
                                 confidence roster (no file, no manifest entry) —
                                 the coverage-gap RED cell (dispatch's own §4a.4
                                 file<->manifest coverage invariant stays satisfied;
                                 only ConfidenceCoverageCheck sees the gap).
      extra_confidence_outputs — {icd10_code: claimed_value} to ADD a confidence
                                 output for a code beyond the fired roster (e.g. one
                                 that never fires) — the nonexistent-code
                                 fail-closed RED cell.
      type_overrides          — {output_id: type_key} to REBIND an output's
                                 declared type away from its natural one (e.g. a
                                 confidence output claiming the codes type) — the
                                 work-set pin rebinding-RED cell.

    Returns the bundle directory.
    """
    out_dir = out_dir.resolve()
    _build_legacy_bundle(out_dir)

    spec_dir = out_dir / "spec"
    outputs_dir = out_dir / "outputs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # --- Auditor spec under spec/<basename> (committed bytes, unless overridden). ---
    spec_bytes = (
        spec_bytes_override
        if spec_bytes_override is not None
        else _SPEC_SRC.read_bytes()
    )
    (spec_dir / _SPEC_BASENAME).write_bytes(spec_bytes)
    spec_sha = _sha256(spec_bytes)
    types_present = json.loads(spec_bytes).get("types", {})

    type_overrides = type_overrides or {}
    manifest_outputs: list[dict] = []
    files_overlay: dict[str, str] = {}

    def _write_output(output_id: str, natural_type: str, claimed: object) -> None:
        type_key = type_overrides.get(output_id, natural_type)
        claim_bytes = json.dumps({"value": claimed}, indent=2).encode("utf-8")
        (outputs_dir / f"{output_id}.json").write_bytes(claim_bytes)
        files_overlay[f"outputs/{output_id}.json"] = _sha256(claim_bytes)
        manifest_outputs.append(
            {
                "output_id": output_id,
                "type": type_key,
                "conforms_to": f"spec/{_SPEC_BASENAME}",
            }
        )

    # --- codes claim: honest = the auditor's own canonical recompute. ---
    if _TYPE_KEY in types_present:
        claimed_codes = _honest_codes(out_dir)
        if claimed_override is not None:
            claimed_codes = claimed_override
        _write_output(_OUTPUT_ID, _TYPE_KEY, claimed_codes)

    # --- confidence claims: honest = the legacy builder's OWN payload field. ---
    if _CONFIDENCE_TYPE_KEY in types_present:
        candidates = json.loads((out_dir / "payload" / "diagnosis.json").read_bytes())
        omit = set(omit_confidence_codes or ())
        confidence_overrides = confidence_overrides or {}
        for cand in candidates:
            code = cand["icd10_code"]
            if code in omit:
                continue
            output_id = f"{_CONFIDENCE_OUTPUT_PREFIX}{code}"
            claimed = confidence_overrides.get(output_id, cand["confidence"])
            _write_output(output_id, _CONFIDENCE_TYPE_KEY, claimed)
        for code, claimed in (extra_confidence_outputs or {}).items():
            output_id = f"{_CONFIDENCE_OUTPUT_PREFIX}{code}"
            _write_output(output_id, _CONFIDENCE_TYPE_KEY, claimed)

    # --- Overlay the manifest: outputs[] + spec_files + files + typed_checks. ---
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].update(files_overlay)
    # Record the auditor binding spec under its basename (FileIntegrity Pass-3
    # skips spec/); the spec-pinned verifier resolves the auditor spec by basename.
    manifest.setdefault("spec_files", {})
    manifest["spec_files"][_SPEC_BASENAME] = spec_sha
    manifest["outputs"] = manifest_outputs
    # The spec-pinned verifier runs FileIntegrityManySmall + step-5 dispatch only;
    # typed_checks must match the registered plugin set (verifier enforces this).
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


def make_verifier(anchor=None):
    """Construct the spec-pinned verifier: FileIntegrity + the confidence
    coverage cross-check + step-5 dispatch under the auditor anchor. Registers
    the in-dir primitives first.

    work_set (§4a.3, rational-band wave [A3]; the auditor WORK-SET since
    2026-09-01): the auditor pins output_id -> required type for EVERY output
    this pilot can produce — the codes claim plus one entry per icd10_code the
    fixture's own _RULES define (derived from _load_legacy_build_module()._RULES,
    not hand-duplicated, so the set cannot silently drift from the fixture).
    A manifest that binds a confidence output_id to the codes type (or vice
    versa) is a ROLE_POLICY_VIOLATION, fail-closed, before dispatch even
    resolves a primitive; a manifest that drops one of these outputs, adds one
    the set does not name, or declares one twice is a WORK_SET_VIOLATION.
    SELF_AUTHORED: the list is written by this harness (out of the fixture's
    rule table), not enumerated from an artifact the anchor pins.
    """
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: PLC0415
    from audit_bundle.rederivation.registry import register_primitive  # noqa: PLC0415
    from audit_bundle.verifier import BundleVerifier  # noqa: PLC0415
    from audit_bundle.work_set import WorkSet  # noqa: PLC0415
    from confidence_coverage_check import ConfidenceCoverageCheck  # noqa: PLC0415
    from healthcare_diagnosis_confidence_recompute import (  # noqa: PLC0415
        HealthcareDiagnosisConfidenceRecompute,
    )
    from healthcare_diagnosis_recompute import HealthcareDiagnosisRecompute  # noqa: PLC0415

    register_primitive(HealthcareDiagnosisRecompute())
    register_primitive(HealthcareDiagnosisConfidenceRecompute())

    all_codes = [r["icd10_code"] for r in _load_legacy_build_module()._RULES]
    pins = {_OUTPUT_ID: _TYPE_KEY}
    for code in all_codes:
        pins[f"{_CONFIDENCE_OUTPUT_PREFIX}{code}"] = _CONFIDENCE_TYPE_KEY

    return BundleVerifier(
        plugins=[FileIntegrityManySmall(), ConfidenceCoverageCheck()],
        spec_anchor=anchor,
        work_set=WorkSet.declare(
            pins,
            source="healthcare_diagnosis_minimal spec_pinned_check: the codes "
            "claim plus one confidence output per icd10_code in the fixture's "
            "_RULES",
            provenance="SELF_AUTHORED",
        ),
    )


def main() -> int:
    argparse.ArgumentParser(
        description="Build + spec-pinned-verify the healthcare_diagnosis_minimal pilot"
    ).parse_args()
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = build_spec_pinned(Path(td) / "bundle")
        anchor = anchor_from_committed_spec()
        result = make_verifier(anchor).verify(bundle_dir)
        if result.ok:
            print("PASS  healthcare_diagnosis_minimal  (spec-pinned dispatch)")
            return 0
        print(
            "FAIL  healthcare_diagnosis_minimal  (spec-pinned dispatch)",
            file=sys.stderr,
        )
        for f in result.failures:
            print(f"    [{f.check_name}] {f.reason_code}: {f.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
