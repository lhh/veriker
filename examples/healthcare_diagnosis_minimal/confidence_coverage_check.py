"""confidence_coverage_check.py — coverage cross-check for the Tier-2
healthcare_diagnosis_confidence slice (RATIONAL_BAND_MIGRATION.md §4b.2).

Condition of calling the confidence claim "in the registry" (per the wave
scope's triage card): every icd10_code present in the bound, exact-compared
`healthcare_diagnosis_codes` claim must have a corresponding
`confidence:<code>` output entry declared in manifest.outputs. Without this
check a producer could silently OMIT a confidence output for one candidate
(e.g. to hide a tampered or embarrassing confidence value) and the omission
would pass unnoticed — the dispatch-level coverage invariant (§4a.4 in
audit_bundle/rederivation/dispatch.py) only enforces that DECLARED outputs
have a matching file; it says nothing about the codes<->confidence roster
relationship, which is a domain-specific cross-check this pilot must supply
itself.

This is a pilot-level TypedCheck plugin (audit_bundle/plugin.py Protocol), NOT
registered into the core typed-check registry (audit_bundle.bundle_manifest
register_typed_check) — it is passed directly to BundleVerifier(plugins=[...])
by spec_pinned_check.py.make_verifier(), the same way other pilots wire their
own StampLatticeCheck / DispatchRecordWellformedCheck instances without
adding their names to
manifest.typed_checks: BundleVerifier._step_typed_check_plugins runs every
instance in `plugins` regardless of the manifest's typed_checks list; that
list is only cross-checked in the OTHER direction (a claimed name must have a
matching instance).

Deliberately reads the CLAIMED codes value from outputs/healthcare_diagnosis_
codes.json (the committed claim), not a re-derived truth — the codes claim's
own correctness is a separate obligation (the `exact` comparator +
healthcare_diagnosis_recompute primitive). This check binds confidence outputs
to whatever code roster is CLAIMED; it cannot force the codes claim itself to
be complete (that is the pre-existing "PASS attests to claims PRESENT"
roster residual, documented in the spec description and README, unchanged by
this slice).

Inert (returns PASS) when the bundle declares no healthcare_diagnosis_codes
output at all, matching the dispatch-loop's own inertness convention for
bundles that do not use this claim.

Stdlib-only.
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle.plugin import PluginResult

_CODES_OUTPUT_ID = "healthcare_diagnosis_codes"
_CONFIDENCE_PREFIX = "confidence:"


class ConfidenceCoverageCheck:
    """TypedCheck: every code in the committed codes claim has a matching
    confidence:<code> output, and vice versa (no extra/undeclared codes)."""

    name: str = "healthcare_diagnosis_confidence_coverage"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        outputs = [
            o for o in (getattr(manifest, "outputs", ()) or ()) if isinstance(o, dict)
        ]

        codes_entry = next(
            (o for o in outputs if o.get("output_id") == _CODES_OUTPUT_ID), None
        )
        if codes_entry is None:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail=(
                    f"no {_CODES_OUTPUT_ID!r} output declared; confidence "
                    "coverage cross-check is inert"
                ),
                files_audited=(),
            )

        codes_path = bundle_dir / "outputs" / f"{_CODES_OUTPUT_ID}.json"
        try:
            doc = json.loads(codes_path.read_bytes())
            codes = doc["value"]
        except (OSError, ValueError, KeyError) as exc:
            return PluginResult(
                ok=False,
                reason_code="CONFIDENCE_COVERAGE_UNREADABLE",
                detail=(
                    "could not read the healthcare_diagnosis_codes claimed "
                    f"value to cross-check confidence coverage: {exc}"
                ),
                files_audited=(str(codes_path),),
            )
        if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
            return PluginResult(
                ok=False,
                reason_code="CONFIDENCE_COVERAGE_UNREADABLE",
                detail=(
                    f"{_CODES_OUTPUT_ID!r} claimed value must be a JSON array "
                    "of code strings"
                ),
                files_audited=(str(codes_path),),
            )

        declared_confidence_codes: set[str] = set()
        for o in outputs:
            oid = o.get("output_id")
            if isinstance(oid, str) and oid.startswith(_CONFIDENCE_PREFIX):
                declared_confidence_codes.add(oid[len(_CONFIDENCE_PREFIX) :])

        expected = set(codes)
        if expected != declared_confidence_codes:
            missing = sorted(expected - declared_confidence_codes)
            extra = sorted(declared_confidence_codes - expected)
            return PluginResult(
                ok=False,
                reason_code="CONFIDENCE_COVERAGE_GAP",
                detail=(
                    "every icd10_code in the bound healthcare_diagnosis_codes "
                    "claim must have a corresponding confidence:<code> output "
                    f"(§4b.2 coverage cross-check); missing={missing!r} "
                    f"extra={extra!r}"
                ),
                files_audited=(str(codes_path),),
            )

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"{len(expected)} code(s) fully covered by confidence:<code> outputs"
            ),
            files_audited=(str(codes_path),),
        )
