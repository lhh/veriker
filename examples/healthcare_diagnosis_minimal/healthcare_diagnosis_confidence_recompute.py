"""healthcare_diagnosis_confidence_recompute.py — Axis-2 recompute primitive for
the per-candidate confidence claim (Tier-2 new-claim slice, rational-band wave
§4b.2).

RATIONAL_BAND_MIGRATION.md §4b: the per-candidate confidence float was
DELIBERATELY excluded from the spec-pinned surface (see the exclusion docstring
in audit_bundle/rederivation/primitives/healthcare_diagnosis.py and the original
"deliberately EXCLUDED to keep the output exact-comparable" sentence in
spec_pinned/healthcare_diagnosis.spec.json) because no float-safe comparator
existed. rational_band dissolves that exclusion reason: this is claim
AUTHORING, not a swap of the existing `exact` codes comparator.

Primitive ID: healthcare_diagnosis_confidence_recompute
Output type:  healthcare_diagnosis_confidence
Comparator:   rational_band {"epsilon": 1e-6}

One output per FIRED candidate. output_id carries the ICD-10 code as
"confidence:<icd10_code>" (e.g. "confidence:J20.9"); this primitive parses the
code out of pack_section["output_id"], re-derives which committed rules fire
from inputs/symptoms.json + inputs/rules.json (an INDEPENDENT rule-traversal
implementation from both the producer's _build_bundle.py copy and the core
exact-codes primitive — the tautology discipline requires the exact-rational
path never share code with either), and recomputes THAT candidate's confidence
as the EXACT rational R = Fraction(severity_sum) * Fraction(confidence_weight)
— UNROUNDED. severity_sum is an int sum of matched symptom severities;
confidence_weight is a committed JSON float literal, and Fraction(float) is
exact for every binary64 value, so R carries zero rounding on the recompute
side. The producer's claim stays its own float pipeline's
round(severity_sum * confidence_weight, 6); epsilon=1e-6 is the terminal 6dp
quantization grain (confidence_weight is a 2-decimal literal and severity_sum
is an integer, so the product's true decimal value already sits on the 6dp
grid — the round is a no-op up to float-representation noise many orders
below 1e-6, the same "no-op terminal rounding" case as the iso42001/aif360
Tier-1 migrations in RATIONAL_BAND_MIGRATION.md §3).

Fail-closed refusal (never invents a partial/fallback confidence):
  - output_id not of the form "confidence:<code>" -> ValueError.
  - the code does not appear as any rule's icd10_code, OR the rule(s) with that
    code do not fire against the committed symptom set -> ValueError. This is
    the deliberate "refusing on a code that does not fire" behavior the wave
    scope calls for; dispatch.py maps any raise here to a recorded, fail-closed
    RECOMPUTE_ERROR (never a silently invented value).
  - more than one fired rule shares the same icd10_code -> ValueError (ambiguous
    which rule's confidence the claim means; not a shape this fixture produces,
    guarded defensively).

Stdlib-only (§C5 core verify() path): json + fractions are stdlib.
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path

_CONFIDENCE_OUTPUT_PREFIX = "confidence:"


def _load_json(path: Path) -> object:
    if not path.is_file():
        raise FileNotFoundError(f"required bundle file missing: {path}")
    return json.loads(path.read_bytes())


def _eval_condition(symptom_map: dict, cond: dict) -> bool:
    """Mirrors the producer's / core exact primitive's condition test EXACTLY,
    but is its OWN independent implementation (tautology discipline: the
    exact-rational recompute path must never share code with the producer or
    with the `exact` codes primitive)."""
    s = symptom_map.get(cond["symptom_id"])
    if s is None:
        return False
    return int(s["severity"]) >= int(cond["min_severity"])


def compute_confidence_for_code(symptoms: list, rules: list, code: str) -> Fraction:
    """Re-derive the EXACT rational confidence for the single fired candidate
    whose icd10_code == `code`.

    Raises ValueError if no committed rule fires for `code` (fail-closed —
    never invents a confidence for a non-firing / nonexistent candidate), or if
    more than one fired rule shares the code (ambiguous).
    """
    if not isinstance(symptoms, list):
        raise TypeError("symptoms must be a JSON array")
    if not isinstance(rules, list):
        raise TypeError("rules must be a JSON array")

    symptom_map = {s["symptom_id"]: s for s in symptoms}
    fired_values: list[Fraction] = []
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        if rule["icd10_code"] != code:
            continue
        matched_ids: list[str] = []
        fired = True
        for cond in rule["conditions"]:
            if _eval_condition(symptom_map, cond):
                matched_ids.append(cond["symptom_id"])
            else:
                fired = False
                break
        if not fired:
            continue
        severity_sum = sum(int(symptom_map[sid]["severity"]) for sid in matched_ids)
        weight = Fraction(rule["confidence_weight"])
        fired_values.append(Fraction(severity_sum) * weight)

    if not fired_values:
        raise ValueError(
            f"icd10 code {code!r} does not fire against the committed symptom "
            "set (no rule with that code matched all conditions) — refusing "
            "to recompute a confidence for a non-firing/nonexistent candidate"
        )
    if len(fired_values) > 1:
        raise ValueError(
            f"icd10 code {code!r} fires from more than one committed rule — "
            "ambiguous confidence recompute is not supported"
        )
    return fired_values[0]


class HealthcareDiagnosisConfidenceRecompute:
    """Verifier-side primitive: re-derive one fired candidate's EXACT rational
    confidence, selected by the ICD-10 code carried in the output_id."""

    primitive_id: str = "healthcare_diagnosis_confidence_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # verifier-side import OK

        output_id = pack_section.get("output_id")
        if not isinstance(output_id, str) or not output_id.startswith(
            _CONFIDENCE_OUTPUT_PREFIX
        ):
            raise ValueError(
                f"output_id {output_id!r} does not carry the "
                f"{_CONFIDENCE_OUTPUT_PREFIX!r} code prefix this primitive expects"
            )
        code = output_id[len(_CONFIDENCE_OUTPUT_PREFIX) :]
        if not code:
            raise ValueError(f"output_id {output_id!r} carries an empty icd10 code")

        bundle_dir: Path = inputs.bundle_dir
        symptoms = _load_json(bundle_dir / "inputs" / "symptoms.json")
        rules = _load_json(bundle_dir / "inputs" / "rules.json")

        R = compute_confidence_for_code(symptoms, rules, code)

        return RecomputedValue(
            value={"kind": "rational", "num": R.numerator, "den": R.denominator},
            detail=f"code={code!r} recomputed confidence R~{float(R):.6f}",
        )


# Deliberately NOT self-registering at import (unlike the PROMOTED core
# primitive). This is a per-dir Tier-2 demo primitive; spec_pinned_check.py's
# make_verifier() registers it explicitly, matching the iso42001 and other
# per-dir migration conventions (register_primitive() called from the harness,
# not at module import time).
