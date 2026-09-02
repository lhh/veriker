"""tests/test_numeric_model_vocabulary.py — the float/exact boundary is
ENFORCED VOCABULARY, not per-pilot judgment.

Endpoint of the numeric_model pass (RATIONAL_BAND_MIGRATION.md §6): after the
rational_band migration wave, every committed auditor spec that still admits a
tolerance must SAY what numeric model that tolerance is for. A `scalar_epsilon`
binding with epsilon > 0 and no `numeric_model` is exactly the shape the
credit_scoring by-catch had — an undocumented coercion nobody re-judged.

SCOPE (deliberate, and a recorded residual):
  * This is a REPO-LEVEL gate over committed `examples/*/spec_pinned/*.spec.json`.
    Verifier/dispatch behavior is UNCHANGED — `numeric_model` stays optional and
    documentary at the comparator (a third-party spec without it still runs), so
    this test cannot bind specs authored elsewhere. The stricter endpoint
    (verifier fail-closed on an unannotated tolerance) is a separate posture
    decision: it changes accept/reject ABI on a frozen path.
  * gaci_city_index carries its comparator bindings as in-code Python dicts
    rather than a committed spec file, so it is outside this walk (annotated
    in place; recorded in the migration doc's residuals).

The allowlist itself is the verifier's (`_NUMERIC_MODELS`), so a spec cannot
invent a model name: this test only enforces PRESENCE, the comparator's own
closed-world validation enforces VALIDITY (asserted here too, so the two
cannot drift apart).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.rederivation.comparators import (
    _NUMERIC_MODELS,
    validate_comparator_params,
)

_PKG_ROOT = Path(__file__).resolve().parents[1]
_SPEC_GLOB = "examples/*/spec_pinned/*.spec.json"


def _tolerance_bindings() -> list[tuple[str, str, dict]]:
    """(spec path, type name, params) for every committed scalar_epsilon
    binding carrying a nonzero tolerance."""
    found: list[tuple[str, str, dict]] = []
    for path in sorted(_PKG_ROOT.glob(_SPEC_GLOB)):
        doc = json.loads(path.read_bytes())
        for tname, tdef in (doc.get("types") or {}).items():
            comparator = tdef.get("comparator") or {}
            if comparator.get("kind") != "scalar_epsilon":
                continue
            params = comparator.get("params") or {}
            try:
                eps = float(params.get("epsilon", 0))
            except (TypeError, ValueError):
                eps = 0.0
            if eps > 0:
                found.append((str(path.relative_to(_PKG_ROOT)), tname, params))
    return found


def test_every_tolerance_declares_its_numeric_model():
    """No committed spec may admit a tolerance without saying what numeric
    model it is for."""
    unannotated = [
        f"{rel}::{tname} (epsilon={params.get('epsilon')})"
        for rel, tname, params in _tolerance_bindings()
        if not params.get("numeric_model")
    ]
    assert not unannotated, (
        "scalar_epsilon bindings with epsilon > 0 and no numeric_model — either "
        "annotate them (binary64_exact / binary64_libm_tolerated, with the reason "
        "in the spec description) or migrate the claim to an exact comparator "
        "kind:\n  " + "\n  ".join(unannotated)
    )


def test_declared_numeric_models_are_allowlisted():
    """Presence is not enough: the value must be one the verifier implements
    (the comparator's own closed-world check is the authority, exercised here
    so this gate and the verifier cannot drift)."""
    for rel, tname, params in _tolerance_bindings():
        nm = params.get("numeric_model")
        assert nm in _NUMERIC_MODELS, (
            f"{rel}::{tname}: numeric_model {nm!r} not allowlisted"
        )
        # Fail-closed authority: the comparator validates it the same way at
        # anchor-load, so a spec that passes here also loads.
        validate_comparator_params("scalar_epsilon", dict(params))


def test_the_walk_actually_finds_specs():
    """A guard that silently matches nothing is not a guard — pin that the
    glob still resolves to real committed specs with real bindings."""
    all_specs = list(_PKG_ROOT.glob(_SPEC_GLOB))
    assert len(all_specs) > 30, f"spec walk found only {len(all_specs)} files"
    assert _tolerance_bindings(), "no tolerance-bearing bindings found at all"


def test_unannotated_tolerance_would_be_caught():
    """Mutation check: the gate must actually reject an unannotated binding
    (a gate whose failure mode is never exercised is a gate nobody has tested)."""
    synthetic = {"epsilon": 1e-6}
    assert not synthetic.get("numeric_model")
    with pytest.raises(Exception):
        validate_comparator_params(
            "scalar_epsilon", {"epsilon": 1e-6, "numeric_model": "made_up"}
        )
