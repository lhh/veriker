"""PayrollPlacementBindingCheck — bind payload/placement.json to the discharged
context and the pinned agreement (claim-set coverage sweep, FIX-B).

The defect this closes: the C16 leg re-runs Z3 against
`dispatch_records[0].proof.recheck_context` — a producer-supplied copy of
{acting_rate, band_min, band_max, raise_floor, windfall_ceiling} — and NO
plugin ever opened `payload/placement.json`. The human-facing placement (the
dollar amount, the band, the classifications) was fully decoupled from the
verified numbers: a producer could ship a placement saying anything at all and
still verify green.

What this check binds, fail-closed:

  PAD_PLACEMENT_MISSING        payload/placement.json absent.
  PAD_PLACEMENT_MALFORMED      not strict-parseable, or key set differs from the
                               closed schema (exact keys, both directions).
  PAD_CONTEXT_MISSING          no dispatch record carries the recheck_context
                               this check must bind against.
  PAD_BAND_EDGES_NOT_REDERIVED recheck_context band edges != the edges
                               recomputed from the sha-pinned
                               spec/acting_pay_rules.json (grounds the context
                               the Z3 leg trusts in the pinned agreement — a
                               widened band in the context is caught HERE).
  PAD_PLACEMENT_RATE_UNBOUND   placement.acting_rate_cents != the acting_rate
                               the verifier actually re-discharged.
  PAD_PLACEMENT_BAND_MISMATCH  placement.admissible_band_cents != the
                               recomputed intersection of the classification
                               band and the uplift bounds.
  PAD_PLACEMENT_FIELD_MISMATCH classifications / substantive_rate_cents /
                               in_band differ from the pinned rules /
                               recomputation.

SCOPE (honest): `employee_id` has NO binding target anywhere in this bundle
(no roster, no second copy) — it is a recorded residual, not silently covered;
see README. `band_source` is free prose: the exact-keys closure stops key
smuggling, but its text is not semantically bound. The recheck_context itself
is verifier-HMAC-bound via the C16 signature; this check adds the payload↔
context and context↔pinned-spec bindings that signature never provided.

Binding by RECOMPUTATION per-field (band edges from the pinned rules) buys
per-field binding of producer-computable values, NOT independence.

Stdlib + audit_bundle only (this pilot ships to the public mirror).
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle._total_binding import TotalBindingError, strict_loads
from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

_PLACEMENT_REL = "payload/placement.json"
_RULES_REL = "spec/acting_pay_rules.json"

_PLACEMENT_KEYS = frozenset(
    {
        "employee_id",
        "substantive_classification",
        "acting_classification",
        "substantive_rate_cents",
        "acting_rate_cents",
        "admissible_band_cents",
        "band_source",
        "in_band",
    }
)
_BAND_KEYS = frozenset({"min", "max"})
_CTX_EDGE_KEYS = ("band_min", "band_max", "raise_floor", "windfall_ceiling")


def _fail(code: str, detail: str) -> PluginResult:
    # Embed the code in detail as well as returning it. Step 4 propagates a
    # failing plugin's own reason_code onto the verdict face (since
    # 2026-08-30); the prefix is redundancy that still covers the crash,
    # declared-but-unwired and clean-ERROR arms.
    return PluginResult(
        ok=False, reason_code=code, detail=f"{code}: {detail}", files_audited=()
    )


def _rhu(num: int, den: int) -> int:
    """Round half up (non-negative) — must mirror the builder's arithmetic."""
    if num < 0:
        raise ValueError(f"_rhu expects non-negative numerator, got {num}")
    return (num + den // 2) // den


def _edges_from_rules(rules: dict) -> dict:
    """Recompute the four admissibility bounds + substantive per-period rate
    from the pinned agreement (the verifier-side twin of the builder's
    _band_edges — these ARE re-derivable; the rate within them is not)."""
    ppy = rules["periods_per_year"]
    substantive_period = _rhu(rules["substantive"]["annual_salary"] * 100, ppy)
    return {
        "substantive_period": substantive_period,
        "band_min": _rhu(rules["acting"]["band_min_annual"] * 100, ppy),
        "band_max": _rhu(rules["acting"]["band_max_annual"] * 100, ppy),
        "raise_floor": substantive_period * rules["raise_min_pct"] // 100,
        "windfall_ceiling": substantive_period * rules["windfall_max_pct"] // 100,
    }


class PayrollPlacementBindingCheck:
    name: str = "payroll_placement_binding"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        placement_path = bundle_dir / _PLACEMENT_REL
        rules_path = bundle_dir / _RULES_REL
        if not placement_path.is_file():
            return _fail(
                "PAD_PLACEMENT_MISSING", f"{_PLACEMENT_REL} not found in bundle"
            )
        if not rules_path.is_file():
            return _fail("PAD_PLACEMENT_MALFORMED", f"{_RULES_REL} not found in bundle")

        try:
            placement = strict_loads(placement_path.read_bytes())
            rules = strict_loads(rules_path.read_bytes())
        except TotalBindingError as exc:
            return _fail("PAD_PLACEMENT_MALFORMED", f"strict parse failed: {exc}")

        if not isinstance(placement, dict) or set(placement) != _PLACEMENT_KEYS:
            got = set(placement) if isinstance(placement, dict) else type(placement)
            return _fail(
                "PAD_PLACEMENT_MALFORMED",
                f"placement key set {sorted(got) if isinstance(got, set) else got} "
                f"!= closed schema {sorted(_PLACEMENT_KEYS)} (exact keys, both "
                f"directions)",
            )
        band = placement["admissible_band_cents"]
        if not isinstance(band, dict) or set(band) != _BAND_KEYS:
            return _fail(
                "PAD_PLACEMENT_MALFORMED",
                f"admissible_band_cents keys {band} != {sorted(_BAND_KEYS)}",
            )

        # The context the C16 leg actually re-discharged (direct manifest read,
        # same pattern as the pilots' other TypedChecks).
        raw = json.loads((bundle_dir / "manifest.json").read_bytes())
        records = raw.get("dispatch_records") or []
        ctx = None
        for rec in records:
            c = ((rec or {}).get("proof") or {}).get("recheck_context")
            if isinstance(c, dict):
                ctx = c
                break
        if ctx is None:
            return _fail(
                "PAD_CONTEXT_MISSING",
                "no dispatch record carries a proof.recheck_context to bind "
                "the placement against",
            )

        # Ground the context's band edges in the sha-pinned agreement.
        edges = _edges_from_rules(rules)
        for k in _CTX_EDGE_KEYS:
            if ctx.get(k) != edges[k]:
                return _fail(
                    "PAD_BAND_EDGES_NOT_REDERIVED",
                    f"recheck_context.{k}={ctx.get(k)!r} != {edges[k]} recomputed "
                    f"from the pinned {_RULES_REL} — the band the discharge ran "
                    f"against is not the agreement's band",
                )

        # Bind the human-facing placement to the discharged value.
        if placement["acting_rate_cents"] != ctx.get("acting_rate"):
            return _fail(
                "PAD_PLACEMENT_RATE_UNBOUND",
                f"payload acting_rate_cents={placement['acting_rate_cents']!r} != "
                f"recheck_context.acting_rate={ctx.get('acting_rate')!r} — the "
                f"human-facing rate is not the rate the verifier re-discharged",
            )

        eff_min = max(edges["band_min"], edges["raise_floor"])
        eff_max = min(edges["band_max"], edges["windfall_ceiling"])
        if band["min"] != eff_min or band["max"] != eff_max:
            return _fail(
                "PAD_PLACEMENT_BAND_MISMATCH",
                f"admissible_band_cents {band} != recomputed intersection "
                f"[{eff_min}, {eff_max}] of the classification band and the "
                f"uplift bounds",
            )

        mismatches = []
        if (
            placement["substantive_classification"]
            != rules["substantive"]["classification"]
        ):
            mismatches.append("substantive_classification")
        if placement["acting_classification"] != rules["acting"]["classification"]:
            mismatches.append("acting_classification")
        if placement["substantive_rate_cents"] != edges["substantive_period"]:
            mismatches.append("substantive_rate_cents")
        if placement["in_band"] is not (
            eff_min <= placement["acting_rate_cents"] <= eff_max
        ):
            mismatches.append("in_band")
        if mismatches:
            return _fail(
                "PAD_PLACEMENT_FIELD_MISMATCH",
                f"placement field(s) {mismatches} differ from the pinned rules / "
                f"recomputation",
            )

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"placement bound: acting_rate_cents={placement['acting_rate_cents']} "
                f"equals the re-discharged context value; band edges re-derived from "
                f"the pinned agreement; admissible band [{eff_min}, {eff_max}] and "
                f"classifications match. Residual (recorded): employee_id has no "
                f"binding target in this bundle; band_source prose is not "
                f"semantically bound."
            ),
            files_audited=(_PLACEMENT_REL, _RULES_REL),
            # Claimset coverage accounting: exactly the fields this check
            # binds above — reported ONLY on the full-binding pass. The two
            # recorded residuals (employee_id, band_source) are NOT reported;
            # they are excused in the bundle's committed residual map, so a
            # coverage claim here would double-account them.
            verified_claim_fields=frozenset(
                {
                    "placement:substantive_classification",
                    "placement:acting_classification",
                    "placement:substantive_rate_cents",
                    "placement:acting_rate_cents",
                    "placement:admissible_band_cents.min",
                    "placement:admissible_band_cents.max",
                    "placement:in_band",
                }
            ),
        )


register_typed_check("payroll_placement_binding")
