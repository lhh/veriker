"""predicate_check.py — verify-time reader for dispatch_records[].predicates.

Closes the by-catch gap recorded in COMPARATOR_KIND_DEMAND_SWEEP.md /
RATIONAL_BAND_MIGRATION.md §5.2: the bundle's record-0 predicate
("sum(line_items.amount_usd) == claim.value_usd") was asserted at BUILD time
only — the C14 stamp_lattice plugin verifies the upgrade SIGNATURE, but
nothing at verify time ever re-evaluated the predicate the upgrade was
granted FOR. A tampered extraction value (with its file SHA re-minted) rode
through every leg while the record still displayed the predicate string.

Discipline (§4a.6 closed-world): predicate strings are IDENTIFIERS resolved
against a verifier-implemented allowlist — never interpreted as code. A
record that carries a signed upgrade must cite at least one predicate, and
every cited predicate must be (a) allowlisted and (b) re-derivable TRUE from
the committed bundle bytes. Unknown predicate on an upgraded record, absent
predicates on an upgraded record, or a refuted predicate all fail closed.
Records WITHOUT an upgrade are not gated here (their predicates, if any, are
informational — they earned nothing).

Stdlib-only; pilot-carried (the demo + tests wire it next to the C14 check).
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path

from audit_bundle.plugin import PluginResult


def _eval_sum_line_items_equals_claim(bundle_dir: Path) -> tuple[bool, str]:
    """Re-derive: sum(line_items.amount_usd) over the committed source table
    equals the committed extract_total claim's value_usd. Decided exactly on
    Fractions (amounts are committed JSON numbers; Fraction(float) is exact
    for every binary64), so there is no float ambiguity in the predicate."""
    source = json.loads((bundle_dir / "evidence" / "source_table.json").read_bytes())
    extractions = json.loads((bundle_dir / "payload" / "extractions.json").read_bytes())
    line_items = source.get("line_items")
    if not isinstance(line_items, list) or not line_items:
        return (False, "source_table.line_items missing or empty")
    total = Fraction(0)
    for idx, li in enumerate(line_items):
        amt = li.get("amount_usd") if isinstance(li, dict) else None
        if isinstance(amt, bool) or not isinstance(amt, (int, float)):
            return (False, f"line_items[{idx}].amount_usd not a JSON number")
        total += Fraction(amt)
    claim_value = None
    for c in extractions.get("claims", ()):
        if isinstance(c, dict) and c.get("claim_id") == "extract_total":
            claim_value = c.get("value_usd")
            break
    if isinstance(claim_value, bool) or not isinstance(claim_value, (int, float)):
        return (False, "extract_total claim missing or value_usd not a number")
    if Fraction(claim_value) != total:
        return (
            False,
            f"sum(line_items.amount_usd)={float(total)!r} != "
            f"claim.value_usd={claim_value!r}",
        )
    return (True, f"sum(line_items.amount_usd)={float(total)!r} == claim.value_usd")


# Closed-world allowlist: predicate string -> verifier-implemented evaluator.
_PREDICATE_EVALUATORS = {
    "sum(line_items.amount_usd) == claim.value_usd": _eval_sum_line_items_equals_claim,
}


class UpgradePredicateCheck:
    """Every dispatch record carrying a signed stamp upgrade must cite only
    allowlisted predicates, and every cited predicate must re-derive TRUE
    from committed bundle bytes (fail-closed on unknown/absent/refuted)."""

    name = "upgrade_predicate_recheck"

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        def _fail(code: str, detail: str) -> PluginResult:
            return PluginResult(
                ok=False,
                reason_code=code,
                detail=f"{code}: {detail}",
                files_audited=(
                    "evidence/source_table.json",
                    "payload/extractions.json",
                ),
            )

        rechecked = 0
        for idx, rec in enumerate(manifest.dispatch_records):
            if not isinstance(rec, dict) or "stamp_upgrade" not in rec:
                continue  # no upgrade claimed -> nothing was earned here
            predicates = rec.get("predicates")
            if not isinstance(predicates, list) or not predicates:
                return _fail(
                    "UPGRADE_PREDICATE_ABSENT",
                    f"dispatch_records[{idx}] carries a signed upgrade but "
                    "cites no predicate — an upgrade must name what it was "
                    "granted for",
                )
            for pred in predicates:
                fn = _PREDICATE_EVALUATORS.get(pred) if isinstance(pred, str) else None
                if fn is None:
                    return _fail(
                        "UPGRADE_PREDICATE_UNKNOWN",
                        f"dispatch_records[{idx}] predicate {pred!r} is not "
                        "in the verifier-implemented allowlist (closed-world; "
                        "predicates are identifiers, never code)",
                    )
                ok, detail = fn(bundle_dir)
                if not ok:
                    return _fail(
                        "UPGRADE_PREDICATE_REFUTED",
                        f"dispatch_records[{idx}] predicate {pred!r} does not "
                        f"hold over the committed bytes: {detail}",
                    )
                rechecked += 1

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"upgrade_predicate_recheck: {rechecked} predicate(s) on "
                "upgraded record(s) re-derived TRUE from committed bytes"
            ),
            files_audited=(
                "evidence/source_table.json",
                "payload/extractions.json",
            ),
        )
