"""AttributionBindingCheck — bind payload/attribution.json to the discharged
context and the pinned allocation table (claim-set coverage sweep, FIX-B).

The defect this closes: the C16 leg proves `(= (+ e0 e1 e2) total)` under
`dispatch_records[0].proof.recheck_context` — a manifest-inline structure the
producer also supplies — and NO plugin ever opened `payload/attribution.json`.
`file_integrity_many_small` only confirms the file matches its own manifest
digest (self-consistency). A producer could report completely different edge
attributions than the numbers Z3 actually discharged and still verify PASS.

What this check binds, fail-closed:

  RD_ATTRIBUTION_MISSING          payload/attribution.json absent.
  RD_ATTRIBUTION_MALFORMED        not strict-parseable, or key set differs from
                                  the closed schema (exact keys, both
                                  directions; edge ids must equal the pinned
                                  table's edge set exactly).
  RD_ATTRIBUTION_CONTEXT_MISSING  no dispatch record carries a recheck_context.
  RD_ATTRIBUTION_SOURCE_UNBOUND   attribution.source_sha256 != sha256 of the
                                  actual spec/allocation_table.json bytes.
  RD_ATTRIBUTION_CONTEXT_MISMATCH attribution edge/total values != the values
                                  the verifier actually re-discharged.
  RD_ATTRIBUTION_TABLE_MISMATCH   discharged context values != the pinned
                                  allocation table's contributions/total
                                  (grounds the context in the hash-pinned
                                  source, not just in itself).

SCOPE (honest): the discharge path stays 100% substrate (C16) — this check
does not touch it; it adds the payload↔context↔pinned-table bindings the
substrate never claimed. Binding by recomputation/equality buys per-field
BINDING of producer-computable values, NOT independence of the underlying
allocation. Stdlib + audit_bundle only (this pilot ships to the public
mirror).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from audit_bundle._total_binding import TotalBindingError, strict_loads
from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

_ATTRIBUTION_REL = "payload/attribution.json"
_TABLE_REL = "spec/allocation_table.json"

_ATTRIBUTION_KEYS = frozenset({"source_sha256", "edge_attribution", "total_impact"})


def _fail(code: str, detail: str) -> PluginResult:
    # Embed the code in detail as well as returning it. Step 4 propagates a
    # failing plugin's own reason_code onto the verdict face (since
    # 2026-08-30); the prefix is redundancy that still covers the crash,
    # declared-but-unwired and clean-ERROR arms.
    return PluginResult(
        ok=False, reason_code=code, detail=f"{code}: {detail}", files_audited=()
    )


class AttributionBindingCheck:
    name: str = "rd_attribution_binding"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        attribution_path = bundle_dir / _ATTRIBUTION_REL
        table_path = bundle_dir / _TABLE_REL
        if not attribution_path.is_file():
            return _fail(
                "RD_ATTRIBUTION_MISSING", f"{_ATTRIBUTION_REL} not found in bundle"
            )
        if not table_path.is_file():
            return _fail(
                "RD_ATTRIBUTION_MALFORMED", f"{_TABLE_REL} not found in bundle"
            )

        table_bytes = table_path.read_bytes()
        try:
            attribution = strict_loads(attribution_path.read_bytes())
            table = strict_loads(table_bytes)
        except TotalBindingError as exc:
            return _fail("RD_ATTRIBUTION_MALFORMED", f"strict parse failed: {exc}")

        if not isinstance(attribution, dict) or set(attribution) != _ATTRIBUTION_KEYS:
            got = sorted(attribution) if isinstance(attribution, dict) else attribution
            return _fail(
                "RD_ATTRIBUTION_MALFORMED",
                f"attribution key set {got!r} != closed schema "
                f"{sorted(_ATTRIBUTION_KEYS)} (exact keys, both directions)",
            )

        table_edges = {e["edge_id"]: e["contribution"] for e in table["edges"]}
        edge_attr = attribution["edge_attribution"]
        if not isinstance(edge_attr, dict) or set(edge_attr) != set(table_edges):
            return _fail(
                "RD_ATTRIBUTION_MALFORMED",
                f"edge_attribution ids {sorted(edge_attr) if isinstance(edge_attr, dict) else edge_attr!r} "
                f"!= pinned table edge set {sorted(table_edges)} (exact set, both "
                f"directions)",
            )

        # 1. The claimed source hash must be the ACTUAL pinned table's bytes.
        actual_sha = hashlib.sha256(table_bytes).hexdigest()
        if attribution["source_sha256"] != actual_sha:
            return _fail(
                "RD_ATTRIBUTION_SOURCE_UNBOUND",
                f"attribution.source_sha256={attribution['source_sha256']!r} != "
                f"sha256({_TABLE_REL})={actual_sha} — the attribution does not "
                f"cite the table this bundle pins",
            )

        # 2. The context the C16 leg actually re-discharged.
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
                "RD_ATTRIBUTION_CONTEXT_MISSING",
                "no dispatch record carries a proof.recheck_context to bind "
                "the attribution against",
            )

        # 3. Payload values must EQUAL the discharged values.
        for eid, contribution in sorted(edge_attr.items()):
            if ctx.get(eid) != contribution:
                return _fail(
                    "RD_ATTRIBUTION_CONTEXT_MISMATCH",
                    f"edge_attribution[{eid!r}]={contribution!r} != "
                    f"recheck_context[{eid!r}]={ctx.get(eid)!r} — the reported "
                    f"attribution is not the one Z3 discharged",
                )
        if attribution["total_impact"] != ctx.get("total"):
            return _fail(
                "RD_ATTRIBUTION_CONTEXT_MISMATCH",
                f"total_impact={attribution['total_impact']!r} != "
                f"recheck_context.total={ctx.get('total')!r} — the reported total "
                f"is not the one Z3 discharged",
            )

        # 4. The discharged context must itself equal the pinned table.
        for eid, contribution in sorted(table_edges.items()):
            if ctx.get(eid) != contribution:
                return _fail(
                    "RD_ATTRIBUTION_TABLE_MISMATCH",
                    f"recheck_context[{eid!r}]={ctx.get(eid)!r} != pinned table "
                    f"contribution {contribution!r} — the discharge ran against "
                    f"numbers that are not the pinned allocation",
                )
        if ctx.get("total") != table["total_impact"]:
            return _fail(
                "RD_ATTRIBUTION_TABLE_MISMATCH",
                f"recheck_context.total={ctx.get('total')!r} != pinned table "
                f"total_impact={table['total_impact']!r}",
            )

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"attribution bound: {len(edge_attr)} edge value(s) + total equal "
                f"the re-discharged context, context equals the pinned table, "
                f"source_sha256 matches the actual {_TABLE_REL} bytes"
            ),
            files_audited=(_ATTRIBUTION_REL, _TABLE_REL),
        )


register_typed_check("rd_attribution_binding")
