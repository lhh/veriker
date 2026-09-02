#!/usr/bin/env python3
"""_build_bundle.py — emit a dry-run replay as an audit bundle.

    python examples/agent_dry_run_minimal/_build_bundle.py \
        --fixture procurement_ap --out-dir /tmp/dry_run_bundle

The bundle commits the inputs, records the verdicts, and carries its own declared limits.
A third party re-derives the whole table from `inputs/` plus the pinned `spec/` — see
`audit_bundle/plugins/reference/agent_dry_run_pack.py`, which is what the typed check runs.

WHAT GOES WHERE, and why the split matters
------------------------------------------
`spec/` holds the POLICY — the tool schema (which arguments carry authority, of what type)
and the ladder spec (every constant that changes a verdict). It is authored by whoever sets
the gate, and it is the part that must be anchored against a copy from OUTSIDE the bundle.

`inputs/` holds the OBSERVED DATA — work orders, the record snapshot, the traces. Committed
and hashed; the manifest binds them, and nothing outside the bundle is needed to check them.

That split is not cosmetic. A reader who anchors the whole bundle against itself has done
nothing, and the two directories are where the difference lives.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]
for p in (str(_PKG_ROOT), str(_HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402
from audit_bundle.plugins.reference.agent_ladder import DryRunRefusal, run_dry_run  # noqa: E402
from dry_run import load_inputs  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_CREATED_AT = "2026-08-18T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "agent_dry_run",
    "coverage_sum_invariant",
]

# Written before any result existed (ADR section 5, frozen 2026-08-18) and shipped verbatim
# INSIDE the bundle, so a reader who never sees the ADR still gets them.
DECLARED_LIMITS = """# Declared limits of this dry-run bundle

Written before any measurement existed, so they cannot be tuned to the results.

1. **A replayed dry-run measures the old distribution.** It reports what the gate would have
   done on traffic produced *under no gate*. Once a gate exists the distribution shifts —
   agents retry differently, people phrase work orders differently, and the task mix changes
   in response to refusals. This is a sample of the pre-gate distribution and is **never a
   bound on the post-gate one**. "This rung would have refused N% of your traffic" describes
   the past; it does not forecast the future.

2. **Without labels, a refusal count is not an error count.** Absent
   `inputs/trace_labels.jsonl`, this bundle reports how many actions each rung refuses and
   nothing about whether refusing them was right. The labelled block is then omitted rather
   than zero-filled: a zero reads as "no attacks found", an omission reads as "nobody
   looked", and only the second is true.

3. **The trusted corpus is assumed clean, and that assumption is unverified here.** A real
   system-of-record contains whatever was written into it, including by a previously
   compromised run. Write-gating the corpus is an architectural dependency, not a hardening
   task, and it is not in this scope.

4. **Value-level only — silent about amount relationships.** A 40 and a 40,000,000 transfer
   to the same authorised recipient differ only if the amount is itself a declared authority
   argument, and then only by exact match.

5. **Content arguments are out of scope.** Destination authorization is by definition silent
   about payload; composed free text can never ground in a destination corpus.

6. **Rung 5 is unbuilt.** Values the instruction establishes by a *selection rule* ("the
   cheapest", "the two smallest open invoices") are refused at rungs 3 and 4, and there is
   no rung that admits them correctly. An action whose every value grounds but whose
   SELECTION is wrong passes every built rung.

7. **Coverage fails open.** An authority argument a call does not set is not evaluated and
   the action admits. This is declared on every verdict face (`fail_open_direction`); it is
   not a bound.

8. **Positional enforcement is out of scope.** Everything in this bundle is a *verdict*.
   Whether the gate can be routed around is a different layer and is documented only.

9. **Replay is not shadow mode.** Shadow mode on live traffic needs a mediation rail
   deployed at the customer. Conflating corpus replay with live shadow overstates what this
   artifact is.
"""


def _anchor_status(result: dict) -> dict:
    """A REMINDER, not a control. A self-declared "anchored: true" is testimony about
    itself and proves nothing; this record exists so a reader who skipped the anchor
    section still sees the obligation."""
    return {
        "self_declared_not_a_control": True,
        "what_must_be_anchored": ["spec/tool_schema.json", "spec/ladder_spec.json"],
        "why": (
            "Together they determine every verdict here. A hash chain proves non-edit, not "
            "non-omission; and an unanchored bundle degrades to stage 1 — testimony — "
            "SILENTLY."
        ),
        "forbidden": (
            "Anchoring on the bundle's own spec/ copy. That is not a weaker anchor, it is "
            "the SAME fail-open: measured 2026-08-17, a forged bundle anchored on its own "
            "spec exits 0 OK."
        ),
        "acceptable_sources_in_preference_order": [
            "the customer's own configuration-management record of the policy they approved",
            "a published spec release hash held outside any bundle",
            "the auditor's own copy taken at engagement start",
        ],
        "tooling_status": (
            "This distribution ships NO verifier flag that refuses an in-bundle anchor "
            "path, and the library API BundleVerifier(spec_anchor=...) has no in-bundle "
            "guard. The anchor comparison is therefore a MANUAL step performed by the "
            "auditor, and no automated green in this bundle asserts that it happened."
        ),
        "computed_anchors_for_convenience": result["anchors"],
    }


def build(fixture_dir: Path, out_dir: Path) -> dict:
    loaded = load_inputs(fixture_dir)
    result = run_dry_run(tick_id=fixture_dir.name, **loaded)

    files = {
        "inputs/work_orders.jsonl": (fixture_dir / "inputs/work_orders.jsonl").read_bytes(),
        "inputs/record_snapshot.json": (fixture_dir / "inputs/record_snapshot.json").read_bytes(),
        "inputs/traces.jsonl": (fixture_dir / "inputs/traces.jsonl").read_bytes(),
        "payload/verdicts.jsonl": "".join(
            json.dumps(v, sort_keys=True) + "\n" for v in result["verdicts"]
        ).encode("utf-8"),
        "payload/aggregate.json": (
            json.dumps(result["aggregate"], indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"),
        "coverage/dry_run_coverage.json": (
            json.dumps(result["coverage"], indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"),
        "disclosures/declared_limits.md": DECLARED_LIMITS.encode("utf-8"),
        "disclosures/anchor_status.json": (
            json.dumps(_anchor_status(result), indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"),
    }
    for rel in ("inputs/trace_labels.jsonl", "inputs/work_order_tools.json"):
        src = fixture_dir / rel
        if src.exists():
            files[rel] = src.read_bytes()

    content = BundleContent(
        bundle_id=f"agent-dry-run-{fixture_dir.name.replace('_', '-')}",
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files=files,
        spec_files={
            "tool_schema.json": (fixture_dir / "spec/tool_schema.json").read_bytes(),
            "ladder_spec.json": (fixture_dir / "spec/ladder_spec.json").read_bytes(),
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    n_sinks = len({r["sink"] for r in result["aggregate"]["rows"]})
    print(f"Bundle written to {out_dir}")
    print(f"  fixture           : {fixture_dir.name}")
    print(f"  traces replayed   : {result['coverage']['n_eligible']}")
    print(f"  sinks x rungs     : {n_sinks} x 4 = {len(result['aggregate']['rows'])} rows")
    print(f"  labelled          : {'yes' if loaded['labels'] else 'NO (block omitted)'}")
    print(f"  manifest files    : {len(manifest['files'])}")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Emit an agent dry-run audit bundle")
    ap.add_argument("--fixture", default="procurement_ap")
    ap.add_argument("--fixture-dir", type=Path, default=None)
    ap.add_argument("--out-dir", required=True, type=Path)
    args = ap.parse_args(argv)
    fixture_dir = (args.fixture_dir or (_HERE / "fixtures" / args.fixture)).resolve()
    try:
        build(fixture_dir, args.out_dir.resolve())
    except DryRunRefusal as exc:
        print(f"REFUSED {exc.reason_code}: {exc.detail}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
