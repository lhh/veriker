#!/usr/bin/env python3
"""dry_run.py — replay a trace corpus through the re-derivation ladder and report what a
gate WOULD have refused, without refusing anything.

    python examples/agent_dry_run_minimal/dry_run.py --inputs <fixture-dir> [--out <dir>]

Deterministic: no clock, no network, no randomness, no LLM. The whole counterfactual is a
pure function of the committed inputs, which is what makes it re-derivable by a third party.

WHY THIS EXISTS
---------------
A customer is asked to switch on a fail-closed gate with no way to see what it would refuse
first. Nobody buys that. Everything measured across this line of work is already a VERDICT
rather than an enforcement, so a dry-run is a packaging job, not a new engine.

WHAT DISTINGUISHES IT from the dry-run a governance vendor already ships is not the feature.
It is that this one emits an audit bundle: the customer recomputes the counterfactual from
the committed inputs instead of trusting our number. `_build_bundle.py` does the emission,
`AgentDryRunCheck` does the recomputation.

WHAT IT DOES NOT MEASURE — read before quoting a number off it
---------------------------------------------------------------
A replayed dry-run reports what the gate would have done on traffic produced under NO gate.
Once a gate exists the distribution shifts: agents retry differently, people phrase work
orders differently, and the task mix changes in response to refusals. This is a sample of
the PRE-gate distribution and is never a bound on the post-gate one. "This rung would have
refused 3 % of your traffic" is a description of the past, not a forecast.

Without `inputs/trace_labels.jsonl` it reports how many actions each rung refuses and
NOTHING about whether refusing them was right. The labelled block is then omitted rather
than zero-filled: a zero reads as "no attacks found", an omission reads as "nobody looked",
and only the second is true.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins.reference.agent_ladder import (  # noqa: E402
    DryRunRefusal,
    LadderSpec,
    ToolSchema,
    run_dry_run,
)

REQUIRED = (
    "spec/tool_schema.json",
    "spec/ladder_spec.json",
    "inputs/work_orders.jsonl",
    "inputs/record_snapshot.json",
    "inputs/traces.jsonl",
)
OPTIONAL = ("inputs/trace_labels.jsonl", "inputs/work_order_tools.json")


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise DryRunRefusal("MALFORMED_INPUT", f"{path.name}:{i}: {exc}") from None
    return rows


def load_inputs(root: Path) -> dict:
    """Read a fixture directory into the engine's inputs. Every absence named in the ADR's
    inputs contract is a refusal here, not a warning."""
    for rel in REQUIRED:
        if not (root / rel).exists():
            raise DryRunRefusal("MISSING_REQUIRED_INPUT", rel)

    schema = ToolSchema.from_json(json.loads((root / "spec/tool_schema.json").read_text()))
    spec = LadderSpec.from_json(json.loads((root / "spec/ladder_spec.json").read_text()))

    wo_rows = _read_jsonl(root / "inputs/work_orders.jsonl")
    work_orders = {}
    for r in wo_rows:
        if "work_order_id" not in r or "instruction_text" not in r:
            raise DryRunRefusal("MALFORMED_INPUT", f"work order missing a field: {r}")
        work_orders[r["work_order_id"]] = r["instruction_text"]

    snapshot = json.loads((root / "inputs/record_snapshot.json").read_text())
    traces = _read_jsonl(root / "inputs/traces.jsonl")

    labels = None
    lp = root / "inputs/trace_labels.jsonl"
    if lp.exists():
        labels = {r["trace_id"]: r["label"] for r in _read_jsonl(lp)}
        bad = sorted({v for v in labels.values() if v not in ("LEGITIMATE", "ILLEGITIMATE")})
        if bad:
            raise DryRunRefusal("UNDECLARED_LABEL", f"{bad}")

    wot = None
    tp = root / "inputs/work_order_tools.json"
    if tp.exists():
        wot = {
            k: v
            for k, v in json.loads(tp.read_text()).items()
            if not k.startswith("_")
        }

    return {
        "schema": schema,
        "spec": spec,
        "work_orders": work_orders,
        "snapshot": snapshot,
        "traces": traces,
        "labels": labels,
        "work_order_tools": wot,
    }


def _print_report(result: dict, labelled: bool) -> None:
    agg = result["aggregate"]
    print(f"{'sink':<30}{'rung':>5}{'n':>6}{'admit':>7}{'deny':>6}{'admit_rate':>12}{'cost':>8}")
    for row in agg["rows"]:
        cost = row["utility_cost_vs_baseline"]
        rate = "not-eval" if row["admit_rate"] is None else f"{row['admit_rate']:.4f}"
        print(
            f"{row['sink']:<30}{row['rung']:>5}{row['n_actions']:>6}{row['n_admit']:>7}"
            f"{row['n_deny']:>6}{rate:>12}"
            f"{('' if cost is None else f'{cost:+.3f}'):>8}"
        )
    cov = result["coverage"]
    print(
        f"\ncoverage: eligible={cov['n_eligible']} issued={cov['n_issued']} "
        f"withheld={cov['n_withheld']} {cov['withheld_reason_breakdown'] or ''}"
    )
    if labelled:
        print("\nAgainst supplied labels (a refusal count is not an error count without these):")
        print(f"{'sink':<30}{'rung':>5}{'deny_rate':>11}{'false_refusal':>15}")
        for row in agg["labelled"]:
            print(
                f"{row['sink']:<30}{row['rung']:>5}"
                f"{str(row['deny_rate']):>11}{str(row['false_refusal_rate']):>15}"
            )
    else:
        print(
            "\nNo trace labels supplied — the ground-truth block is OMITTED, not zero-filled. "
            "These counts say what each rung refuses, nothing about whether that was right."
        )
    print(f"\nrung 5 (selection re-derivation): {result['rung_5_status']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Replay a trace corpus through the ladder")
    ap.add_argument("--inputs", required=True, type=Path, help="fixture directory")
    ap.add_argument("--out", type=Path, help="write verdicts/aggregate/coverage here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    try:
        loaded = load_inputs(args.inputs.resolve())
        result = run_dry_run(tick_id=args.inputs.resolve().name, **loaded)
    except DryRunRefusal as exc:
        print(f"REFUSED {exc.reason_code}: {exc.detail}", file=sys.stderr)
        return 2

    if not args.quiet:
        _print_report(result, labelled=loaded["labels"] is not None)

    if args.out:
        out = args.out.resolve()
        out.mkdir(parents=True, exist_ok=True)
        (out / "verdicts.jsonl").write_text(
            "".join(json.dumps(v, sort_keys=True) + "\n" for v in result["verdicts"]),
            encoding="utf-8",
        )
        (out / "aggregate.json").write_text(
            json.dumps(result["aggregate"], indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out / "coverage.json").write_text(
            json.dumps(result["coverage"], indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if not args.quiet:
            print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
