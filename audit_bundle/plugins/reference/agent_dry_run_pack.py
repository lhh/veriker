#!/usr/bin/env python3
"""agent_dry_run_pack.py — re-derive a dry-run bundle's counterfactual from its committed
inputs and compare, field by field, against what the bundle claims.

    python agent_dry_run_pack.py --bundle-dir <path>

Exit 0 = every verdict face, the aggregate table and the coverage row re-derive. Exit 1 =
at least one does not, with the first disagreement printed to stderr.

SAFE-BY-ORIGIN: this file is `__file__`-rooted verifier-distribution code, not
bundle-supplied, so it runs ungated. Relocating it into a bundle directory would require
adding the execution gate.

WHAT THIS DOES AND DOES NOT ESTABLISH
-------------------------------------
Establishes: the table is a FUNCTION of the committed inputs, and the function is published.
Anyone holding the bundle recomputes it without our dashboard and without the customer's
live systems.

Does NOT establish: that the traces are a complete record of what the agent did — that is
the mediation rail's job and it is not deployed here; nor that any refusal was CORRECT —
that needs labels, and without them the bundle says so on its face.

Does NOT establish anything at all about tampering unless the caller anchored `spec/`
against a copy from OUTSIDE the bundle. Anchoring on the bundle's own `spec/` copy is the
same fail-open as no anchor (measured 2026-08-17: forged bundle -> exit 0 OK). This pack
verifies re-derivation; the anchor is a separate obligation and the bundle's
`disclosures/anchor_status.json` says whose.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[3]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.admission import (  # noqa: E402
    InputInadmissible,
    admit_json_file,
    admit_jsonl_file,
)
from audit_bundle.plugins.reference.agent_ladder import (  # noqa: E402
    DryRunRefusal,
    LadderSpec,
    ToolSchema,
    run_dry_run,
)

# Every read below goes through the admission-bounded loaders. This pack is the thing an
# auditor points at a bundle they did NOT produce, so every byte it parses is
# attacker-controlled by assumption: size-reject before allocation, depth-scan before
# json.loads, cardinality-check after. A raw json.loads here would let a bundle choose how
# much memory its own verifier allocates.
_CHECK = "agent_dry_run"

VERDICTS_REL = "payload/verdicts.jsonl"
AGGREGATE_REL = "payload/aggregate.json"
COVERAGE_REL = "coverage/dry_run_coverage.json"


def _read_jsonl(path: Path) -> list[dict]:
    return admit_jsonl_file(path, check_name=_CHECK)


def _read_json(path: Path):
    return admit_json_file(path, check_name=_CHECK)


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def rederive(bundle_dir: Path) -> dict:
    schema = ToolSchema.from_json(_read_json(bundle_dir / "spec/tool_schema.json"))
    spec = LadderSpec.from_json(_read_json(bundle_dir / "spec/ladder_spec.json"))
    work_orders = {
        r["work_order_id"]: r["instruction_text"]
        for r in _read_jsonl(bundle_dir / "inputs/work_orders.jsonl")
    }
    snapshot = _read_json(bundle_dir / "inputs/record_snapshot.json")
    traces = _read_jsonl(bundle_dir / "inputs/traces.jsonl")

    labels = None
    lp = bundle_dir / "inputs/trace_labels.jsonl"
    if lp.exists():
        labels = {r["trace_id"]: r["label"] for r in _read_jsonl(lp)}

    wot = None
    tp = bundle_dir / "inputs/work_order_tools.json"
    if tp.exists():
        wot = {k: v for k, v in _read_json(tp).items() if not k.startswith("_")}

    tick = _read_json(bundle_dir / COVERAGE_REL)["tick_id"]
    return run_dry_run(
        schema=schema,
        spec=spec,
        work_orders=work_orders,
        snapshot=snapshot,
        traces=traces,
        labels=labels,
        work_order_tools=wot,
        tick_id=tick,
    )


def compare(bundle_dir: Path) -> list[str]:
    """Every disagreement, not just the first, so one run tells the whole story."""
    problems: list[str] = []
    ours = rederive(bundle_dir)

    claimed_v = _read_jsonl(bundle_dir / VERDICTS_REL)
    ours_v = ours["verdicts"]
    if len(claimed_v) != len(ours_v):
        problems.append(
            f"VERDICT_COUNT_MISMATCH: bundle claims {len(claimed_v)}, re-derived {len(ours_v)}"
        )
    by_key = {(v["trace_id"], v["rung"]): v for v in claimed_v}
    for v in ours_v:
        key = (v["trace_id"], v["rung"])
        claimed = by_key.pop(key, None)
        if claimed is None:
            problems.append(f"VERDICT_MISSING: {key}")
            continue
        # Field by field. A verdict that agrees on ADMIT/DENY but disagrees on WHICH LAYER
        # refused is a mismatch: the refusing layer is the part a customer acts on.
        for field in (
            "verdict",
            "refusing_layer",
            "refusing_argument",
            "refusing_value_sha256",
            "rung_reached",
            "coverage",
            "fail_open_direction",
        ):
            if _canon(claimed.get(field)) != _canon(v.get(field)):
                problems.append(
                    f"VERDICT_FIELD_MISMATCH {key} {field}: "
                    f"bundle={claimed.get(field)!r} re-derived={v.get(field)!r}"
                )
    for key in by_key:
        problems.append(f"VERDICT_UNEXPECTED: {key} present in bundle, not re-derived")

    claimed_agg = _read_json(bundle_dir / AGGREGATE_REL)
    if _canon(claimed_agg) != _canon(ours["aggregate"]):
        problems.append("AGGREGATE_MISMATCH: the per-sink table does not re-derive")

    claimed_cov = _read_json(bundle_dir / COVERAGE_REL)
    if _canon(claimed_cov) != _canon(ours["coverage"]):
        problems.append("COVERAGE_MISMATCH: the coverage row does not re-derive")
    if claimed_cov["n_eligible"] != claimed_cov["n_issued"] + claimed_cov["n_withheld"]:
        problems.append("COVERAGE_SUM_VIOLATION: eligible != issued + withheld")

    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Re-derive an agent dry-run bundle")
    ap.add_argument("--bundle-dir", required=True, type=Path)
    args = ap.parse_args(argv)
    bundle_dir = args.bundle_dir.resolve()
    try:
        problems = compare(bundle_dir)
    except DryRunRefusal as exc:
        print(f"REFUSED {exc.reason_code}: {exc.detail}", file=sys.stderr)
        return 1
    except InputInadmissible as exc:
        # A bundle whose own bytes breach the admission bounds is rejected before any
        # re-derivation is attempted — fail-closed, never "could not parse, assume fine".
        print(f"INADMISSIBLE: {exc}", file=sys.stderr)
        return 1
    except (OSError, KeyError, ValueError) as exc:
        print(f"RE_DERIVATION_ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if problems:
        for p in problems[:20]:
            print(p, file=sys.stderr)
        if len(problems) > 20:
            print(f"... and {len(problems) - 20} more", file=sys.stderr)
        return 1
    print("re-derived: every verdict face, the aggregate table and the coverage row match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
