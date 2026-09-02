#!/usr/bin/env python3
"""export_agentdojo_fixture.py — turn an AgentDojo suite into a dry-run fixture.

    python examples/agent_dry_run_minimal/export_agentdojo_fixture.py --suite banking

Run ONCE, with agentdojo installed; the output is committed. After that the pilot needs no
agentdojo, which is the point: **AgentDojo becomes one fixture, not the interface.** The
runner takes a tool schema and a work-order corpus, and a third-party benchmark is simply
one source of those.

WHAT IS EXPORTED, and what is deliberately not:

  * work orders   — the suite's user-task prompts, verbatim.
  * record        — the CLEAN default environment, flattened to JSON. It holds all the
                    legitimate task data and none of the attack payload, exactly as
                    AgentDojo's own contract says.
  * traces        — the suite's canonical ground-truth calls per user task. These are the
                    "traffic produced under no gate" a dry-run replays.
  * tool schema   — the authority declaration and argument types from footprint.py, which is
                    OUR policy, plus every other tool the ground truth touches declared
                    non-authority-bearing so `UNKNOWN_TOOL` cannot fire spuriously.

  * NO labels. The exported corpus is entirely legitimate calls, so a label column would be
    a constant, and a constant column invites reading "0 attacks found" off a corpus that
    contains none by construction. The unlabelled path is the honest one here — and it
    exercises the omission behaviour the ADR requires.
  * NO work-order tool set. Rung 1 therefore reports NOT_EVALUATED and coverage withholds
    every trace, which is the behaviour worth demonstrating: a missing rung is reported, not
    skipped.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]
_EXPERIMENT = (
    _PKG_ROOT
    / "examples"
    / "payroll_agent_gate_minimal"
    / "experiments"
    / "agentdojo_rederive"
)
for p in (str(_PKG_ROOT), str(_EXPERIMENT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from footprint import (  # noqa: E402
    AUTHORITY_KEYS,
    AUTHORITY_KEY_TYPES,
    env_to_record_snapshot,
)

BENCHMARK_VERSION = "v1.2.2"


def _tool_schema(suite, env) -> dict:
    """Authority declaration for every tool the suite's ground truth actually calls."""
    touched: set[str] = set()
    for ut in suite.user_tasks.values():
        try:
            gt = ut.ground_truth(env)
        except Exception:  # noqa: BLE001
            continue
        for call in gt:
            touched.add(call.function)

    tools: dict = {}
    for name in sorted(touched):
        args: dict = {}
        for key in AUTHORITY_KEYS.get(name, []):
            args[key] = {"type": AUTHORITY_KEY_TYPES[(name, key)], "authority": True}
        tools[name] = {"args": args}
    return {
        "schema": "tool-schema.v1",
        "domain": f"agentdojo_{suite.name}",
        "note": (
            "Exported from AgentDojo "
            f"{BENCHMARK_VERSION}/{suite.name}. AgentDojo authored the tasks and the "
            "environment; the authority declaration and the argument types are OURS, "
            "lifted verbatim from footprint.py so this fixture and the intent-layer "
            "experiment cannot disagree about what is gated."
        ),
        "tools": tools,
    }


def export(suite_name: str, out_root: Path) -> None:
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(BENCHMARK_VERSION, suite_name)
    env = suite.load_and_inject_default_environment({})

    (out_root / "spec").mkdir(parents=True, exist_ok=True)
    (out_root / "inputs").mkdir(parents=True, exist_ok=True)

    (out_root / "spec" / "tool_schema.json").write_text(
        json.dumps(_tool_schema(suite, env), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    wo_lines, trace_lines = [], []
    n = 0
    for task_id, ut in sorted(suite.user_tasks.items()):
        try:
            gt = ut.ground_truth(env)
        except Exception:  # noqa: BLE001
            continue
        wo_lines.append(
            json.dumps(
                {"work_order_id": task_id, "instruction_text": getattr(ut, "PROMPT", "") or ""},
                sort_keys=True,
            )
        )
        for i, call in enumerate(gt):
            n += 1
            trace_lines.append(
                json.dumps(
                    {
                        "trace_id": f"{task_id}#{i:02d}",
                        "work_order_id": task_id,
                        "tool": call.function,
                        "args": env_to_record_snapshot(dict(call.args)),
                    },
                    sort_keys=True,
                )
            )
    (out_root / "inputs" / "work_orders.jsonl").write_text(
        "\n".join(wo_lines) + "\n", encoding="utf-8"
    )
    (out_root / "inputs" / "traces.jsonl").write_text(
        "\n".join(trace_lines) + "\n", encoding="utf-8"
    )
    (out_root / "inputs" / "record_snapshot.json").write_text(
        json.dumps(env_to_record_snapshot(env), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{suite_name}: {len(wo_lines)} work orders, {n} traces -> {out_root}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    out = args.out or (_HERE / "fixtures" / f"agentdojo_{args.suite}")
    export(args.suite, out.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
