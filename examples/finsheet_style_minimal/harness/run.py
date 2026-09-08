#!/usr/bin/env python3
"""run.py — the sweep: ask, bundle, re-derive, grade, record.

For every (question, model):
  1. prompt = system contract + serialised workbook + question (+ answer-kind
     format hint) -> cached completion (models.Client);
  2. parse strict JSON {answer, derivation}; unparseable -> recorded as
     `unparseable`, never as wrong and never as a catch;
  3. PRODUCER side: normalise the answer to the contract's normal form and
     build a bundle with the model's own derivation (_build_bundle.build_bundle);
  4. AUDITOR side: write the per-question spec (auditor_entry.make_spec, the
     question's bytes pinned) into run_dir/anchors/ — OUTSIDE the bundle — and
     verify under auditor_entry.build_verifier; read per-arm outcomes;
  5. grade the answer against gold at the verifier's tolerance (strict) and at
     the paper's tier-1 rule (2.5% relative, lenient);
  6. append one row to run_dir/results.jsonl.

Stages:
  --stage measure   one S4 question per model: prompt tokens + a first answer
                    (the pre-registered 120k stop); nothing else runs.
  --stage sweep     everything (default), resumable through the cache and the
                    results file.

Usage:
    python examples/finsheet_style_minimal/harness/run.py --set-dir /tmp/finsheet_set \
        --run-dir /tmp/finsheet_run --models claude-opus-4.6,gpt-5.2,gemini-3.1-pro --stage measure
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PILOT = _HERE.parent
_PKG_ROOT = _PILOT.parents[1]
for _p in (_PKG_ROOT, _PILOT, _HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))



def _load_by_path(name: str, path: Path):
    """Siblings by PATH under pilot-unique names, never bare `import models`:
    in any process that already holds another module of that name (a shared
    pytest run, another pilot's harness) the bare import silently binds the
    wrong one."""
    qual = f"finsheet_style_minimal__{name}"
    spec = importlib.util.spec_from_file_location(qual, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Registered BEFORE exec: @dataclass resolves sys.modules[cls.__module__]
    # at class creation and dies on an unregistered module.
    sys.modules[qual] = mod
    spec.loader.exec_module(mod)
    return mod


ae = _load_by_path("auditor_entry", _PILOT / "auditor_entry.py")
_models = _load_by_path("models", _HERE / "models.py")
ROSTER, Cache, Client, ModelSpec = _models.ROSTER, _models.Cache, _models.Client, _models.ModelSpec
serialize_workbook = _load_by_path("serialize", _HERE / "serialize.py").serialize_workbook


def _load_build():
    spec = importlib.util.spec_from_file_location(
        "finsheet_style_minimal__build_bundle", _PILOT / "_build_bundle.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_build = _load_build()

SYSTEM_PROMPT = """You are a financial analyst answering questions about a private-equity portfolio-monitoring workbook. The workbook is given as text: each sheet starts with "### Sheet: <name>", each following line is one row, cells are separated by tabs, blank cells are empty. There are no row or column indices. Multi-line header cells are shown with " / " between their lines.

Answer ONLY from the workbook. Respond with ONE JSON object and nothing else, of the form:

{"answer": <answer>, "derivation": {"op": <op>, "operands": [<operands>], "column": "<header text of the column you read>", "k": <int, topk only>}}

<answer> formats:
- number: a plain JSON number exactly as it appears in the sheet, or the computed value rounded HALF-UP to 2 decimals. No units, no currency symbols, no thousands separators, no "x".
- count: a JSON integer.
- string: the cell text.
- list: a JSON array of the exact company names as written in the sheet.

<op> is one of: lookup, list, count, sum, mean, median, argmax, topk. Show your working in "operands" — the actual cell values you used, exactly as they appear in the sheet:
- lookup: operands = [the cell value you report]
- list: operands = the company names you listed
- count: operands = the company names you counted
- sum / mean / median: operands = the numeric cell values you aggregated
- argmax: operands = [[company, value], ...] for every candidate you compared
- topk: operands = [[company, value], ...] for every candidate you compared, and "k"

Never include a value in operands that is not in the workbook. If a question cannot be answered from the workbook, answer null with op "lookup" and operands []."""

FORMAT_HINT = {
    "number": "Answer format: a number (2 decimals where the question says so).",
    "count": "Answer format: an integer count.",
    "string": "Answer format: the cell text (a string).",
    "list": "Answer format: a JSON array of company names.",
}

_WS = re.compile(r"\s+")
_NUM_CLEAN = re.compile(r"[,$£€\s]|x$|m$|\$m", re.IGNORECASE)


def norm_text(s: object) -> str:
    return _WS.sub(" ", str(s)).strip().casefold()


def _to_number(v: object) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        t = _NUM_CLEAN.sub("", v.strip())
        try:
            return float(Decimal(t))
        except (InvalidOperation, ValueError):
            return None
    return None


def normalise_answer(kind: str, v: object) -> object | None:
    """Producer-side normal form of the model's answer. None -> unusable."""
    if v is None:
        return None
    if kind == "number":
        # HALF_UP, the contract's rounding. Python round() is half-even on a
        # binary float: 85.945 -> 85.94, and 9 of the set's 48 mean/median
        # questions sit exactly on such a boundary (adversarial pass
        # 2026-09-02) — the harness would have manufactured wrong answers.
        if isinstance(v, str):
            t = _NUM_CLEAN.sub("", v.strip())
            try:
                d = Decimal(t)
            except (InvalidOperation, ValueError):
                return None
        else:
            n = _to_number(v)
            if n is None:
                return None
            d = Decimal(repr(n))
        if not d.is_finite():
            return None
        return float(d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    if kind == "count":
        n = _to_number(v)
        return None if n is None or n != int(n) else int(n)
    if kind == "string":
        return norm_text(v) if isinstance(v, (str, int, float)) else None
    if kind == "list":
        if isinstance(v, str):
            v = [x for x in re.split(r"[;\n]|,\s", v) if x.strip()]
        if not isinstance(v, list):
            return None
        return sorted({norm_text(x) for x in v if isinstance(x, (str, int, float))})
    return None


def parse_model_json(text: str) -> dict | None:
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.MULTILINE).strip()
    for cand in (t, t[t.find("{") : t.rfind("}") + 1] if "{" in t and "}" in t else ""):
        if not cand:
            continue
        try:
            doc = json.loads(cand)
            if isinstance(doc, dict) and "answer" in doc:
                return doc
        except json.JSONDecodeError:
            continue
    return None


def grade(kind: str, claimed: object, gold: object) -> tuple[bool, bool]:
    """(strict, lenient). strict = verifier tolerance; lenient = paper tier-1."""
    if claimed is None:
        return False, False
    if kind == "number":
        c, g = float(claimed), float(gold)
        strict = abs(c - g) <= 0.0051
        lenient = abs(c - g) <= 0.025 * abs(g) if g != 0 else abs(c) <= 0.0051
        return strict, lenient or strict
    if kind == "count":
        return (claimed == gold,) * 2
    if kind == "string":
        return (claimed == gold,) * 2
    if kind == "list":
        eq = sorted(claimed) == sorted(gold)
        return eq, eq
    return False, False


def _coerce_derivation(d: object, kind: str, answer_norm: object) -> dict:
    """Make the model's derivation a sheet-derivation-v1 document without
    inventing content: only the schema tag and a default op are added."""
    if not isinstance(d, dict):
        d = {}
    out = {"schema": "sheet-derivation-v1"}
    op = d.get("op")
    out["op"] = (
        op
        if isinstance(op, str)
        else {"number": "lookup", "count": "count", "string": "lookup", "list": "list"}[
            kind
        ]
    )
    ops = d.get("operands")
    out["operands"] = ops if isinstance(ops, list) else []
    if isinstance(d.get("column"), str):
        out["column"] = d["column"]
    if isinstance(d.get("k"), int):
        out["k"] = d["k"]
    out["round"] = 2
    return out


def _b_kind(b: dict) -> str:
    """pass | mismatch | operand_not_in_sheet | refused | error — keyed on the
    reason code and the refusal kind in the detail, never on free prose."""
    if b["state"] != "NOT_RE_DERIVED":
        return "pass"
    d = b.get("detail") or ""
    if b.get("reason_code") != "RE_DERIVATION_MISMATCH":
        return "error"
    if "'kind': 'operand_not_in_sheet'" in d:
        return "operand_not_in_sheet"
    if "'kind': 'refused'" in d:
        return "refused"
    return "mismatch"


def build_prompt(sheet_text: str, q: dict) -> str:
    return f"WORKBOOK:\n{sheet_text}\nQUESTION: {q['text']}\n{FORMAT_HINT[q['answer_kind']]}\nRespond with the JSON object only."


def run_cell(
    client: Client,
    spec: ModelSpec,
    set_dir: Path,
    run_dir: Path,
    sheet_text: str,
    q: dict,
) -> dict:
    fid, qid = q["file_id"], q["qid"]
    user = build_prompt(sheet_text, q)
    row: dict = {
        "model": spec.label,
        "file_id": fid,
        "layout": fid.split("_")[0],
        "size": fid.split("_")[1],
        "qid": qid,
        "tier": q["tier"],
        "answer_kind": q["answer_kind"],
        "gold": q["gold"],
    }
    try:
        comp = client.complete(spec, SYSTEM_PROMPT, user)
    except Exception as exc:  # noqa: BLE001
        row.update({"status": "api_error", "error": str(exc)[:300]})
        return row
    row["usage"] = comp.usage
    row["cached"] = comp.cached
    doc = parse_model_json(comp.text)
    if doc is None:
        row.update({"status": "unparseable", "raw_head": comp.text[:200]})
        return row
    if doc.get("answer") is None:
        # An explicit null is the model ABSTAINING on an answerable question,
        # not a format failure. Counted as its own status; the report shows
        # accuracy with and without it (adversarial pass 2026-09-02).
        row.update({"status": "abstained", "raw_head": comp.text[:200]})
        return row
    claimed = normalise_answer(q["answer_kind"], doc.get("answer"))
    if claimed is None:
        row.update(
            {
                "status": "unparseable",
                "raw_head": comp.text[:200],
                "answer_raw": doc.get("answer"),
            }
        )
        return row
    derivation = _coerce_derivation(doc.get("derivation"), q["answer_kind"], claimed)
    row["claimed"] = claimed
    row["derivation_op"] = derivation["op"]
    row["derivation_n_operands"] = len(derivation["operands"])
    row["query_op"] = q["query"]["op"]
    row["op_matches_question"] = derivation["op"] == q["query"]["op"]
    strict, lenient = grade(q["answer_kind"], claimed, q["gold"])
    row["correct_strict"] = strict
    row["correct_lenient"] = lenient

    # PRODUCER: bundle. AUDITOR: spec outside the bundle, then verify.
    query_bytes = json.dumps(q["query"], indent=2, sort_keys=True).encode("utf-8")
    spec_id = f"finsheet_style.{fid}.{qid}.v1"
    workbook_path = set_dir / "workbooks" / f"{fid}.xlsx"
    spec_bytes = ae.make_spec(
        spec_id, q["answer_kind"], query_bytes, workbook_path.read_bytes()
    )
    anchor_dir = run_dir / "anchors" / spec.label / fid
    anchor_dir.mkdir(parents=True, exist_ok=True)
    spec_path = anchor_dir / f"{qid}.spec.json"
    spec_path.write_bytes(spec_bytes)
    bundle_dir = run_dir / "bundles" / spec.label / fid / qid
    _build.build_bundle(
        bundle_dir,
        workbook_path=workbook_path,
        query_bytes=query_bytes,
        spec_bytes=spec_bytes,
        spec_basename=spec_path.name,
        claimed_value=claimed,
        derivation=derivation,
        bundle_id=f"finsheet-style-{spec.label}-{fid}-{qid}",
    )
    verifier, _anchor = ae.build_verifier(bundle_dir, spec_path)
    out = ae.read_outcomes(verifier.verify(bundle_dir))
    a = out["outputs"][ae.OUTPUT_SEMANTIC]
    b = out["outputs"][ae.OUTPUT_CONSISTENCY]
    row.update(
        {
            "status": "verified" if out["exit_code"] != 2 else "inconclusive",
            "exit_code": out["exit_code"],
            "A_state": a["state"],
            "A_reason": a["reason_code"],
            "A_detail": (a["detail"] or "")[:300],
            "B_state": b["state"],
            "B_reason": b["reason_code"],
            "B_detail": (b["detail"] or "")[:300],
            "B_kind": _b_kind(b),
            "other_failures": [f["reason_code"] for f in out["other_failures"]],
        }
    )
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description="FinSheet-style sweep")
    ap.add_argument("--set-dir", required=True, type=Path)
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--models", default="claude-opus-4.6,gpt-5.2,gemini-3.1-pro")
    ap.add_argument("--stage", choices=("measure", "sweep"), default="sweep")
    ap.add_argument("--files", default=None, help="comma list of file_ids")
    ap.add_argument("--qids", default=None, help="comma list of qids")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args()

    set_dir: Path = args.set_dir.resolve()
    run_dir: Path = args.run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    questions = json.loads((set_dir / "questions.json").read_text(encoding="utf-8"))
    if args.files:
        keep = set(args.files.split(","))
        questions = [q for q in questions if q["file_id"] in keep]
    if args.qids:
        keep = set(args.qids.split(","))
        questions = [q for q in questions if q["qid"] in keep]
    if args.limit:
        questions = questions[: args.limit]
    specs = [ROSTER[m] for m in args.models.split(",")]
    client = Client(Cache(run_dir / "cache"))
    sheets: dict[str, str] = {}

    def sheet(fid: str) -> str:
        if fid not in sheets:
            sheets[fid] = serialize_workbook(set_dir / "workbooks" / f"{fid}.xlsx")
        return sheets[fid]

    if args.stage == "measure":
        big = (
            [q for q in questions if q["size"] == "S4"]
            if any("size" in q for q in questions)
            else [q for q in questions if q["file_id"].endswith("_S4")]
        )
        big = [q for q in big if q["qid"] == "Q01"]
        for spec in specs:
            for q in big[:1] if not args.files else big:
                user = build_prompt(sheet(q["file_id"]), q)
                n_anthropic = client.count_tokens_anthropic(
                    ROSTER["claude-opus-4.6"], SYSTEM_PROMPT, user
                )
                row = run_cell(client, spec, set_dir, run_dir, sheet(q["file_id"]), q)
                print(
                    json.dumps(
                        {
                            "model": spec.label,
                            "file_id": q["file_id"],
                            "qid": q["qid"],
                            "anthropic_count_tokens": n_anthropic,
                            "usage": row.get("usage"),
                            "status": row.get("status"),
                            "claimed": row.get("claimed"),
                            "gold": q["gold"],
                            "A": row.get("A_state"),
                            "B": row.get("B_state"),
                        }
                    )
                )
        return 0

    results_path = run_dir / "results.jsonl"
    done: set[tuple[str, str, str]] = set()
    if results_path.is_file():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                if r.get("status") not in ("api_error",):
                    done.add((r["model"], r["file_id"], r["qid"]))
    todo = [
        (spec, q)
        for spec in specs
        for q in questions
        if (spec.label, q["file_id"], q["qid"]) not in done
    ]
    print(f"{len(todo)} cells to run ({len(done)} already recorded)")
    t0 = time.time()
    n = 0
    with (
        results_path.open("a", encoding="utf-8") as fh,
        ThreadPoolExecutor(max_workers=args.workers) as ex,
    ):
        futs = {
            ex.submit(
                run_cell, client, spec, set_dir, run_dir, sheet(q["file_id"]), q
            ): (spec, q)
            for spec, q in todo
        }
        for fut in as_completed(futs):
            row = fut.result()
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            fh.flush()
            n += 1
            if n % 20 == 0:
                print(f"  {n}/{len(todo)} done, {time.time() - t0:.0f}s")
    print(f"done: {n} cells in {time.time() - t0:.0f}s -> {results_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
