#!/usr/bin/env python3
"""report.py — results.jsonl -> the pre-registered tables, every number with
its denominator.

Definitions (PREREGISTRATION.md):
  wrong        graded incorrect at the STRICT tolerance (verifier's), among
               parseable, concluded cells; lenient (2.5% relative) reported
               beside it
  catch rate   of wrong answers, share the arm marked NOT_RE_DERIVED
  false alarm  of correct answers, share the arm marked NOT_RE_DERIVED
  split of wrong answers:
    hallucinated_operand  B fired with operand_not_in_sheet
    arithmetic            B fired (mismatch/refused), operands all present
    selection             B passed, A fired
    uncaught              neither arm fired (only possible at the strict/lenient
                          boundary or on an A refusal)
  unparseable / inconclusive / api_error are counted separately and are never
  wrong and never a catch.

Usage:
    python examples/finsheet_style_minimal/harness/report.py --run-dir /tmp/finsheet_run [--md out.md]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

TIERS = ["low", "medium", "high", "very_high"]
SIZES = ["S1", "S2", "S3", "S4"]
LAYOUTS = ["L1", "L2", "L3", "L4", "L5", "L6"]


def _pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:.1f}% ({n}/{d})" if d else "n/a (0)"


def load(run_dir: Path) -> list[dict]:
    rows = []
    for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    # keep the LAST row per (model, file, qid) — reruns append
    last: dict[tuple, dict] = {}
    for r in rows:
        last[(r["model"], r["file_id"], r["qid"])] = r
    return list(last.values())


def classify_wrong(r: dict) -> str:
    """hallucinated_operand | arithmetic | malformed_derivation | selection |
    uncaught. `malformed_derivation` is B refusing the derivation document
    itself (unknown op, non-numeric operands, empty aggregate) or a checker
    error: the model's WORKING was unusable, which is not evidence the model
    computed wrong (adversarial pass 2026-09-02)."""
    a_fired = r.get("A_state") == "NOT_RE_DERIVED"
    b_fired = r.get("B_state") == "NOT_RE_DERIVED"
    kind = r.get("B_kind")
    if b_fired and kind == "operand_not_in_sheet":
        return "hallucinated_operand"
    if b_fired and kind in ("refused", "error"):
        return "malformed_derivation"
    if b_fired:
        return "arithmetic"
    if a_fired:
        return "selection"
    return "uncaught"


def table(rows_by_key: dict, keys: list[str], cols: list[str], cell) -> str:
    out = ["| model | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for k in keys:
        out.append(
            f"| {k} | " + " | ".join(cell(rows_by_key[k], c) for c in cols) + " |"
        )
    return "\n".join(out)


def build_report(rows: list[dict]) -> str:
    models = sorted({r["model"] for r in rows})
    by_model: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_model[r["model"]].append(r)
    md: list[str] = ["# FinSheet-style sweep — report", ""]

    # --- status counts
    md.append("## Cells by status")
    md.append(
        "| model | verified | abstained | unparseable | inconclusive | api_error | total | acc strict incl. abstentions |"
    )
    md.append("|---|---|---|---|---|---|---|---|")
    for m in models:
        rs = by_model[m]
        c = defaultdict(int)
        for r in rs:
            c[r.get("status", "?")] += 1
        v = [r for r in rs if r.get("status") == "verified"]
        denom = len(v) + c["abstained"]
        md.append(
            f"| {m} | {c['verified']} | {c['abstained']} | {c['unparseable']} | {c['inconclusive']} | "
            f"{c['api_error']} | {len(rs)} | {_pct(sum(1 for r in v if r.get('correct_strict')), denom)} |"
        )
    md.append("")

    def concluded(rs):
        return [r for r in rs if r.get("status") == "verified"]

    # --- accuracy by tier and size (strict; lenient in parentheses)
    def acc_cell(rs, key, val):
        sub = [r for r in concluded(rs) if r.get(key) == val]
        n = len(sub)
        s = sum(1 for r in sub if r.get("correct_strict"))
        le = sum(1 for r in sub if r.get("correct_lenient"))
        return f"{_pct(s, n)} / len {_pct(le, n)}" if n else "n/a"

    md.append("## Accuracy by tier (strict / lenient), among concluded cells")
    md.append(table(by_model, models, TIERS, lambda rs, t: acc_cell(rs, "tier", t)))
    md.append("")
    md.append("## Accuracy by size (strict / lenient)")
    md.append(table(by_model, models, SIZES, lambda rs, s: acc_cell(rs, "size", s)))
    md.append("")
    md.append("## Accuracy by layout (strict / lenient)")
    md.append(table(by_model, models, LAYOUTS, lambda rs, l: acc_cell(rs, "layout", l)))
    md.append("")

    # --- overall + catch/false-alarm per arm, both tolerances
    md.append("## Re-derivation: catch rate and false-alarm rate per arm")
    md.append(
        "Catch = of WRONG answers, share the arm marked NOT_RE_DERIVED. False alarm = of CORRECT answers, share flagged. Strict = verifier tolerance; lenient = paper tier-1 (2.5% rel)."
    )
    md.append("")
    md.append(
        "| model | acc strict | acc lenient | A catch (strict) | A false-alarm (strict) | A catch (lenient) | A false-alarm (lenient) | B catch (strict) | B false-alarm (strict) | B catch (lenient) | B false-alarm (lenient) |"
    )
    md.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for m in models:
        rs = concluded(by_model[m])
        n = len(rs)
        cells = [
            m,
            _pct(sum(1 for r in rs if r["correct_strict"]), n),
            _pct(sum(1 for r in rs if r["correct_lenient"]), n),
        ]
        for arm in ("A", "B"):
            for tol in ("strict", "lenient"):
                key = f"correct_{tol}"
                wrong = [r for r in rs if not r[key]]
                right = [r for r in rs if r[key]]
                cells.append(
                    _pct(
                        sum(1 for r in wrong if r[f"{arm}_state"] == "NOT_RE_DERIVED"),
                        len(wrong),
                    )
                )
                cells.append(
                    _pct(
                        sum(1 for r in right if r[f"{arm}_state"] == "NOT_RE_DERIVED"),
                        len(right),
                    )
                )
        md.append("| " + " | ".join(cells) + " |")
    md.append("")

    # --- B catch by tier (P4)
    md.append("## Arm B catch rate by tier (strict wrong answers)")

    def b_catch(rs, t):
        wrong = [r for r in concluded(rs) if r["tier"] == t and not r["correct_strict"]]
        return _pct(
            sum(1 for r in wrong if r["B_state"] == "NOT_RE_DERIVED"), len(wrong)
        )

    md.append(table(by_model, models, TIERS, b_catch))
    md.append("")

    # --- split of wrong answers (P5, P6)
    md.append("## Split of strict-wrong answers")
    md.append(
        "| model | tier | wrong | hallucinated_operand | arithmetic | malformed_derivation | selection | uncaught | op matches question |"
    )
    md.append("|---|---|---|---|---|---|---|---|---|")
    for m in models:
        for t in TIERS + ["ALL"]:
            wrong = [
                r
                for r in concluded(by_model[m])
                if not r["correct_strict"] and (t == "ALL" or r["tier"] == t)
            ]
            c = defaultdict(int)
            for r in wrong:
                c[classify_wrong(r)] += 1
            opm = sum(1 for r in wrong if r.get("op_matches_question"))
            md.append(
                f"| {m} | {t} | {len(wrong)} | {c['hallucinated_operand']} | {c['arithmetic']} | "
                f"{c['malformed_derivation']} | {c['selection']} | {c['uncaught']} | {_pct(opm, len(wrong))} |"
            )
    md.append("")

    # --- hallucinated operands on S4 (P6)
    md.append("## Hallucinated operands among strict-wrong answers, S4 files")
    for m in models:
        wrong = [
            r
            for r in concluded(by_model[m])
            if not r["correct_strict"] and r["size"] == "S4"
        ]
        h = sum(1 for r in wrong if classify_wrong(r) == "hallucinated_operand")
        md.append(f"- {m}: {_pct(h, len(wrong))}")
    md.append("")

    # --- unparseable on S4 (P7)
    md.append("## Unparseable on S4")
    for m in models:
        s4 = [r for r in by_model[m] if r["size"] == "S4"]
        md.append(
            f"- {m}: {_pct(sum(1 for r in s4 if r.get('status') == 'unparseable'), len(s4))}"
        )
    md.append("")

    # --- tokens
    md.append("## Tokens (sum over cells with usage)")
    md.append("| model | cells | input tokens | output tokens | max input |")
    md.append("|---|---|---|---|---|")
    for m in models:
        rs = [r for r in by_model[m] if r.get("usage")]
        inp = sum((r["usage"].get("input_tokens") or 0) for r in rs)
        outp = sum((r["usage"].get("output_tokens") or 0) for r in rs)
        mx = max(((r["usage"].get("input_tokens") or 0) for r in rs), default=0)
        md.append(f"| {m} | {len(rs)} | {inp:,} | {outp:,} | {mx:,} |")
    md.append("")

    # --- uncaught list (the interesting residue)
    unc = [
        r
        for r in rows
        if r.get("status") == "verified"
        and not r["correct_strict"]
        and classify_wrong(r) == "uncaught"
    ]
    md.append(f"## Uncaught strict-wrong answers ({len(unc)})")
    for r in unc[:40]:
        md.append(
            f"- {r['model']} {r['file_id']} {r['qid']}: claimed {r['claimed']!r} gold {r['gold']!r} A={r['A_state']} B={r['B_state']} {r.get('A_detail', '')[:120]}"
        )
    md.append("")
    return "\n".join(md)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--md", type=Path, default=None)
    args = ap.parse_args()
    rows = load(args.run_dir)
    text = build_report(rows)
    if args.md:
        args.md.write_text(text, encoding="utf-8")
        print(f"wrote {args.md}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
