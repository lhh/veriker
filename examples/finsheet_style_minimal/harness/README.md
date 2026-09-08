# harness — the FinSheet-style sweep

Asks models the 384 questions, builds one audit bundle per answer with the
model's own stated derivation, re-derives each bundle under a per-question
anchored spec generated OUTSIDE the bundle, grades against gold, and reports
the pre-registered tables. Predictions and stop conditions are frozen in
`../PREREGISTRATION.md`; read that first.

## Run

```bash
cd <repo root>   # the directory holding pyproject.toml
python examples/finsheet_style_minimal/_generate_set.py --out-dir /tmp/finsheet_set

# 1. the pre-registered token guard: one S4 question per model, prompt tokens printed
python examples/finsheet_style_minimal/harness/run.py --set-dir /tmp/finsheet_set \
    --run-dir /tmp/finsheet_run --models claude-opus-4.6,gpt-5.2,gemini-3.1-pro --stage measure

# 2. the sweep (resumable: cache + results.jsonl)
python examples/finsheet_style_minimal/harness/run.py --set-dir /tmp/finsheet_set \
    --run-dir /tmp/finsheet_run --models claude-opus-4.6,gpt-5.2,gemini-3.1-pro --workers 3

# 3. the report
python examples/finsheet_style_minimal/harness/report.py --run-dir /tmp/finsheet_run --md /tmp/finsheet_run/REPORT.md
```

API keys are read from the environment, or from a `KEY=value` file named by
`$FINSHEET_KEYS_FILE`, and never written anywhere. `claude-haiku-4.5` is available as a cheap smoke
model and is NOT part of the pre-registered roster.

## What a row records (`results.jsonl`)

`model, file_id, layout, size, qid, tier, answer_kind, gold, claimed,
correct_strict, correct_lenient, A_state/A_reason/A_detail,
B_state/B_reason/B_detail, B_kind (mismatch | operand_not_in_sheet | refused |
pass), derivation_op, derivation_n_operands, usage, status`.

`status` is one of `verified` (both arms concluded), `inconclusive` (verifier
exit 2), `unparseable` (no JSON `answer`, or an answer that does not fit the
kind), `api_error`. Only `verified` rows enter accuracy and catch rates.

## Cache key

sha256 over provider, model, temperature, max_output_tokens, the
provider-specific reasoning config, system prompt, user prompt, sample index.
Every one of those changes the answer, so every one is in the key. Claude with
extended thinking runs at temperature 1 (the API requires it); that value is
in the key, not hidden.

## Where the split comes from

| wrong answer class | A (`answer_semantic`) | B (`answer_consistency`) |
|---|---|---|
| hallucinated_operand | fires | fires, `operand_not_in_sheet` |
| arithmetic | fires | fires, mismatch or refusal, all operands present |
| selection | fires | passes |
| uncaught | passes | passes — only at the strict/lenient boundary or on an A refusal |

The harness holds the gold to GRADE; the verifier never sees it. A catch is a
verdict reached from the workbook bytes, the pinned question, and the
producer's own working.
