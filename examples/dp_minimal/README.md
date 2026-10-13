# dp_minimal — Audit Bundle Quick-Start

> **Legacy front door, not evidence.** This pilot's `verify.py` predates the anchored CLI:
> its re-derivation does not catch a changed input whose manifest digest has been
> re-aligned; only file integrity catches the demo below. A PASS here does not show that
> the claimed output re-derives from the committed inputs; the anchored command in the
> root README, with the spec, primitives and work-set held outside the bundle, is. The
> pilot stays until it is migrated.

Minimal domain pilot: differential-privacy release bundled for V-kernel audit
verification (the audit-bundle contract §C5, C6, C9).

Demonstrates stochastic-but-seed-pinned re-derivation — the output is a noisy
aggregate, but the noise draw is deterministic given the committed seed and
mechanism parameters.

## Prerequisites

Python 3.10+.  No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/dp_minimal/_build_bundle.py --out-dir /tmp/dp_bundle
```

Expected output:

```
Bundle written to /tmp/dp_bundle
  dataset rows     : 100
  true_count       : 6
  noised_count     : 6.404251
  manifest files   : 2
  manifest         : /tmp/dp_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/dp_minimal/verify.py --bundle-dir /tmp/dp_bundle
```

Expected stdout: `PASS`.  Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                             |
|-----------------------------|---------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                       |
| `dp_re_derivation`          | §C6 DP-release re-derivation (seed-pinned)  |

## Step 3 — Tamper-flow demo

Mutate one row in `data/dataset.jsonl` so the `true_count` changes:

```bash
# Linux / macOS
python -c "
import json, pathlib
p = pathlib.Path('/tmp/dp_bundle/data/dataset.jsonl')
lines = p.read_text().splitlines()
# The first row is already '18-29'; move it to another bucket
row = json.loads(lines[0])
row['age_bucket'] = '30-39'
lines[0] = json.dumps(row)
p.write_text('\n'.join(lines) + '\n')
"
```

Re-run the verifier:

```bash
python examples/dp_minimal/verify.py --bundle-dir /tmp/dp_bundle
```

Expected exit code: `1`, from `BAD_FILE_SHA`: file integrity catches the changed
bytes. If you also re-align the file's digest in `manifest.json`, this pilot's
re-derivation does **not** catch the change and the run exits `0`. That is the
limit the note at the top of this README refers to.

## File layout

```
examples/dp_minimal/
├── _build_bundle.py          # builds a deployable bundle
├── verify.py                 # runs both TypedCheck plugins
├── DpReDerivationCheck.py    # domain plugin (DP release re-derivation)
├── dp_re_derivation.py       # re-derivation implementation (stdlib only)
└── README.md
```
