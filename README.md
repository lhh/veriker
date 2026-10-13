<div align="center">

# Veriker

**Recompute the answer. Don't trust the claim.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Verify](https://img.shields.io/badge/verify-offline_·_stdlib--only-success.svg)](#the-bundle)
[![Verdict](https://img.shields.io/badge/verdict-OK_·_REJECT_·_ERROR-informational.svg)](#the-verdict)
[![Status](https://img.shields.io/badge/status-v0.x_experimental-orange.svg)](#-status-experimental)

</div>

A producer publishes a number and claims it follows from some inputs under some
rule. Veriker takes the inputs, the rule and the claimed number as one folder (a
*bundle*), recomputes the number itself, and compares. It runs offline, from the
Python standard library alone, and answers with an exit code. If it can't
recompute, it refuses; a refusal is never reported as a pass.

The rule and the tolerance come from the party doing the checking, not from the
bundle. A producer who ships a looser rule changes nothing, because the
verifier won't read it.

## 🚧 Status: experimental

Veriker is v0.x, offered under Apache-2.0 as is. The first line of every run
says so (`veriker 0.2.2 (experimental)`) and the label travels on every
verdict, so a verdict forwarded out of context says what this paragraph says.

What that does promise: a bundle the verifier can't re-derive is refused (exit
2), never passed; the fuzz harnesses under `tests/fuzz/` and the regression
battery run on every change; a silent false PASS is the bug class this project
exists not to have. What it doesn't promise: no production, verified, or 1.0 claim
is made before a completed, dated third-party audit of the verifier
core and the DSSE/COSE/Rekor consumption paths, with its findings fixed. The
target date goes in [SECURITY.md](SECURITY.md) once the engagement is booked.
Releases are unsigned until the signing ceremony.
What changed between releases, including removed public names, is in
[RELEASE_NOTES.md](RELEASE_NOTES.md).

If you can make it print PASS on something you tampered with, through any
input a producer controls, that's the finding we want most. SECURITY.md has
the disclosure path and the named-credit policy.

## Install

```bash
pip install veriker          # the verifier: no dependencies at all, Python 3.11+
```

That gives you the `veriker` command (also `python -m veriker`). To build the
example bundles or to develop, clone and install from source:

```bash
git clone https://github.com/veriker/veriker && cd veriker
pip install -e ".[dev]"
```

Four extras exist for paths that need third-party code: `crypto` (Ed25519
verdict signatures, DSSE and revocation consumption), `c19` (cross-host and
trusted-time), `hostverify` (the TUF-fetched host-digest check) and `all`.
None is needed to verify a bundle. No shipped pilot exercises a DSSE envelope
or a transparency-log anchor end to end, so the presence of those extras is
not evidence that those paths are proven here.

## One run

A vehicle model publishes four tyre loads per sample and asserts they satisfy
rigid-body equilibrium. The checker doesn't own the model; it just substitutes
the published loads into three equations and looks at the residual. Build the
bundle, then verify it with the checker's own spec, primitives and work-set,
none of which live inside the bundle:

```console
$ python examples/corner_load_equilibrium_minimal/_build_bundle.py --out-dir /tmp/cl --profile clean
$ veriker --bundle-dir /tmp/cl \
    --spec-anchor examples/corner_load_equilibrium_minimal/spec_pinned/corner_load_equilibrium.spec.json \
    --primitives  examples/corner_load_equilibrium_minimal/auditor_kit.py \
    --work-set    examples/corner_load_equilibrium_minimal/spec_pinned/corner_load_equilibrium.work_set.json \
    --require-rederivation
veriker 0.2.2 (experimental)
PASS  file_integrity
PASS  spec_sha_pinning
PASS  cross_refs
…
PASS  plugin:refinement_discharge

    acceptance  coverage_exact_outputs@1 APPLIED - satisfied
    type_selection  auditor WORK-SET APPLIED - universe_sha=678abd3b… provenance=SELF_AUTHORED
    recompute_detail  'corner_load_vertical_residual': worst |residual| over 120 sample(s) at index 104 = 0.561530 (480 exact rational ops, no solve)
    recompute_detail  'corner_load_pitch_residual': worst |residual| over 120 sample(s) at index 83 = 1.227961 (960 exact rational ops, no solve)
    …
decision  RELEASE through multi_root (roots auditor/producer; proposer producer); proposer root only on 13/13 propositions

PASS  (12 check(s) passed)
$ echo $?
0
```

Now a bundle whose hashes are all intact but whose numbers are wrong: the same
model, on a trip outside the envelope it was fitted on.

```console
$ python examples/corner_load_equilibrium_minimal/_build_bundle.py --out-dir /tmp/cl_drift --profile drift
$ veriker --bundle-dir /tmp/cl_drift --spec-anchor … --primitives … --work-set … --require-rederivation
veriker 0.2.2 (experimental)
PASS  file_integrity
…
PASS  plugin:refinement_discharge
FAIL  spec_pinned_dispatch:corner_load_vertical_residual  [RE_DERIVATION_MISMATCH] … rational_band: claimed value not within epsilon of recomputed R (claimed=0.000000000e+00, R=1.728193350e+02, epsilon=4.000000000e+01)
FAIL  spec_pinned_dispatch:corner_load_pitch_residual     [RE_DERIVATION_MISMATCH] … (claimed=0.000000000e+00, R=1.117628850e+03, epsilon=6.000000000e+01)
FAIL  spec_pinned_dispatch:corner_load_roll_residual      [RE_DERIVATION_MISMATCH] …
FAIL  spec_pinned_dispatch:corner_load_transfer_split_residual  [RE_DERIVATION_MISMATCH] …
FAIL  re_derivation_surface  [VERIFIER_INCOMPLETE] …
decision  REFUSE through multi_root (roots auditor/producer; proposer producer); proposer root only on 11/13 propositions; contradicted [...]

FAIL  (5 failures across 17 check(s))
$ echo $?
1
```

Both blocks are real output from this tree, with the twelve structural checks,
one gated note and the long digests cut for width. Every file hash matched in
the second run. A checksum would have passed it; the recompute found a 173 N
hole in a claim of zero, against a tolerance of 40 N that the producer never
saw.

## The verdict

| Verdict  | Exit | Meaning |
|----------|:----:|---------|
| `OK`     | `0`  | every gating check passed |
| `REJECT` | `1`  | the *artifact* failed a check: tampering, drift, a forged field, a claim that doesn't recompute |
| `ERROR`  | `2`  | the *verifier* couldn't conclude: a claimed re-derivation it couldn't run, a missing dependency, an anchor that resolved inside the bundle |

The split matters because a crashing input must not launder itself into a
clean REJECT, and an unrunnable check must never become a PASS. Old scripts
that key on `exit != 0` stay correct. `--verdict-out verdict.json` writes the
full verdict face on every exit path (state, reason codes, which layers ran,
the disclosures a green verdict still carries, the manifest's SHA-256). It's an
unsigned operational file and says so; trust comes from re-running the
verifier on the bundle, not from the file.

## The bundle

```
bundle/
├── manifest.json     # every file with its SHA-256, the spec pins, the declared outputs, the typed checks
├── spec/             # the producer's copy of the spec (for the record; the verifier anchors on yours, not this)
├── inputs/           # the committed input snapshots
└── outputs/          # the claimed values, one file each, that the verifier recomputes
```

The verifier reads nothing outside the folder except what you hand it on the
command line. The schema is [MANIFEST_SCHEMA.md](MANIFEST_SCHEMA.md).

Three things on the checker's side, held outside the bundle:

- `--spec-anchor` names which primitive recomputes which output and under
  which comparator and tolerance. The anchor is a digest of the committed spec
  bytes, so a bundle shipping a weaker spec fails `spec_sha_pinning`.
- `--primitives` is the recompute code. The distribution carries a set of
  promoted primitives ([PRIMITIVES.md](audit_bundle/rederivation/PRIMITIVES.md));
  a pilot can ship its own kit and you point at it. A primitive the CLI can't
  load ends the run at `UNKNOWN_PRIMITIVE`, never at a pass.
- `--work-set` is your complete list of the outputs the bundle must deliver,
  each pinned to its type. Without it the producer chooses which claims arrive,
  and the verdict face says so.

The core path never executes code from inside a bundle. Running a bundle's own
re-derivation pack is behind `--unsafe-run-bundle-pack` and is for disposable
hosts only.

## What a PASS says

That each declared output is, within the checker's tolerance, what the
checker's primitive computes from the committed inputs; that every file still
has the digest the manifest commits to; that every structural invariant the
bundle declares still holds. Each is its own line with its own reason code
([REASON_CODES.md](audit_bundle/plugins/REASON_CODES.md)), so a failure names
what broke.

Not that the inputs are true, not that the rule is the right rule, not that a
deployment complies with any standard. Every pilot's data is synthetic. A
bundle that declares no outputs gets structural checks only, and the verdict
prints a `NO_RE_DERIVATION_PERFORMED` note to say so; `--require-rederivation`
turns that note into a failure.
[THREAT_MODEL.md](audit_bundle/rederivation/THREAT_MODEL.md) states what each
check claims to catch and what it leaves open.

## Build your own bundle

The producer side is `audit_bundle.emitter`: it lays out the folder, computes
the digests and writes a canonical manifest.

```python
from audit_bundle.emitter import BundleContent, write_bundle

content = BundleContent(...)   # inputs, outputs, spec copies, typed checks
write_bundle(out_dir, content)
```

Every `_build_bundle.py` under `examples/` is a worked case;
`examples/corner_load_equilibrium_minimal/` is the one to copy, since its
checker-side files (spec, kit, work-set) are laid out exactly as the command
above consumes them. `tests/test_emitter_sdk.py` is the conformance contract.
Timestamp, causal-chain and attestation hooks are protocol seams with
no-network defaults.

## Pilots

`examples/` holds one self-contained bundle builder per computation shape, each
with its own README stating the property it demonstrates and the limits of
that claim; twenty ship their own `tests/`. Citation integrity, climate totals, SQL
aggregates, deterministic builds, finite-element solves, case-law citations,
sensor fusion, streaming windows and more. A pilot that needs an extra, an
SMT solver or `torch` says so when you run it. Older pilots route their
re-derivation through their own `verify.py` rather than the anchored CLI
command shown above; their READMEs say which.

```bash
ls examples/
python examples/<name>/build_bundle.py --help      # some are _build_bundle.py
```

## Tests

```bash
pytest                                            # the verifier and substrate suite
pytest examples/<name>/tests/                     # one pilot, where it ships a suite
python scripts/run_example_batteries.py           # every pilot, each in its own interpreter
```

The pilot suites are isolated on purpose: module names repeat across pilots, so
`pytest examples/` is refused with a pointer at the runner rather than
reporting a number that looks measured. The stdlib-only claim is enforced by a
test that re-verifies bundles under an import hook blocking every third-party
package; the full contract, each clause indexed to the test that holds it, is
[VERIFIER_CONTRACT.md](VERIFIER_CONTRACT.md).

## Security, contributing, licence

- Vulnerabilities: [SECURITY.md](SECURITY.md).
- Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). DCO, not a CLA. New
  pilots follow the anchored layout above and run `pytest` before submitting.
- [GOVERNANCE.md](GOVERNANCE.md), [TRADEMARK.md](TRADEMARK.md), and the
  [no-relicense pledge](NO-RELICENSE.md).
- Apache License 2.0: [LICENSE](LICENSE), [NOTICE](NOTICE).

Veriker is built by Nexi Technologies, Inc., who also build
[NEXIVERIFY](https://nexiverify.com), a commercial audit-trail product for
regulated teams. Veriker stays free under Apache-2.0.
