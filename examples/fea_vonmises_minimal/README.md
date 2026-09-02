# fea_vonmises_minimal — re-run the pinned solve, and pin what it reads

`fea_vonmises_recompute` ships in the open verifier. This is the public bundle
it runs on: a synthetic plane-stress bracket, authored here, with no named firm
and no premium leg anywhere in it.

The producer solves the problem and claims one number — the maximum von-Mises
stress. The verifier re-assembles the same constant-strain-triangle system from
the committed inputs, re-runs the pinned conjugate-gradient solve, recovers the
stress itself, and compares.

```bash
python examples/fea_vonmises_minimal/_build_bundle.py --out-dir /tmp/b
python examples/fea_vonmises_minimal/verify.py --bundle-dir /tmp/b     # PASS
```

## What a PASS certifies

1. The four files the re-derivation reads are byte-for-byte the ones the auditor
   pinned.
2. Re-running the pinned solve over them reproduces the producer's claimed
   `sigma_vm_max` inside the auditor's epsilon.

**Faithfulness, not fitness.** Nothing here evaluates whether the structure is
adequate: no allowable, no margin of safety, no load-case coverage. That
judgement stays with the engineer.

**And not solver independence.** The auditor pinned this algorithm, so re-running
it *is* the claim. `_producer_solve.py` is a separately written implementation of
that same algorithm, which is what keeps the comparison from being `f(x) == f(x)`
— but it is the same algorithm, and a producer running a different solver would
be running a different method. A posture where the producer may solve any way it
likes is a different shape; the certificate family in
[PRIMITIVES.md](../../audit_bundle/rederivation/PRIMITIVES.md) carries that one,
and this primitive's own scope limits say so.

## Why there is a tolerance at all

The two implementations are not bit-identical, and the reason is exact and
singular. Assembly, the boundary-condition passes and stress recovery are
bit-equal — `test_the_two_implementations_are_not_the_same_arithmetic` asserts
that term by term. The conjugate-gradient loops are not: the verifier writes its
matrix-vector product as a builtin `sum()` over a generator, the producer
accumulates in an explicit loop, and on CPython 3.12 `sum()` applies compensated
(Neumaier) summation while a `+=` fold does not. From CG iteration 2 onward 8 of
this problem's 36 rows differ in their last bits, and that reaches
`sigma_vm_max` as **1.4e-12** (measured, CPython 3.12.3).

Compensated summation is an interpreter implementation detail, not a property of
IEEE-754, so an `exact` comparator would bind the claim to one interpreter.
`epsilon = 1e-9` is roughly 700× the measured difference and still about five
orders below any physically meaningful change in the stress. The test above
re-measures the relationship on whatever interpreter runs the suite rather than
trusting the sentence you just read.

## Everything the recompute reads is producer-written, so all of it is pinned

The verifier reads `inputs/{mesh,material,bcs}.json` for the problem and
`spec/solver_config.json` for its own stopping tolerance. The producer writes all
four. The auditor's spec therefore pins each by SHA (`pinned_inputs`, §4a.7), and
a substitution fails closed *before* the recompute reads the file.

Two arms measure what that pin is actually worth, and they do not agree.

**The pin doing work nothing else does.** An analyst runs a completely honest
analysis of a *different* load case:

```bash
python examples/fea_vonmises_minimal/_build_bundle.py --out-dir /tmp/light --shear-scale 0.6
python examples/fea_vonmises_minimal/verify.py --bundle-dir /tmp/light
# FAIL ... PINNED_INPUT_MISMATCH: auditor-pinned input 'inputs/bcs.json'
```

The claimed stress is *correct* for the problem it was handed, so the
re-derivation reproduces it and the mathematics has no complaint.
`test_the_same_substituted_load_case_passes_UNPINNED` strips `pinned_inputs`
from the anchored spec and shows the identical bundle verifying clean. The pin
is the only thing refusing it.

**The pin as belt-and-braces.** Loosening the solver tolerance is the other
obvious attack on a producer-written parameter, and here the pin is *not* what
catches it:

```bash
python examples/fea_vonmises_minimal/_build_bundle.py --out-dir /tmp/loose --tol 1e-1
```

`PINNED_INPUT_MISMATCH` fires — but remove the pin and the bundle still fails,
`RE_DERIVATION_MISMATCH`. Under early stopping the producer's and verifier's
independently-written CG copies stop at different points and diverge by 4.1e-4
(2.7e-5 at `--tol 1e-2`), far outside the 1e-9 band; from `--tol 1e-3` down the 36-DOF
system is fully converged and the answer does not move at all.
`test_loosened_tolerance_would_ALSO_have_failed_the_comparator` keeps that
negative result in the suite rather than leaving the pin looking load-bearing on
both arms.

## The band is a band

```
+1.0        -> RE_DERIVATION_MISMATCH   (the mutant control)
+1.1e-9     -> RE_DERIVATION_MISMATCH
+0.9e-9     -> PASS
```

The middle line is the one that matters. A reject-everything comparator is
already caught by the tests that assert a clean PASS; what those cannot see is a
band **wider** than the auditor pinned. Refusing at 1.1e-9 and admitting at
0.9e-9 measures the edge itself, and a mutant of +1.0 alone would have been
satisfied by any band narrower than 1.0.

## Nothing re-derived must not read as PASS

`manifest.outputs` is a producer-authored declaration of *what to check*. Delete
it — three lines — and the spec-pinned dispatch never runs: every pinned byte
still matches, every plugin still passes, and a **default** `BundleVerifier`
returns clean having re-derived nothing. It is strictly easier than any tamper in
the tables above, and it was measured on this pilot rather than reasoned about.

`verify.py` therefore builds its verifier with `require_rederivation=True`, and
the same bundle is refused:

```
COULD NOT CONCLUDE
  [re_derivation_surface] VERIFIER_INCOMPLETE: …
```

Exit **2**, not 1. Nothing was shown to be wrong with the artifact; the verifier
was prevented from concluding anything about it, and those are different
answers. Both halves ship as tests — the default verifier passing, and the entry
point refusing — because the gap between them is the whole point.

## Layout is the lesson

```
fea_vonmises_minimal/
├── _producer_solve.py     the analyst's tool  — its own copy of the algorithm
├── _build_bundle.py       the analyst's run   — emits the bundle
├── bundle/                THE RECEIPT         — inputs, solver config, claim
└── spec_pinned/           THE AUDITOR         — binding spec + SHA pins
```

The bundle is a **subdirectory** and the auditor's spec is its **sibling**. An
anchor taken from inside the bundle it judges lets the producer author both sides
of the comparison, so `SpecAnchor.from_files(..., forbid_within=...)` refuses it.

Point `--bundle-dir` at the pilot root and the anchor would resolve inside the
directory under audit. That is an operator error, not a property of the bundle,
so `verify.py` exits **2** (could not conclude) rather than 1 (reject) — no
verdict about the artifact was formed, and saying "REJECT" would be a claim
nothing supports.

Neither producer module imports the verifier's primitive — every claimed number
comes from the producer's own solver. Two guards, and it is worth being exact
about what each one reads. `test_producer_does_not_import_the_verifier` in this
pilot's battery walks **both** `_build_bundle.py` and `_producer_solve.py` by
AST, because both files discuss the rule in prose and a text search would match
its own documentation. The repo-wide
`tests/test_recipe_producer_verifier_disjoint.py` covers every pilot that binds
a distribution primitive, which this one does. It reads the build script plus the
producer's whole compute surface: every pilot-local module the build script
imports, and every `_producer*.py` in the pilot directory. A producer copy that
was loaded through `importlib` **and** not named `_producer*` would still sit
outside it.

## Verified by the shipped CLI, with no extra code

`fea_vonmises_recompute` ships in the verifier distribution and resolves by core
auto-registration, so this bundle is reachable by the bare tool:

```bash
python -m veriker.cli.verify \
  --bundle-dir  examples/fea_vonmises_minimal/bundle \
  --spec-anchor examples/fea_vonmises_minimal/spec_pinned/fea_vonmises.spec.json
```

## Regenerating the auditor spec

`spec_pinned/fea_vonmises.spec.json` pins the sha256 of every file the
re-derivation consumes, so it is derived from the committed problem — regenerate
after any change to it:

```bash
python examples/fea_vonmises_minimal/spec_pinned/_generate_auditor_spec.py
```

**Read that command for what it is.** The generator *runs the producer* and pins
the bytes that run emitted; the only content an auditor authored independently is
the epsilon. So the pins record **which problem was analysed**, and regenerating
them is the one-command way to move the arm this README calls load-bearing. That
is acceptable in an exemplar, where the point is to show the mechanism on a
problem the repository also has to be able to rebuild. It is not the posture for
a real engagement: there the auditor supplies the inputs, or hashes a copy they
obtained independently, and never re-derives the pin from a producer run.

The generator is auditor-side tooling and *may* read the verifier's side — this
one happens not to need it. The producer may not, under any circumstances.
