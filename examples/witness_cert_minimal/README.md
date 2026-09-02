# witness_cert_minimal — the verifier never solves

Most re-derivation checks re-run the producer's computation and compare. That
posture assumes the verifier *can* re-run it. Against a large model, a licensed
solver, or a method the producer is not obliged to disclose, it cannot.

This pilot demonstrates the other posture. The producer commits its
**displacement field as a witness**; the verifier checks a **certificate** over
it and never runs a solver at all.

## What a PASS certifies

1. The committed inputs are the ones the auditor anchored (sha256 per role).
2. Prescribed displacements hold **exactly**.
3. The free-DOF equilibrium residual of the **original** stiffness matrix is
   inside the auditor's tolerance.
4. Each claimed quantity lies within the certified interval of the quantity the
   witness algebraically implies.

All of it in exact rational arithmetic — every input is a JSON number, so it is
an exact `Fraction`, and the only approximate objects are the two tolerances,
which are auditor-anchored data in the binding spec and never producer-asserted.

**Faithfulness, not fitness.** A PASS says the claim follows from the anchored
problem and the committed witness. It says nothing about whether the structure
is adequate: no allowable, no margin of safety, no load-case coverage is
evaluated here. That judgement stays with the engineer.

## Solve however you like

Two unrelated solvers ship in `_producer_solve.py` — iterative conjugate
gradient and direct dense Gaussian elimination:

```bash
python examples/witness_cert_minimal/_build_bundle.py --out-dir /tmp/b --solver cg
python examples/witness_cert_minimal/verify.py --bundle-dir /tmp/b          # PASS

python examples/witness_cert_minimal/_build_bundle.py --out-dir /tmp/b2 --solver dense
python examples/witness_cert_minimal/verify.py --bundle-dir /tmp/b2         # PASS
```

They produce **different** displacement vectors and both pass the **same**
certificate, because equilibrium is a property of the answer rather than of the
procedure that found it. `test_the_two_solvers_really_do_disagree` keeps that
demonstration from going vacuous.

This is the property that matters when the producer is an agent: it may solve
any way it likes, at any cost, with any tool, and the acceptance criterion does
not change.

## Reproduction is not physics

Perturb one free DOF of the witness and realign its SHA. Nothing about the
claim or the file integrity is wrong any more — only the physics is:

```
FEA_CERT_EQUILIBRIUM_RESIDUAL ...
```

A solver that mishandles prescribed values would reproduce its own answer
perfectly on a re-run and still fail here.

## The auditor pins the problem, not only the mathematics

An analyst who honestly solves a **lighter load case** produces a witness that
satisfies equilibrium — for the problem they were handed:

```bash
python examples/witness_cert_minimal/_build_bundle.py --out-dir /tmp/light --load-scale 0.5
python examples/witness_cert_minimal/verify.py --bundle-dir /tmp/light
# FAIL ... FEA_CERT_INPUT_ANCHOR_MISMATCH: anchored role 'bcs'
```

The mathematics does not catch this — the witness is honest. The auditor's
`input_anchor` catches it. `test_the_same_lighter_case_passes_UNANCHORED` runs
the counterfactual and shows the identical bundle verifying clean once the
anchor is removed, so the anchor's contribution is measured rather than assumed.

## Layout is the lesson

```
witness_cert_minimal/
├── _producer_solve.py     the analyst's tool  — two solvers
├── _build_bundle.py       the analyst's run   — emits the bundle
├── bundle/                THE RECEIPT         — inputs, witness, claims
└── spec_pinned/           THE AUDITOR         — binding spec + published intervals
```

The bundle is a **subdirectory**, and the auditor's spec is its **sibling**. An
anchor taken from inside the bundle it judges lets the producer author both
sides of the comparison, so `SpecAnchor.from_files(..., forbid_within=...)`
refuses it. Point `--bundle-dir` at the pilot root and verification is refused,
not weakened.

`_build_bundle.py` never imports the verifier's primitive — every claimed number
comes from the producer's own solver. `test_producer_does_not_import_the_verifier`
enforces it by AST, because both files discuss the rule in prose and a text
search would match its own documentation.

## Verified by the shipped CLI, with no extra code

The three certificate primitives ship in the verifier distribution, so this
bundle is reachable by the bare tool:

```bash
python -m veriker.cli.verify \
  --bundle-dir  examples/witness_cert_minimal/bundle \
  --spec-anchor examples/witness_cert_minimal/spec_pinned/witness_cert.spec.json
```

## Regenerating the auditor spec

`spec_pinned/witness_cert.spec.json` pins the sha256 of the committed inputs, and
`spec_pinned/auditor_intervals.json` publishes the exact certified interval per
quantity. Both are derived from the committed problem — regenerate after any
change to it:

```bash
python examples/witness_cert_minimal/spec_pinned/_generate_auditor_spec.py
```

That generator is auditor-side tooling and *may* import the verifier's
primitive. The producer may not.
