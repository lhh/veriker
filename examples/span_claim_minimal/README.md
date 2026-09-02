# span_claim_minimal — is this quotation really in that document?

`spectra_span_recompute` ships in the open verifier. It answers one question: a
producer says a piece of text is a verbatim span of a source document; is it?
Until this pilot, no public bundle ran it.

The source here is synthetic — five sentences of a fictional bridge-survey note,
written for this example.

```bash
python examples/span_claim_minimal/_build_bundle.py --out-dir /tmp/b
python examples/span_claim_minimal/verify.py --bundle-dir /tmp/b     # PASS
```

## What a PASS certifies

The pinned document and the pinned pointer are the ones the auditor fixed, and
the sentence at that position — cut by the pinned segmentation rule — matches the
producer's claimed quotation under the anchored normalization.

It does **not** say the quoted sentence is true, or representative of the
document it came from. Only that it is in there. And "verbatim" is doing less
work than it looks — see *What a PASS does not say*, below.

## Two pins, two questions, both load-bearing

Everything the re-derivation reads is written by the producer, so the auditor
pins it. There are two pins because there are two questions, and each has a
single-pin counterfactual arm in the battery: lift *that* pin, leave the other in
force, and the bundle verifies **clean**.

One qualifier up front rather than buried at the bottom: in this exemplar the
"auditor" is a script that runs the producer and hashes what it emitted
(see [Regenerating the auditor spec](#regenerating-the-auditor-spec)). The pins
are therefore a record of an earlier producer run, and what they buy is that a
tamper *after* pinning is refused. In a real engagement the auditor holds the
source document independently.

**Which document.** Hallucinate a quotation, then edit the source until the
re-derivation returns it. The claim and the document now agree perfectly:

```
FAIL
  [spec_pinned_dispatch:quoted_span] PINNED_INPUT_MISMATCH: output 'quoted_span':
  auditor-pinned input 'corpus/27200c80….txt' has SHA … but the anchored spec
  requires … — the recompute input was substituted after the auditor pinned it
```

`test_the_same_rewritten_source_passes_UNPINNED` strips `pinned_inputs` and the
same bundle verifies clean. The mathematics has no complaint; the pin is the
whole of the refusal.

**Which sentence of it.** Pinning the corpus alone is not enough, and this is the
part that is easy to get wrong. Leave the pinned document untouched, ship a
*second* one beside it, and repoint `source_cid` at that. The pointer is part of
the auditor's **question**, not part of the producer's answer, so it is pinned
too.

Note what does *not* stop this. The corpus file is named for the sha256 of its own
bytes — but that is a convention of this pilot, not something the verifier checks.
The primitive resolves the name it is given and never confirms that the name
matches the content, so `decoy` resolves happily. A content-addressed filename
looks like an integrity property and is not one.

The producer's claimed **text** is deliberately not pinned. That is the answer;
pinning it would leave nothing to verify.

## How much the duplicated copy buys — less than in the siblings

`_producer_extract.py` is the producer's own implementation of the pinned
segmentation rule, and `_build_bundle.py` imports it rather than the verifier's
primitive. But the two are the same rule and, as far as can be measured, the
same function: a differential fuzz over 200,000 random documents finds no input
on which they disagree, and a shorter run of it ships as
`test_the_two_segmenters_agree_on_everything_tried`.

So an honest PASS here shows the claim was not **routed through** the verifier's
code — a structural fact about where the value came from — and **not** that two
behaviourally different programs agreed. That is weaker than the sibling
exemplars: `fea_vonmises_minimal`'s two copies differ by a summation
compensation term, and `event_log_replay_minimal`'s verifier accepts an op-set
its producer refuses.

The one asymmetry that is real runs the safe way. The verifier additionally
contains the read inside `corpus/` and range-checks `fragment_id`; the producer
does neither. A pilot whose *checker* were the laxer side would be the dangerous
shape.

## The read is contained

`source_cid` is bundle-controlled and gets interpolated into a path, so a hostile
bundle could otherwise turn the auditor's read into an arbitrary-file oracle on
the auditor's own machine. A `..` traversal is refused:

```
FAIL
  [spec_pinned_dispatch:quoted_span] RECOMPUTE_ERROR: output 'quoted_span':
  primitive 'spectra_span_recompute' raised ValueError: bundle path
  '/etc/passwd.txt' resolves outside …/corpus — refusing the read (path containment)
```

Three payloads are exercised, not one: a traversal that stays inside the bundle,
a traversal out of the bundle root, and an absolute path. The last two name a
file that exists on the auditor's machine, so a missing-file error cannot be
mistaken for containment — an earlier draft tested only the first, which never
left the bundle and so never exercised the threat the rule is written for.

Those tests run with the **pointer pin** removed, on purpose. With it in place the
tamper is caught before the recompute reads anything, and the test would be
measuring the pin rather than the containment. Two independent defences, and the
inner one is measured on its own.

## What a PASS does not say

`spectra_v1` normalizes by NFC, casefold, **dropping all punctuation**,
collapsing whitespace and stripping. So a PASS is about the words and their
order. The committed sentence is chosen so this can be shown rather than
described:

> The reviewers**,** who had access to the raw telemetry**,** endorsed the
> contractor's figure.

With the commas, that is a non-restrictive clause: *all* the reviewers endorsed
the figure, and the telemetry access is an aside. Take them out and the clause
becomes restrictive: *only* the reviewers who had telemetry access endorsed it.
Different claim, same words, and the two normalize identically —
`test_a_quotation_that_changes_what_the_sentence_says_PASSES` ships as a
**passing** test.

The variant it claims is derived from the honest span by `.replace(",", "")` and
the test asserts that the two differ in exactly that way, so the demonstration is
the minimal comma-only counterexample the paragraph above describes. (An earlier
draft also upper-cased two words and dropped an apostrophe, which would have
shown something broader than the claim.)

That is not a defect in the primitive. It is what the anchored profile says it
does, and it ships as a test so that adopting the profile is a decision rather
than an assumption.

Segmentation is likewise the terminator rule alone: no abbreviation, quotation
or list handling, so `Fig. 4` would be cut in two. The one exception is a `.`
between digits, which is why the committed document contains `3.5 mm` — without
that exception the source would cut into six fragments and every `fragment_id`
after the first would shift.

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

## What the bundle does not bind

`payload/extraction_record.json` is not read by verification at all. Dispatch
opens the pointer, the corpus and the claim; the payload is covered only by a
producer-authored manifest SHA, so one that contradicts the claim rides to a
clean PASS. Anything a reader takes from that file, they take on the producer's
word — `test_the_payload_record_is_not_bound_by_verification` ships that as a
passing test.

That is a loose ornament here rather than a hole, and the difference is the
pins: they fix which document and which sentence are under attestation, so the
thing a PASS is *about* is nailed down even though this one file is not. The
sibling `event_log_replay_minimal` cannot pin anything — its log is the thing
that legitimately changes — and there the same unbound-payload observation sits
on top of a much larger limit. Worth reading the two together.

## Layout is the lesson

```
span_claim_minimal/
├── _producer_extract.py   the quoting tool     — its own copy of the rule
├── _build_bundle.py       the quoting run      — emits the bundle
├── bundle/                THE RECEIPT          — source, pointer, claim
└── spec_pinned/           THE AUDITOR          — binding spec + SHA pins
```

The bundle is a **subdirectory** and the auditor's spec is its **sibling**. An
anchor taken from inside the bundle it judges lets the producer author both sides
of the comparison, so `SpecAnchor.from_files(..., forbid_within=...)` refuses it.

Point `--bundle-dir` at the pilot root and the anchor would resolve inside the
directory under audit. That is an operator error, not a property of the bundle,
so `verify.py` exits **2** (could not conclude) rather than 1 (reject) — no
verdict about the artifact was formed, and saying "REJECT" would be a claim
nothing supports.

Neither producer module imports the verifier's primitive.
`test_producer_does_not_import_the_verifier` walks both by AST, because both
files discuss the rule in prose and a text search would match its own
documentation. The repo-wide
`tests/test_recipe_producer_verifier_disjoint.py` covers every pilot that binds a
distribution primitive, which this one does.

## Verified by the shipped CLI, with no extra code

```bash
python -m veriker.cli.verify \
  --bundle-dir  examples/span_claim_minimal/bundle \
  --spec-anchor examples/span_claim_minimal/spec_pinned/span_claim.spec.json
```

## Regenerating the auditor spec

```bash
python examples/span_claim_minimal/spec_pinned/_generate_auditor_spec.py
```

**Read that command for what it is.** The generator runs the producer and pins
the bytes that run emitted, so the pins record which document and which sentence
an earlier producer run used. That is acceptable in an exemplar the repository
must also be able to rebuild. It is not the posture for a real engagement: there
the auditor holds the source document independently and hashes their own copy.
