# event_log_replay_minimal — replay an append-only log to a record digest

`event_log_replay_recompute` ships in the open verifier. It is the one primitive
that consolidates a shape recurring across many domains: an authoritative record
that is not stored but *reconstructed*, by folding an append-only event stream.
Until this pilot, no public bundle ran it.

The domain here is synthetic and deliberately unremarkable — a hydraulic press in
a fictional workshop, commissioned once, inspected twice and amended twice.
Nothing about it is a compliance artifact and no regime is being asserted. The
log is a shape, and the shape is what the exemplar is for.

```bash
python examples/event_log_replay_minimal/_build_bundle.py --out-dir /tmp/b
python examples/event_log_replay_minimal/verify.py --bundle-dir /tmp/b     # PASS
```

## What a PASS certifies

Replaying the bundle's sole log — from its genesis `CREATE`, applying each
`AMEND` patch in file order, later writes winning — reconstructs a record whose
SHA-256 digest is **exactly** the one the producer claimed. The comparator is
`exact`; a digest agrees or it does not, and there is no tolerance to argue
about.

**Consistency, not provenance.** That sentence is doing more work than it looks,
so read it before the tamper table below. Every tamper this pilot catches is an
*inconsistent* edit — the log moves and the claimed digest does not. An adversary
who can rewrite the log and realign the manifest can equally rewrite the claim,
and this bundle has nothing to say about it. Replace the whole history with a
one-event log saying the press is in normal service, recompute the claim to
match, and it verifies **clean**;
`test_a_wholesale_consistent_replacement_PASSES` ships that as a passing test.

Nothing here fixes *which* record is under attestation. There is no pin (the log
is the thing that legitimately changes, so the SHA-pin mechanism the sibling
exemplars use does not apply to it), no hash chain, and no anchor on the genesis
event — though the primitive exposes `genesis_record_digest` for exactly that job
and nothing in this open shape consumes it. Fixing provenance needs something
out-of-band that this shape does not carry.

**And not completeness of the history.** A maintenance action nobody wrote down
leaves nothing to replay, and no re-derivation over a log can find it.

## The log is found, not pointed at

The verifier locates the log structurally: the **sole** `inputs/*.jsonl`. Zero is
a missing log; several is an ambiguous bundle. Both are refused rather than
resolved, so a producer cannot ship a friendlier second copy and hope the
verifier picks the right one:

```
RECOMPUTE_ERROR: event_log_replay expects exactly one inputs/*.jsonl event log,
found 2: ['service_log.jsonl', 'service_log_archive.jsonl']
```

Nothing in this pilot is SHA-pinned. That follows from the shape — pinning the
log would refuse every honest amendment — but it is a *limit* and not only a
design choice, and the consequences are the ones set out under **What a PASS
certifies** above.

## What the fold catches

| tamper | result |
| --- | --- |
| claimed digest replaced | `RE_DERIVATION_MISMATCH` |
| the restricting `AMEND` deleted | `RE_DERIVATION_MISMATCH` |
| the two `AMEND`s reordered | `RE_DERIVATION_MISMATCH` |
| the restricting `AMEND` edited in place | `RE_DERIVATION_MISMATCH` |
| a second log added | `RECOMPUTE_ERROR` |
| the log removed | `RECOMPUTE_ERROR` |

None of these leaves `manifest.files` inconsistent — the four edits realign the
changed file's SHA, the removal drops its entry, the decoy adds one — so file
integrity has no complaint and only the re-derivation can object. Each test
asserts the exact reason-code *set*, so the attribution is checked rather than
assumed.

All six are, again, *inconsistent* edits. See **What a PASS certifies**.

The reordering is worth a sentence. Later writes win, so swapping the two
amendments is not cosmetic: it puts the earlier `in_service` amendment last, and
the press's restriction vanishes from the reconstructed record.

## What the fold does not catch

This is a fold to **state**, not over the chain, and three tests in the battery
demonstrate what follows from that. None of them is a failure demonstration.

**An appended `LOG` event does not move the record.** Documented behaviour: `LOG`
is recorded but does not enter the authoritative record.

**Erasing every `LOG` event does not move it either.** Delete both inspections
from the log outright — history *removed*, not added — and the bundle verifies
clean. The inspections never entered the record, so their absence cannot change
the digest. An auditor whose question is "were the inspections done" is asking
about the completeness of the chain, and this shape does not answer it.

**Two different tamperings that reach one state produce one digest.** Reordering
the amendments and forging the later one arrive at the same reconstructed record.
Both are refused here — but only because neither matches the honest claim, not
because the check told them apart.

All three follow from "state fold, not a hash-chain fold", which the primitive's
own scope limits state in
[PRIMITIVES.md](../../audit_bundle/rederivation/PRIMITIVES.md). None of them is a
discovery. What they are is *measured*: the difference between reading that
sentence and watching a bundle with the inspections deleted from it come back
PASS is the difference between a limitation an adopter has been told about and
one they have accepted.

**Two more, and these are not in the primitive's declared scope limits at all.**

`seq` **is not read.** Order is file order and nothing else. Renumber every event
to a nonsense descending series and the bundle still verifies. A coherent-looking
sequence is documentation, not evidence, and this pilot carries no hash chain to
supply the difference.

**The accepted op set is wider than three.** The primitive's declared scope
limits say "Accepted ops are CREATE, AMEND and LOG". It also skips `DELETE`,
`DISPOSE`, `PURGE` and `DESTROY` — seven ops, not three; the primitive's module
docstring is the accurate one. So a `DESTROY` event appended to the log leaves
the record untouched and the bundle passes. This is also the one input class on
which the two folds genuinely disagree: `_producer_replay.py` accepts `LOG` and
nothing else, and raises `unrecognised op` on the same log the verifier accepts.
**The verifier is the laxer of the two.** A record-disposition regime adopting
this shape is adopting that.

**And `payload/reconstructed_record.json` is not bound by verification at all.**
Dispatch reads the log and the claim; it never opens the payload, which is
covered only by a producer-authored manifest SHA. A payload that flatly
contradicts the log rides to a clean PASS. Anything a reader takes from that
file, they take on the producer's word.

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
event_log_replay_minimal/
├── _producer_replay.py    the record-keeper's tool — its own copy of the fold
├── _build_bundle.py       the record-keeper's run  — emits the bundle
├── bundle/                THE RECEIPT              — log, record, claim
└── spec_pinned/           THE AUDITOR              — binding spec
```

The bundle is a **subdirectory** and the auditor's spec is its **sibling**. An
anchor taken from inside the bundle it judges lets the producer author both sides
of the comparison, so `SpecAnchor.from_files(..., forbid_within=...)` refuses it.

Neither producer module imports the verifier's primitive — the claimed digest
comes from the record-keeper's own fold. Two guards, and it is worth being exact
about what each one reads. `test_producer_does_not_import_the_verifier` in this
pilot's battery walks **both** `_build_bundle.py` and `_producer_replay.py` by
AST, because both files discuss the rule in prose and a text search would match
its own documentation. The repo-wide
`tests/test_recipe_producer_verifier_disjoint.py` covers every pilot that binds a
distribution primitive, which this one does. It reads the build script plus the
producer's whole compute surface: every pilot-local module the build script
imports, and every `_producer*.py` in the pilot directory. `_producer_replay.py`
is covered twice over.

Point `--bundle-dir` at the pilot root and the anchor would resolve inside the
directory under audit. That is an operator error, not a property of the bundle,
so `verify.py` exits **2** (could not conclude) rather than 1 (reject) — no
verdict about the artifact was formed, and saying "REJECT" would be a claim
nothing supports.

## Verified by the shipped CLI, with no extra code

```bash
python -m veriker.cli.verify \
  --bundle-dir  examples/event_log_replay_minimal/bundle \
  --spec-anchor examples/event_log_replay_minimal/spec_pinned/event_log_replay.spec.json
```
