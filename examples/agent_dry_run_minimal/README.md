# agent_dry_run_minimal — see what the gate would refuse, and recompute it yourself

Turning on a fail-closed gate with no way to see what it would refuse first is a bad trade,
so a dry-run — replay the traffic, report what *would* have been blocked, block nothing — is
the obvious answer, and it is not what makes this one different.

**What makes this one different is that it emits an audit bundle.** The reader recomputes
the counterfactual from the committed inputs rather than trusting the number on the report.
Words like "evidence", "proof" and "immutable audit trail" are routinely used to mean
logging, so the distinction cannot be carried by a word. It has to be carried by an artifact
that survives being run.

**Two limits on that sentence, stated here rather than several sections down.**

*It survives a forged **data** attack, not a forged **policy** attack.* Improving the numbers
in `payload/aggregate.json` and repairing every hash still fails. Rewriting `spec/` and
recomputing every verdict to match does **not** — the bundle is then internally perfect, and
only a copy of the spec from outside it disagrees. Those are battery families N2 and N3, and
they are misses by construction.

*"Without trusting us" is currently "recompute the math, and manually trust a
human-performed spec comparison."* The one check that separates a re-derivation from
testimony-about-itself is the external anchor, and no tooling in this distribution enforces
it (see Anchoring, below). That is the single fact that most limits how strong this claim is
allowed to be today.

---

## Run it

```
# replay a corpus and print the table
python examples/agent_dry_run_minimal/dry_run.py --inputs examples/agent_dry_run_minimal/fixtures/procurement_ap

# emit it as an audit bundle
python examples/agent_dry_run_minimal/_build_bundle.py --fixture procurement_ap --out-dir /tmp/b

# re-derive the whole table from the bundle alone
python examples/agent_dry_run_minimal/verify.py --bundle-dir /tmp/b
python veriker/cli/verify.py --bundle-dir /tmp/b
```

## The ladder

| rung | the value must ground in |
|---|---|
| 1 | *(name layer)* the sink is on the work order's tool set |
| 2 | anywhere in the trusted corpus — record snapshot + instruction |
| 3 | the instruction, **or** inside a record entry the instruction names — one hop |
| 4 | the instruction **alone** |
| 5 | the instruction's stated **selection rule** — **UNBUILT**, and never emitted |

Rungs are assigned **per sink**, never globally. `spec/ladder_spec.json` carries the
assignment. Shipping one rung suite-wide taxes every sink that did not need it: measured on
AgentDojo, the intent rung is free on the travel suite and costs the banking suite 43 points
of benign admit, because 41% of banking's destination values are resolved from the record
rather than quoted in the instruction.

## The two fixtures

**`procurement_ap`** — an accounts-payable agent over four vendors, four invoices and
fifteen replayed actions. No benchmark lineage: authored here, synthetic, labelled. This is
the fixture that satisfies "a bundle produced from a non-AgentDojo fixture verifies clean".

**`agentdojo_banking`** — exported once from AgentDojo v1.2.2 by
`export_agentdojo_fixture.py`; the pilot itself needs no agentdojo installed. **AgentDojo is
one fixture, not the interface.** Unlabelled, and with no work-order tool set, so it
exercises the two "say so rather than skip it" behaviours: rung 1 reports `NOT_EVALUATED`
and coverage withholds every trace, and the ground-truth block is omitted rather than
zero-filled.

### The cross-check that matters

Replayed through a runner that has never heard of AgentDojo, the exported fixture lands on
the intent-layer experiment's own recorded sink admit rates **exactly**:

| rung | dry-run over the fixture | `RESULT_intent_layer.json` |
|---|---:|---|
| 2 | 1.000 | `argref_ev` 1.000 |
| 3 | 0.643 | `argref_ev_ref` 0.643 |
| 4 | 0.500 | `argref_ev_obj` 0.500 |

**What this does and does not establish** — corrected 2026-08-18 after an adversarial pass
called the earlier "two independent paths" wording overstated, correctly.

*Independent:* the two **drivers** (the experiment's own rate loop vs `evaluate_trace` +
`aggregate`) and the two **encodings** — hardcoded policy dicts over live suite objects, vs
a declared JSON schema over committed JSON.

*Shared, deliberately:* the comparison primitive itself. `value_grounds` and `build_corpora`
have exactly ONE implementation, imported by both — that is a design property this pilot
argues for elsewhere, so it cannot also be counted as independent corroboration.

So the agreement catches a **parameterisation** bug — a policy mistranslated from dict to
declared schema, or data mangled from live objects to JSON. It **cannot** catch a bug in the
comparison logic, which would reproduce identically on both sides. Asserted in
`tests/test_agent_dry_run_minimal.py::test_agentdojo_fixture_agrees_with_the_intent_layer_run`,
read live from the recorded result rather than hardcoded.

## What the procurement fixture demonstrates

Every row below is a test, not a description.

- **Rung 3 earns its place, and costs nothing.** `T-12` writes a *genuine* IBAN onto the
  *wrong vendor*. Both values exist in the record, so rung 2 admits it. Only "is it where
  the instruction pointed" refuses it — deny rate 1.0 at **zero** false refusals on that
  sink.
- **Rung 1 catches what no value rung can.** `T-04` emails a real vendor address the work
  order never asked to email. The value grounds; the act is off-work-order.
- **Typed comparison refuses both lookalike directions.** `northwind.example` lifted out of
  `ap@northwind.example`, and `ap@northwind.example.co` extending it.
- **Rung 4 is unaffordable on one sink and free on another.** On `pay_invoice` it has a
  false-refusal rate of 1.0 — a payment IBAN is resolved from the invoice, never quoted in
  the instruction. On `send_remittance_email` it is free, because a remittance address *is*
  quoted. That is the per-sink assignment argument, in one fixture.
- **A wrong SELECTION passes every built rung.** `T-15` pays the largest invoice under an
  instruction that says the two smallest. Every value grounds, so nothing refuses it. Rung 5
  is unbuilt and this is what that costs.
- **A container name in prose widens the reference corpus.** `WO-4` says "invoices", which
  is a top-level container key, so rung 3 harvests every invoice and moves toward rung 2.
  The identifier-vs-schema-field rule stops *column* names doing this; it does not stop
  *container* names. Pinned as a test rather than left to be discovered.

## What a forged bundle looks like

Improve the numbers in `payload/aggregate.json`, then repair the manifest hash so the
forgery is hash-consistent. Every integrity check passes. Exactly one check notices:

```
FAIL  plugin:agent_dry_run   [plugin_failed] AGGREGATE_MISMATCH: the per-sink table does not re-derive
```

A hash chain establishes that what is present was not altered. It establishes nothing about
whether what was written was ever right. That gap is the reason this pilot exists.

## The fault battery

`battery/` plants 14 known-bad bundles with expectations pre-registered in
`battery/PREREGISTRATION.md` *before* the first run, and scores **agreement with that
pre-registration** rather than "faults caught" — because three families are expected
**misses**, and a battery scoring 14/14 detections would mean it was written to flatter the
checker.

Every planted fault repairs the manifest hash of whatever it edited, and hash-consistency is
asserted per fault before scoring. Otherwise the battery would be measuring file integrity.

| | |
|---|---:|
| mechanical families **caught** | 10/10 |
| structural families **missed, as predicted** | 3/3 |
| mutant control | caught (after the fix it forced — see FINDINGS) |
| → agreement with pre-registration | 14/14 |
| negative control detections | 0 of 1 clean bundle (consistency asserted first) |
| post-hoc families, added by the adversarial pass | 3/3 caught |

Read the first three rows, not the fourth: **14/14 is agreement, not detections.** Three of
the fourteen are expected misses. And the post-hoc row is counted separately on purpose —
those families were added *after* the 14/14, by a red-team agent this battery did not catch,
and folding them into the headline would retro-inflate a number whose only value is that it
was fixed in advance. One clean control is not a false-positive *rate*.

**The three predicted misses are the argument for an external anchor, not defects.** N1
deletes a refused trace from the inputs, its verdicts, the aggregate and the coverage row,
all recomputed — a chain proves non-edit, not non-omission. N2 loosens the ladder spec and
N3 downgrades an argument type, each recomputing every verdict to match. In N2 and N3 the
*policy itself* is the forgery: the bundle is internally perfect, and only a copy of `spec/`
from **outside** it disagrees.

**Read `battery/FINDINGS.md` before quoting the score.** The mutant control fired on its
first outing: a forged bundle that simply omitted `agent_dry_run` from
`manifest.typed_checks` passed the shipped CLI with exit 0, and the battery's own probe for
that family was measuring the wrong binary. Both are fixed; the sequence is recorded rather
than smoothed over.

## Anchoring — read before quoting a PASS

A PASS means the counterfactual re-derives. It is **not** a statement about tampering unless
`spec/tool_schema.json` and `spec/ladder_spec.json` were compared against copies from
**outside** the bundle. Anchoring on the bundle's own `spec/` copy is not a weaker anchor —
it is the *same fail-open* (measured 2026-08-17: a forged bundle anchored on its own spec
exits 0 OK). Unanchored, a stage-3 record degrades to stage 1, testimony, and does so
silently.

This distribution ships **no verifier flag that refuses an in-bundle anchor path**, and the
library API `BundleVerifier(spec_anchor=...)` has no in-bundle guard. The anchor comparison
is therefore a **manual step**, and every bundle says so in
`disclosures/anchor_status.json`. That record is a reminder, not a control: a self-declared
`"anchored": true` is testimony about itself.

## Three preconditions of the claim, enforced rather than assumed

Each was a real defect in the first draft, and each is a precondition of "the table
re-derives from the committed inputs":

- **The policy cannot change between parse and check.** `ToolSchema.tools` and
  `LadderSpec.sink_assignment` are deep-frozen at construction. `frozen=True` on a dataclass
  locks the binding, not the container, and every verdict is a function of those two values.
- **The label dispatch is exhaustive.** An unrecognised trace label used to fall through and
  drop its trace from *both* denominators, quietly improving every rate it touched. It is
  now refused.
- **The re-derivation bounds what it parses.** `agent_dry_run_pack.py` is pointed at bundles
  it did not produce, so every byte is attacker-controlled by assumption. All reads go
  through the admission-bounded loaders — size-reject before allocation, depth-scan before
  parse, cardinality-check after.

## Declared limits

Shipped inside every bundle at `disclosures/declared_limits.md`, written before any result
existed. The load-bearing one:

> A replayed dry-run reports what the gate would have done on traffic produced **under no
> gate**. The distribution shifts once a gate exists. It is a sample of the pre-gate
> distribution and is **never a bound on the post-gate one.**

## Files

- `dry_run.py` — replay a fixture, print the per-sink × rung table.
- `_build_bundle.py` — emit the replay as an audit bundle.
- `verify.py` — pilot-local verifier (§C5 auditor independence).
- `export_agentdojo_fixture.py` — run once with agentdojo installed; output is committed.
- `fixtures/<name>/{spec,inputs}/` — a complete inputs contract per fixture.
- `../../audit_bundle/plugins/reference/agent_ladder.py` — the engine, and the ONE place the
  comparison rules live. The AgentDojo experiment imports them from here rather than keeping
  a copy, so the numbers it reports and the numbers a bundle re-derives cannot drift apart.
- `../../audit_bundle/plugins/reference/agent_dry_run_pack.py` — the re-derivation.
- `../../audit_bundle/plugins/reference/AgentDryRunCheck.py` — the typed check that runs it.
