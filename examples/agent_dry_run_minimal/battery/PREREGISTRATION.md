# Fault battery — pre-registration

**Committed before the battery was run.** Expectations are recorded here first so a result
cannot be reinterpreted after the fact into whatever the checker happens to do.

A dry-run that never refuses anything is indistinguishable from a broken dry-run. The
battery plants known-bad bundles and asks which ones the re-derivation notices.

## The construction rule that makes this measure anything

**Every planted fault repairs the manifest hash of whatever it edited.** A forgery that
leaves a hash mismatch is caught by `file_integrity_many_small`, which tells us nothing about
re-derivation. Only a hash-consistent forgery isolates the property under test.

## Expected CAUGHT — 10 mechanical families

| id | fault | why it must be caught |
|---|---|---|
| F1 | `AGGREGATE_FLATTERED` — admit counts raised on one (sink, rung) | the headline number is the thing a deployment decision is made on |
| F2 | `VERDICT_FLIPPED` — one DENY face rewritten to ADMIT | a per-action verdict is what a customer investigates |
| F3 | `REFUSING_LAYER_RELABELLED` — verdict correct, `refusing_layer` wrong | the refusing layer is the part a customer acts on; agreeing on ADMIT/DENY is not enough |
| F4 | `COVERAGE_DENOMINATOR_SHRUNK` — `n_eligible` lowered | the mechanism by which a dry-run would otherwise flatter itself |
| F5 | `VALUE_SHA_WRONG` — `refusing_value_sha256` replaced | the bundle's only commitment to *which* value was refused |
| F6 | `RUNG_5_CLAIMED` — the ladder spec assigns the unbuilt rung | claiming a capability that does not exist |
| F7 | `LABEL_BLOCK_WITHOUT_LABELS` — labelled block kept, labels file deleted | ground truth asserted with nothing behind it |
| F8 | `TRACE_ARG_EDITED` — a refused IBAN in `inputs/traces.jsonl` swapped for an authorised one | the inputs are the evidence; editing them must not silently agree with the old verdicts |
| F9 | `WORK_ORDER_TEXT_EDITED` — the refused value appended to an instruction | would make rung 4 admit; the recorded verdict says otherwise |
| F10 | `SNAPSHOT_ENTRY_ADDED` — the attacker value injected into the record snapshot | would make rung 2 admit; the recorded verdict says otherwise |

## Expected MISSED — 3 structural families, and these ARE the anchor argument

Pre-registered as misses. A battery reporting 13/13 would mean the battery was written to
flatter the checker.

| id | fault | why it is a miss by construction |
|---|---|---|
| N1 | `TRACE_DELETED_CONSISTENTLY` — a refused trace removed from the inputs, its verdicts, the aggregate and the coverage row, all recomputed | **a chain proves non-edit, not non-omission.** Nothing in the bundle records that a fourteenth trace ever existed |
| N2 | `LADDER_SPEC_LOOSENED` — `max_identifier_occurrences` raised so schema field names become followable references; every verdict recomputed to match | the bundle is internally perfect. Only a copy of the spec **from outside the bundle** disagrees |
| N3 | `ARG_TYPE_DOWNGRADED` — `send_remittance_email.recipients` retyped `EMAIL` → `TEXT`, weakening the boundary rule so a bare domain lifted out of an authorised address grounds; every verdict recomputed | same shape as N2, one level down: the policy itself is the forgery |

N2 and N3 are the reason `disclosures/anchor_status.json` exists and the reason §4 of the ADR
forbids anchoring on the bundle's own `spec/` copy. They are not gaps to be closed by a better
checker — no checker that reads only the bundle can close them.

## Mutant negative control

A detector shown only the faults it was designed around is not evidence. One family below was
authored deliberately outside that set:

| id | fault | prediction, recorded before running |
|---|---|---|
| M1 | `TYPED_CHECK_UNCLAIMED` — `agent_dry_run` removed from `manifest.typed_checks`, so the verifier never constructs the plugin, on an otherwise forged bundle | **predicted CAUGHT.** The substrate is documented as refusing a claimed-but-absent plugin; whether it also refuses the reverse — a check silently *not* claimed — was not designed for and is not known. If this is MISSED it is a finding about the substrate, not about this pilot, and it will be reported as one |

## Negative control

The unmutated `agentdojo_banking` bundle — a different fixture, built by the same emitter,
never touched by the battery. **Expected 0 detections.**

*(Wording corrected 2026-08-18 after a process audit: the original said "0 detections out of
13 probes", which never matched the implementation — the control is scored by one combined
re-derivation pass returning one binary result, not by 13 per-family probes. The number
measured and reported was always the binary one.)*

Consistency is asserted *before* scoring: the control must re-derive cleanly first. A negative
control whose planted inputs disagree with their own cited sources measures propagation rather
than blindness — the failure that made an earlier pilot's control score 2/6 for reasons that
had nothing to do with the detector.

---

## Post-hoc additions (adversarial pass, 2026-08-18) — NOT part of the pre-registration

Added **after** the battery had already scored 14/14, by a fresh-context red-team agent that
found something this battery did not. Kept in a separate section, and counted separately in
the result, because a pre-registration that quietly grows once the answer is known is not a
pre-registration. The 14 families above and their `EXPECTED` dict are unchanged.

| id | fault | expected |
|---|---|---|
| P1 | `ONE_ARTIFACT_DELETED_OTHER_FORGED` — forge `payload/verdicts.jsonl`, **delete** `payload/aggregate.json`, drop the `typed_checks` claim | CAUGHT |
| P2 | `OTHER_ARTIFACT_DELETED_FIRST_FORGED` — the symmetric direction | CAUGHT |
| P3 | `ONLY_VERDICTS_LEFT_AND_FORGED` — strip every other artifact the trigger looks at | CAUGHT |

**What they found.** M1's fix made the typed check presence-triggered — but as an **AND** of
two artifacts. Deleting either one while forging the other defeated the presence trigger and
the claim trigger together, and `veriker/cli/verify.py` returned exit 0 on a bundle with 20 DENY
verdicts rewritten to ADMIT. The battery scored 14/14 with that hole live, because M1 drops
the *claim* while keeping both files and no family dropped a *file*.

Two lessons, both about method rather than about this bug: a fix validated only against the
case that motivated it is untested; and a presence trigger must fire on **any** member of the
artifact set, never all of it, because an AND hands the attacker a deletion as an escape.

## Scoring

- **Detected** = `agent_dry_run_pack.py` exits non-zero on the mutated bundle.
- Integrity plugins are deliberately *not* part of the score. Every mutation repairs the
  hashes it disturbs, so anything they catch would be a construction error in the battery, and
  the battery asserts hash-consistency per fault before scoring.
