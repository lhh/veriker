# Fault battery — findings

`RESULT_battery.json` records the state *after* the fixes below. This file records how it
got there, because a result file that shows only the final green overstates what happened.

---

## M1 — the mutant control fired. The shipped CLI passed a forged bundle, exit 0.

**Pre-registered prediction:** CAUGHT.
**First measurement:** **MISSED.**

A bundle with a forged `payload/aggregate.json` that simply drops `agent_dry_run` from
`manifest.typed_checks` passed `veriker/cli/verify.py` with **exit 0**. The plugin was never
constructed, nothing re-derived, and the flattered numbers rode a green exit code.

This is the exact class the substrate already carries as a ratified red-team finding (A1, in
`veriker/cli/verify.py::_c19_crosshost_structural_check`): *"the substrate CC2 cross-check only fires
for names listed in `manifest.typed_checks` — which an attacker simply omits."* That finding
was closed for cross-host edges by making the check **presence-triggered**: if the artifact
that needs checking is present, fail closed regardless of what the manifest claims.

**Fix, following that ratified pattern:** `AgentDryRunCheck` is now constructed when the
manifest claims it **or** when the bundle carries `payload/verdicts.jsonl` and
`payload/aggregate.json`. Carrying the artifacts *is* the obligation.

Note the pilot-local `examples/agent_dry_run_minimal/verify.py` never had this hole — it
constructs the plugin unconditionally. Only the generic CLI's conditional construction did.

### The battery itself was measuring the wrong thing, and that is the second finding

The first run scored M1 as **CAUGHT**, incorrectly. The probe ran
`agent_dry_run_pack.py` directly, and the pack re-derives unconditionally — it never reads
`manifest.typed_checks`. M1 attacks *which checks the verifier decides to construct*, so a
probe that bypasses the verifier answers a question nobody asked.

A fault family is only as good as the probe pointed at it. The runner now records a `probe`
column per family, routes M1 through the shipped CLI binary, and runs **both** probes on
every other family so a fault the pack catches but the shipped binary does not would surface
as `PROBE_DISAGREEMENT` rather than hide.

---

## P1-P3 — the fix for M1 was itself broken, and a red-team agent found it the same day

**The battery scored 14/14 with this live.** That is the honest measure of a 14-family
battery: it is fourteen shapes someone thought of.

M1's fix made the typed check presence-triggered, but wrote the trigger as an **AND**:

```python
_dry_run_artifacts_present = (verdicts.jsonl).exists() and (aggregate.json).exists()
```

Forge one artifact, **delete the other**, drop the `typed_checks` claim, repair the surviving
hash. Both triggers are defeated at once, the plugin is never constructed, and nothing else
in the default CLI plugin set reads those paths. Reproduced with 20 DENY verdicts rewritten
to ADMIT: `veriker/cli/verify.py` → `PASS (12 checks)`, **exit 0**.

**Why the battery missed it:** M1 drops the *claim* while keeping both files. No family
dropped a *file*. The fix was validated against exactly the case that motivated it, which is
the same as not validating it.

**Fixed:** the trigger now fires on **any** of `payload/verdicts.jsonl`,
`payload/aggregate.json`, `coverage/dry_run_coverage.json`, and the plugin's own required-file
list includes the coverage row. With any one present the plugin is constructed, and its
missing-file branch then fails closed (`VERIFIER_INCOMPLETE`, exit 2) rather than passing.

**Generalises past this bug:** a presence trigger must be an OR over the artifact set. An AND
hands the attacker a deletion as an escape route.

The pilot's own `verify.py` was never vulnerable to this either — it constructs the plugin
unconditionally. Twice now the generic CLI has been the weaker of the two verifiers.

A red-team pass also confirmed one attack that **failed**, worth recording so the absence is
not mistaken for absence of testing: path traversal via a `manifest.files` key
(`../../../../etc/passwd`) is correctly rejected by `_safe_bundle_path`.

---

## Reported, not fixed: four sibling plugins share the claim-triggered shape

`veriker/cli/verify.py` constructs `span_re_derivation`, `sensor_re_derivation`,
`control_rederivation` and `aigov_rederivation` on `if <name> in claimed` — the same shape
that produced M1. Whether each is exploitable depends on whether its bundle's re-derivable
artifacts are identifiable by presence, which is a per-pilot question.

**Not changed here.** Those are other pilots' bundles and other owners' conformance
expectations; a presence trigger added blind could reject bundles that are currently valid.
Flagged for a decision rather than fixed unilaterally.

---

## The three pre-registered misses held

N1, N2 and N3 were MISSED exactly as predicted, and they are the artifact's argument for an
external anchor rather than defects in it:

- **N1** deleted a refused trace from the inputs, its verdicts, the aggregate and the coverage
  row, all recomputed. The bundle is internally perfect. **A chain proves non-edit, not
  non-omission** — nothing in a bundle records that a fourteenth trace ever existed.
- **N2** loosened `max_identifier_occurrences` so schema field names become followable
  references, and recomputed every verdict to match.
- **N3** retyped `send_remittance_email.recipients` from `EMAIL` to `TEXT`, weakening the
  boundary rule so a bare domain lifted out of an authorised address grounds, and recomputed.

For N2 and N3 the *policy itself* is the forgery. No checker that reads only the bundle can
close them; only a copy of `spec/` from **outside** the bundle disagrees. This is why the ADR
forbids anchoring on the bundle's own `spec/` copy, and why a PASS from any verifier here is
not a statement about tampering unless that external comparison was actually done.

---

## What the battery does not establish

- It scores **agreement with a pre-registration**, not "faults caught". Three families are
  expected misses.
- Fourteen families is not a coverage claim. It is fourteen shapes someone thought of; the
  mutant control exists precisely because that set is not self-certifying, and it found
  something on its first outing.
- The negative control is one clean bundle from a second fixture. It scored 0 detections and
  its internal consistency was asserted before scoring, but a single control does not measure
  a false-positive *rate*.
