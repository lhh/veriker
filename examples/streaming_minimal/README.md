# streaming_minimal — V-Kernel Event-Time Streaming Pilot

Domain-specific demonstration of the S0 audit-bundle integrator on event-time
tumbling-window aggregation. This pilot forces the **substrate stateful question**:
does the V-Kernel re-derivation primitive generalize from byte-equal output
comparison to state-machine state matching a committed checkpoint?

## Substrate Decision Forced

**v0.1 state model:** per-window-aggregate state — a list of `{window_start_ms,
window_end_ms, aggregate, event_count}` records derived by replaying a committed
timestamped event stream through tumbling-window aggregation.

**The key distinction from prior pilots:** the re-derivation primitive here is NOT
"re-run a function and compare output bytes." It is "replay the event stream,
advance per-window state machine, assert the final per-window state matches the
committed checkpoint." This is the Flink/Kafka Streams pattern — auditors verify
*state* not *bytes*.

### Future state shapes (deferred)

At v0.1, the state model is restricted to stateless-per-window aggregates.
The following are deferred to future schema versions:

- **Per-key state** (e.g. per-user session windows, keyed aggregations) — requires
  a state backend description in the spec and a keyed-replay primitive.
- **Exactly-once side-effects** — wiring to the effect calculus (EFFECT_CALCULUS.md
  §C15) to audit that stateful side-effects (e.g. Kafka commits, DB writes) match
  declared effects.
- **Watermark progression** — auditing that the watermark advances correctly and
  late events are handled per the declared late-event policy. At v0.1, only `"drop"`
  is implemented; `"include"` is reserved and rejects with
  `STREAMING_LATE_EVENT_POLICY_VIOLATED`.

### Reference semantics

- **Apache Flink event-time semantics:** events are bucketed by their embedded
  `timestamp_ms` field (event time), not by wall-clock processing time. This
  matches Flink's `TumblingEventTimeWindows` behavior.
- **Chandy-Lamport snapshot pattern:** the bundled `payload/checkpoint.json` is
  a Chandy-Lamport-style checkpoint of the per-window state machine — a consistent
  cut of distributed state that the verifier can replay from the committed input.

## Bundle Layout

```
streaming_minimal/
  events/
    stream.jsonl            1000 events: {"event_id", "timestamp_ms", "value"}
  spec/
    segmentation.json       windowing parameters (schema: streaming-tumbling-v1)
  payload/
    checkpoint.json         per-window aggregate state (the auditable claim)
  manifest.json
```

The `spec/` tree is owned by `manifest.spec_files` and verified by `SpecShaPinCheck`.
The `events/` and `payload/` trees are owned by `manifest.files` and verified by
`FileIntegrityManySmall`. The two plugins cover disjoint trees by construction.

## Event Generator

1000 deterministic events at 100 ms spacing:

```
event_id    = i
timestamp_ms = i * 100         (events 0..599 in window 0; 600..999 in window 1)
value        = (i * 7) % 200 - 100   (integer in [-100, 99])
```

With `window_size_ms=60000` and 1000 events:
- **Window 0:** `[0ms, 60000ms)` — 600 events, `sum=-300`
- **Window 1:** `[60000ms, 120000ms)` — 400 events, `sum=-200`

## Quick Start

From the `v-kernel-audit-bundle` root:

```bash
# Build bundle
python examples/streaming_minimal/_build_bundle.py --out-dir /tmp/streaming_bundle

# Verify bundle
python examples/streaming_minimal/verify.py --bundle-dir /tmp/streaming_bundle
# → PASS

# Run tests
python -m pytest tests/test_streaming_minimal.py -v
```

## Tamper Flow Demo

### Content tamper (re-derivation catch)

Push event 599's timestamp from 59900 ms to 60000 ms. This moves event 599
from window 0 to window 1, changing both window aggregates and event counts.
Re-align the `events/stream.jsonl` SHA in the manifest so `FileIntegrityManySmall`
passes — the failure is caught exclusively by `StreamingReDerivationCheck`.

Expected result: `ok=False`, reason `RE_DERIVATION_MISMATCH`.

### Spec tamper (SpecShaPinCheck catch)

Append trailing whitespace to `spec/segmentation.json`. Do NOT realign
`manifest.spec_files`. The parsed JSON is semantically identical so
re-derivation still passes — the failure is caught exclusively by `SpecShaPinCheck`.

Expected result: `ok=False`, reason `SPEC_SHA_MISMATCH` or `missing_spec_blob`.

## Claim-field coverage (claimset)

`payload/checkpoint.json` is the claim file, declared structured:
`manifest.claimset.claim_files = {"checkpoint": "payload/checkpoint.json"}`.
It is a bare JSON array at the root (no wrapping object key), so all four of
its observed fields render as `checkpoint:[].<field>` — the payload key, then
the array marker, with no object key in between:

| fields | disposition |
|---|---|
| `checkpoint:[].window_start_ms`, `checkpoint:[].window_end_ms`, `checkpoint:[].aggregate`, `checkpoint:[].event_count` | **covered** — `streaming_re_derivation.py` replays `events/stream.jsonl` through the committed windowing spec and compares every field of every window row, positionally (`zip`, not id-indexed) against the bundled checkpoint, before returning success |

Zero residuals: `events/stream.jsonl` and `spec/segmentation.json` are inputs
(the event stream the re-derivation replays; the windowing rule it replays
under), not claims, so the only claim file is `checkpoint.json`, and every
field it carries is bound. Each checkpoint field is compared as canonical
JSON, so `false` is not `0` and `-300.0` is not `-300`.

`StreamingReDerivationCheck` reports coverage ONLY when the pack exited 0,
and only for the fields its `[COMPARED]` stdout line names (emitted from the
success return, keyed by bundle-relative file): the pack adds each field to a set as its comparison passes and prints the set once from its success return; the plugin requires exactly ONE such line (none, several or malformed → nothing reported) and treats an exit 0 without the line as `incomplete=True`. The per-field tamper battery in
`tests/test_streaming_minimal.py` requires every covered field to flip under
the pack's own tag (`[STREAMING_REDER_FAIL]`), never via a file-sha mismatch.
The `spec_pinned_check.py` overlay lane does not wire
`StreamingReDerivationCheck` and drops the declaration, so that lane's
verdict carries the honest "claimset: not declared" disclosure; same for the
`tests/test_recipe_streaming_promoted.py` variant (the promoted-primitive
demonstration over `outputs/`, not this payload).

**Stated limit.** The comparator binds `payload/checkpoint.json`'s values to
`events/stream.jsonl` replayed under `spec/segmentation.json`, but nothing in
this bundle binds EITHER input to a source outside the bundle — there is no
second, independently registered copy of the event stream (unlike, e.g.,
credit_scoring_minimal's bureau snapshot), and the spec is pinned only by the
producer's own `manifest.spec_files` sha. A forged `events/stream.jsonl`, or
a forged `spec/segmentation.json` (a different `window_size_ms` or
`aggregator`), with an honestly recomputed `payload/checkpoint.json` (all
re-pinned) verifies OK with a receipt identical to the honest one; the
claimset gate accounts for payload *fields*, not the *provenance* of the
inputs those fields were computed from. Two spec fields the replay never
reads are likewise unchecked: `spec.event_count` (the stream's line count is
not compared to it — a stream of 999 events under a spec that says 1000
verifies OK) and `late_event_policy` (only `"drop"` is accepted by name; no
drop logic exists, so an event before the first window creates a window).
Also outside the gate's sight: a second `payload/` file the declaration does
not name rides the honest receipt (the universe anchor digests the DECLARED
maps, not the payload directory); the declaration's completeness is the
producer's, as the gate's own docstring states.

## Plugin Registration

Three plugins registered in `verify.py`:

| Plugin | Contract | Scope |
|---|---|---|
| `SpecShaPinCheck` | §C1 | `spec/` tree |
| `FileIntegrityManySmall` | §C9 | `events/` + `payload/` (skips `spec/`) |
| `StreamingReDerivationCheck` | §C6 | stateful re-derivation via subprocess |

## Files

| File | Purpose |
|---|---|
| `_build_bundle.py` | Generate 1000 deterministic events, compute checkpoint, write manifest |
| `verify.py` | Register plugins, wrap BundleVerifier, print PASS/FAIL |
| `streaming_re_derivation.py` | Stdlib-only re-derivation pack (subprocess target) |
| `StreamingReDerivationCheck.py` | TypedCheck plugin wrapping the subprocess |
| `README.md` | This file |
| `../../tests/test_streaming_minimal.py` | Round-trip + content-tamper + spec-tamper tests |
