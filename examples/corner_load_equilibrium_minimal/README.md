# corner_load_equilibrium_minimal — checking a load claim without solving for it

**Domain:** vehicle-dynamics per-corner vertical load estimation
**Re-derivation primitive:** evaluate the three rigid-body equilibrium residuals
of the four *published* contact-patch loads, in exact rational arithmetic.

## The problem this is shaped for

A tire digital twin publishes four contact-patch loads per sample, inferred
from in-vehicle signals with no load sensor anywhere in the loop. There is no
measurement to compare against — the number *is* a model output. The reference
computation that would produce it honestly does not fit on a vehicle ECU, so
what ships is a surrogate trained offline against that reference.

The useful asymmetry is that **solving is expensive and checking is not.**
Rigid-body quasi-static equilibrium over four contact patches gives three
necessary conditions:

```
vertical :  (FL + FR + RL + RR) − m·g                    = 0
pitch    :  (FL + FR)·a − (RL + RR)·b + m·ax·h           = 0
roll     :  (FR + RR − FL − RL)·(t/2) − m·ay·h           = 0
```

Three equations, four unknowns. The system is underdetermined by exactly one
degree of freedom, and closing it needs the suspension roll-stiffness model —
the expensive, IP-bearing, surrogate-approximated part.

**The auditor never closes it.** It substitutes the loads the producer already
published into the three conditions and evaluates the residuals: a handful of
multiply-adds per sample, no iteration, no factorisation, no closure model, and
— the part that matters for a partner who will not hand over their physics —
**no suspension or tire parameters at all.** The check reads mass, wheelbase
geometry, track width and CG height. Nothing else.

A physics solve satisfies these conditions by construction. A learned
per-corner regressor does not: nothing in four independently fitted models
forces them to sum to `m·g`.

## What is in the bundle

| Path | Role |
|---|---|
| `inputs/vehicle_spec.json` | vehicle parameters, exact decimal strings |
| `inputs/trip_samples.json` | per-sample `ax`, `ay` |
| `payload/corner_loads.json` | **the twin's published loads** — the claim |
| `outputs/corner_load_*_residual.json` | the producer's asserted residual: `0` |
| `spec/corner_load_equilibrium.spec.json` | the auditor's spec, copied in |

The producer claims zero equilibrium residual. It does not check this; nothing
in the model can. Publishing a number as a physical load *is* that assertion,
and it is exactly what the auditor re-derives.

## Who holds what

Two parties, one folder. In production they are different machines under
different owners; here they share a directory so the demo is one command, and
the directory is the demo's compromise, not the product's shape.

| File | Held by | Role |
|---|---|---|
| `_producer_solve.py`, `_producer_surrogate.py` | **producer** | the twin: solves for the corner loads |
| `_build_bundle.py` | **producer** | writes the bundle (inputs, the published loads, its asserted residuals, a copy of the spec) |
| `spec_pinned/corner_load_equilibrium.spec.json` | **auditor** | the anchored spec: which rule judges which claim, at which ε |
| `auditor_kit.py` | **auditor** | the recompute primitives; shares no code with the twin |
| `spec_pinned/corner_load_equilibrium.work_set.json` | **auditor** | the complete set of outputs the bundle must deliver, each pinned to its rule |
| `verify.py` | auditor | the shipped CLI with the three files above prefilled; holds no verification logic |
| `auditor_entry.py`, `hard_negatives.py` | auditor | the miner and its one library constructor, over the same three files |

`verify.py` prints the command it runs before the verdict, so what a relying
party would have to hold themselves is on the screen:

```
$ python -m veriker.cli.verify --bundle-dir /tmp/sl_clean \
    --spec-anchor examples/corner_load_equilibrium_minimal/spec_pinned/corner_load_equilibrium.spec.json \
    --primitives examples/corner_load_equilibrium_minimal/auditor_kit.py \
    --work-set examples/corner_load_equilibrium_minimal/spec_pinned/corner_load_equilibrium.work_set.json \
    --require-rederivation
```

The CLI refuses an anchor or kit path that resolves inside the bundle, names
which auditor rule judged which claim, and exits 2 rather than 0 when nothing
was re-derived. A test re-runs the printed line and checks it reaches the same
conclusion as the miner's library path on the same bytes.

## Two bundles, one of which is wrong

```bash
python examples/corner_load_equilibrium_minimal/_build_bundle.py \
    --out-dir /tmp/sl_clean --profile clean
python examples/corner_load_equilibrium_minimal/verify.py --bundle-dir /tmp/sl_clean
# PASS

python examples/corner_load_equilibrium_minimal/_build_bundle.py \
    --out-dir /tmp/sl_drift --profile drift
python examples/corner_load_equilibrium_minimal/verify.py --bundle-dir /tmp/sl_drift
# FAIL — RE_DERIVATION_MISMATCH on all three channels
```

`drift` differs from `clean` in one respect: the trip leaves the surrogate's
training envelope. **Every byte of the drift bundle is internally consistent** —
every SHA matches, the manifest is well-formed, nothing is tampered. It fails
the physics and only the physics.

That is the point of the pilot. Byte-integrity evidence cannot see this class
of defect, and neither could a "re-derivation" that re-ran the producer's own
model, because the producer's model is the thing that is wrong.

Measured on the shipped fixtures (worst |residual| over 120 samples):

| channel | clean | drift | ε (auditor-pinned) |
|---|---|---|---|
| vertical | 0.56 N | 172.82 N | 40 N |
| pitch | 1.23 N·m | 1117.63 N·m | 60 N·m |
| roll | 0.79 N·m | 903.19 N·m | 60 N·m |

## Failure telemetry as hard negatives

```bash
python examples/corner_load_equilibrium_minimal/hard_negatives.py \
    --bundle-dir /tmp/sl_drift --out /tmp/negatives.json
```

Every violating sample is a labelled hard negative — the exact input state that
made the deployed model produce a physically inadmissible answer — obtained
with no ground truth and no instrumented vehicle. On the shipped drift fixture
this returns 45 of 120 samples, all of them outside the trained |ay| range.
(That fixture *plants* its failure at the training envelope, so treat the
concentration as a check on the miner rather than as evidence about where a
real surrogate fails.)

**Mining is gated on a verdict.** A hard negative asserts something about a
*model* — "this input state made the deployed twin publish an inadmissible
answer" — and that is only sound if the loads under examination are the ones
the producer actually published. So the miner verifies first, under the same
three auditor inputs `verify.py` prefills (the miner through
`auditor_entry.build_verifier`, the front door through the shipped CLI; a
parity test holds the two verdicts equal, so a hardening cannot reach one tool
and miss the other), and mines only when every
reason the verifier concluded is an equilibrium-residual mismatch. Admission is
deny-by-default over the check that fired, with the residual channels derived
from the anchored spec's own type keys:

| verdict | miner |
|---|---|
| OK | mines — an empty export is a result |
| REJECT, residual channels only (one channel or all three) | **mines — this is the finding** |
| REJECT on integrity, coverage, anchor, structure | refuses, exit 2 |
| ERROR (could not conclude) | refuses, exit 2 |

The gate is *not* "the bundle must pass": the bundle worth mining is the one
that fails on physics. Without it this tool mined 60 ranked negatives out of a
clean bundle whose payload had been edited after emission and stamped them with
the clean bundle's id — on fleet telemetry arriving over the air, "the model
extrapolated" and "the file was corrupted in transit" are exactly the two
hypotheses the export exists to separate.

Each negative therefore carries the `bundle_id`, the verdict state, the
admitted reason legs, and the spec identity **taken from the anchor that
judged** rather than recomputed by the exporting tool — a stamp a tool can
produce unaided attests to the tool, not to a verdict. That is what makes the
corpus an auditable model-improvement ledger: when the next version ships you
can show it fixed these negatives and did not regress the ones it already
passed, and the showing is re-runnable by someone who is not you.

## What this does and does not constrain

**Honest scope, and the limit is real.** The three residuals constrain the
*aggregate*: the total vertical load, and the two moment balances. They do
**not** constrain the front/rear split of lateral load transfer — that split is
determined by the roll-stiffness distribution, and it is invisible to
rigid-body statics. A twin can get the split wrong and still pass every check
here.

So a PASS means: *the published loads are physically admissible.* It does not
mean they are correct. An empty hard-negative export is not evidence the model
is right on that trip. Constraining the split requires the tier above this one —
a sampled residual against the actual contact model — which needs the
producer's physics and is a different engagement.

## What is pinned, and what is not

Of the bundle's three inputs, exactly one is checked against a verifier-held
reference: `equilibrium_residual_recompute.TRUSTED_RIGID_BODY_SPEC_SHA256` pins
`inputs/vehicle_spec.json` to the sha256 of the exact bytes `_build_bundle.py`
emits from its `_VEHICLE` module constant, and a mismatch fails closed
(`RECOMPUTE_ERROR`, REJECT, exit 1) before any residual is computed. That is
possible only because `_VEHICLE` *is* pre-existing reference data rather than
something the producer computes per bundle. **The scope-limit is real:** this
pin proves the vehicle spec in a given bundle is byte-identical to the one the
module was written against — nothing more. It does not prove that spec is
still current for the vehicle it names. A production integration would
validate a fleet/engineering authority's signature over a *current* snapshot,
out-of-band, exactly as `ap_payment_agent_gate_minimal`'s
`TRUSTED_RECORD_SHA256` precedent already documents for its own domain — not
trust a frozen constant forever.

`payload/corner_loads.json` is the claim under test and is never a pin
candidate — pinning the claim would make the check tautological.

`inputs/trip_samples.json` is **not pinned, and cannot honestly be.** It is
generated fresh per run by `_make_samples(...)`; there is no fixed reference
value for the verifier to hold.

**Nothing meaningful protects it, and an earlier version of this section said
otherwise.** That text claimed "constraint propagation" protects the trip —
that any tampered trip must stay physically consistent with the pinned vehicle
for the published loads to close all three residuals. **That claim is false,
and was measured false on 2026-09-03.** Count the degrees of freedom per
sample: the three residual channels are three equations in six unknowns —
`FL, FR, RL, RR` from the payload and `ax, ay` from the trip. Because `ax` and
`ay` are attacker-chosen, the pitch and roll channels are *always* exactly
solvable for any load quadruple whatsoever, and they add **zero** constraining
power. Only the vertical channel constrains anything, and only the **sum**
`FL+FR+RL+RR = m·g` — never the distribution, which is the entire point of a
corner-load claim.

Demonstrated: leaving `inputs/vehicle_spec.json` byte-identical to the pin, a
forger who edits `trip_samples.json` and `corner_loads.json` **together** can
publish **zero load on both front wheels** (`FL = FR = 0`, `RL = RR = m·g/2`),
then solve `ax ≈ 27.1 m/s²` (a fabricated 2.8 g deceleration) and `ay = 0` to
null pitch and roll exactly. Both `verify.py` and the anchored `veriker/cli/verify.py`
return **PASS, exit 0** on a physically absurd claim. See
`test_coordinated_trip_and_load_forgery_still_passes`, which encodes this as a
standing test rather than prose, so the limit cannot be quietly forgotten.

**What the auditor now refuses, and what it still cannot see.** Two guards were
added on 2026-09-03 after the above was measured:

- The pin covers the **rigid-body subset only** (`RIGID_BODY_SPEC_FIELDS`), not
  the whole `vehicle_spec.json`. `sprung_mass_kg` and the roll-stiffness fields
  sit in that file because the producer's solver needs them; this module reads
  none of them, which is the "a partner who will not share their physics"
  property. A whole-file pin contradicted that and broke
  `test_auditor_never_reads_the_suspension_model` — the collision was the signal.
- **Negative corner loads are refused.** A wheel cannot pull the vehicle toward
  the road. This is the sign convention, not a suspension model, so it costs
  none of the no-producer-IP property.

Neither closed the diagonal mode; the second only bounded it. A **fourth channel**
now closes it — see below. Before that channel, a 450 N cross-weight shift and the
zero-front-wheel claim both still PASSed, since every corner stayed non-negative.
Only the 8000 N variant, which drives two corners negative, is now refused.

## Channel 4 — the front/rear split of lateral load transfer

**Weaker in kind than the three residuals, and the difference is not a detail.**
The equilibrium channels trust nothing: they ask whether a load set is physically
realisable, against laws nobody vouches for. This channel asks whether the loads
*agree with a reference*, and to ask that the auditor must hold a calibration
somebody produced — here swept offline from the reference solve, in deployment
from the producer's own cluster. An equilibrium failure is a fact about physics;
a split excursion is a disagreement with a producer-supplied reference. Both are
useful. Only the first is independent of the producer, and no external claim may
blur them.

**Why it earns its place.** The producer's solver comments that the axle loads and
the *total* lateral transfer are "fixed by rigid-body statics (cheap, exact in
form)" — exactly what channels 1–3 check. The expensive nonlinear roll-angle solve
determines exactly one quantity: `chi`, the front/rear *split*, which lives in the
cross-weight null space. Measured against the auditor's epsilons (40 N vertical,
60 pitch/roll):

| surrogate error | worst corner error | residuals seen | caught before? |
|---|---|---|---|
| `chi_0` 0.58 → 0.50 | 180.3 N | ~1e-12 | no |
| `chi_0` 0.58 → 0.30 | 631.1 N | ~1e-12 | no |
| `phi_gain` 1.35 → 0 | 123.5 N | ~1e-12 | no |
| `mass_kg` 1850 → 1900 (a spec-sheet number) | 170.4 N | **490 N** | yes |

The auditor saw the errors that needed no reference solve and was blind to the ones
that did. `hard_negatives.py` mined **0 of 120** samples on a bundle 450 N wrong per
corner.

**Two limits, measured, neither closed.**

- **Resolution.** Epsilon is 0.05, and `chi_0` 0.58 → 0.55 (deviation 0.03) is *not*
  caught. This catches gross mis-learning, not fine error, and never establishes
  that a model is accurate.
- **Coverage is a first-class part of the verdict, after a measured fail-open.**
  `_reference_split` refuses above the calibrated envelope, and samples that hit
  that were originally *skipped* — contributing nothing to the reported deviation.
  Since the producer owns `trip_samples.json`, that handed it a switch to turn the
  channel off. Measured 2026-09-03: 119 of 120 samples claiming the **entire
  18,142 N vehicle weight on one wheel** (with `ax`/`ay` solved to null pitch and
  roll, implied `|ay|` = 14.09), one honest sample left to satisfy a floor of
  "at least one" → **PASS, exit 0** — and a *cleaner* verdict than a 450 N shift
  two orders of magnitude smaller. Now: any sample outside the envelope **refuses**,
  and coverage must reach a declared floor (half the trip). The envelope runs to
  10.0 m/s², past any real tire, so nothing legitimate falls outside — an envelope
  of 5.0 refused the pilot's own `--profile drift` bundle, which is how the width
  was caught. The coverage is on the PASS path too — the split primitive's own
  detail rides the CLI's `recompute_detail` rows (since 2026-09-06; before that
  `verify.py` recomputed and printed it by hand, and the CLI could not show it);
  a coverage number only the failure branch shows is not a disclosure.
- **The coverage floor is a policy threshold, not a physical constant**, and is
  labelled as one. A genuinely gentle trip can fall below it and be refused — that
  is a could-not-conclude for a trip that cannot carry the check, not an accusation.

**And the epsilon's provenance is backwards, which is worth stating plainly.** 0.05
was chosen to admit the shipped surrogate, whose own split error reaches 0.0369 —
deriving the auditor's tolerance from the producer's error, a quieter form of the
producer declaring its own tolerance. The number should come from a required load
accuracy, which this synthetic pilot does not have and must not invent. Both limits
are pinned as tests so they cannot be mistaken for working features.

**The pilot's own surrogate has this defect.** The reference split migrates 0.5816 →
0.6348 across the trip; the shipped surrogate publishes a flat ~0.627, never having
learned the migration — +0.045 at low `|ay|`, −0.003 at high. It passes, because
0.045 is inside the 0.05 tolerance. That is the honest state: the channel would
catch a grossly mis-learned split, and does not catch this one.

---

The original note on what would close the gap, kept for the record: a fourth
relation, the front/rear split of
lateral load transfer, `(FR−FL) / [(FR−FL)+(RR−RL)]`. Measured on honest data
that ratio sits in **[0.6234, 0.6340]** across 119 samples, while a 450 N diagonal
forgery ranges over **[−6.36, 7.62]** — it discriminates by orders of magnitude.
The linear coefficient it would be anchored on (`front_roll_stiffness_fraction`,
0.58) is a suspension parameter this module deliberately does not read, and the
honest ratio is 0.628 rather than 0.58 because of the producer's nonlinear terms.
So the verifier could bound the ratio but never predict it — the producer must
solve it exactly, the auditor need only bracket it. That is the solve/verify
asymmetry again, and it is the open design question for this pilot, not a patch.

What the vehicle-spec pin genuinely closes is narrower: the
consistent-tamper witness that motivated it (`tests/
test_corner_load_equilibrium_minimal.py::test_consistent_tamper_of_loads_and_mass_is_rejected`,
MEASURED 2026-09-02) inflated every published corner load *and* the vehicle
mass by the same 10% factor — leaving `sum(loads) - m·g` and both moment
balances inside epsilon under the OLD, unpinned check, with the manifest fully
re-cohered so byte integrity held throughout. Only the vehicle-spec pin closes
that path; it does not and cannot independently authenticate the trip.

## Which claims must arrive, and which rule judges each

The auditor names the work up front. `auditor_entry._work_set()` declares the
complete set of `output_id`s this bundle must deliver — one per residual
channel, derived from the anchored spec's own type keys — each pinned to the
type that judges it, as a closed universe whose `universe_sha` the verifier
holds and whose `source_sha` is the anchored spec's sha. The bundle's
`manifest.outputs` must be exactly that multiset: a dropped claim, an extra
one nobody asked for, or the same claim declared twice is a
`WORK_SET_VIOLATION` (FAIL, exit 1), and a claim carrying a different type
than its pin is a `ROLE_POLICY_VIOLATION`. `manifest.json` is not hash-covered,
so each of those used to cost one string edit; measured 2026-09-01, an extra
output under a valid type verified at exit 0 before the work-set existed.

`verify.py` prints the `type_selection:` row above the verdict so a reader of
a bare PASS can see the set that was applied, its provenance, and its counts.
The generic coverage channel (`anchored_spec_types`) still runs beside it as
the fallback every verifier gets; it can say a rule was never reached, never
which claim reached it.

## Why the check is independent

`equilibrium_residual_recompute.py` shares no code with either producer module,
and could not: it does not solve for loads, it evaluates residuals of loads
already published. This is a different computation, not a second copy of one
computation, so a bug in the producer's model cannot propagate into the check.
A test asserts the absence of the import; `_build_bundle.py` loads the producer
modules by path under builder-private names so they never enter the verifier's
namespace.

The build script reports the measured cost of *producing* the claim (240
reference Newton solves plus the ridge fit) against the cost of *checking* it.
On the shipped fixtures that is ≈22× in counted operations. **Do not read that
ratio as the production one.** This toy closes a scalar cubic; a real tire solve
is a nonlinear hyperelastic contact problem at 10⁵–10⁶ DOF, where one residual
assembly stands against many tangent-stiffness factorisations. The pilot
demonstrates the *structure* of the asymmetry — check ≠ solve, check needs no
closure model, check needs no IP. The *magnitude* is a property of the
production problem, not of this fixture.

## Why the deployed model can't be a physics model

The reference computation behind a per-corner load estimate is a nonlinear
implicit solve — Newton iterations, each assembling and factoring a sparse
tangent stiffness over a 10⁵–10⁶ DOF model. An embedded real-time budget is
microseconds to low milliseconds on a processor in the 1–100 GFLOPS class with
single-digit to tens of MB of fast RAM.

Those do not differ by a factor. They differ by **orders of magnitude** — and
that is the load-bearing point, because it rules out the obvious rebuttal. A
10× gap means "use a coarser mesh." A gap of 10²–10⁷ cannot be closed by mesh
refinement at all: doing so would take a 3×10⁵-DOF model down to a few hundred
DOF, at which point there is no contact patch left to resolve and it is not a
tire model any more.

So a model that runs in that budget cannot be a reduced *physics* model in any
meaningful sense. It has to be a **learned function fitted to offline solves** —
which is the standard and correct architecture, not a shortcut. But a learned
function carries none of the solve's guarantees. Nothing in four independently
fitted per-corner regressors forces them to sum to *m·g*.

That is the entire reason a residual check on the published output is worth
running, and why it is worth running by someone other than the producer.

## Files

| File | Side | Purpose |
|---|---|---|
| `_producer_solve.py` | producer | reference Newton solve — the ECU-infeasible half |
| `_producer_surrogate.py` | producer | the deployed ridge-fitted approximation |
| `_build_bundle.py` | producer | trains, infers, emits the bundle |
| `equilibrium_residual_recompute.py` | **auditor** | exact-rational residual certificates; pins the rigid-body fields of `inputs/vehicle_spec.json` to `TRUSTED_RIGID_BODY_SPEC_SHA256` |
| `auditor_kit.py` | **auditor** | primitive registrations |
| `auditor_entry.py` | **auditor** | the one anchored verifier both auditor tools build; mining-admission policy |
| `spec_pinned/corner_load_equilibrium.spec.json` | **auditor** | bindings + ε |
| `hard_negatives.py` | **auditor** | failure telemetry export; `--cost` for residuals + auditor op count |
| `verify.py` | **auditor** | anchored, `require_rederivation=True` |

Tests live in the repo-root `tests/test_corner_load_equilibrium_minimal.py` —
`pyproject` sets `testpaths = ["tests"]`, so a battery under `examples/` would
never be collected.

## Status

Synthetic fixtures throughout. The vehicle parameters, trip, and surrogate are
invented; no proprietary data is used, and nothing here is derived from any
real tire model or any specific vendor's implementation. Production integration replaces the synthetic
twin with the real one and the synthetic trip with recorded CAN data; the
bundle shape and the verification protocol are unchanged.
