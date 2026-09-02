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
anchor `verify.py` uses (both build it in `auditor_entry.build_verifier`, so a
hardening cannot reach one tool and miss the other), and mines only when every
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
| `equilibrium_residual_recompute.py` | **auditor** | exact-rational residual certificates |
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
