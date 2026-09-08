# The primitive book — what the verifier re-derives with

This is the document a spec's `@version` points at.

Every re-derivation primitive the verifier ships declares four things about
itself, in its own class body: an **identity**, a **contract revision**, a
**tier**, and its **scope limits**. This book renders those declarations. It is
generated from the code, never hand-maintained — if the two could disagree, the
version would name the document rather than the method.

> **Regenerate:** `python release/render_primitive_book.py`
> (the renderer is a maintainer tool and is not part of the distribution).

---

## What `@version` means, and what it does not

A spec names a primitive as `name[@version][#sha256hex]`. The three forms are
different claims and the verdict face keeps them distinguishable, because
collapsing them is the labeling-up defect:

| form | what it establishes |
|---|---|
| `name` | **Unversioned.** The verifier runs whatever it has registered under that name. |
| `name@1` | **Contract revision.** The registered code declares that it implements revision 1 of the behaviour described in this book. Legibility, not a byte binding. |
| `name#<sha256>` | **Binding**, within a stated trust model: the digest of the source file holding the code the verifier will actually invoke. |

**`@version` is a CONTRACT revision, not a release counter.** `@1` means
"revision 1 of the declared behaviour named `climate_emission_recompute`" — a
claim *any* conforming implementation may make, not a claim about whose build
is running. This is deliberate. A version only its original author can honestly
declare would weld every versioned spec to one implementation, which is exactly
what optional-rather-than-mandatory digest pinning exists to avoid: an
independent implementation of a published contract is a feature of this design,
not an attack on it.

Two consequences worth stating plainly:

* **Revisions are monotonic integers**, not semantic versions. The comparison is
  exact string equality, so a dotted spelling would promise compatibility
  semantics the verifier does not implement — under exact equality a "patch"
  bump breaks every spec pinning the old string, for no behavioural reason.
* **Revisions are numbered from first publication.** Everything in this book
  starts at `@1`. That is not a claim that no primitive's behaviour has ever
  changed — several were revised while this set was being assembled, before any
  version was published. It means the numbering starts here, and `@1` does not
  point at a definition that was never published.

A primitive that declares no version refuses `@anything` with
`PRIMITIVE_VERSION_UNDECLARED` rather than assuming a match. The verifier cannot
establish a version the code does not state, and assuming one is the fail-open
choice.

**What a pin does NOT cover.** `#sha256` is taken over the whole source file, so
a pin on one primitive also pins any sibling primitive in the same file: an
unrelated edit refuses. That failure direction is closed, never open, and the
per-primitive entries below say where it applies. `@version` has no such
coupling — each class declares its own — which is the reason both forms exist.

---

## What the tiers mean

The tier is published beside the version on every verdict face, and it is the
field that keeps a version honest. `climate_emission_recompute@1` and
`fintech_audit_recompute@1` are the identical shape of claim about revision
identity; only the tier tells you that one is a reference implementation and the
other a general computational shape.

**Tier A — shape or citable standard, guard-covered.** A general computational
shape, or a method traceable to a public standard, carrying a faithfulness test
against an independently written producer implementation.

**Tier B — reference implementation, not a standard.** Correct, tested, and
ours. A voice-activity detector here is *a* VAD, not *the* VAD. Read a Tier B
result as "this arithmetic was re-derived faithfully", never as "this is the
standard method for the domain".

**A tier is CONFERRED, not claimed — and only for the methods in this book.**
Every tier here was earned through the promotion criteria below. A primitive that
arrives from a kit has been through none of that, so on a verdict face it carries
`tier: null` however it labels itself; a kit's own assessment is reported
separately as `self_declared_tier`, and `origin` records that it came from
outside this distribution. Read a tier as our judgment only when the same row
says `origin: "distribution"` — which is exactly when the `tier` field is
populated at all.

**Tier C — certificate checker; never solves.** Not a recompute method at all,
and this is the label most easily misread as a demotion. A certificate checker
is arguably the strongest mechanism in the set: the producer commits its
solution as a *witness* and the verifier checks an acceptance criterion instead
of re-running anything. That makes it solver-independent by construction and
usable against a proprietary solver that cannot be re-run at all. It also
separates reproduction from correctness — a producer whose solver mishandles
prescribed values fails the certificate even though re-running its own code
would reproduce its own answer perfectly.

---

## How something gets into this set

A primitive is promoted when it has: a general computational shape or a citable
public standard behind it; a faithfulness test against a producer implementation
written independently of the verifier's; declared scope limits; and a maintainer.
Promotion also runs a disjointness check that the producer and verifier
implementations do not share code — a shared helper makes agreement a tautology
rather than a finding.

**These are entry criteria for THIS set, and not a blessing regime for
third-party kits.** What "blessed" should mean for a kit somebody else publishes
— which fixtures it must reproduce, who reviews it, who revokes it — is
deliberately undecided, and will be answered with evidence from how the simple
form is used rather than designed in the abstract. Nothing here should be read
as that answer.

---

## What the CLI can reach

**The CLI re-derives an artifact under an auditor's own anchor wherever a kit
ships or the shape is promoted** — not across the fleet as a whole.

That scope limit is the honest form of the claim, and it is worth stating in the
positive as well. The method has to be somewhere the verifier can reach: either
it is one of the promoted primitives in the set below, which the tool carries
itself, or the pilot ships an auditor kit and you point the tool at it
(`veriker --bundle-dir <bundle> --spec-anchor <your-spec.json> --primitives
<kit.py>`). Where neither holds, the binding names a primitive that lives in the
pilot's own directory, the distribution does not hold it, and the run reaches
`UNKNOWN_PRIMITIVE` — a refusal, not a pass. **A bundle the CLI cannot re-derive
says so.** That is the property worth having: the tool declines rather than
reporting a verdict it did not earn.

The set below therefore *is* the coverage story, and the mechanism matters more
than the ratio — a promoted shape serves every regime that binds it, and a kit
closes the gap for one pilot without waiting for a promotion. Both are how the
number moves.

---

## The set

<!-- BEGIN GENERATED — render_primitive_book.py -->

**26 primitives**, 19 Tier A, 4 Tier B, 3 Tier C.

Of the **45 shipped pilots that carry a spec binding, 23 (51%) are reachable by the bare CLI** — 29 of 55 bindings (52%). The rest bind a pilot-local primitive the distribution does not hold, and reach `UNKNOWN_PRIMITIVE` rather than a verdict. This count is rendered from the tree at build time; it is a property of this release, not a target.

| primitive_id | shape | tier | contract revision |
|---|---|---|---|
| `anticheat_adjudication_recompute` | first-match rule -> verdict + default (decision list) | A | `@1` |
| `audio_recompute` | audio | B | `@1` |
| `auto_ubi_recompute` | feature-aggregation -> threshold-classify | A | `@1` |
| `bom_recompute` | bill-of-materials rollup | A | `@1` |
| `build_real_compiler_recompute` | real-compiler build digest | A | `@1` |
| `build_recompute` | build artifact digest | A | `@1` |
| `climate_emission_recompute` | scalar deterministic aggregate | B | `@1` |
| `dp_recompute` | differential privacy (Laplace seeded-noise aggregate) | A | `@1` |
| `event_log_replay_recompute` | event-log replay -> reconstructed-record digest | A | `@1` |
| `fea_vonmises_recompute` | scalar with tolerance (FEA von-Mises) | A | `@1` |
| `fea_witness_certificate` | witness + certificate | C | `@1` |
| `fea_witness_certificate_u_norm_2` | witness + certificate | C | `@1` |
| `fea_witness_certificate_u_norm_inf` | witness + certificate | C | `@1` |
| `fintech_audit_recompute` | all-pairs predicate -> verdict-or-NOT_APPLICABLE (decision list) | A | `@1` |
| `fp_ml_recompute` | floating-point ML | A | `@1` |
| `healthcare_diagnosis_recompute` | fire-and-collect (decision list) | A | `@1` |
| `kg_recompute` | knowledge-graph derivation | A | `@1` |
| `ml_recompute` | ML metric | A | `@1` |
| `prior_auth_recompute` | first-match rule -> verdict + default (decision list) | A | `@1` |
| `raster_recompute` | geospatial zonal count (point-in-polygon) | A | `@1` |
| `scrabble_recompute` | scrabble dictionary adjudication (lexical membership) | B | `@1` |
| `sheet_derivation_replay` | replay of a producer-stated operation over stated operands, with operand-existence check against the workbook | A | `@1` |
| `sheet_query_recompute` | closed-world query over an .xlsx workbook (lookup / list / count / sum / mean / median / argmax / topk) | A | `@1` |
| `spectra_span_recompute` | extractive span | B | `@1` |
| `streaming_recompute` | streaming aggregation | A | `@1` |
| `tabular_recompute` | tabular aggregation (GROUP BY + SUM/COUNT) | A | `@1` |

---

### `anticheat_adjudication_recompute`

Shape: **first-match rule -> verdict + default (decision list)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> verdict_list = for each case in evidence/detection_signals.jsonl (file order), the FIRST rule (evidence/detection_policy.json, sorted by rule_id) ALL of whose AND-conditions (signal >= or <= threshold over the case's signals) hold, emitting {model_recommendation: rule.verdict, matched_rule_id: rule.rule_id}; default {model_recommendation: "clear", matched_rule_id: null} when NO rule fires.

Scope limits:

- First-match-with-default control structure only.
- The condition vocabulary is numeric signal thresholds (>= and <=) only.

### `audio_recompute`

Shape: **audio**. **Tier B** — reference implementation, not a standard. **Contract revision `@1`.**

> boundaries = the set of [start_frame, end_frame] pairs produced by a frame-energy-threshold VAD over the committed int16 little-endian PCM bytes in audio/samples.bin under spec/segmentation.json (frame_size, energy_threshold, min_segment_frames, n_samples): per-frame energy = sum(s*s), consecutive runs at or above the threshold of length >= min_segment_frames emit one [start, end) pair.

Scope limits:

- A VAD, not THE VAD: a frame-energy threshold is a reference implementation, not a citable standard.
- Only the boundary pair is the auditable claim; segment_id and text are neither re-derived nor compared.
- Bound by the `set` comparator, which is multiplicity-blind. Sound here only because VAD runs are disjoint and strictly increasing, so a legitimate boundary set holds no duplicate.

### `auto_ubi_recompute`

Shape: **feature-aggregation -> threshold-classify**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> tier_list = ordered list, by SORTED policyholder_id, of {policyholder_id, tier}, where each tier is the rate-table classification of the telematics features re-aggregated per policyholder from the committed telematics/trips.jsonl (annual-mileage estimate / hard-brake rate / harsh-accel rate / late-night fraction) evaluated against payload/rate_table.json: high-risk surcharge first (ANY of the three rate-per-mile / late-night thresholds exceeded, STRICT >), then low-mileage discount (annual estimate <= low_max), else standard.

Scope limits:

- Feature-aggregation then threshold-classify: an AGGREGATION shape, not a decision list. There is no per-rule replay.
- The categorical TIER only. The float features and adjustment_pct are OUT OF SCOPE and are neither re-derived nor compared.

### `bom_recompute`

Shape: **bill-of-materials rollup**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> resolved_tree = BFS walk of the committed lockfile DAG from root producing the full per-package tree (id, hash, depth, deps per node in resolution order) plus the deterministic resolution_order list, returned as the canonical dict {root, nodes, resolution_order}.

Scope limits:

- Re-derives the resolution over the COMMITTED lockfile; it does not fetch, and says nothing about whether the pinned hashes match a real artifact.

### `build_real_compiler_recompute`

Shape: **real-compiler build digest**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> pyc_sha = sha256(py_compile(sources/mod_a.py, CHECKED_HASH, dfile="mod_a.py", SOURCE_DATE_EPOCH=0)).hexdigest().

Scope limits:

- One representative module (mod_a.pyc), not a whole build graph.
- Reproducibility is CPython-bytecode reproducibility: the same source under a different CPython version produces a different digest, which the certificate reads as a mismatch.

### `build_recompute`

Shape: **build artifact digest**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> artifact_sha = sha256(gzip(mtime=0, level=6, concat(sources, sep="\n"))).hex().

Scope limits:

- A deterministic recipe over committed sources, not a real toolchain. build_real_compiler_recompute is the primitive that invokes an actual compiler.

### `climate_emission_recompute`

Shape: **scalar deterministic aggregate**. **Tier B** — reference implementation, not a standard. **Contract revision `@1`.**

> total_scope3_kg_co2e = round(sum(round(activity_amount * emission_factor_kg_co2e_per_unit, 6) for each supplier in inputs/supplier_chain.json, in list order), 6).

Scope limits:

- A reference implementation of a Scope-3 roll-up, not a citable emissions standard.
- Fixed-point summation IN LIST ORDER: a different summation order is a different value.
- Re-derives the arithmetic over the committed supplier chain. It does not vouch for the activity amounts or the emission factors themselves.

### `dp_recompute`

Shape: **differential privacy (Laplace seeded-noise aggregate)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> noised_count = float(true_count) + laplace_noise(scale = sensitivity/epsilon, seed), where true_count is re-counted from data/dataset.jsonl under the committed predicate and the Laplace variate is re-drawn deterministically from random.Random(seed) by inverse-CDF: noise = -scale * sign(u-0.5) * log(1 - 2*|u-0.5|), u = Random(seed).random().

Scope limits:

- Re-derives that the RELEASED value follows from the committed seed, epsilon and sensitivity. It does NOT audit the privacy claim: whether that epsilon is an appropriate budget is outside the primitive.
- Bound by scalar_epsilon 1e-6 because math.log is delegated to the platform libm and is not guaranteed bit-identical across platforms.

### `event_log_replay_recompute`

Shape: **event-log replay -> reconstructed-record digest**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> Replay the bundle's single append-only JSONL event log (inputs/<log>.jsonl) from its genesis CREATE event, applying each subsequent AMEND patch in file order to reconstruct the authoritative current record; the re-derived value is the SHA-256 digest of that canonical reconstructed record.

Scope limits:

- State fold, not a hash-chain fold: a log whose claim is chain integrity rather than reconstructed state is a different shape.
- Accepted ops are CREATE, AMEND and LOG. A retention regime that must REFUSE a LOG op needs a stricter op-set than this primitive accepts.

### `fea_vonmises_recompute`

Shape: **scalar with tolerance (FEA von-Mises)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> sigma_vm_max = the maximum von-Mises stress from a pure-Python 2D plane-stress linear-elastic CST solve over inputs/{mesh,material,bcs}.json, with the SOLVER parameters (tol, max_iter) read from spec/solver_config.json.

Scope limits:

- 2D plane-stress linear-elastic CST elements only.
- It RE-RUNS the producer's solve, which is unaffordable at a chokepoint and impossible against a proprietary solver. The fea_witness_certificate family is the solver-independent form of the same claim.
- The acceptance epsilon is read from the auditor-anchored binding spec, never from the producer's solver_config.

### `fea_witness_certificate`

Shape: **witness + certificate**. **Tier C** — certificate checker — never solves. **Contract revision `@1`.**

> Given the producer's committed displacement-field witness (payload/displacement_field.json), check the CERTIFICATE — Dirichlet values hold exactly and the equilibrium residual on the free DOFs of the ORIGINAL assembled K is inside the auditor-anchored tolerance — and return the witness-implied sigma_vm_max, compared by the bound rational_sqrt_band comparator. Assembly, residual and stress recovery are exact rational arithmetic throughout.

Scope limits:

- It NEVER runs a solver. Solver-independent by construction: a Gaussian-elimination solve and a CG solve that both satisfy equilibrium pass the SAME certificate.
- Declared semantics are honoured, not assumed: material must declare model=linear_elastic_isotropic and stress_state=plane_stress, and mesh must declare element_type=CST and dim=2, or the certificate refuses.
- Without the comparator param input_anchor the certificate degrades to a witness-implied predicate over a PRODUCER-CHOSEN problem, and says so in its detail.
- This source file holds three registered primitives, so a #sha256 pin on any one of them also pins its two siblings.

### `fea_witness_certificate_u_norm_2`

Shape: **witness + certificate**. **Tier C** — certificate checker — never solves. **Contract revision `@1`.**

> The same certificate gates as fea_witness_certificate, returning ||u||_2 over ALL DOFs as sqrt_of_rational(sum of u_i^2), bound by rational_sqrt_band, under delta_u conditioning.

Scope limits:

- It NEVER runs a solver. Solver-independent by construction: a Gaussian-elimination solve and a CG solve that both satisfy equilibrium pass the SAME certificate.
- Declared semantics are honoured, not assumed: material must declare model=linear_elastic_isotropic and stress_state=plane_stress, and mesh must declare element_type=CST and dim=2, or the certificate refuses.
- Without the comparator param input_anchor the certificate degrades to a witness-implied predicate over a PRODUCER-CHOSEN problem, and says so in its detail.
- This source file holds three registered primitives, so a #sha256 pin on any one of them also pins its two siblings.

### `fea_witness_certificate_u_norm_inf`

Shape: **witness + certificate**. **Tier C** — certificate checker — never solves. **Contract revision `@1`.**

> The same certificate gates as fea_witness_certificate, returning max|u_i| over ALL DOFs as a plain rational, bound by rational_band, under delta_u conditioning.

Scope limits:

- It NEVER runs a solver. Solver-independent by construction: a Gaussian-elimination solve and a CG solve that both satisfy equilibrium pass the SAME certificate.
- Declared semantics are honoured, not assumed: material must declare model=linear_elastic_isotropic and stress_state=plane_stress, and mesh must declare element_type=CST and dim=2, or the certificate refuses.
- Without the comparator param input_anchor the certificate degrades to a witness-implied predicate over a PRODUCER-CHOSEN problem, and says so in its detail.
- This source file holds three registered primitives, so a #sha256 pin on any one of them also pins its two siblings.

### `fintech_audit_recompute`

Shape: **all-pairs predicate -> verdict-or-NOT_APPLICABLE (decision list)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> policy_verdicts = [{txn_id, rule_id, matched_conditions, verdict} for each (transaction, policy-rule) pair, in transactions-then-policies file-sorted order, where each rule's conditions are AND-ed over the transaction (gt/lt/eq/ne/in/not_in), matched_conditions lists the condition fields that held, and verdict is the rule's verdict_if_match when ALL conditions hold else "NOT_APPLICABLE".

Scope limits:

- All-pairs control structure only: one record per (transaction x rule) pair. The first-match and fire-and-collect structures are separate primitives.
- Condition operators are exactly gt/lt/eq/ne/in/not_in; a policy using any other operator is not re-derivable here.

### `fp_ml_recompute`

Shape: **floating-point ML**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> rep_logit = f32(sum(W[0][j] * x0[j] for j in range(n_features)) + b[0]), the single representative scalar predictions[0].logits[0], accumulated in Python double and snapped to single precision at the serialization boundary via f32(v) = struct.unpack('f', struct.pack('f', v))[0].

Scope limits:

- ONE representative scalar (class 0, input 0), not the full logit matrix.
- Bound by scalar_epsilon, not exact: two float32-snapped doubles can differ at ULP scale across libm and accumulation order.

### `healthcare_diagnosis_recompute`

Shape: **fire-and-collect (decision list)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> icd10_codes = for each rule in inputs/rules.json (sorted by rule_id), the rule FIRES iff every condition's symptom is present in inputs/symptoms.json AND its severity >= the condition's min_severity; each fired rule appends its icd10_code to an ordered list (rules that do not fire emit nothing).

Scope limits:

- Fire-and-collect control structure: the ordered icd10_code list is the whole claim.
- The per-rule confidence float is OUT OF SCOPE and is neither re- derived nor compared.

### `kg_recompute`

Shape: **knowledge-graph derivation**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> answer_nodes = the BFS reachability closure of (query.start, query.predicate, query.max_depth) over the bundled triple set kg/triples.jsonl, excluding query.start itself, each node visited at most once.

Scope limits:

- Single start node, single predicate, bounded depth. Multi-predicate paths, joins and negation are not this shape.
- Bound by the `set` comparator: order-independent and multiplicity- blind.

### `ml_recompute`

Shape: **ML metric**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> predicted_classes = the integer argmax (lowest-index tie-break) of the integer logits logits[k] = sum(W[k][j]*x[j]) + b[k], re-executed per input sample over the committed weights (weights/model.json, linear- classifier-v1) and committed inputs (inputs/features.json).

Scope limits:

- Integer arithmetic linear classifier only — exact, no tolerance. fp_ml_recompute is the floating-point shape.

### `prior_auth_recompute`

Shape: **first-match rule -> verdict + default (decision list)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> decisions = for each prior-auth request in clinical/findings.jsonl (file order), the FIRST plan rule (clinical/plan_rules.json, sorted by rule_id) whose procedure_category matches AND every required diagnosis is present AND every required prior_treatment is present AND the optional max_lab_value (>= / <=) check passes, emitting {request_id, model_recommendation: rule.verdict, matched_rule_id: rule.rule_id}; default {model_recommendation: "deny", matched_rule_id: null} when NO rule matches.

Scope limits:

- First-match-with-default control structure only.
- The condition vocabulary is this pilot's: procedure-category equality, required-list membership, and one optional numeric lab bound. It is NOT a general rule-engine.

### `raster_recompute`

Shape: **geospatial zonal count (point-in-polygon)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> in_polygon_cell_count = the number of grid cells whose center (c+0.5, r+0.5) is inside the polygon, decided by a standard horizontal ray- casting crossing count, driven by the committed polygon vertices and grid dimensions in spec/zonal_query.json.

Scope limits:

- Cell-center point-in-polygon: a cell is in or out, never partial. It is not an area-weighted zonal statistic.
- A single simple polygon; no holes, no multi-part geometry, no projection handling.

### `scrabble_recompute`

Shape: **scrabble dictionary adjudication (lexical membership)**. **Tier B** — reference implementation, not a standard. **Contract revision `@1`.**

> ruling = resolve(jurisdiction, timestamp) to the effective edition via the committed timeline, then test word membership in that edition's wordlist, emitting {edition_cited, word, is_legal}.

Scope limits:

- Dictionary MEMBERSHIP only: no tile scoring, no multipliers, no bingo bonuses.
- The wordlist is whatever the bundle commits; the primitive does not vouch for the edition's contents.

### `sheet_derivation_replay`

Shape: **replay of a producer-stated operation over stated operands, with operand-existence check against the workbook**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> answer = replay(inputs/derivation.json [sheet-derivation-v1], parse(data/workbook.xlsx)) — the operation (lookup / list / count / sum / mean / median / argmax / topk) is applied to the operand values the producer states it used (argmax/topk take [label, value] pairs), with the same rounding, string-normalization and list conventions as sheet_query_recompute (a numeric-looking operand, string or number, is a number for lookup and for every arithmetic op); sheet_query_recompute; every operand must occur somewhere in the workbook (numbers by exact Decimal equality against every numeric cell, strings by normalized equality against every text cell), else the value is {kind: operand_not_in_sheet, missing, replayed} and no claim can match it.

Scope limits:

- This is consistency, not correctness: a wrong selection computed correctly (the other fund's rows summed right) replays to the producer's own number and passes. Only sheet_query_recompute under an auditor-pinned query catches that.
- Operand existence is workbook-wide, not column-scoped; a value that happens to occur elsewhere in the workbook satisfies the check.
- A lookup derivation has one operand and no arithmetic; the only thing this primitive can refuse for a lookup is a value absent from the workbook.
- Operand existence is EXACT Decimal equality against the cell text. A workbook whose XML carries binary-float noise (74.45999999999999 for 74.46, which openpyxl writes by default) makes every honest 2-dp operand 'absent'; canonicalise such a workbook before binding it, or expect operand_not_in_sheet on honest working.
- A non-finite operand (NaN, sNaN, Infinity, as number or string) is 'absent'.
- Refusals carry a per-call nonce so no claimed value can equal one.
- Both primitives in this file share one source file, so a #sha256 pin on either pins the other.

### `sheet_query_recompute`

Shape: **closed-world query over an .xlsx workbook (lookup / list / count / sum / mean / median / argmax / topk)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> answer = evaluate(inputs/query.json [sheet-query-v1], parse(data/workbook.xlsx)) — the workbook is parsed by the verifier from bytes (stdlib zip+xml; shared, inline and formula-cached strings; numeric cells as Decimal); the query's layout locates the header row by header_match, maps logical columns to header texts (casefold, whitespace-collapsed), assigns each data row a group from a Fund column, a divider row matching a regex, or the sheet name, and skips rows whose first cell matches exclude_first_cell; filters are eq/ne (numeric if both sides parse, else normalized text) and gt/gte/lt/lte (numeric); lookup requires exactly one row; sum/mean/median are exact Decimal arithmetic rounded HALF_UP to `round` places (default 2) and emitted as float; count is int; string results are casefolded and whitespace-collapsed; list/topk results are sorted de-duplicated lists; argmax and topk refuse ties; any refusal is emitted as {kind: refused, reason}.

Scope limits:

- The query is auditor-authored and must be pinned through the spec's pinned_inputs (inputs/query.json); an unpinned query is producer-writable and the recompute then answers whatever question the producer chose.
- The layout (header texts, group encoding, exclusion regex) is the auditor's reading of the document, supplied as data; a layout that misreads the sheet yields a determinate refusal or a wrong-but-deterministic answer, never a pass on a producer's say-so.
- Cells are read from cached values; formulas are not evaluated. Dates, styles and merged-cell geometry are ignored; a merged header contributes only its anchor cell.
- The workbook is producer-visible data; unless the spec ALSO pins data/workbook.xlsx through pinned_inputs, a producer can ship the workbook under which its answer is right (measured 2026-09-02, exit 0). The pilot's make_spec pins both.
- Divider and exclusion regexes match the cell's whitespace-collapsed text, case-insensitively; a regex that expects raw whitespace or case never matches.
- Grid bounds: rows 1..1,048,576, columns A..16,384, and at most 4,000,000 cells materialised per sheet; a non-finite numeric cell refuses the workbook.
- Refusals carry a per-call nonce so no claimed value can equal one.
- Both primitives in this file share one source file, so a #sha256 pin on either pins the other.

### `spectra_span_recompute`

Shape: **extractive span**. **Tier B** — reference implementation, not a standard. **Contract revision `@1`.**

> source fragment = sentence-segment corpus/<source_cid>.txt on [.!?]+ not adjacent to a digit, strip and drop empty segments, and return the segment at inputs/span_claim.json.fragment_id.

Scope limits:

- Returns the SOURCE fragment. The producer's claimed span is compared against it by the bound text_normalized comparator, not here.
- Sentence segmentation is the terminator regex alone: no abbreviation, quotation or list handling.
- source_cid is bundle-controlled and the read is contained inside corpus/; a path that escapes fails closed.

### `streaming_recompute`

Shape: **streaming aggregation**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> per-window aggregate list = replay of the committed event stream (events/stream.jsonl) through event-time tumbling-window aggregation per the committed windowing spec (spec/segmentation.json: window_size_ms + aggregator + late_event_policy), bucketing each event into window index timestamp_ms // window_size_ms, applying the aggregator per bucket, and emitting windows in ascending window_start_ms.

Scope limits:

- Event-time TUMBLING windows only: no sliding or session windows, and no processing-time semantics.
- Late events are handled by the committed late_event_policy; the primitive does not decide that policy.

### `tabular_recompute`

Shape: **tabular aggregation (GROUP BY + SUM/COUNT)**. **Tier A** — shape or citable standard, guard-covered. **Contract revision `@1`.**

> result_sha = sha256(serialize(aggregate(data/sales.csv, spec/query.json))).hexdigest() — a GROUP BY with SUM/COUNT aggregation over the committed CSV under the committed query.

Scope limits:

- The claim is the digest of the serialized result, so a mismatch localises to the whole result, never to a row.
- Aggregators are SUM and COUNT over a GROUP BY; no joins, windows or having-clauses.

<!-- END GENERATED -->
