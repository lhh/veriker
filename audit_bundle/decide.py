"""audit_bundle/decide.py — the generic verifier decides THROUGH the join (One F depth 1).

Until this module, `BundleVerifier._verify_in_dir` met its step results itself:
`Verdict.from_failures` over the REJECT legs, `compose` over the clean-ERROR legs,
crash-ERROR > REJECT > clean-ERROR > OK. `multi_root` shipped in the same package and
the verifier never called it (One F register F4: "v-kernel's bundle verifier is a
degenerate join"; F5: "veriker's generic verifier decides through the join").

Depth 1 ("overall only") keeps every step, every plugin and every reason code, and
replaces the DECIDER:

  * the bundle is the ONE record on a `multi_root` roster, attached by the producer
    (`Expected.reached=False`), under a two-root table {auditor, producer} with the
    producer as the proposer root;
  * the walk's ADMISSION steps are the record's provenance and content checks: a REJECT
    from a provenance step (DSSE gate, file sha, spec sha) arrives through
    `signature_valid` as `Refused(why)`, a REJECT from any other admission step through
    `validate_content`; either way the record is UNUSABLE — tamper evidence is not
    absence;
  * every other step is a PROPOSITION on a committed denominator (`PROPOSITIONS`); a
    REJECT leg is a CONTRADICTS finding, a clean-ERROR leg is SILENT, and a step that
    ran to completion with nothing against the record is CONFIRMS. A step that did NOT
    run (an early exit of the walk, an admission that did not finish) gets NO finding:
    absence never reads as agreement (`propositions.py`);
  * `propositions.overall` decides; the returned `Verdict` is BUILT from that decision
    (RELEASE→OK, REFUSE→REJECT, HOLD→clean-ERROR, NO_VERDICT→crash-ERROR); its
    `reasons`/`legs` are the steps' own, in the order `compose` gives them.

What the engine says that the meet never did: every CONFIRMS chain runs through the
producer's envelope, so its effective root is the proposer's (S1 min). This is BY
CONSTRUCTION — a verifier whose only record is the producer's bundle cannot establish
anything — and the face says so on every RELEASE (`residual_proposer_root_only`). Pure
re-derivation is consistency against the producer's own record (register V8/V12). No
`hold_if` is set: release on proposer-rooted confirmation is today's behaviour written
down (the D1 `built` declaration for v-kernel).

The old meet still runs, as a CROSS-CHECK only: if the join's projected state differs
from `compose`'s, that is a defect in THIS module's attribution, and it raises
`VerifierError(DECISION_DIVERGENCE)` — a crash-ERROR through `fail_closed`, never a
softer verdict. The cross-check is transitional and goes when the meet goes (depth 2).
Until then the leg SHAPES the join relies on (a REJECT leg carries reasons, a clean-ERROR
leg is `is_incomplete`, a crash leg `is_crash`) are checked here too, so a malformed leg
can never be invisible to the attribution and visible only to the meet.

Not here: splitting plugins into extractors + terms (depth 2), authorities or
stipulations as inputs (depth 3). Stdlib only; imports nothing from `verifier`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ._freeze import deep_freeze
from .multi_root import (
    CONFIRMS,
    CONTRADICTS,
    HOLD,
    NO_VERDICT,
    REFUSE,
    RELEASE,
    SILENT,
    Expected,
    Refused,
    RootTable,
    Roster,
    admit,
    finding,
    overall,
    proposition_states,
    state_vector,
)
from .verdict import (
    ErrorKind,
    Verdict,
    VerdictReason,
    VerdictState,
    VerifierError,
    compose,
)

__all__ = [
    "AUDITOR",
    "PRODUCER",
    "RECORD_ID",
    "TABLE",
    "ADMISSION_CHECKS",
    "PROVENANCE_CHECKS",
    "CRASH_CHECKS",
    "PROPOSITIONS",
    "ATTRIBUTION",
    "DECISION_DIVERGENCE",
    "UNATTRIBUTED_CHECK_NAME",
    "MALFORMED_LEG",
    "proposition_of",
    "decide_through_join",
    "decide_single",
]

# ---------------------------------------------------------------------------
# the declared table and the one record
# ---------------------------------------------------------------------------

AUDITOR, PRODUCER = "auditor", "producer"
RECORD_ID = "bundle"
#: Two roots. The producer is the proposer; the auditor holds the spec, the kit and the
#: work-set. Depth 3 adds authorities here from an engagement; nothing else changes.
TABLE = RootTable.declare(
    {AUDITOR: AUDITOR, PRODUCER: PRODUCER},
    proposer_root=PRODUCER,
    roots=(AUDITOR, PRODUCER),
)

#: Verifier defects, all crash-class (`VerifierError` → `fail_closed` → crash-ERROR):
#: the join's projected state and the meet's disagree;
DECISION_DIVERGENCE = "VERIFIER_DECISION_DIVERGENCE"
#: a reason carries a check name the attribution table does not know (the census ratchet
#: in tests/test_decide_through_join.py keeps this from happening in-tree);
UNATTRIBUTED_CHECK_NAME = "VERIFIER_UNATTRIBUTED_CHECK_NAME"
#: a leg handed to the decider has a shape the attribution cannot read.
MALFORMED_LEG = "VERIFIER_MALFORMED_LEG"

# ---------------------------------------------------------------------------
# the committed denominator
# ---------------------------------------------------------------------------

#: Admission steps whose REJECT says the record's provenance failed: the bytes are not
#: what the envelope and the pins say they are. Arrive through `signature_valid`.
PROVENANCE_CHECKS: frozenset = frozenset(
    {"dsse_gate", "file_integrity", "spec_sha_pinning"}
)

#: Every admission step: a REJECT here makes the record UNUSABLE (provenance failed, or
#: content the checks cannot read as the artifact it claims — a malformed manifest, a
#: broken cross-reference, a verifier-identity block out of shape, an unowned file).
#: `admission` / `input_admission` are `audit_bundle.admission`'s default names.
ADMISSION_CHECKS: frozenset = PROVENANCE_CHECKS | frozenset(
    {
        "sealed_snapshot",
        "manifest_admission",
        "admission",
        "input_admission",
        "manifest_load",
        "conservation",
        "append_only_floor",
        "cross_refs",
        "c18_structural",
        "deep_manifest_validation",
    }
)

#: The crash boundary's own name (`fail_closed("BundleVerifier.verify")`). A crash leg is
#: never attributed — it reaches the join as `raised` — but the name is listed so the
#: census ratchet accounts for it.
CRASH_CHECKS: frozenset = frozenset({"BundleVerifier.verify"})

#: The propositions, in the walk's order. Committed here, before any leg is read.
PROPOSITIONS: tuple = (
    "typed_check_plugins",
    "spec_pinned_dispatch",
    "extension_receipts",
    "cross_host_authenticators",
    "causal_chain",
    "layer_a_event_obligations",
    "fragment_anchors",
    "stamp_claims",
    "claimset_coverage",
    "assurance_profile",
    "re_derivation_pack",
    "re_derivation_surface",
    "anchored_spec_types",
)

#: check_name (exact, or the part before the first ':') -> proposition. Plugin and
#: primitive results are re-labelled by the walk (`typed_check_plugins:<id>`,
#: `spec_pinned_dispatch:<id>`), so only the walk's own names appear here.
ATTRIBUTION: Mapping = {
    "typed_check_plugins": "typed_check_plugins",
    "spec_pinned_dispatch": "spec_pinned_dispatch",
    "extension_receipt": "extension_receipts",
    "cross_host_authenticators": "cross_host_authenticators",
    "causal_chain": "causal_chain",
    "layer_a_event_obligations": "layer_a_event_obligations",
    "fragment_anchors": "fragment_anchors",
    "dispatch_records": "stamp_claims",
    "aggregate_stamp": "stamp_claims",
    "claimset_coverage": "claimset_coverage",
    "assurance_profile": "assurance_profile",
    "re_derivation_pack": "re_derivation_pack",
    "re_derivation_surface": "re_derivation_surface",
    "anchored_spec_types": "anchored_spec_types",
}

for _p in ATTRIBUTION.values():
    if _p not in PROPOSITIONS:
        raise ImportError(
            f"attribution names a proposition {_p!r} that is not on the denominator"
        )
if ADMISSION_CHECKS & set(ATTRIBUTION) or CRASH_CHECKS & (
    ADMISSION_CHECKS | set(ATTRIBUTION)
):
    raise ImportError("a check name is in more than one class")


def proposition_of(check_name: object) -> str | None:
    """The proposition a check name speaks for; None for an admission check.

    Exact name first, then the prefix before the first ':' (the walk suffixes an
    instance id onto plugin and dispatch legs). A name in neither class is a verifier
    defect and raises (`UNATTRIBUTED_CHECK_NAME`): an item nobody named is an item nobody
    constrained, and it must not become a silent bucket."""
    name = check_name if isinstance(check_name, str) else ""
    if name in ADMISSION_CHECKS:
        return None
    if name in ATTRIBUTION:
        return ATTRIBUTION[name]
    head = name.split(":", 1)[0]
    if head in ADMISSION_CHECKS:
        return None
    if head in ATTRIBUTION:
        return ATTRIBUTION[head]
    raise VerifierError(
        UNATTRIBUTED_CHECK_NAME,
        f"check name {_safe(check_name)} is in no attribution class",
    )


# ---------------------------------------------------------------------------
# legs -> findings
# ---------------------------------------------------------------------------

_STATE_OF = {
    RELEASE: (VerdictState.OK, None),
    REFUSE: (VerdictState.REJECT, None),
    HOLD: (VerdictState.ERROR, ErrorKind.INCOMPLETE),
    NO_VERDICT: (VerdictState.ERROR, ErrorKind.CRASH),
}


def _safe(x: object) -> str:
    """A formatter never raises (§C9): a hostile `__str__` / `__repr__` is shown as such."""
    try:
        return repr(x)
    except Exception:  # noqa: BLE001
        return "<unrepresentable>"


def _reason_text(r: VerdictReason) -> str:
    return f"{_safe(r.check_name)}: {_safe(r.code)}"


def _check_shapes(base: Verdict | None, incompletes: tuple, crashes: tuple) -> None:
    """The join reads reasons; the meet reads legs. A leg whose reasons do not say what
    its state says would be visible to one and not the other, so refuse it here."""
    if base is not None:
        if base.state is VerdictState.OK and base.reasons:
            raise VerifierError(MALFORMED_LEG, "an OK base leg carries reasons")
        if base.state is VerdictState.REJECT and not base.reasons:
            raise VerifierError(MALFORMED_LEG, "a REJECT base leg carries no reasons")
        if base.state is VerdictState.ERROR:
            raise VerifierError(
                MALFORMED_LEG, "an ERROR verdict was handed in as the base leg"
            )
    for leg in incompletes:
        if not leg.is_incomplete or not leg.reasons:
            raise VerifierError(
                MALFORMED_LEG,
                "a clean-ERROR leg must be `is_incomplete` and carry reasons",
            )
    for leg in crashes:
        if not leg.is_crash or not leg.reasons:
            raise VerifierError(
                MALFORMED_LEG, "a crash leg must be `is_crash` and carry reasons"
            )


def _split(base: Verdict | None, incompletes: tuple, crashes: tuple) -> tuple:
    """Per-proposition REJECT and SILENT reasons; provenance and content admission
    REJECT reasons; admission clean-ERROR reasons; crash reasons."""
    contradicts: dict = {p: [] for p in PROPOSITIONS}
    silent: dict = {p: [] for p in PROPOSITIONS}
    provenance: list = []
    content: list = []
    unfinished: list = []
    for r in base.reasons if base is not None else ():
        p = proposition_of(r.check_name)
        if p is not None:
            contradicts[p].append(r)
        elif (
            r.check_name in PROVENANCE_CHECKS
            or str(r.check_name).split(":", 1)[0] in PROVENANCE_CHECKS
        ):
            provenance.append(r)
        else:
            content.append(r)
    for leg in incompletes:
        for r in leg.reasons:
            p = proposition_of(r.check_name)
            (unfinished if p is None else silent[p]).append(r)
    crashed = [r for leg in crashes for r in leg.reasons]
    return contradicts, silent, provenance, content, unfinished, crashed


def _roster() -> Roster:
    return Roster.declare(
        (
            Expected(
                record_id=RECORD_ID,
                authority=PRODUCER,
                standing=PROPOSITIONS,
                subject={},
                # The bundle is attached: the walk has already read it. The engine reads
                # no bundle byte itself (SCOPING stage 1); the walk is the consumer callable.
                fetch=lambda context, nonce, rows: {"subject": {}, "attached": True},
                reached=False,
            ),
        ),
        TABLE,
        source="audit_bundle.decide: the bundle is the producer's one attached record",
    )


def decide_through_join(
    base: Verdict | None,
    incompletes: Iterable[Verdict] = (),
    *,
    crashes: Iterable[Verdict] = (),
    completeness=None,
    walk_completed: bool = True,
) -> Verdict:
    """Decide the walk's legs through `multi_root`, and build the verdict from the decision.

    `base` is `Verdict.from_failures(failures)` (REJECT or OK; every reason a REJECT
    leg) or None when the walk exited before it had a base; `incompletes` are the
    clean-ERROR legs; `crashes` are crash-class legs. `walk_completed` is False on an
    early exit: then no proposition gets a finding, so nothing can CONFIRM.

    Returns a `Verdict` whose `state`/`error_kind` ARE the join's decision, whose
    `reasons`/`legs` are the steps' own in `compose` order, and whose `decision` is the
    join's face."""
    incompletes = tuple(incompletes)
    crashes = tuple(crashes)
    _check_shapes(base, incompletes, crashes)
    contradicts, silent, provenance, content, unfinished, crashed = _split(
        base, incompletes, crashes
    )

    refused = "; ".join(_reason_text(r) for r in provenance)
    problem = "; ".join(_reason_text(r) for r in content) or None
    admission = admit(
        _roster(),
        None,
        signature_valid=lambda e, rec: Refused(refused) if refused else True,
        validate_content=lambda rid, rec: problem,
    )
    rows = admission.rows
    # A proposition speaks only where its step ran. On an early exit, or when an
    # admission step did not finish, no step after admission ran: findings stay empty and
    # every proposition is CANNOT_CONCLUDE / INSUFFICIENT with nothing confirming.
    steps_ran = PROPOSITIONS if (walk_completed and not unfinished) else ()
    findings: dict = {}
    for p in PROPOSITIONS:
        if contradicts[p]:
            f = finding(
                rows,
                RECORD_ID,
                CONTRADICTS,
                "; ".join(_reason_text(r) for r in contradicts[p]),
                table=TABLE,
                content_roots=(AUDITOR,),
            )
        elif silent[p]:
            f = finding(
                rows,
                RECORD_ID,
                SILENT,
                "; ".join(_reason_text(r) for r in silent[p]),
                table=TABLE,
                content_roots=(AUDITOR,),
            )
        elif p in steps_ran:
            # The chain is (bundle, producer) -> (content, auditor): the auditor's spec and
            # kit are content the step read, but the envelope is the producer's, so S1's
            # minimum is the proposer's root whatever `content_roots` says.
            f = finding(
                rows,
                RECORD_ID,
                CONFIRMS,
                "step ran to completion; no finding against the record (vacuity not measured at depth 1)",
                table=TABLE,
                content_roots=(AUDITOR,),
            )
        else:
            continue
        findings[p] = [f]
    states = proposition_states(rows, findings, propositions=PROPOSITIONS, table=TABLE)
    raised = tuple((RECORD_ID, "verify", _reason_text(r)) for r in crashed)
    ov = overall(states, admission, table=TABLE, raised=raised)

    state, kind = _STATE_OF[ov["decision"]]
    legs = tuple(leg for leg in (base, *incompletes, *crashes) if leg is not None)
    # The meet, kept as the cross-check: it also supplies the ratified reason/leg order.
    composed = legs[0] if len(legs) == 1 else compose(legs)
    if composed.state is not state or (
        state is VerdictState.ERROR and composed.error_kind is not kind
    ):
        raise VerifierError(
            DECISION_DIVERGENCE,
            f"join decided {ov['decision']} ({state.value}/{kind.value if kind else '-'}) but the meet gave "
            f"{composed.state.value}/{composed.error_kind.value if composed.error_kind else '-'}: "
            f"provenance={len(provenance)} content={len(content)} unfinished={len(unfinished)} "
            f"crashed={len(crashed)} contradicted={ov['contradicted']!r} unreached={ov['unreached']!r}",
        )
    face = dict(ov)
    face.update(
        engine="multi_root",
        depth=1,
        roots=list(TABLE.roots),
        proposer_root=TABLE.proposer_root,
        walk_completed=bool(walk_completed),
        steps_ran=list(steps_ran),
        record_dispositions={r["record_id"]: r["disposition"] for r in rows},
        admission_reasons={r["record_id"]: r.get("reason") for r in rows},
        admission_unfinished=[_reason_text(r) for r in unfinished],
        states={p: list(v) for p, v in state_vector(states).items()},
        universe_sha=admission.universe_sha,
    )
    return Verdict(
        state,
        composed.reasons,
        # One leg is returned as itself (the walk's early exits had no legs on master);
        # a composite keeps every leg, as `compose` always did.
        composed.legs if len(legs) > 1 else (),
        completeness,
        error_kind=kind,
        decision=deep_freeze(face),
    )


def decide_single(verdict: Verdict, *, completeness=None) -> Verdict:
    """Route one already-built verdict (an early exit of the walk, or the crash boundary's
    verdict) through the join. The walk did not complete, so nothing CONFIRMS."""
    completeness = verdict.completeness if completeness is None else completeness
    if verdict.state is VerdictState.OK:
        # No exit of the walk is an OK: an OK verdict only comes from a completed walk,
        # which goes through `decide_through_join(walk_completed=True)`. Handing one in
        # here would read as "nothing ran, nothing confirms" against a meet that says OK.
        raise VerifierError(MALFORMED_LEG, "an OK verdict is not an exit of the walk")
    if verdict.state is VerdictState.ERROR:
        if verdict.is_crash:
            return decide_through_join(
                None,
                (),
                crashes=(verdict,),
                completeness=completeness,
                walk_completed=False,
            )
        return decide_through_join(
            None, (verdict,), completeness=completeness, walk_completed=False
        )
    return decide_through_join(
        verdict, (), completeness=completeness, walk_completed=False
    )
