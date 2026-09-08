"""audit_bundle/multi_root/propositions.py — findings with a provenance chain, the state
rule, the decision lattice, and the improves relation.

A check reads ADMITTED records and returns findings: (record_id, CONFIRMS | CONTRADICTS |
SILENT, detail, relied_on). `relied_on` is the provenance CHAIN of the content the finding
rests on: the record's envelope root first, then the root of every piece of content the
check read that some OTHER party wrote (an actor label in a log entry is the ERP's
assertion carried in the log's envelope; the vendor name a bank is asked about is the
customer's master, carried in the bank's answer).

THE RULE (S1's, imported, not restated): a finding's effective root is the monotone
MINIMUM over its chain. If any link is the proposer's root, the finding is proposer-rooted
whatever signed the envelope. The tiers come from `plugins/stamp_lattice.STAMP_ORDER`
(proposer-rooted content = INTERNAL_SOURCE, any other declared root = CONFIRMED_EXTERNAL),
and the label a finding carries is graded against its chain by `StampLatticeCheck` — a
label above the min is `STAMP_AGGREGATE_ROUNDUP_DETECTED` and the verifier refuses to
proceed (`ProvenanceError`). On a finding built by `finding()` the label IS the min, so
the grade is tautological by construction; the grade binds every finding built any other
way — by hand, by a consumer, or loaded back from a face — and that is the path a
mislabel arrives by. The first implementation set the label by hand at three call sites
and missed three others across five adversarial passes.

STATE RULE, per proposition, in this order:
  1. any admitted record with standing CONTRADICTS               -> CONTRADICTED
  2. an expected record with standing was not admitted for
     confirmation (the admission channel has a remainder), or no
     record has standing at all                                   -> CANNOT_CONCLUDE / UNREACHED
  3. a finding whose EFFECTIVE root is not the proposer's CONFIRMS -> ESTABLISHED
  4. otherwise                                                    -> CANNOT_CONCLUDE / INSUFFICIENT
     (`proposer_root_confirms` records whether the proposer's own root confirmed).

A stale record may CONTRADICT and never CONFIRM. Absence never reads as agreement; a
SILENT finding is not a confirmation.

DECISION: REFUSE if any proposition is CONTRADICTED, any expected record is UNUSABLE
(tamper evidence is not absence), a producer-attached record the roster names was not
delivered (dropping evidence is not "unreached"), or the input was inadmissible; HOLD if
any proposition is UNREACHED, or INSUFFICIENT with nothing confirming at all, or the
consumer's `hold_if` policy says so; RELEASE otherwise. The lattice REFUSE < HOLD < RELEASE is `_degradation.Severity`'s
REJECT > ERROR_CLEAN > PASS, and `improves` compares two runs on that order — so the
degradation oracle can be pointed at a consumer's verifier without a second vocabulary.

Stdlib only; imports nothing from `verifier`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from types import SimpleNamespace

from .._degradation import Severity
from ..coverage_channels import account_channels
from ..plugins.stamp_lattice import STAMP_RANK, StampLatticeCheck
from ..verdict import VERIFIER_INCOMPLETE, Verdict
from .roots import RootTable, UndeclaredAuthority
from .roster import ADMITTED, UNREACHED, UNUSABLE, Admission, admission_channels

__all__ = [
    "CONFIRMS",
    "CONTRADICTS",
    "SILENT",
    "FINDINGS",
    "ESTABLISHED",
    "CONTRADICTED",
    "CANNOT_CONCLUDE",
    "UNREACHED_Q",
    "INSUFFICIENT_Q",
    "REFUSE",
    "HOLD",
    "RELEASE",
    "DECISION_SEVERITY",
    "TIER_PROPOSER",
    "TIER_INDEPENDENT",
    "REASON_CONTRADICTED",
    "REASON_RECORD_UNUSABLE",
    "REASON_INPUT_INADMISSIBLE",
    "REASON_ATTACHMENT_UNDELIVERED",
    "ProvenanceError",
    "chain_of",
    "effective_root",
    "grade_chain",
    "finding",
    "proposition_states",
    "overall",
    "state_vector",
    "improves",
    "to_verdict",
]

CONFIRMS, CONTRADICTS, SILENT = "CONFIRMS", "CONTRADICTS", "SILENT"
FINDINGS = (CONFIRMS, CONTRADICTS, SILENT)

ESTABLISHED, CONTRADICTED, CANNOT_CONCLUDE = "ESTABLISHED", "CONTRADICTED", "CANNOT_CONCLUDE"
UNREACHED_Q, INSUFFICIENT_Q = "UNREACHED", "INSUFFICIENT"

REFUSE, HOLD, RELEASE = "REFUSE", "HOLD", "RELEASE"
DECISION_SEVERITY = {RELEASE: Severity.PASS, HOLD: Severity.ERROR_CLEAN, REFUSE: Severity.REJECT}

#: The S1 tiers this engine uses. A mapping onto S1's vocabulary, declared once: content
#: written under the proposer's own administrative root is INTERNAL_SOURCE; content from
#: any other declared root is CONFIRMED_EXTERNAL. Both must exist in STAMP_ORDER — a
#: vocabulary drift there must be loud here, not a silent KeyError in a verdict.
TIER_PROPOSER, TIER_INDEPENDENT = "INTERNAL_SOURCE", "CONFIRMED_EXTERNAL"
for _t in (TIER_PROPOSER, TIER_INDEPENDENT):
    if _t not in STAMP_RANK:
        raise ImportError(f"multi_root tier {_t!r} is not in stamp_lattice.STAMP_ORDER")
if STAMP_RANK[TIER_PROPOSER] >= STAMP_RANK[TIER_INDEPENDENT]:
    raise ImportError("multi_root tiers are not ordered proposer < independent in STAMP_ORDER")

REASON_CONTRADICTED = "MULTI_ROOT_CONTRADICTED"
REASON_RECORD_UNUSABLE = "MULTI_ROOT_RECORD_UNUSABLE"
REASON_INPUT_INADMISSIBLE = "INPUT_INADMISSIBLE_PROPOSAL"
REASON_ATTACHMENT_UNDELIVERED = "MULTI_ROOT_ATTACHMENT_UNDELIVERED"

_GRADER = StampLatticeCheck()  # no key: any upgrade-bearing record is refused (fail-closed)


class ProvenanceError(ValueError):
    """A finding's label or chain is unusable. This is a VERIFIER defect and it raises:
    a mislabeled finding must not be silently downgraded into a verdict."""


# ---------------------------------------------------------------------------
# provenance chains
# ---------------------------------------------------------------------------


def _record_root(rows: Iterable[Mapping], record_id: str) -> str:
    for r in rows:
        if r["record_id"] == record_id:
            return r["root"]
    raise ProvenanceError(f"finding names record {record_id!r}, which is not on the roster")


def chain_of(rows: Iterable[Mapping], record_id: str, content_roots: Iterable[str], table: RootTable) -> tuple:
    """The provenance chain: (record_id, envelope root) first, then one ("content", root)
    link per content root. Every root must be declared; the envelope cannot be omitted."""
    envelope = _record_root(rows, record_id)
    chain = [(record_id, envelope)]
    for r in content_roots:
        if not table.is_declared_root(r):
            raise ProvenanceError(f"finding on {record_id!r} relies on undeclared root {r!r}")
        chain.append(("content", r))
    return tuple(chain)


def _tier(root: str, table: RootTable) -> str:
    if not table.is_declared_root(root):
        raise ProvenanceError(f"chain link under undeclared root {root!r}")
    return TIER_PROPOSER if table.is_proposer(root) else TIER_INDEPENDENT


def effective_root(chain: tuple, table: RootTable) -> str:
    """The monotone minimum over the chain: the proposer's root if any link is theirs,
    else the envelope root."""
    if not chain:
        raise ProvenanceError("empty provenance chain")
    tiers = [_tier(root, table) for _, root in chain]
    if min(tiers, key=lambda t: STAMP_RANK[t]) == TIER_PROPOSER:
        return table.proposer_root
    return chain[0][1]


def grade_chain(chain: tuple, claimed_root: str, table: RootTable):
    """S1 grades the CLAIM against the chain. Returns the `PluginResult`. Not ok means the
    label is above (or below) the min over the chain."""
    records = [{"stamp_observed": _tier(root, table)} for _, root in chain]
    manifest = SimpleNamespace(
        dispatch_records=records,
        aggregate_stamp=_tier(claimed_root, table),
        bundle_id="multi_root:finding",
        created_at=None,
    )
    return _GRADER.check(Path("."), manifest)


def finding(
    rows: Iterable[Mapping],
    record_id: str,
    verdict: str,
    detail: str,
    *,
    table: RootTable,
    content_roots: Iterable[str] = (),
    claimed_root: str | None = None,
) -> dict:
    """Build one finding. The label is the min over the chain; a `claimed_root` is graded
    against the chain by S1 and refused if it rounds up."""
    if verdict not in FINDINGS:
        raise ProvenanceError(f"finding verdict must be one of {FINDINGS}, got {verdict!r}")
    chain = chain_of(rows, record_id, content_roots, table)
    root = effective_root(chain, table)
    if claimed_root is not None:
        res = grade_chain(chain, claimed_root, table)
        if not res.ok:
            raise ProvenanceError(f"finding on {record_id!r}: claimed root {claimed_root!r} refused: {res.reason_code}: {res.detail}")
        root = claimed_root
    return {"record_id": record_id, "root": root, "finding": verdict, "detail": detail, "relied_on": chain}


def _graded(f: Mapping, rows: Iterable[Mapping], table: RootTable) -> Mapping:
    """Refuse a malformed or mislabeled finding. A finding without a chain is graded as a
    chain of its envelope alone, so a bare label that differs from the envelope root is a
    claim with nothing behind it."""
    if not isinstance(f, Mapping) or f.get("finding") not in FINDINGS:
        raise ProvenanceError(f"malformed finding {f!r}")
    chain = f.get("relied_on")
    if chain is None:
        chain = chain_of(rows, f["record_id"], (), table)
    try:
        chain = tuple(tuple(link) for link in chain)
    except TypeError:
        raise ProvenanceError(f"finding on {f.get('record_id')!r}: relied_on is not a sequence of links") from None
    if any(len(link) != 2 or not isinstance(link[0], str) or not isinstance(link[1], str) for link in chain):
        # Red-team witness (2026-09-06): a 3-element link raised a bare ValueError out
        # of `grade_chain` instead of this module's own refusal.
        raise ProvenanceError(f"finding on {f.get('record_id')!r}: every relied_on link must be a (what, root) pair of strings, got {chain!r}")
    if not chain or chain[0][0] != f["record_id"]:
        raise ProvenanceError(f"finding on {f.get('record_id')!r}: chain does not start at the record's envelope")
    root = f.get("root")
    if not table.is_declared_root(root):
        raise ProvenanceError(f"finding on {f['record_id']!r} labeled with undeclared root {root!r}")
    res = grade_chain(chain, root, table)
    if not res.ok:
        raise ProvenanceError(f"finding on {f['record_id']!r} labeled {root!r} refused by S1: {res.reason_code}: {res.detail}")
    if root != effective_root(chain, table):
        # equal tier but a different independent root than the envelope: a label swap
        raise ProvenanceError(f"finding on {f['record_id']!r} labeled {root!r} but its chain resolves to {effective_root(chain, table)!r}")
    return f


# ---------------------------------------------------------------------------
# the state rule
# ---------------------------------------------------------------------------


def proposition_states(
    rows: Iterable[Mapping],
    findings: Mapping,
    *,
    propositions: Iterable[str],
    table: RootTable,
    extra_standing: Mapping | None = None,
) -> dict:
    """Per-proposition state. `findings` maps proposition id -> list of findings."""
    rows = list(rows)
    props = tuple(propositions)
    channels = admission_channels(rows, props, extra_standing=extra_standing)
    stale_ids = {r["record_id"] for r in rows if r.get("stale")}
    by_id = {r["record_id"]: r for r in rows}
    out = {}
    for pid in props:
        ch = channels[pid]
        # a stale record may contradict; it never confirms
        fs = [
            _graded(f, rows, table)
            for f in findings.get(pid, ())
            if f["record_id"] not in stale_ids or f["finding"] == CONTRADICTS
        ]
        incompletes: list = []
        account_channels([ch], incompletes)
        missing = [
            f"{rid}:{'STALE' if by_id[rid].get('stale') else by_id[rid]['disposition']}"
            for rid in sorted(ch.uncovered, key=repr)
        ]
        if not ch.present:
            missing = ["no record has standing"]
        confirming = sorted({f["root"] for f in fs if f["finding"] == CONFIRMS}, key=repr)
        contradicting = sorted({f["root"] for f in fs if f["finding"] == CONTRADICTS}, key=repr)
        st = {
            "proposition": pid,
            "state": None,
            "qualifier": None,
            "roots_established_from": [],
            "roots_contradicting": contradicting,
            "proposer_root_confirms": table.proposer_root in confirming,
            "expected_records": sorted(ch.present, key=repr),
            "missing": missing,
            "admission_incomplete": [v.detail for v in incompletes],
            "findings": fs,
        }
        if contradicting:
            st["state"] = CONTRADICTED
        elif missing:
            st["state"], st["qualifier"] = CANNOT_CONCLUDE, UNREACHED_Q
        elif any(not table.is_proposer(r) for r in confirming):
            st["state"], st["roots_established_from"] = ESTABLISHED, confirming
        else:
            st["state"], st["qualifier"] = CANNOT_CONCLUDE, INSUFFICIENT_Q
        out[pid] = st
    return out


def overall(
    states: Mapping,
    rows: "Iterable[Mapping] | Admission",
    *,
    table: RootTable,
    hold_if: Callable[[Mapping], bool] | None = None,
    inadmissible: str | None = None,
) -> dict:
    """The decision. `hold_if(states)` is the consumer's release policy: it can only move a
    RELEASE to HOLD; it cannot lift a REFUSE or an UNREACHED hold. `inadmissible` is
    `Admission.inadmissible`: an inadmissible input REFUSES (the artifact is bad), it is
    never a could-not-conclude.

    Pass the `Admission` itself as `rows` and the flag travels with it. Red-team witness
    (2026-09-06): a consumer helper that rebuilt `overall` from loose rows dropped the flag
    at one of two call sites — the class the memory calls "close the class, not the
    witness" — so the object that carries the rows now carries the flag."""
    if isinstance(rows, Admission):
        if inadmissible is None:
            inadmissible = rows.inadmissible
        rows = rows.rows
    rows = list(rows)
    contradicted = [p for p, s in states.items() if s["state"] == CONTRADICTED]
    unusable = [r["record_id"] for r in rows if r["disposition"] == UNUSABLE]
    undelivered = [r["record_id"] for r in rows if r["disposition"] == UNREACHED and not r.get("reached", True)]
    unreached = [p for p, s in states.items() if s["qualifier"] == UNREACHED_Q]
    insufficient = [p for p, s in states.items() if s["qualifier"] == INSUFFICIENT_Q]
    unconfirmed = [p for p in insufficient if not states[p]["proposer_root_confirms"]]
    established = [p for p, s in states.items() if s["state"] == ESTABLISHED]
    residual = [p for p in insufficient if states[p]["proposer_root_confirms"]]
    policy_hold = bool(hold_if(states)) if hold_if is not None else False
    if contradicted or unusable or undelivered or inadmissible:
        decision = REFUSE
    elif unreached or unconfirmed or policy_hold:
        decision = HOLD
    else:
        decision = RELEASE
    independent = sorted(
        {r for p in established for r in states[p]["roots_established_from"] if not table.is_proposer(r)},
        key=repr,
    )
    return {
        "decision": decision,
        "denominator": len(states),
        "established": established,
        "contradicted": contradicted,
        "unusable_records": unusable,
        "undelivered_attachments": undelivered,
        "unreached": unreached,
        "insufficient": insufficient,
        "residual_proposer_root_only": residual,
        "unconfirmed": unconfirmed,
        "held_by_policy": policy_hold,
        "inadmissible_input": inadmissible,
        "independent_roots_establishing": independent,
    }


def state_vector(states: Mapping) -> dict:
    return {p: (s["state"], s["qualifier"]) for p, s in states.items()}


def improves(degraded: Mapping, counterpart: Mapping, *, propositions: Iterable[str]) -> dict:
    """Does `degraded` buy a better verdict than `counterpart`? Two readings, both
    reported. `improves`: release gained, or a proposition newly ESTABLISHED. `improves_
    lattice`: the decision moved up REFUSE < HOLD < RELEASE, which is `Severity` moving
    DOWN. Propositions leaving CONTRADICTED are reported beside both; they are not a
    verdict."""
    props = tuple(propositions)
    d, c = degraded["overall"]["decision"], counterpart["overall"]["decision"]
    rel = d == RELEASE and c != RELEASE
    gained = [p for p in props if degraded["states"][p]["state"] == ESTABLISHED and counterpart["states"][p]["state"] != ESTABLISHED]
    left = [p for p in props if counterpart["states"][p]["state"] == CONTRADICTED and degraded["states"][p]["state"] != CONTRADICTED]
    dv, cv = state_vector(degraded["states"]), state_vector(counterpart["states"])
    transitions = {p: (cv[p][0], cv[p][1], dv[p][0], dv[p][1]) for p in props if cv[p] != dv[p]}
    moved_up = DECISION_SEVERITY[d] < DECISION_SEVERITY[c]
    return {
        "release_gained": rel,
        "propositions_newly_established": gained,
        "improves": rel or bool(gained),
        "decision_moved_up": moved_up,
        "propositions_leaving_contradicted": left,
        "improves_lattice": moved_up,
        "decisions": (c, d),
        "severities": (int(DECISION_SEVERITY[c]), int(DECISION_SEVERITY[d])),
        "transitions": transitions,
    }


def to_verdict(ov: Mapping, *, check_name: str = "multi_root") -> Verdict:
    """The tri-state face: REFUSE -> REJECT, HOLD -> clean ERROR (could not conclude),
    RELEASE -> OK. Exit codes follow `verdict.exit_code`."""
    if ov["decision"] == REFUSE:
        if ov.get("inadmissible_input"):
            return Verdict.reject(REASON_INPUT_INADMISSIBLE, str(ov["inadmissible_input"]), check_name=check_name)
        if ov["contradicted"]:
            return Verdict.reject(REASON_CONTRADICTED, f"contradicted: {ov['contradicted']!r}", check_name=check_name)
        if ov["unusable_records"]:
            return Verdict.reject(REASON_RECORD_UNUSABLE, f"unusable records: {ov['unusable_records']!r}", check_name=check_name)
        return Verdict.reject(REASON_ATTACHMENT_UNDELIVERED, f"expected attachments not delivered: {ov['undelivered_attachments']!r}", check_name=check_name)
    if ov["decision"] == HOLD:
        parts = []
        if ov["unreached"]:
            parts.append(f"unreached: {ov['unreached']!r}")
        if ov["unconfirmed"]:
            parts.append(f"no root confirms: {ov['unconfirmed']!r}")
        if ov["held_by_policy"]:
            parts.append("held by release policy")
        return Verdict.incomplete(VERIFIER_INCOMPLETE, "; ".join(parts) or "held", check_name=check_name)
    if ov["decision"] == RELEASE:
        return Verdict.passed()
    raise ProvenanceError(f"unknown decision {ov.get('decision')!r}")
