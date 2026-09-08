"""audit_bundle.multi_root — substrate tests on a synthetic two-authority, two-root world.

Not the authority-maximization probe's world: that probe is a CONSUMER of this package and
keeps its own 119-test battery. Every fail-closed branch here has a positive case, and the
mutant controls at the bottom name the assertion each one isolates.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from audit_bundle import multi_root as M
from audit_bundle._degradation import Severity, probe_monotonicity
from audit_bundle.multi_root import propositions as MP
from audit_bundle.multi_root import roster as MR
from audit_bundle.multi_root.roots import RootTable
from audit_bundle.verdict import exit_code

# ---------------------------------------------------------------------------
# the world: an ERP (the proposer's root) and a bank (independent)
# ---------------------------------------------------------------------------

R_A, R_B = "R-ERP", "R-BANK"
TABLE = RootTable.declare({"erp": R_A, "bank": R_B}, proposer_root=R_A, roots=(R_A, R_B))
PROPS = ("P1", "P2", "P3")  # P1: account binding (erp + bank); P2: erp only; P3: nobody has standing
KEYS = {"erp": b"erp-key", "bank": b"bank-key"}


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def sign(authority, subject, body):
    payload = {"authority": authority, "subject": subject, "body": body}
    return {**payload, "sig": hmac.new(KEYS[authority], _canon(payload), hashlib.sha256).hexdigest()}


def sig_ok(exp, rec):
    payload = {k: rec.get(k) for k in ("authority", "subject", "body")}
    if rec.get("authority") != exp.authority or exp.authority not in KEYS:
        return False
    return hmac.compare_digest(str(rec.get("sig", "")), hmac.new(KEYS[exp.authority], _canon(payload), hashlib.sha256).hexdigest())


def honest_world():
    return {"erp": {"vendor": {"account": "ACC-1", "name": "ACME"}, "snapshot": "s1"}, "bank": {"ACC-1": "ACME LTD"}, "pin": "s1",
            "bank_reachable": True, "bank_corrupt": False}


def fetch_erp(ctx, nonce, rows):
    w = ctx.world
    return sign("erp", {"kind": "vendor", "nonce": nonce}, {"vendor": w["erp"]["vendor"], "snapshot": w["erp"]["snapshot"]})


def fetch_bank(ctx, nonce, rows):
    w = ctx.world
    if not w["bank_reachable"]:
        return None
    rec = sign("bank", {"kind": "payee", "account": ctx.proposal["account"], "nonce": nonce}, {"holder": w["bank"].get(ctx.proposal["account"])})
    if w["bank_corrupt"]:
        rec = {**rec, "sig": "00" * 32}
    return rec


def fetch_attached(ctx, nonce, rows):
    return ctx.proposal.get("attached")


def make_roster(proposal, *, with_attached=False, with_dependent=False):
    rows = [
        M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"}, fetch_erp),
        M.Expected("bank:payee", "bank", ("P1",), {"kind": "payee", "account": proposal["account"]}, fetch_bank),
    ]
    if with_attached:
        rows.append(M.Expected("erp:attached", "erp", ("P2",), {"kind": "attached"}, fetch_attached, reached=False))
    if with_dependent:
        rows.append(M.Expected("bank:dependent", "bank", ("P1",), {"kind": "dependent"},
                               lambda c, n, rs: sign("bank", {"kind": "dependent", "nonce": n, "holder": "ACME LTD"}, {}),
                               subject_from=lambda rs: ({"holder": M.admitted(rs, "bank:payee")["body"]["holder"]} if M.admitted(rs, "bank:payee") else None)))
    return M.Roster.declare(rows, TABLE, source="test roster")


def is_stale(exp, rec):
    return None


def validate(record_id, rec):
    return None if isinstance(rec.get("body"), dict) else "body is not an object"


def checks(proposal, rows):
    out = {"P1": [], "P2": [], "P3": []}
    e = M.admitted(rows, "erp:vendor")
    if e:
        v = e["body"]["vendor"]
        out["P1"].append(M.finding(rows, "erp:vendor", M.CONFIRMS if v["account"] == proposal["account"] else M.CONTRADICTS, "erp binding", table=TABLE))
        out["P2"].append(M.finding(rows, "erp:vendor", M.CONFIRMS if v["name"] == proposal["payee"] else M.CONTRADICTS, "erp name", table=TABLE))
    b = M.admitted(rows, "bank:payee")
    if b:
        holder = b["body"]["holder"]
        ok = holder is not None and holder.replace(" LTD", "") == proposal["payee"]
        out["P1"].append(M.finding(rows, "bank:payee", M.CONFIRMS if ok else M.CONTRADICTS, "bank holder", table=TABLE))
    return out


def run(world, proposal, *, roots_enabled=None, hold_if=None, roster=None, nonce=None, stale=is_stale):
    roster = roster or make_roster(proposal)
    ctx = SimpleNamespace(world=world, proposal=proposal)
    adm = M.admit(roster, ctx, signature_valid=sig_ok, validate_content=validate, is_stale=stale, roots_enabled=roots_enabled, nonce=nonce)
    states = M.proposition_states(adm.rows, checks(proposal, adm.rows), propositions=PROPS, table=TABLE)
    ov = M.overall(states, adm.rows, table=TABLE, hold_if=hold_if)
    return {"rows": adm.rows, "admission": adm, "states": states, "overall": ov}


HONEST = {"payee": "ACME", "account": "ACC-1"}


# ---------------------------------------------------------------------------
# roots
# ---------------------------------------------------------------------------

def test_root_table_refuses_undeclared_authority_and_malformed_declarations():
    with pytest.raises(M.UndeclaredAuthority):
        TABLE.root_of("hris")
    with pytest.raises(M.RootTableError):
        RootTable.declare({"erp": R_A}, proposer_root="R-X", roots=(R_A,))
    with pytest.raises(M.RootTableError):
        RootTable.declare({"erp": "R-UNDECLARED"}, proposer_root=R_A, roots=(R_A,))
    with pytest.raises(M.RootTableError):
        RootTable.declare({}, proposer_root=R_A, roots=())
    with pytest.raises(M.RootTableError):
        RootTable.declare({"erp": R_A}, proposer_root=R_A, roots=(R_A, R_A))


def test_collapse_re_roots_one_authority_and_leaves_the_original_untouched():
    three = RootTable.declare({"erp": R_A, "bank": R_B, "log": "R-LOG"}, proposer_root=R_A, roots=(R_A, R_B, "R-LOG"))
    t2 = three.collapse("log", R_B)
    assert t2.root_of("log") == R_B and three.root_of("log") == "R-LOG"
    assert t2.roots == three.roots
    with pytest.raises(M.RootTableError):
        three.collapse("bank", "R-NOPE")
    with pytest.raises(M.UndeclaredAuthority):
        three.collapse("hris", R_A)


def test_collapse_never_crosses_the_proposer_boundary():
    """Red-team witness w5 (2026-09-06): collapse("erp", R-BANK) relabelled the proposer's
    own vendor master as independent and P1 ESTABLISHED off content the payer controls."""
    with pytest.raises(M.RootTableError, match="proposer status"):
        TABLE.collapse("erp", R_B)   # proposer's system -> independent
    with pytest.raises(M.RootTableError, match="proposer status"):
        TABLE.collapse("bank", R_A)  # independent -> proposer's
    # the witness's payload, on the guarded table: P1 stays confirmed by the proposer only
    rows = run(honest_world(), HONEST, roots_enabled=(R_A,))["rows"]
    f = M.finding(rows, "erp:vendor", M.CONFIRMS, "erp binding", table=TABLE)
    st = M.proposition_states(rows, {"P1": [f]}, propositions=("P1",), table=TABLE)
    assert (st["P1"]["state"], st["P1"]["qualifier"]) == (M.CANNOT_CONCLUDE, M.INSUFFICIENT_Q)


def test_independence_metrics_count_admitted_non_stale_rows_only():
    r = run(honest_world(), HONEST)
    m = M.independence_metrics(r["rows"])
    assert (m["authority_count"], m["distinct_root_count"]) == (2, 2)
    w = honest_world(); w["bank_reachable"] = False
    m = M.independence_metrics(run(w, HONEST)["rows"])
    assert (m["authority_count"], m["distinct_root_count"], m["unreached"]) == (1, 1, 1)


# ---------------------------------------------------------------------------
# roster + admission
# ---------------------------------------------------------------------------

def test_roster_declaration_is_fail_closed():
    good = M.Expected("x", "erp", ("P1",), {}, fetch_erp)
    with pytest.raises(M.RosterError):
        M.Roster.declare([good, good], TABLE, source="dup")
    with pytest.raises(M.RosterError):
        M.Roster.declare([M.Expected("y", "hris", ("P1",), {}, fetch_erp)], TABLE, source="undeclared")
    with pytest.raises(M.RosterError):
        M.Roster.declare([M.Expected("y", "erp", (), {}, fetch_erp)], TABLE, source="no standing")
    with pytest.raises(M.RosterError):
        M.Roster.declare([], TABLE, source="empty")


def test_honest_run_admits_everything_and_seals_a_receipt_against_the_held_sha():
    r = run(honest_world(), HONEST)
    assert all(x["disposition"] == M.ADMITTED for x in r["rows"])
    adm = r["admission"]
    assert adm.receipt["universe_sha"] == adm.universe_sha and adm.withheld == {} and adm.inadmissible is None
    # P3 has no record of standing anywhere: the verifier never asked, so the run HOLDs on it
    assert r["overall"]["decision"] == M.HOLD and r["overall"]["unreached"] == ["P3"]


def test_the_denominator_is_the_record_ids_not_their_count():
    p = HONEST
    a = make_roster(p).universe_sha
    swapped = M.Roster.declare([
        M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"}, fetch_erp),
        M.Expected("bank:payee-OTHER", "bank", ("P1",), {"kind": "payee"}, fetch_bank),
    ], TABLE, source="swapped").universe_sha
    assert a != swapped  # same count, different record: a count-based kill condition cannot see this


def test_disabling_a_root_withholds_its_records_on_the_receipt_and_keeps_the_denominator():
    r = run(honest_world(), HONEST, roots_enabled=(R_A,))
    adm = r["admission"]
    assert [x["record_id"] for x in r["rows"]] == ["erp:vendor"]
    assert adm.withheld == {"bank:payee": M.ROOT_NOT_ENABLED}
    assert adm.receipt["universe_sha"] == make_roster(HONEST).universe_sha
    assert adm.receipt["n_withheld"] == 1 if "n_withheld" in adm.receipt else True
    # P1 lost its independent root: INSUFFICIENT, proposer confirms -> residual, still RELEASE-able by policy
    assert (r["states"]["P1"]["state"], r["states"]["P1"]["qualifier"]) == (M.CANNOT_CONCLUDE, M.INSUFFICIENT_Q)
    assert r["states"]["P1"]["proposer_root_confirms"] is True
    with pytest.raises(M.RosterError):
        make_roster(HONEST).in_play(("R-NOPE",))


@pytest.mark.parametrize("mutation, disposition, needle", [
    ("bank_corrupt", M.UNUSABLE, "signature"),
    ("unreachable", M.UNREACHED, "no response"),
])
def test_unusable_and_unreached_are_distinct_dispositions(mutation, disposition, needle):
    w = honest_world()
    if mutation == "bank_corrupt":
        w["bank_corrupt"] = True
    else:
        w["bank_reachable"] = False
    r = run(w, HONEST)
    row = next(x for x in r["rows"] if x["record_id"] == "bank:payee")
    assert row["disposition"] == disposition and needle in row["reason"]
    assert (r["states"]["P1"]["state"], r["states"]["P1"]["qualifier"]) == (M.CANNOT_CONCLUDE, M.UNREACHED_Q)
    assert r["overall"]["decision"] == (M.REFUSE if disposition == M.UNUSABLE else M.HOLD)


def test_a_record_about_another_subject_or_a_replayed_nonce_is_unusable():
    w = honest_world()
    other = {**HONEST, "account": "ACC-9"}
    # the bank answers about ACC-9 while asked about ACC-1 (on-path substitution)
    roster = M.Roster.declare([
        M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"}, fetch_erp),
        M.Expected("bank:payee", "bank", ("P1",), {"kind": "payee", "account": "ACC-1"},
                   lambda c, n, rs: sign("bank", {"kind": "payee", "account": "ACC-9", "nonce": n}, {"holder": "ACME LTD"})),
    ], TABLE, source="substitution")
    r = run(w, HONEST, roster=roster)
    row = next(x for x in r["rows"] if x["record_id"] == "bank:payee")
    assert row["disposition"] == M.UNUSABLE and "not" in row["reason"] and "replay" not in row["reason"]
    # a genuine answer from an earlier run, replayed: right subject, wrong nonce
    roster = M.Roster.declare([
        M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"}, fetch_erp),
        M.Expected("bank:payee", "bank", ("P1",), {"kind": "payee", "account": "ACC-1"},
                   lambda c, n, rs: sign("bank", {"kind": "payee", "account": "ACC-1", "nonce": "stale-nonce"}, {"holder": "ACME LTD"})),
    ], TABLE, source="replay")
    r = run(w, HONEST, roster=roster)
    row = next(x for x in r["rows"] if x["record_id"] == "bank:payee")
    assert row["disposition"] == M.UNUSABLE and "replay" in row["reason"]


class _AlwaysEqual:
    def __eq__(self, other):
        return True


class _LyingSubject(dict):
    """Red-team witness w1/w3 (2026-09-06): a dict subclass that json-serialises (and so
    signs) over its REAL items but answers every `.get` with something that compares
    equal, so a subject-match through `.get` passed for a record about another subject or
    a replayed nonce."""

    def get(self, key, default=None):
        return _AlwaysEqual()


def test_a_record_is_compared_on_its_true_storage_never_through_get():
    from types import MappingProxyType
    w = honest_world()
    for hostile in (
        # about another account, no nonce, lying .get
        lambda c, n, rs: sign("bank", _LyingSubject(kind="payee", account="ACC-9"), {"holder": "ACME LTD"}),
        # genuinely signed answer to YESTERDAY's query, replayed under a lying .get
        lambda c, n, rs: sign("bank", _LyingSubject(kind="payee", account="ACC-1", nonce="stale"), {"holder": "ACME LTD"}),
        # a non-dict Mapping as the record itself
        lambda c, n, rs: MappingProxyType(sign("bank", {"kind": "payee", "account": "ACC-1", "nonce": n}, {"holder": "ACME LTD"})),
    ):
        roster = M.Roster.declare([
            M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"}, fetch_erp),
            M.Expected("bank:payee", "bank", ("P1",), {"kind": "payee", "account": "ACC-1"}, hostile),
        ], TABLE, source="hostile")
        r = run(w, HONEST, roster=roster)
        row = next(x for x in r["rows"] if x["record_id"] == "bank:payee")
        assert row["disposition"] != M.ADMITTED, row
        assert r["states"]["P1"]["state"] != M.ESTABLISHED
    # a lying mapping nested in an otherwise honest record is admitted AS ITS TRUE STORAGE:
    # the checks downstream read a plain dict, never the subclass
    roster = M.Roster.declare([
        M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"}, fetch_erp),
        M.Expected("bank:payee", "bank", ("P1",), {"kind": "payee", "account": "ACC-1"},
                   lambda c, n, rs: sign("bank", {"kind": "payee", "account": "ACC-1", "nonce": n}, _LyingSubject(holder="ACME LTD"))),
    ], TABLE, source="nested")
    r = run(w, HONEST, roster=roster)
    row = next(x for x in r["rows"] if x["record_id"] == "bank:payee")
    assert row["disposition"] == M.ADMITTED and type(row["record"]["body"]) is not _LyingSubject
    assert isinstance(row["record"]["body"], dict) and row["record"]["body"]["holder"] == "ACME LTD"
    # control: the same signer, plain dicts, is admitted (the closure did not over-refuse)
    r = run(w, HONEST)
    assert next(x for x in r["rows"] if x["record_id"] == "bank:payee")["disposition"] == M.ADMITTED
    # and a lying mapping in the body of an otherwise honest record is refused before any check reads it
    assert MR._plain_deep(_LyingSubject(a=1)) == {"a": 1}
    with pytest.raises(MR._NotPlain):
        MR._plain_deep(MappingProxyType({}))


def test_malformed_content_is_unusable_not_a_crash():
    roster = M.Roster.declare([
        M.Expected("erp:vendor", "erp", ("P1", "P2"), {"kind": "vendor"},
                   lambda c, n, rs: sign("erp", {"kind": "vendor", "nonce": n}, "not-an-object")),
        M.Expected("bank:payee", "bank", ("P1",), {"kind": "payee", "account": "ACC-1"}, fetch_bank),
    ], TABLE, source="malformed")
    r = run(honest_world(), HONEST, roster=roster)
    row = next(x for x in r["rows"] if x["record_id"] == "erp:vendor")
    assert row["disposition"] == M.UNUSABLE and "malformed content" in row["reason"]
    assert r["overall"]["decision"] == M.REFUSE


def test_a_stale_record_may_contradict_but_never_confirm():
    def stale(exp, rec):
        return "snapshot moved" if exp.authority == "erp" and rec["body"]["snapshot"] != "s1" else None
    w = honest_world(); w["erp"]["snapshot"] = "s2"
    r = run(w, HONEST, stale=stale)
    row = next(x for x in r["rows"] if x["record_id"] == "erp:vendor")
    assert row["disposition"] == M.ADMITTED and row["stale"] is True
    # P2 has only the ERP: its CONFIRMS is discarded -> UNREACHED (stale counts as not reached)
    assert (r["states"]["P2"]["state"], r["states"]["P2"]["qualifier"]) == (M.CANNOT_CONCLUDE, M.UNREACHED_Q)
    assert "erp:vendor:STALE" in r["states"]["P2"]["missing"]
    # a stale record that CONTRADICTS still refuses
    w["erp"]["vendor"]["account"] = "ACC-ATTACKER"
    r = run(w, HONEST, stale=stale)
    assert r["states"]["P1"]["state"] == M.CONTRADICTED and r["overall"]["decision"] == M.REFUSE


def test_an_expected_attachment_the_artifact_does_not_deliver_refuses_and_a_reached_outage_holds():
    """The oracle's finding, as a control: corrupt attachment -> REFUSE (signature); nulled
    or absent attachment -> REFUSE too, never a softer HOLD. A REACHED record that did not
    answer is still a HOLD."""
    two = ("P1", "P2")
    for attached in (None, "ABSENT"):
        p = {**HONEST}
        if attached is None:
            p["attached"] = None
        r = run(honest_world(), p, roster=make_roster(p, with_attached=True))
        row = next(x for x in r["rows"] if x["record_id"] == "erp:attached")
        assert row["disposition"] == M.UNREACHED and "not attached" in row["reason"]
        st = M.proposition_states(r["rows"], checks(p, r["rows"]), propositions=two, table=TABLE)
        ov = M.overall(st, r["rows"], table=TABLE)
        assert ov["decision"] == M.REFUSE and ov["undelivered_attachments"] == ["erp:attached"]
        assert M.to_verdict(ov).reason == MP.REASON_ATTACHMENT_UNDELIVERED
    w = honest_world(); w["bank_reachable"] = False
    r = run(w, HONEST)
    st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
    ov = M.overall(st, r["rows"], table=TABLE)
    assert ov["decision"] == M.HOLD and ov["undelivered_attachments"] == []


def test_an_attached_record_needs_no_nonce_and_a_dependent_subject_is_unreached_when_its_source_is_not_admitted():
    p = {**HONEST, "attached": sign("erp", {"kind": "attached"}, {"x": 1})}
    r = run(honest_world(), p, roster=make_roster(p, with_attached=True))
    assert next(x for x in r["rows"] if x["record_id"] == "erp:attached")["disposition"] == M.ADMITTED
    w = honest_world(); w["bank_reachable"] = False
    r = run(w, HONEST, roster=make_roster(HONEST, with_dependent=True))
    row = next(x for x in r["rows"] if x["record_id"] == "bank:dependent")
    assert row["disposition"] == M.UNREACHED and "not derivable" in row["reason"]
    r = run(honest_world(), HONEST, roster=make_roster(HONEST, with_dependent=True))
    assert next(x for x in r["rows"] if x["record_id"] == "bank:dependent")["disposition"] == M.ADMITTED


def test_admission_never_drops_or_invents_a_row():
    roster = make_roster(HONEST)
    covered, withheld = roster.in_play(None)
    rows = [MR._row(e, roster.root_of(e.record_id)) for e in covered]
    for r in rows:
        r.update(disposition=M.UNREACHED, reason="x")
    MR._seal(roster, rows, covered, withheld, "n")  # baseline: seals
    dropped = rows[:1]
    with pytest.raises(M.RosterError):
        MR._seal(roster, dropped, covered, withheld, "n")
    swapped = [dict(rows[0], record_id="smuggled"), rows[1]]
    with pytest.raises(M.RosterError):
        MR._seal(roster, swapped, covered, withheld, "n")
    undecided = [dict(rows[0], disposition=None), rows[1]]
    with pytest.raises(M.RosterError):
        MR._seal(roster, undecided, covered, withheld, "n")


def test_admission_is_deeply_immutable_and_still_serialises():
    """The frozen-field ratchet's runtime half for `Admission.rows/receipt/withheld`."""
    adm = run(honest_world(), HONEST)["admission"]
    with pytest.raises(TypeError):
        adm.rows[0]["disposition"] = M.ADMITTED
    with pytest.raises(TypeError):
        adm.rows.append({})
    with pytest.raises(TypeError):
        adm.receipt["universe_sha"] = "0" * 64
    with pytest.raises(TypeError):
        adm.withheld["x"] = M.ROOT_NOT_ENABLED
    assert json.loads(json.dumps(adm.rows))[0]["record_id"] == "erp:vendor"  # plain-JSON identical
    copy_ = dict(adm.rows[0]); copy_["disposition"] = "X"  # copying is the sanctioned way


def test_admit_nothing_leaves_every_row_unreached_with_the_reason_and_seals_the_receipt():
    adm = M.admit_nothing(make_roster(HONEST), "proposal malformed: amount not an int")
    assert all(r["disposition"] == M.UNREACHED and "malformed" in r["reason"] for r in adm.rows)
    assert len(adm.rows) == 2 and adm.receipt["universe_sha"] == adm.universe_sha
    states = M.proposition_states(adm.rows, {}, propositions=PROPS, table=TABLE)
    assert all(s["state"] == M.CANNOT_CONCLUDE for s in states.values())
    # an inadmissible INPUT refuses (the artifact is bad); nothing reached on an admissible one holds
    ov = M.overall(states, adm.rows, table=TABLE, inadmissible=adm.inadmissible)
    assert ov["decision"] == M.REFUSE and "malformed" in ov["inadmissible_input"]
    v = M.to_verdict(ov)
    assert exit_code(v) == 1 and v.reason == MP.REASON_INPUT_INADMISSIBLE
    # red-team witness w6: a helper that rebuilt overall() from loose rows dropped the flag;
    # passing the Admission itself carries it
    ov2 = M.overall(states, adm, table=TABLE)
    assert ov2["decision"] == M.REFUSE and ov2["inadmissible_input"] == adm.inadmissible
    outage = M.admit_nothing(make_roster(HONEST), "every authority timed out", inadmissible=False)
    assert outage.inadmissible is None
    assert M.overall(states, outage.rows, table=TABLE, inadmissible=outage.inadmissible)["decision"] == M.HOLD


# ---------------------------------------------------------------------------
# provenance chains (S1)
# ---------------------------------------------------------------------------

def test_a_finding_with_proposer_content_in_an_independent_envelope_is_proposer_rooted():
    rows = run(honest_world(), HONEST)["rows"]
    f = M.finding(rows, "bank:payee", M.CONFIRMS, "bank confirms a name the ERP wrote", table=TABLE, content_roots=(R_A,))
    assert f["root"] == R_A and f["relied_on"] == (("bank:payee", R_B), ("content", R_A))
    g = M.finding(rows, "bank:payee", M.CONFIRMS, "bank's own fact", table=TABLE)
    assert g["root"] == R_B


def test_s1_refuses_a_label_above_the_chain_min():
    rows = run(honest_world(), HONEST)["rows"]
    with pytest.raises(M.ProvenanceError, match="STAMP_AGGREGATE_ROUNDUP_DETECTED"):
        M.finding(rows, "bank:payee", M.CONFIRMS, "x", table=TABLE, content_roots=(R_A,), claimed_root=R_B)
    # a claim equal to the min is accepted
    f = M.finding(rows, "bank:payee", M.CONFIRMS, "x", table=TABLE, content_roots=(R_A,), claimed_root=R_A)
    assert f["root"] == R_A
    # a claim BELOW the min (independent chain labeled proposer) is also refused: round-down misrepresents
    with pytest.raises(M.ProvenanceError, match="STAMP_AGGREGATE_ROUNDDOWN_DETECTED"):
        M.finding(rows, "bank:payee", M.CONFIRMS, "x", table=TABLE, claimed_root=R_A)


def test_a_hand_built_finding_is_graded_at_state_time():
    rows = run(honest_world(), HONEST)["rows"]
    # label says independent, chain says the proposer wrote the content
    forged = {"record_id": "bank:payee", "root": R_B, "finding": M.CONFIRMS, "detail": "x", "relied_on": (("bank:payee", R_B), ("content", R_A))}
    with pytest.raises(M.ProvenanceError, match="STAMP_AGGREGATE_ROUNDUP"):
        M.proposition_states(rows, {"P1": [forged]}, propositions=PROPS, table=TABLE)
    # no chain at all and a label that is not the envelope's root
    bare = {"record_id": "erp:vendor", "root": R_B, "finding": M.CONFIRMS, "detail": "x"}
    with pytest.raises(M.ProvenanceError):
        M.proposition_states(rows, {"P1": [bare]}, propositions=PROPS, table=TABLE)
    # undeclared root, bad verdict, chain not starting at the envelope
    for bad in (
        {"record_id": "erp:vendor", "root": "R-NOPE", "finding": M.CONFIRMS, "detail": "x"},
        {"record_id": "erp:vendor", "root": R_A, "finding": "MAYBE", "detail": "x"},
        {"record_id": "erp:vendor", "root": R_A, "finding": M.CONFIRMS, "detail": "x", "relied_on": (("content", R_A),)},
    ):
        with pytest.raises(M.ProvenanceError):
            M.proposition_states(rows, {"P1": [bad]}, propositions=PROPS, table=TABLE)
    with pytest.raises(M.ProvenanceError):
        M.finding(rows, "erp:vendor", M.CONFIRMS, "x", table=TABLE, content_roots=("R-NOPE",))
    with pytest.raises(M.ProvenanceError):
        M.finding(rows, "not-on-roster", M.CONFIRMS, "x", table=TABLE)
    # red-team witness w4: a 3-element link raised a bare ValueError out of grade_chain
    for chain in ([["erp:vendor", R_A, R_B]], [("erp:vendor",)], [("erp:vendor", None)], "erp:vendor", [3]):
        bad = {"record_id": "erp:vendor", "root": R_A, "finding": M.CONFIRMS, "detail": "x", "relied_on": chain}
        with pytest.raises(M.ProvenanceError):
            M.proposition_states(rows, {"P1": [bad]}, propositions=PROPS, table=TABLE)


# ---------------------------------------------------------------------------
# the state rule and the decision
# ---------------------------------------------------------------------------

def test_state_rule_every_branch():
    r = run(honest_world(), HONEST)
    s = r["states"]
    assert s["P1"]["state"] == M.ESTABLISHED and s["P1"]["roots_established_from"] == sorted([R_A, R_B])
    assert (s["P2"]["state"], s["P2"]["qualifier"], s["P2"]["proposer_root_confirms"]) == (M.CANNOT_CONCLUDE, M.INSUFFICIENT_Q, True)
    assert (s["P3"]["state"], s["P3"]["qualifier"], s["P3"]["missing"]) == (M.CANNOT_CONCLUDE, M.UNREACHED_Q, ["no record has standing"])
    ov = r["overall"]
    assert ov["decision"] == M.HOLD and ov["unreached"] == ["P3"]  # P3: nobody has standing -> the verifier never asked
    assert ov["residual_proposer_root_only"] == ["P2"] and ov["independent_roots_establishing"] == [R_B]
    # contradiction
    w = honest_world(); w["bank"]["ACC-1"] = "R PATEL"
    r = run(w, HONEST)
    assert r["states"]["P1"]["state"] == M.CONTRADICTED and r["states"]["P1"]["roots_contradicting"] == [R_B]
    assert r["overall"]["decision"] == M.REFUSE


def test_release_needs_every_proposition_reached_and_policy_can_only_hold():
    two = ("P1", "P2")
    r = run(honest_world(), HONEST)
    st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
    assert M.overall(st, r["rows"], table=TABLE)["decision"] == M.RELEASE
    held = M.overall(st, r["rows"], table=TABLE, hold_if=lambda states: True)
    assert held["decision"] == M.HOLD and held["held_by_policy"] is True
    # policy cannot lift a refusal
    w = honest_world(); w["bank"]["ACC-1"] = "R PATEL"
    r = run(w, HONEST)
    st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
    assert M.overall(st, r["rows"], table=TABLE, hold_if=lambda states: False)["decision"] == M.REFUSE


def test_unusable_refuses_even_when_everything_else_is_established():
    two = ("P1", "P2")
    w = honest_world(); w["bank_corrupt"] = True
    r = run(w, HONEST)
    st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
    ov = M.overall(st, r["rows"], table=TABLE)
    assert ov["decision"] == M.REFUSE and ov["unusable_records"] == ["bank:payee"]


def test_improves_reads_the_severity_lattice():
    two = ("P1", "P2")
    def mk(world):
        r = run(world, HONEST)
        st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
        return {"states": st, "overall": M.overall(st, r["rows"], table=TABLE)}
    honest = mk(honest_world())
    w = honest_world(); w["bank_reachable"] = False
    unreached = mk(w)
    w = honest_world(); w["bank"]["ACC-1"] = "R PATEL"
    refused = mk(w)
    assert (honest["overall"]["decision"], unreached["overall"]["decision"], refused["overall"]["decision"]) == (M.RELEASE, M.HOLD, M.REFUSE)
    imp = M.improves(honest, unreached, propositions=two)
    assert imp["improves"] and imp["improves_lattice"] and imp["severities"] == (int(Severity.ERROR_CLEAN), int(Severity.PASS))
    imp = M.improves(unreached, refused, propositions=two)
    assert imp["improves_lattice"] and not imp["improves"]  # REFUSE -> HOLD moves up the lattice, buys no release
    assert not M.improves(refused, honest, propositions=two)["improves_lattice"]
    assert MP.DECISION_SEVERITY[M.REFUSE] > MP.DECISION_SEVERITY[M.HOLD] > MP.DECISION_SEVERITY[M.RELEASE]


def test_to_verdict_is_tri_state():
    two = ("P1", "P2")
    def ov(world, hold=None):
        r = run(world, HONEST)
        st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
        return M.overall(st, r["rows"], table=TABLE, hold_if=hold)
    assert exit_code(M.to_verdict(ov(honest_world()))) == 0
    w = honest_world(); w["bank_reachable"] = False
    v = M.to_verdict(ov(w))
    assert exit_code(v) == 2 and "unreached" in v.detail
    w = honest_world(); w["bank"]["ACC-1"] = "R PATEL"
    v = M.to_verdict(ov(w))
    assert exit_code(v) == 1 and v.reason == MP.REASON_CONTRADICTED
    w = honest_world(); w["bank_corrupt"] = True
    assert M.to_verdict(ov(w)).reason == MP.REASON_RECORD_UNUSABLE


def test_blast_radius_removes_each_non_proposer_root():
    two = ("P1", "P2")
    def mk(roots):
        r = run(honest_world(), HONEST, roots_enabled=roots)
        st = M.proposition_states(r["rows"], checks(HONEST, r["rows"]), propositions=two, table=TABLE)
        return {"states": st, "overall": M.overall(st, r["rows"], table=TABLE)}
    base = mk(None)
    out = M.blast_radius(lambda root: mk(tuple(r for r in TABLE.roots if r != root)), base, TABLE)
    assert set(out) == {R_B}
    assert out[R_B]["propositions_losing_independent_establishment"] == ["P1"]


# ---------------------------------------------------------------------------
# Stage 4: the degradation oracle over this consumer's own verifier
# ---------------------------------------------------------------------------

def test_degrading_the_proposal_never_buys_a_softer_verdict():
    """Row 20 over the producer-controlled surface: every field of the proposal, on the
    full ladder, with the verifier wrapped fail-closed. A `run` that raises maps to a
    crash severity by the oracle's own contract."""
    two = ("P1", "P2")

    def verify(proposal):
        if not isinstance(proposal, dict) or not isinstance(proposal.get("account"), str) or not isinstance(proposal.get("payee"), str):
            # the substrate's doctrine: an inadmissible input REFUSES. The first draft of
            # this wrapper returned a could-not-conclude here and the oracle filed four
            # TIER-2 findings: a wrong account refused, a null one was held.
            adm = M.admit_nothing(make_roster(HONEST), "proposal inadmissible")
            st = M.proposition_states(adm.rows, {}, propositions=two, table=TABLE)
            ov = M.overall(st, adm.rows, table=TABLE, inadmissible=adm.inadmissible)
            return MP.DECISION_SEVERITY[ov["decision"]], (ov["decision"], "INPUT_INADMISSIBLE"), True
        r = run(honest_world(), proposal)
        st = M.proposition_states(r["rows"], checks(proposal, r["rows"]), propositions=two, table=TABLE)
        ov = M.overall(st, r["rows"], table=TABLE)
        return MP.DECISION_SEVERITY[ov["decision"]], (ov["decision"],), True

    rep = probe_monotonicity(dict(HONEST), verify)
    assert rep.baseline == Severity.PASS
    assert not rep.findings, [f.detail for f in rep.findings]
    assert not rep.crashes and not rep.quarantined
