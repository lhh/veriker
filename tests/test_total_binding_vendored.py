"""Normative conformance corpus for the vendored total-binding utility
(audit_bundle/_total_binding.py).

Self-contained: runs against the source tree AND against an installed wheel
(the publish workflow's wheel-conformance step runs it from a non-shadowing
cwd). The expected digests below are FROZEN LITERALS written at
corpus-authoring time with an independent computation (plain json+hashlib
over the hand-built envelope) — never regenerated from the codec under test;
a codec drift fails here even if the codec stays self-consistent.

This corpus is a hand-selected NORMATIVE subset, not a completeness witness:
it pins accepted digests, a rejection vector for every disallowed type and
bound, and metamorphic properties (key order irrelevant, list order
load-bearing).
"""

from __future__ import annotations

import dataclasses

import pytest

from audit_bundle import _total_binding as tb

# ---------------------------------------------------------------------------
# Accepted vectors — frozen independently-computed literals
# ---------------------------------------------------------------------------

_V1 = {"a": [1, 2.5, "x", True, None], "b": {"c": []}}


def test_frozen_canon_bytes():
    assert tb.canon_bytes(_V1) == b'{"a":[1,2.5,"x",true,null],"b":{"c":[]}}'


def test_frozen_value_digest():
    assert (
        tb.value_digest(_V1)
        == "b5fe4a7c83ef1a5ffc0afc1ed9866f6883887028b96ecd50d5827f2e2ac8600c"
    )


def test_frozen_total_digest_plain():
    assert (
        tb.total_digest(_V1, exclude=(), domain="conformance", schema=None)
        == "b77e2814ac4a278e98b437936df8388a622a2cd853ba305f7536153a954eb373"
    )


def test_frozen_total_digest_with_exclusion():
    obj = {
        "meta": {"u": "héllo"},
        "rows": [{"id": "r1", "v": 10}, {"id": "r2", "v": 20}],
    }
    got = tb.total_digest(
        obj,
        exclude=(((("rows"), tb.ANY, "v"), "volatile"),),
        domain="conformance",
        schema=None,
    )
    assert got == "4bc33be7b01f261b1820be7abb66348fc4e01b7bf12f0aaffaed3a46182aef54"


def test_frozen_total_digest_schema_vs_schemaless():
    @dataclasses.dataclass
    class _Root:
        amount: int

    tree, inv = tb.to_plain(_Root(5))
    assert tree == {"amount": 5}
    # pin the inventory to a stable id for the frozen vector (the runtime
    # qualname depends on the defining module; the ENCODING is what's pinned)
    d_schema = tb.total_digest(
        tree, exclude=(), domain="conformance", schema={(): "ledger.Debit"}
    )
    d_none = tb.total_digest(tree, exclude=(), domain="conformance", schema=None)
    assert (
        d_schema == "ab3a972f90d1e7ac37d42ea4cdb32faea7b634502d556a0a826cc962c00630b2"
    )
    assert d_none == "72e48de58b6274259a48bc8068a6c0355c57834cbd3980ef6206087016d443b5"
    assert d_schema != d_none  # a raw dict cannot impersonate a typed node


# ---------------------------------------------------------------------------
# Rejection vectors — one per disallowed type / bound
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        (1, 2),  # tuple (json would collide with [1,2])
        {1, 2},  # set
        {1: "x"},  # non-str key
        float("nan"),
        float("inf"),
        float("-inf"),
        object(),
        b"bytes",
        10**600,  # int magnitude bound
        -(10**600),
        "a" * (tb.MAX_STR_CODEPOINTS + 1),  # string bound
    ],
)
def test_rejection_vectors(bad):
    with pytest.raises(tb.TotalBindingError):
        tb.canon_bytes(bad)


def test_rejection_subclasses():
    class S(str):
        pass

    class IntSub(int):
        pass

    for bad in (S("x"), IntSub(3), {S("k"): 1}):
        with pytest.raises(tb.TotalBindingError):
            tb.canon_bytes(bad)


def test_rejection_cycle():
    a: list = []
    a.append(a)
    with pytest.raises(tb.TotalBindingError, match="cycle"):
        tb.canon_bytes(a)


def test_rejection_depth():
    obj: object = 1
    for _ in range(tb.MAX_DEPTH):
        obj = [obj]
    with pytest.raises(tb.TotalBindingError, match="depth"):
        tb.canon_bytes(obj)


def test_rejection_duplicate_keys_and_tokens_in_loader():
    with pytest.raises(tb.TotalBindingError, match="duplicate object key"):
        tb.strict_loads(b'{"a": 1, "a": 2}')
    with pytest.raises(tb.TotalBindingError, match="integer token"):
        tb.strict_loads(b"1" + b"0" * 600)
    with pytest.raises(tb.TotalBindingError):
        tb.strict_loads(b'{"a": NaN}')


def test_rejection_root_exclusion_and_stale_exclusion():
    with pytest.raises(tb.TotalBindingError, match="root"):
        tb.total_digest({"a": 1}, exclude=(((), "r"),), domain="c", schema=None)
    with pytest.raises(tb.TotalBindingError, match="matches nothing"):
        tb.total_digest({"a": 1}, exclude=((("gone",), "r"),), domain="c", schema=None)


# ---------------------------------------------------------------------------
# Metamorphic properties
# ---------------------------------------------------------------------------


def test_key_order_is_irrelevant():
    assert tb.canon_bytes({"a": 1, "b": 2}) == tb.canon_bytes({"b": 2, "a": 1})


def test_list_order_is_load_bearing():
    assert tb.canon_bytes([1, 2]) != tb.canon_bytes([2, 1])


def test_domain_separates():
    assert tb.total_digest(_V1, exclude=(), domain="x", schema=None) != tb.total_digest(
        _V1, exclude=(), domain="y", schema=None
    )


def test_exclusion_reason_is_load_bearing():
    a = tb.total_digest(_V1, exclude=((("a",), "r1"),), domain="c", schema=None)
    b = tb.total_digest(_V1, exclude=((("a",), "r2"),), domain="c", schema=None)
    assert a != b


def test_rejection_lone_surrogate():
    # fresh-audit A-F2: a lone surrogate must fail CLOSED with
    # TotalBindingError at validation — never accept-then-crash at encode
    with pytest.raises(tb.TotalBindingError, match="surrogate"):
        tb.canon_bytes("\ud800")
    with pytest.raises(tb.TotalBindingError, match="surrogate"):
        tb.strict_loads(b'"\\ud800"')
    with pytest.raises(tb.TotalBindingError, match="surrogate"):
        tb.canon_bytes({"\udfff": 1})


# ---------------------------------------------------------------------------
# Audit A-F4 (2026-07-18): predicate mutants declared on CONTAINER paths must
# actually execute (pre-fix they were validated then silently never ran —
# the rows=[]-grows-a-row exploit rode straight through a "covered" spec).
# ---------------------------------------------------------------------------


def test_audit_f4_empty_list_predicate_mutant_executes():
    fixture = {"rows": [], "meta": {"k": "vv"}}
    mutants = [{"value": [1], "expect": "reject", "reasons": ["ROWS_BAD"]}]
    inv = tb.pattern_inventory(
        fixture, ("rows",), {"class": "predicate", "mutants": mutants}
    )
    spec = {
        "accepting": ["PASS"],
        "expect_reasons": ["SHAPE_BAD", "ROWS_BAD"],
        "patterns": [
            {
                "path": ("rows",),
                "class": "predicate",
                "mutants": mutants,
                "inventory": inv,
            }
        ],
    }

    def mk_run(strict_rows):
        def run(obj):
            reasons = []
            if type(obj) is not dict or set(obj) != {"rows", "meta"}:
                reasons.append("SHAPE_BAD")
            elif set(obj["meta"]) != {"k"} or obj["meta"]["k"] != "vv":
                reasons.append("SHAPE_BAD")
            elif strict_rows and obj["rows"] != []:
                reasons.append("ROWS_BAD")
            return {"decision": "FAIL" if reasons else "PASS", "reasons": reasons}

        return run

    report = tb.probe_check(fixture, mk_run(True), spec=spec)
    assert report["ok"], report
    assert any(
        leg["kind"] == "predicate" and leg["path"] == [{"key": "rows"}]
        for leg in report["legs"]
    ), "container predicate mutant produced no leg — it never ran"

    report = tb.probe_check(fixture, mk_run(False), spec=spec)
    assert not report["ok"], "rows=[] grew a row unnoticed — the exploit"
    bad = [leg for leg in report["legs"] if not leg["ok"]]
    assert bad and all(leg["path"] == [{"key": "rows"}] for leg in bad), bad


# ---------------------------------------------------------------------------
# Completeness asserts — the cells the audit-bundle WORK-SET depends on
# (audit_bundle/work_set.py, 2026-09-01). A re-vendor propagates zero tests, so
# the behaviour a consumer leans on is pinned here, on the vendored copy.
# ---------------------------------------------------------------------------


def test_bijection_projected_is_multiset_aware():
    """[a, a] vs [a] fails — the duplicated-dispatch-row lesson. A dict
    projection would collapse this; the helper must not."""
    key = lambda x: x["id"]  # noqa: E731
    tb.assert_bijection_projected(
        [{"id": "a"}, {"id": "b"}], [{"id": "b"}, {"id": "a"}], key
    )
    with pytest.raises(tb.TotalBindingError, match="bijection failure"):
        tb.assert_bijection_projected([{"id": "a"}], [{"id": "a"}, {"id": "a"}], key)


def test_bijection_projected_missing_and_unexpected_both_fail():
    key = lambda x: x["id"]  # noqa: E731
    with pytest.raises(tb.TotalBindingError):
        tb.assert_bijection_projected([{"id": "a"}, {"id": "b"}], [{"id": "a"}], key)
    with pytest.raises(tb.TotalBindingError):
        tb.assert_bijection_projected([{"id": "a"}], [{"id": "a"}, {"id": "z"}], key)


def test_bijection_projected_key_is_the_only_identity():
    """The projection is the caller's judgment: two entries differing outside
    the key are the SAME element to this helper. Pinned so a consumer never
    mistakes it for a whole-value comparison."""
    key = lambda x: x["id"]  # noqa: E731
    tb.assert_bijection_projected(
        [{"id": "a", "type": "t1"}], [{"id": "a", "type": "t2"}], key
    )


def test_exact_keys_missing_and_unexpected_both_fail():
    tb.assert_exact_keys({"a": 1, "b": 2}, ["b", "a"])
    with pytest.raises(tb.TotalBindingError, match="missing \\['b'\\]"):
        tb.assert_exact_keys({"a": 1}, ["a", "b"])
    with pytest.raises(tb.TotalBindingError, match="unexpected \\['z'\\]"):
        tb.assert_exact_keys({"a": 1, "z": 0}, ["a"])
