"""The helper contract (exception_escape/SPEC.md, layer 1): every shared helper that reads
producer-controlled input raises ONLY its documented error family, on ANY input.

Why a register and not a per-site fix: a 2026-09-21 census found 38 call sites catching
`ValueError` around the ISO parsers while the parsers raised `OverflowError` at either end
of `datetime`'s range, and 51 sites with no handler at all. One such value inside an
authority-signed record crashed a whole join run (exit 1 = REFUSE by the CLI contract,
stale `verdict.json`). Once the contract holds, every narrow catch is correct as written;
this file is what makes it hold. It is TOTAL over the bytes→value helper layer the
substrate-work register names (`iso8601`, `strict_json`, `digest`, `_containment`,
`admission`, and the three canon helpers `audit_bundle` exports): a public callable in one
of those modules that is not registered here fails `test_every_public_helper_is_registered`
— a new helper joins with a family and a battery, or does not join.

Documented-but-caller-owned raises (a `TypeError` for a non-bytes argument to a bytes
parser) are the CALLER's contract, not the producer's, and are tested where the module's
own tests test them; the batteries here feed each helper the argument TYPES its
documentation admits and every hostile VALUE we could think of. A hostile-input battery
hangs before it fails, so every call runs under a per-item alarm (§6 of substrate-work).
"""

from __future__ import annotations

import inspect
import json
import math
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit_bundle  # noqa: E402
from audit_bundle import _containment, admission, digest, iso8601, strict_json  # noqa: E402
from audit_bundle import _total_binding as TB  # noqa: E402
from audit_bundle._total_binding import TotalBindingError  # noqa: E402

PER_ITEM_SECONDS = 5


class _Hung(Exception):
    pass


def _safe_repr(x) -> str:
    try:
        return repr(x)[:80]
    except Exception:  # noqa: BLE001 — the battery's own scaffolding must not raise either
        return f"<{type(x).__name__} whose repr raised>"


def _call_bounded(fn: Callable, *args):
    """Run fn(*args) under an alarm: a hang is a FAIL with a name, not a dead suite."""

    def _alarm(signum, frame):  # pragma: no cover — only on a hang
        raise _Hung(f"{fn.__name__} did not return within {PER_ITEM_SECONDS}s")

    old = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, PER_ITEM_SECONDS)
    try:
        return fn(*args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


# ---------------------------------------------------------------------------
# hostile batteries — every value here is something a producer can put in a record
# ---------------------------------------------------------------------------

_DEEP = 100_000
ISO_STRINGS = [
    "0001-01-01T00:00:00+01:00",  # the F1 crash: OverflowError out of astimezone
    "9999-12-31T23:59:59-01:00",
    "0001-01-01T00:00:00+23:59",
    "9999-12-31T23:59:59.999999-23:59",
    "0001-01-01T00:00:00Z",
    "9999-12-31T23:59:59.999999Z",
    "2026-02-30T00:00:00Z",
    "2026-01-01T00:00:00+99:99",
    "2026-01-01T00:00:00+24:00",
    "2026-01-01T24:00:00Z",
    "2026-01-01T00:00:60Z",
    "2026-01-01T00:00:00",
    "2026-01-01",
    "2026-01-01T00:00:00z",
    "2026-01-01T00:00:00+00:00:00",
    "20260101T000000Z",
    "2026-W01-1T00:00:00Z",
    "+002026-01-01T00:00:00Z",
    "-0001-01-01T00:00:00Z",
    "2026-01-01T00:00:00.1234567890123Z",
    "2026-01-01T00:00:00Z\x00",
    "２０２６-01-01T00:00:00Z",  # fullwidth digits
    "2026-01-01T00:00:00Z ",
    " 2026-01-01T00:00:00Z",
    "",
    "Z",
    "T",
    "x" * 10**6,
    "9" * 10**5 + "-01-01T00:00:00Z",
    "\ud800",  # lone surrogate
    "2026-01-01T00:00:00Z",  # honest
]
ISO_NON_STRINGS = [
    None,
    5,
    5.5,
    True,
    b"2026-01-01T00:00:00Z",
    bytearray(b"x"),
    [],
    {},
    object(),
    10**100,
    float("nan"),
]

JSON_BYTES = [
    b"[" * _DEEP + b"]" * _DEEP,  # the RecursionError
    b'{"a":' * _DEEP + b"1" + b"}" * _DEEP,
    b"[" * _DEEP,  # unterminated AND deep
    b"1" + b"0" * 5000,
    b"-" + b"1" * 5000,
    b"1e999999",
    b"-1e999999",
    b"1" + b"0" * 400,  # a long int under the digit cap: allowed to parse
    b"NaN",
    b"[Infinity, -Infinity]",
    b'{"a":1,"a":2}',
    b'{"a":{"b":1,"b":2}}',
    b"\xff\xfe",
    b"\xef\xbb\xbf{}",  # BOM
    b"",
    b"{",
    b"]",
    b"\x00",
    b'"' + b"a" * 10**6 + b'"',
    b'"\\ud800"',  # lone surrogate escape
    b'"\\u0000"',
    b'{"": 1}',
    b'{"\\u0000": 1}',
    b"[1] [2]",
    b"true false",
    b"01",
    b"1.",
    b".1",
    b"1_000",
    b"0x10",
    "[" * _DEEP + "]" * _DEEP,  # str form
    '{"a": 1}',
    b'{"a": 1}',
]

REL_PATHS = [
    "../x",
    "..",
    ".",
    "",
    "/etc/passwd",
    "a/../../b",
    "a\x00b",
    "\ud800",
    "x" * 10_000,
    "x/" * 5_000,
    "\\..\\x",
    "a\nb",
    "manifest.json",
    "a/./b",
    "~",
    "$HOME",
    "%2e%2e/x",
]


def _hostile_objects():
    deep_list: list = []
    cur = deep_list
    for _ in range(_DEEP):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    cyc: list = []
    cyc.append(cyc)

    class Loud(dict):
        def items(self):
            raise RuntimeError("no items for you")

    class Weird:
        def __repr__(self):
            raise RuntimeError("no repr")

    return [
        deep_list,
        cyc,
        {"a": float("nan")},
        {"a": float("inf")},
        {"a": 10**700},
        {"a": b"bytes"},
        {"a": {1, 2}},
        {"a": object()},
        {"a": Weird()},
        Loud(a=1),
        {1: "int key"},
        {(1, 2): "tuple key"},
        {"a": "x" * 10**6},
        [None] * 10**5,
        {"a": 1, "b": {"c": [1, 2, {"d": None}]}},  # honest
    ]


# ---------------------------------------------------------------------------
# the register
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    fn: Callable
    family: tuple  # exception classes the helper may raise on a producer-controlled value; () = never raises
    battery: Callable  # () -> list of argument tuples
    note: str = ""


def _iso_args():
    return [(v,) for v in ISO_STRINGS] + [(v,) for v in ISO_NON_STRINGS]


def _json_args():
    return [(v,) for v in JSON_BYTES]


def _json_and_types_args():
    return _json_args() + [
        (v,) for v in ISO_NON_STRINGS if not isinstance(v, (bytes, bytearray))
    ]


def _bytes_args():
    return [(v,) for v in JSON_BYTES if isinstance(v, bytes)]


def _obj_args():
    return [(v,) for v in _hostile_objects()]


def _path_args(tmp: Path):
    d = tmp / "dir"
    d.mkdir(exist_ok=True)
    (tmp / "deep.json").write_bytes(b"[" * _DEEP + b"]" * _DEEP)
    (tmp / "dup.json").write_bytes(b'{"a":1,"a":2}')
    (tmp / "bad.json").write_bytes(b"\xff")
    (tmp / "ok.json").write_bytes(b'{"a": 1}')
    (tmp / "ok.jsonl").write_bytes(b'{"a": 1}\n\n{"b": 2}\n')
    (tmp / "deep.jsonl").write_bytes(b"[" * _DEEP + b"]" * _DEEP + b"\n")
    return [
        (tmp / "absent.json",),
        (d,),
        (Path(str(tmp) + "/a\x00b"),),
        (tmp / "deep.json",),
        (tmp / "dup.json",),
        (tmp / "bad.json",),
        (tmp / "ok.json",),
        (tmp / "ok.jsonl",),
        (tmp / "deep.jsonl",),
        (Path("\ud800"),),
    ]


def _rel_args(tmp: Path):
    (tmp / "manifest.json").write_bytes(b"{}")
    # the root is the operator's (`--bundle`) but an unrepresentable one is still a refusal
    # (red team 2026-09-22: `root.resolve()` sat outside the try)
    roots = [tmp, Path("a\x00b"), Path("\ud800"), Path("x" * 10_000), tmp / "absent"]
    return [(tmp, rel) for rel in REL_PATHS] + [(root, "manifest.json") for root in roots]


def _mapping_args():
    class Loud(dict):
        def keys(self):
            raise RuntimeError("no keys")

    return [
        ({"a": 1}, ("a",)),
        ({"a": 1}, ("b",)),
        ({}, ("a",)),
        ({"a": 1, "b": 2}, ("a",)),
        (5, ("a",)),
        (None, ("a",)),
        ({"a": 1}, None),
        ({"a": 1}, 5),
        ({i: i for i in range(10_000)}, tuple(range(10_000))),
        ({"a": 1}, ("a", "a")),
        ([("a", 1)], ("a",)),
        ({("t",): 1}, (("t",),)),
        (Loud(a=1), ("a",)),
    ]


def _partition_args():
    return [
        ([1, 2, 3], [[1], [2, 3]]),
        ([1, 2, 3], [[1], [2]]),
        ([1, 2], [[1], [1, 2]]),
        ([], []),
        ([1], [[1], []]),
        (5, [[5]]),
        ([1, 2], 5),
        ([1, 2], [5]),
        (list(range(10_000)), [list(range(10_000))]),
        ([{"a": 1}], [[{"a": 1}]]),
        ([1, 1], [[1, 1]]),
    ]


def _bijection_args():
    return [
        ([1, 2], [2, 1]),
        ([1, 2], [1]),
        ([1, 1], [1, 2]),
        ([], []),
        (5, [5]),
        ([1], 5),
        (None, None),
        ([{"a": 1}], [{"a": 1}]),
        (list(range(10_000)), list(range(10_000))),
        ([1, 2], [1, 2, 2]),
    ]


def _bijection_projected_args():
    return [(a, b, lambda x: x) for a, b in _bijection_args()] + [
        ([{"id": 1}], [{"id": 1}], lambda r: r["id"]),
        ([{"id": 1}], [{"no": 1}], lambda r: r["id"]),  # the key raises KeyError: the CONSUMER's key, its raise
    ]


REGISTER: dict = {
    "audit_bundle.iso8601.parse_iso8601_utc": Row(
        iso8601.parse_iso8601_utc, (ValueError,), _iso_args
    ),
    "audit_bundle.iso8601.parse_iso8601_utc_ms": Row(
        iso8601.parse_iso8601_utc_ms, (ValueError,), _iso_args
    ),
    "audit_bundle.strict_json.strict_json_loads": Row(
        strict_json.strict_json_loads,
        (ValueError,),
        _json_args,
        "bytes/str only; TypeError on other types is the caller's (own tests)",
    ),
    "audit_bundle.strict_loads": Row(
        audit_bundle.strict_loads, (TotalBindingError,), _json_and_types_args
    ),
    "audit_bundle.canon_bytes": Row(
        audit_bundle.canon_bytes, (TotalBindingError,), _obj_args
    ),
    "audit_bundle.value_digest": Row(
        audit_bundle.value_digest, (TotalBindingError,), _obj_args
    ),
    "audit_bundle.digest.sha256_bytes": Row(
        digest.sha256_bytes, (), _bytes_args, "never raises on bytes"
    ),
    "audit_bundle.digest.sha256_file": Row(
        digest.sha256_file,
        (OSError, ValueError),
        _path_args,
        "absence/unreadable -> OSError; an unrepresentable path -> ValueError (Path.open's)",
    ),
    "audit_bundle._containment.contain": Row(
        _containment.contain, (_containment.ContainmentError,), _rel_args
    ),
    "audit_bundle.admission.admit_bytes": Row(
        admission.admit_bytes,
        (),
        _json_and_types_args,
        "returns a Verdict or None; never raises",
    ),
    "audit_bundle.admission.admit_obj": Row(
        admission.admit_obj, (), _obj_args, "returns a Verdict or None; never raises"
    ),
    "audit_bundle.admission.admit_json_file": Row(
        admission.admit_json_file, (admission.InputInadmissible,), _path_args
    ),
    "audit_bundle.admission.admit_jsonl_file": Row(
        admission.admit_jsonl_file, (admission.InputInadmissible,), _path_args
    ),
    # the set/partition helpers take COLLECTIONS the verifier built; a non-iterable ARGUMENT is the
    # caller's type error (documented here as such, like strict_json's TypeError), while every
    # hostile VALUE inside a collection is TotalBindingError — measured 2026-09-22 over the batteries
    "audit_bundle.assert_exact_keys": Row(TB.assert_exact_keys, (TotalBindingError, TypeError), _mapping_args, "the work-set invariant over producer-derived mappings (join.py about facets); TypeError = a non-iterable argument"),
    "audit_bundle.assert_partition": Row(TB.assert_partition, (TotalBindingError, TypeError), _partition_args, "TypeError = a non-iterable argument"),
    "audit_bundle.assert_bijection": Row(TB.assert_bijection, (TotalBindingError, TypeError), _bijection_args, "TypeError = a non-iterable argument"),
    "audit_bundle.assert_bijection_projected": Row(
        TB.assert_bijection_projected, (TotalBindingError, TypeError, KeyError), _bijection_projected_args, "TypeError = a non-iterable argument; a `key` that raises is the CONSUMER's raise, documented as passing through"
    ),
    "audit_bundle.admission.iter_admitted_jsonl_tolerant": Row(
        lambda p: list(admission.iter_admitted_jsonl_tolerant(p)),
        (admission.InputInadmissible,),
        _path_args,
        "a generator: drained here",
    ),
}

# The modules whose public callables MUST be registered (the substrate-work register's
# bytes→value row). `audit_bundle` itself: the three canon helpers it exports.
TOTAL_OVER = {
    "audit_bundle.iso8601": iso8601,
    "audit_bundle.strict_json": strict_json,
    "audit_bundle.digest": digest,
    "audit_bundle._containment": _containment,
    "audit_bundle.admission": admission,
}
EXPORTED_HELPERS = ("canon_bytes", "value_digest", "strict_loads")
# `_total_binding`'s set/partition helpers the substrate-work register names for producer-derived
# collections (the rest of that module — codec internals, to_plain, total_digest, closure — takes
# verifier-built values and is outside this register's scope; claims audit 2026-09-22)
TOTAL_BINDING_HELPERS = ("assert_exact_keys", "assert_partition", "assert_bijection", "assert_bijection_projected")


def _public_callables(mod) -> list:
    names = getattr(mod, "__all__", None)
    if names is None:
        names = [n for n in dir(mod) if not n.startswith("_")]
    out = []
    for n in names:
        obj = getattr(mod, n)
        if inspect.isfunction(obj) and obj.__module__ == mod.__name__:
            out.append(n)
    return out


def test_every_public_helper_is_registered():
    """Totality: a new bytes→value helper is a new row here, or the suite is red."""
    missing = []
    for modname, mod in TOTAL_OVER.items():
        for n in _public_callables(mod):
            if f"{modname}.{n}" not in REGISTER:
                missing.append(f"{modname}.{n}")
    for n in EXPORTED_HELPERS:
        assert f"audit_bundle.{n}" in REGISTER, n
        assert n in audit_bundle.__all__
    for n in TOTAL_BINDING_HELPERS:
        assert f"audit_bundle.{n}" in REGISTER, n
        assert callable(getattr(TB, n))
    assert missing == [], (
        f"public helpers with no documented error family + battery: {missing}"
    )


def _args_for(row: Row, tmp_path: Path) -> list:
    sig = inspect.signature(row.battery)
    return row.battery(tmp_path) if sig.parameters else row.battery()


@pytest.mark.parametrize("name", sorted(REGISTER))
def test_helper_raises_only_its_documented_family(name, tmp_path):
    row = REGISTER[name]
    escaped = []
    n = 0
    for args in _args_for(row, tmp_path):
        n += 1
        try:
            _call_bounded(row.fn, *args)
        except _Hung as exc:
            escaped.append(("HUNG", _safe_repr(args), str(exc)))
        except row.family:
            continue
        except BaseException as exc:  # noqa: BLE001 — the point of the test
            escaped.append((type(exc).__name__, _safe_repr(args), str(exc)[:120]))
    assert n >= 10, f"{name}: a battery of {n} is not a battery"
    assert escaped == [], (
        f"{name} raised outside its documented family {row.family}: {escaped}"
    )


def test_the_f1_value_is_a_value_error_not_an_overflow():
    """The witness that started this: a signed record's `valid_to`."""
    for v in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
        with pytest.raises(ValueError) as ei:
            iso8601.parse_iso8601_utc(v)
        assert not isinstance(ei.value, OverflowError)
        with pytest.raises(ValueError):
            iso8601.parse_iso8601_utc_ms(v)


def test_a_depth_bomb_is_a_strict_json_error_with_kind_too_deep_not_a_depth_policy():
    with pytest.raises(strict_json.StrictJSONError) as ei:
        strict_json.strict_json_loads(b"[" * _DEEP + b"]" * _DEEP)
    assert ei.value.kind == "too_deep" and isinstance(ei.value, ValueError)
    # the depth POLICY stays with admission: a document admit_bytes admits, the parser parses
    ok = b"[" * 50 + b"]" * 50
    assert (
        admission.admit_bytes(ok) is None
        and strict_json.strict_json_loads(ok) is not None
    )
    # and no cap was smuggled in: nesting well beyond admission's default max still PARSES here
    deeper = b"[" * 200 + b"]" * 200
    assert admission.admit_bytes(deeper) is not None  # admission refuses it…
    assert (
        strict_json.strict_json_loads(deeper) is not None
    )  # …the parser does not: no policy of its own


def test_a_number_that_overflows_float_is_refused_not_returned_as_infinity():
    """Red team 2026-09-22 (measured): `1e999999` PARSED to `inf` — the family held (no raise)
    while the value contract ("non-finite refused") did not; the register reads exceptions,
    not values, so its own battery carried the witness and scored it `ok`."""
    for raw in (b"1e999999", b"-1e999999", b'{"a": [1e400]}'):
        with pytest.raises(strict_json.StrictJSONError) as ei:
            strict_json.strict_json_loads(raw)
        assert ei.value.kind == "non_finite"
    assert strict_json.strict_json_loads(b"1e308") == 1e308  # the largest finite double still parses
    assert strict_json.strict_json_loads(b"2.5") == 2.5


def test_the_json_battery_still_accepts_honest_input_and_refuses_the_named_kinds():
    """Positive arm (§6): the conversion did not make the parser refuse more than before."""
    assert strict_json.strict_json_loads(b'{"a": 1}') == {"a": 1}
    assert strict_json.strict_json_loads(b"1" + b"0" * 400) == 10**400
    with pytest.raises(json.JSONDecodeError):
        strict_json.strict_json_loads(b"{")
    kinds = set()
    for raw in (
        b'{"a":1,"a":2}',
        b"NaN",
        b"1" + b"0" * 5000,
        b"[" * _DEEP + b"]" * _DEEP,
    ):
        with pytest.raises(strict_json.StrictJSONError) as ei:
            strict_json.strict_json_loads(raw)
        kinds.add(ei.value.kind)
    assert kinds == {"duplicate_key", "non_finite", "int_too_long", "too_deep"}
    assert math.isnan(
        float("nan")
    )  # keep math imported for readers extending the battery


def test_the_iso_parsers_still_accept_honest_input():
    d = iso8601.parse_iso8601_utc("2026-01-01T09:00:00+09:00")
    assert (d.hour, d.utcoffset().total_seconds()) == (0, 0)
    assert iso8601.parse_iso8601_utc_ms("1970-01-01T00:00:01Z") == 1000
    # an extreme that IS representable stays accepted (no range policy smuggled in)
    assert iso8601.parse_iso8601_utc("0001-01-01T00:00:00Z").year == 1
    assert iso8601.parse_iso8601_utc("9999-12-31T23:59:59Z").year == 9999


def test_the_battery_has_the_witness_and_is_not_vacuous():
    """The battery names the value that crashed the join, and the ISO battery holds at least
    one honest value (a battery every item of which refuses proves refusal, not the family)."""
    assert "0001-01-01T00:00:00+01:00" in ISO_STRINGS
    assert any(
        iso8601.parse_iso8601_utc(v) for v in ISO_STRINGS if v == "2026-01-01T00:00:00Z"
    )
    assert os.name != "nt" or pytest.skip("signal.setitimer is POSIX")
