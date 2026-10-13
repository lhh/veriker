"""tests/test_claimset_opaque_properties.py — hypothesis properties for the
opaque claim declaration (port 2b). Kept in their own module so a missing
optional dependency skips ONLY these (the negative controls live in
test_claimset_opaque.py and never skip).

The strategies straddle the classifier boundary on purpose: canonical JSON,
pretty JSON, JSON with a corruption applied, BOM/UTF-16 encodings, deep
wrapping, JSONL bodies, and random bytes — uniform random bytes alone are
~never JSON-shaped and would test one branch 199 times out of 200.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.claimset import (  # noqa: E402
    DECLARATION_ADMITS,
    ClaimBytesKind,
    ClaimsetError,
    classify_kind,
    enumerate_claim_universe,
    is_strict_json_value,
    stdlib_reads_as_json,
    validate_claimset_declaration,
)

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings, strategies as st  # noqa: E402


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _bundle(tmp: Path, raw: bytes) -> Path:
    b = tmp / "bundle"
    (b / "payload").mkdir(parents=True)
    (b / "payload" / "a.bin").write_bytes(raw)
    (b / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "legacy",
                "bundle_id": "prop",
                "created_at": "2026-01-01T00:00:00Z",
                "files": {"payload/a.bin": _sha(raw)},
                "spec_files": {},
                "cross_refs": {},
                "payload": {},
                "typed_checks": [],
                "per_output_manifests": [],
            }
        )
    )
    return b


_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=12),
)
_keys = st.text(min_size=1, max_size=6).filter(lambda k: not (set(k) & set(":.[]")))
_docs = st.recursive(
    _scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4), st.dictionaries(_keys, inner, max_size=4)
    ),
    max_leaves=12,
)
_containers = st.one_of(
    st.lists(_docs, max_size=4), st.dictionaries(_keys, _docs, max_size=4)
)


def _corrupt(raw: bytes, how: int) -> bytes:
    if how == 0:
        return raw[:-1]  # truncate
    if how == 1:
        return raw.rstrip(b"}]") + b"," + raw[len(raw.rstrip(b"}]")) :]  # trailing comma-ish
    if how == 2:
        return b"\xef\xbb\xbf" + raw  # BOM
    if how == 3:
        return raw.decode("utf-8").encode("utf-16")  # BOM-prefixed
    if how == 4:
        return b"[" * 70 + raw + b"]" * 70  # deep wrap
    if how == 5:
        return raw.decode("utf-8").encode("utf-16-be")  # BOM-less
    if how == 6:
        return raw.decode("utf-8").encode("utf-32-le")  # BOM-less
    if how == 7:
        return b" " + raw.decode("utf-8").encode("utf-16-le")  # ws then BOM-less
    return b"// c\n" + raw


def _encode_line(line: str, how: int) -> bytes:
    """One line, alone in its own encoding: the per-LINE axis the whole-body
    `_corrupt` never produces (v0.2.1 admitted these as opaque while
    `json.loads(line)` reads them)."""
    if how == 0:
        return b"\xef\xbb\xbf" + line.encode("utf-8")
    if how == 1:
        return line.encode("utf-16")
    if how == 2:
        return line.encode("utf-16-le")
    if how == 3:
        return line.encode("utf-32")
    if how == 4:
        # a lone surrogate inside a string: json.loads(bytes) decodes with
        # surrogatepass and reads it
        return line.replace('"', '"\ud800', 1).encode("utf-8", "surrogatepass")
    return line.encode("utf-8")


def _line_framing(doc_bytes: bytes, how: int) -> bytes:
    """A container on its own line, framed the way a LINE reader still reads
    it: whitespace outside JSON's four at the ends, an RFC 7464 RS, a BOM or
    a UTF-16 encoding on that line alone."""
    return [
        lambda b: b"\x0c" + b,
        lambda b: "\u00a0".encode() + b,
        lambda b: b"\x1e" + b,
        lambda b: b"\xef\xbb\xbf" + b,
        lambda b: b.decode("utf-8").encode("utf-16"),
    ][how](doc_bytes)


def _document_framing(doc_bytes: bytes, how: int) -> bytes:
    """A container inside a whole-file JSON-family document: concatenated
    values, a U+2028 between values, a JSONC comment header, an XSSI guard."""
    return [
        lambda b: b"1" + "\u2028".encode() + b,
        lambda b: b"0 " + b,
        lambda b: b"// header\n" + b,
        lambda b: b"/* h */ " + b,
        lambda b: b")]}',\n" + b,
    ][how](doc_bytes)


_SEP_TEXT = st.text(alphabet="ab\u2028\u2029\u0085\x0b\x0c", min_size=1, max_size=4)
_mixed_line_bodies = st.tuples(
    st.lists(st.one_of(_scalars, _containers, _SEP_TEXT), min_size=1, max_size=3),
    st.integers(min_value=0, max_value=5),
    st.integers(min_value=0, max_value=3),
    st.booleans(),
).map(
    lambda t: b"\n".join(
        # ensure_ascii=False: raw U+2028 / U+0085 / U+2029 inside strings
        _encode_line(json.dumps(d, ensure_ascii=False), t[1] if i == t[2] % len(t[0]) else 5)
        for i, d in enumerate(t[0])
    )
    + (b"\ngarbage\n" if t[3] else b"\n")
)

_near_boundary = st.one_of(
    _mixed_line_bodies,
    _docs.map(lambda d: json.dumps(d).encode("utf-8")),
    _docs.map(lambda d: json.dumps(d, indent=1, ensure_ascii=False).encode("utf-8")),
    st.tuples(_containers, st.integers(min_value=0, max_value=8)).map(
        lambda t: _corrupt(json.dumps(t[0]).encode("utf-8"), t[1])
    ),
    st.lists(_containers, min_size=1, max_size=4).map(
        lambda ds: b"".join(json.dumps(d).encode() + b"\n" for d in ds)
    ),
    st.text(alphabet='{}[]",:0123456789.-eEtrufalsn \n', max_size=24).map(str.encode),
    st.binary(max_size=64),
)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(raw=_near_boundary)
def test_property_classification_is_total_and_deterministic(raw):
    k1, _ = classify_kind(raw, "p")
    k2, _ = classify_kind(raw, "p")
    assert k1 is k2 and isinstance(k1, ClaimBytesKind)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(raw=_near_boundary)
def test_property_opaque_never_admits_what_the_stdlib_reader_reads(raw, tmp_path_factory):
    """THE load-bearing property, graded against the NAMED ORACLE —
    `json.loads` on BYTES (stdlib encoding auto-detection included), via
    `stdlib_reads_as_json` — never against the module's own classifier: if
    the stdlib reader reads the bytes as one value or as every line, an
    opaque declaration is refused. The same implication is then re-checked
    through enumeration: an admitted body enumerates as the one opaque
    element, a refused one raises."""
    kind, _ = classify_kind(raw, "p")
    if stdlib_reads_as_json(raw):
        assert kind not in DECLARATION_ADMITS["opaque_claim_files"], (kind, raw[:40])
    b = _bundle(tmp_path_factory.mktemp("prop"), raw)
    kw = dict(
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/a.bin": _sha(raw)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    if kind in DECLARATION_ADMITS["opaque_claim_files"]:
        assert not stdlib_reads_as_json(raw)
        assert enumerate_claim_universe(b, **kw)["elements"] == ["artifact"]
    else:
        with pytest.raises(ClaimsetError):
            enumerate_claim_universe(b, **kw)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(raw=_near_boundary)
def test_property_unadmitted_kinds_enumerate_under_no_declaration(raw, tmp_path_factory):
    kind, _ = classify_kind(raw, "p")
    admitted_somewhere = any(kind in row for row in DECLARATION_ADMITS.values())
    if admitted_somewhere:
        return
    b = _bundle(tmp_path_factory.mktemp("prop"), raw)
    pins = {"payload/a.bin": _sha(raw)}
    with pytest.raises(ClaimsetError):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={}, manifest_files=pins,
            opaque_claim_files={"artifact": "payload/a.bin"},
        )
    with pytest.raises(ClaimsetError):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={"artifact": "payload/a.bin"}, manifest_files=pins,
        )


_LINE_VALUES = ["1", "[1]", "{}", '"a"', '{"a":1}', "x", "", " ", "[]"]
_LINE_ENCODINGS = [
    "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be",
]
_BODY_PREFIXES = [b"", b"", b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00"]


def _per_line_encoded_body(rng):
    """1-3 short lines, each in its own encoding (a NUL in front of some),
    joined by LF or CRLF, behind an optional BOM, with an optional tail: the
    shapes where json.loads's per-line encoding detection reads what a whole-
    body decode does not."""
    lines = [
        (rng.choice(["", "", "\x00"]) + rng.choice(_LINE_VALUES)).encode(
            rng.choice(_LINE_ENCODINGS), "surrogatepass"
        )
        for _ in range(rng.randint(1, 3))
    ]
    return (
        rng.choice(_BODY_PREFIXES)
        + rng.choice([b"\n", b"\r\n"]).join(lines)
        + rng.choice([b"", b"\n", b"x"])
    )


def test_k5_on_per_line_encodings_seeded():
    """K5 over 20,000 seeded bodies whose lines each carry their own
    encoding. The hypothesis strategies above reach this class only by
    chance; this generator found 65 K5 cases in 2053eddf4 (a one-line
    decoded text whose UTF-8 bytes json.loads reads as UTF-16-BE, V1 in the
    audit record) and must find none. Deterministic: a fixed seed."""
    import random

    rng = random.Random(7)
    read = hits = 0
    for _ in range(20_000):
        raw = _per_line_encoded_body(rng)
        if stdlib_reads_as_json(raw):
            read += 1
            if classify_kind(raw, "p")[0] is ClaimBytesKind.NOT_JSON_SHAPED:
                hits += 1
    assert read > 1_000  # the generator does reach what the oracle reads
    assert hits == 0


_nonempty_containers = st.one_of(
    st.lists(_docs, min_size=1, max_size=4), st.dictionaries(_keys, _docs, min_size=1, max_size=4)
)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    doc=_nonempty_containers,
    how=st.integers(min_value=0, max_value=4),
    garbage=st.booleans(),
    ascii_only=st.booleans(),
)
def test_property_a_framed_object_line_is_never_opaque(doc, how, garbage, ascii_only):
    """A non-empty object or array on its own line, under each of five line
    framings, is never admitted as one opaque element, with or without a
    line nothing reads beside it."""
    raw = _line_framing(json.dumps(doc, ensure_ascii=ascii_only).encode("utf-8"), how)
    # A UTF-16 line holding an LF BYTE (U+0A00-U+0AFF, or U+xx0A in LE) cannot
    # be cut out of a byte stream by any line reader: all of them split there.
    # A CR byte stays in: binary-mode iteration splits at LF only.
    assume(not (how == 4 and b"\n" in raw))
    if garbage:
        raw = b"not json at all\n" + raw + b"\n"
    kind, _ = classify_kind(raw, "p")
    assert kind not in DECLARATION_ADMITS["opaque_claim_files"], (kind, raw[:60])


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(doc=_nonempty_containers, how=st.integers(min_value=0, max_value=4))
def test_property_an_object_in_a_family_document_is_never_opaque(doc, how):
    """A non-empty object or array inside a whole-file JSON-family document,
    under each of five document framings, is never opaque."""
    raw = _document_framing(json.dumps(doc, ensure_ascii=False).encode("utf-8"), how)
    kind, _ = classify_kind(raw, "p")
    assert kind not in DECLARATION_ADMITS["opaque_claim_files"], (kind, raw[:60])


@settings(max_examples=300, deadline=None)
@given(raw=_near_boundary)
def test_property_scanner_agrees_with_json_loads_within_its_budget(raw):
    """The uncapped scanner vs the stdlib on the SAME bytes. Domain: bytes
    the stdlib detects as UTF-8 and that decode strictly (json.loads decodes
    with surrogatepass and auto-detects UTF-16/32; the scanner is strict
    UTF-8 by design, and other bodies are the oracle's job in
    stdlib_reads_as_json), integers of any length on both sides, and texts
    json finishes within its recursion budget (these generators nest about
    70 levels at most, far inside it; past the budget,
    `test_the_scanner_reads_as_json_past_its_budget`)."""
    if json.detect_encoding(raw) != "utf-8":
        return
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        json.loads(raw, parse_int=str)
        ref = True
    except RecursionError:
        return
    except ValueError:
        ref = False
    assert is_strict_json_value(raw) == ref, raw[:40]


def _json_loads_on_a_big_stack(text):
    """json's pure-Python decoder, run with a deep recursion limit on a thread
    with a 512 MiB stack: the stdlib grammar with no practical depth bound.
    (Its number pattern takes Unicode digits, so keep the inputs ASCII.)"""
    import threading

    from json import decoder, scanner

    dec = decoder.JSONDecoder(parse_int=str)
    dec.parse_string = decoder.py_scanstring
    dec.scan_once = scanner.py_make_scanner(dec)
    out = {}

    def run():
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(200_000)
        try:
            dec.decode(text)
            out["reads"] = True
        except ValueError:
            out["reads"] = False
        finally:
            sys.setrecursionlimit(limit)

    size = threading.stack_size(512 * 1024 * 1024)
    try:
        t = threading.Thread(target=run)
        t.start()
        t.join()
    finally:
        threading.stack_size(size)
    return out["reads"]


@pytest.mark.parametrize(
    "text",
    [
        "[" * 20_000 + "1" + "]" * 20_000,
        "[" * 20_000 + "1" + "]" * 19_999,
        '{"a":' * 15_000 + "null" + "}" * 15_000,
        '{"a":' * 15_000 + "null" + "}" * 15_000 + " x",
        "[" * 12_000 + '"]]]"' + "]" * 12_000,
        "[" * 12_000 + "1," * 3 + "]" * 12_000,
    ],
    ids=["array", "array-unclosed", "object", "object-extra", "string-of-closers", "trailing-comma"],
)
def test_the_scanner_reads_as_json_past_its_budget(text):
    """Past json's recursion budget the oracle's answer is the uncapped
    scanner's: held here against json's own grammar with the budget out of
    the way (its pure-Python decoder on a deep stack)."""
    assert is_strict_json_value(text.encode()) == _json_loads_on_a_big_stack(text)


_TRIVIA = st.sampled_from(
    ["", " ", "\n", "\x0c", "\u00a0", "\u2028", "\ufeff", "\t",
     "/* c */", '/* " [ */', "/* ] */", "// x\n", '// "\n', "// {\u2028"]
)
_FAMILY_SCALARS = st.sampled_from(
    ["1", "-2.5e3", "0", "true", "null", "NaN", "-Infinity", '"a"', '"/*"', '"//"',
     '"[x"', '"a\\"b"', '""', '"\u2028"', '"\\u005b"', "9" * 4400]
)
_FAMILY_KEYS = st.sampled_from(['"a"', '"/*"', '"]"', '""', '"k\\"}"'])


def _family_container(children):
    items = st.lists(st.tuples(_TRIVIA, children, _TRIVIA), max_size=3)
    pairs = st.lists(
        st.tuples(_TRIVIA, _FAMILY_KEYS, _TRIVIA, _TRIVIA, children, _TRIVIA), max_size=3
    )
    return st.one_of(
        st.tuples(items, st.booleans(), _TRIVIA).map(
            lambda t: "["
            + ",".join(a + v + b for a, v, b in t[0])
            + ("," if t[1] and t[0] else "")
            + t[2]
            + "]"
        ),
        st.tuples(pairs, st.booleans(), _TRIVIA).map(
            lambda t: "{"
            + ",".join(a + k + b + ":" + c + v + d for a, k, b, c, v, d in t[0])
            + ("," if t[1] and t[0] else "")
            + t[2]
            + "}"
        ),
    )


_family_values = st.recursive(_FAMILY_SCALARS, _family_container, max_leaves=12)
_family_documents = st.builds(
    lambda prefix, values, tail, cut: _cut(
        prefix + "".join(a + v for a, v in values) + tail, cut
    ),
    st.sampled_from(["", ")]}'\n", "for(;;);", "while (1);", "// h\n", "x "]),
    st.lists(st.tuples(_TRIVIA, _family_values), min_size=1, max_size=3),
    _TRIVIA,
    st.one_of(
        st.none(),
        st.tuples(st.integers(min_value=0), st.sampled_from(list('"\\/*,[]{}:x \x0c') + [""])),
    ),
)


def _cut(text, cut):
    """Insert one character at a position (or delete one, for "")."""
    if cut is None:
        return text
    i, ch = cut
    i %= len(text) + 1
    return text[:i] + ch + text[i + (0 if ch else 1):]


def _capped(text, **kw):
    from audit_bundle.claimset import _capped_scan

    return _capped_scan(text, **kw)


@settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_family_documents)
def test_property_the_document_reader_is_the_capped_family_scanner(text):
    """The document reader rewrites a JSON-family document as JSON
    (`_as_json`) and lets json's decoder read it, instead of running the
    Python scanner over 15 MiB. Its answer must be the capped family
    scanner's, which defines it: on documents with comments, Unicode
    whitespace, U+FEFF, trailing commas, quotes and brackets inside comments
    and strings, XSSI guards, and one character inserted or deleted."""
    from audit_bundle.claimset import _reads_as_a_document, _without_xssi_prefix

    ref = _capped(_without_xssi_prefix(text), family=True)
    assert _reads_as_a_document(text) == (ref.reads and ref.container), text[:200]


_TOKENS = list('[]{}":,1 ax\\-.eE\x0c') + ["true", "NaN", '"a"', '"]"', "\\u12", "1e5"]
_deep_texts = st.builds(
    lambda depth, opener, body, closers: opener * depth + body + closers,
    st.sampled_from([1, 60, 1022, 1023, 1024, 1025, 1500]),
    st.sampled_from(["[", '{"a":', '[{"a":', "[ "]),
    st.lists(st.sampled_from(_TOKENS), max_size=12).map("".join),
    st.text(alphabet="]}", max_size=1600),
)


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=st.one_of(_deep_texts, st.lists(st.sampled_from(_TOKENS), max_size=30).map("".join)))
def test_property_the_line_reader_is_the_capped_scanner(text):
    """A line's reader (`_read_text`: json's decoder, the nesting measured
    where json's answer and the scanner's could differ) answers exactly as
    the capped scanner: whether it reads, and whether it holds a member,
    including nesting on each side of the 1024-level cap."""
    from audit_bundle.claimset import _read_text

    ref = _capped(text)
    got = _read_text(text)
    assert (got is not None, bool(got and got.container)) == (
        ref.reads,
        ref.reads and ref.container,
    ), text[:80]


_decl_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8)),
    lambda inner: st.one_of(
        st.lists(inner, max_size=3), st.dictionaries(st.text(max_size=8), inner, max_size=3)
    ),
    max_leaves=10,
)
_decls = st.dictionaries(
    st.sampled_from(
        ["claim_files", "opaque_claim_files", "residuals", "extra", "", "claim_file"]
    ),
    _decl_values,
    max_size=4,
)


@settings(max_examples=300, deadline=None)
@given(decl=st.one_of(_decls, _decl_values))
def test_property_validation_never_crashes_only_refuses(decl):
    try:
        validate_claimset_declaration(decl)
    except ClaimsetError:
        pass
