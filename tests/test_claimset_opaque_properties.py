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
from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402


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


_near_boundary = st.one_of(
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
    """THE load-bearing property, graded against the NAMED EXTERNAL ORACLE —
    `json.loads` on BYTES (stdlib encoding auto-detection included), via
    `stdlib_reads_as_json` — never against the module's own classifier: if
    the stdlib reader reads the bytes as one value or as every line, an
    opaque declaration is refused. The classifier is then checked for the
    reverse direction through enumeration."""
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


@settings(max_examples=300, deadline=None)
@given(raw=_near_boundary)
def test_property_scanner_agrees_with_json_loads_under_the_depth_bound(raw):
    """The UTF-8 scanner vs the stdlib on the SAME bytes: `json.loads(bytes)`
    auto-detects UTF-16/32, the scanner is UTF-8 by design, so the oracle
    here is json.loads over bytes the stdlib detects as UTF-8 (the scanner's
    domain); non-UTF-8 bodies are the oracle's job in stdlib_reads_as_json."""
    if json.detect_encoding(raw) != "utf-8":
        return
    try:
        json.loads(raw)
        ref = True
    except (ValueError, RecursionError):
        ref = False
    assert is_strict_json_value(raw) == ref, raw[:40]


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
