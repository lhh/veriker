"""One strict JSON parser for producer bytes — and the ratchet that keeps it one.

Before 2026-09-05 the package held four hand-rolled duplicate-key parsers with
three different guard sets, and the manifest entry point plus the shared
admission loader parsed producer bytes with a bare `json.loads` (a manifest with
`{"value": 1, "value": 2}` parsed last-wins and was certified; measured). Four
tests here:

1. the contract of `audit_bundle.strict_json`, table-driven;
2. behavioural parity with the vendored canonical codec's own hooks
   (`_total_binding.strict_loads`), which cannot import this module and keeps
   its copy — one vector table, both parsers, same verdict per row;
3. a witness per rewired site, through the site's own entry point: the manifest
   parse, the shared admission loaders, the DSSE header, claimset's kind
   classifier, the FEA certificate parser;
4. a source ratchet over every `json.loads(` / `json.load(` in `audit_bundle/`:
   each site is the single source, a pinned standalone copy, or on the frozen
   allow-list below with the reason it may parse loosely. A new bare site fails.


"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle import _total_binding as tb  # noqa: E402
from audit_bundle.strict_json import (  # noqa: E402
    MAX_INT_DIGITS,
    StrictJSONError,
    strict_json_loads,
)

# ---------------------------------------------------------------------------
# 1 — the contract
# ---------------------------------------------------------------------------

ACCEPT = [
    (b'{"a": 1, "b": [true, null, 2.5, "x"]}', {"a": 1, "b": [True, None, 2.5, "x"]}),
    ('{"z": {"y": {"x": []}}}', {"z": {"y": {"x": []}}}),
    (b"[]", []),
    (b'"\\u00e9"', "é"),
    ("-" + "9" * MAX_INT_DIGITS, -int("9" * MAX_INT_DIGITS)),
    (
        b'{"a": {"a": 1}, "b": {"a": 2}}',
        {"a": {"a": 1}, "b": {"a": 2}},
    ),  # same key, different objects
]

REFUSE_SEMANTIC = [
    (b'{"value": 1, "value": 2}', "duplicate_key"),
    (b'{"outer": {"k": 1, "k": 1}}', "duplicate_key"),  # nested, even with equal values
    (b'[{"k": 1}, {"k": 2, "k": 3}]', "duplicate_key"),
    (b'{"n": NaN}', "non_finite"),
    (b"[Infinity]", "non_finite"),
    (b"-Infinity", "non_finite"),
    (("1" * (MAX_INT_DIGITS + 1)).encode(), "int_too_long"),
    ("-" + "1" * (MAX_INT_DIGITS + 1), "int_too_long"),
]

REFUSE_SYNTAX = [b"{", b'{"a": 1,}', b"", b"   ", b'{"a": 1} trailing', b"\x00"]


@pytest.mark.parametrize("raw,expected", ACCEPT)
def test_accepts(raw, expected):
    assert strict_json_loads(raw) == expected


@pytest.mark.parametrize("raw,kind", REFUSE_SEMANTIC)
def test_refuses_semantically_with_a_kind(raw, kind):
    with pytest.raises(StrictJSONError) as ei:
        strict_json_loads(raw)
    assert ei.value.kind == kind
    assert isinstance(ei.value, ValueError)
    if kind == "duplicate_key":
        assert ei.value.key in ("value", "k")


@pytest.mark.parametrize("raw", REFUSE_SYNTAX)
def test_syntax_errors_propagate_as_json_decode_error(raw):
    with pytest.raises(json.JSONDecodeError):
        strict_json_loads(raw)


def test_non_utf8_bytes_and_wrong_types():
    with pytest.raises(UnicodeDecodeError):
        strict_json_loads(b'{"a": "\xff"}')
    with pytest.raises(TypeError):
        strict_json_loads(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        strict_json_loads(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2 — parity with the vendored canonical codec's own hooks
# ---------------------------------------------------------------------------


def _verdict(fn, raw):
    try:
        return ("ok", fn(raw))
    except (tb.TotalBindingError, StrictJSONError):
        return ("semantic", None)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ("syntax", None)


@pytest.mark.parametrize(
    "raw",
    [r for r, _ in ACCEPT] + [r for r, _ in REFUSE_SEMANTIC] + REFUSE_SYNTAX,
    ids=lambda r: (r if isinstance(r, str) else r.decode("utf-8", "replace"))[:32],
)
def test_parity_with_total_binding_strict_loads(raw):
    """`_total_binding.strict_loads` wraps syntax errors in TotalBindingError, so
    compare refuse-vs-accept and the accepted VALUE, not the exception class."""
    mine = _verdict(strict_json_loads, raw)
    theirs = _verdict(tb.strict_loads, raw)
    assert (mine[0] == "ok") == (theirs[0] == "ok"), (raw, mine, theirs)
    if mine[0] == "ok":
        assert mine[1] == theirs[1]


def test_int_bound_agrees_with_the_codec():
    assert MAX_INT_DIGITS == tb._INT_DIGITS


# ---------------------------------------------------------------------------
# 3 — one witness per rewired site
# ---------------------------------------------------------------------------


def test_manifest_with_a_duplicate_key_is_malformed_not_last_wins(tmp_path):
    from audit_bundle.bundle_manifest import MalformedManifest
    from audit_bundle.verifier import _parse_manifest

    with pytest.raises(MalformedManifest, match="strict JSON"):
        _parse_manifest(b'{"schema_version": "x", "schema_version": "y"}', tmp_path)
    with pytest.raises(MalformedManifest, match="strict JSON"):
        _parse_manifest(b'{"files": {"a": NaN}}', tmp_path)


def test_verify_refuses_a_two_meaning_manifest_instead_of_certifying_it(tmp_path):
    """End to end through BundleVerifier.verify(): the reason code is the
    manifest_load REJECT, not a crash and not a PASS."""
    from audit_bundle.verifier import BundleVerifier

    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "manifest.json").write_bytes(b'{"bundle_id": "one", "bundle_id": "two"}')
    result = BundleVerifier(plugins=[]).verify(bundle)
    assert not result.ok
    codes = {f.reason_code for f in result.failures}
    assert "malformed_manifest" in codes, [
        (f.reason_code, f.detail) for f in result.failures
    ]


def test_admission_loaders_refuse_duplicate_keys_and_nan(tmp_path):
    from audit_bundle.admission import (
        InputInadmissible,
        admit_json_file,
        admit_jsonl_file,
        iter_admitted_jsonl_tolerant,
    )

    p = tmp_path / "x.json"
    p.write_bytes(b'{"value": 1, "value": 2}')
    with pytest.raises(InputInadmissible):
        admit_json_file(p)  # was: {'value': 2}
    p.write_bytes(b'{"n": NaN}')
    with pytest.raises(InputInadmissible):
        admit_json_file(p)
    p.write_bytes(b'{"value": 2}')
    assert admit_json_file(p) == {"value": 2}

    q = tmp_path / "rows.jsonl"
    q.write_bytes(b'{"a": 1}\n{"a": 1, "a": 2}\n')
    with pytest.raises(InputInadmissible):
        admit_jsonl_file(q)
    assert list(iter_admitted_jsonl_tolerant(q)) == [
        {"a": 1}
    ]  # tolerant: skipped, never last-wins


def test_dsse_header_keeps_its_duplicate_code_and_refuses_nan():
    from audit_bundle.dsse.header import (
        DSSE_HEADER_DUPLICATE_KEY,
        DSSE_MALFORMED_ENVELOPE,
        DSSEHeaderError,
        parse_strict_envelope,
    )

    with pytest.raises(DSSEHeaderError) as ei:
        parse_strict_envelope(b'{"payloadType": "a", "payloadType": "b"}')
    assert ei.value.code == DSSE_HEADER_DUPLICATE_KEY
    with pytest.raises(DSSEHeaderError) as ei:
        parse_strict_envelope(b'{"payloadType": NaN}')
    assert ei.value.code == DSSE_MALFORMED_ENVELOPE


def test_claimset_classifies_nan_and_oversized_int_as_corrupt():
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    assert classify_kind(b'{"v": 1}', "f")[0] is ClaimBytesKind.SINGLE_JSON
    assert (
        classify_kind(b'{"v": 1, "v": 2}', "f")[0]
        is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT
    )
    assert (
        classify_kind(b'{"v": NaN}', "f")[0] is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT
    )
    big = ("1" * (MAX_INT_DIGITS + 1)).encode()
    assert (
        classify_kind(b'{"v": ' + big + b"}", "f")[0]
        is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT
    )
    assert (
        classify_kind(b'{"v": 1}\n{"v": NaN}\n', "f")[0]
        is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT
    )


def test_fea_certificate_parser_delegates():
    from audit_bundle.rederivation.primitives.fea_witness_cert import parse_json_bytes

    assert parse_json_bytes(b'{"a": 1}') == {"a": 1}
    for bad in (b'{"a": 1, "a": 2}', b"[NaN]", ("9" * (MAX_INT_DIGITS + 1)).encode()):
        with pytest.raises(ValueError):
            parse_json_bytes(bad)


def test_standalone_pack_loader_carries_the_same_three_refusals(tmp_path):
    """The packs cannot import strict_json; control's `_admit_loads` is the
    family's hand copy (pinned across packs by test_reference_pack_parity)."""
    from audit_bundle.plugins.reference import control_rederivation as ctl

    f = tmp_path / "e.json"
    for bad in (b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": ' + b"9" * (MAX_INT_DIGITS + 1) + b"}"):
        f.write_bytes(bad)
        with pytest.raises(ValueError):
            ctl._admitted_json(f)
    f.write_bytes(b'{"a": 1}')
    assert ctl._admitted_json(f) == {"a": 1}


def test_revocation_list_refuses_duplicate_keys():
    from audit_bundle.revocation import RevocationListInvalid, load_revocation_list

    with pytest.raises(RevocationListInvalid, match="JSON parse error"):
        load_revocation_list(
            b'{"schema": "x", "schema": "y"}', revocation_root_resolver=lambda _k: b""
        )


def test_rekor_intoto_statement_with_duplicate_key_is_unreadable():
    from audit_bundle.extensions.rekor_anchor import intoto_predicate_type

    assert intoto_predicate_type(b'{"predicateType": "https://a", "predicateType": "https://b"}') is None
    assert intoto_predicate_type(b'{"predicateType": "https://a"}') == "https://a"


def test_tuf_metadata_with_duplicate_expires_is_a_client_error(tmp_path):
    from audit_bundle.extensions import c18_tuf_client as tuf

    (tmp_path / "root.json").write_text(
        '{"signed": {"expires": "2999-01-01T00:00:00Z", "expires": "1999-01-01T00:00:00Z"}}'
    )
    with pytest.raises(tuf.TUFClientError):
        tuf._metadata_expires(tmp_path, "root.json")


def test_spec_anchor_refuses_a_two_meaning_spec(tmp_path):
    from audit_bundle.rederivation.spec_binding import (
        AnchorConstructionError,
        SpecAnchor,
    )

    spec = tmp_path / "x.spec.json"
    spec.write_bytes(b'{"spec_id": "x", "spec_id": "y"}')
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with pytest.raises(AnchorConstructionError, match="strict JSON"):
        SpecAnchor.from_files([spec], forbid_within=bundle)


def test_sheet_query_input_loader_refuses_duplicate_keys(tmp_path):
    from audit_bundle.rederivation.primitives.sheet_query import _load_json_input

    p = tmp_path / "q.json"
    p.write_bytes(b'{"cell": "A1", "cell": "B2"}')
    with pytest.raises(ValueError):
        _load_json_input(p, "q.json", "t")


# ---------------------------------------------------------------------------
# 4 — the source ratchet
# ---------------------------------------------------------------------------

#: Every `json.loads(` / `json.load(` call site in audit_bundle/ that is NOT
#: `strict_json.py`, keyed by file, with the reason it may exist. Semantics of a
#: reason: "pinned copy" = a standalone module whose copy a parity test holds to
#: the source; "verifier-held" = bytes the verifier itself wrote or the operator
#: configured, never producer bytes; "round-trip" = json.loads(json.dumps(x)) as a
#: deep copy of an in-memory value. Nothing on this list parses PRODUCER bytes
#: loosely; a site that does belongs in the rewiring, not here.
ALLOWED_LOOSE_SITES: dict[str, str] = {
    "audit_bundle/_total_binding.py": "vendored canonical codec, pinned copy (test 2 above)",
    "audit_bundle/plugins/reference/control_rederivation.py": "standalone pack; _admit_loads (json.loads + the three hooks) is the family's pinned copy",
    "audit_bundle/plugins/reference/aigov_rederivation.py": "standalone pack; _admit_loads pinned to control by test_reference_pack_parity",
    "audit_bundle/plugins/reference/span_re_derivation.py": "standalone pack; _admit_loads pinned to control by test_reference_pack_parity",
    "audit_bundle/plugins/reference/energy_score_pack.py": "standalone pack; _admit_loads pinned to control by test_reference_pack_parity",
    "audit_bundle/discharge/verifier_signing.py": "round-trip deep copy of an in-memory record",
    "audit_bundle/gate/dispatch_ledger.py": "verifier-held: the gate's own fsync'd ledger, written by this module",
    "audit_bundle/vkernel_key_loader.py": "verifier-held: operator-configured key file",
    "audit_bundle/contract_slots.py": "verifier-held: the distribution's own contract_slots.json",
    "audit_bundle/source_registry/issuer_verifier.py": "verifier-held: operator-configured issuer allow-list",
    "audit_bundle/event_stream.py": "verifier-held: the verifier's own event-stream service response",
    "audit_bundle/claimset.py": "is_strict_json_value: a SYNTAX-only scanner that discards the value; the strict path is _parse_refusing_duplicates",
}
_SOURCE = "audit_bundle/strict_json.py"


def _loose_sites() -> dict[str, int]:
    """Count `json.loads(` / `json.load(` CALL nodes per file via the AST —
    docstrings and comments that merely mention the idiom do not count."""
    import ast

    seen: dict[str, int] = {}
    for path in sorted((_PKG_ROOT / "audit_bundle").rglob("*.py")):
        rel = path.relative_to(_PKG_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        n = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("loads", "load")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "json"
        )
        if n:
            seen[rel] = n
    return seen


def test_no_new_bare_json_loads():
    seen = _loose_sites()
    assert _SOURCE in seen, (
        "the single source lost its json.loads — the ratchet is measuring nothing"
    )
    strays = {
        k: v for k, v in seen.items() if k != _SOURCE and k not in ALLOWED_LOOSE_SITES
    }
    assert not strays, (
        f"new bare json.loads sites (route through audit_bundle.strict_json or list with a reason): {strays}"
    )
    # A row whose FILE is absent is not stale: the open-drop export excludes
    # premium / cross-pillar modules, and this test ships in that drop.
    if not (_PKG_ROOT / "release" / "oss_export.py").is_file():
        # Exported clone: the export REWRITES some shipped files (and drops
        # others), so "this row no longer parses loosely" is not a fact about
        # our source there. The strays check above is the guard and ran in
        # full; only this hygiene half is internal-tree-only.
        return
    present = {k for k in ALLOWED_LOOSE_SITES if (_PKG_ROOT / k).is_file()}
    stale = present - set(seen)
    assert not stale, (
        f"allow-list names sites that no longer parse loosely — delete the rows: {stale}"
    )


def test_ratchet_scanner_counts_calls_not_prose(tmp_path, monkeypatch):
    """Self-validation: a docstring mentioning json.loads(manifest.json) is not a
    site; a real call is, in either spelling."""
    import ast

    src = (
        'import json\n'
        'def f(b):\n'
        '    """The anchor comes from `json.loads(manifest.json)` so ..."""\n'
        '    # json.loads(x) in a comment\n'
        '    return json.loads(b)\n'
        'def g(fh):\n'
        '    return json.load(fh)\n'
        'def h(b):\n'
        '    return strict_json_loads(b)\n'
    )
    tree = ast.parse(src)
    n = sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("loads", "load")
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json"
    )
    assert n == 2
