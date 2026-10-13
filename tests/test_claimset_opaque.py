"""tests/test_claimset_opaque.py — opaque (whole-file) claim declarations on the
claimset coverage gate. Port 2b (the internal design notes).

One negative control per refusal path, the properties the scoping registered,
and the two invariants that must not move: the undeclared path is
byte-identical, and no STRUCTURED refusal is weakened to admit an opaque
file (kill condition K1).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.admission import AdmissionLimits  # noqa: E402
from audit_bundle.claimset import (  # noqa: E402
    CLAIMSET_ENUMERATION_FAILED,
    ClaimsetError,
    classify_claim_bytes,
    claimset_disclosure,
    enumerate_claim_universe,
    build_claimset_receipt,
    validate_claimset_declaration,
)
from audit_bundle.plugin import PluginResult  # noqa: E402
from audit_bundle.verifier import BundleVerifier

#: These cases exercise SURVIVED / SKIPPED / crash handling, where the
#: comparator vocabulary is not the subject. The weak mode is named explicitly
#: rather than defaulted into.
_DENYLIST = "DENYLIST_SCORING__FAIL_OPEN_ON_UNCLASSIFIED_CODES"  # noqa: E402

# Bytes a strict JSON/JSONL parser cannot read: a gzip-like header, stray
# quotes, and MORE unbalanced '{' bytes than admit_bytes' max_depth (64) —
# the exact shape that the JSON-shaped depth scan would falsely refuse.
_OPAQUE = b"\x1f\x8b\x08\x00" + b'"' + b"{" * 70 + b"\xff\xfe binary \x00 tail"
_CSV = b"region,total\nnorth,10\nsouth,12\n"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _write_bundle(
    tmp_path: Path,
    files: "dict[str, bytes]",
    *,
    claimset: "dict | None" = None,
    unpinned: "set[str]" = frozenset(),
    name: str = "bundle",
) -> Path:
    bundle_dir = tmp_path / name
    bundle_dir.mkdir()
    pins: dict = {}
    for rel, raw in files.items():
        p = bundle_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        if rel not in unpinned:
            pins[rel] = _sha(raw)
    manifest = {
        "schema_version": "legacy",
        "bundle_id": "claimset-opaque-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": pins,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    if claimset is not None:
        manifest["claimset"] = claimset
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def _enumerate(bundle_dir: Path, **kw) -> dict:
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    cs = manifest.get("claimset") or {}
    return enumerate_claim_universe(
        bundle_dir,
        bundle_id=manifest["bundle_id"],
        claim_files=dict(cs.get("claim_files", {})),
        manifest_files=dict(manifest["files"]),
        opaque_claim_files=dict(cs.get("opaque_claim_files", {})),
        **kw,
    )


class _Reporter:
    """Reports coverage and LISTS the file, but compares nothing — the
    verify-a-copy / false-declaration shape the ratchet exists to catch."""

    name = "claimset_reporter"

    def __init__(self, fields, files=()):
        self._fields = frozenset(fields)
        self._files = tuple(files)

    def check(self, bundle_dir, manifest) -> PluginResult:
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="",
            files_audited=self._files,
            verified_claim_fields=self._fields,
        )


class _ByteBinder:
    """A comparator that actually binds an opaque file: the bundled bytes
    must equal a verifier-held expectation (stand-in for a re-derivation)."""

    name = "byte_binder"

    def __init__(self, rel: str, expected: bytes, key: str):
        self._rel, self._expected, self._key = rel, expected, key

    def check(self, bundle_dir, manifest) -> PluginResult:
        actual = (Path(bundle_dir) / self._rel).read_bytes()
        if actual != self._expected:
            return PluginResult(
                ok=False,
                reason_code="RE_DERIVATION_MISMATCH",
                detail="bundled artifact bytes differ from the re-derived bytes",
                files_audited=(self._rel,),
            )
        return PluginResult(
            ok=True,
            reason_code="RE_DERIVED",
            detail="",
            files_audited=(self._rel,),
            verified_claim_fields=frozenset({self._key}),
        )


def _claimset_reasons(verdict):
    return [r for r in verdict.reasons if r.check_name == "claimset_coverage"]


def _claimset_lines(verdict):
    return [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]


# ---------------------------------------------------------------------------
# Declaration — parse boundary
# ---------------------------------------------------------------------------


def test_opaque_only_declaration_is_valid():
    validate_claimset_declaration({"opaque_claim_files": {"artifact": "payload/a.bin"}})


def test_mixed_declaration_is_valid():
    validate_claimset_declaration(
        {
            "claim_files": {"claims": "payload/claims.json"},
            "opaque_claim_files": {"artifact": "payload/a.bin"},
            "residuals": {},
        }
    )


@pytest.mark.parametrize(
    "decl",
    [
        {"claim_files": {}, "opaque_claim_files": {}},
        {"opaque_claim_files": {}},
        {"claim_files": {}},
        {},
    ],
    ids=["both-empty", "opaque-empty-alone", "structured-empty-alone", "nothing"],
)
def test_vacuous_declarations_refused(decl):
    with pytest.raises(ClaimsetError, match="vacuity"):
        validate_claimset_declaration(decl)


def test_key_in_both_maps_refused():
    with pytest.raises(ClaimsetError, match="both"):
        validate_claimset_declaration(
            {
                "claim_files": {"out": "payload/out.json"},
                "opaque_claim_files": {"out": "payload/out.bin"},
            }
        )


@pytest.mark.parametrize("bad", [None, "", 3, ["payload/a.bin"]])
def test_opaque_path_must_be_non_empty_string(bad):
    with pytest.raises(ClaimsetError, match="opaque_claim_files"):
        validate_claimset_declaration({"opaque_claim_files": {"artifact": bad}})


def test_opaque_key_reserved_character_refused():
    with pytest.raises(ClaimsetError, match="reserved"):
        validate_claimset_declaration({"opaque_claim_files": {"a.b": "payload/a.bin"}})


def test_opaque_map_must_be_object():
    with pytest.raises(ClaimsetError, match="opaque_claim_files"):
        validate_claimset_declaration({"opaque_claim_files": ["payload/a.bin"]})


def test_unknown_subkey_still_refused():
    with pytest.raises(ClaimsetError, match="unknown"):
        validate_claimset_declaration(
            {"opaque_claim_files": {"a": "payload/a.bin"}, "opaque": True}
        )


# ---------------------------------------------------------------------------
# Enumeration — every refusal path, and the admissions that must NOT refuse
# ---------------------------------------------------------------------------


def test_opaque_file_enumerates_as_exactly_its_key(tmp_path):
    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    u = (
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={},
            manifest_files={"payload/a.bin": _sha(_OPAQUE)},
            opaque_claim_files={"artifact": "payload/a.bin"},
        )
    )
    assert u["elements"] == ["artifact"]
    assert u["provenance"] == "SELF_AUTHORED" and u["source_sha"] is None


def test_binary_with_deep_brackets_and_stray_quotes_is_admitted(tmp_path):
    """The JSON-shaped depth scan (admit_bytes) would refuse these bytes for
    'nesting depth'; an opaque file is bounded by SIZE only."""
    raw = b'"' + b"{" * 500 + b"[" * 500
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    u = enumerate_claim_universe(
        b,
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/a.bin": _sha(raw)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    assert u["elements"] == ["artifact"]


def test_invalid_utf8_is_admitted_as_opaque(tmp_path):
    raw = b"\xff\xfe\xfd\x00\x01"
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    u = enumerate_claim_universe(
        b,
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/a.bin": _sha(raw)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    assert u["elements"] == ["artifact"]


def _refused_under_both(tmp_path, raw, *, opaque_match, structured_match):
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    pins = {"payload/a.bin": _sha(raw)}
    with pytest.raises(ClaimsetError, match=opaque_match):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={}, manifest_files=pins,
            opaque_claim_files={"artifact": "payload/a.bin"},
        )
    with pytest.raises(ClaimsetError, match=structured_match):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={"artifact": "payload/a.bin"}, manifest_files=pins,
        )


def _admitted_opaque(tmp_path, raw):
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    u = enumerate_claim_universe(
        b,
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/a.bin": _sha(raw)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    assert u["elements"] == ["artifact"]


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe", "\n".encode("utf-16"), b"\xef\xbb\xbf \n", "\u00a0\n\u3000".encode("utf-16-le")],
    ids=["utf16-bom-only", "utf16-bom-newline", "utf8-bom-whitespace", "utf16-le-unicode-space"],
)
def test_whitespace_once_decoded_is_hollow(tmp_path, raw):
    """A BOM (or UTF-16 whitespace) in front of nothing is a hollow claim,
    refused everywhere, not an opaque artifact. These were admitted opaque in
    v0.2.1, and an earlier commit on this branch pinned that as correct."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    assert classify_kind(raw, "t") == (ClaimBytesKind.HOLLOW, [])
    _refused_under_both(tmp_path, raw, opaque_match="hollow", structured_match="hollow")


_OBJ = b'{"amount": 100, "payee": {"name": "x", "iban": "y"}}'
_PRETTY = b'{\n  "amount": 100,\n  "payee": {"name": "x"}\n}\n'
_BOM8 = b"\xef\xbb\xbf"


@pytest.mark.parametrize(
    "raw",
    [
        b"0\n" + _BOM8 + b'{"secret": 1}\n',
        b"0\n" + _BOM8 + b"1\n",
        b"\n" + _BOM8 + _OBJ,
        b"1\n" + _OBJ.decode().encode("utf-16") + b"\n",
        b"1\n[\x00]\x00\n",
        b"1\n" + _OBJ.decode().encode("utf-32") + b"\n",
        _OBJ.decode().encode("utf-16") + b"\n",
        _BOM8 + b'{"amount": 100, "memo": "\xed\xa0\x80"}',
        b'"\xed\xa0\x80"',
        b'1\n{"amount": 100, "memo": "\xed\xa0\x80"}\n',
        '{"a": "\ud800"}'.encode("utf-16", "surrogatepass"),
        b"\t\n\n\xff\xfe[\x00]\x00",
        b"\r\t\r\x00{\x00}",
        b"1\n" + '"\ud800"'.encode("utf-16", "surrogatepass") + b"\n",
        b"\xef\xbb\xbf\x0c\n\n\n\n-2.5",
        b'\xef\xbb\xbf\n1\n"\xe2\x80\xa8"',
        '1\n"\u2028"'.encode("utf-16"),
        '1\n{"a":"\u2028"}\n\x001'.encode("utf-16"),
        '1\n"a\u0085b"\n'.encode("utf-16"),
        '"x"\n"a\u2029b"\n'.encode("utf-32"),
        '1\n"a\u2028b"'.encode("utf-16-le"),
        '1\x00\n{"a":"x\u2028y"}'.encode("utf-16"),
        b"\xef\xbb\xbf" + ' {"a":"\u010c"}'.encode("utf-16-le") + b"\n2",
        b"\xef\xbb\xbf\x00[\x001\x00]",
        "\x00[\x001\x00]".encode("utf-32"),
        b"\xff\xfe \x00\x00\x00{\x00\x00\x00}\x00\x00\x00",
    ],
    ids=[
        "bom-on-line-2",
        "bom-on-line-2-scalars",
        "bom-after-leading-newline",
        "utf16-line-in-utf8-body",
        "utf16-le-bare-line",
        "utf32-line-in-utf8-body",
        "utf16-odd-length",
        "surrogate-behind-utf8-bom",
        "surrogate-scalar",
        "surrogate-in-jsonl",
        "surrogate-in-utf16",
        "utf16-bom-after-leading-whitespace",
        "utf16-be-line-after-cr",
        # a string holding a lone surrogate, alone on a UTF-16 line: every
        # line reads once decoded with surrogates passed
        "surrogate-scalar-on-utf16-line",
        # the whole body, decoded and trimmed of U+FEFF, FF and LF, reads as
        # -2.5
        "bom-formfeed-then-scalar",
        # a raw U+2028 / U+0085 / U+2029 INSIDE a JSON string: str.splitlines
        # breaks there, the oracle (LF/CR lines of the decoded text) does not
        "bom-body-u2028-in-string",
        "utf16-u2028-in-string",
        "utf16-object-with-u2028-and-a-utf16be-line",
        "utf16-nel-in-string",
        "utf32-ps-in-string",
        "utf16le-u2028-in-string",
        "utf16-line-read-as-utf16le-on-its-own",
        "bom-then-utf16le-line",
        # found by the round-4 fuzz, a hole 2053eddf4 opened: the decoded text is
        # ONE line, and json.loads reads its UTF-8 bytes as UTF-16-BE; the
        # decoded split was skipped for a single line
        "one-decoded-line-read-as-utf16be",
        "one-utf32-decoded-line-read-as-utf16be",
        "one-utf16-decoded-line-read-as-utf16le",
    ],
)
def test_what_the_stdlib_reader_reads_is_never_opaque(tmp_path, raw):
    """K5, which fired on v0.2.1: `json.loads(bytes)` reads each of these (the
    whole body, or every line with that line's own detected encoding and
    surrogates passed), yet each was admitted as ONE opaque element. The
    classifier's refusal reader now reads everything the stdlib reads."""
    from audit_bundle.claimset import stdlib_reads_as_json

    assert stdlib_reads_as_json(raw)  # the oracle, not the classifier, says JSON
    _refused_under_both(
        tmp_path, raw, opaque_match="corrupt", structured_match="corrupt|duplicate|BOM"
    )


@pytest.mark.parametrize(
    "raw",
    [
        _BOM8 + _OBJ + b"\n\xff\n",
        'garbage\n{"x": 1, "y": {"z": 2}}\n'.encode("utf-16") + b"\n",
        b"\x0c" + _OBJ,
        "\u00a0".encode() + _OBJ,
        b"\x1e" + _OBJ + b'\n\x1e{"k": 2}\n',
        b"1" + "\u2028".encode() + _OBJ,
        b"1" + "\u0085".encode() + _OBJ,
        b'1\n{"amount":\r100, "payee": {"name": "x"}}\n',
        b"0 " + _OBJ,
        b'"v1"\n' + _PRETTY,
        b"// generated by exporter v3\n" + _PRETTY,
        b"/* header */ " + _PRETTY,
        b")]}'\n" + _PRETTY,
        b")]}',\n" + _PRETTY,
        b"\r\n)]}'\n" + _PRETTY,
        b'1\n{"amount": 100, "payee": {"name": "x"},}\n',
        b'0\n{"a": 1,}\n',
        'x\n{"amount": 100, "memo": "\u2028"}\n'.encode("utf-16"),
        b'x\n{"a":1}\xff\n',
        'garbage\n{"amount": 100, "memo": "a\u0085b"}\n'.encode("utf-16"),
        b'garbage\n{"amount": 100,\r"payee": "x"}\n',
        b"// exported\x0cby tool v3\n" + _PRETTY,
        "// exported\u0085by tool v3\n".encode() + _PRETTY,
        b"0 [1, 2]\n1 [3, 4]\n",
        'garbage\n{"a":\r1}\n'.encode("utf-16"),
        'garbage\n{"a": "\u020a",\r"b": 1}\n'.encode("utf-16"),
        'garbage\n \ufeff{"a": 1}\n'.encode(),
        b'0 {"a": 1, /* c */ "b": 2}',
        '0 {"a":\ufeff1}'.encode(),
        b'garbage\x0c{"amount": 100, "payee": "x"}\n',
        b'garbage\x1c{"amount": 100}',
        'garbage\u0085{"amount": 100}'.encode(),
        'garbage\u2028{"amount": 100}'.encode(),
        b'# exported by tool\x0b{"amount": 100}\x0b{"amount": 7}\n',
        b'\x1egarbage\x1e{"amount": 100}',
        b'for (;;);{"amount": 100, "payee": "x"}',
        b'while(1);{"amount": 100}',
        b'garbage\n\x00{"amount": 100}\x00\n',
        b"1\n\xc2\xa0\n2\n",
        ('garbage\n{"amount": ' + "9" * 4301 + ', "payee": "x"}\n').encode("utf-16"),
        ("9" * 4301).encode("utf-16"),
        ('garbage\n\x0c{"amount": ' + "9" * 4301 + ', "payee": "x"}\n').encode(),
        b'garbage\n{"amount": ' + b"9" * 4301 + b', "b": "\xff"}\n',
        b"1\n\x00  (\n2\n",
        b"\xef\xbb\xbf1\n\x00  (\n2\n",        b'\x00\n{"amount":\n  100}',
        b'\x00 {"amount": 100}',
        b'\x00\n"s"\n-2.5\x0c{"k": "v"}\n[]',
        b'\x00\n// c\n{\n  "amount": 100\n}',
        b'\x00\ngarbage\n\x00{"amount": 100}\n',
        b'\x00\ngarbage\x0c{"k": "v"}',
        b'garbage\x0c[{"amount": 100, "payee": "x"}]',
        b'\x1egarbage\x1e[{"amount": 100}]',
    ],
    ids=[
        "bom-object-then-invalid-byte",
        "utf16-then-odd-byte",
        "form-feed-before-object",
        "nbsp-before-object",
        "rfc7464-sequence",
        "u2028-separator",
        "nel-separator",
        "cr-inside-record",
        "concatenated-scalar-then-object",
        "scalar-line-then-pretty-object",
        "jsonc-line-comment-header",
        "jsonc-block-comment-header",
        "xssi-prefix",
        "xssi-prefix-comma",
        "xssi-prefix-after-newline",
        "trailing-comma-in-a-document",
        "trailing-comma-in-a-document-after-a-scalar",
        "utf16-object-line-python-text-mode-reads",
        "invalid-byte-dropped-by-a-tolerant-decoder",
        "utf16-object-line-nel-in-string",
        "lone-cr-inside-a-record-lf-line-readers",
        "jsonc-comment-runs-past-a-form-feed",
        "jsonc-comment-runs-past-nel",
        "whole-file-of-concatenated-values",
        "utf16-record-with-a-lone-cr-decoded-lf-lines",
        # U+020A is 0A 02 in UTF-16-LE: the raw split cuts inside it, the
        # decoded LF/CR split cuts at the CR; only decoded LF lines read it
        "utf16-record-cr-and-lf-byte-only-decoded-lf-lines",
        # JavaScript's String.prototype.trim strips U+FEFF; JSON.parse then reads
        "js-trim-strips-a-bom-after-a-space",
        "comment-inside-a-concatenated-object",
        "bom-inside-a-concatenated-object",
        # str.splitlines line ends (Python `text.splitlines()`)
        "splitlines-form-feed",
        "splitlines-file-separator",
        "splitlines-nel",
        "splitlines-line-separator",
        "splitlines-vertical-tab-records",
        # an RFC 7464 reader that reads past a bad record
        "rfc7464-bad-record-then-good-record",
        "xssi-for-guard",
        "xssi-while-guard",
        # Java String.trim / PHP trim strip NUL
        "nul-trimmed-line",
        # a line of only NBSP is blank to a str.strip reader: every line reads
        "nbsp-blank-line-between-scalars",
        # integers past sys.get_int_max_str_digits(): json refused them, so
        # the kind moved with the process-wide setting
        "utf16-record-with-a-4301-digit-integer",
        "utf16-4301-digit-scalar",
        "form-feed-trimmed-record-with-a-4301-digit-integer",
        "invalid-byte-dropped-record-with-a-4301-digit-integer",
        # the middle line is blank to a reader that decodes it on its own
        # (json.loads detects UTF-16-BE there), and the others read: the
        # plain-UTF-8 body was opaque while its BOM twin was refused
        "line-blank-in-its-own-encoding",
        "line-blank-in-its-own-encoding-behind-a-bom",
        # a NUL in the first two bytes makes json.loads detect UTF-16, and the
        # text readers read that decode alone; a UTF-8 text reader (trimming
        # NUL, or splitting lines) reads the object. Found grading loosenings
        # with an independent stdlib reader (round 5)
        "nul-then-pretty-printed-object",
        "nul-then-object",
        "nul-then-object-in-a-concatenated-document",
        "nul-then-jsonc-document",
        # round-5 claims audit: witnesses the line readers (3) and (4) must
        # decide on the UTF-8 decode (the others above are decided by (2)/(5))
        "nul-then-a-line-only-the-utf8-decode-reads",
        "nul-then-a-splitlines-line-only-the-utf8-decode-reads",
        # round-5 claims audit: (4) read objects only, so an array of records
        # shrank the denominator (k:[].amount, k:[].payee -> one element)
        "splitlines-array-of-objects",
        "rfc7464-bad-record-then-array-of-objects",
    ],
)
def test_what_a_json_family_reader_reads_is_never_opaque(tmp_path, raw):
    """Issue 3 on v0.2.1: readers more lenient than `json.loads` pull an
    object or array out of each of these, or read every line of it (a
    tolerant decoder; trimming
    whitespace, U+FEFF or NUL at a line's ends; str.splitlines line ends;
    RFC 7464, also past a bad record; jq concatenation; JSONC comments and
    trailing commas; XSSI guards; Python text-mode and LF-only line
    readers; integers of any length), yet each was admitted as one opaque
    element. The leniency is a DOCUMENT reading (the whole file is
    JSON-family text); line by line the value must be one value in the
    json-module grammar, trimmed at the ends. The declared limits are
    `test_declared_limits_stay_opaque`."""
    _refused_under_both(
        tmp_path, raw, opaque_match="corrupt", structured_match="corrupt|duplicate|BOM"
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"a,b,c\n1,2,3\n",
        _BOM8 + b"a,b,c\n1,2,3\n",
        "a UTF-16 prose note\nsecond line\n".encode("utf-16"),
        b"; settings\nname = x\n[section]\nk = v\n",
        b'2026-09-24 12:00:00 [INFO] started\n2026-09-24 12:00:01 [WARN] payload={"a":1}\n',
        b"1 2 3\n4 5 6\n",
        b"# Title\n- [ ] task\n- [x] done\nSee [link](http://x).\n",
        b'# comment\nimport json\nx = {"a": 1}\n',
        b"\x00",
        b"export function F() {\n  return (\n    <div>\n      {/* Floating Trigger Button */}\n    </div>\n  );\n}\n",
        b"void f() {\n  try { g(); }\n  catch (...)\n\t  { /* swallow the exception */ }\n}\n",
        b"int main() {\n  {} // ignored\n  return 0;\n}\n",
        b"int m[2][3] = {\n  [1, 2, 3] // first\n  [4, 5, 6] // last row\n};\n",
        b"M = [\n    [1, 2, 3,],\n    [4, 5, 6,]\n]\nprint(M)\n",
        b'/* tokens */\n[data-theme="dark"] { --x: 1; }\n',
        b'// Copyright\n[assembly: AssemblyTitle("x")]\n',
        b'status:\n  500 {"detail": "boom"}\n',
        b"n  mean  ci\n10 0.63 [0.6005,0.6712]\n",
        b"X\xd2\x11P\xab\x99\xe1Fh\x15r\r{}\x1d\xb2\\\x7fc\xe3u/\xfe",
        b"garbage\n{}\n[]\n",
        b'"' + b"[" * 2000,
        b"0 {}\n1 []\n",
        b"x\x0c[]\x0c{ }\x0c[x]\x0c1\x0c",
        b"x\n" + b"[" * 1023 + b"1\n",
        b'x\n["' + b"[" * 1100 + b'" x]\n',
        b"?\x1d,\r[1]\x1e\x1dd[",
        b"/|[\x0b[6]\x1c,{5",
        b"\x7fELF\x02\x01\x1d\x0c\x00[1]\x03\x01\x0c\x003\x00",
        b'garbage\x0c[1, "{", "x"]\x1e',
    ],
    ids=[
        "csv",
        "utf8-bom-csv",
        "utf16-prose",
        "ini-comment-first",
        "log-with-embedded-json",
        "numeric-table",
        "markdown-checkboxes",
        "python-source",
        "lone-nul",
        "jsx-comment-line",
        "c-block-holding-a-comment",
        "c-empty-block-then-comment",
        "c-rows-with-trailing-comments",
        "python-trailing-commas",
        "css-comment-header-then-bracket",
        "csharp-comment-then-attribute",
        "report-status-line",
        "results-table-with-interval",
        "binary-with-empty-object-between-separators",
        "empty-containers-beside-garbage",
        "brackets-inside-an-unclosed-string",
        "concatenated-values-holding-only-empty-containers",
        "splitlines-lines-holding-no-member",
        "nesting-one-level-short-of-the-cap",
        # 1,100 '[' inside a string: counted as nesting, a mutant refused it
        "brackets-inside-a-string-are-no-nesting",
        # from a zip, a PNG and a shared library a first version of the
        # str.splitlines reader refused (it read arrays on those lines)
        "zip-bytes-with-1-between-separators",
        "png-bytes-with-6-between-separators",
        "so-bytes-with-1-between-c0-bytes",
        # '{' and a quote only inside strings: no object, so not read by the
        # str.splitlines reader (a mutant reading any such array survived)
        "splitlines-array-whose-brace-is-in-a-string",
    ],
)
def test_ordinary_artifacts_stay_opaque(tmp_path, raw):
    """The false-refusal controls for the two tests above: widening what is
    JSON-shaped must not refuse ordinary artifacts. A stream of scalars (a
    numeric table) hides no field, an EMPTY object or array hides no field
    (`{}` renders as the payload key alone, as an opaque element does), a
    line is read as strict JSON (no comments, no trailing commas, no second
    value: a first version of this fix read `{/* ... */}` in 132 of 306 .tsx
    files as `{}` and refused them), a comment in front of a '[' does not
    make CSS or C# JSON, and a BOM alone is not evidence. A body whose first
    byte is '{' or '[' is still refused (an INI file that opens with a
    section header)."""
    _admitted_opaque(tmp_path, raw)


@pytest.mark.parametrize("seed", [1, 2, 5])
def test_random_binaries_stay_opaque(tmp_path, seed):
    """High-entropy bytes (compressed or encrypted artifacts). The first
    version of this fix refused 9 of 24 random 15 MiB bodies beyond the
    parent's 2, reading `{}` / `[1]` out of short decoded rows."""
    import random

    raw = random.Random(seed).randbytes(256 * 1024)
    assert raw[:1] not in (b"{", b"[")  # the first-byte rule is its own, older rule
    _admitted_opaque(tmp_path, raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"// c\n" + b'{"a": 1',
        b"x\n{a: 1}\n",
        b'x\n{"a": 1,}\n',
        b'x\n0 {"a": 1}\n',
        b'x\n{"a":\x0c1}\n',
        b"\x1egarbage\n\x1e{\n  \"amount\": 100\n}\n",
        b'1\n{\n  "amount": 100\n}\ngarbage\n',
        b"garbage\x0c[100, 7]\x1e",
        b'x\n#{"a": 1}\n',
        b"x\n\x7f[1]\n",
        b"x\n{'a': 1}\n",
        b"x\n[0x1]\n",
        b'x\n{"a": /*c*/ 1}\n',
        b"garbage\n" + b"[" * 2000 + b"x",
        b'garbage\x85{"a":1}',
        b'garbage\x00{"a":1}\x00',
        b"garbage\n" + b"[" * 2000 + b"u",
    ],
    ids=[
        "truncated-jsonc-after-a-comment",
        "json5-unquoted-key-line",
        "trailing-comma-line-beside-garbage",
        "concatenated-values-line-beside-garbage",
        "form-feed-inside-a-value-beside-garbage",
        "rfc7464-bad-record-then-multiline-record",
        "valid-prefix-then-garbage",
        "array-on-a-splitlines-line",
        "a-prefix-other-than-the-three-xssi-guards",
        "a-trim-of-another-character",
        "json5-single-quotes",
        "json5-hexadecimal-number",
        "comment-on-one-line",
        # past the cap, but no line reader parses text that cannot end as a
        # value, and json.loads does not read it either
        "nesting-past-the-cap-in-a-line-that-cannot-end-as-a-value",
        # round-4 red team: plausible readers the statement now names as
        # not modelled (C strings in binaries are NUL-delimited, and a NUL
        # split would read JSON literals embedded in shared libraries)
        "latin1-fallback-nel-line-end",
        "nul-delimited-records",
        # no literal ends in 'u': the value gate had it (round-5 claims audit)
        "nesting-past-the-cap-in-a-line-ending-in-u",
    ],
)
def test_declared_limits_stay_opaque(tmp_path, raw):
    """What the evidence tests do NOT model, stated in the conventions
    statement: readers that change the value grammar (JSON5), leniency on a
    single line (comments, trailing commas, a second value, whitespace other
    than JSON's inside a value), a value spanning several lines after a line
    nothing reads, readers that stop at the first error, and truncated
    JSONC, and an array on a line only the str.splitlines split makes (the
    extra line ends and C0 bytes put `[1]` there in binaries by accident).
    Pinned so that closing one is a deliberate change, not a drift."""
    _admitted_opaque(tmp_path, raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"x\n" + b"[" * 2000 + b"1]",
        b"1 " + b"[" * 100_000 + b"1" + b"]" * 99_999,
    ],
    ids=["line-past-the-cap-past-depth-branch", "document-past-json-recursion"],
)
def test_nesting_past_the_scanner_cap_is_refused(tmp_path, raw):
    """A value whose nesting reaches 1024 levels before its first syntax
    error is read as JSON-shaped, by every refusal reader, without reading
    further (it bounds the Python scanner's work on 15 MiB bracket runs).
    Only refusal follows (the admission bound is 64). Nesting that sits
    inside a string, or in a line that cannot start and end a value, is no
    nesting: `brackets-inside-an-unclosed-string` and the deep-binary test
    stay opaque."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    assert classify_kind(raw, "t")[0] is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT


def test_a_cr_byte_inside_a_utf16_line_does_not_end_it(tmp_path):
    """Found by the line-framing property: U+040D encodes as 0D 04 in
    UTF-16-LE, so a split at CR cut the object line in two. A reader that
    splits at LF only (the raw bytes, or the decoded text) reads it."""
    raw = b"not json at all\n" + '{"\x80\u040d": null}'.encode("utf-16") + b"\n"
    _refused_under_both(
        tmp_path, raw, opaque_match="corrupt", structured_match="corrupt|duplicate|BOM"
    )


def _deep_bodies(depth):
    """One body per refusal reader, each nesting `depth` levels in a text no
    reader can finish: a line beside unreadable lines, a UTF-16 line, a
    concatenated document, a document of objects, and a JSONC document."""
    return {
        "line": b"1\n1\x00\n" + b"[" * depth + b"1\x0c",
        "utf16-line": ("garbage\n" + "[" * depth + "1").encode("utf-16"),
        "document": b"1 " + b"[" * depth + b"x",
        "object-document": b"0 " + b'{"a":' * depth + b"x",
        "jsonc-document": b"// c\n" + b"[" * depth + b"x",
        # a COMPLETE value nesting that deep, then an error: the scanner
        # stops at the cap, before the error
        "closed-value-then-garbage": b"0 " + b"[" * depth + b"1" + b"]" * depth + b" x",
    }


def _deep_bodies_small_stack(depth):
    """`_deep_bodies` and the round-5 paths: the UTF-8 second decode and the
    str.splitlines reader."""
    return {
        **_deep_bodies(depth),
        "nul-led-utf8": b"\x00 " + b"[" * depth + b"1",
        "splitlines-object": b"x\x0c" + b'{"a":' * depth + b"1" + b"}" * depth,
    }


@pytest.mark.parametrize("reader", sorted(_deep_bodies(1)))
def test_nesting_to_the_cap_is_exact_on_every_reader(reader):
    """Round-3 red team (F8) and claims audit (item 3): the cap ran only
    where a scanner happened to run, so the same nesting was JSON-shaped in
    UTF-8 and opaque in UTF-16, or after a comment and not before one. Every
    refusal reader now answers as the capped scanner does: 1023 levels
    before the first error stay opaque, 1024 are refused."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    assert classify_kind(_deep_bodies(1023)[reader], "t")[0] is ClaimBytesKind.NOT_JSON_SHAPED
    assert (
        classify_kind(_deep_bodies(1024)[reader], "t")[0]
        is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT
    )


@pytest.mark.parametrize("depth", [2000, 9_900, 20_000])
def test_the_kind_does_not_depend_on_the_callers_stack(depth):
    """Round-3 red team (F6, F7) and claims audit (item 2): past 1024 levels
    the refusal readers fell back to the scanner only when json ran out of
    recursion budget, and that budget shrinks with the caller's C stack (and
    is ~1000 on CPython 3.11, ~10000 on 3.12), so a body 9,900 deep was
    opaque from a shallow caller and refused from a deep one. json's budget
    no longer decides: the same kind from both."""
    from audit_bundle.claimset import classify_kind

    def from_deep_c_stack(n, fn):
        return fn() if n == 0 else list(map(lambda _: from_deep_c_stack(n - 1, fn), [0]))[0]

    for raw in _deep_bodies(depth).values():
        shallow = classify_kind(raw, "t")[0]
        deep = from_deep_c_stack(150, lambda: classify_kind(raw, "t")[0])
        assert shallow is deep, raw[:20]


def test_a_json_recursion_error_is_answered_by_the_scanner(monkeypatch):
    """Where json runs out of recursion budget within `_JSON_DEPTH` (a caller
    already near its limit), a RecursionError proves nothing about the text,
    and the scanner answers, in the line reader and the document reader.
    Simulated: json's decoder here raises RecursionError past 20 levels (a
    real budget that low leaves too little for the caller as well). A mutant
    taking every RecursionError as "read" refused the unclosed texts."""
    from audit_bundle import claimset

    class Shallow(json.JSONDecoder):
        def raw_decode(self, s, idx=0):
            if s.count("[", idx) >= 20:
                raise RecursionError("simulated budget")
            return super().raw_decode(s, idx)

    monkeypatch.setattr(claimset, "_LIMITLESS", Shallow(parse_int=str))
    calls = []
    capped = claimset._capped_scan
    monkeypatch.setattr(
        claimset, "_capped_scan", lambda s, **kw: calls.append(1) or capped(s, **kw)
    )
    unclosed, closed = "[" * 30 + "1", "[" * 30 + "1" + "]" * 30
    assert claimset._read_text(unclosed) is None
    got = claimset._read_text(closed)
    assert got is not None and got.container
    assert claimset._reads_as_a_document("1 " + unclosed) is False
    assert claimset._reads_as_a_document("1 " + closed) is True
    assert len(calls) == 4  # the scanner answered each of the four


@pytest.mark.parametrize("reader", sorted(_deep_bodies_small_stack(1)))
def test_json_never_sees_nesting_past_the_cap_so_a_small_stack_survives(reader):
    """Round-4 red team: the refusal readers handed json's C decoder text of
    any depth and relied on RecursionError, which counts levels, not stack
    bytes. On a thread with a 1 MiB stack, 9,000 levels ran off the C stack
    and killed the process (SIGSEGV); v0.2.1 never gave json more than 64.
    Round 5: 1,030 levels still overflow a 128 KiB stack (the musl/Alpine
    thread default). Now json reads no deeper than 64 levels (the admission
    bound); every reader path at 9,000 levels runs here on 128 KiB (measured
    floor: 64 KiB on CPython 3.11-3.13). Run in a child process, so a
    regression fails this test instead of killing the suite."""
    import subprocess
    import textwrap

    code = textwrap.dedent(
        f"""
        import sys, threading
        sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
        from audit_bundle.claimset import classify_kind
        from tests.test_claimset_opaque import _deep_bodies_small_stack
        raw = _deep_bodies_small_stack(9000)[{reader!r}]
        out = []
        threading.stack_size(128 * 1024)
        t = threading.Thread(target=lambda: out.append(classify_kind(raw, "t")[0].name))
        t.start(); t.join()
        print(out[0])
        """
    )
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=300,
        env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert r.returncode == 0, (r.returncode, r.stderr[-500:])
    assert r.stdout.strip() == "JSON_SHAPED_BUT_CORRUPT"


def test_the_oracle_has_no_cap():
    """Round-3 claims audit (item 1) and red team (F1): the depth cap sat in
    the scanner the ORACLE shares, so `stdlib_reads_as_json` said True for a
    line json.loads can never read (`[` x 20000 then `x`) and the classifier,
    rightly, admitted it: K5 failed against the named oracle. The oracle's
    scanner is uncapped; it reads what json.loads would read with any
    recursion budget."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind, stdlib_reads_as_json

    unreadable = b"1\n1\x00\n" + b"[" * 20_000 + b"x"
    assert not stdlib_reads_as_json(unreadable)
    assert classify_kind(unreadable, "t")[0] is ClaimBytesKind.NOT_JSON_SHAPED
    assert stdlib_reads_as_json(b"[" * 20_000 + b"1" + b"]" * 20_000)
    assert not stdlib_reads_as_json(b"[" * 20_000 + b"1" + b"]" * 19_999)


@pytest.mark.parametrize("limit", [640, 0])
def test_the_kind_does_not_depend_on_int_max_str_digits(limit):
    """Round-3 red team (F4, F5): json refuses integers past
    `sys.get_int_max_str_digits()`, a process-wide setting, so a record
    holding a 700-digit integer was refused at the default and admitted
    under 640, and one holding 4,301 digits the other way round. Integers
    are kept as text now; the kinds hold under any setting."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind, stdlib_reads_as_json

    bodies = [
        ('garbage\n{"amount": ' + "9" * n + "}\n").encode("utf-16") for n in (700, 4301)
    ] + [("9" * 4301).encode("utf-16")]
    before = sys.get_int_max_str_digits()
    at_default = [(classify_kind(b, "t")[0], stdlib_reads_as_json(b)) for b in bodies]
    try:
        sys.set_int_max_str_digits(limit)
        moved = [(classify_kind(b, "t")[0], stdlib_reads_as_json(b)) for b in bodies]
    finally:
        sys.set_int_max_str_digits(before)
    assert moved == at_default
    assert all(k is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT for k, _ in at_default)


def test_trimming_is_linear():
    """Round-3 red team (F2): `_trim` stripped whitespace and U+FEFF in
    alternation, copying the text each round, and a body of alternating
    spaces and U+FEFF ran past 120 s at 15 MiB (quadratic) while it could
    be declared opaque. 8 MiB of it now classifies in well under a second
    here; the bound below leaves two orders of magnitude of slack."""
    import time

    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    raw = (" \ufeff" * (2 * 1024 * 1024) + "x").encode()
    t = time.perf_counter()
    assert classify_kind(raw, "t")[0] is ClaimBytesKind.NOT_JSON_SHAPED
    assert time.perf_counter() - t < 30


def test_splitlines_object_lines_are_held_to_the_row_ceiling(monkeypatch):
    """The str.splitlines reader reads only lines that open with '{' and a
    key's quote and close with '}'; past the row ceiling of them it refuses,
    so a body cannot spend unbounded parse time there."""
    from audit_bundle import claimset
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    raw = b"x\x0c" + b'{"a" x}\x0c' * 5
    assert classify_kind(raw, "t")[0] is ClaimBytesKind.NOT_JSON_SHAPED
    monkeypatch.setattr(claimset, "_MAX_JSONL_ROWS", 4)
    with pytest.raises(ClaimsetError, match="ceiling"):
        classify_kind(raw, "t")


def test_the_encoding_shortcut_is_json_detect_encoding():
    """`_encoding` skips `json.detect_encoding` for bytes it knows are plain
    UTF-8; over every first two bytes that matter and lengths 0-5 the two
    agree."""
    import itertools

    from audit_bundle.claimset import _encoding

    firsts = [0x00, 0x01, 0x0A, 0x20, 0x5B, 0x7B, 0xBB, 0xBF, 0xEF, 0xFE, 0xFF]
    for n in range(6):
        for combo in itertools.product(firsts, repeat=min(n, 4)):
            b = bytes(combo) + b"x" * (n - len(combo))
            assert _encoding(b) == json.detect_encoding(b), b


def test_unicode_space_is_every_isspace_character():
    """`_UNICODE_SPACE` is built from U+0000..U+3000 at import; no character
    past U+3000 is whitespace to str.isspace (this interpreter's Unicode
    database)."""
    from audit_bundle.claimset import _UNICODE_SPACE

    assert set(_UNICODE_SPACE) == {chr(c) for c in range(0x110000) if chr(c).isspace()}


def test_csv_with_header_is_opaque(tmp_path):
    b = _write_bundle(tmp_path, {"payload/result.csv": _CSV})
    u = enumerate_claim_universe(
        b,
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/result.csv": _sha(_CSV)},
        opaque_claim_files={"result": "payload/result.csv"},
    )
    assert u["elements"] == ["result"]


def _refuses(tmp_path, raw, *, match, **kw):
    b = _write_bundle(tmp_path, {"payload/a.bin": raw}, **kw)
    with pytest.raises(ClaimsetError, match=match):
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={},
            manifest_files=dict(json.loads((b / "manifest.json").read_text())["files"]),
            opaque_claim_files={"artifact": "payload/a.bin"},
        )


def test_opaque_unpinned_refused(tmp_path):
    _refuses(tmp_path, _OPAQUE, match="not pinned", unpinned={"payload/a.bin"})


def test_opaque_missing_refused(tmp_path):
    b = _write_bundle(tmp_path, {"payload/other.bin": _OPAQUE})
    with pytest.raises(ClaimsetError, match="absent|not pinned"):
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={},
            manifest_files={"payload/a.bin": _sha(_OPAQUE)},
            opaque_claim_files={"artifact": "payload/a.bin"},
        )


def test_opaque_traversal_refused(tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(_OPAQUE)
    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    with pytest.raises(ClaimsetError, match="escapes|canonical"):
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={},
            manifest_files={"../outside.bin": _sha(_OPAQUE)},
            opaque_claim_files={"artifact": "../outside.bin"},
        )


def test_opaque_empty_file_refused(tmp_path):
    _refuses(tmp_path, b"", match="empty|hollow")


def test_opaque_oversized_refused_under_injected_limits(tmp_path, monkeypatch):
    """Size is bounded by stat BEFORE the bytes are read: an oversized
    artifact is refused without ever being loaded (design-audit finding 6)."""
    raw = b"\x00" * 4096
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})

    real = Path.read_bytes

    def _never(self):  # proves read_bytes is not reached for the over-bound file
        if self.name == "a.bin":
            raise AssertionError("read_bytes called on an over-bound file")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", _never)
    with pytest.raises(ClaimsetError, match="refused before reading"):
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={},
            manifest_files={"payload/a.bin": _sha(raw)},
            opaque_claim_files={"artifact": "payload/a.bin"},
            limits=AdmissionLimits(max_bytes=1024),
        )


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({"a": 1, "b": [1, 2]}).encode(),
        b"42",
        b'"a string"',
        b"[]",
        b'{"a":1}\n{"a":2}\n',  # JSONL
        b"1\n2\n3\n",  # a headerless one-column CSV IS a JSONL of scalars
    ],
    ids=["object", "scalar", "string", "empty-array", "jsonl", "numeric-lines"],
)
def test_anti_demotion_structured_bytes_refused_as_opaque(tmp_path, raw):
    """A producer cannot flatten a structured denominator to one element by
    declaring it opaque. Loud, never silent."""
    _refuses(tmp_path, raw, match="declared opaque")


def test_structured_refusals_are_not_weakened_by_the_opaque_path(tmp_path):
    """K1: the SAME non-JSON bytes declared under claim_files are still
    refused — opaque is additive, never a loosening of the classifier."""
    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    with pytest.raises(ClaimsetError, match="must be JSON or JSONL"):
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={"artifact": "payload/a.bin"},
            manifest_files={"payload/a.bin": _sha(_OPAQUE)},
        )


def test_union_element_ceiling_counts_opaque_entries(tmp_path, monkeypatch):
    import audit_bundle.claimset as cs_mod

    monkeypatch.setattr(cs_mod, "_MAX_ELEMENTS", 2)
    files = {f"payload/{i}.bin": _OPAQUE + bytes([i]) for i in range(3)}
    b = _write_bundle(tmp_path, files)
    with pytest.raises(ClaimsetError, match="exceeds"):
        enumerate_claim_universe(
            b,
            bundle_id="x",
            claim_files={},
            manifest_files={rel: _sha(raw) for rel, raw in files.items()},
            opaque_claim_files={f"k{i}": f"payload/{i}.bin" for i in range(3)},
        )


def test_mixed_universe_is_union_and_deterministic(tmp_path):
    claims = json.dumps({"x": 1, "y": "s"}).encode()
    files = {"payload/claims.json": claims, "payload/a.bin": _OPAQUE}
    b = _write_bundle(tmp_path, files)
    kw = dict(
        bundle_id="x",
        claim_files={"claims": "payload/claims.json"},
        manifest_files={rel: _sha(raw) for rel, raw in files.items()},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    u1 = enumerate_claim_universe(b, **kw)
    u2 = enumerate_claim_universe(b, **kw)
    assert u1["elements"] == ["artifact", "claims:x", "claims:y"]
    assert u1["universe_sha"] == u2["universe_sha"]


def test_source_conventions_name_the_opaque_rule(tmp_path):
    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    u = enumerate_claim_universe(
        b,
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/a.bin": _sha(_OPAQUE)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    assert "opaque" in u["source"] and "root scalar" in u["source"]


def test_source_conventions_name_the_evidence_tests(tmp_path):
    """The statement rides universe_sha, so it is the receipt's claim. v2
    said opaque bytes carry "no UTF BOM" while the classifier admitted
    BOM-prefixed prose, and it named only two structural tests. v3 names
    each evidence test, each limit and each structured refusal. (Phrase
    presence only; the behaviour behind each phrase is pinned by the
    witness and limit tests above.)"""
    from audit_bundle.claimset import CLAIMSET_CONVENTIONS_VERSION

    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    source = enumerate_claim_universe(
        b,
        bundle_id="x",
        claim_files={},
        manifest_files={"payload/a.bin": _sha(_OPAQUE)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )["source"]
    assert CLAIMSET_CONVENTIONS_VERSION == "claimset-conventions/v3"
    assert "no UTF BOM" not in source
    for phrase in (
        "integer tokens over 600 digits",
        "not NFC",
        "format (Cf) character",
        "each line in its own detected encoding",
        "as json.loads reads its UTF-8 bytes",
        "split at LF only",
        "C0 control characters",
        "integers of any length",
        "str.splitlines",
        "an object or array holding a member",
        "holding no member is not evidence",
        "a UTF BOM alone is not evidence",
        "whole-document reader",
        "JSONC comments, trailing commas allowed",
        "RFC 7464",
        "XSSI guard",
        "for(;;);",
        "while(1);",
        "nesting reaches 1024 levels before its first syntax error",
        "parse only text that, trimmed, starts and ends as a JSON value can",
        "check, by sampling,",
        "not modelled",
        "JSON5",
        "leniency on one line",
        "a value spanning several lines after a line nothing reads",
        "an array holding no object on a line of the str.splitlines split",
        "or as an array holding such an object",
        "with invalid bytes dropped",
        "a Latin-1 fallback, where byte 0x85 is NEL",
        "also decoded as UTF-8",
        "readers that stop at the first error",
        "truncated JSONC",
        "U+FEFF once decoded",
        "does not read as one JSON value and has more than 1000000 non-blank lines",
        "integer-digit and recursion limits lifted",
        "stdlib_reads_as_json",
    ):
        assert phrase in source, phrase
    # and the behaviour behind "a UTF BOM alone is not evidence"
    (tmp_path / "prose").mkdir()
    _admitted_opaque(tmp_path / "prose", "a UTF-16 prose note\n".encode("utf-16"))


# ---------------------------------------------------------------------------
# Verdict face — the gate end to end
# ---------------------------------------------------------------------------


def _opaque_bundle(tmp_path, *, claimset=None, raw=_OPAQUE):
    cs = (
        {"opaque_claim_files": {"artifact": "payload/a.bin"}}
        if claimset is None
        else claimset
    )
    return _write_bundle(tmp_path, {"payload/a.bin": raw}, claimset=cs)


def test_bound_opaque_element_is_ok_and_discloses_n_opaque(tmp_path):
    b = _opaque_bundle(tmp_path)
    v = BundleVerifier(
        plugins=[_ByteBinder("payload/a.bin", _OPAQUE, "artifact")]
    ).verify(b)
    assert v.ok, [(r.code, r.detail) for r in v.reasons]
    (line,) = _claimset_lines(v)
    assert "n_universe=1" in line and "n_covered=1(self-reported)" in line
    assert "n_opaque=1" in line


def test_unbound_opaque_element_is_could_not_conclude(tmp_path):
    b = _opaque_bundle(tmp_path)
    v = BundleVerifier(plugins=[]).verify(b)
    assert v.ok is False
    (r,) = _claimset_reasons(v)
    assert "1 of 1" in r.detail and "'artifact'" in r.detail


def test_anti_demotion_rejects_on_the_verdict_face(tmp_path):
    b = _opaque_bundle(tmp_path, raw=json.dumps({"a": 1, "b": 2}).encode())
    v = BundleVerifier(plugins=[_Reporter({"artifact"})]).verify(b)
    assert v.ok is False
    (r,) = _claimset_reasons(v)
    assert r.code == CLAIMSET_ENUMERATION_FAILED and "declared opaque" in r.detail


def test_opaque_element_can_be_excused_beside_a_covered_element(tmp_path):
    claims = json.dumps({"x": 1}).encode()
    files = {"payload/claims.json": claims, "payload/a.bin": _OPAQUE}
    b = _write_bundle(
        tmp_path,
        files,
        claimset={
            "claim_files": {"claims": "payload/claims.json"},
            "opaque_claim_files": {"artifact": "payload/a.bin"},
            "residuals": {"artifact": "ATTESTED_NOT_REDERIVED"},
        },
    )
    v = BundleVerifier(
        plugins=[_Reporter({"claims:x"}, files=("payload/claims.json",))]
    ).verify(b)
    assert v.ok, [(r.code, r.detail) for r in v.reasons]
    (line,) = _claimset_lines(v)
    assert "n_withheld=1" in line and line.endswith("n_opaque=1")


def test_all_excused_declaration_is_the_vacuity_exploit_and_rejects(tmp_path):
    """Design-audit finding 4: an all-excused declaration used to mint a green
    receipt with n_covered=0 (structured shown here; an opaque element cannot
    even carry INSPECTION_ONLY — see the claim-denying-reason test)."""
    claims = json.dumps({"x": 1}).encode()
    b = _write_bundle(
        tmp_path,
        {"payload/claims.json": claims},
        claimset={
            "claim_files": {"claims": "payload/claims.json"},
            "residuals": {"claims:x": "INSPECTION_ONLY"},
        },
    )
    v = BundleVerifier(plugins=[]).verify(b)
    assert v.ok is False
    (r,) = _claimset_reasons(v)
    assert r.code == "CLAIMSET_RESIDUAL_INCOHERENT" and "covers nothing" in r.detail


@pytest.mark.parametrize(
    "reason", ["NO_BINDING_TARGET", "DERIVED_FROM_COVERED", "INSPECTION_ONLY"]
)
def test_opaque_element_cannot_carry_a_claim_denying_reason(tmp_path, reason):
    claims = json.dumps({"x": 1}).encode()
    files = {"payload/claims.json": claims, "payload/a.bin": _OPAQUE}
    b = _write_bundle(
        tmp_path,
        files,
        claimset={
            "claim_files": {"claims": "payload/claims.json"},
            "opaque_claim_files": {"artifact": "payload/a.bin"},
            "residuals": {"artifact": reason},
        },
    )
    v = BundleVerifier(
        plugins=[_Reporter({"claims:x"}, files=("payload/claims.json",))]
    ).verify(b)
    assert v.ok is False
    assert any(
        r.code == "CLAIMSET_RESIDUAL_INCOHERENT" and "opaque" in r.detail
        for r in _claimset_reasons(v)
    )


def test_covered_file_must_be_audited_by_the_covering_plugin(tmp_path):
    """Design-audit finding 2(ii): a plugin emitting a constant key could
    credit a decoy file it never opened. The declared file must appear in a
    covering plugin's files_audited."""
    b = _opaque_bundle(tmp_path)
    v = BundleVerifier(plugins=[_Reporter({"artifact"}, files=())]).verify(b)
    assert v.ok is False
    (r,) = _claimset_reasons(v)
    assert r.code == "CLAIMSET_COVERED_FILE_UNAUDITED" and "payload/a.bin" in r.detail


def test_decoy_path_swap_is_refused_not_green(tmp_path):
    """The executed attack from the design audit: declare a decoy as the
    opaque claim while the real comparator binds a different file."""
    files = {"payload/real.bin": _OPAQUE, "payload/decoy.bin": _OPAQUE + b"x"}
    b = _write_bundle(
        tmp_path, files, claimset={"opaque_claim_files": {"artifact": "payload/decoy.bin"}}
    )
    # the comparator binds real.bin and reports the constant key
    v = BundleVerifier(
        plugins=[_ByteBinder("payload/real.bin", _OPAQUE, "artifact")]
    ).verify(b)
    assert v.ok is False
    assert any(r.code == "CLAIMSET_COVERED_FILE_UNAUDITED" for r in v.reasons)


def test_absolute_files_audited_under_the_bundle_normalizes(tmp_path):
    b = _opaque_bundle(tmp_path)

    class _Abs(_ByteBinder):
        def check(self, bundle_dir, manifest):
            r = super().check(bundle_dir, manifest)
            return PluginResult(
                ok=r.ok,
                reason_code=r.reason_code,
                detail=r.detail,
                files_audited=(str(Path(bundle_dir) / "payload" / "a.bin"),),
                verified_claim_fields=r.verified_claim_fields,
            )

    v = BundleVerifier(plugins=[_Abs("payload/a.bin", _OPAQUE, "artifact")]).verify(b)
    assert v.ok, [(r.code, r.detail) for r in v.reasons]


def test_declared_paths_ride_universe_sha(tmp_path):
    """Design-audit finding 2(i): the anchor commits the FILES, not just the
    key — the same key over a different declared path is a different
    universe."""
    files = {"payload/a.bin": _OPAQUE, "payload/b.bin": _OPAQUE}
    b = _write_bundle(tmp_path, files)
    pins = {rel: _sha(raw) for rel, raw in files.items()}
    ua = enumerate_claim_universe(
        b, bundle_id="x", claim_files={}, manifest_files=pins,
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    ub = enumerate_claim_universe(
        b, bundle_id="x", claim_files={}, manifest_files=pins,
        opaque_claim_files={"artifact": "payload/b.bin"},
    )
    assert ua["elements"] == ub["elements"] == ["artifact"]
    assert ua["universe_sha"] != ub["universe_sha"]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2,"b":3}',
        b'{"x":1}\ngarbage\n',
        b'garbage\n{"x":1}\n',
        b'[1]\n{"a":1,"a":2}\n',
        b'{"a":1,"b":2,}',
        b'{"a":1,"b":2',
        b'\xef\xbb\xbf{"a":1,"b":2}',
        '{"a":1,"b":2}'.encode("utf-16"),
        '{"a":1,"b":2}'.encode("utf-16-le"),  # BOM-less: json.loads(bytes) still reads it
        '{"a":1,"b":2}'.encode("utf-32-be"),
        b'// comment\n{"a":1}',
        b'  [1, 2, 3',
        'garbage\n{"x":1}\n'.encode("utf-16"),
        'garbage\n{"x":1}\n'.encode("utf-16-le"),
        'garbage\n{"x":1}\n'.encode("utf-32-be"),
        '{"a":1,"b":2'.encode("utf-16"),
        '{"a":1,"b":2'.encode("utf-16-le"),
        '{"a":1,"b":2'.encode("utf-16") + b"x",
        b"NaN",
        b"1\n-Infinity\n",
        b"9" * 700,
        b"garbage\nNaN\n",
        b"garbage\n" + b"9" * 700 + b"\n",
    ],
    ids=[
        "dup-key",
        "jsonl-last-line-corrupt",
        "jsonl-first-line-corrupt",
        "jsonl-dup-key",
        "trailing-comma",
        "truncated",
        "utf8-bom",
        "utf16",
        "utf16-le-no-bom",
        "utf32-be-no-bom",
        "comment-then-object",
        "open-bracket-only",
        # the jsonl-first-line-corrupt body re-encoded: its UTF-8 spelling was
        # CORRUPT while these three were NOT_JSON_SHAPED (opaque-admissible),
        # so an encoding changed the kind — found consolidating the classifier
        "utf16-jsonl-first-line-corrupt",
        "utf16-le-no-bom-jsonl-first-line-corrupt",
        "utf32-be-no-bom-jsonl-first-line-corrupt",
        # truncated JSON in UTF-16: only the decoded container-opener test
        # sees it (nothing reads); a mutant dropping that test survived
        "utf16-truncated",
        "utf16-le-no-bom-truncated",
        # an odd length does not decode: the first character is found by the
        # replacement decode, and a mutant switching that path off survived
        "utf16-truncated-odd-length",
        # the strict parser's semantic refusals on a SCALAR body: no '{'/'['
        # backs them up, so demoting them to "not JSON" made these opaque
        # (the stdlib reader reads all three); a mutant doing that survived
        "bare-nan",
        "jsonl-scalar-infinity",
        "oversized-int-scalar",
        # the strict reader must still see a row after one that does not
        # read: a mutant that skips bracket-less rows there survived
        "nan-after-garbage",
        "oversized-int-after-garbage",
    ],
)
def test_json_shaped_but_corrupt_is_refused_under_every_declaration(tmp_path, raw):
    """Design-audit finding 1 / K5, widened after the red team: a corrupted,
    re-encoded or container-opened structured file has NO declaration — not
    structured (corrupt) and not opaque (JSON-shaped)."""
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    pins = {"payload/a.bin": _sha(raw)}
    with pytest.raises(ClaimsetError, match="corrupt"):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={}, manifest_files=pins,
            opaque_claim_files={"artifact": "payload/a.bin"},
        )
    with pytest.raises(ClaimsetError, match="corrupt|duplicate|BOM"):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={"artifact": "payload/a.bin"}, manifest_files=pins,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"[" * 70 + b"]" * 70,
        b"[" * 65 + json.dumps({f"f{i}": i for i in range(30)}).encode() + b"]" * 65,
        b"[" * 65 + b'{"a":1,"a":2}' + b"]" * 65,
        (b"[" * 70 + b"1" + b"]" * 70 + b"\n") * 2,
    ],
    ids=["deep-empty", "deep-wrapped-30-fields", "deep-dup-key", "deep-jsonl"],
)
def test_strict_json_past_the_depth_bound_is_refused_under_every_declaration(tmp_path, raw):
    """All three audit lenses: admission's depth bound refuses these as
    structured; they must NOT become opaque (a 30-field claim wrapped in 65
    brackets would collapse to one element). The iterative scanner classifies
    them JSON_OVER_DEPTH, admitted nowhere."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    # the kind, AND no documents: the scanner reads syntax only, so nothing
    # it returns is a document (a mutant leaking its bytes as docs survived)
    assert classify_kind(raw, "t") == (ClaimBytesKind.JSON_OVER_DEPTH, [])
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    pins = {"payload/a.bin": _sha(raw)}
    with pytest.raises(ClaimsetError, match="depth"):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={}, manifest_files=pins,
            opaque_claim_files={"artifact": "payload/a.bin"},
        )
    with pytest.raises(ClaimsetError, match="depth"):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={"artifact": "payload/a.bin"}, manifest_files=pins,
        )


@pytest.mark.parametrize("deep", [False, True], ids=["within-depth", "past-depth"])
def test_row_ceiling_refuses_on_both_depth_branches(tmp_path, monkeypatch, deep):
    """The JSONL row ceiling refused a >ceiling body only when it was within
    the depth bound: the past-depth branch skipped its line scan instead and
    fell through to NOT_JSON_SHAPED, so ONE nested line turned a refused
    object-per-line file into an admitted opaque element. Both branches now
    refuse. The ceiling is shrunk to 4 so the case runs in milliseconds."""
    from audit_bundle import claimset

    monkeypatch.setattr(claimset, "_MAX_JSONL_ROWS", 4)
    raw = b"garbage\n" + b'{"a":1}\n' * 5 + (b"[" * 70 + b"\n" if deep else b"")
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    pins = {"payload/a.bin": _sha(raw)}
    for decl in (
        {"claim_files": {}, "opaque_claim_files": {"artifact": "payload/a.bin"}},
        {"claim_files": {"artifact": "payload/a.bin"}},
    ):
        with pytest.raises(ClaimsetError, match="ceiling"):
            enumerate_claim_universe(b, bundle_id="x", manifest_files=pins, **decl)


@pytest.mark.parametrize("depth", [9_990, 100_000], ids=["near-threshold", "far-past"])
def test_depth_hidden_by_an_unbalanced_quote_never_reaches_the_parser(tmp_path, depth):
    """`admit_bytes` carries string state across lines, so the unbalanced
    quote on line 1 hid line 2's brackets from the whole-body depth scan and
    line 2 went to the recursive parser: RecursionError out of the classifier
    (a crash-class ERROR on the verdict, not a REJECT), at a threshold that
    moved with the caller's stack depth. The strict reader now bounds depth
    per value: a clean refusal, the same kind at any stack depth."""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    raw = b'"\n' + b"[" * depth + b"]" * depth

    def at_stack_depth(n):
        return at_stack_depth(n - 1) if n else classify_kind(raw, "t")

    corrupt = (ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, [])
    assert classify_kind(raw, "t") == corrupt
    assert at_stack_depth(400) == corrupt
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    pins = {"payload/a.bin": _sha(raw)}
    for decl in (
        {"claim_files": {}, "opaque_claim_files": {"artifact": "payload/a.bin"}},
        {"claim_files": {"artifact": "payload/a.bin"}},
    ):
        with pytest.raises(ClaimsetError, match="corrupt"):
            enumerate_claim_universe(b, bundle_id="x", manifest_files=pins, **decl)


def test_deep_unbalanced_binary_is_still_opaque(tmp_path):
    """The false-refusal the depth-as-classifier rule exists to avoid: honest
    binary with >64 unbalanced openers is NOT JSON and must enumerate."""
    raw = b'"' + b"{" * 500 + b"[" * 500 + b"\xff\x00"
    b = _write_bundle(tmp_path, {"payload/a.bin": raw})
    u = enumerate_claim_universe(
        b, bundle_id="x", claim_files={}, manifest_files={"payload/a.bin": _sha(raw)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    assert u["elements"] == ["artifact"]


def test_a_form_feed_line_is_blank_to_the_structured_reader():
    """The strict reader reads LINES when the body does not read whole; a line
    that bytes.strip() empties (a form feed) is blank, so one object line
    after it is JSONL. (Behaviour pin. `_json_body`'s one-line shortcut
    compares exact bytes; widening it to JSON-whitespace-stripped bytes is
    an equivalent mutant for the two readers that use it, which ignore JSON
    whitespace and detect no encoding. It matters for an encoding-detecting
    reader, and `_looks_json_shaped` keeps its own exact comparison.)"""
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    assert classify_kind(b'\x0c\n{"a": 1}\n', "t") == (ClaimBytesKind.JSONL, [{"a": 1}])


def test_hollow_is_a_kind_and_is_refused_everywhere(tmp_path):
    from audit_bundle.claimset import ClaimBytesKind, classify_kind

    assert classify_kind(b"", "t")[0] is ClaimBytesKind.HOLLOW
    assert classify_kind(b" \n\t", "t")[0] is ClaimBytesKind.HOLLOW


@pytest.mark.parametrize(
    "rel", ["./payload/a.bin", "payload//a.bin", "/payload/a.bin", "payload/../payload/a.bin", "payload/./a.bin", "payload\\a.bin", " payload/a.bin"]
)
def test_non_canonical_declared_path_is_refused_at_the_parse_boundary(rel):
    """Red-team finding 3: injectivity compared raw strings while the
    matchers normalized, so './payload/x' and 'payload//x' were N keys on one
    file. Non-canonical spellings are refused, never normalized."""
    with pytest.raises(ClaimsetError, match="canonical"):
        validate_claimset_declaration({"opaque_claim_files": {"artifact": rel}})


def test_duplicate_declared_path_is_refused():
    with pytest.raises(ClaimsetError, match="declared twice"):
        validate_claimset_declaration(
            {"opaque_claim_files": {"a": "payload/x.bin", "b": "payload/x.bin"}}
        )
    with pytest.raises(ClaimsetError, match="declared twice"):
        validate_claimset_declaration(
            {"claim_files": {"a": "payload/x.json"}, "opaque_claim_files": {"b": "payload/x.json"}}
        )


@pytest.mark.parametrize("key", ["cafe\u0301", "a\u200bb"], ids=["non-nfc", "zero-width"])
def test_key_hygiene_matches_the_helper_and_is_a_clean_reject(tmp_path, key):
    """Red-team finding 4: the vendored helper refuses non-NFC / format-char
    elements with ClosedUniverseError, which escaped the guard as a
    crash-class ERROR. Now refused at the parse boundary, and the guard
    catches the helper too."""
    with pytest.raises(ClaimsetError):
        validate_claimset_declaration({"opaque_claim_files": {key: "payload/a.bin"}})
    # and through the verdict path: REJECT, never ERROR
    b = _write_bundle(
        tmp_path, {"payload/a.bin": _OPAQUE}, claimset={"opaque_claim_files": {key: "payload/a.bin"}}
    )
    v = BundleVerifier(plugins=[]).verify(b)
    assert v.state.value == "REJECT", (v.state, [(r.code, r.detail[:80]) for r in v.reasons])


def test_structured_claim_file_with_format_char_key_is_a_clean_reject(tmp_path):
    raw = json.dumps({"a\u200bb": 1}).encode()
    b = _write_bundle(
        tmp_path, {"payload/c.json": raw}, claimset={"claim_files": {"claims": "payload/c.json"}}
    )
    v = BundleVerifier(plugins=[]).verify(b)
    assert v.state.value == "REJECT", (v.state, [(r.code, r.detail[:80]) for r in v.reasons])


def test_file_audit_fold_is_per_result_not_a_union(tmp_path):
    """Claims-lens finding 3: plugin A (lists the file, covers x) must not
    launder plugin B (lists nothing, covers y)."""
    raw = json.dumps({"x": 1, "y": 2}).encode()
    b = _write_bundle(
        tmp_path, {"payload/c.json": raw}, claimset={"claim_files": {"claims": "payload/c.json"}}
    )
    honest = _Reporter({"claims:x"}, files=("payload/c.json",))
    launderer = _Reporter({"claims:y"}, files=())
    v = BundleVerifier(plugins=[honest, launderer]).verify(b)
    assert v.ok is False
    assert any(r.code == "CLAIMSET_COVERED_FILE_UNAUDITED" for r in v.reasons)


def test_failing_or_incomplete_results_contribute_no_coverage(tmp_path):
    """Round-2 finding 9: a comparator that REFUSED (or could not conclude)
    used to have its reported fields folded into the receipt numerator."""
    b = _opaque_bundle(tmp_path)

    class _RefusesButReports:
        name = "refuses_but_reports"

        def check(self, bundle_dir, manifest) -> PluginResult:
            return PluginResult(
                ok=False, reason_code="X_MISMATCH", detail="refused",
                files_audited=("payload/a.bin",), verified_claim_fields=frozenset({"artifact"}),
            )

    v = BundleVerifier(plugins=[_RefusesButReports()]).verify(b)
    assert v.ok is False
    assert not [d for d in v.completeness.disclosures if "receipt_sha=" in d]


def test_two_keys_resolving_to_one_file_are_refused(tmp_path):
    """Round-2 finding 10: string canonicality is not file identity."""
    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    link = b / "payload" / "b.bin"
    try:
        link.symlink_to(b / "payload" / "a.bin")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    pins = {"payload/a.bin": _sha(_OPAQUE), "payload/b.bin": _sha(_OPAQUE)}
    with pytest.raises(ClaimsetError, match="resolve to the same file"):
        enumerate_claim_universe(
            b, bundle_id="x", claim_files={}, manifest_files=pins,
            opaque_claim_files={"a": "payload/a.bin", "b": "payload/b.bin"},
        )


@pytest.mark.parametrize("rel", ["payload/cafe\u0301.bin", "payload/a\u200b.bin", "payload/a\nb.bin"])
def test_non_nfc_or_control_character_paths_are_refused(rel):
    with pytest.raises(ClaimsetError, match="canonical"):
        validate_claimset_declaration({"opaque_claim_files": {"artifact": rel}})


def test_conventions_version_rides_universe_sha(tmp_path):
    from audit_bundle.claimset import CLAIMSET_CONVENTIONS_VERSION

    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    u = enumerate_claim_universe(
        b, bundle_id="x", claim_files={}, manifest_files={"payload/a.bin": _sha(_OPAQUE)},
        opaque_claim_files={"artifact": "payload/a.bin"},
    )
    assert u["source"].startswith(CLAIMSET_CONVENTIONS_VERSION + " | ")


def test_admission_table_is_a_closed_disjoint_partition_with_corrupt_in_no_row():
    from audit_bundle.claimset import DECLARATION_ADMITS, ClaimBytesKind

    rows = list(DECLARATION_ADMITS.values())
    admitted = frozenset().union(*rows)
    assert sum(len(r) for r in rows) == len(admitted), "a kind is admitted by two declarations"
    unadmitted = {
        ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT,
        ClaimBytesKind.JSON_OVER_DEPTH,
        ClaimBytesKind.HOLLOW,
    }
    assert not (admitted & unadmitted)
    assert admitted | unadmitted == frozenset(ClaimBytesKind)


def test_receipt_line_byte_stable_across_runs(tmp_path):
    b = _opaque_bundle(tmp_path)
    mk = lambda: BundleVerifier(  # noqa: E731
        plugins=[_ByteBinder("payload/a.bin", _OPAQUE, "artifact")]
    )
    assert _claimset_lines(mk().verify(b)) == _claimset_lines(mk().verify(b))


def test_anchor_admits_matching_and_rejects_shrunk_opaque_denominator(tmp_path):
    claims = json.dumps({"x": 1}).encode()
    files = {"payload/claims.json": claims, "payload/a.bin": _OPAQUE}
    full = {
        "claim_files": {"claims": "payload/claims.json"},
        "opaque_claim_files": {"artifact": "payload/a.bin"},
    }
    b = _write_bundle(tmp_path, files, claimset=full, name="full")
    anchor = _enumerate(b)["universe_sha"]
    plugins = [
        _ByteBinder("payload/a.bin", _OPAQUE, "artifact"),
        _Reporter({"claims:x"}, files=("payload/claims.json",)),
    ]
    ok = BundleVerifier(plugins=plugins, claimset_expected_universe_sha=anchor).verify(
        b
    )
    assert ok.ok, [(r.code, r.detail) for r in ok.reasons]
    assert "universe=anchored" in _claimset_lines(ok)[0]

    shrunk = _write_bundle(
        tmp_path,
        files,
        claimset={"claim_files": {"claims": "payload/claims.json"}},
        name="shrunk",
    )
    bad = BundleVerifier(plugins=plugins, claimset_expected_universe_sha=anchor).verify(
        shrunk
    )
    assert bad.ok is False
    assert any(r.code == "CLAIMSET_UNIVERSE_ANCHOR_MISMATCH" for r in bad.reasons)


def test_undeclared_path_is_byte_identical(tmp_path):
    """K2 on a synthetic bundle: with no claimset the verdict carries only the
    not-declared disclosure."""
    b = _write_bundle(tmp_path, {"payload/a.bin": _OPAQUE})
    v = BundleVerifier(plugins=[]).verify(b)
    assert v.ok
    (line,) = _claimset_lines(v)
    assert line.startswith("claimset: not declared")


_COMMITTED_UNDECLARED = [
    "examples/chat_log_redaction_minimal",
    "examples/climate_emission_minimal",
    "examples/dc_emissions_mrv_minimal",
]


@pytest.mark.parametrize("rel", _COMMITTED_UNDECLARED)
def test_p4_committed_undeclared_bundles_verify_identically_with_the_guard_disabled(rel):
    """P4 (K2), measured: for committed example bundles that declare no
    claimset, the verdict with the claimset guard replaced by a no-op equals
    the real verdict in state, reason codes and disclosures, except for
    exactly the one not-declared disclosure the guard adds."""
    pkg = Path(__file__).resolve().parents[1]
    bundle = pkg / rel
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert "claimset" not in manifest, rel

    real = BundleVerifier().verify(bundle)

    class _NoGuard(BundleVerifier):
        def _step_claimset_coverage_guard(self, *a, **kw):  # type: ignore[override]
            return None

    without = _NoGuard().verify(bundle)
    assert real.state == without.state
    assert [r.code for r in real.reasons] == [r.code for r in without.reasons]
    extra = [d for d in real.completeness.disclosures if d not in without.completeness.disclosures]
    assert extra == ["claimset: not declared — per-field claim coverage is unaccounted for this bundle (payload claim files may carry fields no wired check reads)"]
    assert [d for d in without.completeness.disclosures if d not in real.completeness.disclosures] == []


def test_disclosure_helper_n_opaque_default_is_zero_and_omitted_or_explicit(tmp_path):
    """Structured-only declarations keep reading the same (n_opaque=0)."""
    claims = json.dumps({"x": 1}).encode()
    b = _write_bundle(
        tmp_path,
        {"payload/claims.json": claims},
        claimset={"claim_files": {"claims": "payload/claims.json"}},
    )
    u = _enumerate(b)
    receipt = build_claimset_receipt(u, {"claims:x"}, {})
    assert "n_opaque=0" in claimset_disclosure(receipt)


# ---------------------------------------------------------------------------
# Ratchet — kind by declaration, structure by content
# ---------------------------------------------------------------------------


def _ratchet():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from claimset_ratchet import run_claimset_ratchet  # noqa: E402

    return run_claimset_ratchet


def test_ratchet_flips_a_bound_opaque_element(tmp_path):
    b = _opaque_bundle(tmp_path)
    mk = lambda: BundleVerifier(  # noqa: E731
        plugins=[_ByteBinder("payload/a.bin", _OPAQUE, "artifact")]
    )
    report = _ratchet()(
        b, mk, tmp_path / "scratch",
        comparator_codes={"RE_DERIVATION_MISMATCH"},
    )
    assert report.baseline_state == "OK"
    assert [o.element for o in report.flipped] == ["artifact"]
    assert not report.survived and not report.skipped and not report.inconclusive
    (o,) = report.flipped
    # The COMPARATOR's own code, not the generic wrapper: _step_typed_check_plugins
    # now propagates PluginResult.reason_code onto the verdict face, so this
    # asserts the byte-binder specifically refused the mutation. BAD_FILE_SHA
    # must be absent -- the re-pin makes the mutation producer-consistent, so an
    # integrity-walk flip would prove nothing about binding.
    assert "RE_DERIVATION_MISMATCH" in o.reason_codes, o.reason_codes
    assert "BAD_FILE_SHA" not in o.reason_codes, o.reason_codes
    assert dict(o.positions) == {
        p: "FLIPPED" for p in ("first", "middle", "last", "truncate", "append")
    }
    # the verdict carries the plugin's DETAIL; the comparator's own words must be there
    assert any("bundled artifact bytes differ" in d for _, d in o.reasons), o.reasons


def test_ratchet_reports_a_vacuous_opaque_declaration_as_survived(tmp_path):
    """A plugin that REPORTS the opaque element but never reads the bytes
    (the verify-a-copy shape) is caught: the byte flip survives."""
    b = _opaque_bundle(tmp_path)
    mk = lambda: BundleVerifier(  # noqa: E731
        plugins=[_Reporter({"artifact"}, files=("payload/a.bin",))]
    )
    report = _ratchet()(b, mk, tmp_path / "scratch",
                        comparator_codes=_DENYLIST)
    assert [o.element for o in report.survived] == ["artifact"]
    assert {o for _, o in report.survived[0].positions} == {"SURVIVED"}
    assert len(report.survived[0].positions) == 5


def test_ratchet_names_a_magic_sniff_as_survived(tmp_path):
    """Design-audit finding 7: a comparator that only checks the first
    bytes flips at byte 0 and nowhere else — reported as not bound."""
    b = _opaque_bundle(tmp_path)

    class _MagicSniff:
        name = "magic_sniff"

        def check(self, bundle_dir, manifest) -> PluginResult:
            raw = (Path(bundle_dir) / "payload/a.bin").read_bytes()
            if not raw.startswith(_OPAQUE[:4]):
                return PluginResult(
                    ok=False, reason_code="MAGIC_MISMATCH", detail="", files_audited=("payload/a.bin",)
                )
            return PluginResult(
                ok=True, reason_code="MAGIC_OK", detail="", files_audited=("payload/a.bin",),
                verified_claim_fields=frozenset({"artifact"}),
            )

    report = _ratchet()(b, lambda: BundleVerifier(plugins=[_MagicSniff()]), tmp_path / "s",
                        comparator_codes={"MAGIC_MISMATCH"})
    (o,) = report.outcomes
    assert o.outcome == "SURVIVED" and "magic" in o.detail
    assert dict(o.positions) == {
        "first": "FLIPPED",
        "middle": "SURVIVED",
        "last": "SURVIVED",
        "truncate": "SURVIVED",
        "append": "SURVIVED",
    }


def test_ratchet_catches_a_length_blind_comparator(tmp_path):
    """Red-team finding 6: a comparator binding exactly three positions
    passes position probes; the length probes catch it."""
    b = _opaque_bundle(tmp_path)
    n = len(_OPAQUE)

    class _ThreeBytes:
        name = "three_bytes"

        def check(self, bundle_dir, manifest) -> PluginResult:
            raw = (Path(bundle_dir) / "payload/a.bin").read_bytes()
            ok = (
                len(raw) >= n
                and raw[0] == _OPAQUE[0]
                and raw[n // 2] == _OPAQUE[n // 2]
                and raw[n - 1] == _OPAQUE[n - 1]
            )
            if not ok:
                return PluginResult(
                    ok=False, reason_code="POS_MISMATCH", detail="", files_audited=("payload/a.bin",)
                )
            return PluginResult(
                ok=True, reason_code="POS_OK", detail="", files_audited=("payload/a.bin",),
                verified_claim_fields=frozenset({"artifact"}),
            )

    report = _ratchet()(b, lambda: BundleVerifier(plugins=[_ThreeBytes()]), tmp_path / "s",
                        comparator_codes={"POS_MISMATCH"})
    (o,) = report.outcomes
    assert o.outcome == "SURVIVED" and "length is unbound" in o.detail
    assert dict(o.positions)["append"] == "SURVIVED"


def test_ratchet_probe_plan_collapses_for_tiny_files():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from claimset_ratchet import _opaque_probe_plan

    assert _opaque_probe_plan(1) == ["first", "append"]
    assert _opaque_probe_plan(2) == ["first", "middle", "truncate", "append"]
    assert _opaque_probe_plan(3) == ["first", "middle", "last", "truncate", "append"]


def test_ratchet_lists_excused_elements_on_its_face(tmp_path):
    claims = json.dumps({"x": 1}).encode()
    files = {"payload/claims.json": claims, "payload/a.bin": _OPAQUE}
    b = _write_bundle(
        tmp_path,
        files,
        claimset={
            "claim_files": {"claims": "payload/claims.json"},
            "opaque_claim_files": {"artifact": "payload/a.bin"},
            "residuals": {"artifact": "ATTESTED_NOT_REDERIVED"},
        },
    )

    class _X:
        name = "x"

        def check(self, bundle_dir, manifest) -> PluginResult:
            body = json.loads((Path(bundle_dir) / "payload/claims.json").read_bytes())
            if body != {"x": 1}:
                return PluginResult(ok=False, reason_code="X_MISMATCH", detail="", files_audited=("payload/claims.json",))
            return PluginResult(ok=True, reason_code="X_OK", detail="", files_audited=("payload/claims.json",), verified_claim_fields=frozenset({"claims:x"}))

    report = _ratchet()(b, lambda: BundleVerifier(plugins=[_X()]), tmp_path / "s",
                        comparator_codes={"X_MISMATCH"})
    assert report.excused == ("artifact",)
    assert [o.element for o in report.flipped] == ["claims:x"]


def test_ratchet_scores_a_plugin_crash_as_inconclusive(tmp_path):
    """Design-audit finding 7B: a decoder that CRASHES on corrupt bytes is
    could-not-conclude, never a comparator refusal."""
    b = _opaque_bundle(tmp_path)

    class _Crasher:
        name = "crasher"

        def check(self, bundle_dir, manifest) -> PluginResult:
            raw = (Path(bundle_dir) / "payload/a.bin").read_bytes()
            if raw != _OPAQUE:
                raise RuntimeError("decoder blew up on corrupt input")
            return PluginResult(
                ok=True, reason_code="OK", detail="", files_audited=("payload/a.bin",),
                verified_claim_fields=frozenset({"artifact"}),
            )

    report = _ratchet()(b, lambda: BundleVerifier(plugins=[_Crasher()]), tmp_path / "s",
                        comparator_codes=_DENYLIST)
    (o,) = report.outcomes
    assert o.outcome == "INCONCLUSIVE", (o.outcome, o.detail)
    assert not report.flipped


def test_ratchet_refuses_an_all_excused_universe(tmp_path):
    claims = json.dumps({"x": 1}).encode()
    b = _write_bundle(
        tmp_path,
        {"payload/claims.json": claims},
        claimset={
            "claim_files": {"claims": "payload/claims.json"},
            "residuals": {"claims:x": "INSPECTION_ONLY"},
        },
    )
    with pytest.raises(ClaimsetError, match="proves nothing|vacuity"):
        _ratchet()(b, lambda: BundleVerifier(plugins=[]), tmp_path / "s",
                        comparator_codes=_DENYLIST)


@pytest.mark.parametrize(
    "name", ["payload/claims.JSON", "payload/rows.ndjson", "payload/claims.txt"]
)
def test_ratchet_cell_mutates_structured_files_regardless_of_extension(tmp_path, name):
    """The enumerator decides structure by CONTENT (port-2 audit #2); the
    ratchet used to decide by extension and would byte-flip these, corrupting
    the JSON and scoring INCONCLUSIVE. Now: kind by declaration, structure by
    content — the cell is mutated and a binding comparator flips it."""
    raw = (
        b'{"x":1}\n{"x":2}\n'
        if name.endswith(".ndjson")
        else json.dumps({"x": 1}).encode()
    )
    b = _write_bundle(tmp_path, {name: raw}, claimset={"claim_files": {"claims": name}})

    class _XBinder:
        name = "x_binder"

        def check(self, bundle_dir, manifest) -> PluginResult:
            body = (Path(bundle_dir) / name).read_bytes()
            docs = classify_claim_bytes(body, name)
            expected = [{"x": 1}, {"x": 2}] if name.endswith(".ndjson") else [{"x": 1}]
            if docs != expected:
                return PluginResult(
                    ok=False, reason_code="X_MISMATCH", detail="", files_audited=(name,)
                )
            return PluginResult(
                ok=True,
                reason_code="X_OK",
                detail="",
                files_audited=(name,),
                verified_claim_fields=frozenset({"claims:x"}),
            )

    report = _ratchet()(b, lambda: BundleVerifier(plugins=[_XBinder()]), tmp_path / "s",
                        comparator_codes={"X_MISMATCH"})
    assert [o.element for o in report.flipped] == ["claims:x"], [
        (o.element, o.outcome, o.reason_codes) for o in report.outcomes
    ]
    (o,) = report.flipped
    assert "CLAIMSET_ENUMERATION_FAILED" not in o.reason_codes
