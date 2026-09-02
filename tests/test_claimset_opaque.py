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

    assert classify_kind(raw, "t")[0] is ClaimBytesKind.JSON_OVER_DEPTH
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
