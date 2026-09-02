"""tests/test_claimset_coverage.py — the claim-field coverage gate.

The gate: when a bundle declares `claimset`, every schema-level claim-field
element enumerated from the declared claim files' pinned bytes must be either
reported read-and-compared by a wired plugin (PluginResult.verified_claim_fields)
or excused in the bundle's committed residual map — a silent remainder is
could-not-conclude (clean-ERROR), a contradiction is REJECT, and an undeclared
claimset changes nothing except one disclosure naming the absence.

Locked here, one test per refusal path (the list may grow, never shrink):
  * undeclared → inert + not-declared disclosure, verdict unchanged;
  * the REGRESSION FORGERY: a new load-bearing field added to a fully-covered
    pilot's payload, with no comparator change, fails closed by itself;
  * the FALSE DECLARATION: a plugin reporting a field it never compares
    PASSES the gate (declared coverage is a promise, not proof — the honest
    fail-open this gate does NOT close; the per-field tamper battery is the
    executable check for it);
  * enumeration refusals: unpinned / missing / unparseable / duplicate-key /
    hollow claim files, reserved-character keys;
  * partition refusals: covered-outside-universe, phantom residual,
    double-accounted element, unknown residual reason (parse boundary),
    empty claim_files declaration (parse boundary);
  * receipt identity: byte-stable disclosure across two runs; anchored
    closed-universe verify_receipt interop.

Stdlib + pytest only.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle._closed_universe import (
    ClosedUniverseError,
    build_receipt,
    verify_receipt,
)
from audit_bundle.claimset import (
    CLAIMSET_COVERED_FIELD_UNKNOWN,
    CLAIMSET_ENUMERATION_FAILED,
    CLAIMSET_FIELD_DOUBLE_ACCOUNTED,
    CLAIMSET_NOT_DECLARED_DISCLOSURE,
    CLAIMSET_RESIDUAL_INVALID,
    ClaimsetError,
    enumerate_claim_universe,
    render_element,
)
from audit_bundle.plugin import PluginResult
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier

# ---------------------------------------------------------------------------
# Fixture: a minimal integrity-clean bundle with one claim-bearing payload file
# ---------------------------------------------------------------------------

_PAYLOAD = {
    "model_id": "m-1",
    "records": [
        {"idx": 0, "pd": 0.12, "band": "A"},
        {"idx": 1, "pd": 0.5, "band": "B"},
    ],
    "notes": "",
}

# The five schema-level elements of _PAYLOAD under payload-key "claims".
_ELEMENTS = frozenset(
    {
        "claims:model_id",
        "claims:records[].idx",
        "claims:records[].pd",
        "claims:records[].band",
        "claims:notes",
    }
)


def _write_bundle(
    tmp_path: Path,
    *,
    payload_obj: object = None,
    payload_raw: "bytes | None" = None,
    payload_name: str = "payload/claims.json",
    claimset: "dict | None" = None,
    pin_payload: bool = True,
) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "payload").mkdir()
    if payload_raw is None:
        payload_raw = json.dumps(
            _PAYLOAD if payload_obj is None else payload_obj
        ).encode("utf-8")
    (bundle_dir / payload_name).write_bytes(payload_raw)
    files = {}
    if pin_payload:
        files[payload_name] = hashlib.sha256(payload_raw).hexdigest()
    manifest = {
        "schema_version": "legacy",
        "bundle_id": "claimset-gate-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": files,
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


def _declared(payload_name: str = "payload/claims.json", **kw) -> dict:
    cs = {"claim_files": {"claims": payload_name}}
    cs.update(kw)
    return cs


class _Reporter:
    """Verifier-distribution stand-in: reports the claim fields it 'compared'.
    Reporting without comparing is exactly the false-declaration case one test
    demonstrates below."""

    name = "claimset_reporter"

    def __init__(self, fields, files=("payload/claims.json",)):
        self._fields = frozenset(fields)
        self._files = tuple(files)

    def check(self, bundle_dir, manifest) -> PluginResult:
        # files_audited names the claim file the reporter "opened" — the
        # gate's file-audit fold (CLAIMSET_COVERED_FILE_UNAUDITED) requires
        # every covered element's file to be listed by a covering plugin.
        # Listing it while never comparing is still the false-declaration
        # shape the ratchet exists to catch.
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="",
            files_audited=self._files,
            verified_claim_fields=self._fields,
        )


def _codes(verdict):
    return [(r.code, r.check_name, r.detail) for r in verdict.reasons]


def _claimset_reasons(verdict):
    return [r for r in verdict.reasons if r.check_name == "claimset_coverage"]


def _claimset_disclosures(verdict):
    return [d for d in verdict.completeness.disclosures if d.startswith("claimset:")]


# ---------------------------------------------------------------------------
# Undeclared: inert + disclosure
# ---------------------------------------------------------------------------


def test_undeclared_is_ok_with_not_declared_disclosure(tmp_path):
    verdict = BundleVerifier().verify(_write_bundle(tmp_path))
    assert verdict.state is VerdictState.OK, _codes(verdict)
    assert not _claimset_reasons(verdict)
    assert _claimset_disclosures(verdict) == [CLAIMSET_NOT_DECLARED_DISCLOSURE]


def test_undeclared_verdict_identical_except_disclosure(tmp_path):
    """The back-compat invariant: an undeclared bundle's verdict differs from
    the pre-gate world by exactly the one not-declared disclosure line."""
    verdict = BundleVerifier().verify(_write_bundle(tmp_path))
    assert verdict.ok is True
    assert verdict.reasons == ()


# ---------------------------------------------------------------------------
# Declared: full coverage, residuals, and the silent remainder
# ---------------------------------------------------------------------------


def test_fully_covered_is_ok_and_stamps_receipt_identity(tmp_path):
    bundle = _write_bundle(tmp_path, claimset=_declared())
    verdict = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "receipt_sha=" in line and "universe_sha=" in line
    assert "n_universe=5 n_covered=5(self-reported) n_withheld=0" in line
    assert "universe=producer-declared" in line


def test_receipt_disclosure_is_byte_stable_across_runs(tmp_path):
    bundle = _write_bundle(tmp_path, claimset=_declared())
    v1 = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    v2 = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    assert _claimset_disclosures(v1) == _claimset_disclosures(v2)


def test_residual_excuses_a_field(tmp_path):
    covered = _ELEMENTS - {"claims:notes"}
    bundle = _write_bundle(
        tmp_path,
        claimset=_declared(residuals={"claims:notes": "INSPECTION_ONLY"}),
    )
    verdict = BundleVerifier(
        plugins=[_Reporter(covered)]
    ).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "n_universe=5 n_covered=4(self-reported) n_withheld=1" in line
    assert '{"INSPECTION_ONLY":1}' in line


def test_unaccounted_field_is_clean_error_naming_it(tmp_path):
    covered = _ELEMENTS - {"claims:records[].pd"}
    bundle = _write_bundle(tmp_path, claimset=_declared())
    verdict = BundleVerifier(plugins=[_Reporter(covered)]).verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert reason.code == "VERIFIER_INCOMPLETE"
    assert "claims:records[].pd" in reason.detail


def test_pluginless_declared_bundle_is_clean_error(tmp_path):
    """The plugin-less laundering shape: a bundle DECLARING a claimset that
    nothing accounts for must never read OK."""
    bundle = _write_bundle(tmp_path, claimset=_declared())
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert "5 of 5" in reason.detail


def test_regression_forgery_new_payload_field_fails_closed(tmp_path):
    """THE EXECUTED REGRESSION: a fully-covered bundle grows one new
    load-bearing payload field (producer re-pins the file sha, as a producer
    legitimately does) with NO comparator change. The gate alone must fail
    closed — this is the 'Play 4' shape that previously required a fleet
    sweep to notice."""
    grown = dict(_PAYLOAD)
    grown["new_metric"] = 0.99
    bundle = _write_bundle(tmp_path, payload_obj=grown, claimset=_declared())
    verdict = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert "claims:new_metric" in reason.detail


def test_false_declaration_passes_the_gate_by_design(tmp_path):
    """The honest fail-open, demonstrated: a plugin REPORTING a field it never
    actually compares satisfies the gate (coverage reporting is a promise by
    verifier-distribution code, not proof of comparison). The executable
    check for this shape is the per-field tamper battery
    (tests/claimset_ratchet.py), not this guard."""
    bundle = _write_bundle(tmp_path, claimset=_declared())
    verdict = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    assert verdict.state is VerdictState.OK  # _Reporter compared nothing


# ---------------------------------------------------------------------------
# Partition contradictions REJECT
# ---------------------------------------------------------------------------


def test_covered_field_outside_universe_rejects(tmp_path):
    bundle = _write_bundle(tmp_path, claimset=_declared())
    verdict = BundleVerifier(
        plugins=[_Reporter(_ELEMENTS | {"claims:phantom"})]
    ).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert reason.code == CLAIMSET_COVERED_FIELD_UNKNOWN
    assert "claims:phantom" in reason.detail


def test_residual_naming_no_element_rejects(tmp_path):
    bundle = _write_bundle(
        tmp_path,
        claimset=_declared(residuals={"claims:phantom": "INSPECTION_ONLY"}),
    )
    verdict = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    assert any(r.code == CLAIMSET_RESIDUAL_INVALID for r in _claimset_reasons(verdict))


def test_double_accounted_field_rejects(tmp_path):
    bundle = _write_bundle(
        tmp_path,
        claimset=_declared(residuals={"claims:notes": "INSPECTION_ONLY"}),
    )
    verdict = BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert reason.code == CLAIMSET_FIELD_DOUBLE_ACCOUNTED
    assert "claims:notes" in reason.detail


# ---------------------------------------------------------------------------
# Parse-boundary refusals (present-but-malformed is REJECT, never absent)
# ---------------------------------------------------------------------------


def test_unknown_residual_reason_rejects_at_parse_boundary(tmp_path):
    bundle = _write_bundle(
        tmp_path, claimset=_declared(residuals={"claims:notes": "BECAUSE"})
    )
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    assert any("CLAIMSET_DECLARATION_MALFORMED" in r.detail for r in verdict.reasons)


def test_empty_claim_files_rejects_at_parse_boundary(tmp_path):
    """A declared claimset over nothing is the vacuity exploit — opting out is
    omitting the key, never declaring a hollow one."""
    bundle = _write_bundle(tmp_path, claimset={"claim_files": {}})
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    assert any("vacuity" in r.detail for r in verdict.reasons)


def test_claimset_unknown_keys_reject_at_parse_boundary(tmp_path):
    bundle = _write_bundle(tmp_path, claimset={**_declared(), "extra": True})
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)


# ---------------------------------------------------------------------------
# Enumeration refusals (fail-closed: nothing skipped, nothing downgraded)
# ---------------------------------------------------------------------------


def _assert_enumeration_reject(verdict):
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    reasons = _claimset_reasons(verdict)
    assert reasons and all(r.code == CLAIMSET_ENUMERATION_FAILED for r in reasons), (
        _codes(verdict)
    )


def test_unpinned_claim_file_rejects(tmp_path):
    bundle = _write_bundle(tmp_path, claimset=_declared(), pin_payload=False)
    _assert_enumeration_reject(
        BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    )


def test_missing_claim_file_rejects(tmp_path):
    bundle = _write_bundle(
        tmp_path, claimset=_declared(payload_name="payload/absent.json")
    )
    # the real payload exists and is pinned; the DECLARED file does not
    _assert_enumeration_reject(BundleVerifier().verify(bundle))


def test_unparseable_claim_file_rejects_never_downgrades(tmp_path):
    """A .json that cannot parse must refuse — silently downgrading it to a
    file-level element would shrink the denominator."""
    bundle = _write_bundle(tmp_path, payload_raw=b"{not json", claimset=_declared())
    _assert_enumeration_reject(BundleVerifier().verify(bundle))


def test_duplicate_object_keys_reject(tmp_path):
    raw = b'{"model_id": "m-1", "model_id": "m-2"}'
    bundle = _write_bundle(tmp_path, payload_raw=raw, claimset=_declared())
    verdict = BundleVerifier().verify(bundle)
    _assert_enumeration_reject(verdict)
    assert any("duplicate object key" in r.detail for r in verdict.reasons)


def test_reserved_character_key_rejects(tmp_path):
    bundle = _write_bundle(tmp_path, payload_obj={"a.b": 1}, claimset=_declared())
    verdict = BundleVerifier().verify(bundle)
    _assert_enumeration_reject(verdict)
    assert any("reserved character" in r.detail for r in verdict.reasons)


def test_empty_jsonl_claim_file_rejects(tmp_path):
    bundle = _write_bundle(
        tmp_path,
        payload_raw=b"\n\n",
        payload_name="payload/rows.jsonl",
        claimset=_declared(payload_name="payload/rows.jsonl"),
    )
    _assert_enumeration_reject(BundleVerifier().verify(bundle))


# ---------------------------------------------------------------------------
# Enumeration semantics: jsonl union, non-JSON file-level, root scalar
# ---------------------------------------------------------------------------


def test_jsonl_universe_is_union_of_line_paths(tmp_path):
    raw = b'{"a": 1}\n{"a": 2, "b": {"c": true}}\n'
    bundle = _write_bundle(
        tmp_path,
        payload_raw=raw,
        payload_name="payload/rows.jsonl",
        claimset=_declared(payload_name="payload/rows.jsonl"),
    )
    covered = {"claims:a", "claims:b.c"}
    verdict = BundleVerifier(plugins=[_Reporter(covered, files=("payload/rows.jsonl",))]).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "n_universe=2 n_covered=2" in line


def test_non_json_claim_file_is_refused_not_demoted(tmp_path):
    """A claim file that is neither one JSON value nor JSONL is REJECTED, never
    silently demoted to a single opaque whole-file element — the demotion
    (whether triggered by content OR by a renamed extension) is how a producer
    would shrink the denominator past a strict parser."""
    bundle = _write_bundle(
        tmp_path,
        payload_raw=b"\x00\x01binary-artifact",
        payload_name="payload/output.bin",
        claimset=_declared(payload_name="payload/output.bin"),
    )
    _assert_enumeration_reject(
        BundleVerifier(plugins=[_Reporter(_ELEMENTS)]).verify(bundle)
    )


def test_uppercase_extension_json_still_enumerates(tmp_path):
    """The classifier is content, not filename: a JSON payload named .JSON (or
    any extension) is field-enumerated, never collapsed to one opaque element
    by the extension. Regression for the extension-collapse finding."""
    bundle = _write_bundle(
        tmp_path,
        payload_name="payload/claims.JSON",
        claimset=_declared(payload_name="payload/claims.JSON"),
    )
    verdict = BundleVerifier(plugins=[_Reporter(_ELEMENTS, files=("payload/claims.JSON",))]).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "n_universe=5 n_covered=5(self-reported)" in line


def test_ndjson_extension_enumerates_as_jsonl(tmp_path):
    """A newline-delimited-JSON body named .ndjson is content-classified as a
    JSONL union, not collapsed by its unrecognized extension."""
    raw = b'{"a": 1}\n{"b": 2}\n'
    bundle = _write_bundle(
        tmp_path,
        payload_raw=raw,
        payload_name="payload/rows.ndjson",
        claimset=_declared(payload_name="payload/rows.ndjson"),
    )
    verdict = BundleVerifier(
        plugins=[_Reporter({"claims:a", "claims:b"}, files=("payload/rows.ndjson",))]
    ).verify(
        bundle
    )
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "n_universe=2 n_covered=2(self-reported)" in line


def test_heterogeneous_path_contributes_both_terminations(tmp_path):
    payload = {"records": [{"x": 1}, {"x": {"y": 2}}]}
    bundle = _write_bundle(tmp_path, payload_obj=payload, claimset=_declared())
    covered = {"claims:records[].x", "claims:records[].x.y"}
    verdict = BundleVerifier(plugins=[_Reporter(covered)]).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "n_universe=2 n_covered=2" in line


def test_render_element_shapes():
    assert render_element("claims", ()) == "claims"
    assert render_element("claims", ("a", "b")) == "claims:a.b"
    assert render_element("claims", ("records", "[]", "pd")) == "claims:records[].pd"
    assert render_element("claims", ("[]", "pd")) == "claims:[].pd"


# ---------------------------------------------------------------------------
# Closed-universe interop: the anchored verify path
# ---------------------------------------------------------------------------


def test_anchored_verify_receipt_interop(tmp_path):
    bundle = _write_bundle(tmp_path, claimset=_declared())
    manifest_files = json.loads((bundle / "manifest.json").read_text())["files"]
    universe = enumerate_claim_universe(
        bundle,
        bundle_id="claimset-gate-test",
        claim_files={"claims": "payload/claims.json"},
        manifest_files=manifest_files,
    )
    assert set(universe["elements"]) == set(_ELEMENTS)
    covered = sorted(_ELEMENTS - {"claims:notes"})
    withheld = {"claims:notes": "INSPECTION_ONLY"}
    receipt = build_receipt(universe, covered, withheld)
    verify_receipt(
        receipt,
        universe,
        covered,
        withheld,
        expected_universe_sha=universe["universe_sha"],
    )
    with pytest.raises(ClosedUniverseError):
        verify_receipt(
            receipt, universe, covered, withheld, expected_universe_sha="0" * 64
        )


def test_enumeration_is_deterministic(tmp_path):
    bundle = _write_bundle(tmp_path, claimset=_declared())
    manifest_files = json.loads((bundle / "manifest.json").read_text())["files"]
    kw = dict(
        bundle_id="claimset-gate-test",
        claim_files={"claims": "payload/claims.json"},
        manifest_files=manifest_files,
    )
    u1 = enumerate_claim_universe(bundle, **kw)
    u2 = enumerate_claim_universe(bundle, **kw)
    assert u1 == u2


def test_derived_from_covered_with_zero_covered_rejects(tmp_path):
    """The one mechanizable residual-coherence check: DERIVED_FROM_COVERED
    means recomputable from covered fields, so it is self-contradictory when
    nothing is covered."""
    bundle = _write_bundle(
        tmp_path,
        claimset=_declared(residuals={e: "DERIVED_FROM_COVERED" for e in _ELEMENTS}),
    )
    verdict = BundleVerifier().verify(bundle)  # no plugins → covered is empty
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert reason.code == "CLAIMSET_RESIDUAL_INCOHERENT"


def test_verifier_held_anchor_forces_declaration(tmp_path):
    """A verifier holding an expected universe anchor REJECTs a bundle that
    declares no claimset — closing the omit-the-key dodge for that relying
    party."""
    bundle = _write_bundle(tmp_path)  # no claimset declared
    anchor = _rege_universe_sha(tmp_path)
    verdict = BundleVerifier(
        plugins=[_Reporter(_ELEMENTS)],
        claimset_expected_universe_sha=anchor,
    ).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert reason.code == "CLAIMSET_UNIVERSE_ANCHOR_MISMATCH"


def test_verifier_held_anchor_rejects_shrunk_denominator(tmp_path):
    """A producer who ships a smaller universe than the relying party
    pre-committed to is REJECTED — the denominator cannot be shrunk or
    swapped against a held anchor."""
    # Anchor over the full 5-field payload; producer ships a 1-field payload.
    anchor = _anchor_for(tmp_path / "ref", _PAYLOAD)
    bundle = _write_bundle(
        tmp_path, payload_obj={"model_id": "m-1"}, claimset=_declared()
    )
    verdict = BundleVerifier(
        plugins=[_Reporter({"claims:model_id"})],
        claimset_expected_universe_sha=anchor,
    ).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    (reason,) = _claimset_reasons(verdict)
    assert reason.code == "CLAIMSET_UNIVERSE_ANCHOR_MISMATCH"


def test_verifier_held_anchor_admits_matching_denominator(tmp_path):
    """The honest bundle whose denominator matches the held anchor verifies,
    and the disclosure marks the universe as anchored (not producer-declared)."""
    bundle = _write_bundle(tmp_path, claimset=_declared())
    anchor = _anchor_for(tmp_path / "ref", _PAYLOAD)
    verdict = BundleVerifier(
        plugins=[_Reporter(_ELEMENTS)],
        claimset_expected_universe_sha=anchor,
    ).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)
    (line,) = _claimset_disclosures(verdict)
    assert "universe=anchored" in line


def test_anchor_must_be_64_hex(tmp_path):
    with pytest.raises(ValueError):
        BundleVerifier(claimset_expected_universe_sha="short")


def _rege_universe_sha(tmp_path: Path) -> str:
    return _anchor_for(tmp_path / "ref_default", _PAYLOAD)


def _anchor_for(ref_parent: Path, payload_obj: object) -> str:
    """The out-of-band expected_universe_sha a relying party pre-commits to:
    enumerate the universe from a REFERENCE bundle the verifier controls (not
    the bundle under test) and take its universe_sha — a genuinely externally
    held value, not the in-memory sha of the artifact being checked."""
    ref_parent.mkdir(parents=True, exist_ok=True)
    ref = _write_bundle(ref_parent, payload_obj=payload_obj)
    manifest_files = json.loads((ref / "manifest.json").read_text())["files"]
    universe = enumerate_claim_universe(
        ref,
        bundle_id="claimset-gate-test",
        claim_files={"claims": "payload/claims.json"},
        manifest_files=manifest_files,
    )
    return universe["universe_sha"]


def test_path_traversal_refused(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"a": 1}')
    bundle = _write_bundle(tmp_path)
    with pytest.raises(ClaimsetError):
        enumerate_claim_universe(
            bundle,
            bundle_id="claimset-gate-test",
            claim_files={"claims": "../outside.json"},
            manifest_files={"../outside.json": "0" * 64},
        )


def test_anchor_commits_the_field_set_not_the_row_count(tmp_path):
    """Stated limit, made executable (red-team witness on the credit_scoring
    adoption, 2026-08-20): the verifier-held universe anchor commits the
    DENOMINATOR — the observed FIELD SET — not instance cardinality. A claim
    file with ONE row carrying the same fields as a five-row file enumerates
    to the same universe_sha, so an anchored verify admits it. Row
    cardinality is the comparator's to bind (a bijection with the inputs),
    never the gate's; the guard's comment says so rather than claiming the
    anchor closes a "degenerate instance"."""
    five = {"rows": [{"id": f"r{i}", "v": i} for i in range(5)]}
    one = {"rows": [{"id": "r0", "v": 0}]}
    (tmp_path / "five").mkdir()
    (tmp_path / "one").mkdir()
    five_dir = _write_bundle(tmp_path / "five", payload_obj=five, claimset=_declared())
    one_dir = _write_bundle(tmp_path / "one", payload_obj=one, claimset=_declared())
    from audit_bundle.claimset import enumerate_claim_universe

    def _sha(bundle_dir):
        m = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        return enumerate_claim_universe(
            bundle_dir,
            bundle_id=m["bundle_id"],
            claim_files={"claims": "payload/claims.json"},
            manifest_files=m["files"],
        )["universe_sha"]

    assert _sha(five_dir) == _sha(one_dir)
    fields = {"claims:rows[].id", "claims:rows[].v"}
    anchored = BundleVerifier(
        plugins=[_Reporter(fields)], claimset_expected_universe_sha=_sha(five_dir)
    )
    assert anchored.verify(one_dir).state is VerdictState.OK
