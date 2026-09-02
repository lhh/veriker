"""tests/test_spec_anchor_library.py — the LIBRARY layer refuses what the CLI
refuses (auditor-entry-point ADR D2 + its stage-1/2 mutant battery).

The CLI-only anchor guard was a laundering surface: the verifier's future
callers are GATES (relyable edges, charter dispatch, admission checks) calling
the library, not humans running `veriker/cli/verify.py`. Before this battery the
library accepted an anchor built from bundle bytes and an empty `allowed={}` —
the in-bundle tautology (measured 2026-08-17 on bom_minimal: forged claim,
comparator swapped, SHAs re-cohered -> clean verdict with re-derivation
SATISFIED) was refused only by the CLI. Every refusal below is proven at the
library layer: `SpecAnchor.from_files` and `BundleVerifier.verify`, no
subprocess anywhere.

Battery (each case names its expected reason; incidental rejection is not
binding sensitivity):

  1. in-bundle anchor path        -> AnchorConstructionError ("resolves INSIDE")
  2. symlinked in-bundle path     -> AnchorConstructionError (symlinks followed)
  3. wrong forbid_within          -> verify() refuses at the containment
                                     recheck (SPEC_ANCHOR_INSIDE_BUNDLE,
                                     VERIFIER_INCOMPLETE — construction was
                                     fooled, the verifier is not)
  4. empty allowed={} on an outputs-declaring bundle -> VERIFIER_INCOMPLETE
                                     (never a vacuous pass, never a REJECT)
  5. producer-weaker spec under a correct anchor -> AnchorViolation REJECT,
     fail-closed for the declared outputs
  6. the bom tautology: the raw-dict self-anchor still PASSES the forged bundle
     (half 1 — what makes the rest evidence), the face labels that authority
     UNVERIFIED_CALLER_SUPPLIED, and every from_files route to the same
     tautology is refused (halves 2a/2b); the committed anchor REJECTs it.
  7. honest bundle + correct out-of-bundle anchor -> PASS with zero reasons and
     the anchor's committed source path on the face (anti-vacuity: every forgery
     above must move the verdict map; this case must not).
  8. forged provenance (a hand-set tuple naming a trusted outside path over a
     self-anchored forgery) -> refused SPEC_ANCHOR_PROVENANCE_UNVERIFIED, and a
     genuine from_files source survives the same recheck.

FIXTURE — examples/bom_minimal: its primitive ships in the verifier
distribution and it needs no pilot-local plugin, so the library sees the same
plugin+primitive set every other consumer would.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
_BOM_DIR = _PKG_ROOT / "examples" / "bom_minimal"
_BOM_SPEC = _BOM_DIR / "spec_pinned" / "bom.spec.json"

from audit_bundle.rederivation.spec_binding import (  # noqa: E402
    AnchorConstructionError,
    SpecAnchor,
)


def _load_by_path(name: str, path: Path):
    """Load a pilot module by path, REUSING an existing sys.modules entry.

    Replacing the entry would create a second, equal-named primitive class and
    `register_primitive` rejects that collision — the failure mode where these
    tests pass alone and fail together. Same names as tests/test_bom_spec_pinned
    uses, so whichever file loads first, the other reuses.
    """
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _harness():
    if str(_BOM_DIR) not in sys.path:
        sys.path.insert(0, str(_BOM_DIR))
    _load_by_path("bom_recompute", _BOM_DIR / "bom_recompute.py")
    return _load_by_path("bom_spec_pinned_check", _BOM_DIR / "spec_pinned_check.py")


def _committed_anchor(bundle_dir: Path) -> SpecAnchor:
    """The blessed construction: committed spec bytes, containment enforced."""
    return SpecAnchor.from_files([_BOM_SPEC], forbid_within=bundle_dir)


def _verdict_map(result) -> tuple:
    """The full verdict map — 'caught' is a verdict-map diff, not a keyword."""
    return (
        result.state.value,
        tuple(sorted((r.check_name, r.code) for r in result.reasons)),
    )


def _anchor_disclosure(result) -> list[dict] | None:
    for d in getattr(result.completeness, "disclosures", None) or ():
        if d.startswith("spec_anchor_provenance: "):
            return json.loads(d[len("spec_anchor_provenance: ") :])
    return None


def _forge_bundle(spc, dest: Path) -> Path:
    """The measured 2026-08-17 tautology forgery, verbatim in shape: claim
    emptied, in-bundle spec's comparator swapped `exact` -> `set` (which
    compares only a dict operand's top-level KEYS), every manifest SHA
    re-cohered. Self-anchored, this bundle verifies clean."""
    bundle = spc.build_spec_pinned(dest)
    manifest_path = bundle / "manifest.json"
    output_id = json.loads(manifest_path.read_text(encoding="utf-8"))["outputs"][0][
        "output_id"
    ]
    claim_path = bundle / "outputs" / f"{output_id}.json"
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    assert claim["value"]["nodes"], "fixture must have a non-empty tree to empty out"
    claim["value"] = {"root": "x", "nodes": [], "resolution_order": []}
    raw_claim = json.dumps(claim, indent=2).encode("utf-8")
    claim_path.write_bytes(raw_claim)

    spec_path = bundle / "spec" / "bom.spec.json"
    spec_doc = json.loads(spec_path.read_text(encoding="utf-8"))
    type_key = next(iter(spec_doc["types"]))
    assert spec_doc["types"][type_key]["comparator"]["kind"] == "exact", (
        "fixture assumption: the honest spec must bind `exact`"
    )
    spec_doc["types"][type_key]["comparator"] = {"kind": "set", "params": {}}
    raw_spec = json.dumps(spec_doc, indent=2).encode("utf-8")
    spec_path.write_bytes(raw_spec)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["spec_files"]["bom.spec.json"] = hashlib.sha256(raw_spec).hexdigest()
    manifest["files"]["spec/bom.spec.json"] = hashlib.sha256(raw_spec).hexdigest()
    manifest["files"][f"outputs/{output_id}.json"] = hashlib.sha256(
        raw_claim
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return bundle


def _weaken_spec(bundle: Path) -> None:
    """Producer ships a weaker comparator in its own spec/ copy, fully
    hash-coherent — only auditor-held bytes can catch it."""
    spec_path = bundle / "spec" / "bom.spec.json"
    doc = json.loads(spec_path.read_text(encoding="utf-8"))
    type_key = next(iter(doc["types"]))
    doc["types"][type_key]["comparator"] = {
        "kind": "scalar_epsilon",
        "params": {"epsilon": 1e9},
    }
    raw = json.dumps(doc, indent=2).encode("utf-8")
    spec_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["spec_files"]["bom.spec.json"] = digest
    manifest["files"]["spec/bom.spec.json"] = digest
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# from_files: construction-time refusals (operator errors, never bundle facts)
# ---------------------------------------------------------------------------


def test_from_files_in_bundle_path_is_refused(tmp_path):
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    in_bundle = bundle / "spec" / "bom.spec.json"
    assert in_bundle.is_file()
    with pytest.raises(AnchorConstructionError) as exc:
        SpecAnchor.from_files([in_bundle], forbid_within=bundle)
    assert "resolves INSIDE" in str(exc.value), str(exc.value)


def test_from_files_symlinked_in_bundle_path_is_refused(tmp_path):
    """Containment must resolve symlinks, or the refusal is one `ln -s` away
    from a bypass."""
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    link = tmp_path / "looks_external.spec.json"
    link.symlink_to(bundle / "spec" / "bom.spec.json")
    with pytest.raises(AnchorConstructionError) as exc:
        SpecAnchor.from_files([link], forbid_within=bundle)
    assert "resolves INSIDE" in str(exc.value), str(exc.value)


def test_from_files_operator_errors_are_construction_errors(tmp_path):
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    # Empty path list: an anchor allowing nothing holds no authority.
    with pytest.raises(AnchorConstructionError):
        SpecAnchor.from_files([], forbid_within=bundle)
    # Missing file.
    with pytest.raises(AnchorConstructionError):
        SpecAnchor.from_files([tmp_path / "nope.spec.json"], forbid_within=bundle)
    # Not JSON.
    bad = tmp_path / "bad.spec.json"
    bad.write_bytes(b"{not json")
    with pytest.raises(AnchorConstructionError):
        SpecAnchor.from_files([bad], forbid_within=bundle)
    # No spec_id: must not silently produce an empty/short anchor.
    no_id = tmp_path / "no_id.spec.json"
    no_id.write_text(json.dumps({"types": {}}), encoding="utf-8")
    with pytest.raises(AnchorConstructionError):
        SpecAnchor.from_files([no_id], forbid_within=bundle)
    # Duplicate spec_id, different bytes: ambiguous authority.
    original = json.loads(_BOM_SPEC.read_text(encoding="utf-8"))
    variant = tmp_path / "variant.spec.json"
    variant.write_text(
        json.dumps({**original, "description": "different bytes, same spec_id"}),
        encoding="utf-8",
    )
    with pytest.raises(AnchorConstructionError) as exc:
        SpecAnchor.from_files([_BOM_SPEC, variant], forbid_within=bundle)
    assert "ambiguous" in str(exc.value), str(exc.value)


# ---------------------------------------------------------------------------
# verify(): the containment recheck and the empty-anchor refusal
# ---------------------------------------------------------------------------


def test_wrong_forbid_within_is_caught_at_verify_time(tmp_path):
    """from_files cannot make a caller pass the RIGHT forbid_within. An anchor
    whose attested sources sit inside the bundle actually being judged is the
    same tautology however construction was parameterized — verify() refuses it
    against the real bundle dir, as a could-not-conclude (operator error, not a
    bundle fact)."""
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    fooled = SpecAnchor.from_files(
        [bundle / "spec" / "bom.spec.json"], forbid_within=tmp_path / "elsewhere"
    )
    result = spc.make_verifier(fooled).verify(bundle)
    assert not result.ok
    assert result.state.value == "ERROR", (result.state, _verdict_map(result))
    assert [(r.check_name, r.code) for r in result.reasons] == [
        ("spec_pinned_dispatch:anchor", "VERIFIER_INCOMPLETE")
    ], _verdict_map(result)
    assert "SPEC_ANCHOR_INSIDE_BUNDLE" in result.reasons[0].detail, result.reasons[
        0
    ].detail


def test_empty_allowed_on_outputs_bundle_is_verifier_incomplete(tmp_path):
    """R3 closed: allowed={} used to land on AnchorViolation -> REJECT (a
    verifier with no authority blaming the artifact). It is the no-anchor
    absence wearing a constructor call: could-not-conclude, and never a
    vacuous pass."""
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    result = spc.make_verifier(SpecAnchor(allowed={})).verify(bundle)
    assert not result.ok
    assert result.state.value == "ERROR", _verdict_map(result)
    anchor_rows = [
        (r.check_name, r.code, r.detail)
        for r in result.reasons
        if r.check_name == "spec_pinned_dispatch:anchor"
    ]
    assert [(c, code) for c, code, _ in anchor_rows] == [
        ("spec_pinned_dispatch:anchor", "VERIFIER_INCOMPLETE")
    ], _verdict_map(result)
    assert "allows NOTHING" in anchor_rows[0][2], anchor_rows[0][2]
    assert "AnchorViolation" not in {r.code for r in result.reasons}


# ---------------------------------------------------------------------------
# The tautology, all halves, library-only
# ---------------------------------------------------------------------------


def test_bom_tautology_self_anchor_passes_and_face_says_caller_supplied(tmp_path):
    """Half 1 — the forgery is REAL through the raw-dict constructor: producer
    bytes on both sides of the comparison verify clean. This is what makes the
    refusals below evidence instead of decoration. What changed: the verdict
    face now labels that authority UNVERIFIED_CALLER_SUPPLIED, so a green
    reached this way is no longer byte-indistinguishable from an anchored one.
    """
    spc = _harness()
    forged = _forge_bundle(spc, tmp_path / "forged")
    raw_spec = (forged / "spec" / "bom.spec.json").read_bytes()
    self_anchor = SpecAnchor(
        allowed={json.loads(raw_spec)["spec_id"]: hashlib.sha256(raw_spec).hexdigest()}
    )
    result = spc.make_verifier(self_anchor).verify(forged)
    assert result.ok, (
        "half 1 must PASS or this proves nothing: the `set` comparator on a "
        "dict compares only top-level keys, so an emptied tree agrees. "
        f"failures={[(f.check_name, f.reason_code) for f in result.failures]}"
    )
    rows = _anchor_disclosure(result)
    assert rows is not None, result.completeness.disclosures
    assert [r["source"] for r in rows] == ["UNVERIFIED_CALLER_SUPPLIED"], rows


def test_bom_tautology_is_refused_on_every_from_files_route(tmp_path):
    """Halves 2a/2b — both library routes to the self-anchored tautology are
    refused: construction under the true bundle dir, and verify-time recheck
    when construction was handed a wrong forbid_within."""
    spc = _harness()
    forged = _forge_bundle(spc, tmp_path / "forged")
    # 2a: honest forbid_within -> refused before any bundle byte is judged.
    with pytest.raises(AnchorConstructionError):
        SpecAnchor.from_files([forged / "spec" / "bom.spec.json"], forbid_within=forged)
    # 2b: fooled forbid_within -> refused by verify() against the real dir.
    fooled = SpecAnchor.from_files(
        [forged / "spec" / "bom.spec.json"], forbid_within=tmp_path / "elsewhere"
    )
    result = spc.make_verifier(fooled).verify(forged)
    assert not result.ok
    assert result.state.value == "ERROR", _verdict_map(result)
    assert "SPEC_ANCHOR_INSIDE_BUNDLE" in result.reasons[0].detail


def test_bom_tautology_committed_anchor_rejects_it(tmp_path):
    """Half 3 — the operator's committed anchor stops exactly the forgery that
    self-anchoring blessed."""
    spc = _harness()
    forged = _forge_bundle(spc, tmp_path / "forged")
    result = spc.make_verifier(_committed_anchor(forged)).verify(forged)
    assert not result.ok
    assert result.state.value == "REJECT", _verdict_map(result)
    assert ("spec_pinned_dispatch:anchor", "AnchorViolation") in [
        (r.check_name, r.code) for r in result.reasons
    ], _verdict_map(result)


# ---------------------------------------------------------------------------
# Producer-weaker spec under a correct anchor; honest pass; anti-vacuity
# ---------------------------------------------------------------------------


def test_forged_provenance_cannot_launder_a_self_anchored_forgery(tmp_path):
    """The fresh-context adversarial pass (two independent red-team lenses,
    2026-08-27) SEVERE hit: `provenance` is a public field on the frozen
    SpecAnchor dataclass, so `from_files` is not the only writer a CALLER can
    use. A wrapper self-anchoring on bundle bytes could hand-set a provenance
    tuple naming a trusted OUTSIDE auditor path — passing the containment guard
    (the source string resolves outside the bundle) while the face presented it
    as an attested FILE-anchored authority with NO UNVERIFIED_CALLER_SUPPLIED
    label. The forged bundle then verified GREEN wearing a fabricated external
    authority. Closed by making the verify-time guard re-read each provenance
    source and bind its bytes to `allowed`."""
    spc = _harness()
    forged = _forge_bundle(spc, tmp_path / "forged")
    raw_spec = (forged / "spec" / "bom.spec.json").read_bytes()
    forged_sha = hashlib.sha256(raw_spec).hexdigest()
    spec_id = json.loads(raw_spec)["spec_id"]

    # (a) fabricated NONEXISTENT source, authority = the forged bundle bytes.
    fake = SpecAnchor(
        allowed={spec_id: forged_sha},
        provenance=(
            {
                "spec_id": spec_id,
                "sha256": forged_sha,
                "source": str(tmp_path / "trusted" / "bom.spec.json"),
            },
        ),
    )
    result = spc.make_verifier(fake).verify(forged)
    assert not result.ok, "forged provenance must NOT verify green"
    assert result.state.value == "ERROR", _verdict_map(result)
    assert "SPEC_ANCHOR_PROVENANCE_UNVERIFIED" in result.reasons[0].detail, (
        result.reasons[0].detail
    )
    # The fabricated source is never presented as an attested authority.
    assert _anchor_disclosure(result) is None or all(
        r.get("source") != str(tmp_path / "trusted" / "bom.spec.json")
        for r in _anchor_disclosure(result)
    )

    # (b) a source that EXISTS but whose bytes do NOT back `allowed`
    # (points at the honest committed spec, but the authority is the forgery).
    result2 = spc.make_verifier(
        SpecAnchor(
            allowed={spec_id: forged_sha},
            provenance=(
                {"spec_id": spec_id, "sha256": forged_sha, "source": str(_BOM_SPEC)},
            ),
        )
    ).verify(forged)
    assert not result2.ok
    assert result2.state.value == "ERROR", _verdict_map(result2)
    assert "SPEC_ANCHOR_PROVENANCE_UNVERIFIED" in result2.reasons[0].detail


def test_honest_from_files_provenance_survives_the_recheck(tmp_path):
    """Anti-vacuity for the guard above: a genuine from_files anchor, whose
    source bytes DO hash to `allowed`, must still pass and present its source
    (or the guard would be a blanket refusal, not a binding check)."""
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    result = spc.make_verifier(_committed_anchor(bundle)).verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]
    rows = _anchor_disclosure(result)
    assert rows and rows[0]["source"] == str(_BOM_SPEC.resolve()), rows


def test_weaker_spec_under_correct_anchor_fails_closed_for_all_outputs(tmp_path):
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    _weaken_spec(bundle)
    result = spc.make_verifier(_committed_anchor(bundle)).verify(bundle)
    assert not result.ok
    assert result.state.value == "REJECT", _verdict_map(result)
    codes = [(r.check_name, r.code) for r in result.reasons]
    # Anchor-load failure aborts dispatch BEFORE any output is recomputed, so no
    # declared output re-derived and none is recorded verified — fail-closed for
    # the whole declared set, not a per-output skip.
    assert ("spec_pinned_dispatch:anchor", "AnchorViolation") in codes, codes
    detail = next(r.detail for r in result.reasons if r.code == "AnchorViolation")
    assert "SHA_MISMATCH" in detail, detail


def test_honest_bundle_with_committed_anchor_passes_and_face_is_anchored(
    tmp_path,
):
    """The anti-vacuity leg: the honest case must NOT move, and every forgery
    in this battery must land on a different verdict map than this one."""
    spc = _harness()
    bundle = spc.build_spec_pinned(tmp_path / "bundle")
    result = spc.make_verifier(_committed_anchor(bundle)).verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]
    honest_map = _verdict_map(result)
    assert honest_map == ("OK", ()), honest_map

    rows = _anchor_disclosure(result)
    assert rows is not None, result.completeness.disclosures
    assert len(rows) == 1, rows
    assert rows[0]["spec_id"] == "bom.v1", rows
    assert rows[0]["sha256"] == hashlib.sha256(_BOM_SPEC.read_bytes()).hexdigest()
    assert rows[0]["source"] == str(_BOM_SPEC.resolve()), rows

    # Every forgery moves the verdict map; the honest case does not.
    weakened = spc.build_spec_pinned(tmp_path / "weak")
    _weaken_spec(weakened)
    weak_map = _verdict_map(
        spc.make_verifier(_committed_anchor(weakened)).verify(weakened)
    )
    forged = _forge_bundle(spc, tmp_path / "forged")
    forged_map = _verdict_map(
        spc.make_verifier(_committed_anchor(forged)).verify(forged)
    )
    empty_map = _verdict_map(
        spc.make_verifier(SpecAnchor(allowed={})).verify(
            spc.build_spec_pinned(tmp_path / "for_empty")
        )
    )
    for forgery_map in (weak_map, forged_map, empty_map):
        assert forgery_map != honest_map, (forgery_map, honest_map)
