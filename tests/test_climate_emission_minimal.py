"""Round-trip integration test for examples/climate_emission_minimal.

Mirrors test_healthcare_diagnosis_minimal.py — four tests covering
shape + tamper-discipline for Scope-3 emission attribution.

Tests:
  1. test_clean_bundle_passes              — happy-path build + verify.
  2. test_clean_bundle_shape               — 8 suppliers, total > 0,
                                              OpaqueFragment anchors well-formed.
  3. test_tamper_supplier_chain_sha_fails  — mutate supplier_chain.json without
                                              realigning manifest SHA → file_integrity catches.
  4. test_tamper_payload_total_fails       — mutate total_scope3_kg_co2e and
                                              realign manifest SHA → re-derivation catches.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "climate_emission_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
# Import the primitive module by NAME (not by path) with the pilot dir on
# sys.path, so this module object is the SAME one the pilot's verify.py and the
# spec_pinned_* drivers import. Loading it by path would create a second, equal-
# named class object and `register_primitive` would reject the collision
# ("already registered to a different class") whenever those run in one session.
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import (  # noqa: E402
    UnknownPrimitive,
    register_primitive,
    resolve_primitive,
)
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402


def _ensure_primitive_registered() -> None:
    """Register the pilot's primitive against whatever module object this
    session currently holds under `climate_attribution_recompute`.

    Axis-2 spec-pinned dispatch (migrated 2026-08-16): this pilot no longer
    ships or executes a bundle-supplied re-derivation pack; the verifier
    recomputes both declared outputs with its OWN primitives under the auditor's
    anchored specs.

    Resolution is LATE and idempotent on purpose. Sibling test modules
    (test_climate_multi_output_spec_pinned.py) load the same module BY PATH and
    replace the sys.modules entry, so the class object can differ between import
    sites inside one pytest session. `register_primitive` deliberately rejects a
    second, equal-named class, so registering eagerly at import time makes the
    outcome depend on test collection order.
    """
    mod = importlib.import_module("climate_attribution_recompute")
    cls = mod.ClimateAttributionRecompute
    try:
        existing = resolve_primitive(cls.primitive_id)
    except UnknownPrimitive:
        existing = None
    if existing is not None and type(existing).__qualname__ == cls.__qualname__:
        return
    register_primitive(cls())


_SPEC_SRCS = (
    _PILOT_DIR / "spec_pinned" / "climate.spec.json",
    _PILOT_DIR / "spec_pinned" / "climate_emission.spec.json",
)


def _anchor() -> SpecAnchor:
    """Auditor anchor built from the COMMITTED spec bytes, never the bundle copy."""
    allowed = {}
    for src in _SPEC_SRCS:
        raw = src.read_bytes()
        allowed[json.loads(raw)["spec_id"]] = hashlib.sha256(raw).hexdigest()
    return SpecAnchor(allowed=allowed)


def _make_verifier() -> BundleVerifier:
    _ensure_primitive_registered()
    return BundleVerifier(plugins=[FileIntegrityManySmall()], spec_anchor=_anchor())


def _build_clean(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "ce_bundle"
    _build_bundle_mod.build(bundle_dir)
    return bundle_dir


def _canonical_bytes(obj) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _patch_manifest_sha(manifest_path: Path, rel: str, new_sha: str) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def test_clean_bundle_passes(tmp_path: Path) -> None:
    bundle_dir = _build_clean(tmp_path)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True on clean bundle; failures: {result.failures}"
    )


def test_clean_bundle_shape(tmp_path: Path) -> None:
    bundle_dir = _build_clean(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text("utf-8"))
    report = json.loads(
        (bundle_dir / "payload" / "emission_report.json").read_text("utf-8")
    )

    assert report["aggregation_method"] == "sum"
    assert len(report["attributions"]) == 8, (
        f"expected 8 supplier attributions; got {len(report['attributions'])}"
    )
    assert float(report["total_scope3_kg_co2e"]) > 0, (
        "total_scope3_kg_co2e must be positive for non-trivial fixtures"
    )

    anchors = manifest.get("fragment_anchors", {})
    assert len(anchors) == 8, (
        f"expected 8 anchors (one per supplier); got {len(anchors)}"
    )
    for key, a in anchors.items():
        assert a["kind"] == "opaque", f"anchor {key} not OpaqueFragment: {a}"
        assert a["kind_tag"] == "supplier_emission_anchor", (
            f"anchor {key} kind_tag wrong: {a['kind_tag']!r}"
        )
        for required in ("vendor_id", "factor_source", "tier"):
            assert required in a["locator"], (
                f"anchor {key} locator missing {required}: {a['locator']!r}"
            )

    tc = manifest.get("typed_checks", [])
    assert "file_integrity_many_small" in tc
    assert "re_derivation_invocation" not in tc, (
        "pilot migrated to spec-pinned dispatch — it must not re-acquire the "
        "bundle-supplied pack execution check"
    )

    # Axis-2: both outputs declared, each bound to an auditor spec, and the
    # §4a.4 coverage invariant (declared ids == outputs/*.json present) holds.
    outputs = manifest.get("outputs", [])
    assert [o["output_id"] for o in outputs] == [
        "climate_total_scope3",
        "climate_attribution_by_vendor",
    ], f"unexpected declared outputs: {outputs}"
    for o in outputs:
        assert o["conforms_to"].startswith("spec/"), o
        assert (bundle_dir / o["conforms_to"]).is_file(), (
            f"declared spec {o['conforms_to']} missing from bundle"
        )
        assert (bundle_dir / "outputs" / f"{o['output_id']}.json").is_file(), (
            f"declared output {o['output_id']} has no outputs/ claim file"
        )
    assert not (bundle_dir / "re_derive").exists(), (
        "migrated pilot must not ship bundle-supplied executable code"
    )


def test_tamper_supplier_chain_sha_fails(tmp_path: Path) -> None:
    """Mutate inputs/supplier_chain.json without realigning manifest SHA.
    file_integrity_many_small must catch the SHA divergence."""
    bundle_dir = _build_clean(tmp_path)

    chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    chain = json.loads(chain_path.read_text(encoding="utf-8"))
    # Inflate the first supplier's activity_amount by 999x — any change works.
    chain[0]["activity_amount"] = float(chain[0]["activity_amount"]) * 999.0
    chain_path.write_bytes(_canonical_bytes(chain))
    # Intentionally do NOT update manifest SHA.

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating supplier_chain.json without re-aligning manifest SHA"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "BAD_FILE_SHA" in combined or "FILE_INTEGRITY" in combined, (
        f"expected BAD_FILE_SHA / file_integrity failure; got: {result.failures}"
    )


def _forge_claim(bundle_dir: Path, output_id: str, mutate) -> None:
    """Rewrite a producer's claimed value AND realign the manifest SHA, so
    file_integrity passes and ONLY spec-pinned dispatch can catch the lie."""
    rel = f"outputs/{output_id}.json"
    path = bundle_dir / rel
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["value"] = mutate(doc["value"])
    raw = json.dumps(doc, indent=2).encode("utf-8")
    path.write_bytes(raw)
    _patch_manifest_sha(
        bundle_dir / "manifest.json", rel, hashlib.sha256(raw).hexdigest()
    )


def test_tamper_claimed_total_fails(tmp_path: Path) -> None:
    """Inflate the claimed Scope-3 TOTAL and realign the manifest SHA.

    This is the tamper class a hash alone cannot catch: the bundle is
    internally hash-consistent. The verifier's own `climate_emission_recompute`
    primitive re-derives the total under the auditor's `exact` comparator and
    rejects. Replaces the retired pack-execution route, which delegated this
    verdict to bundle-supplied code.
    """
    bundle_dir = _build_clean(tmp_path)
    _forge_claim(
        bundle_dir, "climate_total_scope3", lambda v: round(float(v) + 1_000_000.0, 6)
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, "expected ok=False after inflating the claimed total"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "RE_DERIVATION_MISMATCH" in combined, (
        f"expected RE_DERIVATION_MISMATCH from spec-pinned dispatch; got: {result.failures}"
    )


def test_tamper_claimed_attribution_list_fails(tmp_path: Path) -> None:
    """Same tamper class against the per-vendor list output (structured
    comparator), proving BOTH declared outputs are dispatched, not just one."""
    bundle_dir = _build_clean(tmp_path)

    def _bump(records):
        records[0]["attributed_kg_co2e"] = round(
            float(records[0]["attributed_kg_co2e"]) + 0.5, 6
        )
        return records

    _forge_claim(bundle_dir, "climate_attribution_by_vendor", _bump)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, "expected ok=False after forging the attribution list"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures)
    assert "RE_DERIVATION_MISMATCH" in combined.upper(), (
        f"expected RE_DERIVATION_MISMATCH; got: {result.failures}"
    )
    assert "climate_attribution_by_vendor" in combined, (
        f"failure must name the list output, not only the total: {result.failures}"
    )


def test_evidence_edit_with_sha_realigned_fails(tmp_path: Path) -> None:
    """Edit the committed evidence AND realign its manifest SHA. file_integrity
    is satisfied; the re-derived values no longer match the (untouched) claims."""
    bundle_dir = _build_clean(tmp_path)

    chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    chain = json.loads(chain_path.read_text(encoding="utf-8"))
    chain[2]["emission_factor_kg_co2e_per_unit"] = (
        float(chain[2]["emission_factor_kg_co2e_per_unit"]) * 2.0
    )
    raw = _canonical_bytes(chain)
    chain_path.write_bytes(raw)
    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "inputs/supplier_chain.json",
        hashlib.sha256(raw).hexdigest(),
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, "expected ok=False after editing committed evidence"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "RE_DERIVATION_MISMATCH" in combined, (
        f"expected RE_DERIVATION_MISMATCH; got: {result.failures}"
    )


def test_weakened_spec_in_bundle_fails_closed(tmp_path: Path) -> None:
    """Axis-1: the producer swaps a laxer comparator into the bundle's spec/
    copy and realigns manifest.spec_files. The auditor's anchor is derived from
    the COMMITTED spec bytes, so the substituted spec resolves to a SHA the
    anchor does not list and dispatch refuses to run."""
    bundle_dir = _build_clean(tmp_path)

    spec_path = bundle_dir / "spec" / "climate_emission.spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    spec["types"]["climate_attribution"]["comparator"] = {
        "kind": "scalar_epsilon",
        "params": {"epsilon": 1e9},
    }
    raw = json.dumps(spec, indent=2).encode("utf-8")
    spec_path.write_bytes(raw)

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["spec_files"]["climate_emission.spec.json"] = hashlib.sha256(
        raw
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, "expected ok=False when the bundle ships a weakened spec"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures)
    assert "Anchor" in combined or "ANCHOR" in combined.upper(), (
        f"expected an anchor violation; got: {result.failures}"
    )


# --------------------------------------------------------------------------
# The SHIPPED entry point — not the locally-built verifier above
# --------------------------------------------------------------------------
#
# Every test above constructs its own BundleVerifier, so none of them exercises
# the posture examples/climate_emission_minimal/verify.py actually ships. This
# pilot is the canonical template named by the v-kernel-pilot skill, so what
# ships here is copied into new pilots — it has to be tested as shipped.

import subprocess  # noqa: E402


def _run_shipped_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PILOT_DIR / "verify.py"), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_shipped_verify_passes_the_clean_bundle(tmp_path: Path) -> None:
    result = _run_shipped_verify(_build_clean(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout


def test_deleting_the_whole_rederivation_surface_does_not_pass(tmp_path: Path) -> None:
    """TOTAL omission must not verify.

    Partial omission (dropping manifest.outputs while the outputs/ files remain)
    is caught by the §4a.4 coverage invariant. Removing the outputs/ files and
    their manifest.files entries as well leaves a bundle that is internally
    consistent and re-derives NOTHING — the coverage check has nothing to
    compare, so without require_rederivation=True the verdict is a clean PASS.

    Measured before the fix on this pilot: exit 0.
    """
    bundle_dir = _build_clean(tmp_path)
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    declared = manifest.pop("outputs", None)
    assert declared, "fixture no longer declares outputs — this test is vacuous"
    removed = [rel for rel in list(manifest.get("files", {})) if rel.startswith("outputs/")]
    assert removed, "fixture has no outputs/ files — this test is vacuous"
    for rel in removed:
        manifest["files"].pop(rel)
        (bundle_dir / rel).unlink()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    result = _run_shipped_verify(bundle_dir)
    assert result.returncode != 0, (
        "a bundle that re-derives nothing verified clean — the pilot this "
        "template produces would advertise re-derivation it never performs"
    )
    assert "NO_RE_DERIVATION_PERFORMED" in result.stderr, result.stderr
