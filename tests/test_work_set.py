"""The auditor work-set: one invariant in place of four selection channels.

THE DEFECT CLASS, and the hole that was still open. Under spec-pinned dispatch
the producer's remaining freedom is WHICH of the auditor's rules judges WHICH
claim. Four escapes were closed on `session/typed-channel` one at a time —
retype, retype-plus-decoy, drop-plus-decoy, `spec_files` shrink — and a fifth
was open: the per-output `role_policy` was allow-by-default, so an output the
auditor never named was unconstrained.

  MEASURED 2026-09-01 at `a851695d9`, through the SHIPPED
  `examples/corner_load_equilibrium_minimal/verify.py`: declare an EXTRA output
  under a valid anchored type with its true value -> exit 0, face reading
  "role policy APPLIED over 3 output_id(s)" having judged four. Declare the
  SAME manifest entry twice -> exit 0, same face.

They are one invariant — the auditor names the complete multiset of work and
the bundle delivers exactly that — and `_total_binding.assert_bijection_projected`
already states it (multiset-aware; `[a, a]` vs `[a]` fails). `audit_bundle/work_set.py`
builds the auditor's set on the vendored closed-universe helper and dispatch
checks it FIRST, above the empty-outputs early return.

These tests hold the fix to the same four things `test_anchored_type_coverage`
does, in this order:

  1. it FIRES on every escape (the two open ones measured red at HEAD; the
     three previously closed by the deleted channels measured red under the
     mutant control below, which is the pre-fix state reconstructed);
  2. it does NOT fire on an honest bundle;
  3. neutralising the bijection brings the exploits BACK (a green run must be
     able to tell a live guard from a dead one);
  4. a violation is a REJECT, and a verifier holding NO work-set is a
     disclosure, never a refusal.

Shape follows `tests/test_anchored_spec_roster.py` (retired by this change),
the closest precedent for a channel test with a working mutant control.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "corner_load_equilibrium_minimal"
_CLIMATE_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"

for _p in (_PKG_ROOT, _PILOT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from audit_bundle.work_set import (  # noqa: E402
    WITHHELD_REASONS,
    WorkSet,
    WorkSetError,
    WorkSetIntegrityError,
)

PASS, FAIL, COULD_NOT_CONCLUDE = 0, 1, 2

_VERTICAL = "corner_load_vertical_residual"
_PITCH = "corner_load_pitch_residual"
_ROLL = "corner_load_roll_residual"
_CORNER_PINS = {_VERTICAL: _VERTICAL, _PITCH: _PITCH, _ROLL: _ROLL}

# The true vertical residual of a uniformly +15 N payload — what makes a decoy
# re-derive cleanly. Pinned so a fixture drift fails loudly instead of quietly
# turning the attack into a no-op.
_TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N = 60.501022


def _import_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_mod = _import_from_path(
    "corner_load_work_set._build_bundle", _PILOT_DIR / "_build_bundle.py"
)


def _run_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(_PILOT_DIR / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _verify_lib(bundle_dir: Path, *, work_set: WorkSet | None):
    """A library verifier over the pilot's anchored authority, work-set
    optional — the unconfigured (fallback-only) configuration has to be tested
    beside the configured one, because the two must differ in exactly one
    way: disclosure versus refusal."""
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.rederivation.kit import load_primitive_kit
    from audit_bundle.rederivation.spec_binding import SpecAnchor
    from audit_bundle.verifier import BundleVerifier

    load_primitive_kit([_PILOT_DIR / "auditor_kit.py"], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=SpecAnchor.from_files(
            [_PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"],
            forbid_within=bundle_dir,
        ),
        require_rederivation=True,
        work_set=work_set,
    ).verify(bundle_dir)


def _corner_work_set(**kw) -> WorkSet:
    return WorkSet.declare(
        _CORNER_PINS,
        source="test: the three corner_load residual channels",
        provenance="SELF_AUTHORED",
        **kw,
    )


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("ws_clean")
    _build_mod.build(out, "clean")
    return out


# ---------------------------------------------------------------- mutators
# Every edit an honest producer could make is re-cohered the way an honest
# producer would (manifest.files sha realigned). manifest.json itself is not
# hash-covered, so the manifest-only edits need no re-hashing at all.


def _manifest(bundle: Path) -> dict:
    return json.loads((bundle / "manifest.json").read_bytes())


def _write_manifest(bundle: Path, manifest: dict) -> None:
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True)
    )


def _offset_every_corner(bundle: Path, newtons: float) -> None:
    loads_path = bundle / "payload" / "corner_loads.json"
    loads = json.loads(loads_path.read_text())
    loads_path.write_text(
        json.dumps([[str(float(x) + newtons) for x in row] for row in loads], indent=2)
    )
    manifest = _manifest(bundle)
    manifest["files"]["payload/corner_loads.json"] = hashlib.sha256(
        loads_path.read_bytes()
    ).hexdigest()
    _write_manifest(bundle, manifest)


def _retype(bundle: Path, output_id: str, new_type: str) -> None:
    manifest = _manifest(bundle)
    hit = False
    for entry in manifest["outputs"]:
        if entry["output_id"] == output_id:
            entry["type"] = new_type
            hit = True
    assert hit, f"no output {output_id!r} to retype — the fixture drifted"
    _write_manifest(bundle, manifest)


def _plant(bundle: Path, output_id: str, type_key: str, value: float) -> None:
    """Declare an EXTRA output under `type_key` with a value that re-derives."""
    claim = bundle / "outputs" / f"{output_id}.json"
    claim.write_bytes(json.dumps({"value": value}, indent=2).encode())
    manifest = _manifest(bundle)
    manifest["files"][f"outputs/{output_id}.json"] = hashlib.sha256(
        claim.read_bytes()
    ).hexdigest()
    manifest["outputs"].append(
        {
            "conforms_to": "spec/corner_load_equilibrium.spec.json",
            "output_id": output_id,
            "type": type_key,
        }
    )
    _write_manifest(bundle, manifest)


def _drop(bundle: Path, output_id: str) -> None:
    (bundle / "outputs" / f"{output_id}.json").unlink()
    manifest = _manifest(bundle)
    del manifest["files"][f"outputs/{output_id}.json"]
    manifest["outputs"] = [
        e for e in manifest["outputs"] if e["output_id"] != output_id
    ]
    _write_manifest(bundle, manifest)


def _duplicate(bundle: Path, output_id: str) -> None:
    """THE ATTACK THE HELPER'S DOCSTRING PREDICTED: the same entry twice. One
    file on disk, so the §4a.4 set-comparison coverage check is satisfied."""
    manifest = _manifest(bundle)
    entry = next(e for e in manifest["outputs"] if e["output_id"] == output_id)
    manifest["outputs"].append(dict(entry))
    _write_manifest(bundle, manifest)


def _omit_everything(bundle: Path) -> None:
    """Total omission: no manifest.outputs, no outputs/ tree, files re-cohered.
    The shape that reaches the OUTER early return in _step_spec_pinned_dispatch
    before dispatch is even imported."""
    manifest = _manifest(bundle)
    for entry in list(manifest["outputs"]):
        manifest["files"].pop(f"outputs/{entry['output_id']}.json", None)
    del manifest["outputs"]
    _write_manifest(bundle, manifest)
    shutil.rmtree(bundle / "outputs")


def _copy(clean: Path, tmp_path: Path, name: str) -> Path:
    bundle = tmp_path / name
    shutil.copytree(clean, bundle)
    return bundle


def _codes(verdict) -> list[tuple[str, str]]:
    return [(r.check_name, r.code) for r in verdict.reasons]


# --------------------------------------------------------------------------
# 1. Negative control: the honest bundle, through the shipped pilot
# --------------------------------------------------------------------------


def test_the_honest_bundle_passes_and_the_face_names_the_set(
    clean_bundle: Path,
) -> None:
    result = _run_verify(clean_bundle)
    assert result.returncode == PASS, result.stderr
    row = next(ln for ln in result.stdout.splitlines() if "type_selection:" in ln)
    assert "WORK-SET APPLIED" in row
    assert "provenance=EXTERNAL_STRUCTURE" in row, row
    assert "n_expected=3" in row and "n_withheld=0" in row, row


def test_the_face_source_sha_is_the_anchored_specs_sha(clean_bundle: Path) -> None:
    """corner_load DERIVES its work-set from the anchored spec, so the set's
    source_sha must be the very sha the anchor lists — the face is checkable
    against `spec_anchor_provenance`, not a free-text claim of derivation."""
    spec = _PILOT_DIR / "spec_pinned" / "corner_load_equilibrium.spec.json"
    want = hashlib.sha256(spec.read_bytes()).hexdigest()
    verdict = _verify_lib(clean_bundle, work_set=None)  # provenance row only
    prov = next(
        d
        for d in verdict.completeness.disclosures
        if d.startswith("spec_anchor_provenance:")
    )
    assert want in prov
    result = _run_verify(clean_bundle)
    row = next(ln for ln in result.stdout.splitlines() if "type_selection:" in ln)
    assert f"source_sha={want}" in row, row


# --------------------------------------------------------------------------
# 2. The escapes, each executed through the shipped pilot
# --------------------------------------------------------------------------


def test_an_unlisted_output_id_is_refused(clean_bundle: Path, tmp_path) -> None:
    """THE OPEN HOLE. Measured exit 0 at a851695d9 (role policy allow-by-default)."""
    bundle = _copy(clean_bundle, tmp_path, "unlisted")
    _plant(bundle, "extra_vertical", _VERTICAL, 0)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    assert "delivered-but-not-named=['extra_vertical']" in result.stderr, result.stderr


def test_a_duplicated_entry_is_refused(clean_bundle: Path, tmp_path) -> None:
    """THE DUPLICATE. Measured exit 0 at a851695d9: the coverage check compares
    SETS and the cardinality guard counts results per entry, so two entries
    for one output_id sailed through both. A dict projection would have
    collapsed it here too — the helper's own docstring names that lesson."""
    bundle = _copy(clean_bundle, tmp_path, "dup")
    _duplicate(bundle, _VERTICAL)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    assert f"delivered-more-than-once=['{_VERTICAL}']" in result.stderr, result.stderr


def test_dropping_a_pinned_claim_with_a_decoy_is_a_reject(
    clean_bundle: Path, tmp_path
) -> None:
    """Escape 3 (drop-plus-decoy), previously a could-not-conclude on the
    deleted `role_policy_roster` channel. A claim the auditor named and the
    bundle did not deliver is the artifact's failure, so it is a REJECT now —
    and the decoy is named too, as an output nobody asked for."""
    bundle = _copy(clean_bundle, tmp_path, "drop_decoy")
    _offset_every_corner(bundle, 15.0)
    _drop(bundle, _VERTICAL)
    _plant(bundle, "decoy_vertical", _VERTICAL, _TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    assert f"named-but-not-delivered=['{_VERTICAL}']" in result.stderr, result.stderr
    assert "delivered-but-not-named=['decoy_vertical']" in result.stderr, result.stderr


def test_a_retype_is_still_refused_by_the_pin(clean_bundle: Path, tmp_path) -> None:
    """Escape 1. The per-output type pin survives, now read from the work-set."""
    bundle = _copy(clean_bundle, tmp_path, "retype")
    _offset_every_corner(bundle, 15.0)
    _retype(bundle, _VERTICAL, _ROLL)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "ROLE_POLICY_VIOLATION" in result.stderr
    assert _VERTICAL in result.stderr


def test_a_retype_plus_decoy_is_refused_twice(clean_bundle: Path, tmp_path) -> None:
    """Escape 2. The retype trips the pin; the decoy is an unnamed output."""
    bundle = _copy(clean_bundle, tmp_path, "retype_decoy")
    _offset_every_corner(bundle, 15.0)
    _retype(bundle, _VERTICAL, _ROLL)
    _plant(bundle, "decoy_vertical", _VERTICAL, _TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "ROLE_POLICY_VIOLATION" in result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    assert "delivered-but-not-named=['decoy_vertical']" in result.stderr


def test_total_omission_against_a_work_set_is_a_reject(
    clean_bundle: Path, tmp_path
) -> None:
    """Delete `manifest.outputs` AND the outputs/ tree. Without the work-set
    trigger this bundle returns from _step_spec_pinned_dispatch before dispatch
    is imported — the guard-under-an-early-return shape, in its outer copy."""
    bundle = _copy(clean_bundle, tmp_path, "omit_all")
    _omit_everything(bundle)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    for oid in (_VERTICAL, _PITCH, _ROLL):
        assert oid in result.stderr


def test_deleting_the_declaration_but_leaving_the_files_is_refused(
    clean_bundle: Path, tmp_path
) -> None:
    """Partial form of the same omission: manifest.outputs gone, files kept.
    Both the §4a.4 coverage invariant and the work-set fire — they are
    different facts (files without declarations; claims not delivered)."""
    bundle = _copy(clean_bundle, tmp_path, "omit_decl")
    manifest = _manifest(bundle)
    del manifest["outputs"]
    _write_manifest(bundle, manifest)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    assert "COVERAGE_MISMATCH" in result.stderr


# --------------------------------------------------------------------------
# 3. Escape 4 — the spec_files shrink — with a work-set held (climate)
# --------------------------------------------------------------------------
#
# `build_anchored_spec_set` iterates the producer's `manifest.spec_files` with
# the anchor as a FILTER, so popping one key removes that spec's types from
# the anchored-type channel's denominator. The deleted `anchored_spec_roster`
# channel caught this generically; with it gone, the work-set is what closes
# it — for a verifier that holds one. (A verifier holding none is back to the
# fallback, which cannot see the shrink. Stated in the build notes.)

_CLIMATE_PINS = {
    "climate_total_scope3": "climate_total_scope3",
    "climate_attribution_by_vendor": "climate_attribution",
}


@pytest.fixture(scope="module")
def climate_bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("ws_climate") / "bundle"
    subprocess.run(
        [sys.executable, str(_CLIMATE_DIR / "_build_bundle.py"), "--out-dir", str(out)],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    return out


def _climate_verify(bundle: Path, *, work_set: WorkSet | None):
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.rederivation.registry import register_primitive
    from audit_bundle.rederivation.spec_binding import SpecAnchor
    from audit_bundle.verifier import BundleVerifier

    if str(_CLIMATE_DIR) not in sys.path:
        sys.path.insert(0, str(_CLIMATE_DIR))
    from climate_attribution_recompute import ClimateAttributionRecompute  # noqa: PLC0415

    register_primitive(ClimateAttributionRecompute())
    anchor = SpecAnchor.from_files(
        sorted((_CLIMATE_DIR / "spec_pinned").glob("*.spec.json")), forbid_within=bundle
    )
    assert len(anchor.allowed) == 2, anchor.allowed
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor, work_set=work_set
    ).verify(bundle)


def _climate_work_set() -> WorkSet:
    return WorkSet.declare(
        _CLIMATE_PINS, source="test: both climate claims", provenance="SELF_AUTHORED"
    )


def _understate_and_withdraw(bundle: Path) -> None:
    report = bundle / "payload" / "emission_report.json"
    doc = json.loads(report.read_text())
    doc["total_scope3_kg_co2e"] = 32930.44  # true value: 52930.44
    report.write_text(json.dumps(doc, indent=2))
    manifest = _manifest(bundle)
    manifest["files"]["payload/emission_report.json"] = hashlib.sha256(
        report.read_bytes()
    ).hexdigest()
    oid = "climate_total_scope3"
    (bundle / "outputs" / f"{oid}.json").unlink()
    manifest["files"].pop(f"outputs/{oid}.json", None)
    manifest["outputs"] = [e for e in manifest["outputs"] if e["output_id"] != oid]
    _write_manifest(bundle, manifest)


def _drop_spec_file(bundle: Path, basename: str) -> None:
    manifest = _manifest(bundle)
    assert basename in manifest["spec_files"], manifest["spec_files"]
    del manifest["spec_files"][basename]
    _write_manifest(bundle, manifest)


def test_the_honest_climate_bundle_passes_with_a_work_set(climate_bundle: Path) -> None:
    verdict = _climate_verify(climate_bundle, work_set=_climate_work_set())
    assert verdict.ok, _codes(verdict)


def test_spec_files_shrink_with_a_work_set_is_refused(
    climate_bundle: Path, tmp_path
) -> None:
    """Understate scope-3 by 20 t, withdraw the catching output, pop its spec
    from manifest.spec_files. Exit 0 before the roster channel; a REJECT now,
    because the auditor named the withdrawn claim."""
    bundle = _copy(climate_bundle, tmp_path, "shrunk")
    _understate_and_withdraw(bundle)
    _drop_spec_file(bundle, "climate.spec.json")

    verdict = _climate_verify(bundle, work_set=_climate_work_set())
    assert not verdict.ok
    assert ("spec_pinned_dispatch:work_set", "WORK_SET_VIOLATION") in _codes(verdict)
    detail = next(r.detail for r in verdict.reasons if r.code == "WORK_SET_VIOLATION")
    assert "climate_total_scope3" in detail
    assert verdict.state.value == "REJECT", verdict.state


def test_spec_files_shrink_alone_leaves_the_claim_unjudgeable(
    climate_bundle: Path, tmp_path
) -> None:
    """Pop the spec but KEEP the output: the claim is delivered under a type no
    authoritative spec defines, so dispatch refuses it (UNKNOWN_TYPE). Either
    way the shrunk spec buys nothing against a held work-set."""
    bundle = _copy(climate_bundle, tmp_path, "shrunk_only")
    _drop_spec_file(bundle, "climate.spec.json")

    verdict = _climate_verify(bundle, work_set=_climate_work_set())
    assert not verdict.ok
    assert any(code == "UNKNOWN_TYPE" for _, code in _codes(verdict)), _codes(verdict)


# --------------------------------------------------------------------------
# 3b. The SHIPPED climate wrapper holds a work-set
# --------------------------------------------------------------------------
# The landing's build notes recorded: deleting `anchored_spec_roster` reopened the
# spec_files shrink on any verifier holding no work-set, and climate's shipped
# verify.py was the one exposed shipped verify.py (anchors two specs, held no
# set; spec_pinned_multi_check.py also anchors both but builds its own bundle).
# Measured 2026-09-01: understate + withdraw + pop one spec key -> exit 0.
# These cells run the wrapper itself, so the property is about what ships.


def _run_climate_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(_CLIMATE_DIR / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _plant_climate_total_decoy(bundle: Path) -> None:
    """An EXTRA output under the scalar-total type, carrying the TRUE total
    (a byte copy of the honest claim), so it re-derives cleanly. Only a
    work-set can refuse it: every rule is reached, every claim agrees."""
    honest = bundle / "outputs" / "climate_total_scope3.json"
    decoy = bundle / "outputs" / "climate_total_scope3_again.json"
    decoy.write_bytes(honest.read_bytes())
    manifest = _manifest(bundle)
    manifest["files"]["outputs/climate_total_scope3_again.json"] = hashlib.sha256(
        decoy.read_bytes()
    ).hexdigest()
    manifest["outputs"].append(
        {
            "conforms_to": "spec/climate.spec.json",
            "output_id": "climate_total_scope3_again",
            "type": "climate_total_scope3",
        }
    )
    _write_manifest(bundle, manifest)


def test_the_shipped_climate_wrapper_passes_and_names_its_work_set(
    climate_bundle: Path,
) -> None:
    proc = _run_climate_verify(climate_bundle)
    assert proc.returncode == PASS, (proc.stdout, proc.stderr)
    assert "WORK-SET APPLIED" in proc.stdout, proc.stdout


def test_the_spec_files_shrink_is_refused_through_the_shipped_climate_wrapper(
    climate_bundle: Path, tmp_path
) -> None:
    bundle = _copy(climate_bundle, tmp_path, "shrunk_shipped")
    _understate_and_withdraw(bundle)
    _drop_spec_file(bundle, "climate.spec.json")

    proc = _run_climate_verify(bundle)
    assert proc.returncode == FAIL, (proc.returncode, proc.stdout, proc.stderr)
    assert "WORK_SET_VIOLATION" in proc.stderr, proc.stderr
    assert "climate_total_scope3" in proc.stderr, proc.stderr


def test_an_extra_output_is_refused_through_the_shipped_climate_wrapper(
    climate_bundle: Path, tmp_path
) -> None:
    bundle = _copy(climate_bundle, tmp_path, "decoy_shipped")
    _plant_climate_total_decoy(bundle)

    proc = _run_climate_verify(bundle)
    assert proc.returncode == FAIL, (proc.returncode, proc.stdout, proc.stderr)
    assert "WORK_SET_VIOLATION" in proc.stderr, proc.stderr
    assert "climate_total_scope3_again" in proc.stderr, proc.stderr


def test_an_unusable_climate_work_set_is_could_not_conclude(
    climate_bundle: Path, monkeypatch, capsys
) -> None:
    """An auditor-side inconsistency (pins that no longer cover the anchored
    types) is the AUDITOR's tooling being unusable, not a finding against the
    bundle: exit 2, never a traceback exiting 1 (fresh-context pass,
    2026-09-02)."""
    if str(_CLIMATE_DIR) not in sys.path:
        sys.path.insert(0, str(_CLIMATE_DIR))
    climate_verify = _import_from_path(
        "climate_shipped_verify", _CLIMATE_DIR / "verify.py"
    )
    monkeypatch.setattr(
        climate_verify,
        "_WORK_SET_PINS",
        {"climate_total_scope3": "climate_total_scope3"},
    )
    monkeypatch.setattr(sys, "argv", ["verify.py", "--bundle-dir", str(climate_bundle)])
    assert climate_verify.main() == COULD_NOT_CONCLUDE
    err = capsys.readouterr().err
    assert "AUDITOR_INPUTS_UNUSABLE" in err and "could not conclude" in err


def test_the_climate_work_set_pins_every_anchored_type_exactly_once() -> None:
    """The set is hand-declared (climate's output_ids are not its type keys,
    so the identity map corner_load uses does not apply). What keeps it honest
    is that it covers the anchored specs' type keys COMPLETELY and each once:
    a type key added to a spec without a pin here fails this cell, and a pin
    naming a type no spec defines fails it too."""
    if str(_CLIMATE_DIR) not in sys.path:
        sys.path.insert(0, str(_CLIMATE_DIR))
    climate_verify = _import_from_path(
        "climate_shipped_verify", _CLIMATE_DIR / "verify.py"
    )
    ws = climate_verify._work_set()
    spec_types: list[str] = []
    for spec_path in sorted((_CLIMATE_DIR / "spec_pinned").glob("*.spec.json")):
        spec_types.extend(json.loads(spec_path.read_bytes())["types"])
    assert sorted(tk for _, tk in ws.pins) == sorted(spec_types), (ws.pins, spec_types)
    assert ws.n_withheld == 0
    assert dict(ws.pins) == _CLIMATE_PINS
    # Hand-written means SELF_AUTHORED with no source_sha: the class is never
    # labelled up to "derived from the anchored spec" when it was not.
    assert ws.receipt["provenance"] == "SELF_AUTHORED"
    assert ws.receipt["source_sha"] is None


# --------------------------------------------------------------------------
# 4. Reject versus disclosure — the two worlds
# --------------------------------------------------------------------------


def test_a_violation_is_a_reject_on_its_own_check_name(
    clean_bundle: Path, tmp_path
) -> None:
    bundle = _copy(clean_bundle, tmp_path, "reject_state")
    _plant(bundle, "extra_vertical", _VERTICAL, 0)

    verdict = _verify_lib(bundle, work_set=_corner_work_set())
    assert not verdict.ok
    assert verdict.state.value == "REJECT", verdict.state
    assert ("spec_pinned_dispatch:work_set", "WORK_SET_VIOLATION") in _codes(verdict)


def test_a_verifier_holding_no_work_set_discloses_rather_than_refuses(
    clean_bundle: Path, tmp_path
) -> None:
    """The unconfigured case. The same unlisted-output bundle through a verifier
    with no work-set must NOT fire WORK_SET_VIOLATION, and its face must say
    selection was the producer's. It deliberately does not assert the verdict
    is OK: 102 of 107 pilots run this configuration, and pinning "a smuggled
    output passes" as a green-suite invariant would ratchet against any future
    generic closure (the lesson of the typed-channel audit's finding 4)."""
    bundle = _copy(clean_bundle, tmp_path, "no_ws")
    _plant(bundle, "extra_vertical", _VERTICAL, 0)

    verdict = _verify_lib(bundle, work_set=None)
    assert not any(code == "WORK_SET_VIOLATION" for _, code in _codes(verdict))
    rows = [
        d for d in verdict.completeness.disclosures if d.startswith("type_selection:")
    ]
    assert len(rows) == 1 and "NO auditor work-set" in rows[0], rows
    assert "anchored_spec_types" in rows[0]  # names the fallback
    if not verdict.ok:
        print(
            "NOTE: the unlisted-output bundle is refused without a work-set by "
            + repr(_codes(verdict))
            + " — a generic closure; update the "
            "fallback paragraph in _step_anchored_type_coverage_guard."
        )


def test_the_configured_face_is_emitted_exactly_once(clean_bundle: Path) -> None:
    verdict = _verify_lib(clean_bundle, work_set=_corner_work_set())
    assert verdict.ok, _codes(verdict)
    rows = [
        d for d in verdict.completeness.disclosures if d.startswith("type_selection:")
    ]
    assert len(rows) == 1 and "WORK-SET APPLIED" in rows[0], rows
    assert "provenance=SELF_AUTHORED" in rows[0] and "source_sha=None" in rows[0]


# --------------------------------------------------------------------------
# 5. Withholding — the committed vocabulary in place of `Binding.required`
# --------------------------------------------------------------------------


def test_a_withheld_output_that_is_absent_is_not_a_violation(
    clean_bundle: Path, tmp_path
) -> None:
    """The auditor names pitch and withholds it. A bundle without pitch passes
    the work-set; the face carries the reason breakdown. The FALLBACK type
    channel still reports the pitch rule as unexercised — withholding excuses
    the set, it does not silence the rule — so the verdict is could-not-
    conclude on THAT channel and nothing else."""
    bundle = _copy(clean_bundle, tmp_path, "withheld_absent")
    _drop(bundle, _PITCH)

    ws = _corner_work_set(withheld={_PITCH: "WITHHELD_BY_AUDITOR"})
    verdict = _verify_lib(bundle, work_set=ws)
    codes = _codes(verdict)
    assert not any(code == "WORK_SET_VIOLATION" for _, code in codes), codes
    assert codes == [("anchored_spec_types", "VERIFIER_INCOMPLETE")], codes
    row = next(
        d for d in verdict.completeness.disclosures if d.startswith("type_selection:")
    )
    assert "n_withheld=1" in row and "withheld=WITHHELD_BY_AUDITOR:1" in row, row


def test_a_withheld_output_that_arrives_anyway_is_refused(clean_bundle: Path) -> None:
    """Deny-by-default over the COVERED set: an output the auditor withheld is
    not one the bundle may deliver."""
    ws = _corner_work_set(withheld={_PITCH: "NOT_PRODUCED_THIS_PERIOD"})
    verdict = _verify_lib(clean_bundle, work_set=ws)
    assert ("spec_pinned_dispatch:work_set", "WORK_SET_VIOLATION") in _codes(verdict)
    detail = next(r.detail for r in verdict.reasons if r.code == "WORK_SET_VIOLATION")
    assert f"delivered-but-not-named=['{_PITCH}']" in detail, detail


# --------------------------------------------------------------------------
# 6. Mutant control — a green suite must be able to tell a live guard from a
#    dead one
# --------------------------------------------------------------------------


def test_without_the_bijection_the_exploits_return(
    clean_bundle: Path, tmp_path, monkeypatch
) -> None:
    """Neutralise `assert_bijection_projected` inside work_set and the three
    set-level escapes go green again — the pre-fix state, reconstructed. The
    retype escape is NOT in this list: its pin is a separate mechanism and
    must keep firing under the mutant, which is asserted too."""
    from audit_bundle import work_set as ws_mod

    unlisted = _copy(clean_bundle, tmp_path, "m_unlisted")
    _plant(unlisted, "extra_vertical", _VERTICAL, 0)
    dup = _copy(clean_bundle, tmp_path, "m_dup")
    _duplicate(dup, _VERTICAL)
    dropped = _copy(clean_bundle, tmp_path, "m_drop")
    _offset_every_corner(dropped, 15.0)
    _drop(dropped, _VERTICAL)
    _plant(dropped, "decoy_vertical", _VERTICAL, _TRUE_VERTICAL_RESIDUAL_AT_PLUS_15N)
    retyped = _copy(clean_bundle, tmp_path, "m_retype")
    _offset_every_corner(retyped, 15.0)
    _retype(retyped, _VERTICAL, _ROLL)

    for b in (unlisted, dup, dropped, retyped):
        assert not _verify_lib(b, work_set=_corner_work_set()).ok, b.name

    monkeypatch.setattr(
        ws_mod, "assert_bijection_projected", lambda left, right, key: None
    )

    for b in (unlisted, dup, dropped):
        dead = _verify_lib(b, work_set=_corner_work_set())
        assert dead.ok, (
            f"{b.name}: still refused with the bijection neutralised — something "
            "ELSE is catching it, so these tests are not measuring the work-set: "
            + repr(_codes(dead))
        )
    still = _verify_lib(retyped, work_set=_corner_work_set())
    assert ("spec_pinned_dispatch:" + _VERTICAL, "ROLE_POLICY_VIOLATION") in _codes(
        still
    )


# --------------------------------------------------------------------------
# 7. The object itself: construction refusals, the boundary, the formatter
# --------------------------------------------------------------------------


def test_construction_refusals() -> None:
    with pytest.raises(WorkSetError, match="vacuity"):
        WorkSet.declare({}, source="s", provenance="SELF_AUTHORED")
    with pytest.raises(WorkSetError, match="SELF_AUTHORED"):
        WorkSet.declare(
            {"a": "t"}, source="s", provenance="SELF_AUTHORED", source_sha="0" * 64
        )
    with pytest.raises(WorkSetError, match="requires source_sha"):
        WorkSet.declare({"a": "t"}, source="s", provenance="EXTERNAL_STRUCTURE")
    with pytest.raises(WorkSetError, match="provenance"):
        WorkSet.declare({"a": "t"}, source="s", provenance="TRUST_ME")
    with pytest.raises(WorkSetError, match="reason_enum"):
        WorkSet.declare(
            {"a": "t"}, source="s", provenance="SELF_AUTHORED", withheld={"a": "BOGUS"}
        )
    with pytest.raises(WorkSetError, match="not in the work-set"):
        WorkSet.declare(
            {"a": "t"},
            source="s",
            provenance="SELF_AUTHORED",
            withheld={"q": WITHHELD_REASONS[0]},
        )
    with pytest.raises(WorkSetError, match="non-empty str"):
        WorkSet.declare({"a": ""}, source="s", provenance="SELF_AUTHORED")
    with pytest.raises(WorkSetError, match="mapping"):
        WorkSet.declare([("a", "t")], source="s", provenance="SELF_AUTHORED")  # type: ignore[arg-type]


def test_required_type_is_none_for_unnamed_and_withheld() -> None:
    ws = WorkSet.declare(
        {"a": "ta", "b": "tb"},
        source="s",
        provenance="SELF_AUTHORED",
        withheld={"b": "WITHHELD_BY_AUDITOR"},
    )
    assert ws.required_type("a") == "ta"
    assert ws.required_type("b") is None
    assert ws.required_type("zzz") is None
    assert ws.n_expected == 1 and ws.n_withheld == 1


def test_the_boundary_raises_only_work_set_error_on_hostile_entries() -> None:
    ws = WorkSet.declare({"a": "ta"}, source="s", provenance="SELF_AUTHORED")
    hostile = [{"output_id": ["x"]}, 7, None, {"no_id": 1}, {"output_id": "a"}]
    with pytest.raises(WorkSetError) as ei:
        ws.check_delivery(hostile)
    assert "delivered-but-not-named" in str(ei.value)
    assert "['x']" in str(ei.value) and "None" in str(ei.value)


def test_a_tampered_work_set_is_the_verifiers_incapacity_not_a_reject(
    clean_bundle: Path,
) -> None:
    """A work-set whose held sha no longer matches its document cannot be
    APPLIED. That is the VERIFIER's problem, so the object raises
    WorkSetIntegrityError (not WorkSetError) and dispatch routes it to
    could-not-conclude — never to a REJECT of an artifact nothing was shown
    wrong with. The documents themselves are held as canonical bytes and
    re-parsed at every use, so in-place mutation is not available; the
    mismatch is reached through the raw constructor."""
    import dataclasses

    ws = dataclasses.replace(_corner_work_set(), universe_sha="0" * 64)
    with pytest.raises(WorkSetIntegrityError):
        ws.check_delivery([])
    verdict = _verify_lib(clean_bundle, work_set=ws)
    assert not verdict.ok
    assert verdict.state.value == "ERROR", verdict.state
    assert ("spec_pinned_dispatch:work_set", "VERIFIER_INCOMPLETE") in _codes(verdict)
    detail = next(
        r.detail
        for r in verdict.reasons
        if r.check_name == "spec_pinned_dispatch:work_set"
    )
    assert "WORK_SET_CHECK_ERROR" in detail
    # and the face does NOT say the set was applied (red team M3, 2026-09-01)
    rows = [
        d for d in verdict.completeness.disclosures if d.startswith("type_selection:")
    ]
    assert len(rows) == 1 and "NOT APPLIED" in rows[0], rows
    assert "WORK-SET APPLIED" not in rows[0], rows


def test_the_held_documents_cannot_be_mutated_in_place() -> None:
    """The frozen-field ratchet's class: `frozen=True` locks bindings, not
    containers. Every read returns a FRESH parse, so a holder who edits what
    it got back changes nothing the next check sees."""
    ws = _corner_work_set()
    doc = ws.universe
    doc["source"] = "edited"
    assert ws.universe["source"] != "edited"
    rec = ws.receipt
    rec["n_covered"] = 0
    assert ws.receipt["n_covered"] == 3
    with pytest.raises(AttributeError):
        ws.universe_sha = "x"  # type: ignore[misc]
    ws.check_delivery([{"output_id": oid} for oid, _ in ws.pins])  # still applies


def test_no_check_harness_still_passes_a_bare_policy() -> None:
    """Every auditor harness in the tree that constructs an anchored
    BundleVerifier does so with `WorkSet.declare(` or with no set at all —
    none passes the retired `role_policy=` kwarg (which the constructor no
    longer accepts) or hand-rolls `work_set={`. Globbed, never listed by
    name: the OSS drop excludes partner-held pilots and its rewriter edits
    strings inside code, so a shipped test that named them was red on a
    customer's first pytest (red team, 2026-09-01). The exact five-pilot
    roster is an internal fact recorded in the build notes, not a floor a
    customer's export must reproduce."""
    harnesses = sorted(
        p
        for pattern in (
            "*/spec_pinned_check.py",
            "*/witness_cert_check.py",
            "*/auditor_entry.py",
        )
        for p in (_PKG_ROOT / "examples").glob(pattern)
    )
    assert harnesses, "no auditor harnesses found — the glob drifted"
    declared = []
    for path in harnesses:
        src = path.read_text()
        assert "role_policy=" not in src, path
        assert "work_set={" not in src, path
        if "WorkSet.declare(" in src:
            declared.append(path.parent.name)
    # corner_load ships in every tree this test runs in, and its shipped
    # entry point is the one that enforces the set.
    assert "corner_load_equilibrium_minimal" in declared, declared


def test_an_overlong_output_id_is_refused_before_any_filesystem_call(
    clean_bundle: Path, tmp_path
) -> None:
    """THE RED TEAM'S SEVERE FINDING (2026-09-01), closed. A 251-char extra
    output_id passed the alphabet grammar, reached `claimed_path.is_file()`,
    and ENAMETOOLONG escaped as VERIFIER_INTERNAL_ERROR (exit 2) — outranking
    the WORK_SET_VIOLATION already recorded and any physics REJECT with it.
    Measured on the baseline tree too: pre-existing, and it let a producer
    downgrade "the artifact is bad" to "the verifier could not conclude"
    with one long string. The grammar now bounds length; the verdict stays
    a REJECT carrying both codes."""
    bundle = _copy(clean_bundle, tmp_path, "long_id")
    manifest = _manifest(bundle)
    manifest["outputs"].append(
        {
            "conforms_to": "spec/corner_load_equilibrium.spec.json",
            "output_id": "a" * 251,
            "type": _VERTICAL,
        }
    )
    _write_manifest(bundle, manifest)

    result = _run_verify(bundle)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "VERIFIER_INTERNAL_ERROR" not in result.stderr
    assert "WORK_SET_VIOLATION" in result.stderr
    assert "OUTPUT_ID_UNSAFE" in result.stderr
    # and the drift REJECT is not swallowed either
    drift = _copy(clean_bundle, tmp_path, "long_id_drift")
    _offset_every_corner(drift, 15.0)
    manifest = _manifest(drift)
    manifest["outputs"].append(
        {
            "conforms_to": "spec/corner_load_equilibrium.spec.json",
            "output_id": "b" * 300,
            "type": _VERTICAL,
        }
    )
    _write_manifest(drift, manifest)
    result = _run_verify(drift)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "RE_DERIVATION_MISMATCH" in result.stderr


def test_a_250_char_output_id_is_still_admitted() -> None:
    """The bound is the filesystem's, not a shorter one: 250 + '.json' = 255."""
    from audit_bundle.rederivation.dispatch import _OUTPUT_ID_RE

    assert _OUTPUT_ID_RE.match("a" * 250)
    assert not _OUTPUT_ID_RE.match("a" * 251)
