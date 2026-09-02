"""tests/test_primitive_kit.py — the auditor-side primitive-kit loader.

The auditor's kit is the anchor bytes PLUS the primitive registrations.
`--spec-anchor` (tests/test_cli_spec_anchor.py) covers the first half; this
file covers the second: `load_primitive_kit` / CLI `--primitives`, which lets
the SHIPPED verifier re-derive a bundle whose pinned spec names a pilot-local
primitive — while keeping every refusal that makes the kit auditor-held code
rather than a bundle-supplied side channel:

  * in-bundle kit path (direct or via symlink) refused BEFORE execution — the
    primitive-shaped twin of the in-bundle anchor tautology;
  * a kit that registers nothing refused (anti-vacuity: a no-op kit reads as
    protection);
  * same path re-loaded with different bytes refused;
  * a primitive whose SOURCE resolves inside the bundle (a kit that imported
    producer code out of the bundle) is refused at verify time
    (`PRIMITIVE_SOURCE_INSIDE_BUNDLE`).

(The NO-kit -> `UNKNOWN_PRIMITIVE` fail-closed default lives in
`tests/test_cli_spec_anchor.py::test_pilot_local_primitive_without_kit_stays_fail_closed`,
alongside its reachable-with-kit complement.)

And the two anti-tautology properties: a kit does not BLESS anything (a
tampered claimed value still REJECTs through kit-registered code), and the
verdict face distinguishes WHOSE code judged (`primitive_provenance`
disclosure rows, registry-derived — never caller-declared).

Library tests use synthetic tmp kits with per-test primitive_ids (the registry
is process-global; a shared id across tests would collide across exec'd
module copies). CLI tests run the climate pilot fixture in a subprocess.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.rederivation import registry  # noqa: E402


@pytest.fixture(autouse=True, scope="module")
def _registry_is_left_as_it_was_found():
    """REGRESSION NET for the leak fixed below -- covers every registration in
    this file, not just the one site that was found.

    It only ever DELETES ids this module added; it never restores or clears,
    because a fixture that rewrites the global registry wholesale can wipe the
    lazily-loaded distribution set for every later file in the worker. (Measured
    while writing this: snapshotting before `_ensure_primitives_loaded()` and
    restoring wholesale broke seven tests in the files that followed -- the
    load-order trap this guard exists to catch is one the guard itself fell into
    on the first attempt.)
    """
    registry._ensure_primitives_loaded()
    before = set(registry._PRIMITIVE_REGISTRY)
    before_dist = set(registry.distribution_primitives())
    yield
    leaked_dist = set(registry.distribution_primitives()) - before_dist
    leaked = set(registry._PRIMITIVE_REGISTRY) - before
    for pid in leaked:
        registry._PRIMITIVE_REGISTRY.pop(pid, None)
    assert not leaked_dist, (
        f"kit test(s) left {sorted(leaked_dist)} in the DISTRIBUTION roster. "
        "Any later file in this xdist worker comparing against "
        "distribution_primitives() will fail on a roster it did not change. "
        "Pop the id in a finally at the registering test."
    )

from audit_bundle.rederivation.kit import (  # noqa: E402
    NO_BUNDLE,
    KitConstructionError,
    load_primitive_kit,
    undeclared_kit_registration,
)
from audit_bundle.rederivation.registry import (  # noqa: E402
    _ensure_primitives_loaded,
    primitive_provenance,
    registered_primitives,
)

_CLIMATE_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"
_CLIMATE_SPECS = (
    _CLIMATE_DIR / "spec_pinned" / "climate.spec.json",
    _CLIMATE_DIR / "spec_pinned" / "climate_emission.spec.json",
)
_CLIMATE_KIT = _CLIMATE_DIR / "auditor_kit.py"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


_KIT_TEMPLATE = """\
from audit_bundle.rederivation.registry import register_primitive


class _KitPrimitive:
    primitive_id = {pid!r}

    def recompute(self, inputs, section):
        raise NotImplementedError("loader-test primitive; never dispatched")


register_primitive(_KitPrimitive())
"""


def _write_kit(path: Path, pid: str) -> Path:
    path.write_text(_KIT_TEMPLATE.format(pid=pid), encoding="utf-8")
    return path


def _build_climate(dest: Path) -> Path:
    if str(_CLIMATE_DIR) not in sys.path:
        sys.path.insert(0, str(_CLIMATE_DIR))
    import importlib.util

    name = "climate_emission_minimal._build_bundle"
    mod = sys.modules.get(name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(
            name, _CLIMATE_DIR / "_build_bundle.py"
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    mod.build(dest)
    return dest


def _run_cli(bundle_dir: Path, verdict_out: Path, *extra: str):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle_dir),
            "--verdict-out",
            str(verdict_out),
            *extra,
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert verdict_out.exists(), (
        f"--verdict-out was not written (exit {proc.returncode})\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    return proc.returncode, json.loads(verdict_out.read_text(encoding="utf-8"))


def _anchored_kit_args() -> list[str]:
    return [
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(_CLIMATE_KIT),
    ]


def _disclosure_rows(face: dict, prefix: str) -> list[dict]:
    comp = ((face.get("verdict") or {}).get("completeness")) or {}
    for d in comp.get("disclosures") or ():
        if d.startswith(prefix):
            return json.loads(d[len(prefix) :])
    return []


# ---------------------------------------------------------------------------
# Library: loading + provenance
# ---------------------------------------------------------------------------


def test_kit_loads_and_reports_verifier_derived_provenance(tmp_path: Path) -> None:
    pid = "kit_test_loads_and_reports"
    kit = _write_kit(tmp_path / "kit.py", pid)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    rows = load_primitive_kit([kit], forbid_within=bundle)

    assert len(rows) == 1
    assert rows[0]["path"] == str(kit.resolve())
    assert rows[0]["sha256"] == hashlib.sha256(kit.read_bytes()).hexdigest()
    assert rows[0]["registered"] == [pid]
    assert pid in registered_primitives()
    prov = primitive_provenance(pid)
    assert prov["origin"] == "external", prov
    assert prov["source"] == str(kit.resolve()), prov
    assert prov["sha256"] == rows[0]["sha256"], prov


def test_distribution_primitive_provenance_says_distribution() -> None:
    _ensure_primitives_loaded()
    prov = primitive_provenance("bom_recompute")
    assert prov["origin"] == "distribution", prov
    assert prov["source"] and prov["source"].endswith("bom.py"), prov
    src = Path(prov["source"])
    assert prov["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()


def test_unknown_primitive_provenance_is_the_honest_unknown_row() -> None:
    prov = primitive_provenance("never_registered_primitive_id")
    assert prov == {"origin": "unknown", "source": None, "sha256": None}


def test_same_kit_twice_is_idempotent(tmp_path: Path) -> None:
    pid = "kit_test_idempotent"
    kit = _write_kit(tmp_path / "kit.py", pid)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    first = load_primitive_kit([kit], forbid_within=bundle)
    second = load_primitive_kit([kit], forbid_within=bundle)
    assert first == second


def test_same_path_different_bytes_is_refused(tmp_path: Path) -> None:
    pid = "kit_test_bytes_drift"
    kit = _write_kit(tmp_path / "kit.py", pid)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    load_primitive_kit([kit], forbid_within=bundle)
    kit.write_text(_KIT_TEMPLATE.format(pid=pid) + "\n# changed\n", encoding="utf-8")
    with pytest.raises(KitConstructionError, match="different bytes"):
        load_primitive_kit([kit], forbid_within=bundle)


# ---------------------------------------------------------------------------
# Library: refusals. Path/containment refusals are pre-execution (canary-proven
# below); the no-op and raise refusals are necessarily POST-execution (the kit
# must run before its registration effect — or absence — can be observed).
# ---------------------------------------------------------------------------


def test_kit_inside_bundle_dir_is_refused_before_execution(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    canary = tmp_path / "canary.txt"
    evil = bundle / "kit.py"
    evil.write_text(f"open({str(canary)!r}, 'w').write('ran')\n", encoding="utf-8")

    with pytest.raises(KitConstructionError, match="INSIDE"):
        load_primitive_kit([evil], forbid_within=bundle)
    assert not canary.exists(), "in-bundle kit code was executed"


def test_kit_symlink_into_bundle_is_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    inside = bundle / "kit.py"
    _write_kit(inside, "kit_test_symlink")
    link = tmp_path / "looks_outside.py"
    link.symlink_to(inside)

    with pytest.raises(KitConstructionError, match="INSIDE"):
        load_primitive_kit([link], forbid_within=bundle)
    assert "kit_test_symlink" not in registered_primitives()


def test_empty_kit_list_is_refused(tmp_path: Path) -> None:
    with pytest.raises(KitConstructionError, match="at least one"):
        load_primitive_kit([], forbid_within=tmp_path)


def test_missing_kit_file_is_refused(tmp_path: Path) -> None:
    # `forbid_within` is an EXISTING directory here on purpose: a non-existent
    # one is now its own refusal (a containment check against a directory that
    # is not there trivially succeeds), so passing one would make this test
    # assert the wrong refusal.
    with pytest.raises(KitConstructionError, match="could not be resolved"):
        load_primitive_kit([tmp_path / "absent.py"], forbid_within=tmp_path)


def test_noop_kit_is_refused(tmp_path: Path) -> None:
    kit = tmp_path / "noop.py"
    kit.write_text("x = 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    with pytest.raises(KitConstructionError, match="registered no new"):
        load_primitive_kit([kit], forbid_within=bundle)


def test_raising_kit_is_refused(tmp_path: Path) -> None:
    kit = tmp_path / "raising.py"
    kit.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    with pytest.raises(KitConstructionError, match="raised during load"):
        load_primitive_kit([kit], forbid_within=bundle)


# ---------------------------------------------------------------------------
# CLI: the kit completes the auditor kit — and blesses nothing
# ---------------------------------------------------------------------------


def test_cli_kit_gate_and_provenance_reach_the_face(tmp_path: Path) -> None:
    bundle_dir = _build_climate(tmp_path / "climate")
    code, face = _run_cli(bundle_dir, tmp_path / "v.json", *_anchored_kit_args())

    assert code == 0, (code, face.get("reason_codes"))
    gates = {g.get("gate"): g for g in face.get("cli_gates") or ()}
    kit_gate = gates.get("primitive_kit")
    # LOADED, not PASS: loading a kit is not a re-derivation (used-ness is the
    # primitive_provenance disclosure, asserted below).
    assert kit_gate and kit_gate["status"] == "LOADED", gates
    (mod_row,) = kit_gate["kit_modules"]
    assert mod_row["path"] == str(_CLIMATE_KIT.resolve())
    assert mod_row["sha256"] == hashlib.sha256(_CLIMATE_KIT.read_bytes()).hexdigest()
    assert "climate_attribution_recompute" in mod_row["registered"]

    rows = _disclosure_rows(face, "primitive_provenance: ")
    by_id = {r["primitive_id"]: r for r in rows}
    kit_row = by_id.get("climate_attribution_recompute")
    assert kit_row and kit_row["origin"] == "external", rows
    assert kit_row["source"] and kit_row["sha256"], rows
    # The face must distinguish kit code from distribution code, so at least
    # this pilot's kit-registered primitive is labeled external — a face where
    # every row said "distribution" would be the constructor lying by omission.


def test_cli_kit_does_not_bless_a_tampered_claim(tmp_path: Path) -> None:
    """Anti-tautology: the kit provides the recompute CODE, not the verdict.
    A tampered claimed value, fully hash-cohered by the producer, must still
    REJECT through the kit-registered primitive."""
    bundle_dir = _build_climate(tmp_path / "climate")
    out_path = bundle_dir / "outputs" / "climate_attribution_by_vendor.json"
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert isinstance(doc.get("value"), list) and doc["value"], doc
    doc["value"] = []  # claim an EMPTY attribution — the bom_minimal shape
    raw = json.dumps(doc, indent=2).encode("utf-8")
    out_path.write_bytes(raw)
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rel = "outputs/climate_attribution_by_vendor.json"
    assert rel in manifest.get("files", {}), (
        "fixture no longer tracks the tampered output in manifest.files — "
        "re-cohering below would be a no-op and the REJECT could then be an "
        "untracked-file artifact, not the hash-cohered re-derivation mismatch "
        "this test means to prove"
    )
    manifest["files"][rel] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    code, face = _run_cli(bundle_dir, tmp_path / "v.json", *_anchored_kit_args())
    assert code == 1, (code, face.get("reason_codes"))
    # Assert the mismatch is on the OUTPUT the kit-registered primitive judges,
    # not merely that RE_DERIVATION_MISMATCH appears somewhere.
    hits = [
        (n, c)
        for (n, c) in _walk_reasons(face)
        if c == "RE_DERIVATION_MISMATCH" and "climate_attribution_by_vendor" in (n or "")
    ]
    assert hits, (face.get("reason_codes"), _walk_reasons(face))


def test_cli_in_bundle_kit_is_refused_with_no_bundle_verdict(tmp_path: Path) -> None:
    bundle_dir = _build_climate(tmp_path / "climate")
    evil = bundle_dir / "kit.py"
    evil.write_text("# never executed\n", encoding="utf-8")

    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(evil),
    )
    assert code == 2, (code, face.get("reason_codes"))
    assert face.get("reason_codes") == ["PRIMITIVES_ARG_INVALID"], face.get(
        "reason_codes"
    )
    # Operator error: no verdict about the bundle was formed.
    assert face.get("verdict") in (None, {}), "a bundle verdict was formed"


def test_cli_noop_kit_is_refused(tmp_path: Path) -> None:
    bundle_dir = _build_climate(tmp_path / "climate")
    noop = tmp_path / "noop_kit.py"
    noop.write_text("x = 1\n", encoding="utf-8")

    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(noop),
    )
    assert code == 2, (code, face.get("reason_codes"))
    assert face.get("reason_codes") == ["PRIMITIVES_ARG_INVALID"], face.get(
        "reason_codes"
    )


def test_module_spoof_cannot_launder_origin_to_distribution(tmp_path: Path) -> None:
    """`cls.__module__` is caller-settable; provenance must not resolve source
    through it (the one-line laundering: point __module__ at a distribution
    module and inherit its file). Derivation binds to the recompute method's
    code object, compiled from the kit file the loader actually executed."""
    pid = "kit_test_module_spoof"
    kit = tmp_path / "spoof_kit.py"
    kit.write_text(
        _KIT_TEMPLATE.format(pid=pid).replace(
            "register_primitive(_KitPrimitive())",
            '_KitPrimitive.__module__ = "audit_bundle.rederivation.primitives.bom"\n'
            "register_primitive(_KitPrimitive())",
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    load_primitive_kit([kit], forbid_within=bundle)
    prov = primitive_provenance(pid)
    assert prov["origin"] == "external", prov
    assert prov["source"] == str(kit.resolve()), prov


# ---------------------------------------------------------------------------
# Seam-fix regressions (fresh-context adversarial pass, 2026-08-26)
# ---------------------------------------------------------------------------


def test_kit_that_warms_the_registry_does_not_over_attribute(tmp_path: Path) -> None:
    """Finding A: `registered[]` is a set-diff over the process-global registry.
    A kit that imports distribution primitives (or calls
    _ensure_primitives_loaded) triggers their self-registration DURING its exec;
    a cold `before` snapshot then credited the kit with all ~28. The loader
    warms the registry before snapshotting, so only genuinely-new ids are
    attributed — this also restores the anti-vacuity check the over-count
    silently defeated."""
    kit = tmp_path / "warm_kit.py"
    kit.write_text(
        "from audit_bundle.rederivation.registry import (\n"
        "    register_primitive, _ensure_primitives_loaded)\n"
        "_ensure_primitives_loaded()\n"
        "class Mine:\n"
        "    primitive_id = 'kit_test_warm_only_mine'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(Mine())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    rows = load_primitive_kit([kit], forbid_within=bundle)
    assert rows[0]["registered"] == ["kit_test_warm_only_mine"], rows[0]["registered"]


def test_kit_that_only_warms_the_registry_is_a_refused_noop(tmp_path: Path) -> None:
    """The camouflage/vacuity twin of the above: a kit whose entire body is
    `import audit_bundle.rederivation.primitives` registers nothing of its own;
    with the registry warmed first, `new` is empty and anti-vacuity refuses it
    rather than crediting it with the distribution set."""
    kit = tmp_path / "noop_import_kit.py"
    kit.write_text("import audit_bundle.rederivation.primitives\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with pytest.raises(KitConstructionError, match="registered no new"):
        load_primitive_kit([kit], forbid_within=bundle)


def test_kit_calling_sys_exit_is_refused_not_a_green_exit(tmp_path: Path) -> None:
    """Hit 5: SystemExit is a BaseException, so an `except Exception` let a kit's
    sys.exit() propagate — past the CLI's SystemExit re-raise — and terminate
    the tool at exit 0 (machine-readable GREEN) having verified nothing. The
    loader now catches BaseException around exec."""
    kit = tmp_path / "exit_kit.py"
    kit.write_text(
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_test_exit'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n"
        "import sys; sys.exit(0)\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with pytest.raises(KitConstructionError, match="raised during load"):
        load_primitive_kit([kit], forbid_within=bundle)


def test_callable_object_recompute_with_module_spoof_stays_external(
    tmp_path: Path,
) -> None:
    """Hit 2: a callable OBJECT as `recompute` has no `__code__` on the bound
    attribute, so an `inspect.getfile(type)` fallback resolved through the
    caller-settable `__module__` — reopening the one-line spoof. Provenance now
    derives from the callable's own `type(fn).__call__.__code__` and has no
    __module__ fallback, so origin stays external."""
    pid = "kit_test_callable_spoof"
    kit = tmp_path / "callable_kit.py"
    kit.write_text(
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class _R:\n"
        "    def __call__(self, i, s): return 0\n"
        "class Evil:\n"
        f"    primitive_id = {pid!r}\n"
        "    recompute = _R()\n"
        "Evil.__module__ = 'audit_bundle.rederivation.registry'\n"
        "register_primitive(Evil())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    load_primitive_kit([kit], forbid_within=bundle)
    prov = primitive_provenance(pid)
    assert prov["origin"] == "external", prov
    assert prov["source"] == str(kit.resolve()), prov


def test_instance_reassigned_recompute_is_what_provenance_describes(
    tmp_path: Path,
) -> None:
    """Hits 1/6: dispatch calls `primitive.recompute` (instance attr) while a
    class-derived row described `type(primitive).recompute`. A reassigned
    instance attr diverges — the face could describe code that never runs.
    Provenance now derives from the instance's bound object."""
    pid = "kit_test_instance_reassign"
    kit = tmp_path / "reassign_kit.py"
    kit.write_text(
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "def _actual(i, s): return 0\n"
        "class M:\n"
        f"    primitive_id = {pid!r}\n"
        "    def recompute(self, i, s): return 1\n"
        "m = M(); m.recompute = _actual\n"  # instance attr shadows the class
        "register_primitive(m)\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    load_primitive_kit([kit], forbid_within=bundle)
    prov = primitive_provenance(pid)
    # _actual and M.recompute share the file here (both in the kit), so the
    # point is that derivation resolved the INSTANCE object without error and
    # bound to the kit file — not the class attribute via a stale path.
    assert prov["origin"] == "external", prov
    assert prov["source"] == str(kit.resolve()), prov


def test_subclass_reusing_distribution_recompute_shows_distribution(
    tmp_path: Path,
) -> None:
    """Disclosed, intended behavior (Finding B honest end): a kit that
    subclasses a distribution primitive to reuse its recompute IS running
    distribution code, so origin: distribution is truthful about the judging
    code. The face does not claim the id is distribution-authored — that the id
    is kit-introduced is separately visible in kit_modules[].registered. This
    pins the behavior so it is a documented property, not a hidden surprise."""
    pid = "kit_test_subclass_reuse"
    kit = tmp_path / "subclass_kit.py"
    kit.write_text(
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "from audit_bundle.rederivation.primitives.bom import BomRecompute\n"
        "class Reuse(BomRecompute):\n"
        f"    primitive_id = {pid!r}\n"
        "register_primitive(Reuse())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    try:
        rows = load_primitive_kit([kit], forbid_within=bundle)
        assert rows[0]["registered"] == [pid]  # the id IS attributed to the kit
        prov = primitive_provenance(pid)
        assert prov["origin"] == "distribution", prov  # the CODE is distribution
        assert prov["source"].endswith("bom.py"), prov
    finally:
        # The registry is process-global and xdist `--dist loadfile` puts several
        # test FILES in one worker, so what this file leaves registered is still
        # there when a later file asks what the distribution ships. This id is
        # the one kit fixture that lands in `distribution_primitives()`:
        # subclassing BomRecompute inherits its code object, so provenance labels
        # the origin `distribution` -- the very property asserted above. Leaking
        # it made the roster 28 names instead of 27 for the rest of the worker,
        # and `test_primitive_contract_ratchet` + `test_primitive_book_drift`
        # both compare against that roster. Measured 2026-08-29: running this
        # file before either of them fails 4 tests, DETERMINISTICALLY. It
        # presented as an intermittent suite because only worker ASSIGNMENT
        # varied -- a green full-suite run was luck, not evidence.
        registry._PRIMITIVE_REGISTRY.pop(pid, None)


def test_cli_primitive_sourced_inside_the_bundle_is_refused(tmp_path: Path) -> None:
    """Findings 1/2 & Hit 4: the --primitives ENTRY is containment-checked, but
    what the entry imports is not. An out-of-bundle kit that reaches into the
    bundle (`sys.path.insert(0, bundle); import producer_prim`) registers
    producer-authored code as the recompute. Dispatch refuses any RESOLVED
    primitive whose source resolves inside the original bundle root —
    `PRIMITIVE_SOURCE_INSIDE_BUNDLE`/could-not-conclude.

    The planted primitive .py is DECLARED in the manifest (with its true hash)
    so file-integrity passes and does not preempt the primitive-source check —
    this is the "producer ships the primitive as bundle content, reached via a
    kit" shape, the one file-integrity alone cannot catch."""
    import shutil

    bundle_dir = _build_climate(tmp_path / "climate")
    planted = bundle_dir / "producer_prim.py"
    shutil.copy(_CLIMATE_DIR / "climate_attribution_recompute.py", planted)
    # Declare the planted file in the manifest so file-integrity accepts it.
    mpath = bundle_dir / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    manifest.setdefault("files", {})["producer_prim.py"] = hashlib.sha256(
        planted.read_bytes()
    ).hexdigest()
    mpath.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    kit = tmp_path / "reach_in_kit.py"
    kit.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(bundle_dir)!r})\n"
        "from producer_prim import ClimateAttributionRecompute\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "register_primitive(ClimateAttributionRecompute())\n",
        encoding="utf-8",
    )
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(kit),
    )
    assert code == 2, (code, face.get("reason_codes"))
    details = " ".join(r.get("detail", "") for r in _all_reason_dicts(face))
    assert "PRIMITIVE_SOURCE_INSIDE_BUNDLE" in details, details
    assert "climate_attribution_recompute" in details, details


def _all_reason_dicts(face: dict) -> list[dict]:
    out: list[dict] = []

    def walk(v):
        for r in v.get("reasons") or ():
            out.append(r)
        for leg in v.get("legs") or ():
            walk(leg)

    if face.get("verdict"):
        walk(face["verdict"])
    return out


def _walk_reasons(face: dict) -> list[tuple]:
    return [(r.get("check_name"), r.get("code")) for r in _all_reason_dicts(face)]


def test_inert_in_bundle_primitive_on_a_no_outputs_bundle_does_not_refuse(
    tmp_path: Path,
) -> None:
    """Scoping regression (full-suite order caught this): the in-bundle-source
    guard is scoped to primitives dispatch RESOLVES, not every registered one.
    A pilot whose own primitive .py lives in its dir, verified IN PLACE, has that
    primitive's source 'inside the bundle' — but if the bundle declares no
    outputs, nothing is resolved and the guard must stay silent. The earlier
    all-registered guard refused here, breaking every no-outputs pilot whose
    primitive a prior test had registered."""
    from audit_bundle.rederivation.registry import register_primitive
    from audit_bundle.verifier import BundleVerifier

    # A pilot-shaped dir that ships its own primitive AND declares no outputs.
    bundle = tmp_path / "pilot"
    bundle.mkdir()
    prim_src = bundle / "my_recompute.py"
    prim_src.write_text(
        "class InDirPrimitive:\n"
        "    primitive_id = 'kit_test_inert_indir'\n"
        "    def recompute(self, i, s): return 0\n",
        encoding="utf-8",
    )
    import importlib.util

    spec = importlib.util.spec_from_file_location("kit_test_inert_mod", prim_src)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kit_test_inert_mod"] = mod
    spec.loader.exec_module(mod)
    register_primitive(mod.InDirPrimitive())  # source resolves INSIDE `bundle`

    # A minimal manifest declaring NO outputs. verify() must not refuse on the
    # in-bundle primitive (it is never resolved). It will reject for an unrelated
    # reason (no real payload), but NEVER PRIMITIVE_SOURCE_INSIDE_BUNDLE.
    (bundle / "manifest.json").write_text(
        json.dumps({"schema_version": "1", "files": {}}), encoding="utf-8"
    )
    result = BundleVerifier().verify(bundle)

    def _details(v):
        out = list(r.detail or "" for r in v.reasons)
        for leg in v.legs:
            out.extend(_details(leg))
        return out

    assert not any("PRIMITIVE_SOURCE_INSIDE_BUNDLE" in d for d in _details(result)), (
        _details(result)
    )


# ---------------------------------------------------------------------------
# The kit manifest: a kit DECLARES what it adds, and the loader checks it
#
# LEGIBILITY, NOT SECURITY (kit.py states this at length): a kit is code the
# verifier executes with its own authority, so a hostile kit can declare one set
# and register another. These tests pin the MISTAKE-and-DRIFT properties — the
# declared set and the actual set disagreeing, in either direction — never a
# defence against a kit that lies on purpose.
# ---------------------------------------------------------------------------


_MANIFEST_KIT_TEMPLATE = """\
KIT_NAME = {name!r}
KIT_VERSION = {version!r}
KIT_REGISTERS = {registers!r}

from audit_bundle.rederivation.registry import register_primitive


def _make(pid):
    ns = {{
        "primitive_id": pid,
        "recompute": lambda self, inputs, section: 0,
    }}
    return type("_KitPrimitive", (), ns)()


for _pid in {actual!r}:
    register_primitive(_make(_pid))
"""


def _write_manifest_kit(
    path: Path,
    *,
    declares,
    registers,
    name: str = "test-kit",
    version: str = "1",
) -> Path:
    """A kit that DECLARES `declares` and actually REGISTERS `registers`.

    Registration runs in a LOOP over the actual ids on purpose: the loader
    constrains only the declared SET against the actual SET, never HOW a kit
    registers, so the fixture that exercises the check must itself be one the
    check could not have been written to depend on statically."""
    path.write_text(
        _MANIFEST_KIT_TEMPLATE.format(
            name=name,
            version=version,
            registers=tuple(declares),
            actual=tuple(registers),
        ),
        encoding="utf-8",
    )
    return path


def test_manifest_matching_reality_is_reported_as_match(tmp_path: Path) -> None:
    ids = ("kit_test_manifest_match_a", "kit_test_manifest_match_b")
    kit = _write_manifest_kit(
        tmp_path / "kit.py",
        declares=ids,
        registers=ids,
        name="acme-fea-kit",
        version="2",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)

    assert row["manifest"] == "match", row
    assert row["manifest_declaration"] == {
        "name": "acme-fea-kit",
        "version": "2",
        "registers": sorted(ids),
        "unreadable": [],
    }, row
    assert row["manifest_mismatch"] is None
    assert row["manifest_reason_codes"] == []
    assert sorted(row["registered"]) == sorted(ids)
    # The declaration is a CLAIM read from the file; `registered` is measured
    # from the registry. Equal here, but never the same field.
    assert row["containment"] == "checked"


def test_kit_with_no_manifest_still_loads_and_says_absent(tmp_path: Path) -> None:
    """A manifest is not mandatory. The row says `absent` — the same posture as
    an outside primitive carrying a null tier rather than a guessed one."""
    pid = "kit_test_manifest_absent"
    kit = _write_kit(tmp_path / "kit.py", pid)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)

    assert row["manifest"] == "absent", row
    assert row["manifest_declaration"] is None
    assert row["manifest_reason_codes"] == []
    assert row["registered"] == [pid]


# --- the two mutant controls. Both must FIRE, with DISTINCT reason codes. ---


def test_mutant_declaring_two_while_registering_three_is_caught(
    tmp_path: Path,
) -> None:
    """MUTANT CONTROL (undeclared direction). The kit adds a method its own
    manifest does not mention — the reviewer's list is SHORT."""
    declares = ("kit_test_mutant_extra_a", "kit_test_mutant_extra_b")
    registers = declares + ("kit_test_mutant_extra_c",)
    kit = _write_manifest_kit(
        tmp_path / "kit.py", declares=declares, registers=registers
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)

    assert row["manifest"] == "mismatch", row
    assert row["manifest_mismatch"]["undeclared"] == ["kit_test_mutant_extra_c"], row
    assert row["manifest_mismatch"]["unfulfilled"] == [], row
    assert row["manifest_reason_codes"] == ["KIT_MANIFEST_UNDECLARED_REGISTRATION"], row
    # And the undeclared id is queryable by dispatch, which is the only place
    # that knows whether a pinned spec actually binds it.
    hit = undeclared_kit_registration("kit_test_mutant_extra_c")
    assert hit and hit["kit_path"] == str(kit.resolve()), hit
    assert undeclared_kit_registration("kit_test_mutant_extra_a") is None


def test_mutant_declaring_an_id_it_never_registers_is_caught(tmp_path: Path) -> None:
    """MUTANT CONTROL (unfulfilled direction). The manifest promises a method
    the kit never registered — the reviewer's list is LONG, and a spec binding
    that id reaches UNKNOWN_PRIMITIVE at dispatch with no explanation on the
    face unless this fires. Checking only the other direction leaves the whole
    check half-inert."""
    registers = ("kit_test_mutant_short_a",)
    declares = registers + ("kit_test_mutant_short_promised",)
    kit = _write_manifest_kit(
        tmp_path / "kit.py", declares=declares, registers=registers
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)

    assert row["manifest"] == "mismatch", row
    assert row["manifest_mismatch"]["unfulfilled"] == [
        "kit_test_mutant_short_promised"
    ], row
    assert row["manifest_mismatch"]["undeclared"] == [], row
    assert row["manifest_reason_codes"] == ["KIT_MANIFEST_UNFULFILLED_DECLARATION"], row
    # An unfulfilled DECLARATION is not an undeclared REGISTRATION: nothing was
    # registered, so dispatch has nothing to refuse.
    assert undeclared_kit_registration("kit_test_mutant_short_promised") is None


def test_the_two_directions_carry_distinct_codes_when_both_fire(
    tmp_path: Path,
) -> None:
    kit = _write_manifest_kit(
        tmp_path / "kit.py",
        declares=("kit_test_both_declared_only",),
        registers=("kit_test_both_registered_only",),
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)

    assert row["manifest_reason_codes"] == [
        "KIT_MANIFEST_UNDECLARED_REGISTRATION",
        "KIT_MANIFEST_UNFULFILLED_DECLARATION",
    ], row
    assert len(set(row["manifest_reason_codes"])) == 2
    assert row["manifest_mismatch"] == {
        "undeclared": ["kit_test_both_registered_only"],
        "unfulfilled": ["kit_test_both_declared_only"],
    }, row


def test_a_kit_may_register_a_family_in_a_loop(tmp_path: Path) -> None:
    """SETTLED design point, pinned as a test so it cannot be tightened by
    accident: nothing constrains HOW a kit registers. Forcing statically
    enumerable `register_primitive(X())` calls would break a kit registering a
    family in a loop and would buy a guarantee only against an attacker the
    trust model already declines to defend against."""
    ids = tuple(f"kit_test_family_{i}" for i in range(5))
    kit = _write_manifest_kit(tmp_path / "kit.py", declares=ids, registers=ids)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)

    assert row["manifest"] == "match", row
    assert sorted(row["registered"]) == sorted(ids)


def test_annotated_declaration_is_read(tmp_path: Path) -> None:
    """`KIT_NAME: str = "..."` is the same declaration with a type hint. Reading
    only bare assignments would report a manifest as ABSENT because of an
    annotation — a false 'this kit declares nothing'."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        'KIT_NAME: str = "annotated-kit"\n'
        'KIT_VERSION: str = "1"\n'
        'KIT_REGISTERS: tuple[str, ...] = ("kit_test_annotated",)\n'
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_test_annotated'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "match", row
    assert row["manifest_declaration"]["name"] == "annotated-kit"


def test_labels_without_a_registers_claim_are_unchecked_not_absent(
    tmp_path: Path,
) -> None:
    """KIT_NAME/KIT_VERSION are LABELS — nothing about them is checkable. A file
    carrying only labels has a manifest a human reader can see, so calling it
    `absent` would be the report lying by omission; `unchecked` says a manifest
    is present and none of it was comparable."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        'KIT_NAME = "labels-only"\n'
        'KIT_VERSION = "3"\n'
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_test_labels_only'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "unchecked", row
    assert row["manifest_declaration"]["registers"] is None
    assert row["manifest_reason_codes"] == []


def test_a_computed_registers_claim_is_unchecked_never_silently_absent(
    tmp_path: Path,
) -> None:
    """The manifest is read by PARSING, so a KIT_REGISTERS built at runtime is
    not readable. Falling through to `absent` would let a computed declaration
    opt out of the comparison by accident; `unchecked` names what happened."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        'KIT_NAME = "computed"\n'
        "KIT_REGISTERS = tuple(sorted({'kit_test_computed'}))\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_test_computed'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "unchecked", row
    assert "KIT_REGISTERS" in (row["manifest_note"] or ""), row


@pytest.mark.parametrize(
    "declaration, match",
    [
        ('KIT_REGISTERS = "kit_test_bad_str"', "list or tuple"),
        ("KIT_REGISTERS = ()", "EMPTY"),
        ('KIT_REGISTERS = ("ok_id", 7)', "non-empty primitive_id string"),
        ('KIT_REGISTERS = ("dup", "dup")', "repeated"),
        ('KIT_NAME = 3\nKIT_REGISTERS = ("x",)', "non-empty string"),
    ],
)
def test_malformed_manifest_is_refused(
    tmp_path: Path, declaration: str, match: str
) -> None:
    """A manifest nobody can compare is worse than no manifest: it still reads
    to a human as a declaration. Operator error -> KitConstructionError."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        declaration + "\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_test_malformed'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with pytest.raises(KitConstructionError, match=match):
        load_primitive_kit([kit], forbid_within=bundle)


def test_manifest_is_read_before_the_kit_executes(tmp_path: Path) -> None:
    """The declaration is parsed from the SAME bytes that get hashed and
    compiled, BEFORE any of them run — so a malformed manifest is refused
    without the kit's body having executed at all."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    canary = tmp_path / "canary.txt"
    kit = tmp_path / "kit.py"
    kit.write_text(
        f"KIT_REGISTERS = \"not-a-list\"\nopen({str(canary)!r}, 'w').write('ran')\n",
        encoding="utf-8",
    )
    with pytest.raises(KitConstructionError, match="list or tuple"):
        load_primitive_kit([kit], forbid_within=bundle)
    assert not canary.exists(), "kit body executed before its manifest was read"


def test_manifest_survives_the_idempotent_cache(tmp_path: Path) -> None:
    ids = ("kit_test_cached_manifest",)
    kit = _write_manifest_kit(tmp_path / "kit.py", declares=ids, registers=ids)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    first = load_primitive_kit([kit], forbid_within=bundle)
    second = load_primitive_kit([kit], forbid_within=bundle)
    assert first == second
    assert second[0]["manifest"] == "match", second[0]


def test_an_id_another_kit_already_registered_is_named_as_such(
    tmp_path: Path,
) -> None:
    """The one reachable case where the declared-vs-ADDED denominator reports a
    disagreement nobody misdeclared: two entry kits importing a SHARED sibling
    module, so the second kit's `register_primitive` is idempotent (sys.modules
    handed it the same class object) and adds nothing to the set-diff.

    Still reported — excusing it would need "declared, and registered by someone
    else" to count as this kit's, which is the claim the row exists to check —
    but the note must say WHICH case it is, so a reader is not sent hunting for
    a missing primitive that is sitting in the registry."""
    (tmp_path / "shared_prim.py").write_text(
        "class Shared:\n"
        "    primitive_id = 'kit_test_shared_prim'\n"
        "    def recompute(self, i, s): return 0\n",
        encoding="utf-8",
    )
    kit_a = tmp_path / "kit_a.py"
    kit_a.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from shared_prim import Shared\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "register_primitive(Shared())\n",
        encoding="utf-8",
    )
    kit_b = tmp_path / "kit_b.py"
    kit_b.write_text(
        'KIT_NAME = "kit-b"\n'
        'KIT_REGISTERS = ("kit_test_shared_prim", "kit_test_kit_b_own")\n'
        "import sys\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from shared_prim import Shared\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "register_primitive(Shared())\n"
        "class Own:\n"
        "    primitive_id = 'kit_test_kit_b_own'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(Own())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    rows = load_primitive_kit([kit_a, kit_b], forbid_within=bundle)

    assert rows[0]["registered"] == ["kit_test_shared_prim"], rows[0]
    assert rows[1]["registered"] == ["kit_test_kit_b_own"], rows[1]
    assert rows[1]["manifest"] == "mismatch", rows[1]
    assert rows[1]["manifest_mismatch"] == {
        "undeclared": [],
        "unfulfilled": ["kit_test_shared_prim"],
    }, rows[1]
    note = rows[1]["manifest_note"] or ""
    assert "already in the registry" in note, note
    assert "NEVER registered" not in note, note


# ---------------------------------------------------------------------------
# `forbid_within`: NO_BUNDLE is STATED, never accidentally satisfied
# ---------------------------------------------------------------------------


def test_no_bundle_sentinel_states_the_refusal_inapplicable(tmp_path: Path) -> None:
    pid = "kit_test_no_bundle_ok"
    kit = _write_kit(tmp_path / "kit.py", pid)

    (row,) = load_primitive_kit([kit], forbid_within=NO_BUNDLE)

    assert row["containment"] == "inapplicable_no_bundle", row
    assert row["registered"] == [pid]


def test_a_nonexistent_forbid_within_is_refused_not_trivially_satisfied(
    tmp_path: Path,
) -> None:
    """THE BYPASS THIS EXISTS TO STOP. A spike reached no-bundle mode by handing
    the containment check "/nonexistent/no-bundle", against which no kit path can
    ever be inside — the check TRIVIALLY SUCCEEDS. A later audit cannot tell that
    apart from a bypass, and this codebase already shipped one fail-open of the
    shape (an in-bundle anchor verifying a fully forged bundle clean). A caller
    with no bundle must say NO_BUNDLE."""
    kit = _write_kit(tmp_path / "kit.py", "kit_test_fake_forbid_within")
    with pytest.raises(KitConstructionError, match="not an existing directory"):
        load_primitive_kit([kit], forbid_within="/nonexistent/no-bundle")
    with pytest.raises(KitConstructionError, match="not an existing directory"):
        load_primitive_kit([kit], forbid_within=tmp_path / "never_created")


def test_no_bundle_mode_cannot_be_reached_by_a_path(tmp_path: Path) -> None:
    """The sentinel is matched by IDENTITY, so no string or path can become it.
    A directory literally named NO_BUNDLE is still a directory: a kit inside it
    is refused exactly as it would be inside any other bundle dir."""
    with pytest.raises(KitConstructionError, match="not an existing directory"):
        load_primitive_kit([tmp_path / "x.py"], forbid_within="NO_BUNDLE")

    bundle = tmp_path / "NO_BUNDLE"
    bundle.mkdir()
    inside = _write_kit(bundle / "kit.py", "kit_test_named_no_bundle")
    with pytest.raises(KitConstructionError, match="INSIDE"):
        load_primitive_kit([inside], forbid_within=bundle)


def test_no_bundle_mode_keeps_every_other_refusal(tmp_path: Path) -> None:
    """Only the CONTAINMENT refusal is inapplicable without a bundle. The
    anti-vacuity, raising-kit and bytes-drift refusals are properties of the kit
    itself and must still fire."""
    noop = tmp_path / "noop.py"
    noop.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(KitConstructionError, match="registered no new"):
        load_primitive_kit([noop], forbid_within=NO_BUNDLE)

    raising = tmp_path / "raising.py"
    raising.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    with pytest.raises(KitConstructionError, match="raised during load"):
        load_primitive_kit([raising], forbid_within=NO_BUNDLE)


# ---------------------------------------------------------------------------
# Bundle mode: an undeclared registration is a DISCLOSURE until a spec binds it
# ---------------------------------------------------------------------------


def test_cli_kit_manifest_reaches_the_face_and_the_exemplar_matches(
    tmp_path: Path,
) -> None:
    """Two kits at once: the shipped climate exemplar (which declares its one
    primitive) and an inert kit whose declaration disagrees with what it
    registered. The bundle still verifies OK — an undeclared primitive NO spec
    binds is inert — and the disagreement is legible on the face rather than
    fatal. This is the scoping precedent PRIMITIVE_SOURCE_INSIDE_BUNDLE set: an
    inert registered primitive launders nothing."""
    bundle_dir = _build_climate(tmp_path / "climate")
    inert = tmp_path / "inert_kit.py"
    inert.write_text(
        'KIT_NAME = "inert-kit"\n'
        'KIT_VERSION = "1"\n'
        'KIT_REGISTERS = ("kit_test_inert_declared",)\n'
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_test_inert_actual'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )

    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(_CLIMATE_KIT),
        str(inert),
    )

    assert code == 0, (code, face.get("reason_codes"))
    gates = {g.get("gate"): g for g in face.get("cli_gates") or ()}
    rows = {r["path"]: r for r in gates["primitive_kit"]["kit_modules"]}

    climate_row = rows[str(_CLIMATE_KIT.resolve())]
    assert climate_row["manifest"] == "match", climate_row
    assert climate_row["manifest_declaration"]["registers"] == [
        "climate_attribution_recompute"
    ], climate_row

    inert_row = rows[str(inert.resolve())]
    assert inert_row["manifest"] == "mismatch", inert_row
    assert inert_row["manifest_mismatch"] == {
        "undeclared": ["kit_test_inert_actual"],
        "unfulfilled": ["kit_test_inert_declared"],
    }, inert_row


def test_cli_undeclared_primitive_that_dispatch_binds_cannot_conclude(
    tmp_path: Path,
) -> None:
    """The scoped refusal. This kit registers the primitive the pinned spec
    actually binds while declaring a different id, so the code that judged the
    output is code the kit that supplied it did not disclose.

    EXIT 2 (could-not-conclude), never exit 1: a manifest disagreement is a
    property of the AUDITOR'S OWN KIT. Nothing has been shown wrong with the
    bundle, so calling it a REJECT would say 'this artifact is bad' about an
    artifact this run never judged. Same routing as
    PRIMITIVE_SOURCE_INSIDE_BUNDLE, whose scoping this mirrors."""
    bundle_dir = _build_climate(tmp_path / "climate")
    kit = tmp_path / "mislabelled_kit.py"
    kit.write_text(
        'KIT_NAME = "mislabelled-kit"\n'
        'KIT_VERSION = "1"\n'
        'KIT_REGISTERS = ("some_other_id",)\n'
        "import sys\n"
        f"sys.path.insert(0, {str(_CLIMATE_DIR)!r})\n"
        "from climate_attribution_recompute import ClimateAttributionRecompute\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "register_primitive(ClimateAttributionRecompute())\n",
        encoding="utf-8",
    )

    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(kit),
    )

    assert code == 2, (code, face.get("reason_codes"))
    details = " ".join(r.get("detail", "") for r in _all_reason_dicts(face))
    assert "PRIMITIVE_UNDECLARED_BY_KIT" in details, details
    assert "climate_attribution_recompute" in details, details


# ---------------------------------------------------------------------------
# `veriker --kit <path>` — judging a KIT, with no bundle in the picture
# ---------------------------------------------------------------------------


def _run_kit_cli(verdict_out: Path, *kits: str, extra: tuple[str, ...] = ()):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--kit",
            *kits,
            "--verdict-out",
            str(verdict_out),
            *extra,
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert verdict_out.exists(), (
        f"--verdict-out was not written (exit {proc.returncode})\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    return proc.returncode, json.loads(verdict_out.read_text(encoding="utf-8")), proc


def test_kit_mode_matching_manifest_exits_zero(tmp_path: Path) -> None:
    code, face, proc = _run_kit_cli(tmp_path / "v.json", str(_CLIMATE_KIT))
    assert code == 0, (code, proc.stdout, proc.stderr)
    assert face["state"] == "OK"
    # Bundle-independent by construction: no bundle was read, so there is no
    # bundle verdict and no input manifest hash to report.
    assert face["verdict"] is None, face["verdict"]
    assert face["input_manifest_sha256"] is None
    gates = {g["gate"]: g for g in face["cli_gates"]}
    (row,) = gates["primitive_kit"]["kit_modules"]
    assert row["manifest"] == "match", row
    assert row["containment"] == "inapplicable_no_bundle", row
    assert gates["kit_manifest"]["status"] == "MATCH", gates["kit_manifest"]


def test_kit_mode_mismatch_exits_one_with_both_codes(tmp_path: Path) -> None:
    kit = _write_manifest_kit(
        tmp_path / "kit.py",
        declares=("kit_mode_declared_only",),
        registers=("kit_mode_registered_only",),
    )
    code, face, proc = _run_kit_cli(tmp_path / "v.json", str(kit))
    assert code == 1, (code, proc.stdout, proc.stderr)
    assert face["state"] == "REJECT"
    assert face["reason_codes"] == [
        "KIT_MANIFEST_UNDECLARED_REGISTRATION",
        "KIT_MANIFEST_UNFULFILLED_DECLARATION",
    ], face["reason_codes"]


def test_kit_mode_unloadable_kit_exits_two(tmp_path: Path) -> None:
    kit = tmp_path / "raising.py"
    kit.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    code, face, _ = _run_kit_cli(tmp_path / "v.json", str(kit))
    assert code == 2, (code, face.get("reason_codes"))
    assert face["state"] == "ERROR"
    assert face["reason_codes"] == ["PRIMITIVES_ARG_INVALID"], face["reason_codes"]


def test_kit_mode_no_manifest_exits_zero_and_the_face_says_absent(
    tmp_path: Path,
) -> None:
    kit = _write_kit(tmp_path / "kit.py", "kit_mode_no_manifest")
    code, face, proc = _run_kit_cli(tmp_path / "v.json", str(kit))
    assert code == 0, (code, proc.stdout, proc.stderr)
    (row,) = {g["gate"]: g for g in face["cli_gates"]}["primitive_kit"]["kit_modules"]
    assert row["manifest"] == "absent", row
    assert face["reason_codes"] == []


def test_kit_mode_refuses_bundle_only_flags(tmp_path: Path) -> None:
    """A bundle-mode flag silently ignored in kit mode is a fail-open reading:
    `--require-rederivation --kit X` returning 0 would tell an operator that
    re-derivation was required and satisfied, on a run that read no bundle."""
    kit = _write_kit(tmp_path / "kit.py", "kit_mode_flag_conflict")
    for flag in ("--require-rederivation", "--unsafe-run-bundle-pack"):
        out = tmp_path / f"v{flag.strip('-')}.json"
        code, face, _ = _run_kit_cli(out, str(kit), extra=(flag,))
        assert code == 2, (flag, code)
        assert face["reason_codes"] == ["INPUT_MODE_INVALID"], (flag, face)


def test_neither_and_both_input_modes_are_refused(tmp_path: Path) -> None:
    kit = _write_kit(tmp_path / "kit.py", "kit_mode_both")
    bundle_dir = _build_climate(tmp_path / "climate")
    out = tmp_path / "v.json"

    proc = subprocess.run(
        [sys.executable, "-m", "veriker.cli.verify", "--verdict-out", str(out)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 2, proc.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["reason_codes"] == [
        "INPUT_MODE_INVALID"
    ]

    out2 = tmp_path / "v2.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle_dir),
            "--kit",
            str(kit),
            "--verdict-out",
            str(out2),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert proc.returncode == 2, proc.stderr
    assert json.loads(out2.read_text(encoding="utf-8"))["reason_codes"] == [
        "INPUT_MODE_INVALID"
    ]


# ---------------------------------------------------------------------------
# Round 2 — fresh-context adversarial pass, 2026-08-29. Every test below pins a
# way the check reported MATCH / ABSENT where an honest kit and its declaration
# had actually diverged, or a claim the code could not back.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pid, declaration, why",
    [
        (
            "kit_r2_tuple",
            'KIT_NAME, KIT_REGISTERS = "n", ("kit_r2_tuple",)',
            "tuple destructuring",
        ),
        (
            "kit_r2_augmented",
            'KIT_REGISTERS = ()\nKIT_REGISTERS += ("kit_r2_augmented",)',
            "augmented assignment",
        ),
    ],
)
def test_declaration_shapes_the_parser_cannot_read_are_never_absent(
    tmp_path: Path, pid: str, declaration: str, why: str
) -> None:
    """A reviewer reads every one of these as a declaration. Reading only
    single-target `ast.Assign` reported `manifest: absent` for all of them —
    silently opting the kit out of the comparison, which is the exact defect the
    AnnAssign branch was added to stop. They must report `unchecked`."""
    kit = tmp_path / f"kit_{why.replace(' ', '_')}.py"
    kit.write_text(
        declaration + "\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        f"    primitive_id = {pid!r}\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "unchecked", (why, row)
    assert "KIT_REGISTERS" in (row["manifest_note"] or ""), (why, row)


def test_a_chained_declaration_is_read_not_merely_flagged(tmp_path: Path) -> None:
    """`KIT_REGISTERS = KIT_ALIAS = ("id",)` binds both names to one literal, so
    the parser can evaluate it — this shape is READ, not downgraded to
    `unchecked`. It reported `absent` before, because only single-target
    assignments were considered."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        'KIT_REGISTERS = KIT_ALIAS = ("kit_r2_chained",)\n'
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_r2_chained'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "match", row
    assert row["manifest_declaration"]["registers"] == ["kit_r2_chained"], row


def test_an_imported_declaration_is_unchecked_not_absent(tmp_path: Path) -> None:
    """`from _manifest import KIT_REGISTERS` binds the name at module level from
    a file this parser does not follow. Absent would be a silent opt-out."""
    (tmp_path / "_manifest.py").write_text(
        'KIT_REGISTERS = ("kit_r2_imported",)\n', encoding="utf-8"
    )
    kit = tmp_path / "kit.py"
    kit.write_text(
        "from _manifest import KIT_REGISTERS\n"
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_r2_imported'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "unchecked", row
    assert "KIT_REGISTERS" in (row["manifest_note"] or ""), row


def test_an_unrelated_kit_prefixed_name_is_not_a_manifest(tmp_path: Path) -> None:
    """`KIT_` was treated as a reserved namespace, so a kit with an ordinary
    `KIT_ROOT` and NO manifest reported `unchecked` with a note about labels it
    never wrote — a false report on honest input. The manifest is the three keys
    exactly; the near-miss is NAMED on the absent row so a typo still surfaces
    instead of reading as silence."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        'KIT_ROOT = "/opt/kits"\n'
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_r2_prefix'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "absent", row
    assert row["manifest_declaration"] is None, row
    assert "KIT_ROOT" in (row["manifest_note"] or ""), row


def test_a_typo_near_miss_is_named_on_the_absent_row(tmp_path: Path) -> None:
    """`KIT_REGISTER` (singular) declares nothing this loader can compare. The
    row is honestly `absent` — but naming what it saw is the difference between
    a legible report and silence."""
    kit = tmp_path / "kit.py"
    kit.write_text(
        'KIT_REGISTER = ("kit_r2_typo",)\n'
        "from audit_bundle.rederivation.registry import register_primitive\n"
        "class M:\n"
        "    primitive_id = 'kit_r2_typo'\n"
        "    def recompute(self, i, s): return 0\n"
        "register_primitive(M())\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["manifest"] == "absent", row
    assert "KIT_REGISTER" in (row["manifest_note"] or ""), row


def test_containment_row_names_the_root_it_was_checked_against(
    tmp_path: Path,
) -> None:
    """`containment: "checked"` is not a backed positive on its own — ANY
    existing directory not containing the kit passes, and the loader cannot know
    whether it was the bundle under audit. The root travels on the row so a
    reader sees WHAT was compared rather than trusting the word."""
    kit = _write_kit(tmp_path / "kit.py", "kit_r2_containment_root")
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    (row,) = load_primitive_kit([kit], forbid_within=bundle)
    assert row["containment"] == "checked", row
    assert row["containment_root"] == str(bundle.resolve()), row

    other = _write_kit(tmp_path / "kit2.py", "kit_r2_containment_none")
    (row2,) = load_primitive_kit([other], forbid_within=NO_BUNDLE)
    assert row2["containment"] == "inapplicable_no_bundle", row2
    assert row2["containment_root"] is None, row2


def test_the_dispatch_guard_still_fires_after_a_cache_hit(tmp_path: Path) -> None:
    """`_LOADED_KITS` returns early on a repeat load without re-seeding the
    undeclared map. That is only correct because the map is process-global and
    never cleared — an invariant nothing pinned until this test."""
    kit = _write_manifest_kit(
        tmp_path / "kit.py",
        declares=("kit_r2_cache_declared",),
        registers=("kit_r2_cache_declared", "kit_r2_cache_undeclared"),
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    load_primitive_kit([kit], forbid_within=bundle)
    assert undeclared_kit_registration("kit_r2_cache_undeclared") is not None

    (cached_row,) = load_primitive_kit([kit], forbid_within=bundle)  # cache hit
    assert cached_row["manifest"] == "mismatch", cached_row
    assert undeclared_kit_registration("kit_r2_cache_undeclared") is not None


def test_kit_mode_keeps_a_mismatch_row_when_a_later_kit_fails_to_load(
    tmp_path: Path,
) -> None:
    """`load_primitive_kit` raises on the first unusable entry and returns
    nothing, so one broken kit discarded every row already gathered — including
    the MISMATCH the operator most needed to see. --kit loads per path. ERROR
    still outranks REJECT for the exit code."""
    good = _write_manifest_kit(
        tmp_path / "a_mismatch.py",
        declares=("kit_r2_multi_declared",),
        registers=("kit_r2_multi_registered",),
    )
    broken = tmp_path / "b_broken.py"
    broken.write_text("raise RuntimeError('boom')\n", encoding="utf-8")

    code, face, proc = _run_kit_cli(tmp_path / "v.json", str(good), str(broken))

    assert code == 2, (code, proc.stdout, proc.stderr)
    gates = {g["gate"]: g for g in face["cli_gates"]}
    rows = gates["primitive_kit"]["kit_modules"]
    assert [r["path"] for r in rows] == [str(good.resolve())], rows
    assert rows[0]["manifest"] == "mismatch", rows[0]
    assert gates["primitive_kit"]["load_errors"], gates["primitive_kit"]
    assert "PRIMITIVES_ARG_INVALID" in face["reason_codes"], face["reason_codes"]
    # And the mismatch is still reported, not swallowed by the load failure.
    assert "KIT_MANIFEST_UNDECLARED_REGISTRATION" in face["reason_codes"], face


def test_kit_mode_aggregate_never_reads_match_for_an_undeclared_kit(
    tmp_path: Path,
) -> None:
    """The aggregate collapsing `absent` back into MATCH would undo the whole
    point of the absent label."""
    plain = _write_kit(tmp_path / "plain.py", "kit_r2_agg_absent")
    code, face, _ = _run_kit_cli(tmp_path / "v.json", str(plain))
    assert code == 0
    gates = {g["gate"]: g for g in face["cli_gates"]}
    assert gates["kit_manifest"]["status"] == "ABSENT", gates["kit_manifest"]
    assert gates["kit_manifest"]["by_status"] == {"absent": 1}
