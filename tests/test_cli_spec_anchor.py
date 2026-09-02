"""tests/test_cli_spec_anchor.py — the shipped CLI can supply an auditor anchor.

Before `--spec-anchor` existed, `python -m veriker.cli.verify` could not hand the
verifier a SpecAnchor at all, so EVERY bundle declaring `manifest.outputs`
(Axis-2 spec-pinned dispatch) came back non-OK no matter how honest it was: the
anchor load refused, and the refusal was reported as an `AnchorViolation`
REJECT — the same code a bundle earns for substituting a weakened spec.

Two independent defects, both closed here:

  1. CAPABILITY — the CLI now builds `SpecAnchor{spec_id: sha256(bytes)}` from
     OPERATOR-side spec files, byte-for-byte as the pilots' own verify.py
     scripts do, so an honest Axis-2 bundle reaches exit 0 through the shipping
     offline tool and its re-derivation actually runs.
  2. REASON-CODE SPLIT — "no anchor was supplied" is the VERIFIER's incapacity
     (`AnchorNotSupplied` -> VERIFIER_INCOMPLETE, exit 2: could not conclude),
     while "the producer's spec is not the anchored one" stays the ARTIFACT's
     defect (`AnchorViolation` -> REJECT, exit 1).

The third test below is the one that makes the split falsifiable. Without it,
splitting the code out is indistinguishable from deleting the Axis-1 check: both
stop the honest-bundle REJECT, only one still catches a substituted spec.

FIXTURE CHOICE — `examples/bom_minimal`. Its spec binds
`primitive_id: bom_recompute`, which ships IN THE VERIFIER DISTRIBUTION
(`audit_bundle/rederivation/primitives/bom.py`), and it needs no pilot-local
typed-check plugin. The CLI can therefore verify it with nothing but the flag.
That is NOT true of most Axis-2 pilots — those need the second half of the
auditor kit, `--primitives` (tests/test_primitive_kit.py); the pair of tests
at the bottom pins both directions: reachable WITH the kit, fail-closed
without it.

Every CLI verdict here is read from the `--verdict-out` JSON, never from stdout:
the terminal summary is a count and does not print failure detail.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_BOM_DIR = _PKG_ROOT / "examples" / "bom_minimal"
_BOM_SPEC = _BOM_DIR / "spec_pinned" / "bom.spec.json"
_CLIMATE_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"
_CLIMATE_SPECS = (
    _CLIMATE_DIR / "spec_pinned" / "climate.spec.json",
    _CLIMATE_DIR / "spec_pinned" / "climate_emission.spec.json",
)

_RE_DERIVATION_ABSENT_CODE = "NO_RE_DERIVATION_PERFORMED"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _load_by_path(name: str, path: Path):
    """Load a pilot module by path, REUSING an existing sys.modules entry.

    Replacing the entry would create a second, equal-named primitive class and
    `register_primitive` rejects that collision — the failure mode where these
    tests pass alone and fail together.
    """
    import importlib.util

    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _build_bom(dest: Path) -> Path:
    if str(_BOM_DIR) not in sys.path:
        sys.path.insert(0, str(_BOM_DIR))
    _load_by_path("bom_recompute", _BOM_DIR / "bom_recompute.py")
    spc = _load_by_path("bom_spec_pinned_check", _BOM_DIR / "spec_pinned_check.py")
    return spc.build_spec_pinned(dest)


def _build_climate(dest: Path) -> Path:
    if str(_CLIMATE_DIR) not in sys.path:
        sys.path.insert(0, str(_CLIMATE_DIR))
    mod = _load_by_path(
        "climate_emission_minimal._build_bundle", _CLIMATE_DIR / "_build_bundle.py"
    )
    mod.build(dest)
    return dest


def _run_cli(bundle_dir: Path, verdict_out: Path, *extra: str):
    """Invoke the SHIPPED CLI in a subprocess and return (exit_code, face)."""
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


def _codes(face: dict) -> list[str]:
    return list(face.get("reason_codes") or ())


def _reasons(face: dict) -> list[tuple[str, str]]:
    """Every (check_name, code) pair on the verdict face, legs included."""
    out: list[tuple[str, str]] = []

    def walk(v):
        for r in v.get("reasons") or ():
            out.append((r.get("check_name"), r.get("code")))
        for leg in v.get("legs") or ():
            walk(leg)

    verdict = face.get("verdict")
    if verdict:
        walk(verdict)
    return out


def _weaken_bundle_spec(bundle_dir: Path, spec_name: str) -> None:
    """Substitute a laxer comparator into the bundle's OWN spec/ copy and realign
    every manifest SHA surface that names it, so file_integrity / spec_sha_pin
    cannot fire first and mask the anchor leg. This is the producer's strongest
    move: the bundle is fully hash-coherent, and ONLY the auditor's anchor —
    computed from bytes the producer never touched — can catch it.
    """
    spec_path = bundle_dir / "spec" / spec_name
    doc = json.loads(spec_path.read_text(encoding="utf-8"))
    type_key = next(iter(doc["types"]))
    doc["types"][type_key]["comparator"] = {
        "kind": "scalar_epsilon",
        "params": {"epsilon": 1e9},
    }
    raw = json.dumps(doc, indent=2).encode("utf-8")
    spec_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["spec_files"][spec_name] = digest
    rel = f"spec/{spec_name}"
    if rel in manifest.get("files", {}):
        manifest["files"][rel] = digest
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# (a) honest bundle + --spec-anchor -> exit 0
# ---------------------------------------------------------------------------


def test_honest_axis2_bundle_with_anchor_exits_0(tmp_path: Path) -> None:
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(
        bundle_dir, tmp_path / "v.json", "--spec-anchor", str(_BOM_SPEC)
    )
    assert code == 0, (code, _codes(face), _reasons(face))
    assert face["verdict"]["state"] == "OK", face["verdict"]["state"]
    assert _codes(face) == [], _codes(face)


# ---------------------------------------------------------------------------
# (b) same bundle, NO flag -> exit 2 (could not conclude), NOT exit 1
# ---------------------------------------------------------------------------


def test_no_anchor_flag_is_exit_2_not_exit_1(tmp_path: Path) -> None:
    """The verifier was handed no authority, so it concluded nothing. Reporting
    that as a REJECT (exit 1) blamed the bundle for the operator's omission —
    and, worse, made an honest Axis-2 bundle indistinguishable from a forged one
    on the exit code alone."""
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(bundle_dir, tmp_path / "v.json")
    assert code == 2, (code, _codes(face), _reasons(face))
    assert face["verdict"]["state"] == "ERROR", face["verdict"]["state"]
    assert face["verdict"]["error_kind"] == "INCOMPLETE", face["verdict"]["error_kind"]
    # The anchor step reports could-not-conclude, and NOTHING reports a REJECT
    # for this cause.
    assert ("spec_pinned_dispatch:anchor", "VERIFIER_INCOMPLETE") in _reasons(face), (
        _reasons(face)
    )
    assert "AnchorViolation" not in _codes(face), _codes(face)


def test_no_anchor_detail_names_the_flag(tmp_path: Path) -> None:
    """The disclosure has to point at the fix. It told operators for months that
    only the library API could supply an anchor; that is now false."""
    bundle_dir = _build_bom(tmp_path / "bom")
    _code, face = _run_cli(bundle_dir, tmp_path / "v.json")
    details = " ".join(
        r["detail"]
        for leg in [face["verdict"], *face["verdict"]["legs"]]
        for r in leg["reasons"]
    )
    assert "--spec-anchor" in details, details


# ---------------------------------------------------------------------------
# (c) weakened in-bundle spec, WITH the flag -> exit 1 AnchorViolation.
#     This is what proves the split did not weaken Axis-1.
# ---------------------------------------------------------------------------


def test_substituted_spec_with_anchor_is_still_exit_1(tmp_path: Path) -> None:
    bundle_dir = _build_bom(tmp_path / "bom")
    _weaken_bundle_spec(bundle_dir, "bom.spec.json")
    code, face = _run_cli(
        bundle_dir, tmp_path / "v.json", "--spec-anchor", str(_BOM_SPEC)
    )
    assert code == 1, (code, _codes(face), _reasons(face))
    assert face["verdict"]["state"] == "REJECT", face["verdict"]["state"]
    assert "AnchorViolation" in _codes(face), _codes(face)
    # Fault-injection guard: confirm the REJECT really comes from the ANCHOR
    # step, not from an unrelated integrity gate the weakening happened to trip.
    assert ("spec_pinned_dispatch:anchor", "AnchorViolation") in _reasons(face), (
        _reasons(face)
    )


def test_anchor_blocks_a_substitution_that_would_otherwise_pass(
    tmp_path: Path,
) -> None:
    """The test above weakens the comparator to `scalar_epsilon`, which CANNOT
    accept this bundle's dict-valued output at all (`_cmp_scalar_epsilon` rejects
    non-numeric operands), so it would have failed as RE_DERIVATION_MISMATCH even
    with the anchor check deleted. It pins the anchor's check_name, but it never
    shows the anchor stopping a substitution that would otherwise have gone
    GREEN. (Adversarial audit, 2026-08-17.)

    This one does. `{"kind": "set"}` takes no params, so it passes
    `validate_comparator_params`, and `_cmp_set` iterates a dict operand — which
    compares only the TOP-LEVEL KEYS. So a producer that swaps `exact` -> `set`
    can empty the entire resolved dependency tree (`nodes: []`) and still
    "agree", because {root, nodes, resolution_order} is unchanged as a key set.
    Proven in two halves:
      (1) self-anchored (authority taken from the bundle) -> the forgery PASSES,
          which is why _build_spec_anchor refuses that path;
      (2) anchored on the operator's committed spec -> AnchorViolation.
    Half (1) is what makes half (2) evidence rather than decoration.
    """
    # --- half 1: the substitution really is a working forgery ---------------
    forged = _build_bom(tmp_path / "forged")
    manifest_path = forged / "manifest.json"
    output_id = json.loads(manifest_path.read_text(encoding="utf-8"))["outputs"][0][
        "output_id"
    ]
    claim_path = forged / "outputs" / f"{output_id}.json"
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    honest_nodes = claim["value"]["nodes"]
    assert honest_nodes, "fixture must have a non-empty resolved tree to empty out"
    claim["value"] = {"root": "x", "nodes": [], "resolution_order": []}
    raw_claim = json.dumps(claim, indent=2).encode("utf-8")
    claim_path.write_bytes(raw_claim)

    spec_path = forged / "spec" / "bom.spec.json"
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

    # Self-anchoring is refused by the CLI, so drive the LIBRARY directly to
    # show the forgery is genuine and not blocked by something incidental.
    sys.path.insert(0, str(_PKG_ROOT))
    from audit_bundle.rederivation.spec_binding import SpecAnchor
    from audit_bundle.verifier import BundleVerifier
    from veriker.cli.verify import _build_plugins, _load_manifest

    self_anchor = SpecAnchor(
        allowed={json.loads(raw_spec)["spec_id"]: hashlib.sha256(raw_spec).hexdigest()}
    )
    loaded = _load_manifest(forged)
    result = BundleVerifier(
        plugins=_build_plugins(forged, loaded, permit_pack_execution=False),
        spec_anchor=self_anchor,
        require_rederivation=True,
    ).verify(forged)
    assert result.ok, (
        "half 1 must PASS or this proves nothing: the `set` comparator on a dict "
        "compares only top-level keys, so an emptied tree agrees. failures="
        f"{[(f.check_name, f.reason_code) for f in result.failures]}"
    )

    # --- half 2: the operator's own anchor stops exactly that forgery -------
    code, face = _run_cli(forged, tmp_path / "v.json", "--spec-anchor", str(_BOM_SPEC))
    assert code == 1, (code, _codes(face), _reasons(face))
    assert ("spec_pinned_dispatch:anchor", "AnchorViolation") in _reasons(face), (
        _reasons(face)
    )


def test_anchor_path_inside_the_bundle_is_refused(tmp_path: Path) -> None:
    """The critical one. An anchor read out of the bundle is authored by the
    party it constrains, making `anchor.matches()` a tautology; measured
    2026-08-17, a fully forged bundle verified at exit 0 / state OK / zero reason
    codes with --require-rederivation satisfied. Prose in --help was the only
    guard; it is now enforced."""
    bundle_dir = _build_bom(tmp_path / "bom")
    in_bundle_spec = bundle_dir / "spec" / "bom.spec.json"
    assert in_bundle_spec.is_file(), in_bundle_spec
    code, face = _run_cli(
        bundle_dir, tmp_path / "v.json", "--spec-anchor", str(in_bundle_spec)
    )
    assert code == 2, (code, _codes(face))
    assert "SPEC_ANCHOR_ARG_INVALID" in _codes(face), _codes(face)
    # Refused BEFORE the bundle is judged — no artifact-side verdict may appear.
    assert "AnchorViolation" not in _codes(face), _codes(face)


def test_anchor_symlink_into_the_bundle_is_refused(tmp_path: Path) -> None:
    """Containment must resolve symlinks, or the refusal above is one `ln -s`
    away from being bypassed."""
    bundle_dir = _build_bom(tmp_path / "bom")
    link = tmp_path / "looks_external.spec.json"
    link.symlink_to(bundle_dir / "spec" / "bom.spec.json")
    code, face = _run_cli(bundle_dir, tmp_path / "v.json", "--spec-anchor", str(link))
    assert code == 2, (code, _codes(face))
    assert "SPEC_ANCHOR_ARG_INVALID" in _codes(face), _codes(face)


def test_anchor_provenance_is_recorded_on_the_verdict_face(tmp_path: Path) -> None:
    """A verdict that cannot say WHOSE authority it applied cannot be audited.
    Before this, an anchored green recorded nothing about the anchor at all."""
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(
        bundle_dir, tmp_path / "v.json", "--spec-anchor", str(_BOM_SPEC)
    )
    assert code == 0, (code, _codes(face))
    gates = [g for g in face["cli_gates"] if g["gate"] == "spec_anchor"]
    assert gates, face["cli_gates"]
    rows = gates[0]["anchored_specs"]
    assert len(rows) == 1, rows
    assert rows[0]["spec_id"] == "bom.v1", rows
    assert rows[0]["sha256"] == hashlib.sha256(_BOM_SPEC.read_bytes()).hexdigest(), rows
    assert rows[0]["source"] == str(_BOM_SPEC.resolve()), rows


def test_spec_anchor_with_unsafe_pack_is_refused(tmp_path: Path) -> None:
    """Packs run BEFORE dispatch reads outputs/, so a pack can write the answer
    dispatch then agrees with — producer code manufacturing both a green verdict
    and MEASURED coverage. Dead while the CLI had no anchor; live once it does.
    Refused rather than documented."""
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        str(_BOM_SPEC),
        "--unsafe-run-bundle-pack",
    )
    assert code == 2, (code, _codes(face))
    assert "SPEC_ANCHOR_PACK_CONFLICT" in _codes(face), _codes(face)


def test_anchor_violation_detail_distinguishes_operator_from_producer(
    tmp_path: Path,
) -> None:
    """`if not authoritative` fires both when a producer substitutes a spec and
    when the OPERATOR anchors the wrong one. The detail must report which
    evidence it saw rather than assert producer fault (audit finding 4)."""
    # Producer-consistent case: anchored spec_id, DIFFERENT on-disk bytes.
    weakened = _build_bom(tmp_path / "weak")
    _weaken_bundle_spec(weakened, "bom.spec.json")
    _code, face = _run_cli(
        weakened, tmp_path / "v1.json", "--spec-anchor", str(_BOM_SPEC)
    )
    detail = " ".join(
        r["detail"]
        for leg in [face["verdict"], *face["verdict"]["legs"]]
        for r in leg["reasons"]
    )
    assert "SHA_MISMATCH" in detail, detail

    # Operator case: anchor a spec whose spec_id the bundle never names.
    honest = _build_bom(tmp_path / "honest")
    other = tmp_path / "other.spec.json"
    other.write_text(
        json.dumps(
            {
                "spec_id": "not.this.pilot.v1",
                "types": {
                    "whatever": {
                        "primitive_id": "bom_recompute",
                        "comparator": {"kind": "exact", "params": {}},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    _code2, face2 = _run_cli(honest, tmp_path / "v2.json", "--spec-anchor", str(other))
    detail2 = " ".join(
        r["detail"]
        for leg in [face2["verdict"], *face2["verdict"]["legs"]]
        for r in leg["reasons"]
    )
    assert "NOT_ANCHORED" in detail2, detail2


def test_substituted_spec_without_anchor_does_not_reach_the_reject(
    tmp_path: Path,
) -> None:
    """Vacuity guard on the test above: the same tampered bundle with NO flag
    must land on the could-not-conclude path instead. If both cases produced the
    same verdict, case (c) would be proving nothing about the anchor."""
    bundle_dir = _build_bom(tmp_path / "bom")
    _weaken_bundle_spec(bundle_dir, "bom.spec.json")
    code, face = _run_cli(bundle_dir, tmp_path / "v.json")
    assert code == 2, (code, _codes(face), _reasons(face))
    assert "AnchorViolation" not in _codes(face), _codes(face)


# ---------------------------------------------------------------------------
# Tier-2 case (c) at CLI level: a genuinely re-derived bundle must NOT carry the
# NO_RE_DERIVATION_PERFORMED disclosure, and must survive --require-rederivation.
# ---------------------------------------------------------------------------


def test_anchored_pass_carries_no_absence_disclosure(tmp_path: Path) -> None:
    """Tier 2 could only assert this at library level, because the CLI had no way
    to supply an anchor. An always-on absence label would mean nothing."""
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(
        bundle_dir, tmp_path / "v.json", "--spec-anchor", str(_BOM_SPEC)
    )
    assert code == 0, (code, _codes(face), _reasons(face))
    assert _RE_DERIVATION_ABSENT_CODE not in _codes(face), _codes(face)
    disclosures = face["verdict"]["completeness"]["disclosures"]
    assert not any("re_derivation_surface" in d for d in disclosures), disclosures


def test_anchored_pass_survives_require_rederivation(tmp_path: Path) -> None:
    """The strict gate is a vacuity check with a STATED limit. It fails unless
    MEASURED coverage came back, so exit 0 here means at least one recompute ran
    and agreed — not merely that dispatch was configured.

    SCOPE: the guard is satisfied by ONE covered output of N
    (`if rederived_outputs or fragment_anchors_verified or rederivations_verified:
    return`), so on a multi-output bundle it does not certify that EVERY declared
    output re-derived. `bom_minimal` declares exactly one output, which is why it
    is a sound fixture for this assertion; do not read the same conclusion off a
    multi-output pilot."""
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        str(_BOM_SPEC),
        "--require-rederivation",
    )
    assert code == 0, (code, _codes(face), _reasons(face))


def test_unanchored_run_still_discloses_the_absence(tmp_path: Path) -> None:
    """Complement of the two above — the disclosure must still fire when nothing
    re-derived, or the assertions above are satisfied by a dead label."""
    bundle_dir = _build_bom(tmp_path / "bom")
    _code, face = _run_cli(bundle_dir, tmp_path / "v.json")
    assert _RE_DERIVATION_ABSENT_CODE in _codes(face), _codes(face)


# ---------------------------------------------------------------------------
# Operator-error handling: a bad --spec-anchor argument is exit 2, never a
# REJECT of the bundle (nothing was read from the bundle when it fires).
# ---------------------------------------------------------------------------


def test_missing_anchor_file_is_operator_error_exit_2(tmp_path: Path) -> None:
    bundle_dir = _build_bom(tmp_path / "bom")
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        str(tmp_path / "nope.spec.json"),
    )
    assert code == 2, (code, _codes(face))
    assert "SPEC_ANCHOR_ARG_INVALID" in _codes(face), _codes(face)


def test_anchor_file_without_spec_id_is_rejected(tmp_path: Path) -> None:
    """A file that is not a binding spec must not silently produce an EMPTY
    anchor — an empty allowlist matches nothing, so the run would look
    fail-closed for the wrong reason and hide the operator's mistake."""
    bundle_dir = _build_bom(tmp_path / "bom")
    bad = tmp_path / "not_a_spec.json"
    bad.write_text(json.dumps({"types": {}}), encoding="utf-8")
    code, face = _run_cli(bundle_dir, tmp_path / "v.json", "--spec-anchor", str(bad))
    assert code == 2, (code, _codes(face))
    assert "SPEC_ANCHOR_ARG_INVALID" in _codes(face), _codes(face)


def test_duplicate_spec_id_with_different_bytes_is_rejected(tmp_path: Path) -> None:
    """Two files claiming one spec_id would make the authority depend on argument
    order. Silently keeping the last one lets a stale path decide the verdict."""
    bundle_dir = _build_bom(tmp_path / "bom")
    original = json.loads(_BOM_SPEC.read_text(encoding="utf-8"))
    variant = tmp_path / "bom_variant.spec.json"
    variant.write_text(
        json.dumps({**original, "description": "different bytes, same spec_id"}),
        encoding="utf-8",
    )
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        str(_BOM_SPEC),
        str(variant),
    )
    assert code == 2, (code, _codes(face))
    assert "SPEC_ANCHOR_ARG_INVALID" in _codes(face), _codes(face)


# ---------------------------------------------------------------------------
# The primitive gap: closed via the auditor kit, fail-closed without it.
# ---------------------------------------------------------------------------


def test_pilot_local_primitive_without_kit_stays_fail_closed(
    tmp_path: Path,
) -> None:
    """`--spec-anchor` closes the ANCHOR gap only. A spec naming a
    `primitive_id` that lives in the PILOT directory rather than in
    `audit_bundle/rederivation/primitives/` remains UNKNOWN_PRIMITIVE unless
    the operator loads an auditor-side kit (`--primitives`) — the verifier
    NEVER loads a primitive from the bundle (threat-model attack #6), and that
    must not regress while the kit loader exists.

    `climate_emission_minimal` is such a pilot — its second output binds
    `climate_attribution_recompute`, registered by the pilot's own verify.py /
    auditor_kit.py, not by the distribution."""
    bundle_dir = _build_climate(tmp_path / "climate")
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
    )
    assert code == 1, (code, _codes(face), _reasons(face))
    assert "UNKNOWN_PRIMITIVE" in _codes(face), _codes(face)
    # The anchor itself resolved — the failure is downstream of it: the anchor
    # gap stays closed, and the primitive default stays fail-closed.
    assert "AnchorViolation" not in _codes(face), _codes(face)
    assert "VERIFIER_INCOMPLETE" not in _codes(face), _codes(face)


def test_pilot_local_primitive_is_reachable_via_the_kit(tmp_path: Path) -> None:
    """The FLIP of the 2026-08-17 residual pin (`--primitives` is the
    "auditor-side extension loader" that pin named): anchor + kit is the
    complete auditor kit, and the honest climate bundle now reaches exit 0
    through the shipped CLI with nothing pilot-shaped beyond the kit file.
    The kit-refusal and does-not-bless batteries live in
    tests/test_primitive_kit.py."""
    bundle_dir = _build_climate(tmp_path / "climate")
    code, face = _run_cli(
        bundle_dir,
        tmp_path / "v.json",
        "--spec-anchor",
        *[str(p) for p in _CLIMATE_SPECS],
        "--primitives",
        str(_CLIMATE_DIR / "auditor_kit.py"),
    )
    assert code == 0, (code, _codes(face), _reasons(face))
    assert "UNKNOWN_PRIMITIVE" not in _codes(face), _codes(face)
