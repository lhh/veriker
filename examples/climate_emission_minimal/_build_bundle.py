"""_build_bundle.py — build a deterministic climate_emission_minimal audit bundle.

Climate / ESG Scope-3 supply-chain emission attribution pilot: for each
supplier in a 4-tier synthetic chain, compute:

    attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)

Sum per-supplier values to produce total_scope3_kg_co2e.

Re-derivation primitive (one sentence):
  For each supplier (sorted by tier then vendor_id), multiply
  activity_amount × emission_factor_kg_co2e_per_unit, round to 6 decimal
  places; sum the per-supplier values to total_scope3_kg_co2e. The verifier
  re-derives BOTH the per-vendor list and the total from committed evidence
  and compares each against the producer's claim under outputs/.

Why this matters for climate:
  Corporate ESG / GHG Protocol Scope-3 disclosures require supply-chain
  emission attributions to be computationally reproducible: the auditor
  must be able to re-derive each supplier's attributed emissions from the
  exact activity data and emission factors the model saw, using only
  committed artifacts. The V-Kernel audit bundle is that receipt.
  This pilot demonstrates the substrate claim on synthetic but
  structurally realistic data; production integrators replace the
  synthetic suppliers with real procurement data + certified EF databases;
  the bundle shape and verification protocol are identical.

Fragment kind: OpaqueFragment(kind_tag="supplier_emission_anchor") —
one fragment per supplier × emission-factor-source pair. Substrate
validates shape only; the semantic property is carried by Axis-2
spec-pinned dispatch (see below), not by a bundle-supplied check.

Axis-2 spec-pinned dispatch (migrated 2026-08-16)
-------------------------------------------------
This pilot USED to ship re_derive/climate_emission_pack.py and have the
verifier execute it in a subprocess. It no longer does: the bundle contains
NO executable code, and the two declared outputs

    outputs/climate_total_scope3.json          (exact)
    outputs/climate_attribution_by_vendor.json (structured)

are re-derived by the VERIFIER's own registered primitives under the
AUDITOR's anchored specs. See verify.py for the anchor construction.

Usage (from v-kernel-audit-bundle root, or anywhere):
    python examples/climate_emission_minimal/_build_bundle.py
        # writes manifest + bundle artifacts into the pilot directory itself

    python examples/climate_emission_minimal/_build_bundle.py --out-dir /tmp/climate_bundle
        # writes into a fresh out-dir

Caveat:
  When --out-dir is specified, only the generated artifacts (inputs/, payload/,
  spec/, outputs/, manifest.json) are written. The pilot's own source files
  (_build_bundle.py, verify.py, README.md, climate_attribution_recompute.py,
  tests/) are not copied.

  NOTE: the generic top-level verify CLI cannot conclude on this bundle —
  it has no flag for supplying an auditor SpecAnchor, so spec-pinned dispatch
  fails closed there. Use the pilot's own verify.py, which carries the anchor.

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# The in-place build imports the pilot's recompute module (to derive the honest
# claimed values). Without this, CPython drops __pycache__/*.pyc into the pilot
# dir AFTER the pycache sweep below, and the in-place bundle then trips Pass 3
# of file_integrity_many_small (EXTRA_FILE_NOT_IN_MANIFEST).
sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "climate-emission-minimal-rc"
_CREATED_AT = "2026-05-18T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
]

# --- Axis-2 spec-pinned dispatch (migrated 2026-08-16) --------------------- #
# This pilot no longer ships a re-derivation pack. Re-derivation runs through
# spec-pinned dispatch: the verifier recomputes the representative output with
# its OWN registered primitive under the AUDITOR's anchored spec, so no
# bundle-supplied code is ever executed. See verify.py + README.
# Output A — the scalar Scope-3 total, compared under `exact`. This is the
# property the retired re-derivation pack used to assert against
# payload/emission_report.json; declaring it as an output keeps that coverage
# while moving the check onto the verifier's own primitive.
_OUT_A_ID = "climate_total_scope3"
_OUT_A_TYPE = "climate_total_scope3"
_SPEC_A_SRC = _HERE / "spec_pinned" / "climate.spec.json"

# Output B — the per-vendor attribution list, compared field-wise under
# `structured` over the allowlisted climate_attribution_v1 schema.
_OUT_B_ID = "climate_attribution_by_vendor"
_OUT_B_TYPE = "climate_attribution"
_SPEC_B_SRC = _HERE / "spec_pinned" / "climate_emission.spec.json"

# ---------------------------------------------------------------------------
# Synthetic fixtures — 4-tier supplier chain (8 suppliers total)
# Emission factors are plausible but invented (not from a real EF database).
# Sorted by tier then vendor_id for deterministic ordering.
# ---------------------------------------------------------------------------

_SUPPLIER_CHAIN = [
    # Tier 1 — raw material extraction
    {
        "tier": 1,
        "vendor_id": "T1-ALUM-001",
        "vendor_name": "Alpine Aluminium Smelting Co.",
        "activity_amount": 4200.0,
        "activity_unit": "kg_aluminium",
        "emission_factor_kg_co2e_per_unit": 8.24,
        "factor_source": "synthetic-EF-v1.0/aluminium-primary",
    },
    {
        "tier": 1,
        "vendor_id": "T1-STEE-002",
        "vendor_name": "Boreal Steel Works",
        "activity_amount": 7800.0,
        "activity_unit": "kg_steel",
        "emission_factor_kg_co2e_per_unit": 1.89,
        "factor_source": "synthetic-EF-v1.0/steel-basic-oxygen",
    },
    # Tier 2 — component manufacturing
    {
        "tier": 2,
        "vendor_id": "T2-CAST-001",
        "vendor_name": "Cascade Components Ltd.",
        "activity_amount": 320.0,
        "activity_unit": "kwh_electricity",
        "emission_factor_kg_co2e_per_unit": 0.233,
        "factor_source": "synthetic-EF-v1.0/electricity-grid-avg",
    },
    {
        "tier": 2,
        "vendor_id": "T2-PACK-002",
        "vendor_name": "Meridian Packaging Solutions",
        "activity_amount": 1500.0,
        "activity_unit": "kg_cardboard",
        "emission_factor_kg_co2e_per_unit": 0.72,
        "factor_source": "synthetic-EF-v1.0/cardboard-recycled",
    },
    # Tier 3 — sub-assembly
    {
        "tier": 3,
        "vendor_id": "T3-ASMB-001",
        "vendor_name": "Northgate Sub-Assembly Inc.",
        "activity_amount": 980.0,
        "activity_unit": "kwh_electricity",
        "emission_factor_kg_co2e_per_unit": 0.411,
        "factor_source": "synthetic-EF-v1.0/electricity-coal-heavy",
    },
    {
        "tier": 3,
        "vendor_id": "T3-LOGX-002",
        "vendor_name": "Overland Express Freight",
        "activity_amount": 12000.0,
        "activity_unit": "tonne_km",
        "emission_factor_kg_co2e_per_unit": 0.096,
        "factor_source": "synthetic-EF-v1.0/road-freight-diesel",
    },
    # Tier 4 — final logistics / last-mile delivery
    {
        "tier": 4,
        "vendor_id": "T4-AIRX-001",
        "vendor_name": "Apex Air Cargo Ltd.",
        "activity_amount": 550.0,
        "activity_unit": "tonne_km",
        "emission_factor_kg_co2e_per_unit": 0.602,
        "factor_source": "synthetic-EF-v1.0/air-freight-long-haul",
    },
    {
        "tier": 4,
        "vendor_id": "T4-SHIP-002",
        "vendor_name": "Coastal Shipping Partners",
        "activity_amount": 45000.0,
        "activity_unit": "tonne_km",
        "emission_factor_kg_co2e_per_unit": 0.012,
        "factor_source": "synthetic-EF-v1.0/sea-freight-container",
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    """Deterministic JSON: sort_keys + compact separators + trailing newline."""
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _compute_attributions(supplier_chain: list) -> tuple[list, float]:
    """Compute per-supplier attributed_kg_co2e and total.

    Re-derivation primitive:
        attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)
    Suppliers processed in input order (already sorted by tier then vendor_id).
    Total = sum of per-supplier attributed values (exact Python float sum).
    """
    attributions = []
    for s in supplier_chain:
        attributed = round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
        attributions.append(
            {
                "vendor_id": s["vendor_id"],
                "tier": s["tier"],
                "activity_amount": s["activity_amount"],
                "activity_unit": s["activity_unit"],
                "emission_factor_kg_co2e_per_unit": s[
                    "emission_factor_kg_co2e_per_unit"
                ],
                "factor_source": s["factor_source"],
                "attributed_kg_co2e": attributed,
            }
        )
    total = round(sum(a["attributed_kg_co2e"] for a in attributions), 6)
    return attributions, total


def _build_fragment_anchors(
    supplier_chain: list,
    attributions: list,
    supplier_chain_cid: str,
) -> dict:
    """One OpaqueFragment(kind_tag="supplier_emission_anchor") per supplier.

    source_cid is the supplier_chain.json content CID. Locator carries
    vendor_id + factor_source — enough for an auditor to trace the emission
    factor to its synthetic-EF-v1.0 registry entry.
    """
    anchors: dict = {}
    for s in supplier_chain:
        key = f"{s['vendor_id']}-ef"
        anchors[key] = fragment_to_canonical_dict(
            OpaqueFragment(
                source_cid=supplier_chain_cid,
                kind_tag="supplier_emission_anchor",
                locator={
                    "vendor_id": s["vendor_id"],
                    "factor_source": s["factor_source"],
                    "tier": s["tier"],
                },
            )
        )
    return anchors


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# NOTE (2026-08-16 spec-pinned migration): the embedded re-derivation pack
# source that used to live here was REMOVED. This pilot no longer ships
# bundle-supplied executable code; re-derivation runs through spec-pinned
# dispatch against the verifier's own registered primitive. See verify.py.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Manifest file enumeration (in-place build)
# ---------------------------------------------------------------------------


def _enumerate_pilot_files_for_manifest(pilot_dir: Path) -> dict:
    """Walk the pilot dir and return {rel_path: sha256} for every file.

    Excludes manifest.json itself, any __pycache__ tree, any .pyc artifacts,
    and any spec/ or snapshots/ trees.
    """
    files: dict[str, str] = {}
    _SKIP_TOP = frozenset({"spec", "snapshots", "__pycache__"})
    for fpath in sorted(pilot_dir.rglob("*")):
        if fpath.is_dir():
            continue
        rel = fpath.relative_to(pilot_dir).as_posix()
        if rel == "manifest.json":
            continue
        parts = rel.split("/")
        if parts[0] in _SKIP_TOP:
            continue
        if any(p == "__pycache__" for p in parts):
            continue
        if rel.endswith(".pyc"):
            continue
        files[rel] = _sha256(fpath.read_bytes())
    return files


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / "inputs"
    payload_dir = out_dir / "payload"
    spec_dir = out_dir / "spec"
    outputs_dir = out_dir / "outputs"
    for d in (inputs_dir, payload_dir, spec_dir, outputs_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Sweep __pycache__ before enumerating files (verifier-self-pollution guard)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            import shutil as _shutil

            _shutil.rmtree(pycache, ignore_errors=True)

    # --- Write the AUDITORS' specs under spec/ (Axis-1 binding) ---
    # These are the committed auditor bytes verbatim. verify.py derives its
    # SpecAnchor from the SOURCE files, never from these copies, so a producer
    # who ships a weakened spec here yields a SHA the anchor does not list.
    spec_a_bytes = _SPEC_A_SRC.read_bytes()
    spec_b_bytes = _SPEC_B_SRC.read_bytes()
    (spec_dir / _SPEC_A_SRC.name).write_bytes(spec_a_bytes)
    (spec_dir / _SPEC_B_SRC.name).write_bytes(spec_b_bytes)

    # --- Write supplier_chain.json ---
    # Sort by tier then vendor_id for deterministic ordering
    sorted_chain = sorted(_SUPPLIER_CHAIN, key=lambda s: (s["tier"], s["vendor_id"]))
    supplier_chain_bytes = _canonical_json_bytes(sorted_chain)
    (inputs_dir / "supplier_chain.json").write_bytes(supplier_chain_bytes)
    supplier_chain_cid = f"sha256:{_sha256(supplier_chain_bytes)}"

    # --- Compute attributions ---
    attributions, total = _compute_attributions(sorted_chain)
    assert len(attributions) == 8, (
        f"Expected exactly 8 supplier attributions; got {len(attributions)}."
    )

    # --- Write emission_report.json ---
    emission_report = {
        "aggregation_method": "sum",
        "attributions": attributions,
        "total_scope3_kg_co2e": total,
    }
    emission_report_bytes = _canonical_json_bytes(emission_report)
    (payload_dir / "emission_report.json").write_bytes(emission_report_bytes)

    # --- Fragment anchors (one OpaqueFragment per supplier) ---
    fragment_anchors = _build_fragment_anchors(
        sorted_chain, attributions, supplier_chain_cid
    )
    assert len(fragment_anchors) == 8, (
        f"Expected exactly 8 fragment anchors (one per supplier); got {len(fragment_anchors)}."
    )

    # --- Producer's claimed value under outputs/<output_id>.json ---
    # The dispatch loop reads the claim from outputs/<id>.json {"value": ...},
    # NOT from manifest.outputs[] (which carries only the binding triple).
    #
    # GATE B (producer<->verifier non-tautology): both claims are computed by
    # the PRODUCER's own copy in `_producer_compute.py`, which is physically
    # separate from the code the verifier re-derives with (the central
    # `climate_emission_recompute` for the total, the in-dir
    # `climate_attribution_recompute` for the attribution list). Until
    # 2026-08-29 this block imported BOTH functions from the verifier's own
    # modules, making `claimed == re-derived` true by construction; the pilot
    # documented the sharing as drift-proofing, which inverts the property.
    # Do NOT reintroduce either import here.
    #
    # Loaded by PATH under a builder-private module name: a bare import would
    # bind a sys.modules name other drivers load by path, and two equal-named
    # class objects make `register_primitive` reject the second with "already
    # registered to a different class". The builder only needs pure functions
    # and never registers a primitive, so a private alias is safe.
    import importlib.util as _ilu  # noqa: PLC0415

    _spec = _ilu.spec_from_file_location(
        "climate_emission_minimal__producer_compute",
        _HERE / "_producer_compute.py",
    )
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    compute_total = _mod.compute_total
    compute_attribution = _mod.compute_attribution

    claim_a_bytes = json.dumps({"value": compute_total(sorted_chain)}, indent=2).encode(
        "utf-8"
    )
    claim_b_bytes = json.dumps(
        {"value": compute_attribution(sorted_chain)}, indent=2
    ).encode("utf-8")
    (outputs_dir / f"{_OUT_A_ID}.json").write_bytes(claim_a_bytes)
    (outputs_dir / f"{_OUT_B_ID}.json").write_bytes(claim_b_bytes)

    # --- Build manifest.files ---
    if out_dir.resolve() == _HERE.resolve():
        files = _enumerate_pilot_files_for_manifest(out_dir)
    else:
        files = {
            "inputs/supplier_chain.json": _sha256(supplier_chain_bytes),
            "payload/emission_report.json": _sha256(emission_report_bytes),
            f"outputs/{_OUT_A_ID}.json": _sha256(claim_a_bytes),
            f"outputs/{_OUT_B_ID}.json": _sha256(claim_b_bytes),
        }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": _BUNDLE_ID,
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {
            _SPEC_A_SRC.name: _sha256(spec_a_bytes),
            _SPEC_B_SRC.name: _sha256(spec_b_bytes),
        },
        "cross_refs": {},
        "payload": {},
        "typed_checks": _TYPED_CHECKS,
        "fragment_anchors": fragment_anchors,
        "outputs": [
            {
                "output_id": _OUT_A_ID,
                "type": _OUT_A_TYPE,
                "conforms_to": f"spec/{_SPEC_A_SRC.name}",
            },
            {
                "output_id": _OUT_B_ID,
                "type": _OUT_B_TYPE,
                "conforms_to": f"spec/{_SPEC_B_SRC.name}",
            },
        ],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Bundle written to {out_dir}")
    print(f"  suppliers        : {len(sorted_chain)} (4 tiers)")
    print(f"  total_scope3     : {total:.6f} kg CO2e")
    print(f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment")
    print(f"  manifest files   : {len(files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic climate_emission_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=False,
        type=Path,
        default=_HERE,
        help=(
            "Destination directory. Defaults to the pilot's own directory "
            "(in-place build) so verifying with --bundle-dir <pilot-dir> Just Works. "
            "Pass an explicit --out-dir to write a standalone bundle."
        ),
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
