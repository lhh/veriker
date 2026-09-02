"""verify.py — climate_emission_minimal domain pilot bundle verifier.

Auditor independence: the primitive kit this loads is auditor-held, never
bundle-supplied, and a kit path resolving inside the bundle is refused. Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required by the caller.

MIGRATED 2026-08-16 — Axis-2 spec-pinned dispatch.
------------------------------------------------
This pilot previously verified re-derivation by EXECUTING a bundle-supplied
`re_derive/climate_emission_pack.py` in a subprocess, via
`ReDerivationInvocationCheck(..., permit_execution=True)`. That route made the
`RE_DERIVED` verdict a claim authored by the bundle: a pack that simply
`exit(0)`s produced a PASS, and it required running untrusted code locally.

Re-derivation now runs through spec-pinned dispatch instead:

  * the verifier recomputes the representative output with ITS OWN registered
    primitive (`ClimateAttributionRecompute`, in this directory);
  * the comparator and the primitive binding come from the AUDITOR's spec;
  * the SpecAnchor is derived from the COMMITTED spec file
    (`spec_pinned/climate_emission.spec.json`) — NOT from the bundle's `spec/`
    copy, so a producer who ships a weaker spec yields a SHA the anchor does
    not list and dispatch fails closed (Axis-1);
  * NO bundle-supplied code is executed at any point.

Representative output: the per-vendor Scope-3 attribution list, compared
field-wise by the generic `structured` comparator over the allowlisted
`climate_attribution_v1` schema (vendor_id / tier / attributed_kg_co2e).

Plugins:
  FileIntegrityManySmall      §C9 — per-file SHA walk + extra-file detection

Usage:
    python examples/climate_emission_minimal/verify.py --bundle-dir <path>

Auditor work-set (2026-09-01): the verifier holds the complete set of outputs
this bundle must deliver, each pinned to its anchored rule (`_work_set`), so
neither a withdrawn claim nor an unasked-for extra one is the producer's call.

Exit codes:
    0  PASS — all checks passed
    1  FAIL — a check concluded against the bundle (details printed to stderr)
    2  ERROR — could not conclude (incl. nothing re-derived)
"""

from __future__ import annotations

import argparse
import sys

# Suppress .pyc generation: the verifier imports the pilot's primitive module
# from inside the pilot directory. Without this, CPython may drop
# __pycache__/<mod>.pyc into the bundle, which trips Pass 3 of
# file_integrity_many_small (EXTRA_FILE_NOT_IN_MANIFEST).
sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402

# §C5 auditor-independence: locate pkg root relative to this file.
# Layout: examples/climate_emission_minimal/verify.py -> parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# The primitive module lives alongside this script (AB4-style local import).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.kit import KitConstructionError, load_primitive_kit  # noqa: E402
from audit_bundle.rederivation.spec_binding import (  # noqa: E402
    AnchorConstructionError,
    SpecAnchor,
)
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from audit_bundle.verdict import exit_code  # noqa: E402
from audit_bundle.work_set import WorkSet, WorkSetError  # noqa: E402

# ---------------------------------------------------------------------------
# Auditor's kit = anchor bytes + primitive registrations. This wrapper packages
# BOTH through the same blessed library paths the standalone CLI uses, so there
# is exactly ONE registration path for this pilot (auditor_kit.py) and the
# wrapper's verdict is byte-identical to the top-level verify CLI invoked with
# `--spec-anchor ... --primitives auditor_kit.py`. Do NOT add the primitive under
# audit_bundle/rederivation/primitives/ (that would be a substrate edit); it
# stays auditor-held in this dir and is loaded from the kit.
# ---------------------------------------------------------------------------

_KIT = _HERE / "auditor_kit.py"
_SPEC_SRCS = (
    _HERE / "spec_pinned" / "climate.spec.json",  # output A — scalar total, exact
    _HERE / "spec_pinned" / "climate_emission.spec.json",  # output B — list, structured
)


def _build_anchor(bundle_dir: Path) -> SpecAnchor:
    """Build the auditor's SpecAnchor from the COMMITTED spec bytes via the
    blessed `from_files` constructor (records provenance the verifier
    re-verifies; refuses a path inside the bundle) — not the raw-dict
    constructor, which the face would label UNVERIFIED_CALLER_SUPPLIED."""
    return SpecAnchor.from_files(list(_SPEC_SRCS), forbid_within=bundle_dir)


# The auditor's WORK-SET: every output_id this bundle must deliver, pinned to
# the anchored type that judges it. HAND-DECLARED, because this pilot's
# output_ids are not its type keys (the attribution list is
# `climate_attribution_by_vendor` under type `climate_attribution`), so the
# identity map corner_load derives from its spec does not apply here.
#
# WHY IT EXISTS. This wrapper anchors TWO specs, and until it held a set it
# was the one shipped entry point exposed to the `spec_files` shrink
# (measured 2026-09-01 on the work-set landing): understate scope-3 by
# 20 t, withdraw the output that would catch it, pop `climate.spec.json` from
# `manifest.spec_files` -> exit 0 PASS. The coverage denominator was the
# producer's to shrink because nobody had written down what the complete set
# of work was. Now the auditor has: a withdrawn claim is named-but-not-
# delivered (WORK_SET_VIOLATION, a REJECT), and an extra output under a valid
# type — which every rule-reached accounting waves through — is
# delivered-but-not-named.
#
# SELF_AUTHORED with no source_sha: it is hand-written, and the class is never
# labelled up to "derived from the anchored spec" when it was not. What keeps
# it honest is `_assert_pins_cover_the_anchored_types`: every type key the
# anchored specs define is pinned by exactly one output, and no pin names a
# type no spec defines — so a channel added to a spec without a pin here
# fails loudly rather than being silently unrequired.
_WORK_SET_PINS = {
    "climate_total_scope3": "climate_total_scope3",  # output A, climate.spec.json
    "climate_attribution_by_vendor": "climate_attribution",  # output B
}


def _assert_pins_cover_the_anchored_types() -> None:
    import json

    spec_types: list[str] = []
    for spec_path in _SPEC_SRCS:
        spec_types.extend(json.loads(spec_path.read_bytes())["types"])
    pinned = sorted(_WORK_SET_PINS.values())
    if pinned != sorted(spec_types):
        raise RuntimeError(
            "climate_emission_minimal/verify.py: the work-set's pinned types "
            f"{pinned} do not cover the anchored specs' type keys "
            f"{sorted(spec_types)} exactly once — the auditor's declared work "
            "has drifted from the auditor's anchored rules"
        )


def _work_set() -> WorkSet:
    _assert_pins_cover_the_anchored_types()
    return WorkSet.declare(
        _WORK_SET_PINS,
        source=(
            "hand-declared by examples/climate_emission_minimal/verify.py: the "
            "two climate claims, one per anchored spec"
        ),
        provenance="SELF_AUTHORED",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "climate_emission_minimal audit bundle verifier "
            "(AUDIT_BUNDLE_CONTRACT §C5, Axis-2 spec-pinned dispatch)"
        )
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Load the auditor-held primitive kit (the pilot-local recompute), then
    # anchor + verify through the same library the standalone CLI uses. The kit
    # loader refuses a kit path inside the bundle; the verifier refuses any
    # registered primitive whose source is inside the bundle.
    # The auditor's three inputs -- kit, anchor, work-set -- are built before
    # any verdict exists. A failure here (a kit path inside the bundle, an
    # unreadable committed spec, a work-set whose pins no longer cover the
    # anchored types) says nothing about the ARTIFACT: it is the auditor's
    # own tooling being unusable, so it must route to could-not-conclude
    # (exit 2), never to an uncaught traceback exiting 1, which this file
    # defines as "a check concluded against the bundle".
    try:
        load_primitive_kit([_KIT], forbid_within=bundle_dir)
        anchor = _build_anchor(bundle_dir)
        work_set = _work_set()
    except (
        KitConstructionError,
        AnchorConstructionError,
        WorkSetError,
        RuntimeError,
        KeyError,
        ValueError,
        OSError,
    ) as exc:
        print("ERROR  could not conclude", file=sys.stderr)
        print(f"  AUDITOR_INPUTS_UNUSABLE: {exc}", file=sys.stderr)
        return 2

    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor,
        # This bundle exists FOR its re-derivation property, so a bundle that
        # re-derives NOTHING must not be a quiet PASS. Deleting manifest.outputs
        # alone is caught by the §4a.4 coverage invariant; deleting the outputs/
        # files and their manifest.files entries too leaves nothing for coverage
        # to compare, and without this flag that verified at exit 0 (measured on
        # this pilot). The v-kernel-pilot skill names this pilot as its canonical
        # template, so the omission hole was inherited by anything built from it.
        require_rederivation=True,
        # Which claims must arrive, and which anchored rule judges each, is the
        # AUDITOR's call, not the producer's (see _work_set). Without this the
        # producer could shrink the coverage denominator by popping one
        # spec_files key, and an extra output under a valid type rode through.
        work_set=work_set,
    )
    result = verifier.verify(bundle_dir)

    code = exit_code(result)

    # WHICH CLAIMS WERE REQUIRED AND WHICH RULE JUDGED EACH, on the terminal,
    # not only in the verdict object: a green run is exactly when a reader
    # needs to see that a set was applied, and under which universe_sha.
    for row in getattr(result.completeness, "disclosures", ()) or ():
        if row.startswith("type_selection:"):
            print(f"  {row}")

    if result.ok:
        print("PASS")
        return 0

    # ADR BI-1 tri-state: a could-not-conclude is a statement about the
    # VERIFIER, not an accusation against the artifact. Say which one.
    print("FAIL" if code == 1 else "ERROR  could not conclude", file=sys.stderr)
    for failure in result.failures:
        print(
            f"  [{failure.check_name}] {failure.reason_code}: {failure.detail}",
            file=sys.stderr,
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
