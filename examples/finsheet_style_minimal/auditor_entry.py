"""auditor_entry.py — the AUDITOR's side of finsheet_style_minimal, in one place.

Everything the relying party holds: how a question becomes an anchored spec
(with the question's own bytes pinned through `pinned_inputs`), how the anchor
and work-set are built from committed out-of-bundle bytes, and how a verdict
is read back per output. `verify.py` and the harness both construct their
verifier HERE, so a hardening on the verdict path cannot fail to reach the
measurement path (the corner_load lesson).

Two outputs per bundle, two primitives, one claimed value:

  answer_semantic     -> sheet_query_recompute@1   (Arm A: the auditor's query)
  answer_consistency  -> sheet_derivation_replay@1 (Arm B: the producer's working)

The comparator follows the question's answer kind and is IDENTICAL on both
types (spec_binding's monotone-strictness rule is per anchored set, and each
bundle anchors exactly one spec — the harness never pools specs of different
kinds into one anchor).

Stdlib only apart from `audit_bundle` itself.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]
for _p in (_PKG_ROOT, _HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verdict import exit_code  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from audit_bundle.work_set import WorkSet  # noqa: E402

OUTPUT_SEMANTIC = "answer_semantic"
OUTPUT_CONSISTENCY = "answer_consistency"
QUERY_REL = "inputs/query.json"
DERIVATION_REL = "inputs/derivation.json"
WORKBOOK_REL = "data/workbook.xlsx"

PRIMITIVE_SEMANTIC = "sheet_query_recompute@1"
PRIMITIVE_CONSISTENCY = "sheet_derivation_replay@1"

# The auditor's tolerance per answer kind. 0.0051 is half a unit in the last
# place of the 2-dp contract plus float slack — a claim must be the re-derived
# 2-dp value, not "close". Counts and normalized strings are exact; lists are
# multiset-equal (the `set` kind).
COMPARATORS: dict[str, dict] = {
    "number": {
        "kind": "scalar_epsilon",
        "params": {"epsilon": 0.0051, "numeric_model": "decimal_fixed_point_half_ulp"},
    },
    "count": {"kind": "exact"},
    "string": {"kind": "exact"},
    "list": {"kind": "set"},
}

DEMO_SPEC = _HERE / "spec_pinned" / "finsheet_demo.spec.json"
DEMO_QUERY = _HERE / "spec_pinned" / "demo_query.json"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_spec(
    spec_id: str,
    answer_kind: str,
    query_bytes: bytes,
    workbook_bytes: bytes,
    *,
    description: str = "",
) -> bytes:
    """The auditor's binding spec for ONE question on ONE workbook.

    BOTH producer-visible inputs are pinned on the semantic type: the question
    (so a producer cannot answer an easier one) AND the workbook (so a producer
    cannot ship the workbook under which its answer is right). The first
    version pinned only the question; the adversarial pass (2026-09-02) added
    1.00 to one NAV cell, re-cohered the manifest, and passed both arms at
    exit 0. The auditor owns the data room: the pin is the auditor holding it.
    """
    if answer_kind not in COMPARATORS:
        raise ValueError(f"answer_kind {answer_kind!r} not in {tuple(COMPARATORS)}")
    cmp = COMPARATORS[answer_kind]
    doc = {
        "spec_id": spec_id,
        "description": description
        or (
            "Auditor binding spec for one FinSheet-style question. answer_semantic is "
            "re-derived from the PINNED workbook under the auditor's PINNED sheet-query-v1 "
            "question (Arm A); answer_consistency replays the producer's own stated "
            "derivation against the same pinned workbook (Arm B). Same claimed value, "
            "same comparator, two different questions being asked of it."
        ),
        "types": {
            OUTPUT_SEMANTIC: {
                "primitive_id": PRIMITIVE_SEMANTIC,
                "comparator": cmp,
                "pinned_inputs": {
                    QUERY_REL: sha256_bytes(query_bytes),
                    WORKBOOK_REL: sha256_bytes(workbook_bytes),
                },
            },
            OUTPUT_CONSISTENCY: {
                "primitive_id": PRIMITIVE_CONSISTENCY,
                "comparator": cmp,
                "pinned_inputs": {WORKBOOK_REL: sha256_bytes(workbook_bytes)},
            },
        },
    }
    return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")


def work_set_for(spec_path: Path) -> WorkSet:
    """One output per anchored type, output_id == type key, derived from the
    committed spec so a type added to the spec is pinned automatically."""
    raw = spec_path.read_bytes()
    spec = json.loads(raw)
    return WorkSet.declare(
        {t: t for t in spec["types"]},
        source=f"anchored spec {spec['spec_id']} ({spec_path.name}): one output per type key",
        provenance="EXTERNAL_STRUCTURE",
        source_sha=sha256_bytes(raw),
    )


def build_verifier(
    bundle_dir: Path, spec_path: Path
) -> tuple[BundleVerifier, SpecAnchor]:
    """THE anchored verifier for this pilot. Anchor from committed bytes outside
    the bundle; require_rederivation so a bundle that re-derives nothing is a
    could-not-conclude, not a PASS; work-set so the producer does not choose
    which claims arrive or which rule judges each."""
    anchor = SpecAnchor.from_files([spec_path], forbid_within=bundle_dir)
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor,
        require_rederivation=True,
        work_set=work_set_for(spec_path),
    )
    return verifier, anchor


def read_outcomes(result) -> dict:
    """Per-output reading of a verdict: {output_id: {"state": RE_DERIVED |
    NOT_RE_DERIVED | INCONCLUSIVE, "reason_code", "detail"}} plus the exit
    code and every non-dispatch failure. Keyed on check_name, never on prose."""
    code = exit_code(result)
    per: dict[str, dict] = {}
    other: list[dict] = []
    for f in result.failures:
        cn = f.check_name
        row = {"reason_code": f.reason_code, "detail": f.detail}
        if cn.startswith("spec_pinned_dispatch:") and cn.split(":", 1)[1] in (
            OUTPUT_SEMANTIC,
            OUTPUT_CONSISTENCY,
        ):
            per[cn.split(":", 1)[1]] = {"state": "NOT_RE_DERIVED", **row}
        else:
            other.append({"check_name": cn, **row})
    for oid in (OUTPUT_SEMANTIC, OUTPUT_CONSISTENCY):
        if oid not in per:
            per[oid] = {
                "state": "RE_DERIVED" if code != 2 and not other else "INCONCLUSIVE",
                "reason_code": None,
                "detail": None,
            }
    if code == 2:
        for oid in per:
            if per[oid]["state"] == "RE_DERIVED":
                per[oid]["state"] = "INCONCLUSIVE"
    return {
        "exit_code": code,
        "ok": bool(result.ok),
        "outputs": per,
        "other_failures": other,
    }
