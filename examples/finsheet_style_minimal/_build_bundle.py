#!/usr/bin/env python3
"""_build_bundle.py — PRODUCER-side bundle writer for finsheet_style_minimal.

Writes one audit bundle for one (workbook, question, claimed answer, stated
derivation). The harness calls `build_bundle` once per model answer; the
`--demo` CLI builds the committed demo question with a profile that shows
which arm has teeth against which failure:

  clean                 honest answer, honest working        -> PASS
  wrong_arithmetic      answer off by 1.00, working honest   -> A FAIL, B FAIL
  wrong_selection       summed the wrong column, consistently-> A FAIL, B PASS
  hallucinated_operand  working cites a number not in sheet  -> A FAIL, B FAIL (operand_not_in_sheet)
  wrong_question        rewrites inputs/query.json to an easier question,
                        answers THAT correctly, re-coheres manifest sha
                                                            -> PINNED_INPUT_MISMATCH

`wrong_selection` is the whole point of the pair: it is the failure Arm B is
documented NOT to catch, and the profile exists so that scope limit is
demonstrated, not asserted.

Imports the generator (producer side) and NOTHING from audit_bundle (sibling
ratchet): the honest derivation's operands come from the producer's own
records, never from the verifier's reader.

Usage:
    python examples/finsheet_style_minimal/_build_bundle.py --demo --out-dir /tmp/fs_demo
    python examples/finsheet_style_minimal/_build_bundle.py --demo --profile wrong_selection --out-dir /tmp/fs_bad
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from decimal import Decimal
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_CREATED_AT = "2026-09-02T00:00:00Z"

WORKBOOK_REL = "data/workbook.xlsx"
QUERY_REL = "inputs/query.json"
DERIVATION_REL = "inputs/derivation.json"
OUTPUT_SEMANTIC = "answer_semantic"
OUTPUT_CONSISTENCY = "answer_consistency"

DEMO_FILE_ID = "L2_S1"
DEMO_QID = "Q10"
DEMO_SPEC = _HERE / "spec_pinned" / "finsheet_demo.spec.json"
DEMO_QUERY = _HERE / "spec_pinned" / "demo_query.json"

PROFILES = (
    "clean",
    "wrong_arithmetic",
    "wrong_selection",
    "hallucinated_operand",
    "wrong_question",
)


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "finsheet_style_minimal__generate_set", _HERE / "_generate_set.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _json_default(o):
    if isinstance(o, Decimal):
        return float(o)
    raise TypeError(type(o).__name__)


def build_bundle(
    out_dir: Path,
    *,
    workbook_path: Path,
    query_bytes: bytes,
    spec_bytes: bytes,
    spec_basename: str,
    claimed_value: object,
    derivation: dict,
    bundle_id: str,
) -> Path:
    """Lay down the bundle. The spec bytes are the AUDITOR's (the bundle carries
    a copy; the anchor decides whether it is authoritative). Returns out_dir."""
    out_dir = Path(out_dir).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    for sub in ("data", "inputs", "outputs", "spec"):
        (out_dir / sub).mkdir(parents=True)
    files: dict[str, str] = {}

    wb_bytes = Path(workbook_path).read_bytes()
    (out_dir / WORKBOOK_REL).write_bytes(wb_bytes)
    files[WORKBOOK_REL] = _sha256(wb_bytes)

    (out_dir / QUERY_REL).write_bytes(query_bytes)
    files[QUERY_REL] = _sha256(query_bytes)

    der_bytes = json.dumps(
        derivation, indent=2, sort_keys=True, default=_json_default
    ).encode("utf-8")
    (out_dir / DERIVATION_REL).write_bytes(der_bytes)
    files[DERIVATION_REL] = _sha256(der_bytes)

    claim_bytes = json.dumps(
        {"value": claimed_value}, indent=2, default=_json_default
    ).encode("utf-8")
    for oid in (OUTPUT_SEMANTIC, OUTPUT_CONSISTENCY):
        rel = f"outputs/{oid}.json"
        (out_dir / rel).write_bytes(claim_bytes)
        files[rel] = _sha256(claim_bytes)

    (out_dir / "spec" / spec_basename).write_bytes(spec_bytes)

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {spec_basename: _sha256(spec_bytes)},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "fragment_anchors": {},
        "outputs": [
            {"output_id": oid, "type": oid, "conforms_to": f"spec/{spec_basename}"}
            for oid in (OUTPUT_SEMANTIC, OUTPUT_CONSISTENCY)
        ],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_dir


def recohere_file(bundle_dir: Path, rel: str) -> None:
    """Producer-side re-alignment of one file's manifest sha after editing it
    (what an attacker does so FileIntegrity does not fire first)."""
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Demo: the committed question, five profiles
# ---------------------------------------------------------------------------


def demo_question(work_dir: Path) -> tuple[Path, list[dict], dict]:
    """Regenerate the demo workbook and pick the committed question."""
    gen = _load_generator()
    wb_path, recs, qs = gen.build_one(DEMO_FILE_ID, work_dir)
    q = next(x for x in qs if x["qid"] == DEMO_QID)
    return wb_path, recs, q


def build_demo(out_dir: Path, profile: str) -> Path:
    if profile not in PROFILES:
        raise ValueError(f"profile {profile!r} not in {PROFILES}")
    out_dir = Path(out_dir).resolve()
    work = out_dir.parent / (out_dir.name + "_work")
    if work.exists():
        shutil.rmtree(work)
    wb_path, recs, q = demo_question(work)
    assert q["query"]["op"] == "sum" and q["query"]["column"] == "nav", q["query"]
    fund = q["query"]["filters"][0]["value"]
    mine = [r for r in recs if r["fund"] == fund]
    navs = [r["nav"] for r in mine]
    honest = float(sum(navs, Decimal(0)).quantize(Decimal("0.01")))

    query_bytes = DEMO_QUERY.read_bytes()
    spec_bytes = DEMO_SPEC.read_bytes()

    if profile == "clean":
        claimed, operands = honest, navs
    elif profile == "wrong_arithmetic":
        claimed, operands = round(honest + 1.0, 2), navs
    elif profile == "wrong_selection":
        inv = [r["invested"] for r in mine]
        claimed, operands = float(sum(inv, Decimal(0)).quantize(Decimal("0.01"))), inv
    elif profile == "hallucinated_operand":
        ghost = Decimal(
            "0.123"
        )  # every real cell has <= 2 decimals; this exists nowhere
        claimed = float((sum(navs, Decimal(0)) + ghost).quantize(Decimal("0.01")))
        operands = navs + [ghost]
    else:  # wrong_question
        claimed, operands = honest, navs

    derivation = {
        "schema": "sheet-derivation-v1",
        "op": "sum",
        "operands": operands,
        "column": "nav",
        "round": 2,
    }
    bundle = build_bundle(
        out_dir,
        workbook_path=wb_path,
        query_bytes=query_bytes,
        spec_bytes=spec_bytes,
        spec_basename=DEMO_SPEC.name,
        claimed_value=claimed,
        derivation=derivation,
        bundle_id=f"finsheet-style-demo-{profile}",
    )
    if profile == "wrong_question":
        # Answer an easier question correctly and ship THAT question as if it
        # were the auditor's. Count of companies in the fund, claimed exactly.
        easier = dict(q["query"])
        easier = {k: v for k, v in easier.items() if k != "column"}
        easier["op"] = "count"
        (bundle / QUERY_REL).write_bytes(
            json.dumps(easier, indent=2, sort_keys=True).encode("utf-8")
        )
        recohere_file(bundle, QUERY_REL)
        count_claim = json.dumps({"value": len(mine)}, indent=2).encode("utf-8")
        for oid in (OUTPUT_SEMANTIC, OUTPUT_CONSISTENCY):
            (bundle / f"outputs/{oid}.json").write_bytes(count_claim)
            recohere_file(bundle, f"outputs/{oid}.json")
        der = {
            "schema": "sheet-derivation-v1",
            "op": "count",
            "operands": [r["company"] for r in mine],
        }
        (bundle / DERIVATION_REL).write_bytes(
            json.dumps(der, indent=2, sort_keys=True).encode("utf-8")
        )
        recohere_file(bundle, DERIVATION_REL)
    shutil.rmtree(work, ignore_errors=True)
    print(f"Bundle written to {bundle}")
    print(f"  profile   : {profile}")
    print(f"  question  : {q['text']}")
    print(f"  claimed   : {claimed if profile != 'wrong_question' else len(mine)}")
    return bundle


def main() -> int:
    ap = argparse.ArgumentParser(
        description="finsheet_style_minimal producer bundle builder"
    )
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument(
        "--demo", action="store_true", help="build the committed demo question"
    )
    ap.add_argument("--profile", default="clean", choices=PROFILES)
    args = ap.parse_args()
    if not args.demo:
        ap.error("only --demo is a CLI mode; the harness calls build_bundle() directly")
    build_demo(args.out_dir, args.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
