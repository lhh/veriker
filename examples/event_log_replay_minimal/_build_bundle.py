"""_build_bundle.py — the PRODUCER for event_log_replay_minimal.

Emits an equipment maintenance-record bundle: the append-only event log, the
record the log reconstructs, and the producer's claimed digest of that record.

    python examples/event_log_replay_minimal/_build_bundle.py --out-dir DIR

The claimed digest comes from `_producer_replay.py`, the record-keeper's own
copy of the fold. This module must never import
`audit_bundle.rederivation.primitives.*` — the verifier's own code — or the
claim would be the verifier's recompute and the comparison would be an identity.
Enforced by `tests/test_event_log_replay_minimal.py` (AST) and repo-wide by
`tests/test_recipe_producer_verifier_disjoint.py`.

THE DOMAIN IS SYNTHETIC. A hydraulic press in a fictional workshop, its
maintenance record amended twice and inspected twice. Nothing here is a
compliance artifact and no regime is being asserted; the log is a shape, and the
shape is what the exemplar is for.

LAYOUT. The bundle is written to `bundle/`, a SUBDIRECTORY, while the auditor's
spec stays in the sibling `spec_pinned/`. An anchor taken from inside the bundle
it judges lets the producer author both sides of the comparison, and
`SpecAnchor.from_files(..., forbid_within=...)` refuses it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

import _producer_replay as replay  # noqa: E402

_BUNDLE_ID = "event-log-replay-minimal-0001"
_CREATED_AT = "2026-08-29T00:00:00Z"
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_TYPED_CHECKS = ["file_integrity_many_small"]

_SPEC_SRC = _HERE / "spec_pinned" / "event_log_replay.spec.json"

_LOG_REL = "inputs/service_log.jsonl"
_OUTPUT_ID = "service_record_digest"
_TYPE_KEY = "maintenance_record_digest"

# --- The committed log. Two AMENDs and two LOGs, deliberately ordered so that
#     the LATER amendment is the restrictive one: reordering the two flips the
#     asset from restricted back to unrestricted, which is what makes the
#     reordering attack in the test battery worth running.
_EVENTS = (
    {
        "seq": 1,
        "op": "CREATE",
        "at": "2026-01-08T09:15:00Z",
        "actor": "commissioning",
        "fields": {
            "asset_id": "PRESS-14",
            "model": "hydraulic press, 40 t",
            "location": "bay 3",
            "status": "in_service",
            "service_interval_days": 180,
            "last_service": "2026-01-08",
        },
    },
    {
        "seq": 2,
        "op": "LOG",
        "at": "2026-02-19T11:02:00Z",
        "actor": "inspector",
        "note": "visual inspection, no findings",
    },
    {
        "seq": 3,
        "op": "AMEND",
        "at": "2026-07-06T14:40:00Z",
        "actor": "technician",
        "patch": {
            "last_service": "2026-07-06",
            "status": "in_service",
            "seal_kit_revision": "B",
        },
    },
    {
        "seq": 4,
        "op": "LOG",
        "at": "2026-08-01T08:30:00Z",
        "actor": "inspector",
        "note": "routine check, seal weep noted",
    },
    {
        "seq": 5,
        "op": "AMEND",
        "at": "2026-08-21T16:05:00Z",
        "actor": "technician",
        "patch": {
            "location": "bay 1",
            "status": "restricted_use",
            "restriction": "25 t ceiling pending seal replacement",
        },
    },
)


def _canonical(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _log_bytes(events) -> bytes:
    lines = [
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for event in events
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build(out_dir: Path, events=_EVENTS) -> None:
    out_dir = Path(out_dir).resolve()
    log_bytes = _log_bytes(events)

    # The producer reconstructs from the bytes it is about to commit, using its
    # OWN fold — never the verifier's.
    record = replay.fold(list(events))
    digest = replay.record_digest(record)

    files = {
        _LOG_REL: log_bytes,
        "payload/reconstructed_record.json": _canonical(
            {"schema": "maintenance-record-v1", "record": record}
        ),
    }
    spec_files: dict[str, bytes] = {}
    extra: dict = {}

    if _SPEC_SRC.is_file():
        spec_files[_SPEC_SRC.name] = _SPEC_SRC.read_bytes()
        files[f"outputs/{_OUTPUT_ID}.json"] = _canonical({"value": digest})
        extra["outputs"] = [
            {
                "output_id": _OUTPUT_ID,
                "type": _TYPE_KEY,
                "conforms_to": f"spec/{_SPEC_SRC.name}",
            }
        ]

    write_bundle(
        out_dir,
        BundleContent(
            bundle_id=_BUNDLE_ID,
            created_at=_CREATED_AT,
            schema_version=_SCHEMA_VERSION,
            files=files,
            spec_files=spec_files,
            typed_checks=_TYPED_CHECKS,
            extra_manifest_fields=extra,
        ),
    )
    amends = sum(1 for e in events if e.get("op") == "AMEND")
    logs = sum(1 for e in events if e.get("op") == "LOG")
    print(f"Bundle written to {out_dir}")
    print(f"  events          : {len(events)} ({amends} AMEND, {logs} LOG)")
    print(f"  record fields   : {len(record)}")
    print(f"  status          : {record.get('status')!r}")
    print(f"  claimed digest  : {digest}")
    print(f"  claims declared : {len(extra.get('outputs', []))}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build the event_log_replay_minimal bundle"
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=_HERE / "bundle",
        help="where to write the bundle (default: the committed bundle/ subdir)",
    )
    args = ap.parse_args()
    build(args.out_dir.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
