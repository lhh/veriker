"""_producer_replay.py — the RECORD-KEEPER's own replay of its maintenance log.

This module is the producer's half of `event_log_replay_minimal`. It is a
SEPARATELY MAINTAINED implementation of the fold the auditor pinned: seed the
record from the genesis CREATE, apply each AMEND patch in file order, skip the
ops that are recorded but do not change the record, and digest the canonical
result.

It must never import `audit_bundle.rederivation.primitives.*`. If it did, the
producer's claimed digest would BE the verifier's recompute and an honest PASS
would prove nothing. Enforced by this pilot's AST test and, repo-wide, by
`tests/test_recipe_producer_verifier_disjoint.py`.

The producer does NOT locate the log structurally the way the verifier does —
it knows which file it wrote. Locating the log is the verifier's problem, and
how it solves it (the sole `inputs/*.jsonl`, refusing zero or several) is a
property of the checker, not something the producer can influence.

Stdlib-only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

#: Ops that are recorded but leave the authoritative record unchanged. An
#: inspection is a fact about the asset's history, not a change to its record.
NON_MUTATING = frozenset({"LOG"})


def read_log(path: Path) -> list[dict]:
    """Read an append-only JSONL log. One JSON object per non-blank line."""
    events: list[dict] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"line {lineno} is not a JSON object")
        events.append(event)
    return events


def fold(events: list[dict]) -> dict:
    """Fold the event stream into the authoritative current record."""
    record: dict = {}
    created = False
    for position, event in enumerate(events):
        op = event.get("op")
        if op == "CREATE":
            if created:
                raise ValueError(f"event[{position}]: only the genesis event may CREATE")
            fields = event.get("fields")
            if not isinstance(fields, dict):
                raise ValueError(f"event[{position}]: CREATE has no 'fields' object")
            record = dict(fields)
            created = True
        elif op == "AMEND":
            if not created:
                raise ValueError(f"event[{position}]: AMEND precedes the genesis CREATE")
            patch = event.get("patch")
            if not isinstance(patch, dict):
                raise ValueError(f"event[{position}]: AMEND has no 'patch' object")
            # Later writes win — an AMEND overwrites whatever an earlier one set.
            for key, value in patch.items():
                record[key] = value
        elif op in NON_MUTATING:
            continue
        else:
            raise ValueError(f"event[{position}]: unrecognised op {op!r}")
    if not created:
        raise ValueError("log has no genesis CREATE event")
    return record


def canonical_bytes(record: dict) -> bytes:
    """Deterministic serialization for digesting: sorted keys, no whitespace."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_digest(record: dict) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def reconstruct(path: Path) -> tuple[dict, str]:
    """Read, fold and digest. Returns (record, sha256-hex)."""
    record = fold(read_log(path))
    return record, record_digest(record)
