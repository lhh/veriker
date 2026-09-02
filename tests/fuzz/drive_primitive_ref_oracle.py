#!/usr/bin/env python3
"""tests/fuzz/drive_primitive_ref_oracle.py — reproducible driver for the
`atheris_primitive_ref` oracle, for environments without atheris.

WHY THIS EXISTS. The D1 stage-4 commit reported "200,012 inputs / 38,195
accepted / zero oracle breaches" from an ad-hoc console run. The adversarial
pass correctly called that out: the committed atheris harness has no counters
and no seed handling, so the figure was not reproducible from anything in the
tree — an unrecorded console reading presented as a measurement. This driver
makes it reproducible.

It runs the SAME oracle as tests/fuzz/atheris_primitive_ref.py (structural
soundness + idempotence + the never-raise contract) over the committed seed
corpus plus a seeded pseudo-random walk, and prints a counted result.

    python tests/fuzz/drive_primitive_ref_oracle.py --n 200000 --seed 20260829

Exit 0 = no oracle breach. Exit 1 = a breach, with the offending input printed.
"""

from __future__ import annotations

import argparse
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from audit_bundle.rederivation.primitive_ref import (  # noqa: E402
    SIGILS,
    MalformedPrimitiveRef,
    PrimitiveRef,
    parse_primitive_ref,
)

_HEXLOWER = frozenset("0123456789abcdef")
CORPUS = Path(__file__).resolve().parent / "corpus" / "primitive_ref"


def check(raw: object) -> str:
    """The oracle. Returns 'accepted' or 'rejected'; raises on a breach."""
    try:
        ref = parse_primitive_ref(raw)
    except MalformedPrimitiveRef:
        return "rejected"
    assert isinstance(ref, PrimitiveRef), type(ref)
    assert ref.name, "accepted ref with an empty name"
    for sig in SIGILS:
        assert sig not in ref.name, f"sigil in name {ref.name!r}"
    if ref.version is not None:
        assert ref.version and not any(s in ref.version for s in SIGILS)
    if ref.digest is not None:
        assert len(ref.digest) == 64 and all(c in _HEXLOWER for c in ref.digest)
    assert parse_primitive_ref(ref.raw) == ref, "parse is not idempotent"
    return "accepted"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=20260829)
    args = ap.parse_args()

    stats = {"accepted": 0, "rejected": 0}
    alphabet = string.printable + "\x00\x01�​"

    inputs: list[str] = []
    if CORPUS.is_dir():
        for f in sorted(CORPUS.iterdir()):
            inputs.append(f.read_bytes().decode("utf-8", "surrogatepass"))

    rng = random.Random(args.seed)
    for i in range(args.n):
        if i % 3 == 0:
            inputs.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40))))
        else:
            s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            if rng.random() < 0.6:
                s += "@" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))
            if rng.random() < 0.6:
                body = "".join(
                    rng.choice("0123456789abcdefABCDEFz") for _ in range(rng.randint(60, 68))
                )
                s += "#" + body
            inputs.append(s)

    for raw in inputs:
        try:
            stats[check(raw)] += 1
        except AssertionError as exc:
            print(f"ORACLE BREACH (assert) on {raw!r}: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(
                f"ORACLE BREACH ({type(exc).__name__}) on {raw!r}: {exc}", file=sys.stderr
            )
            return 1

    total = len(inputs)
    print(f"inputs={total} accepted={stats['accepted']} rejected={stats['rejected']}")
    if stats["accepted"] == 0 or stats["rejected"] == 0:
        print("VACUOUS: one branch was never exercised", file=sys.stderr)
        return 1
    print("CLEAN — no oracle breach")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
