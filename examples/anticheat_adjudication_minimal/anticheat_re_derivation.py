#!/usr/bin/env python3
"""anticheat_re_derivation.py — stdlib re-derivation pack for anticheat_adjudication_minimal.

Re-evaluates the detection-policy decision rules against bundled detection signals
(evidence/detection_signals.jsonl) + bundled policy (evidence/detection_policy.json)
to recompute the ban / review / clear verdict + the cited rule ID for every flagged
case. Compares against bundled payload/ban_decisions.json — including its
final_verdict field, which must equal the independently re-derived
model_recommendation (this pilot's honest construction never lets an adjudicator
override the model recommendation; final_verdict IS model_recommendation).

Also cross-checks that payload/adjudication_provenance.jsonl's model_recommendation
(a derived convenience copy) has not drifted from the payload/ban_decisions.json
value that was just re-derived and checked.

Additionally re-verifies every HMAC-signed adjudicator attestation in
payload/adjudication_provenance.jsonl against the synthetic key in
payload/attestation_key.hex. The HMAC message binds adjudicator_type (automated
detector-version vs. human moderator sign-off) alongside adjudicator_id, case_id,
final_verdict, and attestation_timestamp — WHO stands behind this ban is the
responsible-actor binding this pilot exists to demonstrate, and was previously
unbound, letting adjudicator_type be forged freely with no other copy in the
bundle to cross-check against.

§C6 (domain-agnostic re-derivation) + AB4.

What this proves: the ban verdict followed the committed detection policy over the
committed evidence, that ban_decisions.json's final_verdict is bound to that
re-derived verdict, AND the named adjudicator's identity and type genuinely bind
to that verdict (a post-hoc verdict flip, or a human/automated relabel, is
detectable even when file SHAs are re-aligned).
What this does NOT prove: that the policy correctly distinguishes cheaters from
skilled players. Detection quality is upstream and untouched by this pilot. It
also does not give non-repudiation — see README.md "Honesty rail" — because the
HMAC key ships inside the bundle for demo reproducibility.

Exit codes:
  0  all invariants pass
  1  mismatch found — see stderr for [RE_DERIVATION_MISMATCH],
                       [ANTICHEAT_FINAL_VERDICT_MISMATCH],
                       [ANTICHEAT_MODEL_RECOMMENDATION_DRIFT], or
                       [ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID]

Stdlib only: json, hmac, hashlib, argparse, pathlib, sys.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_signals(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "evidence" / "detection_signals.jsonl"
    if not p.exists():
        return None
    cases = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[RE_DERIVATION_MISMATCH] evidence/detection_signals.jsonl line {i}: "
                f"JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return cases


def _load_policy(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "evidence" / "detection_policy.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] evidence/detection_policy.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_decisions(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "ban_decisions.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] payload/ban_decisions.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_provenance(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "adjudication_provenance.jsonl"
    if not p.exists():
        return None
    rows = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
                f"payload/adjudication_provenance.jsonl line {i}: JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return rows


def _load_attestation_key(bundle_dir: Path) -> bytes | None:
    p = bundle_dir / "payload" / "attestation_key.hex"
    if not p.exists():
        print(
            "[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
            "payload/attestation_key.hex not found in bundle",
            file=sys.stderr,
        )
        return None
    try:
        key_hex = p.read_text(encoding="utf-8").strip()
        return bytes.fromhex(key_hex)
    except ValueError as exc:
        print(
            f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
            f"payload/attestation_key.hex: invalid hex: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Re-derivation logic (mirrors _build_bundle.py — stdlib only)
# ---------------------------------------------------------------------------


def _evaluate_rule(signals: dict, rule: dict) -> bool:
    """Return True if the case signals satisfy every condition in the rule (AND)."""
    for cond in rule["conditions"]:
        sig = cond["signal"]
        comparator = cond["comparator"]
        threshold = cond["threshold"]
        value = signals.get(sig)
        if value is None:
            return False
        if comparator == ">=":
            if not (value >= threshold):
                return False
        elif comparator == "<=":
            if not (value <= threshold):
                return False
        else:
            raise ValueError(
                f"unknown condition comparator {comparator!r} "
                "(supported: '>=', '<=') — refusing to treat an unevaluable "
                "policy condition as satisfied"
            )
    return True


def _derive_decision(case: dict, policy: list[dict]) -> dict:
    """Walk the rule set (sorted by rule_id) and return the first matching verdict."""
    for rule in sorted(policy, key=lambda r: r["rule_id"]):
        if _evaluate_rule(case["signals"], rule):
            return {
                "case_id": case["case_id"],
                "model_recommendation": rule["verdict"],
                "matched_rule_id": rule["rule_id"],
            }
    return {
        "case_id": case["case_id"],
        "model_recommendation": "clear",
        "matched_rule_id": None,
    }


def _compute_attestation_hmac(
    adjudicator_id: str,
    case_id: str,
    final_verdict: str,
    timestamp: str,
    adjudicator_type: str,
    key: bytes,
) -> str:
    """HMAC-SHA256 of (adjudicator_id || case_id || final_verdict || timestamp ||
    adjudicator_type). adjudicator_type is bound so WHO stands behind this ban
    (automated detector-version vs. human moderator — the responsible-actor
    binding this pilot exists to demonstrate) cannot be forged independently of
    the rest of the attestation; the field has no other copy anywhere in the
    bundle to cross-check against."""
    msg = (
        f"{adjudicator_id}|{case_id}|{final_verdict}|{timestamp}|{adjudicator_type}"
    ).encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Anti-cheat ban-adjudication re-derivation + adjudicator attestation "
            "check for anticheat_adjudication_minimal audit bundles"
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

    # Load all inputs
    cases = _load_signals(bundle_dir)
    if cases is None:
        if not (bundle_dir / "evidence" / "detection_signals.jsonl").exists():
            return 0  # domain opted out
        return 1

    policy = _load_policy(bundle_dir)
    if policy is None:
        if not (bundle_dir / "evidence" / "detection_policy.json").exists():
            return 0
        return 1

    decisions = _load_decisions(bundle_dir)
    if decisions is None:
        if not (bundle_dir / "payload" / "ban_decisions.json").exists():
            return 0
        return 1

    provenance = _load_provenance(bundle_dir)
    if provenance is None:
        return 1

    attestation_key = _load_attestation_key(bundle_dir)
    if attestation_key is None:
        return 1

    # -----------------------------------------------------------------------
    # Invariant 1: re-derive every verdict and compare to bundled decisions
    # -----------------------------------------------------------------------
    bundled_by_id: dict[str, dict] = {d["case_id"]: d for d in decisions}

    for case in cases:
        case_id = case.get("case_id")
        if case_id is None:
            print(
                "[RE_DERIVATION_MISMATCH] case missing case_id",
                file=sys.stderr,
            )
            return 1

        derived = _derive_decision(case, policy)
        bundled = bundled_by_id.get(case_id)
        if bundled is None:
            print(
                f"[RE_DERIVATION_MISMATCH] case_id={case_id!r} "
                "not found in bundled decisions",
                file=sys.stderr,
            )
            return 1

        if derived["model_recommendation"] != bundled.get("model_recommendation"):
            print(
                f"[RE_DERIVATION_MISMATCH] case_id={case_id!r}: "
                f"re-derived model_recommendation={derived['model_recommendation']!r} "
                f"but bundled={bundled.get('model_recommendation')!r}",
                file=sys.stderr,
            )
            return 1

        if derived["matched_rule_id"] != bundled.get("matched_rule_id"):
            print(
                f"[RE_DERIVATION_MISMATCH] case_id={case_id!r}: "
                f"re-derived matched_rule_id={derived['matched_rule_id']!r} "
                f"but bundled={bundled.get('matched_rule_id')!r}",
                file=sys.stderr,
            )
            return 1

        # payload/ban_decisions.json.final_verdict — the field the pilot is
        # actually named after — must equal the independently re-derived
        # model_recommendation. In this pilot's honest construction the
        # adjudicator always adopts the model recommendation as the final
        # verdict (no independent override logic exists), so this is the
        # exact, no-slack relationship: final_verdict IS model_recommendation.
        # Previously this field was never read by this checker at all — a
        # producer could ship any final_verdict value with zero consequence.
        if bundled.get("final_verdict") != derived["model_recommendation"]:
            print(
                f"[ANTICHEAT_FINAL_VERDICT_MISMATCH] case_id={case_id!r}: "
                f"bundled ban_decisions.json final_verdict="
                f"{bundled.get('final_verdict')!r} does not equal the "
                f"independently re-derived model_recommendation="
                f"{derived['model_recommendation']!r} — the final_verdict "
                "field was not bound to any re-derived value",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 2: every bundled decision has a corresponding provenance row,
    # and the provenance row's model_recommendation must not have drifted from
    # the (already re-derived) payload/ban_decisions.json value.
    # model_recommendation is carried in payload/adjudication_provenance.jsonl
    # as a DERIVED convenience copy — it must equal the ban_decisions.json
    # field that invariant 1 above already checked, or the two records can
    # silently disagree about what the model actually recommended.
    # -----------------------------------------------------------------------
    provenance_by_id: dict[str, dict] = {row["case_id"]: row for row in provenance}

    for decision in decisions:
        case_id = decision["case_id"]
        provenance_row = provenance_by_id.get(case_id)
        if provenance_row is None:
            print(
                f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
                f"case_id={case_id!r}: no provenance row found in "
                "payload/adjudication_provenance.jsonl",
                file=sys.stderr,
            )
            return 1

        if provenance_row.get("model_recommendation") != decision.get(
            "model_recommendation"
        ):
            print(
                f"[ANTICHEAT_MODEL_RECOMMENDATION_DRIFT] case_id={case_id!r}: "
                f"payload/adjudication_provenance.jsonl model_recommendation="
                f"{provenance_row.get('model_recommendation')!r} does not "
                f"equal payload/ban_decisions.json model_recommendation="
                f"{decision.get('model_recommendation')!r}",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 3: re-verify every adjudicator attestation HMAC
    # -----------------------------------------------------------------------
    for row in provenance:
        case_id = row.get("case_id", "")
        adjudicator_id = row.get("adjudicator_id", "")
        final_verdict = row.get("final_verdict", "")
        timestamp = row.get("attestation_timestamp", "")
        adjudicator_type = row.get("adjudicator_type", "")
        stored_hmac = row.get("attestation_hmac", "")

        expected_hmac = _compute_attestation_hmac(
            adjudicator_id=adjudicator_id,
            case_id=case_id,
            final_verdict=final_verdict,
            timestamp=timestamp,
            adjudicator_type=adjudicator_type,
            key=attestation_key,
        )

        if not _hmac.compare_digest(expected_hmac, stored_hmac):
            print(
                f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
                f"case_id={case_id!r} adjudicator_id={adjudicator_id!r} "
                f"adjudicator_type={adjudicator_type!r}: "
                f"HMAC mismatch — stored={stored_hmac[:16]!r}... "
                f"expected={expected_hmac[:16]!r}... "
                "(final_verdict, adjudicator_id, timestamp, or adjudicator_type "
                "may have been tampered)",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
