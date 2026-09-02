#!/usr/bin/env python3
"""credit_scoring_re_derivation.py — stdlib re-derivation pack for the credit_scoring_minimal domain pilot.

§C6 (domain-agnostic generalization) + AB4 (duplicate-don't-import).
Stdlib only (math, json, argparse, pathlib, sys).

Reads from --bundle-dir:
  model/scorecard.json           — logistic-regression-style coefficient table
  model/threshold_table.json     — PD-to-tier mapping
  applicants/<APP-ID>.json       — one file per applicant (credit attributes)
  payload/credit_decisions.json  — bundled credit decisions to re-derive

Re-derivation primitive:
  Replay each applicant's credit attributes through the bundled scorecard
  coefficients, recompute the probability-of-default (PD) score and the
  approve/decline + APR-tier verdict via the bundled threshold table.
  Assert the re-derived decisions AND the re-derived pd match the bundled
  payload — pd is bound to within ONE 6dp storage grain (|Δ| ≤ 1e-6, and the
  bundled value must be 6dp round-trip stable), not merely referenced in an
  error message, because a PD range maps many distinct raw probabilities onto
  the same tier/decision/apr and pd is the number LGPD art. 20 requires the
  lender disclose. Stated limit: the last stored digit can differ by one unit
  and still pass (the tolerance is sized for cross-platform libm wobble).
  The payload's stated model identity (scorecard_model / scorecard_version)
  is bound to model/scorecard.json's model_name / model_version; bundled
  decision rows and applicants/*.json are a bijection (duplicate applicant_id
  rows refused; array length compared, not index length).

Exit 0 on full match; exit 1 on first mismatch with
[RE_DERIVATION_MISMATCH] (structural/model-identity/tier/
decision/apr) or [CREDIT_SCORING_PD_MISMATCH] (bundled pd not bound to the
re-derived value) on stderr.

On a full match the pack prints ONE machine-readable stdout line naming the
claim fields it compared, keyed by bundle-relative file:

    [COMPARED] {"payload/credit_decisions.json": ["decisions[].pd", ...]}

The pilot's plugin reports claim-field coverage for exactly those fields —
coverage follows what this pack says it compared, never a constant in the
wrapper. Field paths use the claimset rendering (object keys joined by ".",
every array position "[]").

If any of the required input files are absent the bundle opted out of
credit-scoring re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_json(path: Path, label: str) -> dict | None:
    """Load JSON from path; print error + return None on failure."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] {label}: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_applicants(bundle_dir: Path) -> list[dict] | None:
    """Load all applicant JSON files from applicants/."""
    applicants_dir = bundle_dir / "applicants"
    if not applicants_dir.is_dir():
        return None
    applicants: list[dict] = []
    for fpath in sorted(applicants_dir.glob("*.json")):
        data = _load_json(fpath, f"applicants/{fpath.name}")
        if data is None:
            return None
        applicants.append(data)
    return applicants


# ---------------------------------------------------------------------------
# Scoring logic — mirrors _build_bundle.py exactly (stdlib math.exp only)
# ---------------------------------------------------------------------------


def _compute_pd(applicant: dict, scorecard: dict) -> float:
    """Compute probability of default via logistic function.

    linear_combination = intercept + Σ(coef_i * feature_i)
    PD = 1 / (1 + exp(-linear_combination))
    """
    try:
        intercept = float(scorecard["intercept"])
        coefficients: dict = scorecard["coefficients"]
        linear_combination = intercept
        for feature, coef in coefficients.items():
            if feature not in applicant:
                print(
                    f"[RE_DERIVATION_MISMATCH] applicant "
                    f"{applicant.get('applicant_id', '?')!r}: "
                    f"feature {feature!r} missing from applicant record",
                    file=sys.stderr,
                )
                return float("nan")
            value = float(applicant[feature])
            linear_combination += float(coef) * value
        return 1.0 / (1.0 + math.exp(-linear_combination))
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] PD compute error "
            f"for applicant {applicant.get('applicant_id', '?')!r}: {exc}",
            file=sys.stderr,
        )
        return float("nan")


def _lookup_tier(pd: float, threshold_table: dict) -> dict | None:
    """Return the tier dict matching the given PD value."""
    try:
        for tier in threshold_table["tiers"]:
            if float(tier["pd_min"]) <= pd < float(tier["pd_max"]):
                return tier
        # Fallback: PD exactly at 1.0 falls in last tier
        return threshold_table["tiers"][-1]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] tier lookup error for pd={pd}: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Input provenance — applicants/ must be the bureau snapshot the bundle registers
# ---------------------------------------------------------------------------

# The credit-bureau attributes the scorecard consumes. Each applicant file's
# values must equal the bundle's registered bureau snapshot row for that
# applicant — otherwise the scorecard is replayed over inputs the bundle's own
# CID-registered, publication_class="regulatory" snapshot contradicts (found by
# a red-team pass: a forged applicants/APP-004.json with an honestly recomputed
# payload verified PASS while the snapshot still said "decline").
_BUREAU_ATTRIBUTES = (
    "serasa_score",
    "utilization_pct",
    "tradeline_count",
    "dti_pct",
    "derog_marks",
)
_BUREAU_SNAPSHOT_SCHEMA = "bureau-snapshot-v1"


def _verify_bureau_provenance(bundle_dir: Path, applicants: list[dict]) -> bool:
    """Every applicant's five bureau attributes must equal the registered bureau
    snapshot's row for that applicant_id. Exactly one snapshot with schema
    bureau-snapshot-v1 must be registered in manifest.snapshots; a missing
    snapshot, a missing row, or any differing attribute is a refusal. This is
    CONSISTENCY between the replayed inputs and the artifact the bundle itself
    registers as the bureau pull — the snapshot is producer-authored in this
    synthetic pilot (no issuer signature), so it is not external provenance."""
    manifest = _load_json(bundle_dir / "manifest.json", "manifest.json")
    if manifest is None:
        print(
            "[CREDIT_SCORING_BUREAU_MISMATCH] manifest.json unreadable — cannot locate "
            "the registered bureau snapshot",
            file=sys.stderr,
        )
        return False
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, dict):
        print(
            "[CREDIT_SCORING_BUREAU_MISMATCH] manifest.snapshots absent — no registered "
            "bureau snapshot to bind applicants/ against",
            file=sys.stderr,
        )
        return False
    bureau_docs = []
    for cid, rel in sorted(snapshots.items()):
        doc = _load_json(bundle_dir / str(rel), f"snapshots[{cid}]")
        if isinstance(doc, dict) and doc.get("schema") == _BUREAU_SNAPSHOT_SCHEMA:
            bureau_docs.append((rel, doc))
    if len(bureau_docs) != 1:
        print(
            f"[CREDIT_SCORING_BUREAU_MISMATCH] expected exactly one registered snapshot "
            f"with schema {_BUREAU_SNAPSHOT_SCHEMA!r}, found {len(bureau_docs)}",
            file=sys.stderr,
        )
        return False
    rel, bureau = bureau_docs[0]
    try:
        rows = {row["applicant_id"]: row for row in bureau["attributes"]}
    except (KeyError, TypeError) as exc:
        print(
            f"[CREDIT_SCORING_BUREAU_MISMATCH] {rel}: malformed attributes: {exc}",
            file=sys.stderr,
        )
        return False
    for app in applicants:
        app_id = app.get("applicant_id", "<unknown>")
        row = rows.get(app_id)
        if row is None:
            print(
                f"[CREDIT_SCORING_BUREAU_MISMATCH] applicant {app_id!r} has no row in "
                f"the registered bureau snapshot {rel}",
                file=sys.stderr,
            )
            return False
        for attr in _BUREAU_ATTRIBUTES:
            if attr not in app or attr not in row or app[attr] != row[attr]:
                print(
                    f"[CREDIT_SCORING_BUREAU_MISMATCH] applicant {app_id!r}: "
                    f"{attr}={app.get(attr)!r} in applicants/ but "
                    f"{row.get(attr)!r} in the registered bureau snapshot {rel} — "
                    f"the scorecard would be replayed over an input the bundle's own "
                    f"bureau pull contradicts",
                    file=sys.stderr,
                )
                return False
    return True


# ---------------------------------------------------------------------------
# Main verification logic
# ---------------------------------------------------------------------------


def _verify_decisions(
    applicants: list[dict],
    scorecard: dict,
    threshold_table: dict,
    bundled_payload: dict,
) -> bool:
    """Re-derive each decision and compare to the bundled payload.

    Returns True on full match, False on any mismatch (error printed to stderr).
    On a full match, prints the [COMPARED] line listing exactly the payload
    fields whose values were compared on this run (accumulated as each
    comparison passes — never a constant).
    """
    compared: set[str] = set()

    # Index bundled decisions by applicant_id. Every ROW must be visited
    # exactly once: a duplicate applicant_id is refused outright (a dict
    # would silently keep the last row and the count check below would never
    # see the shadowed one — a row nothing compared would ride green), and
    # the arity check is against the ARRAY length, not the index length, so
    # bundled rows ↔ applicant files is a bijection.
    try:
        rows = bundled_payload["decisions"]
        bundled_decisions: dict[str, dict] = {}
        for d in rows:
            app_id = d["applicant_id"]
            if app_id in bundled_decisions:
                print(
                    f"[RE_DERIVATION_MISMATCH] payload/credit_decisions.json: "
                    f"applicant_id {app_id!r} appears in more than one decision row — "
                    f"one applicant, one decision",
                    file=sys.stderr,
                )
                return False
            bundled_decisions[app_id] = d
    except (KeyError, TypeError) as exc:
        print(
            f"[RE_DERIVATION_MISMATCH] payload/credit_decisions.json: "
            f"malformed structure: {exc}",
            file=sys.stderr,
        )
        return False

    if len(applicants) != len(rows):
        print(
            f"[RE_DERIVATION_MISMATCH] applicant count mismatch: "
            f"bundle has {len(applicants)} applicants but payload has "
            f"{len(rows)} decision rows",
            file=sys.stderr,
        )
        return False

    # Model identity: the payload states WHICH scorecard produced these
    # decisions (scorecard_model / scorecard_version). Bind both to the
    # bundled model/scorecard.json — the artifact whose coefficients are
    # replayed below — so a payload cannot claim decisions came from a model
    # other than the one that re-derives them. (These two fields were never
    # read before the claim-field coverage gate named them as unaccounted.)
    for payload_field, scorecard_field in (
        ("scorecard_model", "model_name"),
        ("scorecard_version", "model_version"),
    ):
        claimed = bundled_payload.get(payload_field)
        actual = scorecard.get(scorecard_field)
        if claimed is None or claimed != actual:
            print(
                f"[RE_DERIVATION_MISMATCH] payload "
                f"{payload_field}={claimed!r} but model/scorecard.json "
                f"{scorecard_field}={actual!r} — the decisions' stated model "
                f"identity is not the scorecard that was replayed",
                file=sys.stderr,
            )
            return False
        compared.add(payload_field)

    for app in applicants:
        app_id = app.get("applicant_id", "<unknown>")

        # Re-derive PD
        pd = _compute_pd(app, scorecard)
        if math.isnan(pd):
            return False  # error already printed

        # Re-derive tier
        tier = _lookup_tier(pd, threshold_table)
        if tier is None:
            return False  # error already printed

        # Look up bundled decision for this applicant
        if app_id not in bundled_decisions:
            print(
                f"[RE_DERIVATION_MISMATCH] applicant {app_id!r} "
                f"not found in bundled decisions",
                file=sys.stderr,
            )
            return False

        bundled = bundled_decisions[app_id]
        compared.add("decisions[].applicant_id")

        # Compare tier
        if tier["tier"] != bundled.get("tier"):
            print(
                f"[RE_DERIVATION_MISMATCH] applicant {app_id!r}: "
                f"re-derived tier={tier['tier']!r} but bundled tier={bundled.get('tier')!r} "
                f"(re-derived pd={round(pd, 6)}, bundled pd={bundled.get('pd')})",
                file=sys.stderr,
            )
            return False
        compared.add("decisions[].tier")

        # Compare decision (approve/decline)
        if tier["decision"] != bundled.get("decision"):
            print(
                f"[RE_DERIVATION_MISMATCH] applicant {app_id!r}: "
                f"re-derived decision={tier['decision']!r} but bundled decision={bundled.get('decision')!r}",
                file=sys.stderr,
            )
            return False
        compared.add("decisions[].decision")

        # Compare APR tier value. The key must be PRESENT in every row — a
        # decline row carries apr_pct=null, and an absent key must not compare
        # equal to it (None == None would be a vacuous comparison for exactly
        # the rows whose apr is null).
        apr = tier.get("apr_pct")
        if "apr_pct" not in bundled:
            print(
                f"[RE_DERIVATION_MISMATCH] applicant {app_id!r}: "
                f"bundled decision has no 'apr_pct' field (expected {apr!r})",
                file=sys.stderr,
            )
            return False
        bundled_apr = bundled["apr_pct"]
        if apr != bundled_apr:
            print(
                f"[RE_DERIVATION_MISMATCH] applicant {app_id!r}: "
                f"re-derived apr_pct={apr!r} but bundled apr_pct={bundled_apr!r}",
                file=sys.stderr,
            )
            return False
        compared.add("decisions[].apr_pct")

        # Compare PD (probability of default) — LGPD art. 20 requires the
        # lender disclose the criteria/procedure of the automated decision,
        # and pd is that number: a PD range maps many distinct raw
        # probabilities onto the same tier/decision/apr, so matching tier
        # (checked above) does not by itself bind the disclosed pd to what
        # was actually computed. The comparison is TWO checks:
        #   1. commitment format — the bundled pd must be stored at the
        #      builder's declared 6dp precision (round-trip stable);
        #   2. value — |re-derived pd − bundled pd| <= 1e-6.
        # The old exact-equality-after-round(6) here was the anti-pattern
        # dp_minimal's numeric_model annotation exists to prevent: pd comes
        # off math.exp, and libm transcendentals are NOT bit-identical
        # across platforms, so an honest cross-platform re-derivation could
        # land on the other side of a 6dp rounding boundary and RED. The
        # tolerance is sized for exactly that: 5e-7 rounding half-grain +
        # libm wobble (~1e-16 absolute for pd in (0,1)), with ~2x headroom.
        # numeric_model: binary64_libm_tolerated (the spec-vocabulary term;
        # this legacy pack carries it in-comment because its comparison is
        # hand-rolled, not registry-dispatched).
        _PD_TOL = 1e-6
        bundled_pd = bundled.get("pd")
        if bundled_pd is None:
            print(
                f"[CREDIT_SCORING_PD_MISMATCH] applicant {app_id!r}: "
                f"bundled decision has no 'pd' field — LGPD art. 20 requires "
                f"the probability-of-default be disclosed, not only the tier",
                file=sys.stderr,
            )
            return False

        pd_bad = (
            isinstance(bundled_pd, bool)
            or not isinstance(bundled_pd, (int, float))
            # commitment format: stored at 6dp (round-trip stable)
            or round(bundled_pd, 6) != bundled_pd
            # value: within the libm-wobble + rounding-half-grain tolerance
            or abs(pd - bundled_pd) > _PD_TOL
        )
        if pd_bad:
            print(
                f"[CREDIT_SCORING_PD_MISMATCH] applicant {app_id!r}: "
                f"re-derived pd={round(pd, 6)!r} but bundled pd={bundled_pd!r} "
                f"(tolerance {_PD_TOL}; tier={tier['tier']!r} matches — a PD "
                f"range maps many raw probabilities onto one tier, so the "
                f"bundled pd was not bound to the re-derived value)",
                file=sys.stderr,
            )
            return False
        compared.add("decisions[].pd")

    _emit_compared(compared)
    return True


def _emit_compared(compared: "set[str]") -> None:
    """Print the payload fields whose values this run COMPARED, as one
    machine-readable stdout line, after every comparison succeeded. The set
    is accumulated inside _verify_decisions as each comparison passes — so a
    comparison that is removed, or skipped on some path, drops out of the
    line and the pilot's plugin stops reporting that field (the coverage gate
    then refuses to conclude). Never a constant; no producer-controlled
    string is interpolated. Paths use the claimset rendering (object keys
    joined by ".", every array position "[]")."""
    print(
        "[COMPARED] "
        + json.dumps(
            {"payload/credit_decisions.json": sorted(compared)}, sort_keys=True
        )
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Credit-scoring re-derivation check for credit_scoring_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Opt-out check: if required inputs are absent, pass silently ---
    scorecard_path = bundle_dir / "model" / "scorecard.json"
    threshold_path = bundle_dir / "model" / "threshold_table.json"
    applicants_dir = bundle_dir / "applicants"
    payload_path = bundle_dir / "payload" / "credit_decisions.json"

    if not scorecard_path.exists() and not applicants_dir.is_dir():
        # Bundle opted out of credit-scoring re-derivation
        return 0

    # --- Load required inputs ---
    scorecard = _load_json(scorecard_path, "model/scorecard.json")
    if scorecard is None:
        if not scorecard_path.exists():
            return 0  # opted out
        return 1

    threshold_table = _load_json(threshold_path, "model/threshold_table.json")
    if threshold_table is None:
        if not threshold_path.exists():
            return 0  # opted out
        return 1

    applicants = _load_applicants(bundle_dir)
    if applicants is None:
        if not applicants_dir.is_dir():
            return 0  # opted out
        return 1

    if not applicants:
        print(
            "[RE_DERIVATION_MISMATCH] applicants/ directory is empty",
            file=sys.stderr,
        )
        return 1

    bundled_payload = _load_json(payload_path, "payload/credit_decisions.json")
    if bundled_payload is None:
        if not payload_path.exists():
            return 0  # opted out
        return 1

    # --- Bind the replayed inputs to the bureau snapshot the bundle registers ---
    if not _verify_bureau_provenance(bundle_dir, applicants):
        return 1

    # --- Run re-derivation ---
    ok = _verify_decisions(applicants, scorecard, threshold_table, bundled_payload)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
