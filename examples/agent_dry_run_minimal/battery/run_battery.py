#!/usr/bin/env python3
"""run_battery.py — plant every fault family, score what the re-derivation notices.

    python examples/agent_dry_run_minimal/battery/run_battery.py [--out RESULT_battery.json]

Deterministic. No clock, no network, no LLM.

Expectations are in PREREGISTRATION.md and mirrored in `faults.EXPECTED`, both committed
before this was first run. The score reported is agreement with those expectations — not
"how many faults were caught", because three of them are pre-registered as MISSES and a
battery scoring 13/13 would mean the battery was written to flatter the checker.

Two guards keep the result honest, and both run BEFORE scoring:

  1. **Hash consistency per fault.** Every planted fault must leave the bundle
     hash-consistent. A forgery that trips `file_integrity_many_small` would be "caught" for
     a reason that has nothing to do with re-derivation.
  2. **The negative control must re-derive first.** A control whose own inputs disagree with
     each other measures propagation rather than blindness — which is exactly how an earlier
     pilot's control scored 2/6 for reasons unrelated to its detector.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PILOT = _HERE.parent
_PKG_ROOT = _PILOT.parents[1]
for _p in (str(_PKG_ROOT), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import faults  # noqa: E402

ALL_EXPECTED = {**faults.EXPECTED, **faults.EXPECTED_POST_HOC}

PACK = _PKG_ROOT / "audit_bundle" / "plugins" / "reference" / "agent_dry_run_pack.py"
CLI = _PKG_ROOT / "veriker" / "cli" / "verify.py"
FIXTURE = _PILOT / "fixtures" / "procurement_ap"
CONTROL_FIXTURE = _PILOT / "fixtures" / "agentdojo_banking"
RESULT_PATH = _HERE / "RESULT_battery.json"


def detected_by_pack(bundle: Path) -> tuple[bool, str]:
    """Detected == the re-derivation itself refuses the bundle."""
    r = subprocess.run(
        [sys.executable, str(PACK), "--bundle-dir", str(bundle)], capture_output=True, timeout=300
    )
    reason = (r.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()
    return r.returncode != 0, (reason[0][:200] if reason else "")


def detected_by_cli(bundle: Path) -> tuple[bool, str]:
    """Detected == the SHIPPED VERIFIER BINARY refuses the bundle.

    Distinct from `detected_by_pack` on purpose, and the distinction is not cosmetic: the
    pack re-derives unconditionally, while the CLI decides which checks to construct. A
    fault that attacks the CLI's decision — M1 — is invisible to the pack, so measuring it
    with the pack answers a question nobody asked. The first run of this battery did exactly
    that and scored M1 as CAUGHT when the shipped binary exited 0 on it.
    """
    r = subprocess.run(
        [sys.executable, str(CLI), "--bundle-dir", str(bundle)], capture_output=True, timeout=600
    )
    out = (r.stdout or b"").decode("utf-8", errors="replace")
    line = next((ln for ln in out.splitlines() if ln.startswith("FAIL")), "")
    return r.returncode != 0, line[:200]


# Which probe answers the question each fault actually asks.
# The P-family attacks WHICH CHECKS THE VERIFIER CONSTRUCTS, like M1 — only the shipped CLI
# can see it. The pack would re-derive happily against whatever files remain.
PROBE = {name: "pack" for name in ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10")}


def detected(bundle: Path, fault: str) -> tuple[bool, str, str]:
    """M1 attacks which checks the verifier constructs, so only the CLI can see it. Every
    other family attacks the recorded numbers, which the pack is the right probe for — and
    the CLI is run on those too, so a fault the pack catches but the shipped binary does not
    would show up rather than hide."""
    if PROBE.get(fault.split("_", 1)[0]) == "pack":
        was, reason = detected_by_pack(bundle)
        cli_was, cli_reason = detected_by_cli(bundle)
        if was != cli_was:
            return was, f"PROBE_DISAGREEMENT pack={was} cli={cli_was}: {reason} | {cli_reason}", "both"
        return was, reason, "both"
    was, reason = detected_by_cli(bundle)
    return was, reason, "cli"


def run(tmp: Path) -> dict:
    clean = tmp / "clean"
    faults.build_clean(FIXTURE, clean)

    rows: list[dict] = []

    for name in faults.EDIT_FAULTS:
        out = tmp / f"edit_{name}"
        faults.build_edit_fault(clean, name, out)
        inconsistent = faults.assert_hash_consistent(out)
        was, reason, probe = detected(out, name)
        rows.append(
            {
                "fault": name,
                "shape": "EDIT",
                "probe": probe,
                "expected": ALL_EXPECTED[name],
                "observed": faults.CAUGHT if was else faults.MISSED,
                "agrees": (faults.CAUGHT if was else faults.MISSED) == ALL_EXPECTED[name],
                "hash_consistent": not inconsistent,
                "hash_problems": inconsistent,
                "reason": reason,
            }
        )

    for name in faults.REBUILD_FAULTS:
        work, out = tmp / f"fx_{name}", tmp / f"rebuild_{name}"
        faults.build_rebuild_fault(FIXTURE, name, work, out)
        inconsistent = faults.assert_hash_consistent(out)
        was, reason, probe = detected(out, name)
        rows.append(
            {
                "fault": name,
                "shape": "REBUILD",
                "probe": probe,
                "expected": ALL_EXPECTED[name],
                "observed": faults.CAUGHT if was else faults.MISSED,
                "agrees": (faults.CAUGHT if was else faults.MISSED) == ALL_EXPECTED[name],
                "hash_consistent": not inconsistent,
                "hash_problems": inconsistent,
                "reason": reason,
            }
        )

    # --- negative control: consistency asserted BEFORE scoring ---
    control = tmp / "control"
    faults.build_clean(CONTROL_FIXTURE, control)
    control_inconsistent = faults.assert_hash_consistent(control)
    control_detected, control_reason, _ = detected(control, "CONTROL")

    mechanical = [r for r in rows if r["fault"].startswith("F")]
    structural = [r for r in rows if r["fault"].startswith("N")]
    mutant = [r for r in rows if r["fault"].startswith("M")]
    post_hoc = [r for r in rows if r["fault"].startswith("P")]

    return {
        "run": "agent_dry_run_fault_battery",
        "deterministic": True,
        "llm_calls": 0,
        "fixture": FIXTURE.name,
        "control_fixture": CONTROL_FIXTURE.name,
        "prereg": "PREREGISTRATION.md (committed before this run)",
        # This file records the state AFTER the fixes FINDINGS.md describes. M1 was MISSED
        # on first measurement — the shipped CLI passed a forged bundle with exit 0 — and
        # the battery's own M1 probe was measuring the wrong binary. Read FINDINGS.md before
        # quoting the score below.
        "findings": "FINDINGS.md — M1 was MISSED on first run; see it before quoting a score",
        "rows": rows,
        "score": {
            # PRE-REGISTERED families only. The post-hoc families are counted separately
            # below: folding families added after the answer was known into the headline
            # would retro-inflate a number whose whole value is that it was fixed in advance.
            "agrees_with_prereg": sum(
                r["agrees"] for r in rows if r["fault"] in faults.EXPECTED
            ),
            "families": len(faults.EXPECTED),
            "mechanical_caught": sum(r["observed"] == faults.CAUGHT for r in mechanical),
            "mechanical_total": len(mechanical),
            "structural_missed_as_predicted": sum(
                r["observed"] == faults.MISSED for r in structural
            ),
            "structural_total": len(structural),
            "mutant_control": {r["fault"]: r["observed"] for r in mutant},
            # Added AFTER the battery scored 14/14, by a red-team agent this battery did not
            # catch. Reported separately so the pre-registered score stays legible as what it
            # was, rather than being retro-inflated by families added once the answer was known.
            "post_hoc_adversarial_pass": {r["fault"]: r["observed"] for r in post_hoc},
            "post_hoc_caught": sum(r["observed"] == faults.CAUGHT for r in post_hoc),
            "post_hoc_total": len(post_hoc),
        },
        "negative_control": {
            "bundle": CONTROL_FIXTURE.name,
            "internally_consistent_before_scoring": not control_inconsistent,
            "consistency_problems": control_inconsistent,
            "detections": 1 if control_detected else 0,
            "expected_detections": 0,
            "reason": control_reason,
        },
        "all_faults_hash_consistent": all(r["hash_consistent"] for r in rows),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=RESULT_PATH)
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory() as td:
        result = run(Path(td))

    print(f"{'fault':<34}{'shape':<9}{'probe':<6}{'expected':<10}{'observed':<10}{'ok':<4}")
    for r in result["rows"]:
        print(
            f"{r['fault']:<34}{r['shape']:<9}{r['probe']:<6}{r['expected']:<10}"
            f"{r['observed']:<10}{'yes' if r['agrees'] else 'NO':<4}"
        )
    s = result["score"]
    nc = result["negative_control"]
    print(
        f"\nagrees with pre-registration : {s['agrees_with_prereg']}/{s['families']}"
        f"  (pre-registered families only)"
        f"\npost-hoc (adversarial pass)  : {s['post_hoc_caught']}/{s['post_hoc_total']} caught"
        f"  — added AFTER the 14/14, by a red-team agent this battery missed"
        f"\nmechanical caught            : {s['mechanical_caught']}/{s['mechanical_total']}"
        f"\nstructural missed as predicted: {s['structural_missed_as_predicted']}"
        f"/{s['structural_total']}"
        f"\nmutant control               : {s['mutant_control']}"
        f"\nnegative control detections  : {nc['detections']}/1 "
        f"(expected {nc['expected_detections']}; consistent first: "
        f"{nc['internally_consistent_before_scoring']})"
        f"\nall faults hash-consistent   : {result['all_faults_hash_consistent']}"
    )

    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
