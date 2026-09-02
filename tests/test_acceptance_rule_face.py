"""tests/test_acceptance_rule_face.py — the verdict face names WHICH acceptance
rule ran, and says so only because the rule ran.

WHY THIS EXISTS. Before it, the only thing distinguishing a verifier that
enforces the §4a.4 output-set coverage invariant from one that fails open on it
was the package version — a vendor build counter. That makes the acceptance
behaviour a property of WHOSE BUILD RAN, which is precisely the weld versioned
primitive contracts exist to avoid (PRIMITIVES.md, "What `@version` means"): a
version only its author can supply cannot be declared by a conforming
independent implementation. `coverage_exact_outputs@1` is a contract token any
verifier may declare and any consumer may require.

THE ABSENCE IS THE LOAD-BEARING HALF, and it is why this landed before the
public cut rather than after. Coverage triggers on the PRODUCER-CONTROLLED
`outputs/` path, so a producer who forges every claim, deletes
`manifest.outputs` and renames `outputs/` -> `results/` presents a bundle with
nothing to compare and collects a clean PASS (THREAT_MODEL.md row 5, stated
residual; measured 2026-08-29 and reproduced by these tests). That residual is
NOT closed here — closing it needs the auditor's anchor to state the expected
output_ids. What changes is that the uncovered bundle no longer presents the
SAME FACE as an honestly-covered one, so a strict consumer can refuse it.

MEASURED, NEVER DECLARED. The APPLIED row is written from inside the comparison
(`_check_coverage`), not from a list in the renderer.
`test_face_cannot_claim_the_rule_when_the_check_does_not_run` is the control:
with the check neutered, the row must vanish. A hardcoded row would be the same
shape as the THREAT_MODEL entry that advertised this guard for months while it
sat below an early return in three places.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from audit_bundle.rederivation import dispatch as _dispatch
from audit_bundle.rederivation.coverage_trigger import (
    ACCEPTANCE_RULE_ID,
    ACCEPTANCE_RULE_VERSION,
    acceptance_rule_ref,
)
from audit_bundle.verifier import BundleVerifier

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "witness_cert_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"

_PREFIX = "acceptance: "


def _build(out_dir: Path) -> None:
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _acceptance_rows(bundle_dir: Path) -> list[str]:
    verdict = BundleVerifier().verify(bundle_dir)
    return [
        d[len(_PREFIX) :]
        for d in (verdict.completeness.disclosures or ())
        if d.startswith(_PREFIX)
    ]


def _relocate_outputs(bundle_dir: Path) -> None:
    """The stated residual, as an attacker performs it: forge every claimed
    value, realign each sha so file integrity is satisfied, delete
    `manifest.outputs`, and move the tree out from under the trigger."""
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    for out in sorted((bundle_dir / "outputs").glob("*.json")):
        doc = json.loads(out.read_text())
        for k, v in list(doc.items()):
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                doc[k] = v * 2
        out.write_text(json.dumps(doc))
        manifest["files"].pop(f"outputs/{out.name}", None)
        manifest["files"][f"results/{out.name}"] = hashlib.sha256(
            out.read_bytes()
        ).hexdigest()
    (bundle_dir / "outputs").rename(bundle_dir / "results")
    manifest["outputs"] = []
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))


def test_rule_ref_is_a_contract_token_not_a_build_number():
    """Monotonic integer, exact-equality comparison — never semver. A dotted
    spelling would promise compatibility semantics nothing implements."""
    assert acceptance_rule_ref() == f"{ACCEPTANCE_RULE_ID}@{ACCEPTANCE_RULE_VERSION}"
    assert ACCEPTANCE_RULE_VERSION.isdigit(), (
        f"{ACCEPTANCE_RULE_VERSION!r} is not a monotonic integer revision"
    )
    assert "." not in ACCEPTANCE_RULE_VERSION


def test_honest_bundle_face_says_the_rule_was_applied(tmp_path):
    bundle = tmp_path / "b"
    _build(bundle)
    rows = _acceptance_rows(bundle)
    assert rows == [f"{acceptance_rule_ref()} APPLIED - satisfied"], rows


def test_omitted_outputs_entry_face_says_applied_and_violated(tmp_path):
    """The attack the invariant exists to catch. The face must still report the
    rule as APPLIED — a consumer asking "was coverage evaluated" needs the same
    answer whether it passed or failed."""
    bundle = tmp_path / "b"
    _build(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text())
    manifest["outputs"] = []
    (bundle / "manifest.json").write_text(json.dumps(manifest))
    rows = _acceptance_rows(bundle)
    assert rows == [f"{acceptance_rule_ref()} APPLIED - violated"], rows


def test_relocated_outputs_face_discloses_that_nothing_was_compared(tmp_path):
    """THE ONE THAT MATTERS. This bundle PASSES — the residual is real and is
    not closed here. What must not happen is it passing while presenting the
    same face as an honestly-covered bundle."""
    bundle = tmp_path / "b"
    _build(bundle)
    _relocate_outputs(bundle)
    rows = _acceptance_rows(bundle)
    assert len(rows) == 1, rows
    assert rows[0].startswith(f"{acceptance_rule_ref()} NOT APPLIED"), rows
    assert "relocates" in rows[0], "the disclosure must name the residual it exposes"

    honest = tmp_path / "h"
    _build(honest)
    assert _acceptance_rows(honest) != rows, (
        "an uncovered bundle and an honestly-covered one present the SAME "
        "acceptance face — the disclosure distinguishes nothing"
    )


def test_face_cannot_claim_the_rule_when_the_check_does_not_run(
    tmp_path, monkeypatch
):
    """MUTANT CONTROL for measured-not-declared. Neuter the comparison and the
    APPLIED row must disappear. If it survives, the face is asserting
    enforcement from a hardcoded list — the exact shape of the THREAT_MODEL row
    that advertised this guard while it sat below an early return."""
    bundle = tmp_path / "b"
    _build(bundle)
    assert _acceptance_rows(bundle), "precondition: the honest face carries a row"

    def _neutered(bundle_dir, declared_ids, failures, acceptance_out=None):
        return None

    monkeypatch.setattr(_dispatch, "_check_coverage", _neutered)
    rows = _acceptance_rows(bundle)
    assert not [r for r in rows if "APPLIED - " in r and "NOT APPLIED" not in r], (
        f"face still claims the rule ran after the check was neutered: {rows}"
    )


def test_cli_prints_the_acceptance_row_and_flags_the_absence(tmp_path):
    """A face field nobody renders is a face field nobody reads. The CLI is
    where an operator sees this, and the NOT-APPLIED case must be visually
    marked — it rides an otherwise-clean PASS."""
    bundle = tmp_path / "b"
    _build(bundle)
    cli = _PKG_ROOT / "veriker" / "cli" / "verify.py"
    honest = subprocess.run(
        [sys.executable, str(cli), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    ).stdout
    assert f"acceptance  {acceptance_rule_ref()} APPLIED - satisfied" in honest

    _relocate_outputs(bundle)
    relocated = subprocess.run(
        [sys.executable, str(cli), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    ).stdout
    assert "NOT APPLIED" in relocated
    assert "!!" in relocated, "the absence must be visually marked, not buried"
    assert "\nPASS  (" in relocated, (
        "precondition: this bundle still PASSES — if it now fails, the residual "
        "was closed and this test should be rewritten rather than deleted"
    )
