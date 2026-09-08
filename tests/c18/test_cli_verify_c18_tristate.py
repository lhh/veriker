"""The CLI's copy of the C18 locator is the THIRD copy, and it was still two-state.

`tests/c18/test_c18_malformed_block_tristate.py` closed THREAT_MODEL row 20 for the
extension module and the tripwire plugin: a present-but-unparseable
`evidence.verifier_identity` must never share a return value with an absent one.
Its drift guard holds those TWO hand-maintained copies in agreement. The stdlib-only
`veriker/cli/verify.py` carries a third copy — `_c18_extract_verifier_identity`, `dict | None`
— and every non-dict value collapsed to None, which `_c18_structural_check` read as
"pre-C18 bundle, clean PASS". Measured 2026-09-02 on master ad653a966:

    evidence.verifier_identity = {}   -> FAIL  VERIFIER_IDENTITY_FIELD_MISSING
    evidence.verifier_identity = "x"  -> PASS  "no verifier_identity field (pre-C18 bundle)"

Degrading the block past the parser's recognition threshold was rewarded, in the
binary the repo calls "the shipped, working verifier today". The rule behind this
file: a guard under an early return is never in one place — grep every copy.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle._degradation import (  # noqa: E402
    Severity,
    format_report,
    probe_monotonicity,
    reasons_adapter,
)
from audit_bundle.extensions import c18_verifier_identity as C18  # noqa: E402
from veriker.cli.verify import _c18_structural_check  # noqa: E402

MALFORMED_CODE = "VERIFIER_IDENTITY_BLOCK_MALFORMED"


def _bundle(tmp_path: Path, manifest: dict) -> Path:
    d = tmp_path / "bundle"
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return d


# label -> (manifest, ok expected, reason expected)
_MALFORMED = {
    "verifier_identity is a string": {"evidence": {"verifier_identity": "x"}},
    "verifier_identity is an int": {"evidence": {"verifier_identity": 0}},
    "verifier_identity is a list": {"evidence": {"verifier_identity": []}},
    "verifier_identity is a bool": {"evidence": {"verifier_identity": True}},
    "evidence itself is a string (one level up)": {"evidence": "x"},
    "evidence itself is a list": {"evidence": [1]},
}
_ABSENT = {
    "no evidence key": {"other": 1},
    "evidence with no verifier_identity key": {"evidence": {}},
    "verifier_identity is null (unset)": {"evidence": {"verifier_identity": None}},
    "evidence is null (unset)": {"evidence": None},
}


@pytest.mark.parametrize("label", sorted(_MALFORMED))
def test_malformed_block_fails_with_its_own_code(tmp_path: Path, label: str) -> None:
    ok, reason, detail = _c18_structural_check(_bundle(tmp_path, _MALFORMED[label]))
    assert ok is False, f"{label}: a malformed block passed clean ({detail})"
    assert reason == MALFORMED_CODE, f"{label}: got {reason} — {detail}"
    assert "pre-C18" not in detail


@pytest.mark.parametrize("label", sorted(_ABSENT))
def test_absent_block_still_passes_clean(tmp_path: Path, label: str) -> None:
    """Anti-regression: legacy bundles say nothing and must keep passing."""
    ok, reason, _ = _c18_structural_check(_bundle(tmp_path, _ABSENT[label]))
    assert ok is True, label
    assert reason is None


def test_the_gradient_is_inverted(tmp_path: Path) -> None:
    """Incomplete-but-well-formed draws FIELD_MISSING; unparseable draws
    BLOCK_MALFORMED; NEITHER passes, and malformed is not reported as missing."""
    ok_inc, r_inc, _ = _c18_structural_check(
        _bundle(tmp_path / "a", {"evidence": {"verifier_identity": {}}})
    )
    ok_mal, r_mal, d_mal = _c18_structural_check(
        _bundle(tmp_path / "b", {"evidence": {"verifier_identity": "x"}})
    )
    assert ok_inc is False and r_inc == "VERIFIER_IDENTITY_FIELD_MISSING"
    assert ok_mal is False and r_mal == MALFORMED_CODE
    assert "missing" not in d_mal.lower()


def test_cli_locator_agrees_with_the_extension_copy_on_every_dict_case() -> None:
    """Third copy joins the drift guard. Only dict manifests: the CLI is stdlib-only
    and never sees a dataclass. Same (state, block) tuple, same vocabulary."""
    from veriker.cli.verify import _c18_locate_verifier_identity

    cases = {**_MALFORMED, **_ABSENT}
    cases["found"] = {"evidence": {"verifier_identity": {"k": 1}}}
    for label, manifest in cases.items():
        assert _c18_locate_verifier_identity(manifest) == C18._locate_verifier_identity(
            manifest
        ), f"CLI copy disagrees with the extension on {label!r}"


def test_degradation_oracle_is_clean_on_the_cli_check(tmp_path: Path) -> None:
    """Row 20, mechanised: walk the ladder at evidence.verifier_identity and at
    evidence, and require no rung to be softer than a less-degraded one."""
    counter = {"n": 0}

    def reasons(manifest):
        counter["n"] += 1
        d = _bundle(tmp_path / f"m{counter['n']}", manifest)
        ok, reason, _ = _c18_structural_check(d)
        return [] if ok else [reason]

    fixture = {
        "evidence": {
            "verifier_identity": {
                "verifier_release_id": "v0.3.0",
                "verifier_oci_digest": "sha256:" + "a" * 64,
                "verifier_self_check_status": "passed",
                "release_manifest_url": "https://example.invalid/MANIFEST.txt",
                "release_manifest_hash": "sha256:" + "b" * 64,
                "scitt_statement_hash": "sha256:" + "c" * 64,
                "sigstore_bundle_hash": "sha256:" + "d" * 64,
                "rekor_inclusion_proof": {
                    "leaf_index": 1,
                    "tree_size": 2,
                    "hashes": ["aa"],
                    "root_hash": "bb",
                },
            }
        }
    }
    baseline_ok, baseline_reason, _ = _c18_structural_check(
        _bundle(tmp_path / "baseline", fixture)
    )
    assert baseline_ok, (
        baseline_reason
    )  # the oracle refuses an already-rejected fixture
    # Same declared limit as the extension's own oracle test: JSON null is ABSENT
    # (a `dict | None = None` dataclass default), at BOTH container levels. It grants
    # a producer nothing that deleting the key does not; declared in writing, not
    # filtered in silence. Keyed on the transition, so anything worse at the same
    # rung is not excused.
    null_is_absent = (
        "JSON null is read as ABSENT by the CLI locator, mirroring "
        "c18_verifier_identity._locate_verifier_identity (cd5c782cd); same "
        "capability as deleting the key; no new escape."
    )
    declared = {
        (
            ("evidence", "verifier_identity"),
            "null",
            "MR-1",
            Severity.REJECT,
            Severity.PASS,
        ): null_is_absent,
        (("evidence",), "null", "MR-1", Severity.REJECT, Severity.PASS): null_is_absent,
    }
    rep = probe_monotonicity(
        fixture,
        reasons_adapter(reasons),
        paths=[("evidence", "verifier_identity"), ("evidence",)],
        declared=declared,
    )
    assert not rep.vacuous, format_report(rep)
    assert rep.findings == [], format_report(rep)
    assert rep.declared_limits, "the null declaration went stale — re-derive it"
    # The only disclosures are absence itself (row 20 clause 1: absent may pass).
    assert {d.rung for d in rep.disclosures} <= {"absent", "parent_absent"}, (
        format_report(rep)
    )


def test_main_runs_the_check_on_a_malformed_block() -> None:
    """The fourth site: main() auto-enabled the C18 gate only when the block was a
    dict, so a malformed block never reached `_c18_structural_check` at all."""
    from veriker.cli.verify import _c18_should_run

    assert _c18_should_run({"evidence": {"verifier_identity": "x"}}) is True
    assert _c18_should_run({"evidence": "x"}) is True
    assert _c18_should_run({"evidence": {"verifier_identity": {"k": 1}}}) is True
    assert _c18_should_run({"evidence": {"verifier_identity": None}}) is False
    assert _c18_should_run({"other": 1}) is False
