"""tests/test_claimset_ratchet.py — the per-field tamper battery's own teeth.

The load-bearing pair: a plugin that DECLARES coverage while comparing nothing
passes the gate (by design — documented fail-open) and the ratchet reports
every such field SURVIVED; a plugin that actually binds values FLIPS on every
mutation. Plus the SKIPPED path (empty-container elements) and the
element-string round-trip the mutation targeting depends on.

Stdlib + pytest only.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_bundle.claimset import ClaimsetError, render_element
from audit_bundle.plugin import PluginResult
from audit_bundle.verifier import BundleVerifier
from claimset_ratchet import _split_element, run_claimset_ratchet

_PAYLOAD = {
    "model_id": "m-1",
    "records": [
        {"idx": 0, "pd": 0.12, "band": "A"},
        {"idx": 1, "pd": 0.5, "band": "B"},
    ],
    "notes": "",
}

_ELEMENTS = frozenset(
    {
        "claims:model_id",
        "claims:records[].idx",
        "claims:records[].pd",
        "claims:records[].band",
        "claims:notes",
    }
)


def _write_bundle(tmp_path: Path, payload_obj: object = None) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "payload").mkdir()
    raw = json.dumps(_PAYLOAD if payload_obj is None else payload_obj).encode()
    (bundle_dir / "payload/claims.json").write_bytes(raw)
    manifest = {
        "schema_version": "legacy",
        "bundle_id": "claimset-ratchet-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"payload/claims.json": hashlib.sha256(raw).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
        "claimset": {"claim_files": {"claims": "payload/claims.json"}},
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


class _VacuousReporter:
    """Declares every field covered; compares nothing. The false declaration."""

    name = "vacuous_reporter"

    def check(self, bundle_dir, manifest) -> PluginResult:
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="",
            files_audited=("payload/claims.json",),  # listed, never compared
            verified_claim_fields=frozenset(_ELEMENTS),
        )


class _BindingComparator:
    """Actually binds every claim field against verifier-held expected values
    (auditor-anchored style: the expectation is constructor state, never read
    from the bundle)."""

    name = "binding_comparator"

    def __init__(self, expected: dict):
        self._expected = expected

    def check(self, bundle_dir, manifest) -> PluginResult:
        actual = json.loads(
            (Path(bundle_dir) / "payload/claims.json").read_text(encoding="utf-8")
        )
        ok = actual == self._expected
        return PluginResult(
            ok=ok,
            reason_code="PASS" if ok else "CLAIMS_PAYLOAD_MISMATCH",
            detail="" if ok else "payload does not match verifier-held expectation",
            files_audited=("payload/claims.json",),
            verified_claim_fields=frozenset(_ELEMENTS),
        )


def test_ratchet_reports_false_declarations_as_survived(tmp_path):
    bundle = _write_bundle(tmp_path)
    report = run_claimset_ratchet(
        bundle,
        lambda: BundleVerifier(plugins=[_VacuousReporter()]),
        tmp_path / "scratch",
        comparator_codes={"CLAIMS_PAYLOAD_MISMATCH"},
    )
    assert report.baseline_state == "OK"
    assert not report.skipped
    assert {o.element for o in report.survived} == set(_ELEMENTS)
    assert not report.flipped


def test_ratchet_passes_a_real_comparator(tmp_path):
    bundle = _write_bundle(tmp_path)
    report = run_claimset_ratchet(
        bundle,
        lambda: BundleVerifier(plugins=[_BindingComparator(_PAYLOAD)]),
        tmp_path / "scratch",
        comparator_codes={"CLAIMS_PAYLOAD_MISMATCH"},
    )
    assert report.baseline_state == "OK"
    assert not report.survived, [o.element for o in report.survived]
    assert {o.element for o in report.flipped} == set(_ELEMENTS)
    for outcome in report.flipped:
        # the flip must come from the COMPARATOR -- and now that
        # _step_typed_check_plugins propagates the plugin's own reason_code,
        # this names the comparator's code instead of the generic wrapper.
        # Never from the file-sha walk: the re-pin makes the mutation
        # producer-consistent, so a BAD_FILE_SHA flip would prove nothing.
        assert "CLAIMS_PAYLOAD_MISMATCH" in outcome.reason_codes, outcome.reason_codes
        assert "BAD_FILE_SHA" not in outcome.reason_codes, outcome.reason_codes


def test_ratchet_skips_empty_container_elements_loudly(tmp_path):
    payload = {"model_id": "m-1", "empty_block": {}}
    bundle = _write_bundle(tmp_path, payload_obj=payload)
    expected = json.loads(json.dumps(payload))

    class _Cmp:
        """Binds both declared fields against a verifier-held expectation.

        NB the reason_code is conditional. It used to be the literal "PASS" on
        BOTH arms, which made this a MALFORMED plugin: a failing result
        carrying the success sentinel. That was invisible while the verifier
        overwrote every failing plugin's code with "plugin_failed"; once the
        real code is propagated, such a result has no usable code and scores
        INCONCLUSIVE rather than being credited as a comparator refusal.
        """

        name = "cmp"

        def check(self, bundle_dir, manifest) -> PluginResult:
            actual = json.loads(
                (Path(bundle_dir) / "payload/claims.json").read_text(encoding="utf-8")
            )
            ok = actual == expected
            return PluginResult(
                ok=ok,
                reason_code="PASS" if ok else "CLAIMS_PAYLOAD_MISMATCH",
                detail="" if ok else "payload does not match verifier-held expectation",
                files_audited=("payload/claims.json",),
                verified_claim_fields=frozenset(
                    {"claims:model_id", "claims:empty_block"}
                ),
            )

    report = run_claimset_ratchet(
        bundle,
        lambda: BundleVerifier(plugins=[_Cmp()]),
        tmp_path / "scratch",
        comparator_codes={"CLAIMS_PAYLOAD_MISMATCH"},
    )
    skipped = {o.element for o in report.skipped}
    assert skipped == {"claims:empty_block"}
    assert {o.element for o in report.flipped} == {"claims:model_id"}
    assert report.scoring == "deny-by-default"


def test_ratchet_refuses_a_failing_baseline(tmp_path):
    bundle = _write_bundle(tmp_path)
    with pytest.raises(ClaimsetError, match="baseline"):
        run_claimset_ratchet(
            bundle, lambda: BundleVerifier(), tmp_path / "scratch",
            comparator_codes={"CLAIMS_PAYLOAD_MISMATCH"},
        )


def test_split_element_round_trips_render_element():
    cases = [
        ("claims", ()),
        ("claims", ("a",)),
        ("claims", ("a", "b")),
        ("claims", ("records", "[]", "pd")),
        ("claims", ("[]", "pd")),
        ("claims", ("a", "[]", "[]", "b")),
        (
            "claims",
            (
                "a",
                "[]",
            ),
        ),
    ]
    for key, path in cases:
        rendered = render_element(key, path)
        assert _split_element(rendered) == (key, path), rendered


def test_classify_ratchet_outcome_attribution():
    from claimset_ratchet import classify_ratchet_outcome

    # still OK → the coverage declaration is false
    assert classify_ratchet_outcome(True, ())[0] == "SURVIVED"
    # flipped only via plumbing → not evidence of binding
    assert classify_ratchet_outcome(False, ("BAD_FILE_SHA",))[0] == "INCONCLUSIVE"
    assert (
        classify_ratchet_outcome(False, ("CLAIMSET_UNIVERSE_ANCHOR_MISMATCH",))[0]
        == "INCONCLUSIVE"
    )
    # flipped with a comparator reason → real evidence
    assert (
        classify_ratchet_outcome(False, ("CLAIMS_PAYLOAD_MISMATCH",))[0] == "FLIPPED"
    )
    # a mix that includes a comparator reason is still a real flip
    assert (
        classify_ratchet_outcome(False, ("BAD_FILE_SHA", "CLAIMS_PAYLOAD_MISMATCH"))[0]
        == "FLIPPED"
    )
    # "plugin_failed" is NOT a comparator reason. Since the verifier stopped
    # overwriting plugin codes with it, it is emitted only when a plugin
    # crashed, was declared but never wired, or returned a failing result with
    # no usable code — none of which compared a value.
    assert classify_ratchet_outcome(False, ("plugin_failed",))[0] == "INCONCLUSIVE"
    assert (
        classify_ratchet_outcome(False, ("BAD_FILE_SHA", "plugin_failed"))[0]
        == "INCONCLUSIVE"
    )
    # non-OK with no reasons at all is not creditable as a comparator flip.
    # (This assertion used to read FLIPPED while its own comment said the
    # opposite; absence of a plumbing code is not presence of a refusal.)
    assert classify_ratchet_outcome(False, ())[0] == "INCONCLUSIVE"

    # --- deny-by-default mode: the caller names its comparator's codes -------
    declared = {"CLAIMS_PAYLOAD_MISMATCH"}
    assert (
        classify_ratchet_outcome(
            False, ("CLAIMS_PAYLOAD_MISMATCH",), None, declared
        )[0]
        == "FLIPPED"
    )
    # a code nobody classified is NOT credited in this mode — the whole point
    assert (
        classify_ratchet_outcome(False, ("SOME_NEW_PILOT_CODE",), None, declared)[0]
        == "INCONCLUSIVE"
    )
    # ...whereas the denylist default DOES credit it (the disclosed fail-open)
    assert (
        classify_ratchet_outcome(False, ("SOME_NEW_PILOT_CODE",))[0] == "FLIPPED"
    )
