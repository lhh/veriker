"""Battery for event_log_replay_minimal — replay an append-only log to a digest.

What this pilot demonstrates, and what each surface below pins down:

  THE PUBLIC VERIFIER RUNS THE METHOD. `event_log_replay_recompute` ships in the
  distribution and consolidates a shape that recurs across domains. This is the
  public bundle it runs on: no demo-local `register_primitive`, no import of the
  primitive module, nothing but core auto-registration.

  THE LOG IS FOUND, NOT POINTED AT. The verifier locates the log structurally as
  the sole `inputs/*.jsonl`. Zero is a missing log and several is an ambiguous
  bundle, and both are refused rather than resolved — so a producer cannot ship a
  friendlier second log and hope the verifier picks it.

  WHAT THE DIGEST DOES NOT SEE. It is a fold to STATE, not over the chain. Two
  further tests below make that concrete and neither of them is a failure
  demonstration: an appended LOG event, and the ERASURE of every LOG event
  already in the log, both leave the reconstructed record — and therefore the
  digest — untouched, and the bundle verifies clean. An auditor adopting this
  shape is adopting that.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_PILOT = Path(__file__).resolve().parents[1]
_PKG_ROOT = _PILOT.parents[1]
for p in (str(_PKG_ROOT), str(_PILOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402

import _producer_replay as replay  # noqa: E402

_BUILD = _PILOT / "_build_bundle.py"
_SPEC_SRC = _PILOT / "spec_pinned" / "event_log_replay.spec.json"
_LOG_REL = "inputs/service_log.jsonl"
_OUTPUT_ID = "service_record_digest"
_CLAIM_REL = f"outputs/{_OUTPUT_ID}.json"
_RECORD_REL = "payload/reconstructed_record.json"


def _load_verify_module():
    """The pilot's verify.py by PATH under a pilot-unique module name (a bare
    `import verify` collides across pilots)."""
    spec = importlib.util.spec_from_file_location(
        "event_log_replay_minimal__verify", _PILOT / "verify.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(out_dir: Path) -> Path:
    subprocess.run(
        [sys.executable, str(_BUILD), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    return out_dir


def _verify(bundle_dir: Path):
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier

    anchor = SpecAnchor.from_files([_SPEC_SRC], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def _realign(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _forget(bundle_dir: Path, rel: str) -> None:
    """Delete a file AND its manifest entry, so file integrity has no complaint
    and only the re-derivation can object."""
    (bundle_dir / rel).unlink()
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"].pop(rel, None)
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _log_lines(bundle_dir: Path) -> list[str]:
    return (bundle_dir / _LOG_REL).read_text(encoding="utf-8").splitlines()


def _rewrite_log(bundle_dir: Path, lines: list[str]) -> None:
    (bundle_dir / _LOG_REL).write_text("\n".join(lines) + "\n", encoding="utf-8")
    _realign(bundle_dir, _LOG_REL)


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _details(result) -> str:
    return " | ".join(f.detail for f in result.failures)


def _index_of_seq(lines: list[str], seq: int) -> int:
    for i, line in enumerate(lines):
        if json.loads(line).get("seq") == seq:
            return i
    raise AssertionError(f"no event with seq={seq}")


# --------------------------------------------------------------------------- #
# The honest bundle
# --------------------------------------------------------------------------- #


def test_honest_bundle_passes(tmp_path):
    result = _verify(_build(tmp_path / "b"))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_pilot_verify_entry_point_passes(tmp_path):
    mod = _load_verify_module()
    bundle = _build(tmp_path / "b")
    assert mod.make_verifier(bundle).verify(bundle).ok


def test_committed_bundle_passes():
    """The bundle checked into the repo is the one the README's commands run."""
    result = _verify(_PILOT / "bundle")
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# Gate B — the claim is the producer's, never the verifier's
# --------------------------------------------------------------------------- #


def _import_targets(path: Path) -> set[str]:
    """Every module path a file can reach, as dotted strings.

    `from x.y import z` yields BOTH `x.y` and `x.y.z`. Recording only
    `node.module` would miss one spelling entirely --
    `from audit_bundle.rederivation import primitives` has module
    `audit_bundle.rederivation`, and `primitives/__init__.py` eagerly imports
    every primitive module, so the verifier's fold would be one attribute access
    away from a producer this check had just called clean.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, (
                f"{path.name}: relative import — this is a top-level script "
                "where that cannot bind, and it would be invisible to the check "
                "below"
            )
            if node.module:
                targets.add(node.module)
                targets |= {f"{node.module}.{a.name}" for a in node.names}
    return targets


def test_producer_does_not_import_the_verifier():
    """AST, not substring: both producer modules DISCUSS the rule in prose, so a
    text search matches its own documentation and proves nothing."""
    for mod in ("_build_bundle.py", "_producer_replay.py"):
        offending = {
            m
            for m in _import_targets(_PILOT / mod)
            if m == "audit_bundle.rederivation.primitives"
            or m.startswith("audit_bundle.rederivation.primitives.")
        }
        assert not offending, (
            f"{mod} imports the verifier's own primitive {sorted(offending)} — the "
            f"comparison would be f(x) == f(x)"
        )


def test_the_emitted_record_and_the_claimed_digest_agree(tmp_path):
    """A build-time consistency check, and NOT a disjointness proof.

    Both sides of this comparison come from one `replay.fold()` call in
    `_build_bundle.py`, so what it establishes is that the record survives its
    JSON round-trip into `payload/` unchanged. It is filed away from Gate B on
    purpose: an earlier draft asserted exactly this under a "the claim is the
    producer's, never the verifier's" heading, where it proved nothing of the
    kind. The disjointness claim is carried by
    `test_producer_does_not_import_the_verifier`, and the agreement between the
    producer and the shipped verifier is carried by the honest PASS.

    See also `test_the_payload_record_is_not_bound_by_verification`: nothing in
    the verifier checks this file, so this test is the ONLY thing that does.
    """
    bundle = _build(tmp_path / "b")
    claimed = json.loads((bundle / _CLAIM_REL).read_bytes())["value"]
    emitted = json.loads((bundle / _RECORD_REL).read_bytes())["record"]
    assert claimed == replay.record_digest(emitted)


# --------------------------------------------------------------------------- #
# Tamper surfaces the fold DOES catch
# --------------------------------------------------------------------------- #


def test_mutant_claimed_digest_fails(tmp_path):
    """THE MUTANT CONTROL. Replace the claimed digest and realign the manifest
    SHA so file integrity cannot preempt the verdict."""
    bundle = _build(tmp_path / "b")
    path = bundle / _CLAIM_REL
    doc = json.loads(path.read_bytes())
    doc["value"] = "0" * 64
    path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign(bundle, _CLAIM_REL)

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_mutant_fails_through_the_shipped_entry_point(tmp_path):
    """The same mutant through `verify.py` itself: FAIL on stdout, exit 1."""
    bundle = _build(tmp_path / "b")
    path = bundle / _CLAIM_REL
    doc = json.loads(path.read_bytes())
    doc["value"] = "0" * 64
    path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign(bundle, _CLAIM_REL)

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "RE_DERIVATION_MISMATCH" in proc.stdout


def test_dropped_amend_fails(tmp_path):
    """Remove the amendment that restricted the asset. The log then reconstructs
    a record that says the press is in normal service."""
    bundle = _build(tmp_path / "b")
    lines = _log_lines(bundle)
    del lines[_index_of_seq(lines, 5)]
    _rewrite_log(bundle, lines)

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_reordered_amends_fail(tmp_path):
    """Later writes win, so swapping the two AMENDs is not a cosmetic edit: it
    puts the earlier `in_service` amendment last and the restriction disappears
    from the reconstructed record."""
    bundle = _build(tmp_path / "b")
    lines = _log_lines(bundle)
    i3, i5 = _index_of_seq(lines, 3), _index_of_seq(lines, 5)
    lines[i3], lines[i5] = lines[i5], lines[i3]
    # The swap is only worth testing if it actually changes the record.
    before = replay.fold([json.loads(x) for x in _log_lines(bundle)])
    after = replay.fold([json.loads(x) for x in lines])
    assert before["status"] == "restricted_use" and after["status"] == "in_service"
    _rewrite_log(bundle, lines)

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_forged_amend_fails(tmp_path):
    """Edit the restricting amendment in place to say the asset stayed in
    service."""
    bundle = _build(tmp_path / "b")
    lines = [line.replace('"restricted_use"', '"in_service"') for line in _log_lines(bundle)]
    _rewrite_log(bundle, lines)

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


# --------------------------------------------------------------------------- #
# The log is located structurally, and ambiguity is refused
# --------------------------------------------------------------------------- #


def test_a_second_log_is_refused_not_resolved(tmp_path):
    """A producer ships an 'archive' copy beside the real log. The verifier does
    not choose between them."""
    bundle = _build(tmp_path / "b")
    decoy_rel = "inputs/service_log_archive.jsonl"
    (bundle / decoy_rel).write_bytes((bundle / _LOG_REL).read_bytes())
    mp = bundle / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][decoy_rel] = hashlib.sha256((bundle / decoy_rel).read_bytes()).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RECOMPUTE_ERROR"}, _reason_codes(result)
    assert "exactly one" in _details(result)


def test_a_missing_log_is_refused(tmp_path):
    """Delete the log and its manifest entry, so file integrity has nothing to
    say and only the re-derivation can object."""
    bundle = _build(tmp_path / "b")
    _forget(bundle, _LOG_REL)

    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RECOMPUTE_ERROR"}, _reason_codes(result)
    assert "exactly one" in _details(result)


# --------------------------------------------------------------------------- #
# Scope limits, demonstrated rather than described
# --------------------------------------------------------------------------- #


def test_an_appended_LOG_event_does_not_move_the_record(tmp_path):
    """Documented behaviour, shown rather than asserted: a LOG op is recorded but
    does not enter the authoritative record, so the digest is unchanged and the
    bundle still verifies."""
    bundle = _build(tmp_path / "b")
    lines = _log_lines(bundle)
    lines.append(
        json.dumps(
            {
                "seq": 6,
                "op": "LOG",
                "at": "2026-08-25T10:00:00Z",
                "actor": "inspector",
                "note": "follow-up",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    _rewrite_log(bundle, lines)

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_ERASING_every_LOG_event_also_passes(tmp_path):
    """THE SCOPE LIMIT WITH TEETH, and the reason the test above is not enough.
    Both inspections are deleted from the log outright — history removed, not
    added — and the bundle verifies CLEAN, because a LOG event never entered the
    record and so its absence cannot change the digest.

    This is not a defect in the primitive; it is what a fold to STATE means. An
    auditor whose question is 'were the inspections done' is asking about the
    completeness of the chain, and this shape does not answer it. Recorded here
    so that adopting the shape is a decision rather than an assumption."""
    bundle = _build(tmp_path / "b")
    before = _log_lines(bundle)
    lines = [line for line in before if json.loads(line)["op"] != "LOG"]
    assert len(lines) == len(before) - 2, (
        "fixture changed — the erasure no longer removes 2 events. (Pinning the "
        "REMAINDER instead, as an earlier draft did, would pass unchanged for a "
        "4-event fixture that erases one.)"
    )
    _rewrite_log(bundle, lines)

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def _rederived_digest_from_failure(result) -> str:
    """Pull the digest the VERIFIER recomputed out of the exact comparator's
    failure detail: `exact: re='<digest>' != claimed=...`."""
    match = re.search(r"re='([0-9a-f]{64})'", _details(result))
    assert match, f"no re-derived digest in the failure detail: {_details(result)}"
    return match.group(1)


def test_two_different_tamperings_that_reach_one_state_are_indistinguishable(tmp_path):
    """A fold to state cannot tell WHICH edit produced a record.

    Reordering the amendments and forging the later one arrive at the same
    reconstructed record, so the VERIFIER recomputes one digest for both. Both
    are refused — but only because neither matches the honest claim, not because
    the check told them apart.

    Measured against the shipped verifier, not against the producer's copy. An
    earlier draft asserted this by calling the producer's fold twice, which is
    the exact substitution this pilot forbids: the producer's copy is a
    DIFFERENT program (see `test_a_disposition_op_the_producer_would_refuse_is_
    ACCEPTED`), so it is not an oracle for what the verifier does.
    """
    reordered = _build(tmp_path / "reordered")
    lines = _log_lines(reordered)
    i3, i5 = _index_of_seq(lines, 3), _index_of_seq(lines, 5)
    lines[i3], lines[i5] = lines[i5], lines[i3]
    _rewrite_log(reordered, lines)

    forged = _build(tmp_path / "forged")
    _rewrite_log(
        forged,
        [line.replace('"restricted_use"', '"in_service"') for line in _log_lines(forged)],
    )

    result_reordered = _verify(reordered)
    result_forged = _verify(forged)
    assert not result_reordered.ok and not result_forged.ok

    digest_reordered = _rederived_digest_from_failure(result_reordered)
    digest_forged = _rederived_digest_from_failure(result_forged)
    honest = json.loads((_PILOT / "bundle" / _CLAIM_REL).read_bytes())["value"]

    assert digest_reordered == digest_forged, (
        "two edits reaching one state should re-derive to one digest"
    )
    assert digest_reordered != honest


def test_a_disposition_op_the_producer_would_refuse_is_ACCEPTED(tmp_path):
    """THE OP-SET GAP, and the one input class on which the two folds disagree.

    The bound primitive's non-mutating set is LOG, DELETE, DISPOSE, PURGE and
    DESTROY — seven accepted ops in all, not the three its own declared
    `primitive_scope_limits` names (its module docstring is the accurate one).
    So a DESTROY event appended to the log is SKIPPED, the reconstructed record
    does not move, and the bundle verifies clean.

    The producer's copy is stricter: `_producer_replay.NON_MUTATING` is `{"LOG"}`
    and everything else falls through to `unrecognised op`. So this is also the
    answer to "can these two folds ever disagree?" — they can, on exactly this
    class, and the VERIFIER is the laxer of the two. A record-disposition regime
    adopting this shape is adopting that.
    """
    bundle = _build(tmp_path / "b")
    lines = _log_lines(bundle)
    lines.append(
        json.dumps(
            {
                "seq": 6,
                "op": "DESTROY",
                "at": "2026-08-26T09:00:00Z",
                "actor": "records",
                "note": "disposed",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    _rewrite_log(bundle, lines)

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]

    with pytest.raises(ValueError, match="unrecognised op"):
        replay.fold([json.loads(line) for line in lines])


def test_the_seq_field_is_not_read(tmp_path):
    """`seq` is documentation. The verifier folds in FILE ORDER and never looks
    at it, so renumbering every event to a nonsense descending series changes
    nothing. A coherent-looking sequence is not evidence that the log is in the
    order it claims — and this pilot carries no hash chain to supply that."""
    bundle = _build(tmp_path / "b")
    events = [json.loads(line) for line in _log_lines(bundle)]
    for offset, event in enumerate(events):
        event["seq"] = 100 - offset
    _rewrite_log(
        bundle,
        [
            json.dumps(e, sort_keys=True, separators=(",", ":"))
            for e in events
        ],
    )

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_the_payload_record_is_not_bound_by_verification(tmp_path):
    """Dispatch reads the log and the claim. It never opens
    `payload/reconstructed_record.json`, which is covered only by a
    producer-authored manifest SHA — so a payload that flatly contradicts the log
    rides to a clean PASS. Anything a reader takes from that file, they are
    taking on the producer's word."""
    bundle = _build(tmp_path / "b")
    path = bundle / _RECORD_REL
    doc = json.loads(path.read_bytes())
    doc["record"] = {"asset_id": "SOMETHING-ELSE", "status": "in_service"}
    path.write_bytes((json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    _realign(bundle, _RECORD_REL)

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_a_wholesale_consistent_replacement_PASSES(tmp_path):
    """THE LARGEST SCOPE LIMIT, and the one the other tamper tests quietly
    assume away. Every tamper surface above is an INCONSISTENT edit: the log
    moves and the claimed digest does not. An adversary who can rewrite the log
    and realign the manifest can equally rewrite the claim, and this bundle has
    nothing to say about it — no pinned inputs (the log is the thing that
    legitimately changes), no hash chain, no anchor on the genesis event.

    Replace the log with a one-event history that says the press is in normal
    service, recompute the claim to match, and it verifies CLEAN. What a PASS
    attests is the CONSISTENCY of a producer-authored log with a
    producer-authored digest; it fixes nothing about which record is under
    attestation. The primitive exposes `genesis_record_digest` for exactly that
    anchoring job and nothing in this open shape consumes it."""
    bundle = _build(tmp_path / "b")
    rewritten = [
        {
            "seq": 1,
            "op": "CREATE",
            "at": "2026-01-08T09:15:00Z",
            "actor": "commissioning",
            "fields": {
                "asset_id": "PRESS-14",
                "status": "in_service",
                "location": "bay 3",
            },
        }
    ]
    _rewrite_log(
        bundle,
        [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in rewritten],
    )
    claim = bundle / _CLAIM_REL
    claim.write_bytes(
        (
            json.dumps(
                {"value": replay.record_digest(replay.fold(rewritten))}, indent=2
            )
            + "\n"
        ).encode("utf-8")
    )
    _realign(bundle, _CLAIM_REL)

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]
    # And the record really is a different one, or the test is about nothing.
    honest = json.loads((_PILOT / "bundle" / _CLAIM_REL).read_bytes())["value"]
    assert json.loads(claim.read_bytes())["value"] != honest


# --------------------------------------------------------------------------- #
# The anchor may not come from inside the bundle
# --------------------------------------------------------------------------- #


def test_anchor_taken_from_inside_the_bundle_is_refused(tmp_path):
    bundle = _build(tmp_path / "b")
    with pytest.raises(Exception) as exc:
        SpecAnchor.from_files([bundle / "spec" / _SPEC_SRC.name], forbid_within=bundle)
    assert "INSIDE" in str(exc.value).upper() or "within" in str(exc.value).lower()


def test_bundle_dir_at_the_pilot_root_is_COULD_NOT_CONCLUDE_not_a_reject():
    """The tri-state matters. An unusable anchor is an OPERATOR error — no
    verdict about the artifact was formed — so `spec_binding.AnchorConstructionError`
    must route to could-not-conclude (exit 2), NEVER to a REJECT (exit 1). Letting
    it escape `main()` as a traceback also exits 1, which is the same wrong
    answer wearing a stack trace."""
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(_PILOT)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "COULD NOT CONCLUDE" in proc.stdout
    assert "Traceback" not in proc.stderr


def _cli(bundle_dir: Path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle_dir),
            "--spec-anchor",
            str(_SPEC_SRC),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_the_shipped_CLI_verifies_this_bundle(tmp_path):
    """The README documents `python -m veriker.cli.verify --spec-anchor ...` as the way
    an auditor reaches this pilot with no pilot code at all. Walk it, rather
    than assert it."""
    proc = _cli(_build(tmp_path / "b"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_shipped_CLI_rejects_the_mutant(tmp_path):
    """And the same path exits non-zero on the mutant, so the line above is a
    verification and not a smoke test."""
    bundle = _build(tmp_path / "b")
    path = bundle / _CLAIM_REL
    doc = json.loads(path.read_bytes())
    doc["value"] = "0" * 64
    path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign(bundle, _CLAIM_REL)
    proc = _cli(bundle)
    assert proc.returncode == 1, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# Nothing re-derived must not read as PASS
# --------------------------------------------------------------------------- #


def test_deleting_manifest_outputs_no_longer_makes_the_dispatch_inert(tmp_path):
    """THE FAIL-OPEN THIS PILOT USED TO SHIP, now closed in the substrate.

    `manifest.outputs` is a producer-authored declaration of what to check.
    Deleting it -- three lines -- USED TO make spec-pinned dispatch inert:
    every pinned byte still matched, every plugin still passed, and a
    `BundleVerifier` returned ok=True having re-derived nothing at all. The
    adversary who can realign the manifest for any other tamper in this file
    could do this one instead, and it was strictly easier.

    Two stacked early returns on `not outputs` -- one in
    `BundleVerifier._step_spec_pinned_dispatch`, one in
    `run_spec_pinned_dispatch` -- skipped the SS4a.4 coverage invariant, the
    guard written to catch exactly this. Partial omission (drop one entry of
    several) engaged dispatch and fired COVERAGE_MISMATCH; total omission
    returned OK. Both returns are now file-presence-triggered, so a bundle
    that ships outputs/*.json while declaring none is refused, and a bundle
    with no outputs/ tree at all stays inert as before.

    This assertion is INVERTED from the one this test shipped with. It is not
    a relaxed expectation: the pilot-level mitigation below is now defence in
    depth behind a substrate fix, rather than the only thing standing between
    a forged claim and a clean PASS.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    assert manifest.pop("outputs", None), "fixture declares no outputs to delete"
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    result = _verify(bundle)
    assert not result.ok, "deleting manifest.outputs must no longer read as clean"
    assert "COVERAGE_MISMATCH" in {r.code for r in result.reasons}, [
        (r.check_name, r.code) for r in result.reasons
    ]


def test_the_shipped_entry_point_REFUSES_the_inert_bundle(tmp_path):
    """And the closure, now STRONGER than when this test was written.

    `verify.py` builds its verifier with `require_rederivation=True`, which
    used to be the only thing refusing this bundle -- and it refused as
    COULD NOT CONCLUDE at exit 2, on the reasoning that nothing had been shown
    wrong with the artifact and the verifier had merely been prevented from
    concluding.

    That reasoning no longer holds, so neither does the exit code. The
    coverage invariant now shows something IS wrong with the artifact: it
    ships an output file its own manifest does not declare. That is an
    artifact-side finding, so it is a REJECT at exit 1 naming
    COVERAGE_MISMATCH, not a could-not-conclude.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest.pop("outputs", None)
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    assert "COVERAGE_MISMATCH" in proc.stdout, proc.stdout


def test_require_rederivation_still_owns_the_no_outputs_tree_case(tmp_path):
    """The case the coverage invariant CANNOT see, and the flag still does.

    SS4a.4 coverage triggers on files present at `outputs/*.json`. A producer
    who removes the declaration AND the tree leaves coverage nothing to count
    -- and the same is true of the cheaper restages coverage misses (rename
    `outputs/` to `results/`, nest a subdir, change the extension). Here
    nothing is re-derived and nothing is provably wrong with the artifact, so
    this is a COULD NOT CONCLUDE at exit 2, and `require_rederivation=True` is
    the only reason it is not a clean PASS.

    This replaces the exit-2 assertion that the coverage hoist moved to exit 1
    in the test above: without it, no test in this battery would pin the
    entry point's NO_RE_DERIVATION_PERFORMED -> exit 2 mapping any more.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest.pop("outputs", None)
    if isinstance(manifest.get("files"), dict):
        for rel in [k for k in manifest["files"] if k.startswith("outputs/")]:
            manifest["files"].pop(rel)
    shutil.rmtree(bundle / "outputs", ignore_errors=True)
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "COULD NOT CONCLUDE" in proc.stdout
    assert "VERIFIER_INCOMPLETE" in proc.stdout
