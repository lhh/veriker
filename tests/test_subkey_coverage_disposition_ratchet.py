"""Sub-key coverage-disposition ratchet — every open-namespace manifest field
has a LIVE ``present − verified == ∅`` coverage guard on the verdict path
(2026-06-23).

This is ``test_manifest_field_disposition_ratchet`` pushed one level down. That
ratchet closes the orphan class at TOP-LEVEL field granularity: a new
``BundleManifest`` field cannot ship without naming the step that enforces it.
But several of those fields are OPEN-NAMESPACE dicts whose *sub-keys* carry the
claims — ``causal_chain`` (S19 sub-streams + pilot-custom chains),
``dispatch_records``/``aggregate_stamp`` (stamp claims), ``fragment_anchors``.
For those, "a step runs" is NOT the guarantee; the guarantee is the UNIVERSAL
coverage identity ``present_subkeys − verified_subkeys == ∅`` (else
could-not-conclude), so a sub-key nobody verified fails closed instead of
riding green.

That coverage discipline already exists per-namespace and is behaviorally
tested in isolation (test_causal_chain_coverage / test_cross_host_edge_coverage
/ test_layer_a_event_obligation_coverage / test_fragment_anchor_coverage /
test_stamp_claims_coverage_guard). What did NOT exist is the META property —
the ``assurance_profile`` failure mode one level out: nothing enumerated the
coverage namespaces in ONE place and proved each guard is actually wired into
the verdict path, and nothing forced a NEW verdict-path step to declare whether
it is a sub-key coverage guard. A coverage guard silently dropped from
``_verify_in_dir``, or a new open-namespace field shipped with only a
shape-validation step, would not be caught by any single test.

Three assertions close that:

  1. LIVENESS — every guard named in ``_COVERAGE_NAMESPACE_GUARDS`` exists on
     ``BundleVerifier`` AND is invoked in ``_verify_in_dir`` source. A coverage
     guard the verdict path never calls is an orphan, not a guarantee.
  2. KIND TEETH — each named guard's source carries the universal-coverage
     signature (``present`` / ``verified`` / ``uncovered`` / the
     ``VERIFIER_INCOMPLETE`` could-not-conclude leg). A field cannot be
     registered as sub-key-covered by pointing at a shape-only or floor step.
  3. PARTITION CLOSURE — the set of ``_step_*`` methods invoked in
     ``_verify_in_dir`` is EXACTLY the registry's guards ∪ the explicit
     non-coverage exclusion set. A new verdict-path step (or a renamed one)
     fails until it is classified here, in this diff — the same diff-is-the-
     disclosure forcing function the top-level disposition ratchet uses.
"""

from __future__ import annotations

import inspect
import re

from audit_bundle.coverage_channels import CoverageChannel, account_channels
from audit_bundle.verifier import BundleVerifier

# --- the coverage-namespace registry -----------------------------------------
#
# manifest open-namespace (or nested namespace) -> the verdict-path step that
# enforces ``present_subkeys − verified_subkeys == ∅`` over it. These are the
# guards whose absence would let an unguarded sub-key ride a green verdict.
_COVERAGE_NAMESPACE_GUARDS: dict[str, str] = {
    "causal_chain (whole open namespace)": "_step_causal_chain_coverage_guard",
    "causal_chain.cross_host_authenticators (edge-level)": "_step_cross_host_guard",
    "causal_chain.layer_a events (per-event obligations)": "_step_layer_a_event_obligation_guard",
    "fragment_anchors (fragments.attestable)": "_step_fragment_anchor_guard",
    "dispatch_records + aggregate_stamp (stamp claims)": "_step_stamp_claims_guard",
    "claimset (claim-field elements of declared claim_files + opaque_claim_files; file-audit fold)": "_step_claimset_coverage_guard",
    "anchored spec types (the FALLBACK: was every anchored binding-table row reached by something; the auditor WORK-SET in _step_spec_pinned_dispatch is the mechanism that asks by which claim, and refuses a dropped/extra/duplicated one)": "_step_anchored_type_coverage_guard",
}

# Verdict-path ``_step_*`` methods that are NOT sub-key coverage guards. Listed
# explicitly so the partition is CLOSED: a new step forces an entry here or in
# the registry above (diff-is-the-disclosure). One-line rationale each.
_NON_SUBKEY_COVERAGE_STEPS: dict[str, str] = {
    "_step_file_integrity": "per-FILE byte-equality (file space, not a sub-key namespace)",
    "_step_spec_sha_pinning": "spec/ hash pinning (file space)",
    "_step_cross_refs": "cross-ref shape/resolution, not present−verified coverage",
    "_step_typed_check_plugins": "runs + reconciles plugins; not a namespace coverage fold",
    "_step_deep_manifest_validation": "structural shape validation of nested fields",
    "_step_spec_pinned_dispatch": "re-derivation from anchored spec (output space)",
    "_step_rederivation_pack_guard": "present−verified but over re_derive/*_pack FILES, not manifest sub-keys",
    "_step_rederivation_surface_guard": "bare non-emptiness test (no present set, no uncovered fold) disclosing the TOTAL absence of verifier-side re-derivation; NOT a coverage-completeness check — see its KNOWN RESIDUAL. NOTE the coupling: it READS fragment_anchors_verified, the same verified-set _step_fragment_anchor_guard folds, under different semantics — that guard asks 'was every attestable anchor covered?', this one asks only 'was anything re-derived at all?'",
    "_step_extension_receipts": "receipt-verifier dispatch by kind, not a sub-key fold",
    "_step_assurance_profile_guard": "assurance FLOOR (downgrade gate), not sub-key coverage",
}

# Tokens that together mark a ``present − verified == ∅`` universal-coverage
# guard (verified live across all five guards 2026-06-23). A shape-only or floor
# step does not carry this full signature.
_COVERAGE_SIGNATURE = ("present", "verified", "uncovered", "VERIFIER_INCOMPLETE")

# A guard that DELEGATES the fold to the shared accounting engine
# (audit_bundle/coverage_channels.py) cannot carry the whole signature in its own
# body — `uncovered` and the VERIFIER_INCOMPLETE leg now live in the engine.
#
# The FIRST version of this amendment simply appended the engine source for any
# delegating step, and that was a TAUTOLOGY: the engine contains all four tokens
# by construction, so the kind check became an assertion about
# coverage_channels.py rather than about the guard. PROVEN by mutant — replacing
# `_step_anchored_type_coverage_guard`'s entire body with
# `account_channels([], incompletes)` left this file at 6/6 passing.
#
# So the split is explicit: a delegating guard must still DECLARE ITS OWN SETS in
# its own body, and only the tokens it genuinely cannot own are read from the
# engine. A guard that hands the engine nothing fails, which is what the mutant
# should have done and now does (see the control below).
_SELF_TOKENS = ("CoverageChannel(", "present=", "verified=")
_ENGINE_TOKENS = ("uncovered", "VERIFIER_INCOMPLETE")

_ENGINE_SRC = inspect.getsource(account_channels) + inspect.getsource(CoverageChannel)
_DELEGATION_MARK = "account_channels("


def _missing_signature(src: str) -> list[str]:
    """Signature tokens a guard's source fails to account for.

    A non-delegating guard owns the whole signature. A delegating one owns
    `_SELF_TOKENS` itself and may source `_ENGINE_TOKENS` from the engine.
    """
    if _DELEGATION_MARK not in src:
        return [tok for tok in _COVERAGE_SIGNATURE if tok not in src]
    missing = [tok for tok in _SELF_TOKENS if tok not in src]
    missing += [tok for tok in _ENGINE_TOKENS if tok not in src + _ENGINE_SRC]
    return missing


_VERIFY_IN_DIR_SRC = inspect.getsource(BundleVerifier._verify_in_dir)


def _fold_source(symbol: str) -> str:
    """The source in which `symbol`'s present−verified fold actually lives."""
    src = inspect.getsource(getattr(BundleVerifier, symbol))
    return src + _ENGINE_SRC if _DELEGATION_MARK in src else src


def _verdict_path_step_calls() -> set[str]:
    """Every ``self._step_<name>(`` invoked in ``_verify_in_dir`` source."""
    return set(re.findall(r"self\.(_step_[a-z_]+)\(", _VERIFY_IN_DIR_SRC))


def test_coverage_guards_exist_and_are_live_on_the_verdict_path():
    for namespace, symbol in sorted(_COVERAGE_NAMESPACE_GUARDS.items()):
        assert hasattr(BundleVerifier, symbol), (
            f"{namespace}: coverage guard {symbol!r} does not exist on BundleVerifier"
        )
        assert symbol in _VERIFY_IN_DIR_SRC, (
            f"{namespace}: coverage guard {symbol!r} exists but is NOT invoked "
            "in _verify_in_dir — a coverage guard the verdict path never calls "
            "is an orphan, not a guarantee (the assurance_profile failure mode)."
        )


def test_registered_guards_are_universal_coverage_kind():
    """A guard registered as sub-key coverage must actually fold
    present−verified, not merely shape-check the namespace."""
    for namespace, symbol in sorted(_COVERAGE_NAMESPACE_GUARDS.items()):
        missing = _missing_signature(inspect.getsource(getattr(BundleVerifier, symbol)))
        assert not missing, (
            f"{namespace}: {symbol!r} is registered as a sub-key coverage guard "
            f"but its source lacks the universal-coverage signature {missing} — "
            "a coverage namespace cannot be discharged by a shape-only / floor "
            "step (else a forged sub-key rides green, the orphan-key class)."
        )


def test_verdict_path_step_partition_is_closed():
    """Every verdict-path step is classified: a sub-key coverage guard, or an
    explicit non-coverage exclusion. A new/renamed step fails until placed."""
    invoked = _verdict_path_step_calls()
    classified = set(_COVERAGE_NAMESPACE_GUARDS.values()) | set(
        _NON_SUBKEY_COVERAGE_STEPS
    )

    unclassified = invoked - classified
    assert not unclassified, (
        f"verdict-path step(s) not classified: {sorted(unclassified)}. Add each "
        "to _COVERAGE_NAMESPACE_GUARDS (if it folds present−verified over an "
        "open sub-key namespace) or to _NON_SUBKEY_COVERAGE_STEPS with a "
        "one-line rationale — in THIS diff, so the classification is disclosed."
    )

    stale = classified - invoked
    assert not stale, (
        f"classified step(s) no longer invoked in _verify_in_dir: "
        f"{sorted(stale)}. Remove the stale entry — a registry/exclusion that "
        "names a dead step hides whether the verdict path still enforces it."
    )

    overlap = set(_COVERAGE_NAMESPACE_GUARDS.values()) & set(_NON_SUBKEY_COVERAGE_STEPS)
    assert not overlap, (
        f"step(s) both registered as coverage AND excluded: {sorted(overlap)} — "
        "the partition must be disjoint."
    )


def test_non_coverage_exclusions_are_real_methods():
    """No stale exclusion entry: every excluded name is a real BundleVerifier
    step (mirrors the top-level ratchet's stale-entry check)."""
    for symbol in sorted(_NON_SUBKEY_COVERAGE_STEPS):
        assert hasattr(BundleVerifier, symbol), (
            f"_NON_SUBKEY_COVERAGE_STEPS names {symbol!r} which is not a "
            "BundleVerifier method — remove the stale entry."
        )


# The steps that delegate their fold to the shared engine, pinned by name. This
# is the MISS direction: `_missing_signature` must relax for exactly these and
# for nothing else.
_ENGINE_DELEGATING_STEPS = frozenset({"_step_anchored_type_coverage_guard"})


def test_the_delegation_amendment_moves_exactly_the_steps_it_names():
    """Forward: every step named above really delegates. Backward: no other
    verdict-path step silently picks up the relaxation."""
    delegating = {
        symbol
        for symbol in _verdict_path_step_calls()
        if _DELEGATION_MARK in inspect.getsource(getattr(BundleVerifier, symbol))
    }
    assert delegating == _ENGINE_DELEGATING_STEPS, (
        f"the set of engine-delegating steps changed: {sorted(delegating)} != "
        f"{sorted(_ENGINE_DELEGATING_STEPS)}. Update _ENGINE_DELEGATING_STEPS in "
        "THIS diff — the relaxation's blast radius is the thing being disclosed."
    )


def test_a_guard_that_delegates_everything_fails_the_kind_check():
    """THE CONTROL THAT MUST FIRE, and did not in the first version of this
    amendment.

    A guard whose whole body is `account_channels([], incompletes)` hands the
    engine nothing: it declares no sets, so it cannot be folding anything. The
    earlier amendment passed it, because appending the engine source supplied
    every token. Measured on a real mutant: the guard's body was replaced with
    exactly this stub and the whole file stayed at 6/6 green.
    """
    vacuous = (
        "    def _step_pretend_coverage_guard(self, incompletes) -> None:\n"
        '        """VACUOUS MUTANT: shape-only, no fold at all."""\n'
        "        account_channels([], incompletes)\n"
    )
    missing = _missing_signature(vacuous)
    assert missing, (
        "a guard that declares NO sets and delegates everything passed the kind "
        "check — the check is an assertion about coverage_channels.py, not "
        "about the guard (this is the exact tautology the mutant proved)"
    )
    assert "CoverageChannel(" in missing


def test_a_shape_only_step_still_cannot_register_as_coverage():
    """`_step_cross_refs` is shape/resolution only and must fail the kind check
    under the SAME function the registered guards are judged by."""
    missing = _missing_signature(inspect.getsource(BundleVerifier._step_cross_refs))
    assert missing, (
        "_step_cross_refs carries the full coverage signature — the kind check "
        "can no longer tell a shape-only step from a coverage fold."
    )


def test_the_real_delegating_guard_owns_its_sets():
    """The positive half: the shipped delegating guard passes because it builds
    its own CoverageChannel(present=..., verified=...), not because the engine
    was appended to its source."""
    src = inspect.getsource(BundleVerifier._step_anchored_type_coverage_guard)
    assert _DELEGATION_MARK in src
    for tok in _SELF_TOKENS:
        assert tok in src, f"the delegating guard does not own {tok!r}"
    assert not _missing_signature(src)
