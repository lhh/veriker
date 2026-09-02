"""The canonical re-derivation vocabulary and its classifier.

The negation test below is the important one. An earlier `classify` collapsed
`ATTESTED_NOT_REDERIVED` onto `RE_DERIVED` -- a code meaning "attested but NOT
re-derived" folded into the code meaning "re-derived". Not a lost distinction:
an INVERTED one, which turns a refusal into a pass. It was found by an AST
sweep over every string constant in the tree, the same sweep that caught the
first census under-counting by 19 codes.
"""

from __future__ import annotations

import pytest

from audit_bundle.rederivation.reason_codes import (
    CANONICAL,
    RE_DERIVATION_MISMATCH,
    RE_DERIVATION_NOT_COMPARED,
    RE_DERIVATION_TIMEOUT,
    RE_DERIVED,
    classify,
)


@pytest.mark.parametrize(
    "code,expected",
    [
        ("BOM_REDERIVED", RE_DERIVED),
        ("KG_REDERIVED", RE_DERIVED),
        ("THREE_SET_RE_DERIVED", RE_DERIVED),
        ("FEA_REDERIVATION_MISMATCH", RE_DERIVATION_MISMATCH),
        ("AIGOV_REDERIVE_VIOLATION", RE_DERIVATION_MISMATCH),
        ("AIF360_REDERIVATION_TIMEOUT", RE_DERIVATION_TIMEOUT),
        ("CONTROL_REDERIVE_TIMEOUT", RE_DERIVATION_TIMEOUT),
        ("WORKPAPER_NOT_COMPARED", RE_DERIVATION_NOT_COMPARED),
    ],
)
def test_domain_prefixed_spellings_collapse(code, expected):
    assert classify(code) == expected


@pytest.mark.parametrize("code", sorted(CANONICAL))
def test_canonical_codes_are_not_themselves_collapsed(code):
    """A canonical code is already right; returning a target for it would make
    the migration non-idempotent and the ratchet refuse correct kits."""
    assert classify(code) is None


@pytest.mark.parametrize(
    "code",
    [
        "ATTESTED_NOT_REDERIVED",
        "PAD_BAND_EDGES_NOT_REDERIVED",
        "CLAIM_NEVER_REDERIVED",
        "SPAN_MISSING_REDERIVATION_TIMEOUT",
    ],
)
def test_negation_ADJACENT_to_the_family_suffix_is_RETAINED(code):
    """INVERSION GUARD, distance 1. `X_NOT_REDERIVED` is the OPPOSITE of
    RE_DERIVED. Collapsing it would silently convert a refusal into a pass --
    the worst error this module can make."""
    assert classify(code) is None, f"{code} inverts its family; it must be retained"


#: The four cases above ALL sit adjacent to the suffix, and the guard that
#: passed them inspected exactly one token -- `toks[i - 1]`. A fix tested only
#: against its motivating shape is untested, so the guard is exercised at every
#: distance a negation can actually appear at. Each of these returned a
#: CANONICAL code before the distance fix; `NOT_YET_REDERIVED` returned
#: RE_DERIVED, which reads "checked and passed" for a code that says the check
#: has not happened yet.
@pytest.mark.parametrize(
    "code,distance",
    [
        # distance 2 -- one word between the negation and the family
        ("NOT_YET_REDERIVED", 2),
        ("CANNOT_BE_REDERIVED", 2),
        ("NO_LONGER_REDERIVED", 2),
        ("NEVER_SUCCESSFULLY_REDERIVATION_MISMATCH", 2),
        ("MISSING_PACK_REDERIVATION_TIMEOUT", 2),
        # distance 3
        ("CLAIM_NEVER_ACTUALLY_REDERIVED", 2),
        ("NOT_IN_THIS_REDERIVED", 3),
        ("ABSENT_FROM_THE_REDERIVATION_MISMATCH", 3),
        # distance 4, with a domain prefix in front of the negation
        ("BOM_NOT_EVER_ACTUALLY_YET_REDERIVED", 4),
    ],
)
def test_negation_at_ANY_distance_before_the_suffix_is_RETAINED(code, distance):
    """INVERSION GUARD, the CLASS. The negating word does not have to be the
    token immediately in front of the family suffix -- `NOT_YET_REDERIVED` puts
    one word between them and `CLAIM_NEVER_ACTUALLY_REDERIVED` puts two. Any
    negation ANYWHERE before the matched suffix inverts the family's meaning,
    so the whole prefix is scanned, not its last token.

    The error direction here is deliberate and matches the module's stated
    doctrine: a domain prefix that innocently contains one of these words is
    RETAINED rather than collapsed. A wrongly-retained code is clutter; a
    wrongly-collapsed negation reverses a verdict.
    """
    assert distance >= 2, "this case belongs in the adjacent-negation test"
    assert classify(code) is None, (
        f"{code} inverts its family at token distance {distance}; it must be "
        f"retained, and collapsing it asserts the opposite of what it says"
    )


#: SECOND CORRECTION, from the fresh-context adversarial pass. The distance fix
#: above widened the guard's REACH and left its VOCABULARY at nine hand-picked
#: words, so every OTHER negating word walked the same inversion straight back
#: in. Each of these returned a CANONICAL code -- most of them RE_DERIVED,
#: which reads "the recompute ran and agreed" -- for a label that says it did
#: not.
#:
#: These are not invented shapes. The repo's live reason codes already speak
#: this exact idiom: EVIDENCE_CLASS_UNVERIFIED, EDGE_TIMESTAMP_UNVERIFIED,
#: SPEC_ANCHOR_PROVENANCE_UNVERIFIED, DSSE_REVOCATION_LIST_STALE,
#: COSIGN_EVIDENCE_INCOMPLETE, FEA_LINEAGE_INCOMPLETE. Any of those authors
#: gluing a family suffix onto their existing habit reproduces the bug.
@pytest.mark.parametrize(
    "code",
    [
        # not trustworthy / out of date
        "UNVERIFIED_REDERIVED",
        "UNVALIDATED_REDERIVED",
        "UNCHECKED_REDERIVED",
        "STALE_REDERIVED",
        "EXPIRED_REDERIVED",
        "REVOKED_REDERIVED",
        "SUPERSEDED_REDERIVED",
        # never ran / not yet
        "PENDING_REDERIVED",
        "DEFERRED_REDERIVED",
        "QUEUED_REDERIVED",
        "BYPASSED_REDERIVED",
        "DISABLED_REDERIVED",
        "AWAITING_REDERIVED",
        # ran but could not conclude
        "FAILED_REDERIVED",
        "ERRORED_REDERIVED",
        "ABORTED_REDERIVED",
        "INCOMPLETE_REDERIVED",
        "PARTIAL_REDERIVED",
        "INCONCLUSIVE_REDERIVED",
        # absence
        "OMITTED_REDERIVED",
        "EXCLUDED_REDERIVED",
        "DROPPED_REDERIVED",
        "WITHOUT_REDERIVED",
        "LACKS_REDERIVED",
        # structural UN-/NON-, which must hold WITHOUT the word being listed
        "UNAVAILABLE_REDERIVED",
        "UNREACHABLE_REDERIVED",
        "UNSUBSTANTIATED_REDERIVED",
        "UNCORROBORATED_REDERIVED",
        "NONDETERMINISTIC_REDERIVED",
        # with a real domain prefix in front, and on the other families
        "PE_STAMP_UNVERIFIED_REDERIVED",
        "AUDIT_STALE_REDERIVATION_TIMEOUT",
        "FEA_TOOLCHAIN_FAILED_REDERIVATION_MISMATCH",
    ],
)
def test_negation_VOCABULARY_beyond_the_first_nine_words_is_RETAINED(code):
    """INVERSION GUARD, the vocabulary axis.

    A closed hand-picked denylist cannot be complete, so `_is_negating` also
    treats any `UN`/`NON`-prefixed token as negating structurally. The last
    five cases exist to prove that half works without the word being listed.
    """
    assert classify(code) is None, (
        f"{code} says the re-derivation did NOT happen (or cannot be trusted) "
        f"and classify collapses it onto {classify(code)!r}"
    )


#: The cost of scanning the whole prefix with an open negation vocabulary,
#: stated rather than discovered later: a DOMAIN whose name innocently contains
#: a negating word is now RETAINED where it would once have collapsed. This is
#: under-collapse -- clutter -- and it is the direction the module chooses on
#: purpose. Measured 2026-08-30: zero live codes in the tree are affected.
@pytest.mark.parametrize(
    "code",
    [
        "MISSING_DATA_HANDLER_REDERIVED",
        "NON_PII_REDERIVED",
        "ABSENT_VALUE_AUDIT_REDERIVATION_MISMATCH",
        "SKIPPED_ROW_HANDLER_REDERIVED",
    ],
)
def test_ACCEPTED_COST_a_domain_containing_a_negating_word_is_retained(code):
    """DECLARED LIMIT, not a bug. `MISSING_DATA_HANDLER_REDERIVED` plausibly
    names a missing-data handler that DID re-derive, and it is retained anyway.

    The trade is deliberate and asymmetric: a wrongly-retained code is clutter
    a human notices, and a wrongly-collapsed negation silently turns a refusal
    into a pass. If this ever costs something real, the fix is a committed list
    of domain prefixes -- not a narrower negation list.
    """
    assert classify(code) is None


@pytest.mark.parametrize(
    "code,expected",
    [("UNIT_REDERIVED", RE_DERIVED), ("UNI_REDERIVED", RE_DERIVED)],
)
def test_a_SHORT_un_word_is_a_domain_not_a_negation(code, expected):
    """The structural UN-/NON- rule has a length floor, and this is what it
    buys. `UNIT` is a domain, not a negation of `IT`, so `UNIT_REDERIVED`
    still collapses. The floor is a crude heuristic and will misfire in both
    directions on rare words (`UNION` reads as negating); retention bias makes
    those misfires clutter rather than inverted verdicts, which is why a crude
    rule is tolerable here at all."""
    assert classify(code) == expected


#: The collapse rewrote 684 BARE-family sites -- `REDERIVATION_MISMATCH` with no
#: domain prefix at all, which core itself emitted from
#: `rederivation/dispatch.py` while `plugins/re_derivation_invocation.py`
#: emitted `RE_DERIVATION_MISMATCH` beside it. Until this test there was no
#: assertion anywhere that `classify` maps the bare spellings, so the larger
#: half of the migration had zero coverage.
@pytest.mark.parametrize(
    "code,expected",
    [
        ("REDERIVED", RE_DERIVED),
        ("REDERIVATION_MISMATCH", RE_DERIVATION_MISMATCH),
        ("REDERIVE_VIOLATION", RE_DERIVATION_MISMATCH),
        ("REDERIVATION_TIMEOUT", RE_DERIVATION_TIMEOUT),
        ("REDERIVE_TIMEOUT", RE_DERIVATION_TIMEOUT),
    ],
)
def test_bare_family_spellings_collapse(code, expected):
    assert classify(code) == expected


@pytest.mark.parametrize(
    "code",
    [
        "FEA_TOOLCHAIN_MISMATCH",
        "PE_STAMP_INVALID",
        "NO_PACK",
        "NO_PAYLOAD",
        "STREAMING_LATE_EVENT_POLICY_VIOLATED",
        "ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID",
        "BAD_FILE_SHA",
    ],
)
def test_genuinely_domain_specific_codes_are_retained(code):
    """When in doubt, RETAIN. A wrongly-retained code is clutter; a
    wrongly-collapsed one erases a distinction."""
    assert classify(code) is None


def test_bare_family_word_with_no_domain_prefix_is_retained():
    """`NOT_COMPARED` alone has no domain prefix -- there is nothing to strip,
    so there is nothing to collapse."""
    assert classify("NOT_COMPARED") is None


def test_classify_is_idempotent():
    """Collapsing twice must equal collapsing once, or a re-run of the
    migration would keep rewriting."""
    for code in (
        "BOM_REDERIVED",
        "FEA_REDERIVATION_MISMATCH",
        "WORKPAPER_NOT_COMPARED",
    ):
        first = classify(code)
        assert first is not None
        assert classify(first) is None


#: MEASURED 2026-08-30, not assumed. Four families were nominated for addition
#: to `_FAMILY_SUFFIXES`. Reading their emitters rejected all four, and the
#: reasons differ enough that each gets its own row. This test is what stops the
#: nomination being made again from the names alone.
@pytest.mark.parametrize(
    "code,why",
    [
        (
            "GAIA_REDERIVATION_MISMATCH_ANSWER",
            "the name says mismatch, the emitter does not. Across "
            "examples/amd_gaia_minimal/gaia_re_derivation.py (16 sites) and "
            "examples/rag_audit_minimal/rag_re_derivation.py (13 sites) this "
            "code is raised at 29 sites, and only SIX are a disagreement -- "
            "readings_ordered / sensor_ids / consensus / answer (x2) / "
            "jurisdiction. The other 23 are 'absent from bundle_dir', 'failed "
            "to read' (x12), 'is empty', schema-shape refusals, 'missing "
            "expected node_ids', and three '<stage> re-derivation error' "
            "sites. CORRECTED 2026-08-30: this said 10 and 19, which counted "
            "the schema-shape refusals and the escaping exceptions as "
            "disagreements -- contradicting the rule stated two rows below, "
            "that an exception escaping a recompute is not a disagreement. "
            "The true split is 6/23 and it makes the case stronger, not "
            "weaker. Mapping this onto RE_DERIVATION_MISMATCH would assert "
            "'the recompute ran and DISAGREED' at 23 sites where the recompute "
            "never ran -- the negation inversion again, in the direction that "
            "manufactures a substantive REJECT out of a could-not-run.",
        ),
        (
            "REDERIVATION_ERROR",
            "an exception escaped the recompute and the emitter failed closed. "
            "That is none of the four universal events: not a disagreement, not "
            "a timeout, and not RE_DERIVATION_NOT_COMPARED either -- that one "
            "names a pack that exited CLEANLY having compared nothing, and this "
            "one did not exit cleanly.",
        ),
        (
            "VECTOR_REDERIVE_ERROR",
            "same event as REDERIVATION_ERROR, in the conformance vectors "
            "(examples/payroll_agent_gate_minimal/conformance/spec_conformance.py "
            "and the other pilots' conformance vectors). Retained for the same reason.",
        ),
        (
            "CONTROL_REDERIVE_FAIL",
            "not a reason code at all. It is the stderr CHANNEL MARKER of a "
            "documented CLI protocol -- '[CONTROL_REDERIVE_FAIL] <reason>: "
            "<detail>' -- and the reason code is the token that follows it. "
            "Collapsing the marker would rewrite a published output contract "
            "while leaving the actual code untouched.",
        ),
    ],
)
def test_families_deliberately_NOT_added_to_the_vocabulary(code, why):
    """Nominated, read, and RETAINED. `why` is the finding, kept beside the
    assertion so the next reader does not have to re-derive it from the name."""
    assert classify(code) is None, why
