"""audit_bundle/rederivation/reason_codes.py — the canonical re-derivation vocabulary.

Four events are universal to every Axis-2 re-derivation, whatever the domain:
the recompute matched, it did not match, it ran out of time, or it compared
nothing. A domain prefix on any of these says nothing that the check name
already on the verdict face does not say. The fleet had minted 156 spellings of
those four events (the first count said 139 and was wrong; see the collapse
scoping record for the corrected census), in six different suffix spellings:
`_REDERIVATION_MISMATCH` beside `_REDERIVE_VIOLATION`, `_REDERIVATION_TIMEOUT`
beside `_REDERIVE_TIMEOUT`.

What a reason code is. It is a label on a verdict, not the verdict itself. The
verdict is `PluginResult.ok` (and `.incomplete`).

  Corrected 2026-08-30: this header used to claim that exactly one site
  branches on a reason-code value, and that the site is a docstring. That
  claim was false, and it was the stated basis for calling the collapse
  control-flow-safe. Two shipped sites really do branch on a value:
  `veriker/cli/verify.py` reads `if r.code == VERIFIER_INCOMPLETE:` to decide
  NOT_EVALUATED versus FAIL, and `audit_bundle/contract_slots.py` branches on
  `"TOMBSTONED_FIELD_PRESENT"`. Neither names a re-derivation code, so the
  collapse is still control-flow safe. But it is safe because the codes it
  moved are unbranched, not because no code anywhere is branched on. The
  weaker, true claim is the one to keep.

  A green suite is not evidence this was done right, and for a sharper reason
  than "no control flow changed": until 2026-08-30, `_step_typed_check_plugins`
  overwrote a failing plugin's reason_code with the literal string
  "plugin_failed" and propagated only `detail`. That meant the pilot tamper
  batteries, which build `combined = reason_code + " " + detail` and
  substring-match it, were actually matching detail prose against a constant.
  The boundary now propagates the plugin's own code (the crash and
  declared-but-unwired arms still stay generic), so those batteries do bind
  the code. Several of them needed correcting in the same commit, and one was
  found to have been passing with its plugin deleted. See
  `tests/test_reason_code_emission_ratchet.py`, which pins all three arms.

Where the domain survives, measured rather than asserted: `verifier.py` puts
the plugin id on the face as `check_name=f"typed_check_plugins:{plugin_id}"`;
that is the load-bearing half, and a probe confirmed it reaches the verdict.
The `detail` string carries whatever domain prose the pilot writes into it,
which varies by pilot and is not guaranteed by anything here. What this module
deletes is a second, unregistered, per-pilot vocabulary that no code consumed
and no document listed.

Retention is the default. A code is collapsed only if it is a domain prefix in
front of a family suffix. A code naming a domain condition the four universal
events cannot express (`FEA_TOOLCHAIN_MISMATCH`, `PE_STAMP_INVALID`,
`STREAMING_LATE_EVENT_POLICY_VIOLATED`) is retained, and `classify` returns
None for it. When in doubt the answer is retain: a wrongly-retained code is
clutter, a wrongly-collapsed one erases a distinction.

Stdlib only. Not imported by the core verify path (corrected 2026-08-30): the
importers are `release/reason_code_census.py` and three tests, and production
code imports nothing from here. The vocabulary is a convention this module
defines and `tests/test_reason_code_emission_ratchet.py` enforces. It is not
consulted at verify time, and saying otherwise implies a binding that does not
exist.
"""

from __future__ import annotations

#: The recompute ran and agreed with the producer's claim.
RE_DERIVED = "RE_DERIVED"
#: The recompute ran and DISAGREED. A REJECT.
RE_DERIVATION_MISMATCH = "RE_DERIVATION_MISMATCH"
#: The recompute did not finish in the budget. Could-not-conclude, never a pass.
RE_DERIVATION_TIMEOUT = "RE_DERIVATION_TIMEOUT"
#: The pack exited cleanly having compared NOTHING -- the vacuity leg. Carries
#: `incomplete=True`: neither a REJECT (nothing was shown bad) nor an OK
#: (nothing was shown good). A zero-comparison run that reports PASS is the
#: single most repeated substrate defect in this repo; it gets its own code.
RE_DERIVATION_NOT_COMPARED = "RE_DERIVATION_NOT_COMPARED"

#: The canonical four. Frozen: adding a fifth is a vocabulary change that needs
#: its own justification, not a convenience.
CANONICAL: frozenset[str] = frozenset(
    {
        RE_DERIVED,
        RE_DERIVATION_MISMATCH,
        RE_DERIVATION_TIMEOUT,
        RE_DERIVATION_NOT_COMPARED,
    }
)

#: Suffix spellings observed in the fleet, mapped to what they mean. DERIVED by
#: clustering the census on trailing token-suffixes, not hand-listed: the
#: hand-listed first pass had three entries and missed `_REDERIVE_VIOLATION`,
#: `_REDERIVE_TIMEOUT` and every `_NOT_COMPARED`. Ordered longest-first so
#: `RE_DERIVATION_MISMATCH` is matched before `REDERIVED` can match inside it.
_FAMILY_SUFFIXES: tuple[tuple[str, str], ...] = tuple(
    sorted(
        (
            ("REDERIVED", RE_DERIVED),
            ("RE_DERIVED", RE_DERIVED),
            ("REDERIVATION_MISMATCH", RE_DERIVATION_MISMATCH),
            ("RE_DERIVATION_MISMATCH", RE_DERIVATION_MISMATCH),
            ("REDERIVE_VIOLATION", RE_DERIVATION_MISMATCH),
            ("REDERIVATION_VIOLATION", RE_DERIVATION_MISMATCH),
            ("REDERIVATION_TIMEOUT", RE_DERIVATION_TIMEOUT),
            ("RE_DERIVATION_TIMEOUT", RE_DERIVATION_TIMEOUT),
            ("REDERIVE_TIMEOUT", RE_DERIVATION_TIMEOUT),
            ("NOT_COMPARED", RE_DERIVATION_NOT_COMPARED),
        ),
        key=lambda kv: -len(kv[0]),
    )
)


#: A token that inverts the family suffix behind it. `ATTESTED_NOT_REDERIVED`
#: means "attested but NOT re-derived", the opposite of RE_DERIVED, and an
#: earlier version of this function collapsed it onto RE_DERIVED anyway,
#: turning a refusal into a pass. That is the worst error this module can
#: make: not a lost distinction but an inverted one. It was found by an AST
#: sweep over every string constant, the same sweep that caught the regex
#: census missing 19 codes.
#:
#: The guard scans the whole prefix (corrected 2026-08-30). The first fix
#: looked only at `toks[i - 1]`, the token touching the suffix, because all
#: four cases that motivated it happened to be adjacent (`X_NOT_REDERIVED`).
#: A negation does not have to touch what it negates: `NOT_YET_REDERIVED` and
#: `CANNOT_BE_REDERIVED` put one word in between, `CLAIM_NEVER_ACTUALLY_REDERIVED`
#: puts two, and all three collapsed onto RE_DERIVED, reading as "checked and
#: passed" for codes that say the check has not happened. A fix tested only
#: against its motivating shape is untested.
#:
#: `NOT_COMPARED` is not affected: there the word NOT is part of the family
#: name itself, so it lies inside the matched suffix and never in the prefix
#: the guard scans.
#:
#: Vocabulary widened 2026-08-30, second correction, from a fresh-context
#: adversarial pass. The first fix widened the guard's reach to the whole
#: prefix but left its vocabulary at nine hand-picked words, so the same
#: inversion walked straight back in through any other negating word:
#: `UNVERIFIED_REDERIVED`, `STALE_REDERIVED`, `PENDING_REDERIVED`,
#: `FAILED_REDERIVED`, `INCOMPLETE_REDERIVED` all returned RE_DERIVED, which
#: reads "the recompute ran and agreed". That is not idle wordplay: this
#: repo's reason codes already speak this idiom, e.g.
#: `EVIDENCE_CLASS_UNVERIFIED`, `EDGE_TIMESTAMP_UNVERIFIED`,
#: `SPEC_ANCHOR_PROVENANCE_UNVERIFIED`, `DSSE_REVOCATION_LIST_STALE`,
#: `COSIGN_EVIDENCE_INCOMPLETE`, `FEA_LINEAGE_INCOMPLETE`. Fixing the distance
#: axis of a class and leaving the vocabulary axis is the same "tested only
#: against its motivating case" error, one level up.
#:
#: This list is open, not closed. It cannot be complete: English has more ways
#: to negate than anyone will enumerate. So `_is_negating` also treats any
#: token beginning `UN`/`NON` as negating whatever follows it, and the whole
#: design is biased toward retention. Over-retention costs clutter; a missed
#: negation inverts a verdict label. Add to this list freely.
_NEGATIONS = frozenset(
    {
        # explicit negation
        "NOT",
        "NEVER",
        "NO",
        "NON",
        "UN",
        "CANNOT",
        "CANT",
        "WITHOUT",
        "LACKS",
        "LACKING",
        # absence
        "MISSING",
        "ABSENT",
        "OMITTED",
        "EXCLUDED",
        "DROPPED",
        "VOID",
        # never ran / not yet
        "SKIPPED",
        "BYPASSED",
        "DISABLED",
        "DEFERRED",
        "PENDING",
        "QUEUED",
        "AWAITING",
        "UNATTEMPTED",
        "INERT",
        # ran but could not conclude
        "FAILED",
        "FAILING",
        "ERRORED",
        "ABORTED",
        "INCOMPLETE",
        "PARTIAL",
        "INCONCLUSIVE",
        # not trustworthy / out of date
        "UNVERIFIED",
        "UNVALIDATED",
        "UNCHECKED",
        "UNCONFIRMED",
        "UNAVAILABLE",
        "UNREACHABLE",
        "UNKNOWN",
        "STALE",
        "EXPIRED",
        "SUPERSEDED",
        "REVOKED",
    }
)

#: Structural negation: a token glued to `UN`/`NON` negates what it is glued
#: to, whatever the word is, so the guard does not depend on the list above
#: being complete. The length floor keeps `UN` and `NON` themselves (already
#: listed) from double-counting, and keeps short `UN`-words reading as
#: domains: `UNIT` is `UN` plus two characters, so `UNIT_REDERIVED` still
#: collapses, which is right, since `UNIT` names a domain and does not negate
#: anything. The floor is a crude heuristic and misfires both ways on rare
#: words (`UNION` reads as negating). That is tolerable only because the
#: misfire direction is retention: clutter, never an inverted verdict.
_NEGATING_TOKEN_PREFIXES = ("UN", "NON")


def _is_negating(token: str) -> bool:
    """Does this prefix token invert the family suffix behind it?"""
    if token in _NEGATIONS:
        return True
    return any(
        token.startswith(p) and len(token) > len(p) + 2
        for p in _NEGATING_TOKEN_PREFIXES
    )


#: Bare family words that are unambiguously a re-derivation event. NOT_COMPARED
#: is excluded on purpose; see the note inside `classify`.
_BARE_ALIASES: dict[str, str] = {
    "REDERIVED": RE_DERIVED,
    "REDERIVATION_MISMATCH": RE_DERIVATION_MISMATCH,
    "REDERIVE_VIOLATION": RE_DERIVATION_MISMATCH,
    "REDERIVATION_TIMEOUT": RE_DERIVATION_TIMEOUT,
    "REDERIVE_TIMEOUT": RE_DERIVATION_TIMEOUT,
}


def classify(code: str) -> str | None:
    """The canonical code `code` collapses to, or None to retain it as-is.

    Collapsible means: a non-empty domain prefix, on a token boundary, in
    front of a family suffix, with no negation between them. The token
    boundary matters: matching a bare substring would fold `NOT_COMPARED_YET`
    or a hypothetical `PRE_DERIVED` into the vocabulary. An already-canonical
    code returns None. It is not "collapsed"; it is already right.

    When in doubt this returns None. A wrongly-retained code is clutter; a
    wrongly-collapsed one erases a distinction, and a wrongly-collapsed
    negation reverses a verdict.
    """
    if code in CANONICAL:
        return None
    # A bare family word with no domain prefix is still a second spelling of a
    # canonical event, and core had one: `rederivation/dispatch.py` emitted
    # `REDERIVATION_MISMATCH` while `plugins/re_derivation_invocation.py`
    # emitted `RE_DERIVATION_MISMATCH`. Collapsing only domain-prefixed codes
    # would have left those two side by side in the distribution, the exact
    # drift this module removes, surviving in the one place people read first.
    #
    # `NOT_COMPARED` is deliberately excluded from this bare set: outside a
    # re-derivation context it is an ordinary English phrase, and mapping it
    # onto RE_DERIVATION_NOT_COMPARED would claim a re-derivation happened.
    if code in _BARE_ALIASES:
        return _BARE_ALIASES[code]
    toks = code.split("_")
    for i in range(1, len(toks)):  # i >= 1 ⇒ a real domain prefix
        tail = "_".join(toks[i:])
        for suffix, canon in _FAMILY_SUFFIXES:
            if tail == suffix:
                # Any negation anywhere in the prefix inverts the family, not
                # just one touching the suffix. Scanning the whole prefix errs
                # toward retention: a domain that innocently contains one of
                # these words keeps its code, which is the module's stated
                # safe direction.
                if any(_is_negating(t) for t in toks[:i]):
                    return None  # inverted meaning: retain
                return canon
    return None


# `detail_for(domain, message)` -> "[DOMAIN] message" lived here and was
# deleted 2026-08-30. It had zero production callers, its only test was a
# self-test, and the module header pointed at it as the place the domain now
# survives, which made an unadopted three-line helper look like the mechanism
# carrying the collapse's central promise. The domain survives via
# `check_name` on the face (measured), not via a helper nobody called. Anyone
# who wants the bracket convention back should adopt it across the fleet in
# the same commit that reintroduces it.
