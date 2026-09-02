"""One accounting engine for every ``present − verified`` coverage channel.

`verifier.py` carries nine ``_step_*_guard`` methods. Seven of them hand-write
the identical idiom: build the set of things the artifact presents, build the
set a wired check reported verifying, and fail closed on the remainder. That
idiom covers cross-host authenticators, re-derivation packs, the re-derivation
surface, `causal_chain` sub-keys, layer-A event obligations, fragment anchors,
dispatch records, claimset elements, and the assurance profile. Their
docstrings cross-reference each other, so the repetition was recognised; it
was never lifted. Each of the seven was written in response to a specific
found defect.

The channel nobody wrote the tenth copy for is anchored spec types, and that
omission was exploitable in one string edit: remap an output's `type` onto a
sibling type in the same anchored spec and the rule that would have judged it
runs zero times, while the rule that does run passes. Measured on
`corner_load_equilibrium_minimal` 2026-08-31: a bundle whose vertical
equilibrium residual is 60.5 N against an auditor ε of 40 N verified at exit 0.

This module is the missing generalisation. A channel declares its two sets;
`account_channels` does the subtraction once and routes any remainder to a
could-not-conclude naming the uncovered members. Adding the eleventh channel is
then a registration, not a tenth transcription of an idiom already transcribed
nine times. That is the maintenance property the ADR (§E6) asks for, and the
reason this lands before the leaf edits it subsumes.

What an accounting channel is not
----------------------------------
It is bookkeeping over a comparison, never the comparison itself. `present −
verified == ∅` establishes that every element the authority named was reached
by some check. It says nothing about whether that check was the right one for
the element, and nothing about what the check concluded. A channel whose
`verified` set is fed by a producer-controlled declaration launders exactly as
hard as the guard it replaced. `verified` must be measured from inside the
check that did the work (see `resolved_primitives` and `acceptance_out` in
`rederivation/dispatch.py`, which exist for this reason), and `present` must be
sourced from bytes the producer cannot author.

Stdlib only; no imports from `verifier` (which imports this).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .verdict import VERIFIER_INCOMPLETE, Verdict

__all__ = ["CoverageChannel", "account_channels"]


def _stable(items: Iterable[object]) -> tuple[str, ...]:
    """Deterministic display order for a set of channel members.

    `sorted()` on a set carrying mixed types raises `TypeError` out of a
    fail-closed path (§C9: an error formatter that raises converts a refusal
    into a crash). Members are strings by contract, so this is defense in
    depth for a directly-constructed channel: key on `repr` and render with
    `repr`, so no member's own `__str__` is consulted either.
    """
    return tuple(repr(i) for i in sorted(items, key=repr))


@dataclass(frozen=True, slots=True)
class CoverageChannel:
    """One ``present − verified`` accounting channel.

    Attributes:
      check_name: the name this channel reports under on the verdict face. It
        is what a consumer keys on, so it is part of the contract. Do not
        rename a shipped channel without treating it as one.
      present: everything the authority names for this channel. Must come
        from bytes the producer cannot author (an anchored spec, a
        verifier-held policy), or from the artifact only where the artifact's
        own claim is the thing being held against it (a present-but-unverified
        edge).
      verified: everything a check measured itself covering. Never a
        declaration; never derived from `present`.
      noun: singular noun for the members, used in the prose ("edge",
        "anchored spec type").
      note: the channel-specific sentence explaining what an uncovered member
        means and what the consumer must not read the verdict as covering.
      reason_code: defaults to VERIFIER_INCOMPLETE. A remainder is a
        could-not-conclude about the verifier's own coverage, not an
        accusation against the artifact. A channel that genuinely establishes
        something against the artifact does not belong here; it belongs in
        `failures`.
    """

    check_name: str
    present: frozenset = field(default_factory=frozenset)
    verified: frozenset = field(default_factory=frozenset)
    noun: str = "element"
    note: str = ""
    reason_code: str = VERIFIER_INCOMPLETE

    @property
    def uncovered(self) -> frozenset:
        """Members the authority named that no check reported covering."""
        return frozenset(self.present) - frozenset(self.verified)

    def detail(self) -> str:
        """The could-not-conclude prose. Names the uncovered members, not just
        a count: a consumer who cannot tell which element was skipped cannot
        act on the refusal, and a count alone is what let a remapped type read
        as a coverage rounding error."""
        unc = _stable(self.uncovered)
        n_present = len(frozenset(self.present))
        one = len(unc) == 1
        head = (
            f"{len(unc)} of {n_present} {self.noun}{'' if one else 's'} "
            f"{'was' if one else 'were'} NOT covered by any check that ran: "
            f"[{', '.join(unc)}]."
        )
        tail = f" {self.note}" if self.note else ""
        return head + tail


def account_channels(
    channels: Iterable[CoverageChannel],
    incompletes: list,
) -> None:
    """Append one could-not-conclude Verdict per channel with a remainder.

    A channel whose `present` is empty is inert and appends nothing. That is
    the "no authority was established, so there is nothing to account for"
    case, and it is the only inertness this engine grants. Inertness keyed on
    the producer's own declaration being empty is the shape that made
    `manifest.outputs` deletion fail open; a registrant must key `present` on
    the authority instead, and this engine cannot check that for them.
    """
    for channel in channels:
        if not channel.present or not channel.uncovered:
            continue
        incompletes.append(
            Verdict.incomplete(
                channel.reason_code,
                channel.detail(),
                check_name=channel.check_name,
            )
        )
