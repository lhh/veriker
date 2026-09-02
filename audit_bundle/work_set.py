"""audit_bundle/work_set.py — the auditor's WORK-SET: the complete set of
outputs a bundle must deliver, each pinned to the anchored rule that judges it.

THE INVARIANT, stated once. Under spec-pinned dispatch the producer's
remaining freedom is WHICH of the auditor's rules judges WHICH claim, and
it has had four expressions, each closed on its own as it was found:

  1. retype output A onto sibling type B, so A's rule runs zero times;
  2. retype A AND declare a decoy that exercises A's type honestly;
  3. drop A entirely and substitute a decoy under another `output_id`;
  4. drop one `manifest.spec_files` key, so the coverage DENOMINATOR shrinks.

And a fifth was still open: the per-output type pin (`role_policy`) was
allow-by-default, so an `output_id` the auditor never named was
unconstrained. MEASURED 2026-09-01 on `corner_load_equilibrium_minimal`: an
extra output under a valid anchored type verified exit 0 while the face
said "role policy APPLIED over 3 output_id(s)", having judged four. A
duplicated manifest entry for one `output_id` did the same.

They are one invariant: **the auditor names the complete set of work, and
the bundle delivers exactly that**, and this repository already vendors the
helper that states it. `_total_binding.assert_exact_keys`' docstring:
"Missing AND unexpected keys both fail (a dropped slot and a smuggled slot
are equally findings)". Missing is escape 3; unexpected is the open hole.
`manifest.outputs` is a LIST, so the exact-keys form is the wrong one:
dict-ifying it silently collapses duplicate `output_id`s, the projection
that docstring warns against. `assert_bijection_projected` is
multiset-aware ([a, a] vs [a] fails) and its name makes the projection
visible at the callsite. That is the call this module makes.

WHAT THE CLOSED-UNIVERSE HELPER BUYS. The work-set is a denominator someone
authors, which is what `_closed_universe` is for:

  * `universe_sha`: verifier-held, so the policy is tamper-evident and is
    re-verified against the held sha at every use (`verify_receipt`);
  * `provenance` + `source_sha`: a work-set DERIVED from an anchored spec
    names that spec's sha as its source; a hand-written one is
    SELF_AUTHORED and must carry `source_sha=None` (the class cannot be
    labelled up; the helper refuses);
  * `reason_enum`: a committed closed vocabulary (`WITHHELD_REASONS`) for
    an output the auditor names and does NOT expect this bundle to
    deliver. This is the honest shape of "optional": the element stays in
    the denominator, its absence is excused by an enumerated reason on the
    receipt, and delivering it anyway is still a finding (deny-by-default
    over the COVERED set).

INVARIANTS THIS MODULE HOLDS
  * VERIFIER-HELD. A work-set is constructed by the auditor's harness and
    handed to `BundleVerifier(work_set=...)`. Nothing here reads a bundle.
  * DENY-BY-DEFAULT over `output_id`. An output the work-set does not name
    is a violation, not an ignored extra.
  * DUPLICATES ARE FINDINGS. Two manifest entries for one `output_id` fail
    the bijection; the invariant is never reached through a dict.
  * THE HELPERS RAISE; the verifier's contract is fail-closed VERDICTS.
    Every public method here converts `TotalBindingError` /
    `ClosedUniverseError` into `WorkSetError`, and the error prose is built
    by a formatter that cannot raise (§C9: an error path that raises turns
    a refusal into a crash).

WHAT THIS IS NOT. A work-set says which claims must arrive and under which
rule. It says nothing about whether the rule is the RIGHT one for the
physics (see the corner_load `rational_band` comparator, which bounds
|claim - recompute| rather than |residual|, a separate, open finding), and
it exists only where an auditor supplies one: the unconfigured fleet gets
the `anchored_spec_types` coverage channel as its generic FALLBACK, which
asks only whether every anchored rule was reached, never by which claim.

Stdlib + the two vendored helpers only. Imported by `rederivation/dispatch.py`
(the core verify path).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ._closed_universe import (
    PROVENANCE_CLASSES,
    ClosedUniverseError,
    build_receipt,
    declare_universe,
    verify_receipt,
)
from ._total_binding import (
    TotalBindingError,
    assert_bijection_projected,
    canon_bytes,
    strict_loads,
    value_digest,
)

__all__ = [
    "PROVENANCE_CLASSES",
    "WITHHELD_REASONS",
    "WORK_SET_DOMAIN",
    "WorkSet",
    "WorkSetError",
    "WorkSetIntegrityError",
]

#: Domain-separates the work-set's universe_sha from every other closed-universe
#: consumer's. Part of the digest, so a work-set document cannot be replayed as
#: some other consumer's universe.
WORK_SET_DOMAIN = "audit_bundle.work_set.v1"

#: The committed closed vocabulary for an output the auditor names and does not
#: expect this bundle to deliver. Sourced from THIS module's code at every use
#: (the closed-universe v3 rule: a consumer that interprets reasons pins the
#: vocabulary it understands, never the one the document presents).
#:
#:   NOT_PRODUCED_THIS_PERIOD — the producer legitimately emits this output only
#:                              in some periods, and the auditor knows this is
#:                              not one of them.
#:   WITHHELD_BY_AUDITOR      — the auditor chose not to require it this run.
WITHHELD_REASONS = ("NOT_PRODUCED_THIS_PERIOD", "WITHHELD_BY_AUDITOR")


class WorkSetError(ValueError):
    """A work-set could not be declared, or a bundle did not deliver it.

    Raised at construction for an auditor-side inconsistency (empty set, a
    withheld reason outside the enum, a withheld id the set does not name, a
    provenance/source_sha combination the helper refuses) and by
    `check_delivery` for a bundle-side violation. Dispatch catches the latter
    and maps it to the `WORK_SET_VIOLATION` reason code, a REJECT.
    """


class WorkSetIntegrityError(RuntimeError):
    """The verifier's OWN work-set no longer re-derives under its held
    universe_sha. Deliberately NOT a WorkSetError: this is the verifier's
    incapacity, not evidence against the artifact, so dispatch routes it to a
    could-not-conclude (`WORK_SET_CHECK_ERROR`, VERIFIER_INCOMPLETE) rather
    than a REJECT. A crashed checker is not a disagreement."""


def _element(output_id: str, type_key: str) -> dict:
    return {"output_id": output_id, "type": type_key}


def _output_id_of(entry: object) -> object:
    """The projection the bijection is taken over. Never raises: a malformed
    manifest entry projects to None, which no work-set element can equal."""
    if isinstance(entry, dict):
        return entry.get("output_id")
    return None


def _safe_repr(x: object) -> str:
    try:
        return repr(x)
    except Exception:  # noqa: BLE001 - a formatter must never raise (§C9)
        return "<unrepresentable>"


def _delivery_prose(expected: Iterable, delivered: Iterable, exc: Exception) -> str:
    """Name the ids that were missing, unexpected, or duplicated. A consumer
    who cannot tell WHICH output was skipped cannot act on the refusal.
    Display only: the DECISION was the helper's. Keys are `repr`-ed before
    counting so an unhashable hostile output_id cannot raise out of the
    formatter."""
    want = Counter(_safe_repr(_output_id_of(e)) for e in expected)
    got = Counter(_safe_repr(_output_id_of(o)) for o in delivered)
    missing = sorted(k for k in want if got[k] < want[k])
    unexpected = sorted(k for k in got if k not in want)
    duplicated = sorted(k for k in got if k in want and got[k] > want[k])
    parts = []
    if missing:
        parts.append(f"named-but-not-delivered=[{', '.join(missing)}]")
    if unexpected:
        parts.append(f"delivered-but-not-named=[{', '.join(unexpected)}]")
    if duplicated:
        parts.append(f"delivered-more-than-once=[{', '.join(duplicated)}]")
    if not parts:
        parts.append(f"helper: {_safe_repr(str(exc))}")
    return (
        "the bundle did not deliver exactly the auditor's work-set: "
        + " ".join(parts)
        + ". A named output that did not arrive is a dropped claim; an output "
        "the auditor never named was judged by a rule nobody assigned it; a "
        "duplicate is two claims under one name. All three are refused."
    )


@dataclass(frozen=True, slots=True)
class WorkSet:
    """The auditor's declared work: every `output_id` the bundle must deliver,
    each pinned to its anchored type, as a closed universe with a receipt.

    Construct with `WorkSet.declare(...)`; the raw constructor is for the
    dataclass only. DEEPLY immutable: the universe and receipt documents are
    held as their canonical bytes (the same bytes their shas are taken over)
    and re-parsed into fresh dicts at every use, so no holder of this object
    can mutate the committed set in place (the frozen-field ratchet's class of
    defect); `check_delivery` re-verifies the receipt against the held
    `universe_sha` before it compares anything.
    """

    universe_canon: bytes
    universe_sha: str
    receipt_canon: bytes
    #: The COVERED (output_id, type) pairs, those the bundle must deliver, in
    #: the universe's canonical order. The universe's elements minus the
    #: withheld ones.
    pins: tuple[tuple[str, str], ...]
    #: (element value_digest, reason) pairs, exactly as handed to `build_receipt`.
    withheld: tuple[tuple[str, str], ...]

    @property
    def universe(self) -> dict:
        """A FRESH parse of the committed universe document."""
        return strict_loads(self.universe_canon)

    @property
    def receipt(self) -> dict:
        """A FRESH parse of the committed receipt."""
        return strict_loads(self.receipt_canon)

    @property
    def expected(self) -> tuple[dict, ...]:
        """The covered elements as fresh element dicts."""
        return tuple(_element(oid, tk) for oid, tk in self.pins)

    @classmethod
    def declare(
        cls,
        pins: Mapping[str, str],
        *,
        source: str,
        provenance: str,
        source_sha: "str | None" = None,
        withheld: "Mapping[str, str] | None" = None,
    ) -> "WorkSet":
        """Declare the work-set.

        pins:       output_id -> the anchored type key that must judge it. The
                    complete set; there is no "and anything else".
        source:     where this enumeration came from, for the human reading the
                    face (an anchored spec's id and path; "hand-written by the
                    auditor harness").
        provenance: one of PROVENANCE_CLASSES. A work-set DERIVED from an
                    anchored spec is EXTERNAL_STRUCTURE and carries that spec's
                    sha; a hand-written one is SELF_AUTHORED and must carry
                    source_sha=None. The helper refuses the other pairings.
        withheld:   output_id -> reason (from WITHHELD_REASONS) for an output
                    named here that this bundle is NOT expected to deliver.
        """
        if not isinstance(pins, Mapping):
            raise WorkSetError(
                f"pins must be a mapping output_id -> type, got {type(pins).__name__}"
            )
        for oid, tk in pins.items():
            if not (isinstance(oid, str) and oid and isinstance(tk, str) and tk):
                raise WorkSetError(
                    f"pins must map non-empty str output_id -> non-empty str "
                    f"type; got {_safe_repr(oid)} -> {_safe_repr(tk)}"
                )
        elements = [_element(oid, tk) for oid, tk in pins.items()]
        try:
            universe = declare_universe(
                elements,
                domain=WORK_SET_DOMAIN,
                source=source,
                provenance=provenance,
                reason_enum=WITHHELD_REASONS,
                source_sha=source_sha,
            )
        except (ClosedUniverseError, TotalBindingError) as exc:
            raise WorkSetError(f"work-set could not be declared: {exc}") from exc

        by_id = {e["output_id"]: e for e in universe["elements"]}
        withheld_by_digest: dict = {}
        for oid, reason in dict(withheld or {}).items():
            if oid not in by_id:
                raise WorkSetError(
                    f"withheld output_id {_safe_repr(oid)} is not in the work-set "
                    "— only a NAMED output can be withheld (the denominator "
                    "stays complete; withholding excuses, it never removes)"
                )
            withheld_by_digest[value_digest(by_id[oid])] = reason
        expected = [
            e for e in universe["elements"] if value_digest(e) not in withheld_by_digest
        ]
        try:
            receipt = build_receipt(universe, expected, withheld_by_digest)
        except (ClosedUniverseError, TotalBindingError) as exc:
            raise WorkSetError(f"work-set receipt could not be built: {exc}") from exc
        return cls(
            universe_canon=canon_bytes(universe),
            universe_sha=universe["universe_sha"],
            receipt_canon=canon_bytes(receipt),
            pins=tuple((e["output_id"], e["type"]) for e in expected),
            withheld=tuple(sorted(withheld_by_digest.items())),
        )

    # ------------------------------------------------------------------ reads
    def required_type(self, output_id: object) -> "str | None":
        """The type the auditor pinned for `output_id`, or None when the
        work-set does not name it. None is NOT "unconstrained": an unnamed
        output has already failed `check_delivery`. Callers use this only for
        the per-output retype check on outputs the set does name."""
        for oid, tk in self.pins:
            if oid == output_id:
                return tk
        return None

    @property
    def n_expected(self) -> int:
        return len(self.pins)

    @property
    def n_withheld(self) -> int:
        return len(self.withheld)

    # ------------------------------------------------------------- the check
    def check_delivery(self, outputs: Iterable) -> None:
        """THE TRUST BOUNDARY. `outputs` is `manifest.outputs` as the producer
        wrote it: a list, taken whole, never projected to a dict first.

        Re-verifies this work-set's receipt against the sha the verifier holds
        (a work-set that no longer re-derives is refused before it can be
        applied), then requires an exact multiset bijection between the covered
        elements and the delivered entries over `output_id`. Raises
        WorkSetError for a bundle-side violation and WorkSetIntegrityError when
        the work-set itself no longer re-derives; never anything else."""
        delivered = list(outputs)
        expected = self.expected
        try:
            verify_receipt(
                self.receipt,
                self.universe,
                list(expected),
                dict(self.withheld),
                expected_universe_sha=self.universe_sha,
                expected_reason_enum=WITHHELD_REASONS,
            )
        except (ClosedUniverseError, TotalBindingError) as exc:
            raise WorkSetIntegrityError(
                f"the verifier's own work-set does not re-derive under its held "
                f"universe_sha — refusing to apply it: {exc}"
            ) from exc
        try:
            assert_bijection_projected(expected, delivered, _output_id_of)
        except TotalBindingError as exc:
            raise WorkSetError(_delivery_prose(expected, delivered, exc)) from exc

    # -------------------------------------------------------------- the face
    def face(self) -> str:
        """The `type_selection:` disclosure row for a verdict this work-set was
        applied to. States the pre-commitment, its provenance class, and the
        counts, so a reader of a GREEN verdict can see exactly what was
        required rather than inferring it from a count of policy keys."""
        r = self.receipt
        breakdown = r.get("withheld_reason_breakdown") or {}
        withheld = (
            " withheld=" + ",".join(f"{k}:{v}" for k, v in sorted(breakdown.items()))
            if breakdown
            else ""
        )
        return (
            "type_selection: auditor WORK-SET APPLIED - "
            f"universe_sha={self.universe_sha} provenance={r.get('provenance')} "
            f"source_sha={r.get('source_sha')} n_universe={r.get('n_universe')} "
            f"n_expected={r.get('n_covered')} n_withheld={r.get('n_withheld')}"
            f"{withheld}. Every named output was required to arrive exactly "
            "once under its auditor-assigned type; an output the work-set does "
            "not name is refused."
        )
