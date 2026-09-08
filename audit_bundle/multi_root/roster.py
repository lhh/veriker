"""audit_bundle/multi_root/roster.py — admission: one row per EXPECTED record, whatever came back.

The keel of a multi-root verifier is not the checks; it is the list of records the
verifier EXPECTS before it reaches anything. That list is the auditor's, it is committed
as a closed universe before the run, and after the reach stage every row on it carries
exactly one disposition:

  ADMITTED   reached; provenance held (the consumer's signature check passed); about the
             subject the verifier asked for (this run's nonce included, for reached
             records); content readable by the checks. Optionally flagged `stale` by the
             consumer: admitted for CONTRADICTION only, counts as not reached for
             confirmation (a snapshot other than the pinned one is neither tamper nor
             agreement).
  UNUSABLE   reached, but provenance failed: bad signature, wrong subject, replayed nonce,
             or content the checks cannot read. Stays in the denominator. Tamper evidence
             is not absence, and it refuses.
  UNREACHED  nothing came back, or the record's expected subject could not be derived
             because the record it depends on was not admitted. For a PRODUCER-ATTACHED
             record (`Expected.reached=False`) this means the artifact did not deliver a
             record the roster names — the work-set rule ("the auditor names the complete
             set of work, and the bundle delivers exactly that") makes that a finding, and
             the decision REFUSES on it rather than holding. Found by the degradation
             oracle: a corrupted attachment refused (signature fails) while a nulled one
             was held — dropping the evidence that would convict bought the softer verdict.

A record that was never expected has no row. Absence is therefore never confused with
agreement, and a corrupted record is never confused with an absent one.

Three substrate pieces the first implementation hand-rolled are BOUND here:

  * the roster is a `_closed_universe` universe (`declare_universe` at declaration,
    `build_receipt` + `verify_receipt` against the held `universe_sha` at every
    admission). A configuration that disables a root WITHHOLDS those records under the
    committed reason `ROOT_NOT_ENABLED`; the denominator never shrinks and the excuse is
    on the receipt. A kill condition that compares roster SIZES cannot see a swapped
    record; the receipt can.
  * admission never drops a row: `_total_binding.assert_bijection_projected` over
    record ids at the end of `admit`.
  * the per-proposition `present − verified` subtraction is a `CoverageChannel`
    (`admission_channels`): present = records with standing for the proposition,
    verified = those ADMITTED and not stale. A remainder is the proposition's
    `CANNOT_CONCLUDE / UNREACHED` — the engine's could-not-conclude, not a hand-written
    list comprehension.

What the engine does NOT read: any record's `body`. Signature validity, content
validation and staleness are consumer callables; the engine binds subject-match (every
expected key equal; the run nonce for reached records) and nothing else. It never
imports a cryptography library — the consumer brings the keys.

Stdlib only; imports nothing from `verifier`.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from .._freeze import deep_freeze
from .._closed_universe import (
    ClosedUniverseError,
    build_receipt,
    declare_universe,
    verify_receipt,
)
from .._total_binding import TotalBindingError, assert_bijection_projected
from ..coverage_channels import CoverageChannel
from .roots import RootTable, UndeclaredAuthority

__all__ = [
    "ADMITTED",
    "UNUSABLE",
    "UNREACHED",
    "DISPOSITIONS",
    "ROOT_NOT_ENABLED",
    "WITHHELD_REASONS",
    "ROSTER_DOMAIN",
    "RosterError",
    "Expected",
    "Roster",
    "Admission",
    "admit",
    "admit_nothing",
    "admitted",
    "standing_of",
    "admission_channels",
]

ADMITTED, UNUSABLE, UNREACHED = "ADMITTED", "UNUSABLE", "UNREACHED"
DISPOSITIONS = (ADMITTED, UNUSABLE, UNREACHED)

#: The one committed reason a roster record may be withheld from a run: its declared root
#: is not enabled in this configuration. Rides `universe_sha`; cannot be widened per run.
ROOT_NOT_ENABLED = "ROOT_NOT_ENABLED"
WITHHELD_REASONS = (ROOT_NOT_ENABLED,)
ROSTER_DOMAIN = "multi_root:roster"


class RosterError(ValueError):
    """The roster declaration or an admission invariant failed. Fail-closed: raised."""


@dataclass(frozen=True, slots=True)
class Expected:
    """One record the verifier expects.

    record_id:    unique within the roster; what the face names.
    authority:    which authority answers it; must be in the `RootTable`.
    standing:     the proposition ids this record has standing for (non-empty).
    subject:      the expected subject keys — what the verifier ASKED. Every key must be
                  equal on the answer, or the answer is about something else (UNUSABLE).
    fetch:        (context, nonce, rows_so_far) -> record | None. None = UNREACHED.
    subject_from: optional (rows_so_far) -> extra expected subject keys, or None when the
                  record it depends on was not admitted (then this row is UNREACHED with
                  the reason, never asked with a guessed subject).
    reached:      True for a record the verifier reaches itself and binds to its run
                  nonce; False for a producer-attached record bound to the artifact
                  instead (a quote, a stamp). An attached record cannot carry a nonce the
                  producer never held.
    """

    record_id: str
    authority: str
    standing: tuple
    subject: Mapping
    fetch: Callable
    subject_from: Callable | None = None
    reached: bool = True


def _nonempty_str(x: object, what: str) -> str:
    if not isinstance(x, str) or not x:
        raise RosterError(f"{what} must be a non-empty str, got {x!r}")
    return x


class Roster:
    """The auditor's committed list of expected records, rooted by a `RootTable`.

    Construct with `Roster.declare(rows, table, source=...)`. Immutable. Holds the
    closed-universe document and its sha; `admit` re-verifies against that sha.
    """

    __slots__ = ("_rows", "_table", "_root", "_universe", "_universe_sha")

    def __init__(self, rows: tuple, table: RootTable, root: dict, universe: dict):
        self._rows = rows
        self._table = table
        self._root = root
        self._universe = universe
        self._universe_sha = universe["universe_sha"]

    @classmethod
    def declare(cls, rows: Iterable[Expected], table: RootTable, *, source: str) -> "Roster":
        rows = tuple(rows)
        if not isinstance(table, RootTable):
            raise RosterError(f"table must be a RootTable, got {type(table).__name__}")
        ids: set = set()
        root: dict = {}
        for e in rows:
            if not isinstance(e, Expected):
                raise RosterError(f"roster rows must be Expected, got {type(e).__name__}")
            rid = _nonempty_str(e.record_id, "record_id")
            if rid in ids:
                raise RosterError(f"record_id {rid!r} declared twice")
            ids.add(rid)
            _nonempty_str(e.authority, f"authority of {rid!r}")
            try:
                root[rid] = table.root_of(e.authority)
            except UndeclaredAuthority as exc:
                raise RosterError(f"{rid!r}: {exc.args[0]}") from None
            if not isinstance(e.standing, tuple) or not e.standing:
                raise RosterError(f"{rid!r}: standing must be a non-empty tuple of proposition ids")
            for p in e.standing:
                _nonempty_str(p, f"{rid!r} standing entry")
            if not isinstance(e.subject, Mapping):
                raise RosterError(f"{rid!r}: subject must be a mapping")
            if not callable(e.fetch):
                raise RosterError(f"{rid!r}: fetch must be callable")
            if e.subject_from is not None and not callable(e.subject_from):
                raise RosterError(f"{rid!r}: subject_from must be callable or None")
        try:
            universe = declare_universe(
                sorted(ids),
                domain=ROSTER_DOMAIN,
                source=source,
                provenance="SELF_AUTHORED",
                reason_enum=WITHHELD_REASONS,
            )
        except ClosedUniverseError as exc:
            raise RosterError(f"roster universe refused: {exc}") from exc
        return cls(rows, table, root, universe)

    @property
    def rows(self) -> tuple:
        return self._rows

    @property
    def table(self) -> RootTable:
        return self._table

    @property
    def ids(self) -> tuple:
        return tuple(e.record_id for e in self._rows)

    @property
    def universe(self) -> dict:
        return dict(self._universe)

    @property
    def universe_sha(self) -> str:
        return self._universe_sha

    def root_of(self, record_id: str) -> str:
        try:
            return self._root[record_id]
        except KeyError:
            raise RosterError(f"record {record_id!r} is not on the roster") from None

    def in_play(self, roots_enabled: Iterable[str] | None) -> tuple:
        """(covered rows, withheld {record_id: reason}) for a configuration."""
        if roots_enabled is None:
            return self._rows, {}
        enabled = frozenset(roots_enabled)
        for r in enabled:
            if not self._table.is_declared_root(r):
                raise RosterError(f"roots_enabled names undeclared root {r!r}")
        covered = tuple(e for e in self._rows if self._root[e.record_id] in enabled)
        withheld = {e.record_id: ROOT_NOT_ENABLED for e in self._rows if self._root[e.record_id] not in enabled}
        return covered, withheld


@dataclass(frozen=True, slots=True)
class Admission:
    """What `admit` returns. `rows` is the face; `receipt` is the denominator's proof.

    DEEPLY immutable: `rows`, `receipt` and `withheld` are deep-frozen at construction
    (`audit_bundle._freeze.deep_freeze`), so a consumer that mutates a row in place after
    admission raises at the offending line instead of laundering a later state. Copy
    before mutating (`dict(row)`); the frozen containers still JSON-serialise as plain
    dict/list. Ratcheted by tests/test_frozen_field_ratchet.py (RUNTIME_FROZEN)."""

    rows: list
    nonce: str
    receipt: dict
    withheld: dict
    universe_sha: str
    #: Set by `admit_nothing` when the INPUT itself was inadmissible (a malformed proposal).
    #: The decision is then REFUSE, never HOLD: the substrate's admission doctrine
    #: (`audit_bundle/admission.py`, ADR D9/Q4) says an inadmissible input is a recognised,
    #: bounded property of the ARTIFACT — a REJECT — and the degradation oracle reads a
    #: could-not-conclude on a null field, where a wrong field refuses, as a softening.
    inadmissible: str | None = None

    def __post_init__(self) -> None:
        for name in ("rows", "receipt", "withheld"):
            object.__setattr__(self, name, deep_freeze(getattr(self, name)))


class _NotPlain(Exception):
    """A fetched record carries a container that is not plain JSON structure."""


def _plain_deep(obj: object, _depth: int = 0):
    """A plain-dict/list copy of a fetched record, built from TRUE storage.

    Red-team witness (2026-09-06): `_subject_matches` compared through `actual.get(k)`.
    A `dict` subclass whose `.get` always answers "equal" json-serialises (and therefore
    signs) over its REAL items, so a genuinely signed answer about another subject, or a
    replay under a stale nonce, passed subject-match. Nothing here may read a record
    through a method the record's own type can override: dict subclasses are copied with
    `dict.items` (the base implementation, over real storage — the same storage
    `json.dumps` and any canonicaliser see); any other Mapping, or any non-list sequence,
    is refused. A record that came off the wire as JSON is always plain, so this costs an
    honest producer nothing.
    """
    if _depth > 64:
        raise _NotPlain("nesting deeper than 64")
    if isinstance(obj, dict):
        return {k: _plain_deep(v, _depth + 1) for k, v in dict.items(obj)}
    if isinstance(obj, list):
        return [_plain_deep(v, _depth + 1) for v in list.__iter__(obj)]
    if isinstance(obj, tuple):
        return [_plain_deep(v, _depth + 1) for v in tuple.__iter__(obj)]
    if isinstance(obj, Mapping):
        raise _NotPlain(f"{type(obj).__name__} is not a plain object")
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    raise _NotPlain(f"{type(obj).__name__} is not JSON structure")


def _subject_matches(expected: Mapping, actual: object) -> bool:
    """`actual` is already a plain dict (from `_plain_deep`); compare real items."""
    return type(actual) is dict and all(k in actual and actual[k] == v for k, v in expected.items())


def _row(e: Expected, root: str) -> dict:
    return {
        "record_id": e.record_id,
        "authority": e.authority,
        "root": root,
        "standing": list(e.standing),
        "reached": e.reached,
        "disposition": None,
        "reason": None,
        "record": None,
        "stale": False,
    }


def _seal(roster: Roster, rows: list, covered: tuple, withheld: dict, nonce: str, *, inadmissible: str | None = None) -> Admission:
    """Receipt against the held sha, then the never-drop-a-row bijection."""
    covered_ids = [e.record_id for e in covered]
    try:
        receipt = build_receipt(roster.universe, covered_ids, withheld)
        verify_receipt(
            receipt,
            roster.universe,
            covered_ids,
            withheld,
            expected_universe_sha=roster.universe_sha,
            expected_reason_enum=WITHHELD_REASONS,
        )
    except ClosedUniverseError as exc:
        raise RosterError(f"roster receipt failed: {exc}") from exc
    try:
        assert_bijection_projected(rows, covered, key=lambda r: r["record_id"] if isinstance(r, dict) else r.record_id)
    except TotalBindingError as exc:
        raise RosterError(f"admission dropped or invented a row: {exc}") from exc
    for r in rows:
        if r["disposition"] not in DISPOSITIONS:
            raise RosterError(f"row {r['record_id']!r} left without a disposition")
    return Admission(rows=rows, nonce=nonce, receipt=receipt, withheld=dict(withheld), universe_sha=roster.universe_sha, inadmissible=inadmissible)


def admit(
    roster: Roster,
    context: object,
    *,
    signature_valid: Callable[[Expected, Mapping], bool],
    validate_content: Callable[[str, Mapping], str | None] | None = None,
    is_stale: Callable[[Expected, Mapping], str | None] | None = None,
    roots_enabled: Iterable[str] | None = None,
    nonce: str | None = None,
) -> Admission:
    """Reach every in-play roster record and give it a disposition. Never drops a row.

    signature_valid(expected, record) -> bool   the consumer's provenance check.
    validate_content(record_id, record) -> str | None   a reason the checks cannot read
        this content (-> UNUSABLE), or None.
    is_stale(expected, record) -> str | None   a reason this admitted record is stale
        (admitted for contradiction only), or None.
    roots_enabled   the configuration; records under other roots are WITHHELD on the
        receipt with `ROOT_NOT_ENABLED`, never silently absent.
    nonce   verifier-held; generated here when not supplied. Tests may pin it.
    """
    covered, withheld = roster.in_play(roots_enabled)
    nonce = nonce if nonce is not None else secrets.token_hex(8)
    rows: list = []
    for e in covered:
        row = _row(e, roster.root_of(e.record_id))
        expected_subject = dict(e.subject)
        if e.reached:
            expected_subject["nonce"] = nonce
        derived = e.subject_from(rows) if e.subject_from is not None else {}
        if derived is None:
            row.update(disposition=UNREACHED, reason="subject not derivable: the record it depends on was not admitted")
            rows.append(row)
            continue
        expected_subject.update(derived)
        rec = e.fetch(context, nonce, rows)
        if rec is not None:
            try:
                rec = _plain_deep(rec)
            except _NotPlain as exc:
                row.update(disposition=UNUSABLE, reason=f"record is not plain JSON structure: {exc}")
                rows.append(row)
                continue
        if rec is None:
            # A reached record that did not answer is a network fact (could-not-conclude).
            # A producer-attached record that is not there was not DELIVERED: the roster
            # named it and the artifact omitted it, which the decision treats as a finding
            # (`propositions.overall`: `undelivered_attachments` -> REFUSE). Same
            # disposition, different reason, different consequence.
            row.update(disposition=UNREACHED, reason="no response" if e.reached else "not attached to the artifact")
        elif type(rec) is not dict:
            row.update(disposition=UNUSABLE, reason=f"record is not an object: {type(rec).__name__}")
        elif not signature_valid(e, rec):
            row.update(disposition=UNUSABLE, reason="signature does not validate under the declared key")
        elif not _subject_matches(expected_subject, rec.get("subject")):
            actual = rec.get("subject")
            got = {k: v for k, v in actual.items() if k != "nonce"} if type(actual) is dict else actual
            want = {k: v for k, v in expected_subject.items() if k != "nonce"}
            nonce_ok = (not e.reached) or (type(actual) is dict and actual.get("nonce") == nonce)
            row.update(
                disposition=UNUSABLE,
                reason=(f"record is about {got!r}, not {want!r}" if nonce_ok else "record does not carry this run's nonce (replay)"),
            )
        elif validate_content is not None and (problem := validate_content(e.record_id, rec)) is not None:
            row.update(disposition=UNUSABLE, reason=f"malformed content: {problem}")
        elif is_stale is not None and (why := is_stale(e, rec)) is not None:
            row.update(disposition=ADMITTED, stale=True, record=rec, reason=f"stale: {why}; admitted for contradiction only")
        else:
            row.update(disposition=ADMITTED, reason="ok", record=rec)
        rows.append(row)
    return _seal(roster, rows, covered, withheld, nonce)


def admit_nothing(roster: Roster, reason: str, *, roots_enabled: Iterable[str] | None = None, inadmissible: bool = True) -> Admission:
    """An inadmissible input reaches nothing: every in-play row is UNREACHED with the
    reason and the receipt still seals the full denominator, so the face is never empty
    and no proposition reads as agreed. With `inadmissible=True` (the default) the
    decision is REFUSE — see `Admission.inadmissible`. Pass False only when the input was
    admissible and the verifier simply reached nothing (an outage), which is a HOLD."""
    covered, withheld = roster.in_play(roots_enabled)
    reason = _nonempty_str(reason, "reason")
    rows = []
    for e in covered:
        row = _row(e, roster.root_of(e.record_id))
        row.update(disposition=UNREACHED, reason=reason)
        rows.append(row)
    return _seal(roster, rows, covered, withheld, nonce="", inadmissible=reason if inadmissible else None)


def admitted(rows: Iterable[Mapping], record_id: str) -> Mapping | None:
    """The admitted record (stale included — the caller decides what a stale one may do)."""
    for r in rows:
        if r["record_id"] == record_id and r["disposition"] == ADMITTED:
            return r["record"]
    return None


def standing_of(row: Mapping, extra_standing: Mapping | None = None) -> set:
    return set(row["standing"]) | set((extra_standing or {}).get(row["record_id"], ()))


def admission_channels(
    rows: Iterable[Mapping],
    propositions: Iterable[str],
    *,
    extra_standing: Mapping | None = None,
) -> dict:
    """One `CoverageChannel` per proposition: present = expected records with standing,
    verified = those ADMITTED and not stale. A remainder is the proposition's
    CANNOT_CONCLUDE / UNREACHED. Keyed by proposition id.

    A proposition with NO record of standing has an empty `present`, which the channel
    engine treats as inert. That is correct for the engine ("nothing to account for") and
    wrong for a verdict, so `propositions.py` refuses to conclude on such a proposition
    separately — the inertness is never read as agreement.
    """
    rows = list(rows)
    out = {}
    for pid in propositions:
        present = frozenset(r["record_id"] for r in rows if pid in standing_of(r, extra_standing))
        verified = frozenset(
            r["record_id"]
            for r in rows
            if pid in standing_of(r, extra_standing) and r["disposition"] == ADMITTED and not r.get("stale")
        )
        out[pid] = CoverageChannel(
            check_name=f"multi_root:admission:{pid}",
            present=present,
            verified=verified,
            noun="expected record",
            note=(
                f"Proposition {pid} cannot be concluded: a record with standing for it "
                "was not admitted for confirmation (unreached, unusable, or stale)."
            ),
        )
    return out
