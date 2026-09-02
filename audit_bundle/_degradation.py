"""audit_bundle/_degradation.py — the degradation-monotonicity oracle.

Mechanizes THREAT_MODEL row 20 (`rederivation/THREAT_MODEL.md`), which is
stated as DOCTRINE with the reason-code column "own code per surface" and the
admission "A doctrine row is not a guard".

**The property.** Verdict severity must be monotone in artifact degradation.
Breaking an artifact HARDER must never buy a SOFTER verdict. Stated in
`cd5c782cd` about our own code: *"a well-formed-but-INCOMPLETE block draws 7
blocking reasons, while a MALFORMED one passes clean. Degrading the input past
the parser's recognition threshold is REWARDED."*

**Relation to `probe_check` (`_total_binding.py`).** This EXTENDS it; it does
not reimplement it. probe_check is a completeness witness — for every part of a
fixture, prove the check is not indifferent to it. Two structural gaps put row
20 out of its reach:

  G1  `run_leg` computes `rejected = decision not in accepting_set` — BINARY,
      and no leg is ever compared to ANOTHER leg. NARROWED after audit: the
      exact leg also requires an EXPECTED REASON (`_total_binding.py:1012`,
      "incidental rejection is not binding sensitivity"), so a REJECT that
      softens into a could-not-conclude carrying a different code ALREADY
      fails a probe_check leg. The true residue is that probe_check cannot
      RANK two non-accepting decisions against each other, and cannot see a
      softening into a decision that is inside `accepting_set` at all.
  G2  `_default_mutant` is type- and shape-PRESERVING (int+1, bool negate, str
      char-flip), so wrong-type / empty-of-same-type / null / parent-scalar are
      mutants it does not generate; on a DEGENERATE node it raises
      `ProbeConfigError` and delegates to a hand-written predicate pattern,
      with the docstring "silence here is exactly where the exploit lives". The
      c18 mutant (a dict node set to "x") is one it will not generate.

**The relation, restated.** MR-1 is monotonicity along the ORDERED ladder
against a running maximum, not each rung against a fixed base. The old
base-anchored form is what made the instrument report clean over real
fail-opens; see `probe_monotonicity`. Rung 6/7 (parent degradation) is skipped
when the parent IS the document root — destroying the whole document is a
different event, which a defect-free tool may answer "cannot parse" to, and
comparing that against a field-level rejection manufactured one false finding
per top-level key.

**The novel surface is four rungs, not seven.** CORRECTED after audit: an
earlier revision claimed the whole ladder was out of probe_check's reach. It is
not. probe_check runs a `structural:key-delete` leg for every key of every
mapping node (`_total_binding.py:1186-1196`) and asserts REJECT — that IS rungs
5 and 7, and it is STRICTER there than this module, which files deletion as an
MR-2 disclosure because row 20's first clause is "absent may pass". What
probe_check does not generate is rungs 2/3/4/6 (empty-same-type, wrong-type,
null, parent-scalar), and what it cannot do at any rung is compare one leg's
verdict to another's.

**Why it ports to a foreign target, and what that does NOT mean.** The RELATION
needs no ground truth: MR-1 compares the verifier to itself, so no spec, oracle
or expected-verdict table is required. Two costs are real and were overstated
before. (1) V1 requires a fixture the target ACCEPTS, and authoring one takes
target knowledge — the c18 fixture needed all eight required fields
reverse-engineered before the probe would run. (2) Every adapter encodes some
of the target's vocabulary (an exit-code contract at minimum). The probe is
O(paths x rungs) runs, not two. What survives: given an accepted fixture and an
exit-code contract, no knowledge of the target's SEMANTICS is needed, and it can
only find ORDERING defects — never a wrong-but-self-consistent verdict.

Scope: JSON-ish roots (dict / list / str / int / float / bool / None). Roots
carrying dataclasses or SimpleNamespace are out of scope — declared, not
silently mishandled (`UnsupportedRoot`).
"""

from __future__ import annotations

import copy
import json
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Iterator, Sequence

# AUDIT #1: the scalar mutant is IMPORTED, not re-authored. A hand-copied
# twin had already drifted — probe_check's returns None on an empty string
# (a LOUD ProbeConfigError telling the author to supply a predicate), the copy
# here returned () (a SILENT missing rung). The duplicated-helper lesson in
# this repo is that the drift, not the duplication, is the defect; the walkers
# below stay local because they are genuinely different (JSON-only, root-first,
# and they support deletion, which _total_binding has no need for), and
# tests/test_degradation_monotonicity.py pins them against their counterparts.
from audit_bundle._total_binding import _default_mutant

__all__ = [
    "Severity",
    "Rung",
    "Leg",
    "Finding",
    "Report",
    "DegradationConfigError",
    "UnsupportedRoot",
    "build_ladder",
    "probe_monotonicity",
    "reasons_adapter",
    "verdict_adapter",
    "plugin_result_adapter",
    "exit_code_adapter",
    "format_report",
]


class DegradationConfigError(Exception):
    """The probe cannot run as configured (vacuous, or a bad fixture)."""


class UnsupportedRoot(DegradationConfigError):
    """The root carries a node kind this oracle does not model."""


class _LegRaised(Exception):
    """Internal. `run` raised on ONE degraded leg.

    Never escapes `probe_monotonicity`: the leg is quarantined (recorded,
    labelled, and it blocks `ok`) so that one bad leg costs one leg rather
    than the other 399. The untouched fixture is the exception — a `run` that
    cannot even score the fixture is a configuration error, not a leg.
    """

    def __init__(self, label: str):
        super().__init__(label)
        self.label = label


class Severity(IntEnum):
    """The severity lattice — `verdict.py`'s own four-element order.

    `PASS < ERROR_CLEAN < REJECT < ERROR_CRASH`, which is exactly
    `verdict.py`'s ratified `crash-ERROR > REJECT > clean-ERROR > OK`.

    CORRECTED after a fresh-context audit. An earlier revision flattened this
    to a three-element `PASS < ERROR < REJECT` on the argument that row 20
    calls could-not-conclude "the SOFTER verdict for the MORE degraded input" —
    true, but row 20 reasons about the CLEAN error only. A crash ranks ABOVE
    reject in the ratified algebra (process integrity is in doubt, so sibling
    results cannot be trusted), so mapping every ERROR to 1 filed
    REJECT->crash as a "softening" the codebase's own order calls a
    STRENGTHENING. The docstring warned against that conflation and the code
    then committed it 260 lines later.

    A crash is therefore never an MR-1 finding — but it is not silence either:
    it lands in `Report.crashes`, because a crash reachable from
    producer-controlled bytes is its own reportable class ("a crashed checker
    is not a disagreement").

    Findings are still tiered, because the ERROR_CLEAN rank is the arguable
    part: TIER-1 reaches PASS and is a fail-open under EVERY lattice choice;
    TIER-2 is a REJECT softening to a clean could-not-conclude, whose
    exploitability depends on how the consumer treats that exit code.
    """

    PASS = 0
    ERROR_CLEAN = 1
    REJECT = 2
    ERROR_CRASH = 3
    ERROR = 1  # alias of ERROR_CLEAN, kept for callers that cannot tell


# --- rung taxonomy ---------------------------------------------------------
# presence: PRESENT rungs are constrained by MR-1; ABSENT rungs are not
# (row 20's first clause is "absent may pass") and surface as MR-2 disclosures.
PRESENT, ABSENT = "PRESENT", "ABSENT"

_RUNG_ORDER = (
    "shape_preserving",  # rung 1 — the MR-1 base
    "empty_same_type",  # rung 2
    "wrong_type",  # rung 3
    "null",  # rung 4
    "absent",  # rung 5
    "parent_scalar",  # rung 6
    "parent_absent",  # rung 7
)


@dataclass(frozen=True)
class Rung:
    name: str
    presence: str
    root: Any


@dataclass(frozen=True)
class Leg:
    path: tuple
    rung: str
    presence: str
    severity: Severity
    reasons: tuple
    spoke: bool = True


@dataclass(frozen=True)
class Finding:
    tier: int
    relation: str
    path: tuple
    rung: str
    base_rung: str
    base_severity: Severity
    rung_severity: Severity
    detail: str


@dataclass
class Report:
    ok: bool = True
    vacuous: bool = False
    baseline: Severity = Severity.PASS
    findings: list = field(default_factory=list)
    disclosures: list = field(default_factory=list)
    indifferent: list = field(default_factory=list)
    no_ladder: list = field(default_factory=list)
    upstream_only: list = field(default_factory=list)
    crashes: list = field(default_factory=list)
    quarantined: list = field(default_factory=list)
    declared_limits: list = field(default_factory=list)
    reason_census: dict = field(default_factory=dict)
    legs: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)


# --- path machinery --------------------------------------------------------

_SCALARS = (str, int, float, bool)

# MEASURED, not guessed: at the default recursion limit `copy.deepcopy` and
# `json.dumps` both survive a 400-deep tower and both raise RecursionError at
# 500. The ceiling is set at half the measured breaking point so the refusal
# comes from HERE, with a path, rather than as a traceback out of the middle
# of a 400-leg sweep.
_MAX_DEPTH = 200


def _kind_ok(node: Any) -> bool:
    return node is None or type(node) in (dict, list, str, int, float, bool)


def _validate_fixture(root: Any) -> None:
    """Refuse, up front and loudly, every fixture this oracle does not model.

    Runs on the WHOLE fixture whether or not `paths=` narrows the probe — a
    projection used to skip `_walk` entirely, so `_kind_ok` never ran and an
    unmodelled node reached `run` through a parent rung.

    Dict KEYS are checked, not only values. `_canon` (the verdict-cache key)
    is `json.dumps(sort_keys=True)`, which spells {1: "a"} and {"1": "a"}
    identically; a non-str key therefore let one root's verdict be served for
    another, and the answer depended on which root was walked first. With keys
    required to be str and values JSON-kinds, `json.dumps` is injective over
    everything this module accepts (1 / 1.0 / True are "1" / "1.0" / "true").

    C9 (never raise) is enforced HERE, not by a try/except at the top: a cycle,
    a tower deeper than `_MAX_DEPTH`, and an int past the int->str digit
    ceiling each used to escape as a raw RecursionError / ValueError from
    somewhere inside deepcopy or json.dumps. Each is now a
    `DegradationConfigError` naming the PATH, raised before any leg runs.
    """
    stack = [((), root, ())]  # (path, node, ancestor ids)
    while stack:
        path, node, ancestors = stack.pop()
        if not _kind_ok(node):
            raise UnsupportedRoot(
                f"node at {path!r} is {type(node).__name__}; this oracle models "
                f"JSON-ish roots only. Convert the fixture or probe a projection "
                f"EXPLICITLY (handing a projection here narrows the denominator)."
            )
        t = type(node)
        if t is int and not isinstance(node, bool):
            # `str()` carries CPython's int->str digit ceiling, so this asks
            # the same question `_canon`'s json.dumps would ask later, and
            # pays for it once, up front, with a path attached.
            try:
                str(node)
            except ValueError:
                raise DegradationConfigError(
                    f"int at {path!r} has more than "
                    f"{sys.get_int_max_str_digits()} digits; the verdict cache "
                    f"spells every root with json.dumps, so this would raise "
                    f"from the middle of the sweep instead of from here"
                ) from None
        if t not in (dict, list):
            continue
        if id(node) in ancestors:
            raise DegradationConfigError(
                f"the fixture is cyclic: the container at {path!r} is its own "
                f"ancestor. Every walker here, and json.dumps, and deepcopy, "
                f"would run forever or blow the stack"
            )
        if len(ancestors) >= _MAX_DEPTH:
            raise DegradationConfigError(
                f"the fixture nests deeper than {_MAX_DEPTH} at {path!r}; "
                f"deepcopy and json.dumps raise RecursionError at 500 and the "
                f"probe would die mid-sweep. Probe a projection EXPLICITLY"
            )
        inner = ancestors + (id(node),)
        if t is dict:
            for k, v in node.items():
                if type(k) is not str:
                    # NOT repr'd: a key whose __repr__ raises must still land
                    # here as a config error, not as its own traceback.
                    raise DegradationConfigError(
                        f"dict at {path!r} has a {type(k).__name__} key; keys "
                        f"must be str (a non-str key canonicalises onto a str "
                        f"one and the verdict cache serves the wrong verdict)"
                    )
                stack.append((path + (k,), v, inner))
        else:
            for i, v in enumerate(node):
                stack.append((path + (i,), v, inner))


def _validate_paths(root: Any, paths: Sequence) -> list:
    out = []
    for path in paths:
        if not isinstance(path, tuple):
            raise DegradationConfigError(
                f"paths entries must be tuples, got {type(path).__name__} "
                f"{path!r} (a bare string would be iterated character-wise)"
            )
        cur = root
        for tok in path:
            try:
                cur = cur[tok]
            except (KeyError, IndexError, TypeError):
                raise DegradationConfigError(
                    f"path {path!r} does not resolve in the fixture (at token "
                    f"{tok!r}); every probed path must name a real node"
                ) from None
        out.append(path)
    return out


def _walk(root: Any) -> Iterator[tuple]:
    """(path, node) for the root and every reachable node, root first.

    Assumes `_validate_fixture` has run (str keys, JSON kinds, bounded depth).
    """

    def rec(node: Any, path: tuple) -> Iterator[tuple]:
        yield path, node
        if type(node) is dict:
            for k in sorted(node):
                yield from rec(node[k], path + (k,))
        elif type(node) is list:
            for i, v in enumerate(node):
                yield from rec(v, path + (i,))

    yield from rec(root, ())


def _node_at(root: Any, path: tuple) -> Any:
    cur = root
    for tok in path:
        cur = cur[tok]
    return cur


def _set_at(root: Any, path: tuple, value: Any) -> Any:
    if not path:
        return copy.deepcopy(value)
    out = copy.deepcopy(root)
    cur = out
    for tok in path[:-1]:
        cur = cur[tok]
    cur[path[-1]] = copy.deepcopy(value)
    return out


def _delete_at(root: Any, path: tuple) -> Any:
    if not path:
        raise DegradationConfigError("cannot delete the root")
    out = copy.deepcopy(root)
    cur = out
    for tok in path[:-1]:
        cur = cur[tok]
    del cur[path[-1]]
    return out


def _canon(x: Any) -> str:
    """The verdict-cache key. Injective over validated roots — no `default=`,
    because a fallback that spells two distinct objects the same way is how
    one root's verdict gets served for another."""
    return json.dumps(x, sort_keys=True)


# --- ladder construction ---------------------------------------------------


def _shape_preserving(node: Any) -> tuple:
    """(value,) or () when no shape-preserving mutant exists.

    Scalars DELEGATE to probe_check's `_default_mutant` (imported, not copied).
    Containers extend it the way probe_check's STRUCTURAL legs do: a dict drops
    one key, a list drops one element. For a dict that is precisely the
    "well-formed but INCOMPLETE" case that is c18's MR-1 base.
    """
    t = type(node)
    if t in (bool, int, float, str):
        m = _default_mutant(node)
        return () if m is None else m
    if t is dict:
        if not node:
            return ()
        drop = sorted(node)[0]
        return ({k: v for k, v in node.items() if k != drop},)
    if t is list:
        if not node:
            return ()
        return (node[1:],)
    return ()


def _empty_same_type(node: Any):
    t = type(node)
    if t is dict:
        return ({},)
    if t is list:
        return ([],)
    if t is str:
        return ("",)
    if t is int and not isinstance(node, bool):
        return (0,)
    if t is float:
        return (0.0,)
    return ()


def _wrong_type(node: Any):
    # A scalar of the wrong type: the mutation that turns a structural check
    # into a parse failure. This is c18's mutant.
    return (0,) if type(node) is str else ("x",)


def build_ladder(root: Any, path: tuple) -> list:
    """The degradation ladder at `path`, least-degraded first.

    Rungs producing a root byte-identical to an earlier rung (or to the
    untouched fixture) are dropped — a no-op mutation is not a probe.
    """
    node = _node_at(root, path)
    seen = {_canon(root)}
    out: list = []

    def add(name: str, presence: str, mutated: Any) -> None:
        key = _canon(mutated)
        if key in seen:
            return
        seen.add(key)
        out.append(Rung(name, presence, mutated))

    for value in _shape_preserving(node):
        add("shape_preserving", PRESENT, _set_at(root, path, value))
    for value in _empty_same_type(node):
        add("empty_same_type", PRESENT, _set_at(root, path, value))
    if node is not None:
        for value in _wrong_type(node):
            add("wrong_type", PRESENT, _set_at(root, path, value))
        add("null", PRESENT, _set_at(root, path, None))
    if path:
        add("absent", ABSENT, _delete_at(root, path))
        # rung 6/7 — the SAME degradation one level up. Verbatim from
        # cd5c782cd: `"evidence": "x"` hides verifier_identity just as
        # effectively and previously landed on the absent path.
        #
        # NOT when the parent IS the document. Replacing or deleting the whole
        # root is not "degrading the parent of this field" — it is a different,
        # whole-document event, and a defect-free tool is entitled to answer it
        # "cannot parse this document" (ERROR_CLEAN, which sits BELOW REJECT).
        # Comparing that against a field-level rejection manufactured one false
        # finding per top-level key — MEASURED 1/3/6/10 for 1/3/6/10 keys on a
        # target with no ordering defect at all. Nothing is lost by the
        # exclusion: whole-document destruction IS still probed, as the root's
        # own `wrong_type` / `null` rungs, where it is ranked only against
        # other whole-document outcomes.
        parent = path[:-1]
        if parent:
            add("parent_scalar", PRESENT, _set_at(root, parent, "x"))
            add("parent_absent", ABSENT, _delete_at(root, parent))
    out.sort(key=lambda r: _RUNG_ORDER.index(r.name))
    return out


# --- adapters --------------------------------------------------------------


def reasons_adapter(fn: Callable) -> Callable:
    """A check returning a list of reason strings: [] -> PASS, else REJECT.

    This surface has no could-not-conclude channel, so it can only ever
    produce TIER-1 findings. That is a property of the SURFACE, not evidence
    that no TIER-2 defect exists there.
    """

    def run(root: Any):
        reasons = fn(root)
        sev = Severity.PASS if not reasons else Severity.REJECT
        return sev, tuple(str(r) for r in reasons)

    return run


def verdict_adapter(fn: Callable) -> Callable:
    """A check returning an object with `.state` in {OK, REJECT, ERROR}."""

    def run(root: Any):
        v = fn(root)
        state = str(getattr(v, "state", "")).upper().rsplit(".", 1)[-1]
        if state == "OK":
            sev = Severity.PASS
        elif state == "REJECT":
            sev = Severity.REJECT
        elif state == "ERROR":
            # AUDIT #4: read error_kind. verdict.py defaults an ERROR built
            # with no explicit kind to CRASH, and the rungs most likely to
            # induce one are exactly wrong_type / parent_scalar.
            kind = str(getattr(v, "error_kind", "") or "CRASH").upper()
            sev = (
                Severity.ERROR_CLEAN
                if kind.rsplit(".", 1)[-1] == "INCOMPLETE"
                else Severity.ERROR_CRASH
            )
        else:
            raise DegradationConfigError(f"unmappable verdict state {state!r}")
        reasons = getattr(v, "failures", None) or getattr(v, "reason", None) or ()
        if isinstance(reasons, str):
            reasons = (reasons,)
        return sev, tuple(str(r) for r in reasons)

    return run


def plugin_result_adapter(fn: Callable) -> Callable:
    """A check returning a PluginResult-like object (`.ok`, `.reason_code`)."""

    def run(root: Any):
        r = fn(root)
        sev = Severity.PASS if getattr(r, "ok", False) else Severity.REJECT
        code = getattr(r, "reason_code", None)
        return sev, ((str(code),) if code else ())

    return run


# --- the probe -------------------------------------------------------------


_RELATIONS = ("MR-1", "MR-2")


def _waiver_key(f: Finding) -> tuple:
    """The key a declaration must match to excuse `f`.

    It carries the TRANSITION, not just the spot. Keyed on `(path, rung)`
    alone, a waiver written for a REJECT -> ERROR_CLEAN softening silently
    excused a REJECT -> PASS regression that arrived later at the same spot:
    `ok` flipped green and the staleness check never fired, because the key
    still matched. A waiver must name what it excuses precisely enough that a
    WORSE hit is a different, un-excused hit.
    """
    return (f.path, f.rung, f.relation, f.base_severity, f.rung_severity)


def _file(rep: Report, declared: dict, used: set, f: Finding) -> None:
    """Route one hit to findings / disclosures / declared_limits."""
    key = _waiver_key(f)
    if key in declared:
        used.add(key)
        rep.declared_limits.append((f, declared[key]))
        return
    (rep.disclosures if f.relation == "MR-2" else rep.findings).append(f)


def probe_monotonicity(
    fixture: Any,
    run: Callable,
    *,
    paths: Sequence | None = None,
    declared: dict | None = None,
) -> Report:
    """Run the ladder at every node and assert MR-1 / MR-2 / MR-3.

    MR-1 (present-monotonicity, primary): no PRESENT rung is softer than any
      LESS-DEGRADED present rung — monotonicity along the WHOLE ordered ladder,
      against a running maximum. A merely-wrong value that is caught means a
      more-broken value must be caught at least as hard.

      CORRECTED. This used to anchor every comparison on `shape_preserving`
      alone, and discard the ladder (AFTER computing it) when that base passed
      or was absent, so no rung was ever compared to another rung and a
      softening between two LATER rungs was invisible. Measured on a checker
      that accepts an int, rejects a string and wrongly accepts null:
      `ok=True, tier1=0` over a textbook REJECT->PASS fail-open.

      This subsumes the old MR-3 (`parent_scalar` at least as severe as
      `wrong_type`), which was one ordered pair of PRESENT rungs. The relation
      was DELETED rather than left to double-report the same hit.
    MR-2 (absent-as-disclosure): ABSENT rungs are NOT constrained — "absent may
      pass" is row 20's first clause. But an ABSENT rung that PASSES while a
      less-degraded PRESENT one rejects means every guard at that path is
      bypassable by DELETION. Reported as a disclosure; never silently green,
      never a failure. If nothing less-degraded rejects, there is no guard to
      bypass and nothing is disclosed.

    Vacuity, committed before the numerator and never allowed to read as green:
      V1 the baseline fixture must be accepted (else the probe is meaningless);
      V2 EVERY present rung == PASS, so nothing at this path moved the
         verdict — reported VACUOUS there AND as INDIFFERENT, since a verifier
         that ignores a wrong value is itself a probe_check-class finding.
         CORRECTED: this used to fire on a PASSing `shape_preserving` alone,
         which means only that the LEAST-degraded rung did not move and says
         nothing about the six below it;
      V3 no constructible ladder at a node (or none this instrument may rank);
      V4 the check under test NEVER SPOKE on a non-PASS leg — every rejection
         came from upstream of it (a parse boundary, a loader). CORRECTED: this
         read the BASE leg's flag plus one global `any()`, so a path counted as
         probed while the rung it was compared AGAINST was decided upstream. A
         comparison now counts only if BOTH rungs were spoken. `run` reports
         this by returning a third element `spoke: bool`; without it the sweep
         reports a clean bill of health for a check that was inert, which is
         this module's own defect class turned on the instrument. MEASURED: a
         12-plugin sweep over a real bundle read probed=1/98 and vacuous=False
         for every plugin, and the reason census was 588 PASS + 80
         MANIFEST_PARSE_REFUSED — zero plugin reason codes.

    A leg whose `run` RAISES is quarantined, not fatal: recorded in
    `Report.quarantined` with its path, rung and exception, excluded from every
    MR relation, and blocking `ok`. Only a `run` that raises on the UNTOUCHED
    fixture is a configuration error.

    `declared` maps
    `(path_tuple, rung_name, relation, base_severity, rung_severity) -> reason`
    and moves a finding or disclosure to `declared_limits`. The key carries the
    TRANSITION, not just the spot: keyed on `(path, rung)` alone, a waiver
    written for a REJECT -> ERROR_CLEAN softening also excused a REJECT -> PASS
    regression arriving later at the same spot, and the staleness check never
    fired because the key still matched. A reason is MANDATORY (an undocumented
    waiver is how a real hit gets retired quietly) and a declaration matching
    nothing RAISES as stale — probe_check's rule, for the same reason: the
    waiver outlives the behaviour it excused and silently covers the next one.
    """
    rep = Report()
    cache: dict = {}
    _validate_fixture(fixture)
    all_paths = (
        [p for p, _ in _walk(fixture)]
        if paths is None
        else _validate_paths(fixture, paths)
    )
    declared = dict(declared or {})
    for key, reason in declared.items():
        if not (
            isinstance(key, tuple)
            and len(key) == 5
            and isinstance(key[0], tuple)
            and key[1] in _RUNG_ORDER
            and key[2] in _RELATIONS
            and isinstance(key[3], Severity)
            and isinstance(key[4], Severity)
        ):
            raise DegradationConfigError(
                f"declared key must be (path_tuple, rung_name, relation, "
                f"base_severity, rung_severity) — rung one of {_RUNG_ORDER}, "
                f"relation one of {_RELATIONS}, both severities from "
                f"`Severity`. Got {key!r}. The transition is part of the key "
                f"BY DESIGN: a waiver keyed on the spot alone excused whatever "
                f"softening turned up there, including a worse one."
            )
        if not isinstance(reason, str) or not reason.strip():
            raise DegradationConfigError(
                f"declared {key!r} needs a non-empty reason — an undocumented "
                f"waiver is how a real hit gets retired quietly"
            )
    used_declarations: set = set()

    def sev_of(root: Any, _where: str = "fixture", *, fatal: bool = True) -> tuple:
        key = _canon(root)
        if key not in cache:
            try:
                out = run(root)
            except Exception as exc:  # noqa: BLE001 - re-raised with context
                # `run` owns the fail-closed decision (a crashed checker is not
                # a disagreement, and swallowing it here would hide exactly the
                # crash-to-verdict collapse this oracle is meant to expose).
                if fatal:
                    # The UNTOUCHED fixture. Nothing downstream means anything
                    # if the target cannot score it, so this stays a config
                    # error, and it says WHICH leg produced it.
                    raise DegradationConfigError(
                        f"run() raised on {_where}: {type(exc).__name__}: "
                        f"{exc}. Wrap it fail-closed and map the crash to a "
                        f"severity (ERROR for could-not-conclude) — do not let "
                        f"the probe decide what a crash means."
                    ) from exc
                # A DEGRADED leg. One bad leg costs one leg, not the other 399:
                # cached so the same root is not re-invoked, and raised as the
                # internal signal the ladder loop quarantines.
                cache[key] = _LegRaised(f"{type(exc).__name__}: {exc}")
            else:
                if len(out) == 2:
                    out = (out[0], out[1], True)
                cache[key] = out
        got = cache[key]
        if isinstance(got, _LegRaised):
            raise got
        return got

    base_sev, base_reasons, _ = sev_of(fixture)
    rep.baseline = base_sev
    if base_sev != Severity.PASS:
        raise DegradationConfigError(
            f"V1: the untouched fixture is not accepted (severity="
            f"{base_sev.name}, reasons={base_reasons!r}) — every degraded rung "
            f"would trivially satisfy MR-1 and the probe would be vacuous"
        )

    probed = 0

    for path in all_paths:
        ladder = build_ladder(fixture, path)
        if not ladder:
            rep.no_ladder.append(path)
            continue
        by_name = {}
        spoke_by_name = {}
        for rung in ladder:
            try:
                sev, reasons, spoke = sev_of(
                    rung.root,
                    f"path={list(path)!r} rung={rung.name}",
                    fatal=False,
                )
            except _LegRaised as raised:
                # The leg is LOST, not silently green: it is recorded with its
                # path, its rung and the exception, it blocks `ok`, and it is
                # absent from `by_name` so no MR relation is computed against a
                # verdict that was never produced. Every other rung at this
                # path — including a fail-open on a different one — still runs.
                rep.quarantined.append((path, rung.name, raised.label))
                continue
            by_name[rung.name] = sev
            spoke_by_name[rung.name] = spoke
            rep.legs.append(Leg(path, rung.name, rung.presence, sev, reasons, spoke))
            if sev == Severity.ERROR_CRASH:
                # Never an MR-1 finding (a crash outranks REJECT in the
                # ratified algebra), never silence either.
                rep.crashes.append((path, rung.name, reasons))

        # The CHAIN: the PRESENT rungs, in degradation order, that produced a
        # verdict this instrument is entitled to rank AND that the check under
        # test actually spoke. A quarantined rung is absent from `by_name`; a
        # CRASH outranks REJECT in the ratified algebra, so ranking it as a
        # softening would file a STRENGTHENING as a defect (it is reported in
        # `rep.crashes` instead); and an UNSPOKEN rung carries a verdict from
        # upstream of the check -- a loader, a parse boundary -- so comparing
        # anything to it says nothing about the check.
        rankable = [
            r.name
            for r in ladder
            if r.presence == PRESENT
            and r.name in by_name
            and by_name[r.name] != Severity.ERROR_CRASH
        ]
        chain = [n for n in rankable if spoke_by_name.get(n, True)]
        if not rankable:
            rep.no_ladder.append(path)
            continue
        if not chain:
            # V4, at the path level: the check spoke on NOTHING here.
            rep.upstream_only.append(path)
            continue
        if all(by_name[n] == Severity.PASS for n in chain):
            # V2, CORRECTED. (Read over the SPOKEN rungs: a path where the
            # check itself passed everything is indifferent, whatever the
            # pipeline said around it.) This used to read a PASS `shape_preserving` as
            # "nothing to see at this path" and discard the ladder AFTER
            # computing it. A PASS base means the LEAST-degraded rung did not
            # move, which says nothing about the seven below it; a path is
            # vacuous only when EVERY present rung passes.
            rep.indifferent.append(path)
            continue
        if not any(by_name[n] != Severity.PASS for n in chain):
            # V4. Every non-PASS rung here was decided UPSTREAM of the check
            # under test (a parse boundary, a loader), so the comparison is the
            # pipeline against itself and says nothing about the check.
            # Counting it as probed is how a sweep reports "clean" for a check
            # that was inert -- this module's own defect class, wearing the
            # instrument's clothes.
            rep.upstream_only.append(path)
            continue
        probed += 1

        # MR-1 / MR-2 in ONE pass down the ordered ladder, against a RUNNING
        # MAXIMUM: "no present rung is softer than any LESS-DEGRADED present
        # rung". Naming the running max as the base points the reader at the
        # strongest prior evidence rather than at whichever rung happened to be
        # first, and it keeps the report linear in the ladder instead of
        # quadratic in its pairs.
        worst_name: str | None = None
        worst_sev: Severity | None = None
        for rung in ladder:
            sev = by_name.get(rung.name)
            if sev is None:
                continue  # quarantined: no verdict, so no relation
            if not spoke_by_name.get(rung.name, True):
                # V4, at the LEG level. This verdict came from upstream of the
                # check under test, so it neither raises the running maximum
                # nor is measured against it: a comparison counts only if BOTH
                # rungs were spoken by the check. Deciding this from the base
                # leg's flag alone let a loader's REJECT be attributed to the
                # check and manufactured softenings out of it.
                continue
            if rung.presence == ABSENT:
                # MR-2. Row 20's first clause is "absent may pass", so this is
                # never a finding -- but an ABSENT rung that passes while a
                # less-degraded PRESENT one bites means every guard at this
                # path is bypassable by deletion, and that does not get to be
                # silence either.
                if (
                    sev == Severity.PASS
                    and worst_sev is not None
                    and worst_sev != Severity.PASS
                ):
                    _file(
                        rep,
                        declared,
                        used_declarations,
                        Finding(
                            tier=0,
                            relation="MR-2",
                            path=path,
                            rung=rung.name,
                            base_rung=worst_name,
                            base_severity=worst_sev,
                            rung_severity=sev,
                            detail=(
                                f"{rung.name} PASSES while {worst_name}="
                                f"{worst_sev.name} — every guard at this path "
                                f"is bypassable by deletion. Allowed by row 20 "
                                f"clause 1; declare it or it stays on the "
                                f"report."
                            ),
                        ),
                    )
                continue
            if sev == Severity.ERROR_CRASH:
                continue  # never an MR-1 finding; see rep.crashes
            if worst_sev is not None and sev < worst_sev:
                _file(
                    rep,
                    declared,
                    used_declarations,
                    Finding(
                        tier=1 if sev == Severity.PASS else 2,
                        relation="MR-1",
                        path=path,
                        rung=rung.name,
                        base_rung=worst_name,
                        base_severity=worst_sev,
                        rung_severity=sev,
                        detail=(
                            f"degrading further SOFTENED the verdict: "
                            f"{worst_name}={worst_sev.name} but "
                            f"{rung.name}={sev.name}"
                        ),
                    ),
                )
            if worst_sev is None or sev > worst_sev:
                worst_name, worst_sev = rung.name, sev


    stale = set(declared) - used_declarations
    if stale:
        # Say what ELSE is on the report. A stale waiver very often means the
        # transition it named got WORSE rather than went away, and raising
        # without saying so would hide a live finding behind a config error.
        live = "; ".join(
            f"{list(f.path)} {f.rung} {f.relation} "
            f"{f.base_severity.name}->{f.rung_severity.name}"
            for f in rep.findings + rep.disclosures
        )
        raise DegradationConfigError(
            f"stale declarations matching nothing: {sorted(map(repr, stale))} — "
            f"the behaviour they excused is gone, and a live waiver over absent "
            f"behaviour silently covers the NEXT defect at that path. "
            + (
                f"UNEXCUSED on this same run: {live}. A waiver goes stale when "
                f"the transition it named got WORSE, not only when it went away."
                if live
                else "Nothing else is on the report."
            )
        )

    census: dict = {}
    for leg in rep.legs:
        for code in leg.reasons or ("<PASS>",):
            census[code] = census.get(code, 0) + 1
    rep.reason_census = dict(sorted(census.items(), key=lambda kv: -kv[1]))
    check_spoke = any(
        leg.spoke and leg.severity != Severity.PASS for leg in rep.legs
    )

    rep.counts = {
        "paths": len(all_paths),
        "paths_probed": probed,
        "paths_indifferent_v2": len(rep.indifferent),
        "paths_no_ladder_v3": len(rep.no_ladder),
        "paths_upstream_only_v4": len(rep.upstream_only),
        "legs": len(rep.legs),
        "distinct_runs": len(cache),
        "findings_tier1": sum(1 for f in rep.findings if f.tier == 1),
        "findings_tier2": sum(1 for f in rep.findings if f.tier == 2),
        "disclosures": len(rep.disclosures),
        "crashes": len(rep.crashes),
        "quarantined": len(rep.quarantined),
        "declared_limits": len(rep.declared_limits),
    }
    rep.vacuous = probed == 0 or not check_spoke
    # AUDIT #8: `ok` used to ignore disclosures entirely, so a run in which
    # EVERY guard was bypassable by deletion returned ok=True and said so only
    # in human-readable text. That is "present-but-unparseable shares a return
    # value with absent" reproduced inside the instrument. An undeclared
    # disclosure now blocks ok; declaring it (with a reason) clears it, which
    # is what "declare it or it stays on the report" has to mean mechanically.
    # A quarantined leg is EVIDENCE NOT COLLECTED. Letting it pass as green
    # would be the instrument committing the defect it hunts: an input the
    # target could not answer for, scored as an answer.
    rep.ok = (
        not rep.findings
        and not rep.disclosures
        and not rep.quarantined
        and not rep.vacuous
    )
    return rep


def format_report(rep: Report) -> str:
    lines = [
        f"baseline={rep.baseline.name}  ok={rep.ok}  vacuous={rep.vacuous}",
        "counts: " + ", ".join(f"{k}={v}" for k, v in rep.counts.items()),
    ]
    if rep.vacuous:
        lines.append(
            "VACUOUS -- NOT a pass. Either no path had a rejecting "
            "shape_preserving rung (MR-1 trivially true everywhere), or the "
            "check under test never spoke on a non-PASS leg (V4: every "
            "rejection came from upstream of it)."
        )
    if rep.reason_census:
        lines.append(
            "reason census: "
            + ", ".join(f"{k}={v}" for k, v in list(rep.reason_census.items())[:8])
        )
    for f in rep.findings:
        lines.append(
            f"  [TIER-{f.tier}] {f.relation} at {list(f.path)!r} rung={f.rung}: "
            f"{f.detail}"
        )
    for d in rep.disclosures:
        lines.append(
            f"  [disclosure] {d.relation} at {list(d.path)!r} rung={d.rung}: "
            f"{d.detail}"
        )
    for f, reason in rep.declared_limits:
        lines.append(
            f"  [declared] {f.relation} at {list(f.path)!r} rung={f.rung}: {reason}"
        )
    for path, rung, label in rep.quarantined:
        lines.append(
            f"  [quarantined] {list(path)!r} rung={rung}: run() RAISED, so this "
            f"leg produced no verdict and no relation was computed against it "
            f"— evidence not collected, never a green: {label}"
        )
    for path, rung, reasons in rep.crashes:
        lines.append(
            f"  [crash] {list(path)!r} rung={rung}: the check CRASHED on "
            f"producer-controlled bytes — outranks REJECT so it is not an MR-1 "
            f"softening, but a crashed checker is not a disagreement: {reasons}"
        )
    for p in rep.indifferent:
        lines.append(
            f"  [V2 indifferent] {list(p)!r}: a shape-preserving mutation did "
            f"not move the verdict — MR-1 vacuous here, and the indifference is "
            f"itself a probe_check-class finding"
        )
    return "\n".join(lines)


def exit_code_adapter(
    invoke: Callable,
    *,
    pass_codes: frozenset = frozenset({0}),
    reject_codes: frozenset = frozenset({1}),
    error_codes: frozenset = frozenset({2}),
    crash_detector: Callable | None = None,
) -> Callable:
    """A CLI target: map an exit code to a severity.

    `invoke(root) -> (exit_code, stderr_text)`. The caller writes the mutated
    root wherever the tool expects it and runs the tool.

    This is the adapter a FOREIGN target uses — it needs no import, no source,
    and no knowledge of the tool's semantics, only its exit-code contract. That
    contract is the ONE thing the prober must state, and getting it wrong is the
    likeliest way to manufacture a false finding, so an unmapped code RAISES
    rather than being bucketed by a default.

    `spoke` is False for an unmapped-but-declared "harness" code, so a run where
    the tool never ran is VACUOUS (V4) rather than clean.
    """

    def run(root: Any):
        code, err = invoke(root)
        if code in pass_codes:
            return Severity.PASS, (), True
        if code in reject_codes:
            return Severity.REJECT, (f"exit={code}",), True
        if code in error_codes:
            # An exit code CANNOT distinguish a clean could-not-conclude from a
            # crash, and the two sit on opposite sides of REJECT. Supply
            # `crash_detector` (e.g. "Traceback" in stderr) or accept that
            # every could-not-conclude is scored as the CLEAN kind, which is
            # the direction that over-reports softenings rather than hiding
            # them. Stated, not defaulted silently.
            crashed = bool(crash_detector(err)) if crash_detector else False
            sev = Severity.ERROR_CRASH if crashed else Severity.ERROR_CLEAN
            return sev, (f"exit={code}", err[:120]), True
        raise DegradationConfigError(
            f"exit code {code} is in none of pass={sorted(pass_codes)} "
            f"reject={sorted(reject_codes)} error={sorted(error_codes)} — "
            f"state the tool's contract rather than letting a default bucket "
            f"an unknown code into a verdict. stderr: {err[:200]!r}"
        )

    return run
