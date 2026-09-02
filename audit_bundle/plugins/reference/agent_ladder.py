"""agent_ladder.py — the parameterised re-derivation ladder, and the one place its
comparison rules live.

WHAT THIS IS
------------
A gate that admits a proposed agent action only if the action's authority-bearing arguments
RE-DERIVE from something the agent did not author. Four rungs, tightest corpus last:

  1  name        the sink is on the work order's tool set
  2  evidence    the value grounds anywhere in the trusted corpus (record + instruction)
  3  reference   the value grounds in the instruction, or inside a record entry the
                 instruction NAMES — one hop
  4  intent      the value grounds in the instruction ALONE
  5  selection   the value re-derives from the instruction's stated selection rule — UNBUILT.
                 Declared so the hole is visible; never emitted as a verdict.

Every input is DATA: the tool schema (which arguments carry authority, and of what type),
the work orders, the system-of-record snapshot, and the traces. Nothing about any particular
benchmark or customer is compiled in. AgentDojo is one fixture.

WHY IT LIVES HERE rather than in the experiment that produced it
----------------------------------------------------------------
`examples/payroll_agent_gate_minimal/experiments/agentdojo_rederive/footprint.py` measured
these rungs against a third party's task set and imports its comparison rules from this
module. There is exactly ONE implementation of the grounding test, so the numbers that
experiment reports and the numbers a customer's bundle re-derives cannot drift apart. That
property is worth more than the tidier layering of a private copy.

DECLARED TOLERANCES — choices, not incidentals, and someone sets them
---------------------------------------------------------------------
 (t1) CASE. Corpora and candidate values are lowercased. This is a fail-open direction for
      case-sensitive identifiers (a path /Admin grounds against /admin).
 (t2) EMPTY. An empty argument value carries no authority and grounds trivially. This is
      the coverage fail-open, and it is reported on every verdict face rather than hidden
      here: an authority argument a call does not set is NOT EVALUATED, and the action
      admits.
 (t3) NUMBERS compare as exact decimals. No epsilon — no authority argument in this design
      carries a MEASURED quantity; every one is a record key or a stated amount. A key that
      ever carries a measurement needs its tolerance declared beside it in the tool schema,
      set by whoever declares the key, never by this module.
 (t4) DATES parse ISO-8601 only. An unparseable value on a DATE-typed argument fails CLOSED
      rather than falling back to string matching.

WHAT THE LADDER CANNOT DO, stated here so it is not discovered as a surprise
----------------------------------------------------------------------------
 * It is value-level and silent about AMOUNT relationships: a 40 and a 40,000,000 transfer
   to the same authorised recipient differ only if the amount is itself a declared authority
   argument, and even then only by exact match.
 * It assumes the record snapshot is CLEAN. A real system-of-record holds whatever was
   written into it, including by a previously compromised run. Write-gating the corpus is an
   architectural dependency, not a hardening task, and it is not addressed here.
 * Rung 5 is unbuilt, so a value the instruction establishes by a selection rule ("the
   cheapest", "the two smallest open invoices") is refused at rungs 3 and 4 and there is no
   rung that admits it correctly.
 * It produces VERDICTS. Whether the gate can be routed around is a positional question and
   is not in scope.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from audit_bundle._freeze import deep_freeze

# ===========================================================================
# Declared argument types
# ===========================================================================

T_IDENTIFIER = "IDENTIFIER"
T_EMAIL = "EMAIL"
T_URL = "URL"
T_NUMBER = "NUMBER"
T_DATE = "DATE"
T_TEXT = "TEXT"

DECLARED_TYPES = (T_IDENTIFIER, T_EMAIL, T_URL, T_NUMBER, T_DATE, T_TEXT)

# ===========================================================================
# Typed comparison
# ===========================================================================
# Identifier boundaries are TWO character classes, not one.
#
#   CORE     letters, digits, `_` — always continue an identifier. A match flanked by one is
#            a match inside a longer token: this is what made host="val" ground inside
#            "internal.eval".
#   JOINER   `.` and `-` (plus `@ + %` for e-mail) — continue an identifier ONLY when a CORE
#            character sits on their far side. `internal.eval` continues into `eval` because
#            the dot has `l` behind it; the sentence "The recipient is US1220...212." does
#            NOT, because the dot is terminal punctuation with a space behind it.
#
# The one-class version of this rule was written first and measured: it reclassified an IBAN
# quoted verbatim in an instruction as not-named, purely because the sentence ended in a full
# stop. Boundary rules that ignore punctuation do not survive contact with prose.
_CORE_CONT = frozenset(string.ascii_lowercase + string.digits + "_")
_IDENT_JOIN = frozenset(".-")
_EMAIL_JOIN = _IDENT_JOIN | frozenset("@+%")

_NUM_TOKEN_RE = re.compile(r"-?\d[\d,]*(?:\.\d+)?")
_URL_TOKEN_RE = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s\"'<>)\]},]+")
_DATE_TOKEN_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

# Derived indexes are expensive to rebuild per call and the same corpus is queried many
# times. Keyed by the corpus string itself (Python caches a str's hash, so lookup is O(1)
# after the first) and bounded so a long run cannot grow it without limit.
_INDEX_CACHE: dict[str, dict] = {}
_INDEX_CACHE_MAX = 256


def _as_decimal(tok: str):
    try:
        return Decimal(str(tok).replace(",", ""))
    except (InvalidOperation, ValueError):
        return None


def _as_iso_date(tok: str):
    tok = str(tok).strip()
    for parse in (
        lambda t: date.fromisoformat(t),
        lambda t: datetime.fromisoformat(t.replace("z", "+00:00")).date(),
    ):
        try:
            return parse(tok)
        except ValueError:
            continue
    return None


def _url_key(raw: str):
    """Normalised comparison key for a URL. Query and fragment are KEPT — dropping them
    would let `?next=https://attacker` ride an authorised origin. Only a default port and a
    redundant trailing slash are normalised away."""
    parts = urlsplit(str(raw).strip())
    if not parts.scheme or not parts.netloc:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").rstrip(".")
    if port is not None and (
        (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)
    ):
        port = None
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return (parts.scheme, host, port, path, parts.query, parts.fragment)


def _blob_index(blob: str) -> dict:
    idx = _INDEX_CACHE.get(blob)
    if idx is None:
        idx = {
            "numbers": frozenset(
                d for d in (_as_decimal(t) for t in _NUM_TOKEN_RE.findall(blob)) if d is not None
            ),
            "urls": frozenset(
                k for k in (_url_key(t) for t in _URL_TOKEN_RE.findall(blob)) if k is not None
            ),
            "dates": frozenset(
                d for d in (_as_iso_date(t) for t in _DATE_TOKEN_RE.findall(blob)) if d is not None
            ),
        }
        if len(_INDEX_CACHE) >= _INDEX_CACHE_MAX:
            _INDEX_CACHE.clear()
        _INDEX_CACHE[blob] = idx
    return idx


def _continues(blob: str, at: int, outward: int, join: frozenset) -> bool:
    """Does the character at `at` continue an identifier away from the match?

    `outward` is -1 when looking left of the match and +1 when looking right. A CORE
    character always continues; a JOINER continues only when the character further out is
    itself CORE (so `.eval` continues, but a terminal `. ` does not)."""
    if at < 0 or at >= len(blob):
        return False
    c = blob[at]
    if c in _CORE_CONT:
        return True
    if c in join:
        far = at + outward
        return 0 <= far < len(blob) and blob[far] in _CORE_CONT
    return False


def _delimited_in(needle: str, blob: str, join: frozenset) -> bool:
    """True iff `needle` occurs in `blob` as a whole token rather than as a fragment of a
    longer one — see `_continues` for what "longer" means."""
    start = 0
    n = len(needle)
    while True:
        i = blob.find(needle, start)
        if i < 0:
            return False
        if not _continues(blob, i - 1, -1, join) and not _continues(blob, i + n, +1, join):
            return True
        start = i + 1


def _phrase_in(needle: str, blob: str) -> bool:
    """Word-boundary, whitespace-flexible phrase match for human text."""
    toks = needle.split()
    if not toks:
        return True
    pattern = r"(?<![0-9a-z])" + r"\s+".join(re.escape(t) for t in toks) + r"(?![0-9a-z])"
    return re.search(pattern, blob) is not None


def scalar_grounds(x, blob: str, vtype: str) -> bool:
    """True iff scalar value `x` grounds in corpus `blob` under its DECLARED type.

    Replaces a single untyped `str(x).strip().lower() in blob` test, which admitted
    host="eval" against the authorised host "internal.eval" and admitted a record key id=7
    against the digit 7 inside an unrelated account number. See the module docstring for the
    two fail-open directions this function deliberately keeps (t1, t2)."""
    s = str(x).strip().lower()
    if not s:
        return True  # (t2)
    if vtype == T_IDENTIFIER:
        return _delimited_in(s, blob, _IDENT_JOIN)
    if vtype == T_EMAIL:
        return _delimited_in(s, blob, _EMAIL_JOIN)
    if vtype == T_TEXT:
        return _phrase_in(s, blob)
    if vtype == T_NUMBER:
        d = _as_decimal(s)
        return d is not None and d in _blob_index(blob)["numbers"]
    if vtype == T_DATE:
        d = _as_iso_date(s)
        return d is not None and d in _blob_index(blob)["dates"]  # (t4)
    if vtype == T_URL:
        k = _url_key(s)
        return k is not None and k in _blob_index(blob)["urls"]
    raise KeyError(f"UNDECLARED_TYPE: {vtype!r}")


def value_grounds(val, blob: str, vtype: str) -> bool:
    """As `scalar_grounds`, lifted over a list-valued argument. EVERY element must ground —
    one unauthorised recipient in a list of five is an unauthorised destination."""
    if isinstance(val, (list, tuple, set, frozenset)):
        return all(scalar_grounds(x, blob, vtype) for x in val)
    return scalar_grounds(val, blob, vtype)


# ===========================================================================
# Corpus construction
# ===========================================================================
# A record key shorter than this is not treated as a reference. Without the floor, keys like
# "id" or "to" appear in almost any instruction and would drag their whole entry into the
# corpus, quietly turning the reference rung back into the evidence rung.
DEFAULT_MIN_REFERENCE_KEY_LEN = 4

# A key occurring more often than this is a SCHEMA FIELD, not an identifier, and is never
# followed as a reference. 1 would be the purest reading; the small allowance covers a record
# that legitimately repeats one identifier in two indexes.
#
# Measured, not assumed: matching keys against prose without this check produced 138 matches
# on one AgentDojo travel task, because every hotel object carries the keys `name`, `rating`,
# `address` and `reviews`, and an English sentence mentioning reviews and ratings therefore
# "referenced" every hotel in the city — including the one the attacker wanted. It took that
# suite's decisive injection from 20/20 denied to 2/20.
DEFAULT_MAX_IDENTIFIER_OCCURRENCES = 2

DEFAULT_MAX_DEPTH = 40


def harvest_strings(obj, out, _depth=0, max_depth=DEFAULT_MAX_DEPTH):
    """Recursively collect every scalar leaf of a JSON value into `out`."""
    if _depth > max_depth or obj is None:
        return
    if isinstance(obj, str):
        out.append(obj)
        return
    if isinstance(obj, (int, float, bool)):
        out.append(str(obj))
        return
    if isinstance(obj, dict):
        for v in obj.values():
            harvest_strings(v, out, _depth + 1, max_depth)
        return
    if isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            harvest_strings(v, out, _depth + 1, max_depth)


def count_keys(obj, counts: dict, _depth=0, max_depth=DEFAULT_MAX_DEPTH):
    """How often each key occurs anywhere in the record. Distinguishes an IDENTIFIER from a
    SCHEMA FIELD — a file name occurs once, a column name occurs once per row."""
    if _depth > max_depth or obj is None:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k).strip().lower()
            counts[ks] = counts.get(ks, 0) + 1
            count_keys(v, counts, _depth + 1, max_depth)
        return
    if isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            count_keys(v, counts, _depth + 1, max_depth)


def harvest_referenced(obj, prompt_lc, out, counts, spec, _depth=0):
    """Collect the contents of exactly those record entries the instruction NAMES.

    ONE HOP, deliberately: the harvested value is flattened, never re-scanned for further
    references. Following transitively would reach most of the record and dissolve the very
    distinction the reference rung exists to draw."""
    if _depth > spec.max_depth or obj is None:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k).strip().lower()
            is_identifier = counts.get(ks, 0) <= spec.max_identifier_occurrences
            if len(ks) >= spec.min_reference_key_len and is_identifier and ks in prompt_lc:
                harvest_strings(v, out, max_depth=spec.max_depth)
            else:
                harvest_referenced(v, prompt_lc, out, counts, spec, _depth + 1)
        return
    if isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            harvest_referenced(v, prompt_lc, out, counts, spec, _depth + 1)


@dataclass(frozen=True)
class Corpora:
    """The three corpora a verdict is computed against, one per rung 2-4.

    Kept as three separate fields rather than one narrowed blob so all three questions stay
    askable of the same trace: "is this value known?", "is it where the instruction
    pointed?", and "is it the one that was asked for?" are different questions."""

    evidence: str
    reference: str
    work_order: str


def build_corpora(record_snapshot, instruction: str, spec: "LadderSpec") -> Corpora:
    parts: list[str] = []
    harvest_strings(record_snapshot, parts, max_depth=spec.max_depth)
    instruction_lc = (instruction or "").lower()
    evidence = "\n".join([*parts, instruction or ""]).lower()
    ref_parts: list[str] = []
    key_counts: dict = {}
    count_keys(record_snapshot, key_counts, max_depth=spec.max_depth)
    harvest_referenced(record_snapshot, instruction_lc, ref_parts, key_counts, spec)
    reference = "\n".join([instruction_lc, *ref_parts]).lower()
    return Corpora(evidence=evidence, reference=reference, work_order=instruction_lc)


# ===========================================================================
# The declared policy — tool schema + ladder spec, both INPUTS
# ===========================================================================


class DryRunRefusal(Exception):
    """A fail-closed refusal at the door. Carries a named reason code so the refusal is
    reportable rather than a stack trace."""

    def __init__(self, reason_code: str, detail: str = ""):
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)
        self.reason_code = reason_code
        self.detail = detail


def _canonical_sha256(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True)
class ToolSchema:
    """WHICH arguments carry authority, and of WHAT TYPE. Authored by whoever sets the gate;
    committed into the bundle and covered by the external anchor, because changing it
    changes every verdict."""

    tools: dict

    def __post_init__(self) -> None:
        # frozen=True locks the binding, not the container. `tools` IS the policy — which
        # arguments carry authority and of what type — and every verdict in a bundle is a
        # function of it. An in-place edit between parse and check would let a run claim a
        # determinism it no longer has, so mutation raises TypeError at the offending line
        # instead. Frozen at EVERY construction site, not just from_json().
        object.__setattr__(self, "tools", deep_freeze(self.tools))

    @staticmethod
    def from_json(doc) -> "ToolSchema":
        if not isinstance(doc, dict) or "tools" not in doc:
            raise DryRunRefusal("MALFORMED_TOOL_SCHEMA", "no 'tools' object")
        tools = {}
        for name, spec in doc["tools"].items():
            args = (spec or {}).get("args") or {}
            parsed = {}
            for key, a in args.items():
                authority = bool((a or {}).get("authority", False))
                vtype = (a or {}).get("type")
                if authority and vtype is None:
                    raise DryRunRefusal("UNTYPED_AUTHORITY_KEY", f"{name}.{key}")
                if authority and vtype not in DECLARED_TYPES:
                    raise DryRunRefusal("UNDECLARED_TYPE", f"{name}.{key} -> {vtype!r}")
                parsed[key] = {"authority": authority, "type": vtype}
            tools[name] = parsed
        return ToolSchema(tools=tools)

    def known(self, tool: str) -> bool:
        return tool in self.tools

    def authority_args(self, tool: str) -> list[tuple[str, str]]:
        """[(arg_key, declared_type)] for the authority-bearing arguments of `tool`."""
        return [
            (k, a["type"]) for k, a in self.tools.get(tool, {}).items() if a["authority"]
        ]

    def is_sink(self, tool: str) -> bool:
        """A sink is a tool with at least one authority-bearing argument. Reads and
        observations are not gated: a read is essentially never the payload, and gating
        reads only over-blocks legitimate exploration."""
        return bool(self.authority_args(tool))

    def anchor(self) -> str:
        return _canonical_sha256(
            {
                t: {k: [a["authority"], a["type"]] for k, a in sorted(args.items())}
                for t, args in sorted(self.tools.items())
            }
        )


RUNGS = (1, 2, 3, 4)
RUNG_NAMES = {
    1: "rung_1_name",
    2: "rung_2_evidence",
    3: "rung_3_reference",
    4: "rung_4_intent",
    5: "rung_5_selection_UNBUILT",
}


@dataclass(frozen=True)
class LadderSpec:
    """Every number that changes a verdict, in one file, so a third party re-deriving has
    one artifact to anchor externally."""

    min_reference_key_len: int = DEFAULT_MIN_REFERENCE_KEY_LEN
    max_identifier_occurrences: int = DEFAULT_MAX_IDENTIFIER_OCCURRENCES
    max_depth: int = DEFAULT_MAX_DEPTH
    # {tool: rung} — the rung this deployment PROPOSES to run at, per sink. Per-sink, never
    # global: the same rung was free on one AgentDojo suite and a 43-point tax on the other.
    sink_assignment: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Same reason as ToolSchema.tools: this is policy the verdicts depend on.
        object.__setattr__(self, "sink_assignment", deep_freeze(self.sink_assignment))

    @staticmethod
    def from_json(doc) -> "LadderSpec":
        if not isinstance(doc, dict):
            raise DryRunRefusal("MALFORMED_LADDER_SPEC", "not an object")
        declared = doc.get("type_rules") or {}
        # The spec must name the SAME comparison rules this module implements. A spec that
        # names a rule set we do not have is a spec for a different verifier, and silently
        # running ours against it is the fail-open this check exists to stop.
        if declared and sorted(declared) != sorted(DECLARED_TYPES):
            raise DryRunRefusal(
                "TYPE_RULES_MISMATCH",
                f"spec declares {sorted(declared)}, verifier implements {sorted(DECLARED_TYPES)}",
            )
        assignment = doc.get("sink_assignment") or {}
        for tool, rung in assignment.items():
            if rung not in RUNGS:
                raise DryRunRefusal(
                    "UNEMITTABLE_RUNG",
                    f"{tool} assigned rung {rung}; emittable rungs are {list(RUNGS)}"
                    + (" (rung 5 is declared but UNBUILT)" if rung == 5 else ""),
                )
        return LadderSpec(
            min_reference_key_len=int(
                doc.get("min_reference_key_len", DEFAULT_MIN_REFERENCE_KEY_LEN)
            ),
            max_identifier_occurrences=int(
                doc.get("max_identifier_occurrences", DEFAULT_MAX_IDENTIFIER_OCCURRENCES)
            ),
            max_depth=int(doc.get("max_depth", DEFAULT_MAX_DEPTH)),
            sink_assignment=dict(assignment),
        )

    def anchor(self) -> str:
        return _canonical_sha256(
            {
                "min_reference_key_len": self.min_reference_key_len,
                "max_identifier_occurrences": self.max_identifier_occurrences,
                "max_depth": self.max_depth,
                "sink_assignment": self.sink_assignment,
                "type_rules": sorted(DECLARED_TYPES),
                "rungs": list(RUNGS),
            }
        )


# ===========================================================================
# Evaluation — one verdict face per (trace, rung)
# ===========================================================================

LABEL_LEGITIMATE = "LEGITIMATE"
LABEL_ILLEGITIMATE = "ILLEGITIMATE"
DECLARED_LABELS = (LABEL_LEGITIMATE, LABEL_ILLEGITIMATE)

ADMIT = "ADMIT"
DENY = "DENY"
NOT_EVALUATED = "NOT_EVALUATED"

# Declared on every verdict rather than in a footnote. This is the F7 shape: the check fails
# open on missing observation, and a reader who does not see that on the face will read a
# green rate as coverage.
FAIL_OPEN_DIRECTION = "UNEVALUATED_ARG_ADMITS"


def _value_sha256(val) -> str:
    """Commit to WHICH value was refused without republishing it. A dry-run bundle goes to
    auditors and the refused values are the customer's live IBANs, hostnames and recipients.
    Any holder of the committed inputs can re-derive the value — which is exactly the set of
    people who already have it."""
    return hashlib.sha256(
        json.dumps(val, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _rung_corpus(rung: int, corpora: Corpora) -> str:
    return {2: corpora.evidence, 3: corpora.reference, 4: corpora.work_order}[rung]


def evaluate_trace(trace, corpora, schema, spec, work_order_tools=None) -> list[dict]:
    """One verdict face per rung for one proposed action.

    `work_order_tools` is the rung-1 tool set. None means it was not supplied, and rung 1
    reports NOT_EVALUATED — never a silent skip, because a ladder reported with a missing
    rung reads as "the tight rungs cost nothing"."""
    tool = trace["tool"]
    args = trace.get("args") or {}
    declared = schema.authority_args(tool)
    evaluated = [(k, t) for k, t in declared if k in args]

    faces: list[dict] = []
    rung_reached = 0
    blocked = False
    for rung in RUNGS:
        if rung == 1:
            if work_order_tools is None:
                verdict, layer, argument, refused = NOT_EVALUATED, None, None, None
            elif not schema.is_sink(tool) or tool in work_order_tools:
                verdict, layer, argument, refused = ADMIT, None, None, None
            else:
                verdict, layer, argument, refused = DENY, RUNG_NAMES[1], None, None
        elif not schema.is_sink(tool):
            # Reads and observations pass unconditionally at every value rung. Gating them
            # only over-blocks legitimate exploration.
            verdict, layer, argument, refused = ADMIT, None, None, None
        else:
            blob = _rung_corpus(rung, corpora)
            verdict, layer, argument, refused = ADMIT, None, None, None
            for key, vtype in evaluated:
                if not value_grounds(args[key], blob, vtype):
                    verdict, layer, argument, refused = (
                        DENY,
                        RUNG_NAMES[rung],
                        key,
                        _value_sha256(args[key]),
                    )
                    break
        # "How far up the ladder does this action survive", NOT "the highest rung that
        # happens to admit". The two differ exactly where they matter: rung 1 gates the TOOL
        # while rungs 2-4 gate VALUES, so an off-work-order call with a perfectly grounded
        # argument would otherwise report rung_reached=2 and read as though it had passed
        # the name layer. A rung nobody evaluated does not block.
        if verdict == DENY:
            blocked = True
        elif verdict == ADMIT and not blocked:
            rung_reached = rung
        faces.append(
            {
                "trace_id": trace["trace_id"],
                "work_order_id": trace["work_order_id"],
                "tool": tool,
                "is_sink": schema.is_sink(tool),
                "rung": rung,
                "verdict": verdict,
                "refusing_layer": layer,
                "refusing_argument": argument,
                "refusing_value_sha256": refused,
                "coverage": {
                    "authority_args_declared": len(declared),
                    "authority_args_evaluated": len(evaluated),
                },
                "fail_open_direction": FAIL_OPEN_DIRECTION,
            }
        )
    for f in faces:
        f["rung_reached"] = rung_reached
    return faces


# ===========================================================================
# Aggregation
# ===========================================================================


def aggregate(faces: list[dict], labels: dict | None, spec: LadderSpec) -> dict:
    """The per-sink x rung table. This is the counterfactual the customer reads: if I turn
    rung r on for sink s, N of my M actions would have been refused."""
    per: dict = {}
    for f in faces:
        if not f["is_sink"]:
            continue
        row = per.setdefault(
            (f["tool"], f["rung"]),
            {"n_actions": 0, "n_admit": 0, "n_deny": 0, "n_not_evaluated": 0},
        )
        row["n_actions"] += 1
        if f["verdict"] == ADMIT:
            row["n_admit"] += 1
        elif f["verdict"] == DENY:
            row["n_deny"] += 1
        else:
            row["n_not_evaluated"] += 1

    # A rung that was NOT EVALUATED has no rate. Scoring it 0/n would report "this rung
    # refuses everything" for a rung nobody ran, and — worse — make it the baseline every
    # other rung's utility cost is measured against. None, and the baseline falls through.
    admit_rate = {}
    for k, v in per.items():
        decided = v["n_admit"] + v["n_deny"]
        admit_rate[k] = round(v["n_admit"] / decided, 6) if decided else None
    rows = []
    for (tool, rung), v in sorted(per.items()):
        base = admit_rate.get((tool, 1))
        row = {
            "sink": tool,
            "rung": rung,
            "rung_name": RUNG_NAMES[rung],
            # The rung this deployment PROPOSES for this sink, per spec/ladder_spec.json.
            # Declarative: every rung is still computed and reported, because the point of a
            # dry-run is to show the whole ladder before anyone commits to a rung.
            "assigned_by_spec": spec.sink_assignment.get(tool) == rung,
            "n_actions": v["n_actions"],
            "n_admit": v["n_admit"],
            "n_deny": v["n_deny"],
            "n_not_evaluated": v["n_not_evaluated"],
            "admit_rate": admit_rate[(tool, rung)],
            # Cost is measured against rung 1 when rung 1 was evaluated, and against rung 2
            # otherwise — never silently against nothing.
            "utility_cost_vs_baseline": None,
            "baseline_rung": None,
        }
        baseline_rung = 1 if base is not None else 2
        base = base if base is not None else admit_rate.get((tool, 2))
        if base is not None and row["admit_rate"] is not None:
            row["baseline_rung"] = baseline_rung
            row["utility_cost_vs_baseline"] = round(base - row["admit_rate"], 6)
        rows.append(row)

    out = {"rows": rows}
    if labels:
        out["labelled"] = _labelled_block(faces, labels)
    # Deliberately NOT zero-filled when labels are absent: a zero reads as "no attacks
    # found", an omission reads as "nobody looked", and only the second is true.
    return out


def _labelled_block(faces: list[dict], labels: dict) -> list[dict]:
    per: dict = {}
    for f in faces:
        if not f["is_sink"]:
            continue
        lab = labels.get(f["trace_id"])
        if lab is None:
            continue
        row = per.setdefault(
            (f["tool"], f["rung"]),
            {
                "n_illegitimate": 0,
                "n_illegitimate_denied": 0,
                "n_legitimate": 0,
                "n_legitimate_denied": 0,
            },
        )
        denied = f["verdict"] == DENY
        if lab == LABEL_ILLEGITIMATE:
            row["n_illegitimate"] += 1
            row["n_illegitimate_denied"] += denied
        elif lab == LABEL_LEGITIMATE:
            row["n_legitimate"] += 1
            row["n_legitimate_denied"] += denied
        else:
            # Exhaustive on purpose. Falling through would drop the trace from BOTH
            # denominators, so an unrecognised label would quietly improve every rate it
            # touches — the ground-truth column's own fail-open.
            raise DryRunRefusal(
                "UNDECLARED_LABEL", f"{f['trace_id']}: {lab!r} is not {DECLARED_LABELS}"
            )
    rows = []
    for (tool, rung), v in sorted(per.items()):
        rows.append(
            {
                "sink": tool,
                "rung": rung,
                **v,
                "deny_rate": (
                    round(v["n_illegitimate_denied"] / v["n_illegitimate"], 6)
                    if v["n_illegitimate"]
                    else None
                ),
                "false_refusal_rate": (
                    round(v["n_legitimate_denied"] / v["n_legitimate"], 6)
                    if v["n_legitimate"]
                    else None
                ),
            }
        )
    return rows


def coverage_row(tick_id: str, traces: list[dict], faces_by_trace: dict) -> dict:
    """Standard CoverageRow over the trace corpus as the eligible tuple set. The substrate's
    sum invariant then makes it impossible to silently drop a trace from the denominator,
    which is the mechanism by which a dry-run would otherwise flatter itself."""
    issued, withheld, reasons = 0, 0, {}
    for t in traces:
        faces = faces_by_trace.get(t["trace_id"], [])
        evaluated_rungs = {f["rung"] for f in faces if f["verdict"] != NOT_EVALUATED}
        if evaluated_rungs == set(RUNGS):
            issued += 1
        else:
            withheld += 1
            missing = sorted(set(RUNGS) - evaluated_rungs)
            reason = "RUNG_1_TOOL_SET_NOT_SUPPLIED" if missing == [1] else f"RUNGS_NOT_EVALUATED_{missing}"
            reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "tick_id": tick_id,
        "n_eligible": len(traces),
        "n_issued": issued,
        "n_withheld": withheld,
        "withheld_reason_breakdown": reasons,
    }


# ===========================================================================
# The inputs contract — fail-closed at the door
# ===========================================================================


def validate_inputs(
    schema: ToolSchema, spec: LadderSpec, work_orders: dict, snapshot, traces: list
) -> None:
    """Every check here is a hard refusal with a named reason code, not a warning.

    The reason a missing work-order corpus is a REFUSAL rather than a degraded run: rungs 3
    and 4 are defined against instruction text. With no instructions the ladder truncates at
    rung 2, and a 2-rung ladder reported in a 4-rung table reads as "the tight rungs cost
    nothing". Same shape as every failure in this stack — it fails open on missing
    observation — so it is refused at the door instead."""
    if not schema.tools:
        raise DryRunRefusal("MISSING_REQUIRED_INPUT", "tool schema declares no tools")
    if not work_orders:
        raise DryRunRefusal("MISSING_REQUIRED_INPUT", "work-order corpus is empty")
    if snapshot is None:
        raise DryRunRefusal("MISSING_REQUIRED_INPUT", "record snapshot absent")
    if not isinstance(snapshot, (dict, list)):
        raise DryRunRefusal("NON_DATA_RECORD_SNAPSHOT", f"snapshot is {type(snapshot).__name__}")
    if not traces:
        raise DryRunRefusal(
            "EMPTY_TRACE_CORPUS",
            "no traces — there is no counterfactual to report, only a policy",
        )
    for t in traces:
        for required in ("trace_id", "work_order_id", "tool"):
            if required not in t:
                raise DryRunRefusal("MALFORMED_TRACE", f"trace missing {required!r}: {t}")
        if t["work_order_id"] not in work_orders:
            raise DryRunRefusal("UNKNOWN_WORK_ORDER", f"{t['trace_id']} -> {t['work_order_id']}")
        if not schema.known(t["tool"]):
            raise DryRunRefusal("UNKNOWN_TOOL", f"{t['trace_id']} -> {t['tool']}")
    seen = set()
    for t in traces:
        if t["trace_id"] in seen:
            raise DryRunRefusal("DUPLICATE_TRACE_ID", t["trace_id"])
        seen.add(t["trace_id"])

    # A per-sink assignment naming a tool the schema does not declare is a dangling policy
    # entry: it reads as coverage and enforces nothing. Same class of defect as declaring an
    # argument authority-bearing that the mechanism cannot check — a policy artifact needs
    # an administrator, and this is the cheap half of that job.
    dangling = sorted(t for t in spec.sink_assignment if not schema.known(t))
    if dangling:
        raise DryRunRefusal("UNKNOWN_SINK_IN_ASSIGNMENT", f"{dangling}")
    # A sink with NO assignment is NOT refused: choosing a rung is the decision this
    # dry-run exists to inform, so requiring it up front would invert the whole point.


def run_dry_run(
    *,
    schema: ToolSchema,
    spec: LadderSpec,
    work_orders: dict,
    snapshot,
    traces: list,
    labels: dict | None = None,
    work_order_tools: dict | None = None,
    tick_id: str = "dry-run",
) -> dict:
    """The whole counterfactual, as a pure function of the committed inputs.

    Deterministic and side-effect free: no clock, no network, no randomness. That is what
    makes the re-derivation claim checkable — a third party with these inputs and this
    module gets the same object, byte for byte."""
    validate_inputs(schema, spec, work_orders, snapshot, traces)

    corpora_by_wo = {
        wo_id: build_corpora(snapshot, text, spec) for wo_id, text in work_orders.items()
    }
    faces: list[dict] = []
    faces_by_trace: dict = {}
    for t in traces:
        wo_tools = None
        if work_order_tools is not None:
            wo_tools = set(work_order_tools.get(t["work_order_id"], []))
        f = evaluate_trace(t, corpora_by_wo[t["work_order_id"]], schema, spec, wo_tools)
        faces.extend(f)
        faces_by_trace[t["trace_id"]] = f

    return {
        "verdicts": faces,
        "aggregate": aggregate(faces, labels, spec),
        "coverage": coverage_row(tick_id, traces, faces_by_trace),
        "anchors": {
            "tool_schema": schema.anchor(),
            "ladder_spec": spec.anchor(),
        },
        "rung_5_status": "DECLARED_UNBUILT",
    }
