"""total_binding — make *complete* the default and *partial* an explicit,
named, digest-recorded opt-out.

Substrate utility per ADR-substrate-total-binding (accepted 2026-07-18 after a
five-round adversarial two-model consult). The failure class it targets:
binding or covering a hand-enumerated subset of an object where the asserted
property is universal over the whole object, against an adversary who reads
the source and mutates exactly the omitted part.

Two ranks, deliberately distinct:

* RUNTIME MECHANICS — ``strict_loads``, ``to_plain``, ``total_digest``,
  ``closure``/``closure_digest``, and the completeness asserts. Each proves a
  property RELATIVE TO ITS ARGUMENTS. ``total_digest(projection_of(x))``
  binds the projection completely and re-opens the hole completely; the
  helper cannot see through a caller-built projection. Doctrine: bind the
  root object where it crosses the trust boundary; any narrowing between the
  root and the digest must be a recorded exclusion, never a projection.
* THE COMPLETENESS WITNESS — ``probe_check``: a test-time battery that
  mechanizes the adversary's move (mutate, duplicate, insert, delete,
  reorder, rekey, and type-substitute exactly what might be unbound) against
  the authoritative root and the real check.

What none of this enforces (the honest boundary, part of the accepted
decision): correctness of grounding (a completely-bound producer-controlled
object is a completely-bound story — independence needs an out-of-band
anchor); root authenticity (that the argument IS the trust-boundary object is
witnessed only by the probe + planted violations); expand/universe semantics
of caller callbacks; probe oracle limits (predicate fields need
caller-supplied oracles; a check can spuriously emit an expected reason;
probe-green on one fixture is not sensitivity on all inputs).

Codec version 1 (Python-side; cross-language byte-equivalence is explicitly
out of scope): strict exact-type plain JSON — only ``dict``/``list``/``str``/
``int``/``bool``/``float``/``None``, no subclasses, no tuples (json would
collide ``(1,2)`` with ``[1,2]``), finite floats only, str keys only, cycles
rejected, and the resource bounds below are normative — changing any bound is
a codec-version change, because two verifiers with different bounds accept
different objects.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import json
import math
from typing import Any, Callable, Iterable

# ---------------------------------------------------------------------------
# Codec version 1 — normative constants. A change to ANY value below is a
# codec-version change, not a tweak.
# ---------------------------------------------------------------------------
TB_CODEC_VERSION = 1
MAX_RAW_BYTES = 64 * 2**20  # strict_loads input cap, enforced BEFORE parsing
MAX_DEPTH = 100
MAX_NODES = 1_000_000
MAX_STR_CODEPOINTS = 2**20
MAX_CANON_BYTES = 128 * 2**20  # enforced incrementally during serialization
INT_LIMIT = 10**600  # value cap: env-independent (below CPython's guaranteed
# minimum str-conversion limit of 640 digits, so a passing value serializes
# under any legal int_max_str_digits configuration)
_INT_DIGITS = 600


class TotalBindingError(ValueError):
    """Codec violation, API misuse, or a failed completeness assert."""


class ProbeConfigError(TotalBindingError):
    """The probe configuration itself is unsound (vacuous fixture,
    nondeterministic check, stale/overlapping patterns, degenerate node with
    no supplied leg, drifted frozen inventory)."""


# ---------------------------------------------------------------------------
# Typed path tokens. A path is a tuple whose elements are exact str (dict
# key), exact int (list index), or ANY (every key/index at that level). No
# string grammar exists, so keys containing separators cannot collide.
# ---------------------------------------------------------------------------
class _Any:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ANY"


ANY = _Any()
PathToken = Any  # str | int | ANY
Path = tuple


def _valid_token(t: object) -> bool:
    return t is ANY or type(t) is str or (type(t) is int and not isinstance(t, bool))


def encode_token(t: object) -> dict:
    """The pinned canonical JSON encoding of one path token (codec v1)."""
    if t is ANY:
        return {"any": True}
    if type(t) is str:
        return {"key": t}
    if type(t) is int and not isinstance(t, bool):
        return {"index": t}
    raise TotalBindingError(f"invalid path token {t!r}")


def encode_path(path: Iterable) -> list:
    return [encode_token(t) for t in path]


# ---------------------------------------------------------------------------
# The strict exact-type codec walk (validation + budgets + cycles).
# ---------------------------------------------------------------------------
def _walk_validate(obj: Any) -> None:
    """Fail closed on anything outside strict plain JSON or any codec-v1
    bound. Iterative; an active identity set rejects cycles instead of
    hanging."""
    nodes = 0
    # stack of (value, depth, active-ancestor-ids-tuple is too costly; use
    # enter/exit markers with one shared active set)
    active: set[int] = set()
    stack: list = [(obj, 1, False)]
    while stack:
        cur, depth, is_exit = stack.pop()
        if is_exit:
            active.discard(id(cur))
            continue
        nodes += 1
        if nodes > MAX_NODES:
            raise TotalBindingError(f"node count exceeds MAX_NODES={MAX_NODES}")
        if depth > MAX_DEPTH:
            raise TotalBindingError(f"depth exceeds MAX_DEPTH={MAX_DEPTH}")
        t = type(cur)
        if cur is None:
            continue
        if t is bool:
            continue
        if t is int:
            if not (-INT_LIMIT < cur < INT_LIMIT):
                raise TotalBindingError(
                    f"integer magnitude at or beyond 10**{_INT_DIGITS} is not "
                    f"canonicalizable under codec v1"
                )
            continue
        if t is float:
            if not math.isfinite(cur):
                raise TotalBindingError(f"non-finite float {cur!r} is not JSON")
            continue
        if t is str:
            if len(cur) > MAX_STR_CODEPOINTS:
                raise TotalBindingError(
                    f"string exceeds MAX_STR_CODEPOINTS={MAX_STR_CODEPOINTS}"
                )
            try:
                cur.encode("utf-8")  # lone surrogates are not UTF-8 (A-F2):
                # json.loads('"\\ud800"') yields one, so acceptance here
                # would break "validated implies canonicalizable" and later
                # crash canon_bytes with a non-TotalBindingError
            except UnicodeEncodeError as e:
                raise TotalBindingError(
                    f"string contains a lone surrogate and is not UTF-8 encodable: {e}"
                ) from e
            continue
        if t is dict:
            if id(cur) in active:
                raise TotalBindingError("cycle detected (dict contains itself)")
            active.add(id(cur))
            stack.append((cur, depth, True))
            for k, v in cur.items():
                if type(k) is not str:
                    raise TotalBindingError(
                        f"dict key {k!r} has non-str exact type "
                        f"{type(k).__name__} (str subclasses carry behavior; "
                        f"json coerces non-str keys, colliding payloads)"
                    )
                if len(k) > MAX_STR_CODEPOINTS:
                    raise TotalBindingError("dict key exceeds MAX_STR_CODEPOINTS")
                try:
                    k.encode("utf-8")  # keys never reach the str value
                    # branch — check lone surrogates here too (A-F2)
                except UnicodeEncodeError as e:
                    raise TotalBindingError(
                        f"dict key contains a lone surrogate and is not "
                        f"UTF-8 encodable: {e}"
                    ) from e
                stack.append((v, depth + 1, False))
            continue
        if t is list:
            if id(cur) in active:
                raise TotalBindingError("cycle detected (list contains itself)")
            active.add(id(cur))
            stack.append((cur, depth, True))
            for v in cur:
                stack.append((v, depth + 1, False))
            continue
        raise TotalBindingError(
            f"value {cur!r} of exact type {t.__name__} is not strict plain "
            f"JSON (no tuples, sets, subclasses, or objects; convert "
            f"dataclass roots via to_plain)"
        )


def canon_bytes(obj: Any) -> bytes:
    """Canonical UTF-8 bytes of a strict-plain-JSON value: sorted keys,
    compact separators, allow_nan=False, ensure_ascii=False, floats via
    CPython repr (shortest round-trip). Output size is enforced incrementally
    (MAX_CANON_BYTES) — a value cannot make the serializer materialize an
    unbounded buffer before rejection."""
    _walk_validate(obj)
    enc = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False
    )
    out: list[bytes] = []
    total = 0
    for chunk in enc.iterencode(obj):
        b = chunk.encode("utf-8")
        total += len(b)
        if total > MAX_CANON_BYTES:
            raise TotalBindingError(
                f"canonical output exceeds MAX_CANON_BYTES={MAX_CANON_BYTES}"
            )
        out.append(b)
    return b"".join(out)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def value_digest(obj: Any) -> str:
    """sha256 of canon_bytes — the bare value identity (no envelope). For a
    BINDING digest use total_digest, which records domain + exclusions +
    schema; this bare form exists for closure/bijection internals."""
    return _sha(canon_bytes(obj))


# ---------------------------------------------------------------------------
# strict_loads — the authoritative root for byte evidence.
# ---------------------------------------------------------------------------
def strict_loads(data: "bytes | str") -> Any:
    """Parse JSON bytes into the authoritative root tree. Raw size is capped
    BEFORE parsing (a huge document must not be fully allocated first);
    duplicate object keys are rejected (ordinary json.loads silently keeps
    one occurrence — independent parsers may keep different ones — a
    laundering surface); oversized integer tokens are rejected lexically;
    NaN/Infinity tokens are rejected; the parsed tree then passes the full
    codec-v1 validation walk."""
    if type(data) is str:
        raw = data.encode("utf-8")
    elif type(data) is bytes:
        raw = data
    else:
        raise TotalBindingError(
            f"strict_loads takes bytes or str, not {type(data).__name__}"
        )
    if len(raw) > MAX_RAW_BYTES:
        raise TotalBindingError(f"raw input exceeds MAX_RAW_BYTES={MAX_RAW_BYTES}")

    def _pairs(pairs: list) -> dict:
        d: dict = {}
        for k, v in pairs:
            if k in d:
                raise TotalBindingError(f"duplicate object key {k!r} in input")
            d[k] = v
        return d

    def _int(s: str) -> int:
        if len(s.lstrip("-")) > _INT_DIGITS:
            raise TotalBindingError(f"integer token longer than {_INT_DIGITS} digits")
        return int(s)

    def _const(name: str) -> Any:
        raise TotalBindingError(f"non-standard JSON token {name!r} rejected")

    try:
        tree = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=_int,
            parse_constant=_const,
        )
    except TotalBindingError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise TotalBindingError(f"input is not valid JSON: {e}") from e
    _walk_validate(tree)
    return tree


# ---------------------------------------------------------------------------
# to_plain — the authoritative root for in-memory dataclass evidence.
# ---------------------------------------------------------------------------
def _is_dc_instance(x: Any) -> bool:
    """True for a dataclass INSTANCE (not the class). Deliberately a plain
    bool predicate: is_dataclass's TypeGuard narrowing is unwanted here."""
    return dataclasses.is_dataclass(x) and not isinstance(x, type)


def _type_id(obj: Any) -> str:
    t = type(obj)
    return f"{t.__module__}.{t.__qualname__}"


def to_plain(obj: Any) -> tuple:
    """Totally convert a dataclass/plain tree to (tree, schema_inventory).

    Dataclasses convert via dataclasses.fields — a COMPUTED field closure (a
    new field is picked up automatically; callers never write the per-type
    adapter that dropped event_id). schema_inventory maps each dataclass
    node's concrete path (token tuple) to its stable type identifier, so two
    field-identical types (Debit/Credit) cannot digest identically once the
    inventory rides the total_digest envelope. Containers are rebuilt, never
    aliased. Everything outside exact plain JSON + dataclass instances —
    tuples, sets, enums, datetimes, subclasses, arbitrary objects — is a
    hard error. Same cycle + resource budgets as the codec."""
    inventory: dict = {}
    active: set[int] = set()
    nodes = 0

    def rec(cur: Any, path: tuple, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES:
            raise TotalBindingError(f"node count exceeds MAX_NODES={MAX_NODES}")
        if depth > MAX_DEPTH:
            raise TotalBindingError(f"depth exceeds MAX_DEPTH={MAX_DEPTH}")
        t = type(cur)
        if cur is None or t is bool or t is int or t is float or t is str:
            _walk_validate(cur)  # scalar bounds (int magnitude, str length, finite)
            return cur
        if _is_dc_instance(cur):
            if id(cur) in active:
                raise TotalBindingError("cycle detected through dataclass")
            active.add(id(cur))
            try:
                inventory[path] = _type_id(cur)
                out = {}
                for f in dataclasses.fields(cur):
                    out[f.name] = rec(getattr(cur, f.name), path + (f.name,), depth + 1)
                return out
            finally:
                active.discard(id(cur))
        if t is dict:
            if id(cur) in active:
                raise TotalBindingError("cycle detected (dict contains itself)")
            active.add(id(cur))
            try:
                out = {}
                for k, v in cur.items():
                    if type(k) is not str:
                        raise TotalBindingError(
                            f"dict key {k!r} has non-str exact type {type(k).__name__}"
                        )
                    out[k] = rec(v, path + (k,), depth + 1)
                return out
            finally:
                active.discard(id(cur))
        if t is list:
            if id(cur) in active:
                raise TotalBindingError("cycle detected (list contains itself)")
            active.add(id(cur))
            try:
                return [rec(v, path + (i,), depth + 1) for i, v in enumerate(cur)]
            finally:
                active.discard(id(cur))
        raise TotalBindingError(
            f"value {cur!r} of exact type {t.__name__} is outside to_plain's "
            f"domain (exact dict/list/scalars + dataclass instances only)"
        )

    tree = rec(obj, (), 1)
    return tree, inventory


# ---------------------------------------------------------------------------
# Path resolution (concrete + ANY expansion) over plain trees.
# ---------------------------------------------------------------------------
def _resolve(obj: Any, path: tuple) -> list:
    """All concrete token paths matching `path` in `obj` (ANY expands over
    every dict key / list index at its level). Returns [] when nothing
    matches."""
    matches: list[tuple] = []

    def rec(cur: Any, remaining: tuple, concrete: tuple) -> None:
        if not remaining:
            matches.append(concrete)
            return
        head, rest = remaining[0], remaining[1:]
        if head is ANY:
            if type(cur) is dict:
                for k in cur:
                    rec(cur[k], rest, concrete + (k,))
            elif type(cur) is list:
                for i, v in enumerate(cur):
                    rec(v, rest, concrete + (i,))
            return
        if type(head) is str and type(cur) is dict and head in cur:
            rec(cur[head], rest, concrete + (head,))
        elif (
            type(head) is int
            and not isinstance(head, bool)
            and type(cur) is list
            and 0 <= head < len(cur)
        ):
            rec(cur[head], rest, concrete + (head,))

    rec(obj, path, ())
    return matches


def _get_at(obj: Any, concrete: tuple) -> Any:
    cur = obj
    for tok in concrete:
        cur = cur[tok]
    return cur


def _is_prefix(a: tuple, b: tuple) -> bool:
    return len(a) <= len(b) and b[: len(a)] == a


# ---------------------------------------------------------------------------
# total_digest — the binding digest with recorded exclusions + schema.
# ---------------------------------------------------------------------------
def _validate_exclusions(obj: Any, exclude: Iterable) -> list:
    """Validate + resolve exclusions. Returns [(path, reason, [concrete...])]
    in input order. Errors: malformed entries, root exclusion, zero matches
    (stale wildcards die per-call), ancestor/descendant overlap between any
    two concrete matches of different or the same exclusion."""
    entries: list = []
    for e in exclude:
        if not (isinstance(e, tuple) and len(e) == 2):
            raise TotalBindingError(
                f"exclusion entry must be a (path, reason) pair, got {e!r}"
            )
        path, reason = e
        if not isinstance(path, tuple) or not all(_valid_token(t) for t in path):
            raise TotalBindingError(
                f"exclusion path must be a tuple of str/int/ANY tokens, got {path!r}"
            )
        if len(path) == 0:
            raise TotalBindingError("excluding the root is prohibited")
        if type(reason) is not str or not reason:
            raise TotalBindingError(
                f"exclusion reason must be a non-empty str, got {reason!r}"
            )
        concrete = _resolve(obj, path)
        if not concrete:
            raise TotalBindingError(
                f"exclusion path {path!r} matches nothing in this object "
                f"(stale exclusions are errors)"
            )
        entries.append((path, reason, concrete))
    flat = [c for _, _, cs in entries for c in cs]
    for i, a in enumerate(flat):
        for b in flat[i + 1 :]:
            if a != b and (_is_prefix(a, b) or _is_prefix(b, a)):
                raise TotalBindingError(
                    f"exclusions overlap (ancestor/descendant): {a!r} vs {b!r}"
                )
            if a == b:
                raise TotalBindingError(f"duplicate exclusion match at {a!r}")
    return entries


def _apply_exclusions(obj: Any, entries: list) -> Any:
    """Deep-copied tree with each excluded subtree replaced by a structural
    marker carrying the exclusion's index — never silently dropped."""
    out = copy.deepcopy(obj)
    if not entries:
        return out
    for idx, (_path, _reason, concretes) in enumerate(entries):
        for c in concretes:
            parent = _get_at(out, c[:-1])
            parent[c[-1]] = {"_tb_excluded": idx}
    return out


def _encode_schema(obj: Any, schema: dict, entries: list) -> list:
    """Pinned encoding: canonical sorted per-element entries
    [{"path": [...tokens...], "type": id}, ...]. ANY never appears (paths
    are concrete). Validated: paths resolve to mapping nodes in obj, no
    duplicates, non-empty str type IDs, no path under an exclusion."""
    if type(schema) is not dict:
        raise TotalBindingError(
            f"schema must be a dict of concrete-path-tuple -> type id or "
            f"None, got {type(schema).__name__}"
        )
    excluded_concrete = [c for _, _, cs in entries for c in cs]
    seen: set = set()
    encoded = []
    for path, tid in schema.items():
        if not isinstance(path, tuple) or any(
            not _valid_token(t) or t is ANY for t in path
        ):
            raise TotalBindingError(
                f"schema path must be a concrete token tuple (no ANY), got {path!r}"
            )
        if path in seen:
            raise TotalBindingError(f"duplicate schema path {path!r}")
        seen.add(path)
        if type(tid) is not str or not tid:
            raise TotalBindingError(
                f"schema type id must be non-empty str, got {tid!r}"
            )
        hits = _resolve(obj, path)
        if len(hits) != 1:
            raise TotalBindingError(f"schema path {path!r} does not resolve in object")
        if type(_get_at(obj, hits[0])) is not dict:
            raise TotalBindingError(
                f"schema path {path!r} does not name a mapping node"
            )
        for c in excluded_concrete:
            if _is_prefix(c, path):
                raise TotalBindingError(
                    f"schema path {path!r} falls under exclusion at {c!r}"
                )
        encoded.append({"path": encode_path(path), "type": tid})
    encoded.sort(key=lambda e: canon_bytes(e["path"]))
    return encoded


def total_digest(
    obj: Any, *, exclude: Iterable, domain: str, schema: "dict | None"
) -> str:
    """The binding digest: sha256 over the codec-v1 envelope
    {"_tb": 1, "domain", "excluded", "schema", "bound"}.

    All three keyword arguments are MANDATORY-EXPLICIT — passing `exclude=()`
    and `schema=None` is a visible statement, not a default you can forget.
    Exclusions are (path, reason) pairs; each is validated (no root, >=1
    match, no overlap) and folded into the digest, so an omission is a
    hash-visible decision, never silence. `schema` is the inventory returned
    by to_plain (None for raw-JSON roots) — it rides a separate envelope
    field, so a raw dict in `bound` cannot impersonate a typed node.

    This proves completeness RELATIVE TO `obj`. Handing it a projection of
    the real root re-opens the hole; the probe battery is the witness that
    you didn't."""
    if type(domain) is not str or not domain:
        raise TotalBindingError(f"domain must be a non-empty str, got {domain!r}")
    _walk_validate(obj)
    entries = _validate_exclusions(obj, exclude)
    encoded_exclusions = [{"path": encode_path(p), "reason": r} for p, r, _ in entries]
    encoded_exclusions.sort(key=lambda e: canon_bytes(e))
    encoded_schema = None if schema is None else _encode_schema(obj, schema, entries)
    envelope = {
        "_tb": TB_CODEC_VERSION,
        "domain": domain,
        "excluded": encoded_exclusions,
        "schema": encoded_schema,
        "bound": _apply_exclusions(obj, entries),
    }
    return _sha(canon_bytes(envelope))


# ---------------------------------------------------------------------------
# closure — transitive closure with computed member identity.
# ---------------------------------------------------------------------------
def closure(
    seeds: Iterable, expand: Callable, *, key: "Callable | None" = None
) -> list:
    """Deterministic BFS transitive closure of `expand` from `seeds`.

    Member identity is the canonical digest of key(item) (default: the item
    itself, which must then be strict plain JSON). Two DISTINCT members
    mapping to one key digest are a collision ERROR, never a silent merge.
    Returns members in BFS discovery order (deterministic given seeds order
    and expand output order). The helper guarantees transitivity over
    `expand` — no hand-picked member list; whether `expand` sees every real
    edge is the caller's semantic claim, testable by the probe (edit a
    member the closure should reach -> the closure digest must move)."""
    key_fn = key if key is not None else (lambda x: x)
    seen: dict = {}
    order: list = []
    queue = list(seeds)
    i = 0
    while i < len(queue):
        item = queue[i]
        i += 1
        k = value_digest(key_fn(item))
        if k in seen:
            prev = seen[k]
            if prev != item:
                raise TotalBindingError(
                    f"closure key collision: distinct members {prev!r} and "
                    f"{item!r} share key digest {k}"
                )
            continue
        seen[k] = item
        order.append(item)
        queue.extend(expand(item))
    return order


def closure_digest(
    seeds: Iterable,
    expand: Callable,
    item_digest: Callable,
    *,
    key: "Callable | None" = None,
    domain: str,
) -> str:
    """total_digest over {member_key_digest: item_digest(member)} for the
    ENTIRE closure — the generalized manifest fix: any edit to any member the
    closure reaches changes the digest."""
    key_fn = key if key is not None else (lambda x: x)
    members = closure(seeds, expand, key=key)
    mapping = {value_digest(key_fn(m)): item_digest(m) for m in members}
    return total_digest(mapping, exclude=(), domain=domain, schema=None)


# ---------------------------------------------------------------------------
# Completeness asserts (multiset semantics — duplicates are failures, never
# collapsed).
# ---------------------------------------------------------------------------
def _multiset(items: Iterable) -> dict:
    counts: dict = {}
    for it in items:
        d = value_digest(it)
        counts[d] = counts.get(d, 0) + 1
    return counts


def assert_bijection(left: Iterable, right: Iterable) -> None:
    """Exact multiset equality of full canonical values. [a, a] vs [a] fails
    (the duplicated-dispatch-row lesson); identity is the WHOLE value — for
    a projected identity use assert_bijection_projected, whose name makes
    the projection visible at the callsite."""
    lm, rm = _multiset(left), _multiset(right)
    if lm != rm:
        only_l = {d: c for d, c in lm.items() if rm.get(d) != c}
        only_r = {d: c for d, c in rm.items() if lm.get(d) != c}
        raise TotalBindingError(
            f"bijection failure: left-only/mismatched counts {only_l}, "
            f"right-only/mismatched counts {only_r}"
        )


def assert_bijection_projected(left: Iterable, right: Iterable, key: Callable) -> None:
    """Multiset bijection over key(x) — a PROJECTED identity. The projection
    is the caller's judgment; this name exists so it is visible in review."""
    assert_bijection([key(x) for x in left], [key(x) for x in right])


def assert_exact_keys(mapping: dict, required: Iterable) -> None:
    """Missing AND unexpected keys both fail (a dropped slot and a smuggled
    slot are equally findings). Apply at the trust boundary, not to a
    projection."""
    if type(mapping) is not dict:
        raise TotalBindingError(f"assert_exact_keys needs a dict, got {mapping!r}")
    req = set(required)
    got = set(mapping)
    missing, extra = req - got, got - req
    if missing or extra:
        raise TotalBindingError(
            f"exact-key failure: missing {sorted(missing)!r}, "
            f"unexpected {sorted(extra)!r}"
        )


def assert_partition(universe: Iterable, parts: Iterable) -> None:
    """The parts exactly tile the universe: multiset union of parts equals
    the universe multiset, and no element rides two parts. The universe must
    be DERIVED from the evidence object, not hand-assembled — that residual
    is the caller's."""
    uni = _multiset(universe)
    combined: dict = {}
    for part in parts:
        for it in part:
            d = value_digest(it)
            combined[d] = combined.get(d, 0) + 1
    if combined != uni:
        over = {d: c for d, c in combined.items() if uni.get(d, 0) < c}
        under = {d: c for d, c in uni.items() if combined.get(d, 0) < c}
        raise TotalBindingError(
            f"partition failure: over-covered {over}, uncovered {under}"
        )


# ---------------------------------------------------------------------------
# The probe battery — the completeness WITNESS.
# ---------------------------------------------------------------------------
_VERDICT_KEYS = {"decision", "reasons"}


def _run_verdict(run: Callable, obj: Any) -> dict:
    v = run(obj)
    if (
        type(v) is not dict
        or set(v) != _VERDICT_KEYS
        or type(v["decision"]) is not str
        or type(v["reasons"]) is not list
        or any(type(r) is not str for r in v["reasons"])
    ):
        raise ProbeConfigError(
            f"run must return exactly {{'decision': str, 'reasons': "
            f"[str, ...]}} — no diagnostics channel (a verdict echoing the "
            f"input would make every mutation 'move the verdict'); got {v!r}"
        )
    return v


def _walk_nodes(root: Any):
    """Yield (concrete_path, node) over the ORIGINAL root — dataclasses
    enumerate via fields() (children under attribute-name tokens), dicts via
    keys, lists via indices. Scalars are leaves."""
    stack: list[tuple[tuple, Any]] = [((), root)]
    while stack:
        path, cur = stack.pop()
        yield path, cur
        if _is_dc_instance(cur):
            for f in dataclasses.fields(cur):
                stack.append((path + (f.name,), getattr(cur, f.name)))
        elif type(cur) is dict:
            for k, v in cur.items():
                stack.append((path + (k,), v))
        elif type(cur) is list:
            for i, v in enumerate(cur):
                stack.append((path + (i,), v))


def _node_at(root: Any, concrete: tuple) -> Any:
    cur = root
    for tok in concrete:
        if _is_dc_instance(cur):
            cur = getattr(cur, tok)
        else:
            cur = cur[tok]
    return cur


def _set_at(root: Any, concrete: tuple, value: Any) -> Any:
    """Return a deep-copied root with the node at `concrete` replaced by
    `value` (ancestors rebuilt; dataclasses via replace)."""

    def rec(cur: Any, remaining: tuple) -> Any:
        if not remaining:
            return value
        tok, rest = remaining[0], remaining[1:]
        if _is_dc_instance(cur):
            return dataclasses.replace(cur, **{tok: rec(getattr(cur, tok), rest)})
        if type(cur) is dict:
            out = {
                k: (rec(v, rest) if k == tok else copy.deepcopy(v))
                for k, v in cur.items()
            }
            return out
        if type(cur) is list:
            return [
                rec(v, rest) if i == tok else copy.deepcopy(v)
                for i, v in enumerate(cur)
            ]
        raise ProbeConfigError(f"cannot descend token {tok!r} into {cur!r}")

    return rec(copy.deepcopy(root), concrete)


def _pattern_matches(root: Any, pattern: tuple) -> list:
    """Concrete paths matching a probe pattern over the original root
    (dataclass-aware ANY expansion)."""
    matches: list[tuple] = []

    def rec(cur: Any, remaining: tuple, concrete: tuple) -> None:
        if not remaining:
            matches.append(concrete)
            return
        head, rest = remaining[0], remaining[1:]
        is_dc = _is_dc_instance(cur)
        if head is ANY:
            if is_dc:
                for f in dataclasses.fields(cur):
                    rec(getattr(cur, f.name), rest, concrete + (f.name,))
            elif type(cur) is dict:
                for k, v in cur.items():
                    rec(v, rest, concrete + (k,))
            elif type(cur) is list:
                for i, v in enumerate(cur):
                    rec(v, rest, concrete + (i,))
            return
        if type(head) is str:
            if is_dc and head in {f.name for f in dataclasses.fields(cur)}:
                rec(getattr(cur, head), rest, concrete + (head,))
            elif type(cur) is dict and head in cur:
                rec(cur[head], rest, concrete + (head,))
        elif type(head) is int and not isinstance(head, bool):
            if type(cur) is list and 0 <= head < len(cur):
                rec(cur[head], rest, concrete + (head,))

    rec(root, pattern, ())
    return matches


def pattern_inventory(root: Any, pattern_path: tuple, decl: dict) -> tuple:
    """(digest, count) commitment for an exception pattern: sha over the
    sorted concrete resolved paths PLUS the declaration content
    (classification, reason(s), order). Authors call this ONCE at
    spec-writing time and freeze the returned values into the spec; the
    probe recomputes and any drift — including one path leaving while
    another enters — is a configuration failure."""
    matches = _pattern_matches(root, pattern_path)
    record = {
        "paths": sorted(
            (encode_path(p) for p in matches), key=lambda e: canon_bytes(e)
        ),
        "decl": decl,
    }
    return _sha(canon_bytes(record)), len(matches)


def _default_mutant(value: Any):
    """Type- and shape-preserving default mutant, or None-marker when no
    default exists (degenerate: caller must supply)."""
    t = type(value)
    if t is bool:
        return (not value,)
    if t is int:
        return (value + 1,)
    if t is float:
        return (value + 1.0,)
    if t is str:
        if not value:
            return None  # degenerate: empty string has no shape-preserving flip
        i = len(value) // 2
        c = value[i]
        repl = "0" if c != "0" else "1"
        return (value[:i] + repl + value[i + 1 :],)
    return None


def _mutate_identity(elem: Any):
    """A clone of `elem` with one leaf mutated (for the insertion leg), or
    None when no leaf is mutable."""
    if _is_dc_instance(elem) or type(elem) in (dict, list):
        for path, node in _walk_nodes(elem):
            if path and type(node) in (bool, int, float, str):
                m = _default_mutant(node)
                if m is not None:
                    return _set_at(elem, path, m[0])
        return None
    m = _default_mutant(elem)
    return None if m is None else m[0]


def probe_check(fixture: Any, run: Callable, *, spec: dict) -> dict:
    """The completeness witness. Mechanizes the adversary: for every part of
    `fixture` (the AUTHORITATIVE root — handing a projection here defeats
    the point), verify the real check `run` is not indifferent to it.

    spec = {
      "accepting":       [decision, ...]            # non-empty
      "expect_reasons":  [reason_id, ...]           # default for exact legs
                                                    # + structural rejection legs
      "patterns": [                                 # exceptions ONLY
        {"path": (tokens...), "class": "exact",
         "expect_reasons": [...]},                  # override reasons
        {"path": (...), "class": "predicate",
         "mutants": [{"value": v, "expect": "accept"} |
                     {"value": v, "expect": "reject", "reasons": [...]}],
         "inventory": (digest, count)},             # frozen commitment
        {"path": (...), "class": "out_of_scope", "reason": "...",
         "inventory": (digest, count)},
      ],
      "lists": [                                    # list-node declarations
        {"path": (tokens...), "order": "ordered"|"multiset",
         "expect_reasons": [...],                   # optional override
         "inventory": (digest, count)},             # frozen (multiset only)
      ],
    }

    Legs (per accepted ADR): exact — default class for every leaf; the
    mutated decision must LEAVE the accepting set AND carry an expected
    reason (a transition on only unexpected reasons — e.g. the mutant broke
    parsing upstream — FAILS the leg). predicate — caller-supplied oracle.
    Structural rejection legs per list node: duplication, deletion,
    insertion of a clone-with-mutated-identity; reorder is a rejection leg
    for `ordered` nodes and an INVARIANCE leg for `multiset` nodes (must
    REMAIN accepting). Mapping nodes: novel-key injection + per-key
    deletion. Degenerate nodes (empty list/mapping, None leaf, empty str)
    FAIL the configuration unless a predicate pattern supplies the
    empty<->non-empty / None<->typed mutant or the node is out-of-scope.
    Dataclass nodes get a type-substitution leg (equal-fields imposter must
    be rejected).

    Returns {"ok": bool, "legs": [...], "counts": {...}} — each failing leg
    names the mutated path: the report IS the adversary's finding."""
    accepting = spec.get("accepting")
    if not accepting or not all(type(d) is str for d in accepting):
        raise ProbeConfigError("spec['accepting'] must be a non-empty list of str")
    accepting_set = set(accepting)
    default_reasons = spec.get("expect_reasons")
    if not default_reasons or not all(type(r) is str for r in default_reasons):
        raise ProbeConfigError(
            "spec['expect_reasons'] must be a non-empty list of reason ids "
            "(mandatory: without an expected reason, an incidental parse "
            "rejection would count as sensitivity)"
        )

    # -- determinism pre-check on fresh deep copies -------------------------
    v1 = _run_verdict(run, copy.deepcopy(fixture))
    v2 = _run_verdict(run, copy.deepcopy(fixture))
    if v1 != v2:
        raise ProbeConfigError(
            f"check is nondeterministic on the unmutated fixture: {v1!r} != "
            f"{v2!r} (normalize timestamps/state before probing)"
        )
    if v1["decision"] not in accepting_set:
        raise ProbeConfigError(
            f"unmutated fixture is not accepted ({v1!r}) — the probe would be vacuous"
        )

    # -- compile patterns to concrete paths, verify frozen inventories ------
    leaf_class: dict = {}
    predicate_specs: dict = {}
    oos: dict = {}
    exact_reasons: dict = {}
    patterns = spec.get("patterns", [])
    claimed: list = []
    for p in patterns:
        cls = p.get("class")
        path = p.get("path")
        if cls not in ("exact", "predicate", "out_of_scope"):
            raise ProbeConfigError(f"unknown pattern class {cls!r}")
        if not isinstance(path, tuple) or not all(_valid_token(t) for t in path):
            raise ProbeConfigError(f"pattern path must be a token tuple, got {path!r}")
        matches = _pattern_matches(fixture, path)
        if not matches:
            raise ProbeConfigError(f"pattern {path!r} matches nothing (stale)")
        if cls in ("predicate", "out_of_scope"):
            decl = {k: v for k, v in p.items() if k not in ("inventory", "mutants")}
            decl["path"] = encode_path(path)
            if "mutants" in p:
                decl["mutants"] = [{k: v for k, v in m.items()} for m in p["mutants"]]
            inv = p.get("inventory")
            got = pattern_inventory(
                fixture, path, {k: v for k, v in decl.items() if k != "path"}
            )
            # commitment binds decl content + resolved concrete paths
            got = (got[0], got[1])
            if not (isinstance(inv, tuple) and len(inv) == 2 and inv == got):
                raise ProbeConfigError(
                    f"pattern {path!r} frozen inventory mismatch: spec has "
                    f"{inv!r}, fixture resolves to {got!r} — a path entered "
                    f"or left the exception; update the spec intentionally"
                )
        for m in matches:
            claimed.append((m, cls))
    # ambiguity: one concrete path claimed twice is a config error
    seen_paths: dict = {}
    for m, cls in claimed:
        if m in seen_paths:
            raise ProbeConfigError(
                f"patterns overlap ambiguously at concrete path {m!r}"
            )
        seen_paths[m] = cls
    for p in patterns:
        for m in _pattern_matches(fixture, p["path"]):
            cls = p["class"]
            leaf_class[m] = cls
            if cls == "predicate":
                if not p.get("mutants"):
                    raise ProbeConfigError(
                        f"predicate pattern {p['path']!r} needs mutants"
                    )
                predicate_specs[m] = p["mutants"]
            elif cls == "out_of_scope":
                if not p.get("reason"):
                    raise ProbeConfigError(
                        f"out_of_scope pattern {p['path']!r} needs a reason"
                    )
                oos[m] = p["reason"]
            elif cls == "exact":
                exact_reasons[m] = p.get("expect_reasons", default_reasons)

    list_decls: dict = {}
    for ld in spec.get("lists", []):
        path = ld.get("path")
        order = ld.get("order")
        if order not in ("ordered", "multiset"):
            raise ProbeConfigError(f"list decl order must be ordered|multiset: {ld!r}")
        matches = _pattern_matches(fixture, path)
        if not matches:
            raise ProbeConfigError(f"list decl {path!r} matches nothing (stale)")
        if order == "multiset":
            decl = {"order": order, "expect_reasons": ld.get("expect_reasons")}
            inv = ld.get("inventory")
            got = pattern_inventory(fixture, path, decl)
            if not (isinstance(inv, tuple) and len(inv) == 2 and inv == got):
                raise ProbeConfigError(
                    f"multiset list decl {path!r} frozen inventory mismatch: "
                    f"{inv!r} vs {got!r}"
                )
        for m in matches:
            if type(_node_at(fixture, m)) is not list:
                raise ProbeConfigError(f"list decl {path!r} matched non-list {m!r}")
            list_decls[m] = ld

    legs: list = []

    def run_leg(kind: str, path: tuple, mutated_root: Any, expect: str, reasons):
        v = _run_verdict(run, mutated_root)
        rejected = v["decision"] not in accepting_set
        if expect == "reject":
            hit = rejected and (set(v["reasons"]) & set(reasons))
            ok = bool(hit)
            why = (
                None
                if ok
                else (
                    "still accepted"
                    if not rejected
                    else f"rejected but with unexpected reasons {v['reasons']!r} "
                    f"(expected one of {sorted(set(reasons))!r} — incidental "
                    f"rejection is not binding sensitivity)"
                )
            )
        else:  # invariance / expected accept
            ok = not rejected
            why = None if ok else f"decision left accepting set: {v!r}"
        legs.append({"kind": kind, "path": encode_path(path), "ok": ok, "why": why})

    # -- field legs ---------------------------------------------------------
    all_nodes = list(_walk_nodes(fixture))
    for path, node in all_nodes:
        is_dc = _is_dc_instance(node)
        if is_dc or type(node) in (dict, list):
            continue  # containers handled structurally
        cls = leaf_class.get(path, "exact")
        if cls == "out_of_scope":
            legs.append(
                {
                    "kind": "out_of_scope",
                    "path": encode_path(path),
                    "ok": True,
                    "why": None,
                    "reason": oos[path],
                }
            )
            continue
        if cls == "predicate":
            for m in predicate_specs[path]:
                mutated = _set_at(fixture, path, m["value"])
                if m["expect"] == "reject":
                    run_leg(
                        "predicate",
                        path,
                        mutated,
                        "reject",
                        m.get("reasons", default_reasons),
                    )
                else:
                    run_leg("predicate", path, mutated, "accept", ())
            continue
        # exact
        mut = _default_mutant(node)
        if mut is None:
            raise ProbeConfigError(
                f"degenerate leaf at {path!r} ({node!r}) has no default "
                f"mutant — supply a predicate pattern (None<->typed / "
                f"empty<->non-empty) or declare it out_of_scope; silence "
                f"here is exactly where the exploit lives"
            )
        mutated = _set_at(fixture, path, mut[0])
        run_leg(
            "exact", path, mutated, "reject", exact_reasons.get(path, default_reasons)
        )

    # -- structural legs ----------------------------------------------------
    for path, node in all_nodes:
        if leaf_class.get(path) == "out_of_scope":
            continue
        if path in predicate_specs and (
            _is_dc_instance(node) or type(node) in (dict, list)
        ):
            # A predicate pattern on a CONTAINER replaces its default
            # structural legs with the caller's oracle — and the mutants MUST
            # actually run. (Pre-fix, container mutants were validated at
            # config time and then silently never executed: the field loop
            # skips containers and this loop only consulted predicate_specs
            # as an empty-node escape hatch — a declared empty<->non-empty
            # probe for rows=[] never fired, which is the exact exploit D5's
            # degenerate-node rule exists to close.)
            for m in predicate_specs[path]:
                mutated = _set_at(fixture, path, m["value"])
                if m["expect"] == "reject":
                    run_leg(
                        "predicate",
                        path,
                        mutated,
                        "reject",
                        m.get("reasons", default_reasons),
                    )
                else:
                    run_leg("predicate", path, mutated, "accept", ())
            continue
        if type(node) is list:
            decl = list_decls.get(path, {"order": "ordered"})
            reasons = decl.get("expect_reasons") or default_reasons
            if not node:
                raise ProbeConfigError(
                    f"empty list at {path!r} has no constructible "
                    f"structural leg — supply a predicate pattern with "
                    f"an empty<->non-empty mutant or declare "
                    f"out_of_scope (a verifier ignoring rows=[] growing "
                    f"a row is the exploit)"
                )
            dup = list(node) + [copy.deepcopy(node[0])]
            run_leg(
                "structural:duplicate",
                path,
                _set_at(fixture, path, dup),
                "reject",
                reasons,
            )
            run_leg(
                "structural:delete",
                path,
                _set_at(fixture, path, list(node[:-1])),
                "reject",
                reasons,
            )
            clone = _mutate_identity(node[0])
            if clone is None:
                raise ProbeConfigError(
                    f"list at {path!r}: cannot build a mutated-identity "
                    f"clone of element 0 — supply a predicate pattern"
                )
            run_leg(
                "structural:insert",
                path,
                _set_at(fixture, path, list(node) + [clone]),
                "reject",
                reasons,
            )
            # gate on whether the reversal is ACTUALLY distinct — an
            # endpoints-equal proxy silently skipped [X,B,C,X] (fresh-audit
            # A-F1: probe green on an order-insensitive check); only a true
            # palindrome, where reversal is a no-op, has no leg to run
            reordered = list(reversed(copy.deepcopy(node)))
            if len(node) >= 2 and reordered != node:
                if decl.get("order") == "multiset":
                    run_leg(
                        "structural:reorder-invariance",
                        path,
                        _set_at(fixture, path, reordered),
                        "accept",
                        (),
                    )
                else:
                    run_leg(
                        "structural:reorder",
                        path,
                        _set_at(fixture, path, reordered),
                        "reject",
                        reasons,
                    )
        elif type(node) is dict:
            reasons = default_reasons
            if not node:
                # predicate-classed containers were handled above
                raise ProbeConfigError(
                    f"empty mapping at {path!r} has no constructible "
                    f"structural leg — supply a predicate pattern or "
                    f"declare out_of_scope"
                )
            novel = "_tb_probe_novel"
            while novel in node:
                novel += "_"
            with_novel = dict(copy.deepcopy(node))
            with_novel[novel] = 1
            run_leg(
                "structural:novel-key",
                path,
                _set_at(fixture, path, with_novel),
                "reject",
                reasons,
            )
            for k in sorted(node):
                if leaf_class.get(path + (k,)) == "out_of_scope":
                    continue
                without = {kk: copy.deepcopy(vv) for kk, vv in node.items() if kk != k}
                run_leg(
                    "structural:key-delete",
                    path + (k,),
                    _set_at(fixture, path, without),
                    "reject",
                    reasons,
                )
        elif _is_dc_instance(node):
            # type-substitution leg: equal-fields imposter must be rejected
            fields = [
                (f.name, f.type if isinstance(f.type, type) else object)
                for f in dataclasses.fields(node)
            ]
            imposter_cls = dataclasses.make_dataclass(
                "TBImposter_" + type(node).__name__, [n for n, _ in fields]
            )
            imposter = imposter_cls(
                **{
                    f.name: copy.deepcopy(getattr(node, f.name))
                    for f in dataclasses.fields(node)
                }
            )
            run_leg(
                "structural:type-substitution",
                path,
                _set_at(fixture, path, imposter),
                "reject",
                default_reasons,
            )

    ok = all(leg["ok"] for leg in legs)
    counts = {"total": len(legs), "failed": sum(1 for x in legs if not x["ok"])}
    return {"ok": ok, "legs": legs, "counts": counts}


# ---------------------------------------------------------------------------
# The advisory CI ratchet — AST scan for the hand-subset smell.
# ---------------------------------------------------------------------------
_DEFAULT_SINKS = frozenset(
    {
        "_sha",
        "sha",
        "sha256",
        "digest",
        "value_digest",
        "total_digest",
        "hash_of",
        # canonicalizers count as sinks: the house idiom is _sha(_canon({...}))
        # and the projection sits under the canonicalizer call
        "_canon",
        "canon",
        "canon_bytes",
    }
)


def _stmt_ast_path(func_node: ast.AST, target: ast.stmt) -> "str | None":
    """Deterministic AST location path from the function root to `target`,
    e.g. 'body[3].orelse[0]' — a LOCATION identity: an identical statement
    anywhere else has a different path (waiver transfer is impossible; code
    motion fails loudly, which is the reviewed direction)."""

    def rec(node: ast.AST, prefix: str) -> "str | None":
        for field, val in ast.iter_fields(node):
            if isinstance(val, list):
                for i, item in enumerate(val):
                    if item is target:
                        return f"{prefix}{field}[{i}]"
                    if isinstance(item, ast.AST):
                        r = rec(item, f"{prefix}{field}[{i}].")
                        if r is not None:
                            return r
            elif val is target:
                return f"{prefix}{field}"
            elif isinstance(val, ast.AST):
                r = rec(val, f"{prefix}{field}.")
                if r is not None:
                    return r
        return None

    return rec(func_node, "")


def _projection_base(node: ast.AST) -> "str | None":
    """If `node` is a dict display / dict comprehension / dict(...) call
    whose values contain >=2 attribute/subscript reads off ONE base Name,
    return that base name; else None."""
    values: list = []
    if isinstance(node, ast.Dict):
        values = [v for v in node.values if v is not None]
    elif isinstance(node, ast.DictComp):
        values = [node.key, node.value]  # base reads in the KEY position
        # count too — {r["id"]: r["v"] for r in rows} is a projection
        # (fresh-audit A-F3)
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dict"
        and node.keywords
    ):
        values = [kw.value for kw in node.keywords if kw.arg is not None]
    else:
        return None
    bases: list[str] = []
    for v in values:
        for sub in ast.walk(v):
            if isinstance(sub, (ast.Attribute, ast.Subscript)) and isinstance(
                sub.value, ast.Name
            ):
                bases.append(sub.value.id)
    if not bases:
        return None
    counts: dict = {}
    for b in bases:
        counts[b] = counts.get(b, 0) + 1
    base, n = max(counts.items(), key=lambda kv: kv[1])
    return base if n >= 2 else None


def _sink_name(call: ast.Call) -> "str | None":
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def projection_digest_occurrences(
    source: str, filename: str, *, sinks: frozenset = _DEFAULT_SINKS
) -> list:
    """Advisory ratchet scan (author-mistake tooling, NOT an enforcement
    boundary — tuple projections, manual update loops, and cross-function
    flows are documented evasions, out of fingerprint reach by design).

    Flags, inside each function: (a) a call to a known digest/hash sink
    whose argument is a dict-projection of >=2 reads off one base object —
    directly, via a single local assignment used in the sink call, or via a
    dict(...) call form — INCLUDING such arguments passed to total_digest
    itself (routing a projection through the helper is still a projection);
    (b) equality comparisons between two such projections.

    Each occurrence is fingerprinted (file, function, normalized-statement
    sha, full AST path) — a per-LOCATION identity for the waiver list; the
    recorded statement is the INNERMOST enclosing statement of the match, so
    identical statements at different locations stay distinct."""
    tree = ast.parse(source, filename=filename)
    parent: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    def _enclosing(node: ast.AST, kinds) -> "ast.AST | None":
        cur = parent.get(node)
        while cur is not None and not isinstance(cur, kinds):
            cur = parent.get(cur)
        return cur

    # single-assignment projection names, per enclosing function
    func_kinds = (ast.FunctionDef, ast.AsyncFunctionDef)
    assigned: dict = {}
    assign_count: dict = {}
    for sub in ast.walk(tree):
        if (
            isinstance(sub, ast.Assign)
            and len(sub.targets) == 1
            and isinstance(sub.targets[0], ast.Name)
        ):
            fn = _enclosing(sub, func_kinds)
            if fn is None:
                continue
            key = (fn, sub.targets[0].id)
            assign_count[key] = assign_count.get(key, 0) + 1
            base = _projection_base(sub.value)
            if base is not None:
                assigned[key] = base

    occurrences: list = []

    def record(node: ast.AST, base: str, form: str) -> None:
        stmt = node if isinstance(node, ast.stmt) else _enclosing(node, ast.stmt)
        fn = _enclosing(node, func_kinds)
        if not isinstance(stmt, ast.stmt) or not isinstance(
            fn, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return  # module-level projection: outside the fingerprint scope
        norm = ast.dump(stmt, annotate_fields=False, include_attributes=False)
        occurrences.append(
            {
                "file": filename,
                "function": fn.name,
                "stmt_sha": _sha(norm.encode("utf-8")),
                "ast_path": _stmt_ast_path(fn, stmt),
                "base": base,
                "form": form,
                "lineno": stmt.lineno,
            }
        )

    for sub in ast.walk(tree):
        if isinstance(sub, ast.Call):
            name = _sink_name(sub)
            if name in sinks and sub.args:
                arg = sub.args[0]
                base = _projection_base(arg)
                fn = _enclosing(sub, func_kinds)
                if base is not None:
                    record(sub, base, "sink-projection")
                elif (
                    isinstance(arg, ast.Name)
                    and fn is not None
                    and (fn, arg.id) in assigned
                    and assign_count.get((fn, arg.id)) == 1
                ):
                    record(sub, assigned[(fn, arg.id)], "sink-assigned-projection")
        elif isinstance(sub, ast.Compare) and any(
            isinstance(op, (ast.Eq, ast.NotEq)) for op in sub.ops
        ):
            sides = [sub.left] + list(sub.comparators)
            proj = [s for s in sides if _projection_base(s) is not None]
            if len(proj) >= 2:
                record(sub, _projection_base(proj[0]) or "?", "projection-equality")

    # de-duplicate: one statement can contain several matches
    seen: set = set()
    unique: list = []
    for o in occurrences:
        k = (o["file"], o["function"], o["stmt_sha"], o["ast_path"])
        if k not in seen:
            seen.add(k)
            unique.append(o)
    return unique


def ratchet_check(occurrences: list, allowlist: dict) -> None:
    """Exact-in-both-directions comparison of scan occurrences against the
    waiver allowlist {(file, function, stmt_sha, ast_path): justification}.
    A new occurrence fails; a stale waiver fails. Growth of the allowlist is
    a visible reviewed diff to one constant — not impossible, visible."""
    found = {
        (o["file"], o["function"], o["stmt_sha"], o["ast_path"]): o for o in occurrences
    }
    new = {k: v for k, v in found.items() if k not in allowlist}
    stale = {k: v for k, v in allowlist.items() if k not in found}
    if new or stale:
        msgs = []
        for k, o in sorted(new.items()):
            msgs.append(
                f"NEW hand-subset smell at {k[0]}:{o['lineno']} in "
                f"{k[1]} ({o['form']} off base {o['base']!r}) — bind the "
                f"root via total_digest with recorded exclusions, or add a "
                f"reviewed waiver for this exact location"
            )
        for k, j in sorted(stale.items()):
            msgs.append(
                f"STALE waiver {k!r} ({j!r}) — the site moved or was "
                f"fixed; remove or re-review the entry"
            )
        raise TotalBindingError("ratchet failure:\n" + "\n".join(msgs))
