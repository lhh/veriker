"""closed_universe — the closed-universe receipt: a pre-committed denominator,
a covered/withheld partition with enumerated reasons, and a re-derivable
receipt designed to be embedded beside outputs (nothing embeds it yet; the
intended ports — charter per-regulation inclusion manifests, bundle claimset
coverage, P2 channel inventories — are queued, not built).

Salvaged as a substrate helper from horizon's Tier Q Inclusion Manifest
("closed-world warranty", 2026-04-28), composed over total_binding
(canon/digests, assert_partition) with CoverageRow-compatible accounting
(audit_bundle contract §C4).

What this adds: DENOMINATOR PROVENANCE. Every universe declares where its
element list came from, and the class rides the commitment:

  EXTERNAL_STRUCTURE   - enumerated from a structure the asserting party does
                         not author (a pinned CFR part's own section list, a
                         counterparty document set). Requires source_sha, the
                         digest of that artifact.
  MEASURED_ENUMERATION - enumerated by measurement the asserting party ran
                         over something it does not fully control (an OS op
                         census). Requires source_sha of the measurement
                         record.
  SELF_AUTHORED        - the asserting party wrote the list. A self-authored
                         universe is a COMMITTED STORY - still worth
                         committing (it pins the story), and the receipt
                         carries the class so a consumer can discount it.

  The class is a DECLARATION bound into universe_sha, not a check: nothing
  here verifies that source_sha's artifact exists or says what is claimed.
  Checking that is the consumer's anchoring procedure, outside this module.

THE ANCHOR RULE, applied to this module itself (both fresh-context audits of
v1 landed the same hit): a receipt/universe pair re-authored *consistently*
re-verifies, so verification against material supplied by the asserting
party is internal consistency, not evidence. Therefore:

  * verify_receipt REQUIRES expected_universe_sha - the digest the verifier
    holds from its OWN pre-commitment channel. Mandatory-explicit, no
    default. Without an externally-held sha, nothing distinguishes a
    re-derivation from a well-formed forgery.
  * the reason enum lives INSIDE the universe document, so committing the
    denominator commits the excuse vocabulary - it cannot be widened or
    shrunk per-receipt.
  * every entry point re-validates a supplied universe document in full
    (validate_universe); v1 enforced its invariants only in the constructor,
    and hand-built empty/duplicate universes built verifying receipts
    (executed, not hypothetical).
  * check_receipt_self_consistency exists for receipt-only consumers and is
    labelled what it is: internal consistency. A receipt is evidence-bearing
    only when accompanied by its universe + covered + withheld inputs and an
    externally-held expected_universe_sha.
  * (v3) a consumer that INTERPRETS withheld reasons semantically — counts
    them, branches on them, excuses by them — must pass expected_reason_enum:
    the vocabulary its own code understands, required to be the same reason
    set as the committed enum (order immaterial; compared in canonical
    sorted form). The anchor pins the enum only transitively, and not at
    all under same-custody anchoring (the asserting party publishes both the
    universe and its sha); an uninterpreted reason that falls through a
    consumer's arithmetic uncounted is a silent denominator leak (executed:
    port 3 audit finding #1 — a widened enum laundered an under-informed 2/3
    into an anchored, re-derived 1.0). expected_reason_enum is beyond the
    asserting party's reach ONLY when sourced from the consumer's own code;
    echoing the presented document's enum back into the parameter is a no-op
    that reads as protection, and no runtime check can tell the two apart —
    the pin's whole value is sourcing discipline. It pins the vocabulary,
    not the truth of any reason.

Fail-closed doctrine (matches total_binding): duplicates are errors, an
unknown withheld reason is an error, an element outside the universe is an
error, an empty universe is an error (a closed universe of nothing is the
vacuity exploit), a withheld key colliding across the string/digest
namespaces is an error (never a silent merge), float-bearing and
zero-width/unnormalized-string elements are errors (eye-invisible
denominator padding), and every public function raises ClosedUniverseError.

Honest limits: a closed universe converts "silently blind" into "declaredly
blind" and nothing more - it cannot close an open-ended universe and says
nothing about elements the enumeration missed. Unicode-confusable element
pairs beyond the NFC/format-character check are not linted.

Convention: canonical here; consumers vendor a byte-identical copy under a
drift-guard test (see total_binding / _total_binding.py). The dual-path
import below is what keeps the copies byte-identical.
"""

from __future__ import annotations

import unicodedata
from typing import Iterable, Mapping

try:  # canonical location (paired_events_ref sibling)
    from total_binding import (
        TotalBindingError,
        assert_partition,
        canon_bytes,
        total_digest,
        value_digest,
    )
except ImportError:  # vendored location (audit_bundle/_closed_universe.py)
    from audit_bundle._total_binding import (  # type: ignore[no-redef]
        TotalBindingError,
        assert_partition,
        canon_bytes,
        total_digest,
        value_digest,
    )

PROVENANCE_CLASSES = (
    "EXTERNAL_STRUCTURE",
    "MEASURED_ENUMERATION",
    "SELF_AUTHORED",
)

# Names the DOCUMENT format. v3 (expected_reason_enum) is verification-side
# only — universe/receipt bytes and shas are unchanged, so the version is not.
RECEIPT_VERSION = 2

_UNIVERSE_FIELDS = (
    "version",
    "domain",
    "source",
    "source_sha",
    "provenance",
    "reason_enum",
    "elements",
    "n",
    "universe_sha",
)

_RECEIPT_FIELDS = (
    "version",
    "domain",
    "universe_sha",
    "provenance",
    "source",
    "source_sha",
    "reason_enum",
    "n_universe",
    "n_covered",
    "n_withheld",
    "covered_sha",
    "withheld",
    "withheld_reason_breakdown",
    "receipt_sha",
)


class ClosedUniverseError(ValueError):
    """Universe/receipt construction or verification failure. Fail closed."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ClosedUniverseError(msg)


def _digest(obj, domain: str) -> str:
    """total_digest with this module's fixed envelope choices, converting the
    codec's own failures into this module's exception contract."""
    try:
        return total_digest(obj, exclude=(), domain=domain, schema=None)
    except TotalBindingError as exc:
        raise ClosedUniverseError(f"object not digestible: {exc}") from exc


def _value_digest(obj) -> str:
    try:
        return value_digest(obj)
    except TotalBindingError as exc:
        raise ClosedUniverseError(f"element not digestible: {exc}") from exc


def _walk_hygiene(obj, path: str) -> None:
    """Reject element content that pads or disguises the denominator:
    floats (repr-dependent, cross-toolchain collapse hazard) and strings that
    are non-NFC or carry format/zero-width characters (eye-invisible
    distinctness)."""
    if type(obj) is float:
        raise ClosedUniverseError(
            f"float at {path} in a universe/covered element: floats are "
            "repr-dependent denominator hazards; use strings or ints"
        )
    if type(obj) is str:
        if unicodedata.normalize("NFC", obj) != obj:
            raise ClosedUniverseError(f"non-NFC string at {path}: {obj!r}")
        for ch in obj:
            if unicodedata.category(ch) == "Cf":
                raise ClosedUniverseError(
                    f"format/zero-width character U+{ord(ch):04X} at {path}"
                )
    elif type(obj) is dict:
        for k, v in obj.items():
            _walk_hygiene(k, f"{path}.{k!r}")
            _walk_hygiene(v, f"{path}.{k!r}")
    elif type(obj) is list:
        for i, v in enumerate(obj):
            _walk_hygiene(v, f"{path}[{i}]")


def _element_list(elements: Iterable, what: str) -> list:
    """Validate an element collection: strict plain JSON per element (enforced
    by canon_bytes), hygiene-checked, duplicates are errors, order is
    canonicalized."""
    out = list(elements)
    for e in out:
        try:
            canon_bytes(e)
        except TotalBindingError as exc:
            raise ClosedUniverseError(
                f"{what} element {e!r} is not strict plain JSON: {exc}"
            ) from exc
        _walk_hygiene(e, what)
    seen: dict = {}
    for e in out:
        d = _value_digest(e)
        if d in seen:
            raise ClosedUniverseError(
                f"duplicate {what} element (multiset discipline): {e!r}"
            )
        seen[d] = e
    return sorted(out, key=canon_bytes)


def _validate_reason_enum(reasons: list) -> list:
    _require(
        len(reasons) > 0
        and all(type(r) is str and r for r in reasons)
        and len(set(reasons)) == len(reasons),
        "reason_enum must be a non-empty list of unique non-empty strings",
    )
    return sorted(reasons)


def _expected_enum(expected: "Iterable[str]") -> list:
    """Normalize a caller-supplied expected_reason_enum. A bare string is
    refused, never char-split: list("ab") == ["a", "b"] would silently turn a
    fat-fingered spelling into a character vocabulary that can even MATCH a
    single-character enum (v3 red-team finding #1)."""
    _require(
        not isinstance(expected, (str, bytes)),
        "expected_reason_enum must be a collection of reason strings, not a "
        "bare string (a string would be char-split, silently)",
    )
    return _validate_reason_enum(list(expected))


def declare_universe(
    elements: Iterable,
    *,
    domain: str,
    source: str,
    provenance: str,
    reason_enum: Iterable[str],
    source_sha: "str | None" = None,
) -> dict:
    """Commit the denominator AND the excuse vocabulary. Returns the universe
    document (fields: _UNIVERSE_FIELDS).

    - elements: the full enumeration, strict plain JSON, hygiene-checked, no
      duplicates, canonically sorted. Empty is an error.
    - source: human-checkable statement of WHERE the enumeration came from.
    - source_sha: digest of the enumerated artifact itself (the pinned CFR
      XML, the counterparty document set, the measurement record). REQUIRED
      for EXTERNAL_STRUCTURE and MEASURED_ENUMERATION; must be None for
      SELF_AUTHORED (there is no independent artifact to point at, and
      pretending otherwise would launder the class).
    - reason_enum: the closed vocabulary of withholding reasons, committed
      here so it rides universe_sha and cannot be rewritten per-receipt.
    - provenance: one of PROVENANCE_CLASSES - a bound declaration, not a
      check (see module docstring).
    """
    _require(bool(domain) and type(domain) is str, "domain must be a non-empty str")
    _require(bool(source) and type(source) is str, "source must be a non-empty str")
    _require(
        provenance in PROVENANCE_CLASSES,
        f"provenance must be one of {PROVENANCE_CLASSES}, got {provenance!r}",
    )
    if provenance == "SELF_AUTHORED":
        _require(
            source_sha is None,
            "SELF_AUTHORED universes must not carry a source_sha - there is "
            "no independent artifact, and claiming one launders the class",
        )
    else:
        _require(
            type(source_sha) is str and len(source_sha) == 64,
            f"{provenance} requires source_sha: the 64-hex digest of the "
            "enumerated artifact",
        )
    reasons = _validate_reason_enum(list(reason_enum))
    elems = _element_list(elements, "universe")
    _require(
        len(elems) > 0,
        "empty universe refused: a closed universe of nothing is the vacuity exploit",
    )
    body = {
        "version": RECEIPT_VERSION,
        "domain": domain,
        "source": source,
        "source_sha": source_sha,
        "provenance": provenance,
        "reason_enum": reasons,
        "elements": elems,
        "n": len(elems),
    }
    body["universe_sha"] = _digest(body, f"closed_universe:{domain}")
    return body


def validate_universe(
    universe: dict, *, expected_reason_enum: "Iterable[str] | None" = None
) -> None:
    """Re-run EVERY declare-time invariant on a supplied universe document,
    and require it to re-derive its own universe_sha. Called at the top of
    build_receipt and verify_receipt: v1 trusted supplied documents, and
    hand-built empty/duplicate universes produced verifying receipts.

    expected_reason_enum (v3): the vocabulary the CALLER's own code
    interprets, and it MUST come from that code — echoing the presented
    document's own enum back is a no-op that reads as protection, and
    nothing here can detect it. When given, the committed enum must be the
    same reason set (order of the expectation immaterial; comparison is on
    the canonical sorted form): widened, narrowed, or renamed all refuse — a
    difference that happens to be harmless is still a different excuse
    contract. A bare string is refused, never char-split. Semantic consumers
    must pass it — see the module docstring's v3 rule; None checks nothing
    and leaves v2 behavior untouched."""
    _require(type(universe) is dict, "universe document must be a dict")
    for field in _UNIVERSE_FIELDS:
        _require(field in universe, f"universe document missing {field!r}")
    _require(
        set(universe) == set(_UNIVERSE_FIELDS),
        f"universe document carries unknown fields: "
        f"{sorted(set(universe) - set(_UNIVERSE_FIELDS))}",
    )
    _require(
        universe["version"] == RECEIPT_VERSION,
        f"unsupported universe version {universe['version']!r}",
    )
    rebuilt = declare_universe(
        universe["elements"],
        domain=universe["domain"],
        source=universe["source"],
        provenance=universe["provenance"],
        reason_enum=universe["reason_enum"],
        source_sha=universe["source_sha"],
    )
    _require(
        universe["n"] == rebuilt["n"],
        f"universe n={universe['n']!r} does not match its {rebuilt['n']} elements",
    )
    _require(
        universe["elements"] == rebuilt["elements"],
        "universe elements are not in canonical order (was this document "
        "built by declare_universe?)",
    )
    _require(
        universe["reason_enum"] == rebuilt["reason_enum"],
        "universe reason_enum is not in canonical order",
    )
    _require(
        universe["universe_sha"] == rebuilt["universe_sha"],
        "universe document does not re-derive its own universe_sha",
    )
    if expected_reason_enum is not None:
        expected = _expected_enum(expected_reason_enum)
        _require(
            universe["reason_enum"] == expected,
            f"universe reason_enum {universe['reason_enum']!r} does not equal "
            f"the consumer's expected_reason_enum {expected!r} — a semantic "
            "consumer must refuse vocabulary it does not interpret (an "
            "uncounted reason is a silent denominator leak)",
        )


def _withheld_indexes(elements: list) -> "tuple[dict, dict]":
    """(digest_index, string_index). A string element equal to ANOTHER
    element's digest is a namespace collision and an error - never a silent
    merge (the total_binding.closure rule)."""
    digest_index: dict = {}
    string_index: dict = {}
    for e in elements:
        digest_index[_value_digest(e)] = e
        if type(e) is str:
            string_index[e] = e
    for s in string_index:
        if s in digest_index and digest_index[s] is not string_index[s]:
            raise ClosedUniverseError(
                f"withheld-key namespace collision: string element {s!r} "
                "equals another element's digest - never a silent merge"
            )
    return digest_index, string_index


def build_receipt(universe: dict, covered: Iterable, withheld: Mapping) -> dict:
    """Partition the universe and emit the receipt (fields: _RECEIPT_FIELDS).

    covered:  elements the output actually covers.
    withheld: {key: reason}. A key is the element itself (string elements
              only) or the element's value_digest. Reasons MUST come from the
              universe's committed reason_enum. Duplicate keys resolving to
              one element, keys matching nothing, and string/digest namespace
              collisions are all errors.

    The emitted receipt's `withheld` is a canonically-sorted list of
    {"element": ..., "reason": ...} pairs - the SAME partition always yields
    the SAME receipt bytes regardless of which key spelling the caller used
    (v1 let the spelling leak into receipt_sha: 2^k encodings of one fact).

    Enforced, all fail-closed: validate_universe(universe) first; then the
    exact multiset partition covered ⊎ withheld = universe via
    total_binding.assert_partition (omission, surplus, and double-counting
    all fail; a duplicate inside `covered` fails earlier in _element_list).
    """
    validate_universe(universe)
    reasons = universe["reason_enum"]
    covered_list = _element_list(covered, "covered")

    digest_index, string_index = _withheld_indexes(universe["elements"])
    withheld_pairs: list = []
    seen_digests: set = set()
    for key, reason in dict(withheld).items():
        _require(
            type(key) is str,
            f"withheld key {key!r} must be an exact str (element or digest)",
        )
        _require(
            type(reason) is str and reason in reasons,
            f"withheld reason {reason!r} for {key!r} is not in the universe's "
            f"committed reason_enum {reasons}",
        )
        if key in digest_index:
            elem = digest_index[key]
        elif key in string_index:
            elem = string_index[key]
        else:
            raise ClosedUniverseError(
                f"withheld key {key!r} matches no universe element"
            )
        d = _value_digest(elem)
        _require(
            d not in seen_digests,
            f"duplicate withheld keys resolve to one universe element: {elem!r}",
        )
        seen_digests.add(d)
        withheld_pairs.append({"element": elem, "reason": reason})
    withheld_pairs.sort(key=lambda p: canon_bytes(p["element"]))

    try:
        assert_partition(
            universe["elements"],
            [covered_list, [p["element"] for p in withheld_pairs]],
        )
    except TotalBindingError as exc:
        raise ClosedUniverseError(
            "covered + withheld is not exactly the universe (omission, "
            f"surplus, or double-count): {exc}"
        ) from exc

    breakdown: dict = {}
    for p in withheld_pairs:
        breakdown[p["reason"]] = breakdown.get(p["reason"], 0) + 1

    body = {
        "version": RECEIPT_VERSION,
        "domain": universe["domain"],
        "universe_sha": universe["universe_sha"],
        "provenance": universe["provenance"],
        "source": universe["source"],
        "source_sha": universe["source_sha"],
        "reason_enum": reasons,
        "n_universe": len(universe["elements"]),
        "n_covered": len(covered_list),
        "n_withheld": len(withheld_pairs),
        "covered_sha": _digest(
            {"covered": covered_list},
            f"closed_universe_covered:{universe['domain']}",
        ),
        "withheld": withheld_pairs,
        "withheld_reason_breakdown": dict(sorted(breakdown.items())),
    }
    body["receipt_sha"] = _digest(
        {k: v for k, v in body.items()},
        f"closed_universe_receipt:{universe['domain']}",
    )
    return body


def check_receipt_self_consistency(
    receipt: dict, *, expected_reason_enum: "Iterable[str] | None" = None
) -> None:
    """INTERNAL CONSISTENCY ONLY - what a receipt-only consumer can check:
    field inventory, §C4 sum invariants, withheld-list coherence against the
    embedded enum, and receipt_sha recomputation. It cannot establish that
    the universe was honest, that covered was real, or that the enum matches
    any prior commitment; a consistently re-authored receipt passes. Evidence
    requires verify_receipt with the inputs and an externally-held
    expected_universe_sha.

    expected_reason_enum (v3): required to be the same reason set as the
    receipt's EMBEDDED enum (order immaterial), so a semantic receipt-only
    consumer at least never interprets a vocabulary it does not understand —
    the module docstring's v3 rule, applied at the weakest door. This
    upgrades nothing to evidence — a re-authored receipt embedding the
    expected enum still passes."""
    _require(type(receipt) is dict, "receipt must be a dict")
    for field in _RECEIPT_FIELDS:
        _require(field in receipt, f"receipt missing {field!r}")
    _require(
        set(receipt) == set(_RECEIPT_FIELDS),
        f"receipt carries unknown fields: "
        f"{sorted(set(receipt) - set(_RECEIPT_FIELDS))}",
    )
    if expected_reason_enum is not None:
        expected = _expected_enum(expected_reason_enum)
        _require(
            receipt["reason_enum"] == expected,
            f"receipt reason_enum {receipt['reason_enum']!r} does not equal "
            f"the consumer's expected_reason_enum {expected!r} — a semantic "
            "consumer must refuse vocabulary it does not interpret",
        )
    _require(
        receipt["n_covered"] + receipt["n_withheld"] == receipt["n_universe"],
        "sum invariant violated: n_covered + n_withheld != n_universe",
    )
    pairs = receipt["withheld"]
    _require(
        type(pairs) is list and len(pairs) == receipt["n_withheld"],
        "withheld list length does not match n_withheld",
    )
    reasons = receipt["reason_enum"]
    breakdown: dict = {}
    for p in pairs:
        _require(
            type(p) is dict and set(p) == {"element", "reason"},
            f"malformed withheld pair: {p!r}",
        )
        _require(
            p["reason"] in reasons,
            f"withheld reason {p['reason']!r} not in the receipt's enum",
        )
        breakdown[p["reason"]] = breakdown.get(p["reason"], 0) + 1
    _require(
        breakdown == receipt["withheld_reason_breakdown"],
        "withheld_reason_breakdown does not match the withheld list",
    )
    recomputed = _digest(
        {k: v for k, v in receipt.items() if k != "receipt_sha"},
        f"closed_universe_receipt:{receipt['domain']}",
    )
    _require(
        recomputed == receipt["receipt_sha"],
        "receipt does not re-derive its own receipt_sha",
    )


def verify_receipt(
    receipt: dict,
    universe: dict,
    covered: Iterable,
    withheld: Mapping,
    *,
    expected_universe_sha: str,
    expected_reason_enum: "Iterable[str] | None" = None,
) -> None:
    """Full verification: the universe re-validates, it matches the sha the
    VERIFIER holds (mandatory-explicit - material supplied by the asserting
    party cannot anchor its own check), and the receipt re-derives
    byte-identically from (universe, covered, withheld).

    expected_reason_enum (v3): mandatory in spirit for any verifier that goes
    on to INTERPRET reasons — the anchor pins the enum only through
    universe_sha, which under same-custody anchoring the asserting party
    authored. See validate_universe."""
    _require(
        type(expected_universe_sha) is str and len(expected_universe_sha) == 64,
        "expected_universe_sha (the verifier's own pre-commitment) is "
        "required: without it this is internal consistency, not evidence",
    )
    validate_universe(universe, expected_reason_enum=expected_reason_enum)
    _require(
        universe["universe_sha"] == expected_universe_sha,
        "universe does not match the verifier's expected_universe_sha",
    )
    rebuilt = build_receipt(universe, covered, withheld)
    try:
        identical = canon_bytes(rebuilt) == canon_bytes(receipt)
    except TotalBindingError as exc:
        raise ClosedUniverseError(f"receipt not canonicalizable: {exc}") from exc
    _require(
        identical,
        "receipt does not re-derive byte-identically from its inputs",
    )


def to_coverage_row(
    receipt: dict,
    tick_id: str,
    *,
    expected_reason_enum: "Iterable[str] | None" = None,
) -> dict:
    """CoverageRow-shaped dict for the audit-bundle §C4 accounting. Runs
    check_receipt_self_consistency first - v1 passed hand-forged counts
    straight through to the sum-invariant validator, which a consistent
    forgery satisfies. Returned as a plain dict (no audit_bundle import
    here); the row is accounting only and MUST travel with
    coverage_row_binding(receipt), which carries the identity the row
    cannot.

    expected_reason_enum (v3): this door EMITS per-reason counts — the exact
    semantic interpretation the v3 rule is about — so a §C4 consumer passes
    its own vocabulary here and an unrecognised reason refuses instead of
    riding into the accounting (v3 red-team finding #2)."""
    check_receipt_self_consistency(receipt, expected_reason_enum=expected_reason_enum)
    return {
        "tick_id": tick_id,
        "n_eligible": receipt["n_universe"],
        "n_issued": receipt["n_covered"],
        "n_withheld": receipt["n_withheld"],
        "withheld_reason_breakdown": dict(receipt["withheld_reason_breakdown"]),
    }


def coverage_row_binding(
    receipt: dict, *, expected_reason_enum: "Iterable[str] | None" = None
) -> dict:
    """The identity fields a coverage row must carry alongside its counts -
    without these the row is three integers from nowhere. Takes the v3
    expected_reason_enum pin like to_coverage_row, so the paired calls can be
    pinned symmetrically."""
    check_receipt_self_consistency(receipt, expected_reason_enum=expected_reason_enum)
    return {
        "universe_sha": receipt["universe_sha"],
        "provenance": receipt["provenance"],
        "source_sha": receipt["source_sha"],
        "receipt_sha": receipt["receipt_sha"],
    }
