"""audit_bundle/claimset.py — claim-field coverage as a closed-universe receipt.

THE PROBLEM. A bundle's claim-bearing payload files can carry fields no
wired check ever reads: the verdict is then green over claims nothing
compared, a scope defect invisible on the verdict face. A 99-pilot fleet
sweep (2026-07) found 46 pilots in that state, and the per-pilot fixes left
the honest residuals ("this field has no binding target", "this field's
semantics are not mechanically checkable") recorded only as README prose,
which machine consumers never see (against the spirit of contract clause
C-6: machine-readable completeness).

THE MECHANISM. When a bundle opts in via the manifest's `claimset` key, the
verifier enumerates a closed universe of claim-field elements from the
declared claim files' pinned bytes, takes the union of the fields wired
plugins REPORTED they accounted for (`PluginResult.verified_claim_fields`,
the same per-channel coverage-accounting discipline as cross-host edges,
fragment anchors, dispatch records, and stamp claims), takes the bundle's
committed residual map, and requires an exact partition:

    covered ⊎ withheld-with-committed-reason = every claim-field element

Any silent remainder is could-not-conclude (clean-ERROR, exit 2): a field
neither checked nor excused never rides a green verdict. On a coherent
partition the verdict face carries the receipt's identity (counts +
universe_sha + receipt_sha + reason breakdown) as a machine-readable
Completeness disclosure. Bundles that do not declare `claimset` verify
byte-identically to before, with one added disclosure naming the absence.

    NOTE this is a COVERAGE gate, not a required-structure PRESENCE gate:
    the assurance-profile completeness walk asks "are the required parts of
    the manifest present"; this gate asks "was every field the payload DOES
    carry accounted for by some check or excused for a committed reason".
    Presence of a field is exactly what it does NOT certify: reading is.

THE UNIVERSE (per bundle). Elements are the OBSERVED field paths of each
declared claim file, instance-measured, NOT schema-derived (there is no
schema; the paths are whatever the shipped bytes actually carry), rendered
"<payload-key>:a.b[].c":

  * object keys join with "."; every array position collapses to "[]" (the
    obligation is per-FIELD, not per-cell; instance cells are exercised by
    per-field tamper batteries, not by this accounting);
  * a claim file MUST be structured JSON or JSONL, decided by CONTENT never
    filename: bytes that parse as one JSON value are one document; bytes
    that are not one JSON value but whose every non-empty line parses are a
    JSONL union of line paths; bytes that are NEITHER are REFUSED, never
    demoted to a single opaque whole-file element (a demotion would let a
    producer shrink the denominator by shipping claims a strict parser
    cannot read, and using content not filename means a rename cannot
    trigger it either). Whole-file (OPAQUE) claims are a separate, explicit
    DECLARATION (`opaque_claim_files`): the classifier is TOTAL over bytes
    into a closed set of kinds (SINGLE_JSON, JSONL, NOT_JSON_SHAPED,
    JSON_SHAPED_BUT_CORRUPT: duplicate object keys; a NaN/Infinity token or
    an integer over 600 digits; a body with a line holding an object or
    array with a member beside lines that do not read; any other JSON
    evidence), and each declaration
    admits a fixed subset (`DECLARATION_ADMITS`): structured admits the two
    JSON kinds, opaque admits ONLY NOT_JSON_SHAPED, and CORRUPT /
    JSON_OVER_DEPTH / HOLLOW are admitted by no declaration (so a producer
    cannot shrink a structured denominator by corrupting, re-encoding,
    deep-wrapping or relabelling the file). STATED LIMIT: "opaque" is the
    complement of THIS module's strict reader and of its JSON-evidence
    tests (`_looks_json_shaped`: a '{'/'['-opened body; one value once
    decoded and trimmed; a line read as an object or array holding a
    member, or every line read, over the LF/CR and LF line splits; a
    str.splitlines line read as an object holding a member or an array
    holding one; a JSON-family DOCUMENT holding one), not a positive format
    check: a document in some other structured vocabulary (YAML, CSV) is
    one opaque element, and what the evidence tests do not model is stated
    in the conventions statement (JSON5 value syntax, leniency on one line,
    a multi-line value after an unreadable line, an array holding no object
    on a str.splitlines-only line, other prefixes, trims, decodes and
    record separators, readers that stop at the first error, truncated
    JSONC). Whole-file binding is evidenced only by the
    tamper battery, never by admission. An opaque element renders as the
    payload key alone, the same rendering as a root scalar; the kind and
    the declared path ride `universe_sha` through the `source` statement,
    which carries both declared maps. Opaque bytes are bounded by SIZE
    (stat before read); the JSON depth scan only classifies on that path
    (depth past the admission bound is classified by an iterative scanner;
    the strict parser never sees it). Every declared claim file WITH A
    COVERED ELEMENT must appear
    in the `files_audited` of EACH plugin result that covered one of its
    elements (`CLAIMSET_COVERED_FILE_UNAUDITED` otherwise): a covered
    element names a file the covering plugin REPORTED opening; both sides
    are the plugin's self-report (C-10 trust), so this is a consistency
    obligation on the report, and the tamper battery remains the evidence
    that the bytes were bound;
  * a leaf is a scalar position or an empty container; when instances
    disagree (a path holds a scalar in one record and an object in
    another) BOTH the terminating path and the deeper paths are elements:
    every observed termination is an obligation;
  * enumeration is FAIL-CLOSED: a declared claim file that is missing,
    unpinned in manifest.files, outside the bundle directory, empty (a
    JSONL body with no rows), carrying duplicate object keys (stdlib JSON
    silently keeps the last, an eye-invisible way to make this walker and a
    comparator read different fields), or using reserved characters (":",
    ".", "[", "]") or empty strings as keys, refuses loudly. Duplicate keys
    and other JSON-shaped corruption RAISE even though the file "looks"
    structured; they never quietly fall through to the opaque branch. A
    partial universe silently re-opens the very hole this module closes.

  KNOWN LIMIT (instance, not schema): a field that is optional in the
  producer's own data model and absent from every shipped instance is not
  an element; the denominator is the field set the bytes carry, not a
  declared maximal schema. Shipping degenerate instances yields a smaller,
  honest-looking denominator; the fix for a relying party that needs the
  full field set is the verifier-held universe anchor (below), not this
  enumeration.

PROVENANCE = SELF_AUTHORED (the closed_universe doctrine applied honestly).
The claim files are the producer's OWN artifact, fully controlled: the
element set is a pure function of bytes the asserting party wrote, so the
universe is a COMMITTED STORY, not a measurement over something external.
The helper reserves MEASURED_ENUMERATION for enumeration over an artifact
the asserting party does not control and requires a source_sha of that
independent artifact; there is none here, so declaring one would launder
the class. Byte-integrity of the claim files is provided SEPARATELY and
already: every declared file is pinned in manifest.files under the §C9 SHA
walk (a declared file absent from manifest.files is refused), so the
denominator is bound to the verdict's byte-set without over-claiming an
independent provenance the enumeration does not have.

WHEN IS THIS EVIDENCE-GRADE. On its own the gate is a coverage-accounting
receipt for a COOPERATIVE producer: it makes the covered/withheld partition
of the producer-chosen denominator legible and fails closed on a silent
remainder. It is not, by itself, a defence against an adversarial producer,
which can (all disclosed, none silent) shrink the denominator by leaving a
claim file out of `claim_files`, excuse a real field with a residual
reason, or over-report coverage. Two anchors turn the cooperative receipt
into evidence for a relying party that pre-commits: the verifier-held
`expected_universe_sha` (below) commits the exact denominator and forces
declaration, closing the omit-the-file and omit-the-key moves for that
relying party; and the per-field tamper battery (tests/claimset_ratchet.py)
is the executable check that a reported-covered field is actually bound.
Residual-reason truth stays a producer-committed story no mechanical check
can settle in general (the one mechanizable sub-case, DERIVED_FROM_COVERED
with zero covered fields, is refused).

WHAT THIS DOES AND DOES NOT CLAIM. The gate converts silently-unaccounted
into declared: it proves nothing about comparator QUALITY (a covered field
can still be weakly compared, that is the tolerance/fail-open problem,
tracked separately), and residual REASONS are a producer-committed story
the receipt makes legible, never a verified fact. Coverage reporting is a
promise by verifier-distribution plugin code (contract clause C-10 trust
posture, same as every other accounting channel); the executable check
that a reported field is REALLY compared is the per-field tamper battery
(tests/claimset_ratchet.py), which mutates covered cells
producer-consistently and requires the verdict to flip. And the universe
is what the producer chose to emit: a claim never written into a claim
file is invisible here. A closed universe converts silently-blind into
declaredly-blind, nothing more.

Stdlib + first-party only (contract clause C-2).
"""

from __future__ import annotations

import codecs
import json
import re
from .strict_json import StrictJSONError, strict_json_loads
import unicodedata
from collections.abc import Callable, Iterable
from enum import Enum
from itertools import accumulate
from typing import NamedTuple
from pathlib import Path, PurePosixPath

from ._closed_universe import ClosedUniverseError, build_receipt, declare_universe
from .admission import AdmissionLimits, admit_bytes

# The committed withholding vocabulary for claim-field residuals. One line
# each; the helper binds the enum into universe_sha so it cannot drift
# per-bundle. Seeded from the residual vocabulary the pilot fleet actually
# records (2026-07 sweep + the post-fix pilot documentation).
CLAIMSET_REASON_ENUM = (
    # nothing else in the bundle exists to bind the field against
    "NO_BINDING_TARGET",
    # the field's semantics require judgment (entailment, intent); an honest
    # residual beats a fake heuristic
    "NOT_MECHANICALLY_CHECKABLE",
    # a named party vouches for the value; the verifier checks the
    # attestation artifact, never the fact itself (C17 / C19.B posture)
    "ATTESTED_NOT_REDERIVED",
    # recomputable from covered fields, self-defending, now declared
    "DERIVED_FROM_COVERED",
    # human-inspection convenience / schema label carrying no claim
    "INSPECTION_ONLY",
)

# Structured reason codes surfaced on the verdict face by the coverage guard.
CLAIMSET_DECLARATION_MALFORMED = "CLAIMSET_DECLARATION_MALFORMED"
CLAIMSET_ENUMERATION_FAILED = "CLAIMSET_ENUMERATION_FAILED"
CLAIMSET_COVERED_FIELD_UNKNOWN = "CLAIMSET_COVERED_FIELD_UNKNOWN"
CLAIMSET_RESIDUAL_INVALID = "CLAIMSET_RESIDUAL_INVALID"
CLAIMSET_RESIDUAL_INCOHERENT = "CLAIMSET_RESIDUAL_INCOHERENT"
CLAIMSET_FIELD_DOUBLE_ACCOUNTED = "CLAIMSET_FIELD_DOUBLE_ACCOUNTED"
CLAIMSET_UNIVERSE_ANCHOR_MISMATCH = "CLAIMSET_UNIVERSE_ANCHOR_MISMATCH"
CLAIMSET_COVERED_FILE_UNAUDITED = "CLAIMSET_COVERED_FILE_UNAUDITED"

# Reserved by the element rendering; a key containing one would make two
# different fields render identically, so enumeration refuses them.
_RESERVED_KEY_CHARS = frozenset(":.[]")

# Fail-closed ceiling on universe size: a schema-level enumeration of any
# real payload is far below this; a pathological one must refuse rather than
# stall the verdict path.
_MAX_ELEMENTS = 10_000

_ARRAY_MARKER = "[]"


class ClaimBytesKind(str, Enum):
    """The closed, TOTAL classification of a claim file's bytes. Every byte
    string is exactly one of these (the exceptions are the two row ceilings,
    resource bounds that refuse loudly rather than classify: the LF/CR line
    count, and the object-line count of the str.splitlines split);
    which DECLARATION may carry a kind is the `DECLARATION_ADMITS` table,
    never an inference from a parse failure."""

    SINGLE_JSON = "SINGLE_JSON"  # one value the strict parser reads
    JSONL = "JSONL"  # every non-empty line one value the strict parser reads
    # No strict JSON/JSONL reader can read it, AND it carries no JSON
    # evidence (`_looks_json_shaped`). The ONLY kind an opaque declaration
    # admits.
    NOT_JSON_SHAPED = "NOT_JSON_SHAPED"
    # JSON-shaped bytes a producer could have made unreadable on purpose:
    # duplicate object keys (stdlib keeps the last, eye-invisible); a NaN or
    # Infinity token, an integer over 600 digits; a body with a line holding
    # an object or array with a member beside lines that do not read (a
    # corrupted JSONL claim file); bytes `json.loads(bytes)` reads that the
    # strict reader does not (a BOM, UTF-16/32, a surrogate, on the body or
    # on one line); a JSON-family document holding an object or array with
    # a member (JSONC, concatenated values, other whitespace, an XSSI guard);
    # or bytes whose first character opens a JSON container ('{' / '[') but
    # that do not parse (truncation, ...). The full list is
    # `_looks_json_shaped`. Admitted by NO declaration: a corrupt structured
    # file has nowhere to hide, under any name.
    JSON_SHAPED_BUT_CORRUPT = "JSON_SHAPED_BUT_CORRUPT"
    # JSON nested past the admission depth bound (one value, or every line,
    # in the json-module grammar as the capped scanner reads it, nesting to
    # 1024 levels read as JSON): refused at admission as structured,
    # and refused as opaque. Otherwise wrapping a claim file in 65 brackets
    # would collapse its denominator to one element. Admitted by NO
    # declaration.
    JSON_OVER_DEPTH = "JSON_OVER_DEPTH"
    # Empty or whitespace-only bytes, or bytes that are only whitespace and
    # U+FEFF once decoded (a BOM in front of nothing): a hollow claim,
    # admitted nowhere.
    HOLLOW = "HOLLOW"


# Which kinds each declaration map admits. A closed table: the ratchet in
# tests asserts it is disjoint and that JSON_SHAPED_BUT_CORRUPT appears in
# no row. Structured admits the two JSON kinds; opaque admits ONLY bytes that
# carry no JSON evidence, never "bytes this parser failed on".
DECLARATION_ADMITS: "dict[str, frozenset[ClaimBytesKind]]" = {
    "claim_files": frozenset({ClaimBytesKind.SINGLE_JSON, ClaimBytesKind.JSONL}),
    "opaque_claim_files": frozenset({ClaimBytesKind.NOT_JSON_SHAPED}),
}

# Residual reasons an OPAQUE element may not carry: every reason that denies
# the artifact is a claim at all: nothing to bind against (then do not declare
# it), recomputable from covered fields (then re-derive it, i.e. cover it),
# or "inspection only / carries no claim" (the same denial in other words).
# What remains: a named party attests it, or its semantics need judgment.
OPAQUE_RESIDUAL_REASONS_FORBIDDEN = frozenset(
    {"NO_BINDING_TARGET", "DERIVED_FROM_COVERED", "INSPECTION_ONLY"}
)

# Conventions version token. It rides universe_sha through the source
# statement, so a relying party seeing CLAIMSET_UNIVERSE_ANCHOR_MISMATCH can
# tell "the conventions moved" from "the producer shrank the denominator".
CLAIMSET_CONVENTIONS_VERSION = "claimset-conventions/v3"


class ClaimsetError(ValueError):
    """Claimset declaration or universe-enumeration failure. Fail closed."""


class NotJsonShaped(ClaimsetError):
    """Bytes the strict reader cannot read that carry no JSON evidence
    (`_looks_json_shaped`): the ONLY refusal of the structured path that an
    opaque declaration may stand on."""


class JsonShapedButCorrupt(ClaimsetError):
    """JSON-shaped bytes the strict reader refuses (duplicate keys, a
    NaN/Infinity token, an integer over 600 digits; a JSONL body with a
    corrupted line; any other JSON evidence). Refused under EVERY
    declaration."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ClaimsetError(msg)


def _check_key(key: object, where: str) -> None:
    _require(
        type(key) is str and key != "",
        f"{where}: object keys must be non-empty strings, got {key!r}",
    )
    assert isinstance(key, str)
    bad = sorted(set(key) & _RESERVED_KEY_CHARS)
    _require(
        not bad,
        f"{where}: key {key!r} contains reserved character(s) {bad} — the "
        "element rendering cannot express it unambiguously, refusing rather "
        "than escaping (two spellings of one field is the hazard)",
    )
    # The vendored closed-universe helper refuses non-NFC strings and
    # format/zero-width characters in elements (eye-invisible distinctness).
    # Apply the same rule here so the refusal is a clean REJECT at this
    # boundary, never a helper exception escaping the verdict path.
    _require(
        unicodedata.normalize("NFC", key) == key,
        f"{where}: key {key!r} is not NFC-normalized — two visually identical "
        "spellings of one field is the hazard; normalize the key",
    )
    _require(
        not any(unicodedata.category(ch) == "Cf" for ch in key),
        f"{where}: key {key!r} carries a format/zero-width character — refused",
    )


def _is_canonical_rel(rel: str) -> bool:
    """A declared path must already be in the one canonical spelling
    (`payload/a.bin`): POSIX separators, no leading '/' or './', no '..', no
    empty/'.' segments, NFC-normalized, no control or format characters.
    Refusing non-canonical spellings (instead of normalizing them) keeps "one
    file, one key" decidable by string equality and keeps the declared string
    identical to its manifest.files pin. String canonicality is not file
    identity: enumeration additionally refuses two keys whose declared paths
    RESOLVE to one file (symlinks, case-insensitive filesystems)."""
    if "\\" in rel or rel.startswith("/") or rel != rel.strip():
        return False
    if unicodedata.normalize("NFC", rel) != rel:
        return False
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in rel):
        return False
    parts = rel.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        return False
    return PurePosixPath(rel).as_posix() == rel


def validate_claimset_declaration(claimset: object) -> None:
    """Shape-check a manifest `claimset` value (parse-boundary discipline:
    present-but-malformed is rejected, never treated as absent).

    Required shape:
        {"claim_files":        {payload-key: bundle-relative path, ...},
         "opaque_claim_files": {payload-key: bundle-relative path, ...},
         "residuals":          {element: reason, ...}}
    Every map is optional in FORM; at least one of the two claim-file maps
    must be non-empty (a declaration over nothing is the vacuity exploit,
    opt out by omitting the `claimset` key, never by declaring a hollow
    one). Keys are disjoint across the two maps (one payload key, one kind)
    and declared PATHS are injective across their union (one file, one key:
    two keys on one file would pad the denominator for free). Residual
    REASONS must come from CLAIMSET_REASON_ENUM; whether each residual
    element exists in the universe, and whether an opaque element's reason is
    permitted, is checked at verify time (the universe does not exist yet at
    the parse boundary).
    """
    # isinstance, not exact-type: manifest values arrive deep-frozen as a
    # dict subclass (audit_bundle._freeze), and JSON parsing can only ever
    # produce plain containers underneath.
    _require(isinstance(claimset, dict), "claimset must be a JSON object")
    assert isinstance(claimset, dict)
    unknown = sorted(
        str(k)
        for k in set(claimset) - {"claim_files", "opaque_claim_files", "residuals"}
    )
    _require(not unknown, f"claimset carries unknown keys: {unknown}")

    def _file_map(name: str) -> dict:
        value = claimset.get(name, {})
        _require(
            isinstance(value, dict),
            f"claimset.{name} must be an object of "
            "{payload-key: bundle-relative path}",
        )
        assert isinstance(value, dict)
        for key, rel in value.items():
            _check_key(key, f"claimset.{name}")
            _require(
                isinstance(rel, str) and rel != "",
                f"claimset.{name}[{key!r}] must be a non-empty "
                f"bundle-relative path string, got {rel!r}",
            )
            assert isinstance(rel, str)
            _require(
                _is_canonical_rel(rel),
                f"claimset.{name}[{key!r}] path {rel!r} is not a canonical "
                "bundle-relative path (no leading './' or '/', no '..', no "
                "empty or '.' segments, no backslashes) — the injectivity "
                "rule compares canonical paths, so non-canonical spellings "
                "are refused rather than normalized",
            )
        return dict(value)

    claim_files = _file_map("claim_files")
    opaque = _file_map("opaque_claim_files")
    _require(
        len(claim_files) + len(opaque) > 0,
        "claimset declares no claim files (claim_files and opaque_claim_files "
        "are both empty or absent) — an empty declaration is the vacuity "
        "exploit; omit the claimset key to opt out",
    )
    both = sorted(set(claim_files) & set(opaque))
    _require(
        not both,
        f"payload key(s) {both} appear in both claim_files and "
        "opaque_claim_files — one payload key, one kind",
    )
    seen: dict = {}
    for name, fm in (("claim_files", claim_files), ("opaque_claim_files", opaque)):
        for key, rel in fm.items():
            _require(
                rel not in seen,
                f"claim file {rel!r} is declared twice ({seen.get(rel)} and "
                f"{name}[{key!r}]) — one file, one key; a second key on the "
                "same bytes pads the denominator without adding a claim",
            )
            seen[rel] = f"{name}[{key!r}]"

    residuals = claimset.get("residuals", {})
    _require(
        isinstance(residuals, dict),
        "claimset.residuals must be an object of {element: reason}",
    )
    assert isinstance(residuals, dict)
    for element, reason in residuals.items():
        _require(
            isinstance(element, str) and element != "",
            f"claimset.residuals key {element!r} must be a non-empty string",
        )
        _require(
            reason in CLAIMSET_REASON_ENUM,
            f"claimset.residuals[{element!r}] reason {reason!r} is not in the "
            f"committed enum {CLAIMSET_REASON_ENUM}",
        )


# ---------------------------------------------------------------------------
# "Is it JSON?" is asked by ONE classifier, `classify_kind`.
#
# ADMISSION as structured (SINGLE_JSON / JSONL) is decided by `_json_body`
# with the strict parser (`_read_strict`): the whole body as one value, else
# every non-empty line as one, else an object/array line holding a member
# beside a line that does not read (a corrupt JSONL file). Past the depth
# bound, in the body or in one line, the iterative scanner (`_read_syntax`)
# answers instead and the strict parser never sees those bytes
# (JSON_OVER_DEPTH).
#
# REFUSAL as JSON-shaped, for bytes the strict parser does not admit, is
# decided by `_looks_json_shaped` over the body decoded as json.loads decodes
# it (`_decode`), and where that is UTF-16/32, also as UTF-8 (`_text_read`),
# with readers that only ever widen refusal:
#
# * `_read_trimmed`: one value in the json-module grammar (NaN and Infinity
#   included, integers of any length) once `_TRIM` is trimmed from the ends —
#   for the whole body and for every line of the line splits;
# * `_reads_as_a_document`, for the whole body only: JSON-family documents
#   (JSONC comments and trailing commas, concatenated values, RFC 7464, any
#   Unicode whitespace and U+FEFF between tokens, an XSSI guard) that hold an
#   object or array with a member.
#
# `_read_text` and the document reader answer exactly as the capped
# iterative scanner (`_scan_json_text(..., cap=_SCAN_DEPTH_CAP)`) does. json's
# C decoder does the reading, and never deeper than `_JSON_DEPTH` (64, the
# admission bound): `_nesting_index` finds where the text's structure first
# nests that deep, json reads only up to there, and a prefix valid up to
# there is read on by the scanner. So json's recursion stays within what any
# thread stack Python runs on holds (1,030 levels overflow a 128 KiB musl
# stack). The line and body
# readers hand `_read_text` only text that could start and end a value
# (`_could_be_a_value`): text nesting past the cap that ends in something
# else is not read, and json.loads does not read it either. So the kind
# depends on neither the caller's stack depth, the CPython version (3.11,
# 3.12 and 3.13 checked), nor `sys.get_int_max_str_digits()`.
#
# Leniency is a DOCUMENT reading on purpose: applied line by line, comments,
# trailing commas and concatenation read `{}` or `[4, 5, 6]` out of source
# code, reports and binaries. And only an object or array holding a member is
# evidence in a line: an empty one hides no field.
#
# `stdlib_reads_as_json` is NOT part of the classifier and nothing on the
# verify path calls it. It is the named oracle the opaque admission
# is graded against (the property tests, kill condition K5); it calls the
# real `json.loads`, with its own decoder `_decode_bom_text` for its line
# split, and past json's recursion budget the UNCAPPED scanner. It shares
# with the classifier the scanner's grammar and the row ceiling, and cannot
# catch a bug in those.
# ---------------------------------------------------------------------------


def stdlib_reads_as_json(raw: bytes) -> bool:
    """THE NAMED ORACLE for opaque admission: does the stdlib reader
    a relying party would actually use (`json.loads` on BYTES, with its own
    encoding auto-detection) read these bytes as one JSON value, or every
    non-empty line as one? json's two limits that vary by setting are
    lifted, so the answer holds under any digit limit and any recursion
    budget: integers of any length (no `sys.get_int_max_str_digits()`), and
    nesting of any depth (past json's recursion budget the UNCAPPED
    iterative scanner reads the text json.loads decoded). It recurses as
    json.loads does, on the caller's C stack: a test-side oracle, never on
    the verify path (the classifier bounds json at `_JSON_DEPTH`). The
    opaque admission is graded against THIS function (properties, kill
    condition K5), never against the classifier alone."""
    if not raw.strip():
        return False

    def _one(b: bytes) -> bool:
        try:
            json.loads(b, parse_int=str)
            return True
        except RecursionError:
            # json.loads decoded the bytes before it recursed; a leading
            # U+FEFF left after that is not JSON whitespace to either reader
            return _scan_json_text(
                b.decode(json.detect_encoding(b), "surrogatepass")
            ).reads
        except ValueError:
            return False

    if _one(raw):
        return True
    dec = _decode_bom_text(raw)
    body = dec if dec is not None else raw
    lines = [ln for ln in body.splitlines() if ln.strip()]
    return (
        bool(lines) and len(lines) <= _MAX_JSONL_ROWS and all(_one(ln) for ln in lines)
    )


_JSON_WS = " \t\n\r"
_JSON_WS_RUN = re.compile(r"[ \t\n\r]*")
_JSON_DIGITS = "0123456789"
_JSON_HEX = "0123456789abcdefABCDEF"


def is_strict_json_value(raw: bytes) -> bool:
    """Iterative syntax scanner: whether `raw` (strict UTF-8, no BOM) is ONE
    value in `json.loads`' grammar (the same literals incl. NaN/Infinity, the
    same string and number grammar), at ANY nesting depth and with integers
    of any length, in linear time and without recursion. Syntax only
    (duplicate keys are not its concern). The tests hold it against
    `json.loads`; the oracle uses its scanner past json's recursion budget."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return _scan_json_text(s).reads


class _Scan(NamedTuple):
    reads: bool
    # a top-level object or array holds at least one member: an empty one
    # hides no field (a root `{}` renders as the payload key alone, the same
    # single element an opaque declaration gives)
    container: bool


_NOT_READ = _Scan(False, False)
# The refusal readers take a value whose nesting reaches this many levels
# before its first syntax error as read, holding a member (JSON-shaped),
# without reading further: it bounds the Python scanner's work on bracket runs
# a producer can make 15 MiB long. The oracle's scanner has no cap.
_SCAN_DEPTH_CAP = 1024
_JSON_WS_SET = frozenset(_JSON_WS)
# A `//` comment ends where JSONC and JavaScript end it: LF, CR, LS, PS.
_COMMENT_END = "\n\r\u2028\u2029"
# Everything a JSON-family reader skips between tokens of a DOCUMENT: any
# Unicode whitespace (`\s` is str.isspace: NBSP, U+2028, the RS that frames RFC
# 7464 sequences), U+FEFF, `//` line comments, `/* */` block comments (an
# unterminated one runs to the end). Whitespace is matched a RUN per
# iteration (a group repeated per character costs ~1 us each in `re`); the
# pattern can end anywhere and nothing follows it, so a failed iteration ends
# the match instead of backtracking.
_FAMILY_TRIVIA = re.compile(
    r"(?:[\s\ufeff]+|//[^" + _COMMENT_END + r"]*|/\*.*?(?:\*/|\Z))*", re.DOTALL
)
# Unicode whitespace: every character str.isspace() accepts (29; none past
# U+3000, which a test holds against the whole code space).
_UNICODE_SPACE = "".join(ch for ch in map(chr, range(0x3001)) if ch.isspace())
# Whitespace and U+FEFF: what the HOLLOW test and the first-character test
# skip.
_SPACE = _UNICODE_SPACE + "\ufeff"
# What a line reader trims from a line's ends: the union over common readers
# of Unicode whitespace (Python str.strip, Go TrimSpace, Java strip), U+FEFF
# (JavaScript trim) and the C0 control characters (Java String.trim takes
# U+0000-U+0020; PHP and Ruby trim NUL).
_TRIM = _SPACE + "".join(map(chr, range(0x20)))


def _skip_json_ws(s: str, i: int) -> int:
    """The index past the JSON whitespace starting at `i`."""
    m = _JSON_WS_RUN.match(s, i)
    return m.end() if m else i


def _skip_family_trivia(s: str, i: int) -> int:
    """The index past the trivia starting at `i` (`_FAMILY_TRIVIA`)."""
    m = _FAMILY_TRIVIA.match(s, i)
    return m.end() if m else i


def _scan_json_text(
    s: str, *, family: bool = False, start: int = 0, cap: "int | None" = None
) -> _Scan:
    """The scanner behind `is_strict_json_value`, over text. Strict: `s` is
    ONE value in `json.loads(str)`'s grammar (integers of any length). With
    `family`: one or more values (concatenated JSON, JSON Lines, RFC 7464
    sequences), separated by the trivia `_skip_family_trivia` skips, with a
    trailing comma allowed before a closing bracket. The value grammar
    (strings, numbers, literals) is the same in both modes. `start` skips a
    prefix the caller has already read. With `cap`: once an opener would
    nest `cap` levels deep, the answer is "read, holding a member", without
    reading further."""
    n = len(s)

    def skip_ws(i: int) -> int:
        if i < n and s[i] not in _JSON_WS_SET and (not family or not s[i].isspace()):
            if not family or s[i] not in "/\ufeff":
                return i  # nothing to skip: the common case, without a regex
        if family:
            return _skip_family_trivia(s, i)
        m = _JSON_WS_RUN.match(s, i)
        return m.end() if m else i

    def scan_string(i: int) -> int:
        i += 1
        while i < n:
            c = s[i]
            if c == '"':
                return i + 1
            if c == "\\":
                i += 1
                if i >= n:
                    return -1
                e = s[i]
                if e in '"\\/bfnrt':
                    i += 1
                elif e == "u":
                    hexpart = s[i + 1 : i + 5]
                    if len(hexpart) != 4 or any(h not in _JSON_HEX for h in hexpart):
                        return -1
                    i += 5
                else:
                    return -1
            elif ord(c) < 0x20:
                return -1
            else:
                i += 1
        return -1

    def scan_number(i: int) -> int:
        j = i
        if j < n and s[j] == "-":
            j += 1
        if j < n and s[j] == "0":
            j += 1
        elif j < n and s[j] in "123456789":
            while j < n and s[j] in _JSON_DIGITS:
                j += 1
        else:
            return -1
        if j < n and s[j] == ".":
            j += 1
            if j >= n or s[j] not in _JSON_DIGITS:
                return -1
            while j < n and s[j] in _JSON_DIGITS:
                j += 1
        if j < n and s[j] in "eE":
            j += 1
            if j < n and s[j] in "+-":
                j += 1
            if j >= n or s[j] not in _JSON_DIGITS:
                return -1
            while j < n and s[j] in _JSON_DIGITS:
                j += 1
        return j

    def scan_scalar(i: int) -> int:
        c = s[i]
        if c == '"':
            return scan_string(i)
        elif c == "-" or c in _JSON_DIGITS:
            if s.startswith("-Infinity", i):
                return i + len("-Infinity")
            return scan_number(i)
        else:
            # the literal vocabulary is closed; anything else is a terminal
            # syntax failure (-1), never a silent pass
            for lit in ("true", "false", "null", "NaN", "Infinity"):
                if s.startswith(lit, i):
                    return i + len(lit)
            return -1

    def scan_key_colon(i: int) -> int:
        i = skip_ws(i)
        if i >= n or s[i] != '"':
            return -1
        i = scan_string(i)
        if i < 0:
            return -1
        i = skip_ws(i)
        if i >= n or s[i] != ":":
            return -1
        return i + 1

    stack: list[str] = []
    container = False
    i = skip_ws(start)
    if i >= n:
        return _NOT_READ
    expect_value = True
    while True:
        if expect_value:
            if len(stack) == 1:
                container = True  # a member of a top-level object or array
            i = skip_ws(i)
            if i >= n:
                return _NOT_READ
            c = s[i]
            if (c == "{" or c == "[") and cap is not None and len(stack) + 1 >= cap:
                return _Scan(True, True)
            if c == "{":
                stack.append("o")
                i = skip_ws(i + 1)
                if i < n and s[i] == "}":
                    i += 1
                    stack.pop()
                    expect_value = False
                    continue
                i = scan_key_colon(i)
                if i < 0:
                    return _NOT_READ
                continue
            elif c == "[":
                stack.append("a")
                i = skip_ws(i + 1)
                if i < n and s[i] == "]":
                    i += 1
                    stack.pop()
                    expect_value = False
                continue
            else:
                # not a container opener: must be a scalar, or it is a
                # terminal syntax failure
                i = scan_scalar(i)
                if i < 0:
                    return _NOT_READ
                expect_value = False
                continue
        i = skip_ws(i)
        if not stack:
            if i >= n:
                return _Scan(True, container)
            if family:
                expect_value = True  # the next value of a stream
                continue
            return _NOT_READ
        if i >= n:
            return _NOT_READ
        top = stack[-1]
        c = s[i]
        if c == ",":
            i += 1
            if family:
                j = skip_ws(i)
                if j < n and s[j] == ("}" if top == "o" else "]"):
                    stack.pop()  # a trailing comma before the closer
                    i = j + 1
                    expect_value = False
                    continue
            if top == "o":
                i = scan_key_colon(i)
                if i < 0:
                    return _NOT_READ
            else:
                pass  # array: the next value follows directly
            expect_value = True
            continue
        elif (c == "}" and top == "o") or (c == "]" and top == "a"):
            stack.pop()
            i += 1
            expect_value = False
            continue
        else:
            # any other byte after a value inside an open container is a
            # terminal syntax failure
            return _NOT_READ


def _capped_scan(s: str, *, family: bool = False, start: int = 0) -> _Scan:
    return _scan_json_text(s, family=family, start=start, cap=_SCAN_DEPTH_CAP)


# A JSON string, or an unterminated one running to the end: the structure-free
# spans `_nesting_index` skips when it counts brackets. On a valid JSON prefix
# every '"' outside a string opens one, so this matches exactly the prefix's
# strings.
_STRING_OR_TAIL = re.compile(r'"(?:[^"\\]++|\\.?)*+(?:"|\Z)', re.DOTALL)
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")
_BRACKET_STEP = {"[": 1, "{": 1, "]": -1, "}": -1}
_STRUCTURE = re.compile(_STRING_OR_TAIL.pattern + r"|[\[\]{}]", re.DOTALL)


# The deepest nesting the refusal readers hand json's recursive C decoder:
# the admission bound's default, as in v0.2.1. json's recursion guard counts
# levels, not stack bytes: 1,030 levels overflow a 128 KiB thread stack (the
# musl/Alpine default) and kill the process; 64 fit any stack Python runs on.
# Text nesting deeper is read by the iterative scanner, which answers the same.
_JSON_DEPTH = 64


def _nesting_index(s: str, depth: int) -> "int | None":
    """The index just past the opener where the brackets outside strings
    first nest `depth` deep, or None when they never do. On the prefix json's
    decoder reads before its first syntax error these brackets ARE its
    nesting, so json handed `s[:index]` (or `s`, for None) recurses fewer than
    `depth` levels. Counted in C first; the index is located only for text
    that does nest that deep."""
    if s.count("[") + s.count("{") < depth:
        return None
    brackets = _NOT_BRACKET.sub("", _STRING_OR_TAIL.sub("", s))
    if max(accumulate(map(_BRACKET_STEP.__getitem__, brackets)), default=0) < depth:
        return None
    level = 0
    for m in _STRUCTURE.finditer(s):
        c = s[m.start()]
        if c == "[" or c == "{":
            level += 1
            if level >= depth:
                return m.end()
        elif c == "]" or c == "}":
            level -= 1
    raise AssertionError("unreachable: the bracket count reached the depth")  # pragma: no cover


# integers of any length: json parses the digits into nothing, so
# `sys.get_int_max_str_digits()` never decides a read
_LIMITLESS = json.JSONDecoder(parse_int=str)


def _scan_read(text: str) -> "_Read | None":
    scan = _capped_scan(text)
    return _Read(None, scan.container) if scan.reads else None


def _read_text(text: str) -> "_Read | None":
    """One value in the json-module grammar (NaN and Infinity, integers of
    any length), answering exactly as the capped scanner does. json's
    decoder reads no deeper than `_JSON_DEPTH` (`_nesting_index`): where the
    text nests that deep, json reads the prefix up to that opener; an error
    before it is the text's first error (not read), and a prefix valid up to
    it leaves the answer to the scanner. A RecursionError (a caller already
    near its limit) also leaves it to the scanner."""
    q = _nesting_index(text, _JSON_DEPTH)
    try:
        value = _LIMITLESS.decode(text if q is None else text[:q])
    except json.JSONDecodeError as exc:
        return None if q is None or exc.pos < q else _scan_read(text)
    except (RecursionError, ValueError):  # ValueError: none known, integers kept as text
        return _scan_read(text)
    # text[:q] ends in an opener, so only a whole value shallower than
    # `_JSON_DEPTH` gets here
    return _Read(None, _has_member(value))


def _decode_bom_text(raw: bytes) -> "bytes | None":
    """If `raw` is in an encoding the stdlib's own `json.loads(bytes)` would
    auto-detect (a UTF BOM, or the BOM-less UTF-16/UTF-32 null-byte patterns
    that `json.detect_encoding` recognises), decode it strictly and return
    the text re-encoded as plain UTF-8 (BOM stripped); None for plain UTF-8
    or when the body does not decode. The oracle's decoder for its line
    split (`stdlib_reads_as_json`); the classifier decodes with `_decode`.
    An encoding alone proves nothing: a UTF-16 text file is a genuine
    artifact."""
    enc = json.detect_encoding(raw)
    if enc == "utf-8":
        return None
    try:
        return raw.decode(enc).encode("utf-8")
    except (UnicodeDecodeError, LookupError):
        return None


def _opens_container(raw: bytes) -> bool:
    """The first byte past JSON whitespace (these four bytes) opens a JSON
    object or array."""
    return raw.lstrip(b" \t\n\r")[:1] in (b"{", b"[")


# Fail-closed ceiling on JSONL rows before any parse, so a many-micro-row body
# cannot spend unbounded parse time (admit_bytes already caps total bytes).
_MAX_JSONL_ROWS = 1_000_000


class _Read(NamedTuple):
    """A reader's answer for bytes it reads: the value (a document from the
    strict reader; None from the others) and whether it is an object or
    array holding at least one member. A reader returns None for bytes it
    does not read."""

    value: object
    container: bool


class _PastDepth(Exception):
    """Raised by `_read_strict` BEFORE parsing bytes that nest past the
    admission depth bound: the strict parser must never see them."""


def _read_strict(raw: bytes, what: str, *, max_depth: int) -> "_Read | None":
    """The strict parser (`audit_bundle.strict_json`) as a reader: the parsed
    value, or None when the bytes do not read as one value (a syntax error,
    or not UTF-8); the caller decides the shape. A SEMANTIC refusal —
    duplicate object keys (stdlib silently keeps the last, and two parsers
    can then disagree about which field a document carries), a NaN/Infinity
    token, an integer token over 600 digits — raises JsonShapedButCorrupt.

    Depth is bounded per VALUE, not only per body: `admit_bytes` carries its
    string state across lines, so an unbalanced quote on one line hides the
    brackets of every later line from the whole-body scan, and a line nested
    ~10,000 deep then reached the recursive parser (RecursionError, at a
    threshold that moved with the caller's stack depth). Bytes with no more
    openers than the bound cannot nest past it, so the scan runs only when
    they could."""
    if raw.count(b"[") + raw.count(b"{") > max_depth and (
        admit_bytes(
            raw, AdmissionLimits(max_bytes=max(len(raw), 1), max_depth=max_depth)
        )
        is not None
    ):
        raise _PastDepth(what)
    try:
        doc = strict_json_loads(raw)
    except StrictJSONError as exc:
        raise JsonShapedButCorrupt(
            f"{what}: {exc} — refusing a document whose meaning depends on "
            "parser tie-breaking or on a non-JSON token"
        ) from exc
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return _Read(doc, _has_member(doc))


def _read_syntax(raw: bytes, what: str) -> "_Read | None":
    """The capped iterative scanner as a reader: strict UTF-8, the
    json-module grammar (NaN and Infinity, integers of any length), syntax
    only, nesting to `_SCAN_DEPTH_CAP` read as holding a member. It never
    builds the value."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text.startswith("\ufeff") or not _could_be_a_value(text.strip(_JSON_WS)):
        return None
    scan = _capped_scan(text)
    return _Read(None, scan.container) if scan.reads else None


def _has_member(value: object) -> bool:
    """An object or array holding at least one member (see `_Scan`)."""
    return type(value) in (dict, list) and len(value) > 0  # type: ignore[arg-type]


def _encoding(raw: bytes) -> str:
    """`json.detect_encoding(raw)`, without the call where its answer is
    plain UTF-8 for certain: no BOM can start with this first byte and
    neither of the first two bytes is zero (a line of text, the common case,
    decoded once per line and split)."""
    if raw[:1] not in (b"\x00", b"\xef", b"\xfe", b"\xff") and raw[1:2] != b"\x00":
        return "utf-8"
    return json.detect_encoding(raw)


def _decode(raw: bytes) -> "tuple[str, bool]":
    """The bytes as text, decoded as `json.loads(bytes)` decodes them (the
    encoding `json.detect_encoding` names, a BOM consumed, surrogates passed),
    and True; where that decode fails, in the same encoding with the invalid
    bytes dropped (`errors="ignore"`, which reads everything `"replace"`
    reads: a replacement character is never structure), and False. A UTF-16
    or UTF-32 length that is not a whole number of code units cannot decode,
    so it is not tried."""
    enc = _encoding(raw)
    unit = 4 if enc.startswith("utf-32") else 2 if enc.startswith("utf-16") else 1
    if len(raw) % unit == 0:
        try:
            return raw.decode(enc, "surrogatepass"), True
        except UnicodeDecodeError:
            pass
    return raw.decode(enc, "ignore"), False


def _opens_after_space(raw: bytes, text: str, exact: bool) -> bool:
    """The first character past Unicode whitespace and U+FEFF opens an object
    or array, the bytes decoded as `json.loads(bytes)` decodes them, or where
    that fails with invalid bytes REPLACED (a replacement character stays a
    character, so garbage in front of a bracket is not skipped) — decoded
    only as far as that first character."""
    if exact:
        return text.lstrip(_SPACE)[:1] in ("{", "[")
    decoder = codecs.getincrementaldecoder(json.detect_encoding(raw))("replace")
    step = 1 << 16
    for k in range(0, len(raw), step):
        head = decoder.decode(raw[k : k + step], final=k + step >= len(raw))
        head = head.lstrip(_SPACE)
        if head:
            return head[0] in "{["
    return False


# Every JSON value starts with one of these and ends with one of these.
_VALUE_START = frozenset('{["-0123456789tfnNI')
_VALUE_END = frozenset('}]"0123456789elyN')


def _trim(text: str) -> str:
    """`text` without `_TRIM` (Unicode whitespace, U+FEFF, C0 controls) at
    either end."""
    return text.strip(_TRIM)


def _could_be_a_value(t: str) -> bool:
    return bool(t) and t[0] in _VALUE_START and t[-1] in _VALUE_END


def _read_trimmed(t: str) -> "_Read | None":
    """A trimmed line (or a trimmed whole body) as a line reader reads it,
    used only to REFUSE: ONE value in the json-module grammar, any kind.
    Everything `json.loads(bytes)` reads once decoded is read here (JSON
    whitespace is in `_TRIM`, and a value neither starts nor ends with a
    `_TRIM` character). No comments, no trailing commas, no second value:
    those are document readings (`_reads_as_a_document`), and on single
    lines they read `{}` out of source code and binaries. Text that cannot
    start and end a JSON value is never handed to a parser."""
    return _read_text(t) if _could_be_a_value(t) else None


# What the family grammar allows INSIDE a value that json's decoder refuses:
# a comment, a trailing comma, whitespace other than JSON's four, U+FEFF.
_FAMILY_HINT = re.compile(r"/[/*]|,[\s\ufeff]*[\]}]|[^\S \t\n\r]|\ufeff")
# One JSON scalar, as json's decoder reads it (numbers, strings, literals),
# and an object or array holding only scalars. A run of these with JSON
# whitespace between is read in one step by the document reader: it matches
# only what json's decoder reads, nests one level at most, and holds a member
# where `_FLAT_MEMBER` finds one.
_WS = r"[ \t\n\r]*+"
_STRING = r'"[^"\\\x00-\x1f]*+(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})[^"\\\x00-\x1f]*+)*+"'
_SCALAR = (
    r"(?:-Infinity|-?(?:0|[1-9][0-9]*+)(?:\.[0-9]++)?(?:[eE][-+]?[0-9]++)?|"
    + _STRING
    + r"|true|false|null|NaN|Infinity)"
)
_FLAT_ARRAY = rf"\[{_WS}(?:{_SCALAR}(?:{_WS},{_WS}{_SCALAR})*+{_WS})?\]"
_FLAT_PAIR = rf"{_STRING}{_WS}:{_WS}{_SCALAR}"
_FLAT_OBJECT = rf"\{{{_WS}(?:{_FLAT_PAIR}(?:{_WS},{_WS}{_FLAT_PAIR})*+{_WS})?\}}"
_FLAT_RUN = re.compile(rf"(?:(?:{_SCALAR}|{_FLAT_ARRAY}|{_FLAT_OBJECT}){_WS})*+")
# In a flat run with its strings emptied: a container holding a member.
_FLAT_MEMBER = re.compile(r"\[[ \t\n\r]*+[^\] \t\n\r]|\{[ \t\n\r]*+[^} \t\n\r]")
# The guards a JSON-hijacking defence puts in front of a JSON response and its
# client strips before parsing: `)]}'` (optionally `,`) on a line of its own
# (AngularJS, Google), `for(;;);` and `while(1);` (spaces allowed inside).
_XSSI_GUARD = re.compile(
    r"[\s\ufeff]*(?:\)\]\}',?[ \t]*(?=[\n\r\u2028\u2029])"
    r"|for\s*\(\s*;\s*;\s*\)\s*;|while\s*\(\s*1\s*\)\s*;)"
)


def _without_xssi_prefix(text: str) -> str:
    """The text after an XSSI guard that opens it (`_XSSI_GUARD`,
    whitespace aside), or the text unchanged."""
    m = _XSSI_GUARD.match(text)
    return text[m.end() :] if m else text


# A JSON string, kept as it stands (an unterminated one runs to the end), and
# the family's own trivia outside strings: JSONC comments, whitespace other
# than JSON's four, U+FEFF. `_as_json` turns each trivia run into a space.
# The alternatives are tried left to right at each position, as a lexer
# reads, so a comment marker inside a string stays string content and a
# quote inside a comment opens no string.
_STRING_ALT = r'("(?:[^"\\]++|\\.?)*+(?:"|\Z))'
_FAMILY_ONLY_TRIVIA = re.compile(
    _STRING_ALT
    + r"|//[^\n\r\u2028\u2029]*+|/\*.*?(?:\*/|\Z)|[^\S \t\n\r]++|\ufeff++",
    re.DOTALL,
)
# A trailing comma: after the end of a value (a string's closing quote, a
# digit, the last letter of a literal, a closing bracket), before a closing
# bracket, JSON whitespace around it. `_as_json` drops it.
_TRAILING_COMMA = re.compile(
    _STRING_ALT
    + r"(?:[ \t\n\r]*+,(?=[ \t\n\r]*+[\]}]))?"
    + r"|([0-9elyN\]}])[ \t\n\r]*+,(?=[ \t\n\r]*+[\]}])"
)


def _as_json(text: str) -> str:
    """A JSON-family document rewritten as a JSON stream that json's decoder
    reads exactly where the family grammar does (`_capped_scan(family=True)`,
    held against it by the tests): each run of family-only trivia outside
    strings becomes a space, then each trailing comma is dropped. Strings are
    kept (a space follows each, which JSON allows). A comma that follows no
    value (`[,]`, `{,}`) is kept, so the rewrite reads nothing the family
    grammar refuses."""
    return _TRAILING_COMMA.sub(r"\1\2 ", _FAMILY_ONLY_TRIVIA.sub(r"\1 ", text))


def _reads_as_a_document(text: str) -> bool:
    """Whether a JSON-family reader of whole DOCUMENTS reads the decoded text
    and finds an object or array holding a member: an XSSI guard dropped,
    then one or more values (concatenated JSON, jq, JSON Lines, RFC 7464)
    separated by any Unicode whitespace, U+FEFF or JSONC comments, with
    trailing commas allowed. Used only to REFUSE. The answer is the capped
    family scanner's (`_capped_scan(family=True)`): where the text holds
    something the family allows and json refuses (`_FAMILY_HINT`), it is
    rewritten as JSON (`_as_json`), and json's decoder reads the values, no
    deeper than `_JSON_DEPTH` (`_nesting_index`); past that the scanner
    reads on."""
    text = _without_xssi_prefix(text)
    if "{" not in text and "[" not in text:
        return False  # no object or array to find
    if _FAMILY_HINT.search(text):
        text = _as_json(text)
    # json reads no deeper than `_JSON_DEPTH`: a stream valid up to there is
    # read on by the scanner
    q = _nesting_index(text, _JSON_DEPTH)
    head = text if q is None else text[:q]
    n = len(head)
    member = False
    i = _skip_json_ws(head, 0)
    while i < n:
        j = _FLAT_RUN.match(head, i).end()  # type: ignore[union-attr]
        if j > i:
            if not member:
                flat = _STRING_OR_TAIL.sub('""', head[i:j])
                member = _FLAT_MEMBER.search(flat) is not None
            i = j
            continue
        try:
            value, end = _LIMITLESS.raw_decode(head, i)
        except json.JSONDecodeError as exc:
            if q is None or exc.pos < q:
                return False
            scan = _capped_scan(text, family=True, start=i)
            return scan.reads and (member or scan.container)
        except (RecursionError, ValueError):  # a caller near its limit; none known
            scan = _capped_scan(text, family=True, start=i)
            return scan.reads and (member or scan.container)
        member = member or _has_member(value)
        i = _skip_json_ws(head, end)
    return member


def _json_body(
    body: bytes,
    read: "Callable[[bytes, str], _Read | None]",
    where: str,
    *,
    whole: ClaimBytesKind,
    per_line: ClaimBytesKind,
    every_row: bool = False,
) -> "tuple[ClaimBytesKind, list] | None":
    """The admission readers' decision over a body: `body` read as one value
    → (`whole`, [value]); else `_json_rows`. A body that is exactly one line
    is not read again. (Only exactly: the line filter strips with
    bytes.strip, which removes \\x0b and \\x0c, and those are not JSON
    whitespace.)"""
    got = read(body, where)
    if got is not None:
        return whole, [got.value]
    rows = [ln for ln in body.splitlines() if ln.strip()]
    if rows == [body]:
        return None
    return _json_rows(rows, read, where, per_line=per_line, every_row=every_row)


def _json_rows(
    rows: "list[bytes]",
    read: "Callable[[bytes, str], _Read | None]",
    where: str,
    *,
    per_line: ClaimBytesKind,
    every_row: bool = False,
) -> "tuple[ClaimBytesKind, list] | None":
    """Every non-empty row read as one value → (`per_line`, values); else a
    row that reads as an object or array holding a member beside a row that
    does not → (JSON_SHAPED_BUT_CORRUPT, []): one corrupted line of a JSONL
    file, whichever line (`{}` hides no field); else None — no container
    row hides beside a failing one (scalar-only lines, such as a headerless
    numeric column, stay undecided), or there are no rows. A reader's
    JsonShapedButCorrupt propagates. The JSONL row ceiling raises HERE, and
    every body the classifier does not refuse as hollow passes through here
    (or is one value), so it binds every branch alike: a body the ceiling
    refuses must not become opaque because it also nests past the depth
    bound, or because it is UTF-16.

    Once a row has not read, a row with no '{' or '[' byte cannot change the
    answer (it is no container, in any encoding `json.detect_encoding` names,
    and "every row reads" is already false), so it is not read, unless
    `every_row`: a reader that can refuse a row semantically (the strict
    reader: a NaN or oversized-integer row) must see every row."""
    _require(
        len(rows) <= _MAX_JSONL_ROWS,
        f"{where}: {len(rows)} JSONL rows exceed the {_MAX_JSONL_ROWS} ceiling",
    )
    if not rows:
        # Nothing to read (decoded text can be empty where the raw bytes were
        # not). "Every line reads" over zero lines would be vacuously true.
        return None
    values: list = []
    unread = False
    container = False
    for i, row in enumerate(rows):
        if unread and not every_row and b"{" not in row and b"[" not in row:
            continue
        got = read(row, f"{where} line {i + 1}")
        if got is None:
            unread = True
        else:
            values.append(got.value)
            container = container or got.container
        if unread and container:
            # decided: "every row reads" is false and a container row hides
            # beside a failing one; no later row can change that (a reader
            # that refuses semantically would only say CORRUPT again)
            return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
    if not unread:
        return per_line, values
    if container:
        return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
    return None


def _redetects(row: str) -> bool:
    """Whether `json.loads` on this decoded line's UTF-8 bytes would detect
    another encoding (the line starts with NUL, or with one ASCII character
    and NUL): the stdlib oracle reads each line of a decoded body that way."""
    # a UTF-16/32 BOM cannot open UTF-8, and otherwise detection names
    # UTF-16/32 only for a zero byte among the first two, which only U+0000
    # encodes to
    return "\x00" in row[:2] and json.detect_encoding(
        row[:4].encode("utf-8", "surrogatepass")
    ) not in ("utf-8", "utf-8-sig")


def _read_decoded_line(
    row: str, t: str, read: "Callable[[str], _Read | None]"
) -> "_Read | None":
    """A line of the decoded text, `t` its trimmed form: read (`read`) as it
    stands, and also as `json.loads` reads the line's UTF-8 bytes where that
    detects another encoding (a line opening with NUL); read if either reads,
    holding a member if either does."""
    got = read(t)
    if (got is None or not got.container) and _redetects(row):
        other = read(_trim(_decode(row.encode("utf-8", "surrogatepass"))[0]))
        if other is not None:
            return other if got is None or other.container else got
    return got


def _lines_read(
    rows: "Iterable[bytes] | Iterable[str]",
    *,
    raw: bool,
    memo: "dict[str, _Read | None]",
) -> bool:
    """A line reader over one line split finds JSON: a line reads as an
    object or array holding a member, or every non-blank line reads (a line
    that trims to nothing is blank; a decoded line also where json.loads
    would read its UTF-8 bytes as nothing). `raw` lines are bytes, each
    decoded in its own detected encoding (`_decode`); the others are decoded
    text, and on plain UTF-8 they read all the raw lines would. Once
    a line has not read, a line with no '{' or '[' cannot change the answer,
    so it is not read. `memo` holds the reads of trimmed lines across the
    splits of one body: most lines are the same text in every split."""

    def read(t: str) -> "_Read | None":
        if t not in memo:
            memo[t] = _read_trimmed(t)
        return memo[t]

    every = True
    seen = False
    for row in rows:
        if raw:
            assert isinstance(row, bytes)
            if not every and b"{" not in row and b"[" not in row:
                continue
            t = _trim(_decode(row)[0])
            got = read(t) if t else None
        else:
            assert isinstance(row, str)
            if not every and "{" not in row and "[" not in row:
                continue
            t = _trim(row)
            got = _read_decoded_line(row, t, read) if t else None
            if got is None and t and _redetects(row):
                # blank as json.loads reads the line's UTF-8 bytes: the raw
                # split's rule, so this split reads all that one does
                if not _trim(_decode(row.encode("utf-8", "surrogatepass"))[0]):
                    t = ""
        if not t:
            continue  # blank
        seen = True
        if got is None:
            every = False
        elif got.container:
            return True
    return seen and every


_LONE_CR = re.compile(rb"\r(?!\n)")
_LONE_CR_TEXT = re.compile(r"\r(?!\n)")
_LF_CR = re.compile(r"\r\n?|\n")
# The line ends `str.splitlines` adds to LF and CR: VT, FF, FS, GS, RS (which
# also frames RFC 7464 records), NEL, LS, PS.
_OTHER_LINE_ENDS = "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
_ALL_LINE_ENDS = "\n\r" + _OTHER_LINE_ENDS
_TRIM_NOT_END = "".join(ch for ch in _TRIM if ch not in _ALL_LINE_ENDS)
# A line of `str.splitlines` that could hold an object with a member:
# trimmed, it opens with '{' and a key's opening quote (JSON whitespace
# between) and closes with '}', or opens with '[', holds '{' and a key's
# quote, and closes with ']'. An array holding no object is not read on
# these lines: between the extra line ends and C0 bytes a binary holds `[1]`
# or `[6]` by accident (a zip, two PNGs and three shared libraries in a sweep
# of 37k real files; 5 of 24 random 15 MiB bodies), and `{"` takes a key.
# Matches start only where a line starts, and each tries only its own line,
# so the scan is linear.
_OBJECT_LINE = re.compile(
    rf"(?<![^{_ALL_LINE_ENDS}])[{_TRIM_NOT_END}]*+"
    rf"(\{{[ \t]*+\"[^{_ALL_LINE_ENDS}]*\}}"
    rf"|\[(?=[^{_ALL_LINE_ENDS}]*\{{[ \t]*+\")[^{_ALL_LINE_ENDS}]*\])"
    rf"[{_TRIM_NOT_END}]*+(?![^{_ALL_LINE_ENDS}])"
)
# In JSON with its strings emptied: an object holding a member.
_OBJECT_WITH_MEMBER = re.compile(r"\{[ \t\n\r]*+[^} \t\n\r]")


def _splitlines_member(text: str, where: str) -> bool:
    """Python's `text.splitlines()` line reader (and an RFC 7464 reader that
    reads past a bad record) finds a line reading as an object holding a
    member, or as an array holding one. Only the lines that could are read;
    past `_MAX_JSONL_ROWS` of them the row ceiling raises."""
    count = 0
    for m in _OBJECT_LINE.finditer(text):
        count += 1
        _require(
            count <= _MAX_JSONL_ROWS,
            f"{where}: more than {_MAX_JSONL_ROWS} object lines "
            "(str.splitlines) exceed the JSONL row ceiling",
        )
        line = m.group(1)
        if _read_trimmed(line) is not None and (
            line[0] == "{"  # '{' then a key: an object holding a member
            or _OBJECT_WITH_MEMBER.search(_STRING_OR_TAIL.sub('""', line))
        ):
            return True
    return False


def _looks_json_shaped(raw: bytes, where: str, text: str, exact: bool) -> bool:
    """Evidence that bytes the strict reader does not admit are a JSON
    document some reader would still parse into fields. `text, exact` is
    `_decode(raw)`; where json detects UTF-16/32, the text-level tests run
    again over the bytes decoded as UTF-8 (`_text_read`). Any of:

    * the first non-whitespace byte opens a JSON object or array, or the
      first character of the decoded text (`_opens_after_space`) does past
      Unicode whitespace and U+FEFF;
    * the whole body, decoded and trimmed, reads as one value
      (`_read_trimmed`), whatever kind;
    * `_reads_as_a_document`: a JSON-family document reader finds an object
      or array holding a member;
    * a line reader (`_lines_read`) reads a line as an object or array
      holding a member, or reads every non-blank line. Its line splits: the
      raw bytes split at LF/CR, each line decoded in its own detected
      encoding (the oracle's split of a UTF-8 body); the decoded text split
      at LF/CR (the oracle's split of a BOM or UTF-16/32 body, and Python's
      text-mode iteration), each line read as it stands and, where
      json.loads would detect another encoding in its UTF-8 bytes, as that;
      where a lone CR occurs, both again split at LF only (binary-mode line
      iteration, JSON Lines; Go, Rust and JavaScript line splitting: a CR
      byte inside a UTF-16 character, or inside a record, does not end a
      line there). The raw split is not read where it is the decoded one
      (plain UTF-8 that decodes);
    * `_splitlines_member`: a line of `str.splitlines` (which also ends
      lines at VT, FF, FS, GS, RS, NEL, LS and PS) reads as an object
      holding a member (not an array: see `_OBJECT_LINE`).

    A BOM alone is not evidence: a UTF-16 text artifact stays opaque. Used
    ONLY to widen JSON_SHAPED_BUT_CORRUPT: bytes with this evidence are
    refused under every declaration, so admission as opaque never rests
    solely on "our strict parser failed". The strict sweep already held the
    raw bytes split at LF/CR to the row ceiling, and a LF/CR split of the
    decoded text has at most one non-blank line more (a last UTF-16-BE line
    whose bytes are all ASCII whitespace, U+2020 for one), so these line
    readers are not counted again: the ceiling bounds work, it is not
    evidence."""
    if _opens_container(raw) or _opens_after_space(raw, text, exact):
        return True
    plain_utf8 = exact and text.encode("utf-8", "surrogatepass") == raw
    memo: "dict[str, _Read | None]" = {}
    if not plain_utf8:
        rows = raw.splitlines()
        if rows != [raw] and _lines_read(rows, raw=True, memo=memo):
            return True
        if _LONE_CR.search(raw) and _lines_read(raw.split(b"\n"), raw=True, memo=memo):
            return True
    if _text_read(text, where, memo):
        return True
    # A text-mode reader decodes UTF-8 whatever json.detect_encoding says: a
    # NUL in the first two bytes makes json see UTF-16/32, and every text
    # reader above then sees that decode alone.
    if _encoding(raw) not in ("utf-8", "utf-8-sig"):
        return _text_read(_decode_as(raw, "utf-8"), where, memo)
    return False


def _decode_as(raw: bytes, enc: str) -> str:
    """`raw` in `enc`, surrogates passed, else with invalid bytes dropped."""
    try:
        return raw.decode(enc, "surrogatepass")
    except UnicodeDecodeError:
        return raw.decode(enc, "ignore")


def _text_read(text: str, where: str, memo: "dict[str, _Read | None]") -> bool:
    """The text-level evidence (2)-(5) over one decode of the body: the whole
    text trimmed is one value; the document reader; line readers over its
    LF/CR split and, where a lone CR occurs, its LF split; the str.splitlines
    reader."""
    whole = _trim(text)
    if whole and (_read_trimmed(whole) is not None or _reads_as_a_document(whole)):
        return True
    lines = _LF_CR.split(text)
    # one line read as it stands is the whole-body read above; json.loads
    # may still read its UTF-8 bytes in another encoding
    if (len(lines) > 1 or _redetects(text)) and _lines_read(lines, raw=False, memo=memo):
        return True
    if _LONE_CR_TEXT.search(text) and _lines_read(text.split("\n"), raw=False, memo=memo):
        return True
    return any(ch in text for ch in _OTHER_LINE_ENDS) and _splitlines_member(text, where)


def classify_kind(
    raw: bytes, where: str, *, limits: "AdmissionLimits | None" = None
) -> "tuple[ClaimBytesKind, list]":
    """TOTAL classification of one claim file's bytes into ClaimBytesKind,
    with the parsed documents for the two structured kinds (empty list
    otherwise). Decided by CONTENT, never filename. The raises are the row
    ceilings (resource bounds: the LF/CR line count here, and the object-line
    count of `_splitlines_member`), refused loudly under every
    declaration and on every branch below: a body the ceiling would refuse
    must not become opaque by also nesting past the depth bound, or by
    being UTF-16); everything else, including empty bytes, is a kind.

    Order of decision:
    * empty, or only Unicode whitespace and U+FEFF once decoded (a BOM in
      front of nothing) → HOLLOW;
    * the strict reader, in ONE sweep, body first, then lines in order:
      - one strict JSON value → SINGLE_JSON; else every non-empty line one
        → JSONL;
      - a duplicate key, a NaN/Infinity token or an integer over 600
        digits in the body or in a line reached → CORRUPT;
      - nesting past the admission depth bound in the body or in a line
        reached (the strict parser never sees it) → the capped scanner
        decides: one value, or every line → JSON_OVER_DEPTH;
      - an object/array holding a member beside a line that does not read
        → CORRUPT (one corrupted line of a JSONL claim file, whichever
        line);
      (which of CORRUPT and JSON_OVER_DEPTH comes back can depend on which
      line the sweep reaches first; both are refused everywhere)
    * else JSON evidence (`_looks_json_shaped`) → CORRUPT;
    * else → NOT_JSON_SHAPED. Scalar-only lines (a headerless numeric
      column) beside lines nothing reads stay NOT_JSON_SHAPED unless a line
      reader reads every one; an empty object or array beside them hides no
      field. (The strict reader's semantic refusals apply where it reads,
      UTF-8 within the depth bound; a NaN line in a UTF-16 body beside a
      line nothing reads stays NOT_JSON_SHAPED.)
    """
    text, exact = _decode(raw)
    if not raw.strip() or (exact and not text.strip(_SPACE)):
        # empty, or whitespace once decoded: a BOM (or a UTF-16 newline) in
        # front of nothing is a hollow claim, not an opaque artifact. (A
        # body that does not decode holds a replacement character.)
        return ClaimBytesKind.HOLLOW, []
    lim = limits if limits is not None else AdmissionLimits()

    def strict(b: bytes, what: str) -> "_Read | None":
        return _read_strict(b, what, max_depth=lim.max_depth)

    try:
        found = _json_body(
            raw,
            strict,
            where,
            whole=ClaimBytesKind.SINGLE_JSON,
            per_line=ClaimBytesKind.JSONL,
            every_row=True,
        )
    except JsonShapedButCorrupt:
        return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
    except _PastDepth:
        # Nesting past the bound, in the whole body or in one line: the
        # capped scanner reads, the strict parser never sees these bytes, and
        # no documents come back.
        over = ClaimBytesKind.JSON_OVER_DEPTH
        found = _json_body(raw, _read_syntax, where, whole=over, per_line=over)
        if found is not None:
            return found[0], []
    else:
        if found is not None:
            return found
    if _looks_json_shaped(raw, where, text, exact):
        return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
    return ClaimBytesKind.NOT_JSON_SHAPED, []


def classify_claim_bytes(raw: bytes, where: str) -> list:
    """The JSON documents to enumerate from one STRUCTURED claim file's bytes
    (the `claim_files` admission: SINGLE_JSON or JSONL). Any other kind is
    REFUSED with its typed reason, never demoted to an opaque element:
    whole-file claims are a separate, explicit declaration
    (`opaque_claim_files`), and the kinds no declaration admits (CORRUPT,
    OVER_DEPTH, HOLLOW) are refused under every declaration (the demotion is
    how a producer shrinks the denominator past a strict parser;
    content-not-filename means a rename cannot trigger it).
    """
    kind, docs = classify_kind(raw, where)
    if kind in DECLARATION_ADMITS["claim_files"]:
        return docs
    raise _refusal_for(kind, where)


def _refusal_for(kind: "ClaimBytesKind", where: str) -> ClaimsetError:
    """The typed refusal for a kind the current declaration does not admit."""
    if kind is ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT:
        return JsonShapedButCorrupt(
            f"{where}: JSON-shaped but corrupt (duplicate object keys; a NaN / "
            "Infinity token or an integer over 600 digits; a line holding an "
            "object or array with a member beside lines that do not read, or "
            "every line read as JSON by a line reader; JSON "
            "that json.loads reads but the strict reader does not (a BOM, a "
            "UTF-16/32 encoding or a surrogate, on the body or one line); a "
            "JSON-family document holding an object or array with a member "
            "(JSONC, concatenated values, other whitespace, an XSSI guard); "
            "nesting to 1024 levels; or a '{'/'['-opened body that does not "
            "parse strictly) — refused under every declaration; repair the file"
        )
    if kind is ClaimBytesKind.JSON_OVER_DEPTH:
        return ClaimsetError(
            f"{where}: JSON nested past the admission depth bound — "
            "refused under every declaration (as structured it is inadmissible; "
            "as opaque it would collapse a structured claim to one element)"
        )
    if kind is ClaimBytesKind.HOLLOW:
        return ClaimsetError(
            f"{where}: empty, or only whitespace once decoded (a BOM in front of "
            "nothing) — a hollow body is refused under every declaration"
        )
    if kind is ClaimBytesKind.NOT_JSON_SHAPED:
        return NotJsonShaped(
            f"{where}: a structured claim file must be JSON or JSONL and these "
            "bytes are neither — declare a genuine artifact under "
            "opaque_claim_files; a non-JSON body is never demoted to one element "
            "here"
        )
    return ClaimsetError(
        f"{where}: declared opaque but the bytes are structured {kind.value} — "
        "declare it under claim_files so its fields enumerate; opaque is for "
        "bytes that carry no JSON evidence"
    )


def _leaf_paths(doc: object, where: str) -> "set[tuple[str, ...]]":
    """Observed leaf paths of one parsed JSON document (instance-measured,
    not schema-derived). Array positions collapse to the "[]" marker; a leaf
    is a scalar or an empty container; object keys are checked against the
    reserved-character policy."""
    paths: set[tuple[str, ...]] = set()

    def _walk(node: object, prefix: "tuple[str, ...]") -> None:
        if type(node) is dict:
            if not node:
                paths.add(prefix)
                return
            for k, v in node.items():
                _check_key(k, where)
                _walk(v, prefix + (k,))
        elif type(node) is list:
            if not node:
                paths.add(prefix)
                return
            for item in node:
                _walk(item, prefix + (_ARRAY_MARKER,))
        else:
            paths.add(prefix)

    _walk(doc, ())
    return paths


def render_element(payload_key: str, path: "tuple[str, ...]") -> str:
    """Canonical element string: "<payload-key>:a.b[].c". The empty path
    (a root scalar, or a non-JSON claim file) renders as the payload key
    alone: the whole file's content as one element."""
    if not path:
        return payload_key
    out = payload_key + ":"
    for seg in path:
        if seg == _ARRAY_MARKER:
            out += _ARRAY_MARKER
        elif out.endswith(":"):
            out += seg
        else:
            out += "." + seg
    return out


_SOURCE_CONVENTIONS = (
    "elements are the OBSERVED leaf paths (instance-measured, not "
    "schema-derived) of the manifest-declared claim files, rendered "
    "'<payload-key>:a.b[].c' by audit_bundle.claimset — authored conventions "
    "(a SELF_AUTHORED, producer-controlled denominator): a claim file must be "
    "structured JSON or JSONL, decided by CONTENT not filename (bytes that "
    "parse as one JSON value = one document; else all-parsing lines = a JSONL "
    "union; else REFUSED, never demoted to an opaque element), object keys "
    "join with '.', array positions collapse to '[]', a leaf is a scalar or "
    "empty container; the structured reader refuses duplicate object keys, "
    "NaN and Infinity tokens, integer tokens over 600 digits, keys that are "
    "empty, not NFC, carry a format (Cf) character or contain ':', '.', '[' "
    "or ']', and a JSONL body with a line holding an object or array with a "
    "member beside a line that does not read; opaque_claim_files entries are "
    "whole-file claims rendered as the payload key alone (the same rendering "
    "as a root scalar — the kind is carried by the declared maps appended to "
    "this statement, not by the element), admitted only for bytes that this "
    "module's strict JSON/JSONL reader cannot read AND that carry no JSON "
    "evidence, which is any of: (1) the first non-whitespace byte is '{' or "
    "'[', or the first character of the text is, past Unicode whitespace and "
    "U+FEFF (the text decoded as json.loads decodes bytes, invalid bytes "
    "replaced); (2) the text (decoded as json.loads decodes bytes, "
    "surrogates passed; where that fails, invalid bytes dropped; and where "
    "json.loads detects UTF-16 or UTF-32, also decoded as UTF-8 with invalid "
    "bytes dropped, the text (2) to (5) read), trimmed of "
    "Unicode whitespace, U+FEFF and C0 control characters at its ends, is one "
    "value in the json-module grammar (NaN and Infinity, integers of any "
    "length); (3) a line reader, lines trimmed the same way, reads a line as "
    "an object or array holding a member, or reads every non-blank line, the "
    "lines being the raw bytes split at LF/CR (each line in its own detected "
    "encoding), the decoded text split at LF/CR (each line also as json.loads "
    "reads its UTF-8 bytes), and, where a lone CR occurs, both split at LF "
    "only; (4) a line of the decoded text split as str.splitlines splits it "
    "(also at VT, FF, FS, GS, RS, NEL, LS and PS) reads as an object holding "
    "a member, or as an array holding such an object; (5) a whole-document reader finds an object or array "
    "holding a member in the text, trimmed as in (2), read after an XSSI guard (\")]}'\" on a "
    "line of its own, \"for(;;);\" or \"while(1);\") as one or more values "
    "separated by Unicode whitespace, U+FEFF or JSONC comments, trailing "
    "commas allowed (RFC 7464 sequences, concatenated JSON); readers (2) to "
    "(4) parse only text that, trimmed, starts and ends as a JSON value can "
    "('{', '[', a quote, '-', a digit or a literal's first letter; '}', ']', "
    "a quote, a digit or a literal's last letter), and each of the five "
    "readers takes a value whose nesting reaches 1024 levels before its "
    "first syntax error as read and holding a member; an object or array "
    "holding no member is not evidence in a line or a document, since it "
    "hides no field (a body that opens with one is refused by (1)), and a "
    "UTF BOM alone is not evidence; not modelled: readers that change the "
    "JSON value grammar (JSON5 unquoted keys, single quotes, hexadecimal "
    "numbers), leniency on one line (comments, trailing commas, a second "
    "value, whitespace other than JSON's inside a value), a value spanning "
    "several lines after a line nothing reads, an array holding no object on "
    "a line of the str.splitlines split that no LF/CR split reads, a prefix other than whitespace "
    "and those three XSSI guards, trimming other characters, other decodes "
    "(a Latin-1 fallback, where byte 0x85 is NEL, a line end) and other "
    "record separators (NUL), readers that stop at the first error, and a "
    "truncated JSONC document; bytes that are "
    "JSON-shaped but corrupt, JSON nested past the admission depth bound "
    "(one value, or every line, read by the capped scanner), or hollow "
    "(empty, or only Unicode whitespace and U+FEFF once decoded) are refused "
    "under every declaration, and so is a body that does not read as one "
    "JSON value and has more than 1000000 non-blank lines (split at LF/CR "
    "bytes, blank meaning only ASCII whitespace), or that the strict reader "
    "does not admit and whose str.splitlines split (of either decode) has "
    "more than 1000000 lines that could hold an object read by (4) (opening "
    "with '{' and a key's quote, or with '[' and holding one, and "
    "closing with the matching bracket); the opaque admission is graded against a NAMED oracle "
    "— the stdlib json.loads on BYTES with its encoding auto-detection, its "
    "integer-digit and recursion limits lifted (past json's budget this "
    "module's uncapped scanner reads) (stdlib_reads_as_json): the property "
    "tests and fuzzing check, by sampling, that whatever that reader reads "
    "as one value or as every line is not opaque; it is not a positive "
    "format check, and "
    "whole-file binding is evidenced only by the per-field tamper battery; "
    "declared paths are canonical and injective; opaque bytes are bounded by "
    "size before reading; the claim files' byte-integrity is provided "
    "separately by their pins in manifest.files (§C9), not by a source_sha "
    "here (SELF_AUTHORED carries none)"
)


def _source_statement(
    claim_files: "dict[str, str]", opaque_claim_files: "dict[str, str]"
) -> str:
    """The universe `source`: the conventions above PLUS the declared maps
    (both kinds, canonical JSON, ASCII). `source` is digested into
    universe_sha, so the declared paths and kinds ride the anchor: an
    anchored relying party commits to the FILES, not just to field names
    (design-audit finding 2: without this, a path swap to a decoy file kept
    the anchor green)."""
    declared = {
        "claim_files": {k: claim_files[k] for k in sorted(claim_files)},
        "opaque_claim_files": {
            k: opaque_claim_files[k] for k in sorted(opaque_claim_files)
        },
    }
    return (
        CLAIMSET_CONVENTIONS_VERSION
        + " | "
        + _SOURCE_CONVENTIONS
        + " | declared="
        + json.dumps(declared, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    )


def enumerate_claim_universe(
    bundle_dir: "str | Path",
    *,
    bundle_id: str,
    claim_files: "dict[str, str]",
    manifest_files: "dict[str, str]",
    opaque_claim_files: "dict[str, str] | None" = None,
    limits: "AdmissionLimits | None" = None,
) -> dict:
    """Enumerate the closed claim-field universe from the declared claim
    files' bytes and commit it (closed-universe receipt, SELF_AUTHORED; see
    the module docstring for why the denominator is a producer-committed
    story, not a measurement over an independent artifact).

    Structured files (`claim_files`): content-classified (`classify_kind`),
    admitted for SINGLE_JSON / JSONL only, elements = observed leaf paths.
    Opaque files (`opaque_claim_files`): admitted for NOT_JSON_SHAPED only,
    never for bytes that are JSON-shaped but corrupt, and never for
    structured JSON relabelled as opaque; element = the payload key alone.
    Both: pinned in manifest.files (an unpinned claim file would let the
    denominator ride bytes outside the verdict's byte-set), inside the
    bundle, size-bounded BEFORE reading. All refusals are loud; nothing is
    skipped or silently demoted (a partial universe re-opens the coverage
    hole).
    """
    opaque = dict(opaque_claim_files or {})
    lim = limits if limits is not None else AdmissionLimits()
    validate_claimset_declaration(
        {"claim_files": dict(claim_files), "opaque_claim_files": opaque}
    )
    base = Path(bundle_dir).resolve()
    elements: set[str] = set()

    def _locate(key: str, rel: str, what: str) -> Path:
        _require(
            rel in manifest_files,
            f"{what} {rel!r} (payload-key {key!r}) is not pinned in "
            "manifest.files — an unpinned claim file cannot anchor a "
            "denominator",
        )
        target = (base / rel).resolve()
        _require(
            target.is_relative_to(base), f"{what} {rel!r} escapes the bundle directory"
        )
        _require(target.is_file(), f"{what} {rel!r} is absent from the bundle")
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise ClaimsetError(f"{what} {rel!r} could not be stat'ed: {exc}") from exc
        _require(
            size <= lim.max_bytes,
            f"{what} {rel!r} is {size} bytes, over the {lim.max_bytes}-byte "
            "admission bound — refused before reading",
        )
        return target

    resolved_seen: dict = {}

    def _identity(target: Path, rel: str) -> None:
        """One file, one key, by IDENTITY, not just by spelling: two declared
        paths that resolve to the same file (an in-bundle symlink, a
        case-insensitive filesystem) would pad the denominator."""
        try:
            ident = target.resolve()
            st = target.stat()
            key_ = (
                ident.as_posix(),
                getattr(st, "st_dev", 0),
                getattr(st, "st_ino", 0),
            )
        except OSError as exc:
            raise ClaimsetError(
                f"claim file {rel!r} could not be resolved: {exc}"
            ) from exc
        other = resolved_seen.get(key_)
        _require(
            other is None,
            f"claim files {other!r} and {rel!r} resolve to the same file — one "
            "file, one key; a second key on the same bytes pads the denominator",
        )
        resolved_seen[key_] = rel

    def _ceiling() -> None:
        _require(
            len(elements) <= _MAX_ELEMENTS,
            f"claim-field universe exceeds {_MAX_ELEMENTS} elements — refusing "
            "a pathological enumeration rather than stalling the verdict path",
        )

    def _read(target: Path, what: str, rel: str) -> bytes:
        try:
            return target.read_bytes()
        except OSError as exc:
            raise ClaimsetError(f"{what} {rel!r} could not be read: {exc}") from exc

    for key in sorted(claim_files):
        rel = claim_files[key]
        target = _locate(key, rel, "claim file")
        _identity(target, rel)
        raw = _read(target, "claim file", rel)
        where = f"claim file {rel!r}"
        kind, docs = classify_kind(raw, where, limits=lim)
        if kind not in DECLARATION_ADMITS["claim_files"]:
            raise _refusal_for(kind, where)
        for doc in docs:
            for path in _leaf_paths(doc, where):
                elements.add(render_element(key, path))
        _ceiling()

    for key in sorted(opaque):
        rel = opaque[key]
        where = f"opaque claim file {rel!r}"
        target = _locate(key, rel, "opaque claim file")
        _identity(target, rel)
        raw = _read(target, "opaque claim file", rel)
        kind, _docs = classify_kind(raw, where, limits=lim)
        if kind not in DECLARATION_ADMITS["opaque_claim_files"]:
            raise _refusal_for(kind, where)
        elements.add(render_element(key, ()))
        _ceiling()

    try:
        return declare_universe(
            sorted(elements),
            domain=f"bundle_claimset:{bundle_id}",
            source=_source_statement(dict(claim_files), opaque),
            provenance="SELF_AUTHORED",
            reason_enum=CLAIMSET_REASON_ENUM,
        )
    except ClosedUniverseError as exc:
        # The helper's hygiene (NFC, no format chars, strict JSON elements) is
        # mirrored in _check_key; anything that still reaches it is a clean
        # REJECT at this boundary, never a crash-class ERROR.
        raise ClaimsetError(
            f"claim-field universe refused by the helper: {exc}"
        ) from exc


def opaque_keys_for_paths(
    claimset: object, compared_paths: "set[str] | frozenset[str]"
) -> "frozenset[str]":
    """The opaque payload keys a plugin may REPORT as covered, given the set of
    bundle-relative artifact paths its pack ACTUALLY compared byte-for-byte.

    A plugin must never report a constant key (that credits whatever file the
    producer declared under it); it reports the keys whose DECLARED path is in
    the set of files it compared, and lists those files in `files_audited`.
    Coverage then follows the comparison, not the declaration. Returns the
    empty set for an absent / malformed declaration (the guard refuses those
    separately); never raises on the verdict path."""
    if not isinstance(claimset, dict):
        return frozenset()
    opaque = claimset.get("opaque_claim_files")
    if not isinstance(opaque, dict):
        return frozenset()
    compared = {Path(str(p)).as_posix() for p in compared_paths}
    return frozenset(
        str(key)
        for key, rel in opaque.items()
        if isinstance(rel, str) and Path(rel).as_posix() in compared
    )


def build_claimset_receipt(
    universe: dict, covered: "set[str] | list[str]", residuals: "dict[str, str]"
) -> dict:
    """The closed-universe receipt for one bundle's claim-field partition.
    All partition/enum discipline (omission, surplus, double-count, unknown
    reason, enum drift) fails closed in the vendored helper, not in new
    logic here."""
    return build_receipt(universe, sorted(covered), residuals)


def claimset_disclosure(
    receipt: dict, *, universe_anchored: bool = False, n_opaque: int = 0
) -> str:
    """The machine-readable Completeness disclosure line carrying the
    receipt's identity.

    The `covered:self-reported` marker is load-bearing: `n_covered` is the
    count of fields a wired plugin PROMISED it bound, not fields this gate
    measured. A remote consumer must read it as a promise, not a
    measurement (the executable check is the per-field tamper battery). The
    `universe:anchored|producer` marker says whether the denominator matched
    a verifier-held `expected_universe_sha` (anchored) or is the producer's
    own committed story (producer). `n_opaque` (appended LAST, so every
    existing prefix of the line keeps matching) is the count of whole-file
    elements in the universe, a declaration count backed by the digest
    (the declared maps ride universe_sha), so a consumer reading
    `n_universe=1` can tell one artifact from one JSON field. Without the
    anchor marker the receipt is identity metadata over a producer-chosen
    denominator, not evidence of coverage completeness: the closed_universe
    anchor rule, stated on the line the consumer actually reads rather than
    only in a docstring."""
    breakdown = json.dumps(
        receipt["withheld_reason_breakdown"], sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    )
    return (
        "claimset: receipt_sha="
        + receipt["receipt_sha"]
        + " universe_sha="
        + receipt["universe_sha"]
        + f" universe={'anchored' if universe_anchored else 'producer-declared'}"
        + f" n_universe={receipt['n_universe']}"
        + f" n_covered={receipt['n_covered']}(self-reported)"
        + f" n_withheld={receipt['n_withheld']}"
        + f" withheld_reasons={breakdown}"
        + f" n_opaque={int(n_opaque)}"
    )


CLAIMSET_NOT_DECLARED_DISCLOSURE = (
    "claimset: not declared — per-field claim coverage is unaccounted for "
    "this bundle (payload claim files may carry fields no wired check reads)"
)


__all__ = [
    "CLAIMSET_REASON_ENUM",
    "CLAIMSET_COVERED_FILE_UNAUDITED",
    "ClaimBytesKind",
    "DECLARATION_ADMITS",
    "OPAQUE_RESIDUAL_REASONS_FORBIDDEN",
    "NotJsonShaped",
    "JsonShapedButCorrupt",
    "classify_kind",
    "is_strict_json_value",
    "stdlib_reads_as_json",
    "CLAIMSET_CONVENTIONS_VERSION",
    "opaque_keys_for_paths",
    "CLAIMSET_DECLARATION_MALFORMED",
    "CLAIMSET_ENUMERATION_FAILED",
    "CLAIMSET_COVERED_FIELD_UNKNOWN",
    "CLAIMSET_RESIDUAL_INVALID",
    "CLAIMSET_FIELD_DOUBLE_ACCOUNTED",
    "CLAIMSET_NOT_DECLARED_DISCLOSURE",
    "CLAIMSET_RESIDUAL_INCOHERENT",
    "CLAIMSET_UNIVERSE_ANCHOR_MISMATCH",
    "ClaimsetError",
    "validate_claimset_declaration",
    "render_element",
    "classify_claim_bytes",
    "enumerate_claim_universe",
    "build_claimset_receipt",
    "claimset_disclosure",
]
