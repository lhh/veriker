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
    JSON_SHAPED_BUT_CORRUPT: duplicate object keys; a body mixing JSON
    object/array lines with lines that do not parse), and each declaration
    admits a fixed subset (`DECLARATION_ADMITS`): structured admits the two
    JSON kinds, opaque admits ONLY NOT_JSON_SHAPED, and CORRUPT /
    JSON_OVER_DEPTH / HOLLOW are admitted by no declaration (so a producer
    cannot shrink a structured denominator by corrupting, re-encoding,
    deep-wrapping or relabelling the file). STATED LIMIT: "opaque" is the
    complement of THIS module's strict reader plus two structural tests (no
    UTF BOM; first non-whitespace byte not '{'/'['), not a positive format
    check: a document in some other structured vocabulary (YAML, CSV) is
    one opaque element, and whole-file binding is evidenced only by the
    tamper battery, never by admission. An opaque element renders as the
    payload key alone, the same rendering as a root scalar; the kind and
    the declared path ride `universe_sha` through the `source` statement,
    which carries both declared maps. Opaque bytes are bounded by SIZE
    (stat before read); the JSON depth scan only classifies on that path
    (depth past the bound is classified by an iterative scanner, never
    parsed). Every declared claim file WITH A COVERED ELEMENT must appear
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

import json
import unicodedata
from enum import Enum
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
    string is exactly one of these (the single exception is the JSONL row
    ceiling, a resource bound that refuses loudly rather than classify);
    which DECLARATION may carry a kind is the `DECLARATION_ADMITS` table,
    never an inference from a parse failure."""

    SINGLE_JSON = "SINGLE_JSON"  # one strict JSON value
    JSONL = "JSONL"  # every non-empty line one strict JSON value
    # No strict JSON/JSONL reader can read it, AND it is not JSON-shaped by
    # the structural tests below. The ONLY kind an opaque declaration admits.
    NOT_JSON_SHAPED = "NOT_JSON_SHAPED"
    # JSON-shaped bytes a producer could have made unreadable on purpose:
    # duplicate object keys (stdlib keeps the last, eye-invisible); a body
    # carrying JSON object/array lines alongside lines that do not parse (a
    # corrupted JSONL claim file); a UTF-8 BOM / UTF-16 / UTF-32 encoded
    # body (a strict reader that auto-detects encodings reads it); or bytes
    # whose first non-whitespace character opens a JSON container ('{' /
    # '[') but that do not parse strictly (trailing comma, truncation, a
    # comment, ...). Admitted by NO declaration: a corrupt structured file
    # has nowhere to hide, under any name.
    JSON_SHAPED_BUT_CORRUPT = "JSON_SHAPED_BUT_CORRUPT"
    # Strict JSON (one value, or every line) nested past the admission depth
    # bound: readable by a strict reader, refused at admission as structured,
    # and refused as opaque. Otherwise wrapping a claim file in 65 brackets
    # would collapse its denominator to one element. Admitted by NO
    # declaration.
    JSON_OVER_DEPTH = "JSON_OVER_DEPTH"
    # Empty or whitespace-only bytes: a hollow claim, admitted nowhere.
    HOLLOW = "HOLLOW"


# Which kinds each declaration map admits. A closed table: the ratchet in
# tests asserts it is disjoint and that JSON_SHAPED_BUT_CORRUPT appears in
# no row. Structured admits the two JSON kinds; opaque admits ONLY bytes no
# strict reader can read, never "bytes this parser failed on".
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
CLAIMSET_CONVENTIONS_VERSION = "claimset-conventions/v2"


class ClaimsetError(ValueError):
    """Claimset declaration or universe-enumeration failure. Fail closed."""


class NotJsonShaped(ClaimsetError):
    """Bytes no strict JSON/JSONL reader can read at all: the ONLY refusal
    of the structured path that an opaque declaration may stand on."""


class JsonShapedButCorrupt(ClaimsetError):
    """JSON-shaped bytes made unreadable (duplicate keys; a JSONL body with a
    corrupted line). Refused under EVERY declaration."""


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


def stdlib_reads_as_json(raw: bytes) -> bool:
    """THE NAMED EXTERNAL ORACLE for opaque admission: does the stdlib reader
    a relying party would actually use (`json.loads` on BYTES, with its own
    encoding auto-detection) read these bytes as one JSON value, or every
    non-empty line as one? Deep bodies the recursive reader cannot parse are
    answered by the iterative scanner over the detected encoding. The opaque
    admission is graded against THIS function (properties, kill condition
    K5), never against the module's classifier alone."""
    if not raw.strip():
        return False

    def _one(b: bytes) -> bool:
        try:
            json.loads(b)
            return True
        except RecursionError:
            dec = _decode_bom_text(b)
            return is_strict_json_value(dec if dec is not None else b)
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
_JSON_DIGITS = "0123456789"
_JSON_HEX = "0123456789abcdefABCDEF"


def is_strict_json_value(raw: bytes) -> bool:
    """Iterative strict-JSON syntax scanner: decides whether `raw` is ONE JSON
    value exactly as `json.loads` would (same literals incl. NaN/Infinity,
    same string/number grammar, strict UTF-8, no BOM) with an explicit stack
    instead of recursion, so it answers for bodies of ANY nesting depth in
    linear time. Syntax only (duplicate keys are not its concern). Used to
    classify bytes the recursive parser must never see (past the admission
    depth bound)."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if s.startswith("\ufeff"):
        return False
    n = len(s)

    def skip_ws(i: int) -> int:
        while i < n and s[i] in _JSON_WS:
            i += 1
        return i

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
    i = skip_ws(0)
    if i >= n:
        return False
    expect_value = True
    while True:
        if expect_value:
            i = skip_ws(i)
            if i >= n:
                return False
            c = s[i]
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
                    return False
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
                    return False
                expect_value = False
                continue
        i = skip_ws(i)
        if not stack:
            return i >= n
        if i >= n:
            return False
        top = stack[-1]
        c = s[i]
        if c == ",":
            i += 1
            if top == "o":
                i = scan_key_colon(i)
                if i < 0:
                    return False
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
            return False


def _decode_bom_text(raw: bytes) -> "bytes | None":
    """If `raw` is in an encoding the stdlib's own `json.loads(bytes)` would
    auto-detect (a UTF BOM, or the BOM-less UTF-16/UTF-32 null-byte patterns
    that `json.detect_encoding` recognises), decode it and return the text
    re-encoded as plain UTF-8 (BOM stripped); None for plain UTF-8 (handled
    by the strict path) or when the body does not decode. Mirroring
    `json.detect_encoding` exactly is the point: a reader that calls
    `json.loads` on bytes would parse these into fields, so their decoded
    TEXT must get the JSON tests. An encoding alone proves nothing: a UTF-16
    text file is a genuine artifact."""
    enc = json.detect_encoding(raw)
    if enc == "utf-8":
        return None
    try:
        return raw.decode(enc).encode("utf-8")
    except (UnicodeDecodeError, LookupError):
        return None


def _reads_as_json_text(text: bytes) -> bool:
    if is_strict_json_value(text):
        return True
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return (
        bool(lines)
        and len(lines) <= _MAX_JSONL_ROWS
        and all(is_strict_json_value(ln) for ln in lines)
    )


def _looks_json_shaped(raw: bytes) -> bool:
    """Structural (not parser-derived) evidence that bytes are a JSON document
    some reader would parse into fields: a BOM-prefixed body whose DECODED
    text reads as JSON/JSONL or opens a container (an encoding-detecting or
    BOM-tolerant reader reads it), or a first non-whitespace byte that opens
    a JSON container. Used ONLY to widen JSON_SHAPED_BUT_CORRUPT: bytes with
    this evidence that do not parse strictly are refused under every
    declaration, so admission as opaque never rests solely on "our strict
    parser failed"."""
    decoded = _decode_bom_text(raw)
    if decoded is not None:
        return _reads_as_json_text(decoded) or decoded.lstrip(b" \t\n\r")[:1] in (
            b"{",
            b"[",
        )
    head = raw.lstrip(b" \t\n\r")
    return head[:1] in (b"{", b"[")


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


def _parse_refusing_duplicates(raw: bytes, what: str) -> object:
    """json.loads with duplicate object keys refused (stdlib silently keeps
    the last duplicate, and two parsers can then disagree about which field
    a document carries, which is exactly the divergence this module exists
    to prevent)."""

    def _pairs(pairs: list) -> dict:
        out: dict = {}
        for k, v in pairs:
            if k in out:
                raise JsonShapedButCorrupt(
                    f"{what}: duplicate object key {k!r} — refusing a document "
                    "whose field set depends on parser tie-breaking"
                )
            out[k] = v
        return out

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except ClaimsetError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NotJsonShaped(f"{what}: not parseable as JSON: {exc}") from exc


# Fail-closed ceiling on JSONL rows before any parse, so a many-micro-row body
# cannot spend unbounded parse time (admit_bytes already caps total bytes).
_MAX_JSONL_ROWS = 1_000_000


def classify_kind(
    raw: bytes, where: str, *, limits: "AdmissionLimits | None" = None
) -> "tuple[ClaimBytesKind, list]":
    """TOTAL classification of one claim file's bytes into ClaimBytesKind,
    with the parsed documents for the two structured kinds (empty list
    otherwise). Decided by CONTENT, never filename. The one raise is the
    JSONL row ceiling (a resource bound, refused loudly under every
    declaration); everything else, including empty bytes, is a kind.

    Order of decision:
    * empty / whitespace-only → HOLLOW;
    * past the admission depth bound (the recursive parser must never see
      these): if the iterative scanner reads them as one strict JSON value,
      or every non-empty line as one → JSON_OVER_DEPTH; else if any line
      scans as a JSON container beside a line that does not → CORRUPT; else
      if structurally JSON-shaped (BOM / container-opened) → CORRUPT; else
      NOT_JSON_SHAPED;
    * one strict JSON value → SINGLE_JSON (duplicate keys anywhere → CORRUPT);
    * else every non-empty line one strict JSON value → JSONL (a duplicate
      key in any line → CORRUPT);
    * else any line parses as a JSON object/array while another does not →
      CORRUPT (one corrupted line of a JSONL claim file, whichever line);
    * else BOM-prefixed, or first non-whitespace byte '{' / '[' → CORRUPT
      (trailing comma, truncation, a comment, a non-UTF-8 encoding: a
      JSON document some reader would still parse into fields);
    * else → NOT_JSON_SHAPED. Scalar-only lines (a headerless numeric
      column) mixed with non-parsing lines are NOT_JSON_SHAPED: no
      object-shaped claim is being hidden there.
    """
    if not raw.strip():
        return ClaimBytesKind.HOLLOW, []
    lim = limits if limits is not None else AdmissionLimits()
    adm = admit_bytes(
        raw, AdmissionLimits(max_bytes=max(len(raw), 1), max_depth=lim.max_depth)
    )
    if adm is not None:
        # Depth past the bound. Classify structurally with the iterative
        # scanner; never hand these bytes to json.loads.
        if is_strict_json_value(raw):
            return ClaimBytesKind.JSON_OVER_DEPTH, []
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if lines and len(lines) <= _MAX_JSONL_ROWS:
            scanned = [is_strict_json_value(ln) for ln in lines]
            if all(scanned):
                return ClaimBytesKind.JSON_OVER_DEPTH, []
            if any(
                ok and ln.lstrip(b" \t\n\r")[:1] in (b"{", b"[")
                for ok, ln in zip(scanned, lines)
            ):
                return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
        if _looks_json_shaped(raw):
            return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
        return ClaimBytesKind.NOT_JSON_SHAPED, []
    try:
        return ClaimBytesKind.SINGLE_JSON, [_parse_refusing_duplicates(raw, where)]
    except JsonShapedButCorrupt:
        return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
    except NotJsonShaped:
        pass  # not a single JSON value, try JSONL
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    _require(
        len(lines) <= _MAX_JSONL_ROWS,
        f"{where}: {len(lines)} JSONL rows exceed the {_MAX_JSONL_ROWS} ceiling",
    )
    docs: list = []
    saw_container = False
    failed = False
    for i, ln in enumerate(lines):
        try:
            doc = _parse_refusing_duplicates(ln, f"{where} line {i + 1}")
        except JsonShapedButCorrupt:
            return ClaimBytesKind.JSON_SHAPED_BUT_CORRUPT, []
        except NotJsonShaped:
            failed = True
            continue
        docs.append(doc)
        saw_container = saw_container or type(doc) in (dict, list)
    if not failed:
        return ClaimBytesKind.JSONL, docs
    if saw_container or _looks_json_shaped(raw):
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
            f"{where}: JSON-shaped but corrupt (duplicate object keys; a body "
            "mixing JSON object/array lines with lines that do not parse; a "
            "BOM / non-UTF-8 encoding; or a '{'/'['-opened body that does not "
            "parse strictly) — refused under every declaration; repair the file"
        )
    if kind is ClaimBytesKind.JSON_OVER_DEPTH:
        return ClaimsetError(
            f"{where}: strict JSON nested past the admission depth bound — "
            "refused under every declaration (as structured it is inadmissible; "
            "as opaque it would collapse a structured claim to one element)"
        )
    if kind is ClaimBytesKind.HOLLOW:
        return ClaimsetError(
            f"{where}: empty or whitespace-only — a hollow body is refused under "
            "every declaration"
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
        "bytes no strict reader can read"
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
    "join with '.', array "
    "positions collapse to '[]', a leaf is a scalar or empty container, keys "
    "containing ':', '.', '[', ']' are refused, duplicate object keys and "
    "corrupt JSONL bodies are refused; opaque_claim_files entries are "
    "whole-file claims rendered as the payload key alone (the same rendering "
    "as a root scalar — the kind is carried by the declared maps appended to "
    "this statement, not by the element), admitted only for bytes that this "
    "module's strict JSON/JSONL reader cannot read AND that carry no "
    "structural JSON evidence (no UTF BOM, first non-whitespace byte not "
    "'{' or '['); bytes that are JSON-shaped but corrupt, strict JSON past "
    "the admission depth bound, or hollow are refused under every "
    "declaration; the opaque admission is graded against a NAMED external "
    "oracle — the stdlib json.loads on BYTES with its encoding auto-detection "
    "(stdlib_reads_as_json): whatever that reader reads as one value or as "
    "every line is never opaque — plus those structural tests; it is not a "
    "positive format check, and "
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
        + json.dumps(declared, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
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
        receipt["withheld_reason_breakdown"], sort_keys=True, separators=(",", ":")
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
