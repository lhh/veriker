"""audit_bundle/rederivation/spec_binding.py — Axis-1 binding source + anchor.

The per-type binding type -> {primitive_id, comparator{kind,params}} lives in a
SHA-pinned spec file (the spec/ tree the verifier already integrity-checks at
step 2). This module:

  (step 3) parses a spec's binding object and resolves type -> Binding;
  (step 4 — GATING, §4a.1/4a.2) anchors the AUTHORITATIVE spec set to an
    AUDITOR-controlled allowlist (spec_id -> required SHA). SHA-pinning proves a
    named spec's *contents* are immutable; it does NOT prove the producer chose
    the *right* spec. The anchor closes that: a spec is authoritative only if its
    spec_id is in the anchor AND its on-disk SHA equals the anchored SHA. The
    producer cannot author or select around it — a substituted weak spec has a
    SHA the anchor does not list, so it is not authoritative and its types do not
    resolve (fail-closed). `conforms_to` is reduced to a non-load-bearing
    cross-check hint: resolution searches ALL anchored specs and fails closed on
    ambiguity (§4a.2 option (b)), so a producer cannot redirect dispatch by
    pointing `conforms_to` at a weaker spec.
  (step 5 — GATING, §4a.3) the monotone-strictness invariant: across the
    authoritative set, any primitive_id bound by >=2 types must carry an
    IDENTICAL comparator (kind + canonical params). This is the conservative
    instantiation of "comparators must be equally-or-more strict under a partial
    order" — it admits no weaker sibling at all, so the type-substitution attack
    has no weaker type to substitute TO. (A graded partial order is a documented
    future generalization; identical-comparator is sound and the strictest read.)

Stdlib-only (core verify() path). The auditor anchor is supplied to
BundleVerifier at construction (verifier-side, auditor-controlled), never read
from the producer's manifest.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..admission import admit_json_file
from .comparators import validate_comparator_params


from .primitive_ref import (  # noqa: E402
    MalformedPrimitiveRef,
    PrimitiveRef,
    parse_primitive_ref,
)


class SpecBindingError(Exception):
    """Base for all spec-binding / anchor failures (all fail-closed)."""


class MalformedSpec(SpecBindingError):
    """A spec file is not a JSON object or its types/binding shape is invalid."""


class AnchorViolation(SpecBindingError):
    """An anchor WAS supplied and the authoritative spec set still came out
    empty: no spec named by the manifest matched an anchor entry by
    (spec_id, on-disk SHA) -> REJECT (exit 1).

    Distinct from AnchorNotSupplied (below). The two used to share this class,
    which made a verifier that was never handed an anchor indistinguishable from
    a bundle caught substituting a weak spec.

    SCOPE — this class does NOT prove producer fault. The same condition is
    reached when the OPERATOR anchored the wrong pilot's spec, a stale committed
    copy, or the same JSON with different bytes (a CRLF checkout, a re-indent).
    REJECT is the fail-closed default because the verifier cannot tell those
    apart from a substitution with certainty, but the detail must not assert
    which it was: `_describe_anchor_mismatch` below reports, per spec_id the
    manifest named, whether the anchor listed that spec_id AT ALL (points at the
    operator) versus listed it with a different SHA (the substitution case), so
    the reader can assign blame from evidence instead of from the exception
    name."""


class AnchorNotSupplied(SpecBindingError):
    """VERIFIER-side incapacity: spec-pinned dispatch engaged (the manifest
    declares outputs) but no auditor SpecAnchor was supplied at all — or the
    supplied anchor allows NOTHING (empty `allowed`), which is the same absence
    of authority wearing a constructor call. Either way no authority exists to
    judge against. Nothing was shown about the artifact — this is a
    could-not-conclude, so it routes to a clean-ERROR / VERIFIER_INCOMPLETE
    leg (exit 2), NEVER a REJECT (exit 1).

    Contract: OSS_RELEASE_BOUNDARY.md tri-state (OK / REJECT / ERROR)."""


class AnchorConstructionError(SpecBindingError):
    """`SpecAnchor.from_files` was given an unusable operator-side spec file:
    unreadable, not JSON, no non-empty `spec_id`, a duplicate spec_id with
    different bytes, an empty path list, or a path that resolves INSIDE the
    directory the anchor is meant to constrain (`forbid_within`).

    An OPERATOR error, not a bundle property: no verdict about the bundle is
    formed when this fires, so callers must map it to could-not-conclude
    (exit 2), never to a REJECT of the artifact."""


class AmbiguousTypeBinding(SpecBindingError):
    """A type key is defined by >1 authoritative spec (§4a.2 fail-on-ambiguity)."""


class MonotoneStrictnessViolation(SpecBindingError):
    """A primitive_id is bound by >=2 types with non-identical comparators
    (§4a.3 — admits a weaker sibling; reject the anchored set at load)."""


class UnknownType(SpecBindingError):
    """A claimed output type is not defined by any authoritative spec."""


# ---------------------------------------------------------------------------
# Binding + SpecAnchor
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Binding:
    """One type's rule: which primitive recomputes it, which comparator kind
    checks the recomputed value against the producer's claim, and with which
    params. Built by `parse_spec` from an authoritative, SHA-anchored spec."""

    type_key: str
    primitive_id: str
    comparator_kind: str
    comparator_params: dict
    spec_id: str  # which authoritative spec defined this binding
    # §4a.7 pinned inputs: bundle-relative path -> required SHA-256 hex. The
    # recompute primitive READS these files from the bundle; pinning their hash
    # in the AUDITOR-anchored spec fixes their contents out-of-band. A producer
    # who swaps a pinned input (e.g. substitutes a laxer detection policy) and
    # re-coheres the manifest still fails closed: to match, the spec's pinned
    # hash would have to change, but that changes the spec SHA the anchor lists,
    # so the swapped-spec is no longer authoritative (AnchorViolation). Empty by
    # default — every legacy/other spec that omits it pins nothing (unchanged).
    pinned_inputs: tuple[tuple[str, str], ...] = ()

    def resolved_ref(self) -> PrimitiveRef:
        """The parsed `name[@version][#sha256hex]` reference (D1).

        `primitive_id` deliberately keeps the RAW anchored bytes -- the spec's
        SHA covers that string, so rewriting it here would decouple the field
        from what the anchor signed. Parsing is a pure string walk, already
        performed (and fail-closed) at load in `parse_spec`, so this never
        introduces a new failure mode at dispatch."""
        return parse_primitive_ref(self.primitive_id)

    def _comparator_canonical(self) -> str:
        """Canonical, order-independent rendering of (kind, params) for the
        monotone-strictness identity check. json.dumps(sort_keys=True) is safe
        here — these are verifier-anchored spec params, NOT adversarial bundle
        dict keys, and all keys are strings."""
        return json.dumps(
            {"kind": self.comparator_kind, "params": self.comparator_params},
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class SpecAnchor:
    """Auditor-controlled allowlist: spec_id -> required SHA-256 hex.

    Supplied to BundleVerifier at construction by the auditor's harness (NOT by
    the producer's manifest). This is the trust root for spec-pinned dispatch:
    only specs whose (spec_id, on-disk-sha) match an entry here are authoritative.

    CONSTRUCT VIA `SpecAnchor.from_files(paths, forbid_within=bundle_dir)` —
    it reads the auditor's committed spec bytes itself, records per-spec
    {spec_id, sha256, source} provenance on the anchor, and REFUSES a path
    that resolves inside `forbid_within` (an anchor read out of the bundle is
    authored by the party it constrains; measured 2026-08-17, a fully forged
    bundle verified at exit 0 that way). The raw `SpecAnchor(allowed={...})`
    constructor survives for tests and exotic operators, but it carries NO
    provenance, so the verdict face reports its authority as
    UNVERIFIED_CALLER_SUPPLIED — the verifier cannot show where those hashes
    came from, and says so instead of implying an anchored read.
    """

    allowed: dict[str, str]  # spec_id -> sha256 hex (lowercase)
    # {spec_id, sha256, source} per anchored file, in anchor order — set ONLY
    # by from_files (a caller-built dict has no provenance the verifier can
    # attest, and faking this field up is exactly the laundering the face
    # label exists to prevent). None => UNVERIFIED_CALLER_SUPPLIED on the face.
    provenance: tuple[dict, ...] | None = None

    def matches(self, spec_id: str, computed_sha: str) -> bool:
        """True iff `spec_id` is anchored and its on-disk SHA equals the
        anchored one — the sole test for whether a spec is authoritative."""
        want = self.allowed.get(spec_id)
        return want is not None and want.lower() == computed_sha.lower()

    @classmethod
    def from_files(
        cls, paths: "Sequence[str | Path]", *, forbid_within: Path
    ) -> "SpecAnchor":
        """Build the auditor's anchor from AUDITOR-SIDE committed spec bytes.

        The blessed constructor (D2 in the auditor-entry-point scoping). It reaches the
        SAME authority the pilots' own verify.py scripts build — the same
        `allowed` map (spec_id -> sha256 of the committed spec bytes) over the
        same files — so the CLI, a wrapper, and a library consumer anchored on
        the same files agree. (The pilots currently spell that construction as a
        raw `SpecAnchor(allowed=...)`; the stage-4 sweep migrates them to this
        constructor, which additionally records provenance and refuses
        containment.)

        ENFORCED, not advised: a path that resolves INSIDE `forbid_within`
        (pass the bundle dir under audit) is refused. An anchor read out of the
        bundle's own spec/ tree makes `anchor.matches(spec_id, sha)` a
        tautology — the producer authored both sides — and the whole Axis-1
        defense evaporates: MEASURED 2026-08-17 on examples/bom_minimal (claim
        rewritten to an empty dependency tree, comparator swapped exact->set,
        every manifest SHA re-cohered -> exit 0 with --require-rederivation
        SATISFIED). Resolution follows symlinks on BOTH sides, so a symlink
        outside the bundle pointing in — or a bundle reached via a symlinked
        parent — is caught too. The bytes are read from the RESOLVED path, so
        the containment decision and the hashed bytes name the same file.

        SCOPE: this protects against the operator anchoring producer-controlled
        bytes by PATH. It cannot know whether an out-of-bundle path is itself
        producer-writable (a shared tempdir, a checkout the producer pushes
        to) — the auditor's side of the trust root is the auditor's to hold.

        Raises AnchorConstructionError on any unusable input (operator error,
        could-not-conclude — never a statement about the bundle).
        """
        if not paths:
            raise AnchorConstructionError(
                "SpecAnchor.from_files requires at least one spec path — an "
                "anchor that allows nothing holds no authority to judge with "
                "(the empty-allowed refusal in build_anchored_spec_set exists "
                "so this cannot be reached by accident either)."
            )
        try:
            forbid_root = Path(forbid_within).resolve()
        except OSError as exc:
            raise AnchorConstructionError(
                f"forbid_within {str(forbid_within)!r} could not be resolved: {exc}"
            ) from exc
        allowed: dict[str, str] = {}
        provenance: list[dict] = []
        for raw_path in paths:
            path = Path(raw_path)
            try:
                resolved = path.resolve()
            except OSError as exc:
                raise AnchorConstructionError(
                    f"spec-anchor path {str(raw_path)!r} could not be resolved: {exc}"
                ) from exc
            if resolved == forbid_root or forbid_root in resolved.parents:
                raise AnchorConstructionError(
                    f"spec-anchor path {str(raw_path)!r} resolves INSIDE the "
                    f"bundle ({resolved}). The anchor is the auditor's "
                    "authority over the producer; taking it from the bundle "
                    "lets the producer author both sides of the comparison, "
                    "and a forged bundle then verifies at exit 0. Point this "
                    "at YOUR committed copy of the spec, outside the bundle "
                    "directory."
                )
            try:
                raw = resolved.read_bytes()
            except OSError as exc:
                raise AnchorConstructionError(
                    f"spec-anchor path {str(raw_path)!r} could not be read: {exc}"
                ) from exc
            try:
                doc = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AnchorConstructionError(
                    f"spec-anchor path {str(raw_path)!r} is not valid JSON: {exc}"
                ) from exc
            if not isinstance(doc, dict):
                raise AnchorConstructionError(
                    f"spec-anchor path {str(raw_path)!r} is not a JSON object"
                )
            spec_id = doc.get("spec_id")
            if not isinstance(spec_id, str) or not spec_id:
                raise AnchorConstructionError(
                    f"spec-anchor path {str(raw_path)!r} has no non-empty "
                    "string 'spec_id' — it is not a binding spec"
                )
            digest = hashlib.sha256(raw).hexdigest()
            prior = allowed.get(spec_id)
            if prior is not None and prior != digest:
                # Two files claiming the same spec_id with different bytes: the
                # operator has handed the verifier an ambiguous authority.
                # Silently keeping the last one would let a stale path decide
                # the verdict.
                raise AnchorConstructionError(
                    f"spec-anchor lists two DIFFERENT files both declaring "
                    f"spec_id {spec_id!r} ({prior} vs {digest}) — the "
                    "authority would be ambiguous; pass exactly one file per "
                    "spec_id"
                )
            allowed[spec_id] = digest
            provenance.append(
                {"spec_id": spec_id, "sha256": digest, "source": str(resolved)}
            )
        return cls(allowed=allowed, provenance=tuple(provenance))


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def parse_spec(raw: object, spec_path: str) -> tuple[str, dict[str, Binding]]:
    """Parse one spec's binding object -> (spec_id, {type_key: Binding}).

    Raises MalformedSpec on any shape error (fail-closed). Each comparator's
    params are validated against the closed-world allowlist (§4a.6) here so a
    bad profile/schema is rejected at load, before any dispatch.
    """
    if not isinstance(raw, dict):
        raise MalformedSpec(f"spec {spec_path!r} is not a JSON object")
    spec_id = raw.get("spec_id")
    if not isinstance(spec_id, str) or not spec_id:
        raise MalformedSpec(f"spec {spec_path!r} missing non-empty string 'spec_id'")
    types_obj = raw.get("types")
    if not isinstance(types_obj, dict) or not types_obj:
        raise MalformedSpec(f"spec {spec_path!r} missing non-empty 'types' object")

    bindings: dict[str, Binding] = {}
    for type_key, body in types_obj.items():
        if not isinstance(type_key, str) or not type_key:
            raise MalformedSpec(
                f"spec {spec_path!r}: type key must be a non-empty string"
            )
        if not isinstance(body, dict):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} body not an object"
            )
        primitive_id = body.get("primitive_id")
        if not isinstance(primitive_id, str) or not primitive_id:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} missing 'primitive_id'"
            )
        comparator = body.get("comparator")
        if not isinstance(comparator, dict):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} missing 'comparator' object"
            )
        kind = comparator.get("kind")
        if not isinstance(kind, str) or not kind:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} comparator missing 'kind'"
            )
        params = comparator.get("params", {})
        if not isinstance(params, dict):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} comparator.params not an object"
            )
        # §4a.6 closed-world: reject unknown kind / unimplemented profile/schema
        # at load, not at dispatch.
        try:
            validate_comparator_params(kind, params)
        except Exception as exc:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} comparator invalid: {exc}"
            ) from exc
        # D1: parse the primitive reference at LOAD (§4a.6 discipline -- reject
        # here, not at dispatch). A malformed ref must never fall back to an
        # unversioned/unpinned resolution: that fallback is exactly how a
        # producer would strip a pin the auditor wrote.
        try:
            parse_primitive_ref(primitive_id)
        except MalformedPrimitiveRef as exc:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} primitive_id {exc}"
            ) from exc
        pinned_inputs = _parse_pinned_inputs(
            body.get("pinned_inputs"), spec_path, type_key
        )
        bindings[type_key] = Binding(
            type_key=type_key,
            primitive_id=primitive_id,
            comparator_kind=kind,
            comparator_params=params,
            spec_id=spec_id,
            pinned_inputs=pinned_inputs,
        )
    # Defence in depth: these also run across the WHOLE anchored set in
    # build_anchored_spec_set. Running them per-spec means an incoherent single
    # spec is refused by every entry point that loads it, not only the one.
    _enforce_monotone_strictness(bindings)
    _enforce_ref_coherence(bindings, spec_path)
    return spec_id, bindings


_SHA256_HEX_RE = None  # lazily compiled below to keep imports stdlib-only


def _parse_pinned_inputs(
    obj: object, spec_path: str, type_key: str
) -> tuple[tuple[str, str], ...]:
    """Parse + validate an OPTIONAL per-type `pinned_inputs` map (§4a.7).

    Shape: {bundle-relative-path: sha256-hex}. Absent -> () (pins nothing).
    Fail-closed (MalformedSpec) on any shape/path error so a malformed pin is
    rejected at load, not silently ignored at dispatch. Paths must be
    bundle-relative and traversal-free; they are resolved+confined again at
    enforcement time (defense in depth), but a spec that names an unsafe path is
    rejected here outright.
    """
    global _SHA256_HEX_RE
    if obj is None:
        return ()
    if not isinstance(obj, dict):
        raise MalformedSpec(
            f"spec {spec_path!r}: type {type_key!r} pinned_inputs must be an object"
        )
    if _SHA256_HEX_RE is None:
        import re as _re

        _SHA256_HEX_RE = _re.compile(r"\A[0-9a-fA-F]{64}\Z")
    out: list[tuple[str, str]] = []
    for rel, want_sha in obj.items():
        if not isinstance(rel, str) or not rel:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} pinned_inputs key must be "
                "a non-empty string path"
            )
        # Bundle-relative + traversal-free. No absolute path, no drive, no '..'
        # segment, no backslash separators.
        norm = rel.replace("\\", "/")
        if (
            norm.startswith("/")
            or ":" in norm.split("/")[0]
            or any(seg in ("..", "") for seg in norm.strip("/").split("/"))
        ):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} pinned_inputs path {rel!r} "
                "is not a safe bundle-relative path (no absolute paths, drives, "
                "empty segments, or '..' traversal)"
            )
        if not isinstance(want_sha, str) or not _SHA256_HEX_RE.match(want_sha):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} pinned_inputs[{rel!r}] must "
                "be a 64-char hex SHA-256 string"
            )
        out.append((norm, want_sha.lower()))
    return tuple(sorted(out))


# ---------------------------------------------------------------------------
# AnchoredSpecSet — the authoritative, anchored, conflict-checked binding map
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnchoredSpecSet:
    """The global type -> Binding map built ONLY from authoritative (anchored)
    specs, after uniqueness + monotone-strictness checks. Frozen at load."""

    by_type: dict[str, Binding]
    authoritative_spec_ids: tuple[str, ...]

    def resolve(self, type_key: str) -> Binding:
        """The Binding for `type_key`, or raise UnknownType (fail-closed) if
        no authoritative spec defines it."""
        b = self.by_type.get(type_key)
        if b is None:
            raise UnknownType(
                f"output type {type_key!r} is not defined by any authoritative "
                f"(auditor-anchored) spec; anchored spec_ids="
                f"{self.authoritative_spec_ids!r}. A spec the producer named but "
                "the auditor did not anchor (or whose SHA does not match the "
                "anchor) is NOT authoritative — fail-closed."
            )
        return b


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_anchored_spec_set(
    bundle_dir: Path,
    manifest,
    anchor: SpecAnchor | None,
) -> AnchoredSpecSet:
    """Build the authoritative binding map under the auditor anchor.

    Reads each spec named in manifest.spec_files offline-first from
    bundle_dir/spec/<basename> (the §C5 verifier-in-a-box copy step 2 already
    SHA-verifies). A spec is AUTHORITATIVE iff (spec_id, on-disk-sha) matches an
    anchor entry. Non-authoritative specs are excluded. Then:
      - reject duplicate type keys across authoritative specs (§4a.2);
      - reject any primitive_id bound by non-identical comparators (§4a.3).

    Raises AnchorNotSupplied when no anchor is supplied, or the supplied anchor
    allows nothing (dispatch engaged but the auditor never established
    authority — verifier incapacity, clean-ERROR), and AnchorViolation when an
    anchor WAS supplied but the authoritative set is empty (artifact-side,
    REJECT).
    """
    if anchor is None:
        raise AnchorNotSupplied(
            "spec-pinned dispatch engaged (manifest declares outputs) but no "
            "auditor SpecAnchor was supplied to BundleVerifier. Without an "
            "auditor-controlled spec allowlist the producer's manifest alone "
            "would select authority — refused (§4a.1). This says NOTHING about "
            "the bundle: the verifier could not conclude, so it is a clean "
            "ERROR, not a REJECT. Supply one with `veriker/cli/verify.py --spec-anchor "
            "<committed-spec.json> ...` or "
            "`BundleVerifier(spec_anchor=SpecAnchor.from_files(...))`."
        )
    if not anchor.allowed:
        # R3 (2026-08-17 CLI-port audit): an EMPTY allowlist used to fall
        # through to the `if not authoritative` AnchorViolation below — a
        # verifier holding NO authority blaming the ARTIFACT (REJECT) for the
        # auditor's empty allowlist. It is the no-anchor absence wearing a
        # constructor call, and it must not pass vacuously either: no
        # authority, no conclusion.
        raise AnchorNotSupplied(
            "spec-pinned dispatch engaged (manifest declares outputs) but the "
            "supplied SpecAnchor allows NOTHING (empty `allowed` set). A "
            "verifier holding no authority cannot judge the artifact — this "
            "says NOTHING about the bundle: clean ERROR, not a REJECT. Build "
            "the anchor from your committed spec bytes with "
            "`SpecAnchor.from_files([...], forbid_within=bundle_dir)`."
        )

    spec_dir = bundle_dir / "spec"
    by_type: dict[str, Binding] = {}
    type_origin: dict[str, str] = {}  # type_key -> spec_id that first defined it
    authoritative: list[str] = []
    # (spec_id, on-disk sha, anchored sha or None) for every binding spec the
    # manifest named that did NOT match the anchor. Feeds the blame-neutral
    # AnchorViolation detail below.
    rejected: list[tuple[str, str, str | None]] = []

    for spec_path in manifest.spec_files:
        offline_copy = spec_dir / Path(spec_path).name
        if not offline_copy.exists():
            # Not loadable offline -> cannot be authoritative for dispatch.
            continue
        computed_sha = _sha256_file(offline_copy)
        try:
            # Admission-bounded (RES-02): the spec copy is an IN-BUNDLE file and
            # is parsed BEFORE the anchor-authority check, so a hostile
            # non-anchored spec must not reach an unbounded parse.
            # InputInadmissible subclasses ValueError -> MalformedSpec below.
            raw = admit_json_file(offline_copy, check_name="spec_admission")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            raise MalformedSpec(f"spec {spec_path!r} is not valid JSON: {exc}") from exc
        # Only specs that ALSO declare a binding object participate. A plain
        # prose spec (no spec_id/types) is silently skipped for dispatch.
        if not (isinstance(raw, dict) and "types" in raw and "spec_id" in raw):
            continue
        spec_id, bindings = parse_spec(raw, spec_path)
        if not anchor.matches(spec_id, computed_sha):
            # SHA-pinned but NOT auditor-anchored (or substituted) -> not
            # authoritative. This is the spec-selection defense (§4a.1).
            # Record WHY it did not match so the failure detail can distinguish
            # "the operator never anchored this spec_id" (operator error) from
            # "anchored, but the on-disk bytes differ" (the substitution case).
            # Dropping this on a bare `continue` is what made AnchorViolation's
            # message assert a blame it had not established.
            rejected.append((spec_id, computed_sha, anchor.allowed.get(spec_id)))
            continue
        authoritative.append(spec_id)
        for type_key, binding in bindings.items():
            if type_key in by_type:
                raise AmbiguousTypeBinding(
                    f"type {type_key!r} defined by both spec_id "
                    f"{type_origin[type_key]!r} and {spec_id!r} — ambiguous "
                    "across the authoritative set; fail-closed (§4a.2)."
                )
            by_type[type_key] = binding
            type_origin[type_key] = spec_id

    if not authoritative:
        raise AnchorViolation(
            "no authoritative spec resolved: none of the manifest's spec_files "
            "matched the auditor anchor by (spec_id, sha) — fail-closed (§4a.1). "
            f"{_describe_anchor_mismatch(rejected, anchor)}"
        )

    _enforce_monotone_strictness(by_type)
    _enforce_ref_coherence(by_type)
    return AnchoredSpecSet(
        by_type=by_type,
        authoritative_spec_ids=tuple(authoritative),
    )


def _describe_anchor_mismatch(
    rejected: list[tuple[str, str, str | None]], anchor: SpecAnchor
) -> str:
    """Blame-NEUTRAL account of why the authoritative set came out empty.

    Two causes reach the same fail-closed REJECT and the verifier cannot tell
    them apart with certainty, so it must report the evidence rather than pick:

      SHA_MISMATCH — the anchor DOES list this spec_id, with different bytes.
                     Consistent with a producer substituting a weaker spec, and
                     also with a stale/re-indented operator copy.
      NOT_ANCHORED — the anchor does not list this spec_id at all. Usually the
                     operator anchored a different pilot's spec or forgot one of
                     several; a producer inventing a spec_id lands here too.

    The old detail asserted "either the producer supplied no anchored binding
    spec, or substituted one" — naming only producer-fault readings for a
    condition an operator typo also produces.
    """
    if not rejected:
        return (
            "The manifest named no loadable binding spec at all (no spec_files "
            "entry carried both 'spec_id' and 'types', or none was present in "
            f"the bundle's spec/ tree). Anchored spec_ids: "
            f"{sorted(anchor.allowed)!r}."
        )
    mismatched = [(sid, got, want) for sid, got, want in rejected if want is not None]
    unanchored = [sid for sid, _got, want in rejected if want is None]
    parts: list[str] = []
    if mismatched:
        parts.append(
            "SHA_MISMATCH (anchored spec_id, DIFFERENT bytes — a substituted "
            "spec looks like this, so does a stale operator copy): "
            + "; ".join(
                f"{sid!r} on-disk={got} anchored={want}"
                for sid, got, want in mismatched
            )
        )
    if unanchored:
        parts.append(
            "NOT_ANCHORED (spec_id absent from the anchor entirely — usually the "
            f"operator anchored the wrong or too few specs): {sorted(unanchored)!r}"
        )
    return " ".join(parts) + f" Anchored spec_ids: {sorted(anchor.allowed)!r}."


def _enforce_ref_coherence(
    by_type: dict[str, Binding], spec_path: str = "<set>"
) -> None:
    """D1/R1: every binding of one primitive NAME must carry an IDENTICAL
    reference constraint — same version, same digest, bare-or-not.

    An earlier version of this check only looked for CONTRADICTIONS (two
    different versions, two different digests) and deliberately permitted a bare
    spelling alongside a pinned one, on the reasoning that "bare imposes
    nothing, so it cannot contradict a pin."

    **That reasoning was wrong, and the adversarial pass measured it.** It is
    true about SATISFIABILITY and false about AUTHORITY. Dispatch selects the
    binding from the PRODUCER-SUPPLIED `type` field, so if the anchored set
    contains both `foo#<digest>` and bare `foo`, the producer simply claims the
    bare type and the auditor's pin is never evaluated. The registry holds
    exactly ONE instance per name, so it is the same code either way — the pin
    would have refused it, and the bare spelling admits it, with the face
    reading `digest_status: "unpinned"`. Measured on one anchored spec, one
    registry: pinned type -> PRIMITIVE_DIGEST_UNAVAILABLE, bare type -> [].

    A pin is therefore a property of the NAME, not of one binding. Requiring
    identical constraints costs a legitimate auditor nothing (they write the
    same reference twice) and closes the strip at LOAD, where the incoherent set
    is visible, rather than per-output at dispatch where it is not.
    """
    seen: dict[str, tuple[tuple[str | None, str | None], str]] = {}
    for type_key, binding in by_type.items():
        ref = binding.resolved_ref()
        constraint = (ref.version, ref.digest)
        prior = seen.get(ref.name)
        if prior is None:
            seen[ref.name] = (constraint, type_key)
            continue
        if prior[0] == constraint:
            continue

        def _fmt(c: tuple[str | None, str | None]) -> str:
            v, dg = c
            bits = []
            bits.append(f"version={v!r}" if v is not None else "unversioned")
            bits.append(f"digest={dg!r}" if dg is not None else "unpinned")
            return " + ".join(bits)

        raise MalformedSpec(
            f"spec {spec_path!r}: primitive {ref.name!r} is bound with "
            f"DIFFERENT reference constraints — type {prior[1]!r} says "
            f"{_fmt(prior[0])}, type {type_key!r} says {_fmt(constraint)}. "
            "The registry holds exactly one implementation per name, so both "
            "bindings reach the SAME code; the weaker spelling is an unpinned "
            "door to it, and dispatch picks the binding from the PRODUCER's "
            "declared type. Bind the name identically everywhere in the "
            "anchored set (§4a.3 sibling; D1/R1)."
        )


def _enforce_monotone_strictness(by_type: dict[str, Binding]) -> None:
    """§4a.3: any primitive_id bound by >=2 types must carry an IDENTICAL
    comparator. A differing comparator on a shared primitive admits a weaker
    sibling the producer could substitute to — reject the anchored set."""
    # D1: key on the PARSED NAME, never the raw string. Once `@version` and
    # `#digest` exist, `foo`, `foo@1` and `foo@2` are three spellings of ONE
    # registry entry -- keying on the raw string makes them three dict keys and
    # lets a producer bind one primitive under two spellings with NON-IDENTICAL
    # comparators, walking straight through this guard. Found by the D1 scoping
    # pass; regression test: tests/test_primitive_ref_wiring.py.
    seen: dict[str, tuple[str, str]] = {}  # primitive NAME -> (canonical_cmp, type_key)
    for type_key, binding in by_type.items():
        canonical = binding._comparator_canonical()
        name = binding.resolved_ref().name
        prior = seen.get(name)
        if prior is None:
            seen[name] = (canonical, type_key)
        elif prior[0] != canonical:
            raise MonotoneStrictnessViolation(
                f"primitive_id {binding.primitive_id!r} is bound by type "
                f"{prior[1]!r} and type {type_key!r} with NON-IDENTICAL "
                f"comparators ({prior[0]} vs {canonical}). This admits a "
                "strength-substitution attack (producer claims the weaker "
                "type); the auditor's anchored spec set is rejected at load "
                "(§4a.3 monotone-strictness)."
            )
