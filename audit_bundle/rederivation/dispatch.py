"""audit_bundle/rederivation/dispatch.py — core spec-pinned dispatch loop.

Runs the per-output dispatch loop and its hardening layer (§4a below). Per
claimed output O in manifest.outputs:

    binding  = anchored_spec_set.resolve(O.type)        # Axis 1 (auditor-anchored)
    value    = registry[binding.primitive_id].recompute(...)   # Axis 2 (value return)
    ok,_     = comparator[binding.comparator.kind](value, claimed, params)  # Axis 2 (split)

The verifier core ROUTES and AGGREGATES; the only domain-specific component is
the recompute primitive. Comparison is generic.

Fail-closed semantics (§4a.8): every per-output evaluation is wrapped so an
error becomes a RECORDED failure, never a crash and never a silent skip. Exactly
one result is recorded per declared output; a final cardinality assertion
(result-count == declared-output-count) guarantees `all([])` can never read True
on an empty or skipped set.

Coverage invariant (§4a.4 / C19): file-presence-triggered on outputs/ — the set
of output_ids declared in manifest.outputs must equal the set of output files
actually present (outputs/<output_id>.json). Otherwise "omit the check name"
just becomes "omit the output entry".

Stdlib-only (core verify() path).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from ..admission import admit_json_file
from ..plugin import ParsedInputs
from ..work_set import WorkSet, WorkSetError
from .coverage_trigger import (
    acceptance_rule_ref,
    coverage_is_triggered,
    outputs_dir,
)
from .comparators import (
    UnknownComparatorKind,
    UnknownComparatorParam,
    resolve_comparator,
)
from .primitive_ref import (
    MalformedPrimitiveRef,
    PrimitiveRefViolation,
    resolve_primitive_ref,
)
from .registry import (
    UnknownPrimitive,
    _ensure_primitives_loaded,
    derive_provenance_of_callable,
    resolve_primitive,
)
from .spec_binding import (
    AnchorNotSupplied,
    SpecAnchor,
    SpecBindingError,
    UnknownType,
    build_anchored_spec_set,
)


@dataclass(slots=True)
class DispatchFailure:
    """One reason the dispatch loop declined to bless an output: which check
    named it, a machine-readable reason code, and a human-readable detail."""

    check_name: str
    reason_code: str
    detail: str
    # True when the row is a VERIFIER could-not-conclude, not evidence against
    # the artifact. The caller (BundleVerifier._step_spec_pinned_dispatch) routes
    # these to a clean-ERROR / VERIFIER_INCOMPLETE leg (exit 2) instead of a
    # REJECT failure (exit 1). Default False: every existing row is artifact-side.
    incomplete: bool = False


# ---------------------------------------------------------------------------
# Non-finite (inf/nan) boundary — applies to EVERY comparator kind.
#
# A re-derivation primitive recomputes the producer's binary64 arithmetic
# faithfully (the MIRROR-the-producer doctrine: re-derivers reproduce the
# producer's exact numeric model, never a "safer" Decimal/fixed-point one).
# That faithfulness has a hard floor: a non-finite result (inf / -inf / nan)
# is never a meaningful compliance claim. It signals overflow or a degenerate
# input, it is not portably reproducible, and stdlib `json` will happily round-
# trip `Infinity`/`NaN` (a non-standard extension) so a producer can both
# OVERFLOW a committed input and CLAIM the overflowed value.
#
# Without this boundary the laundering succeeds comparator-by-comparator: the
# `exact` comparator returns True for `inf == inf` (and `structured` does the
# same for a non-finite field via `!=`), blessing "emissions = infinity" GREEN.
# `scalar_epsilon` already rejects non-finite operands in isolation; this lifts
# that defense to the dispatch chokepoint so it holds for ALL kinds uniformly,
# on BOTH the recomputed value and the producer's claimed value.
#
# The walk is iterative (explicit stack) so a deeply-nested adversarial claimed
# value drives a bounded loop, not a new RecursionError surface.
# ---------------------------------------------------------------------------


def _undeclared_kit_registration(primitive_id: str) -> dict | None:
    """Ask the kit loader whether `primitive_id` was registered by a kit whose
    own `KIT_REGISTERS` manifest does not declare it.

    Consulted through `sys.modules` rather than an import: `kit.py` is the
    `compile()`/`exec()` surface, deliberately kept OFF the default verify
    path's import closure (it is imported lazily, only when a kit is actually
    loaded). If it was never imported then no kit ran in this process, so there
    is nothing to ask — the absence IS the answer, not a swallowed error."""
    mod = sys.modules.get("audit_bundle.rederivation.kit")
    if mod is None:
        return None
    return mod.undeclared_kit_registration(primitive_id)


def _first_nonfinite_path(value: object) -> str | None:
    """Return a human path to the first non-finite float in `value` (walking
    nested lists/tuples/dicts), or None if every float is finite. bool/int are
    always finite; strings are opaque. Iterative to stay bounded on adversarial
    nesting."""
    stack: list[tuple[str, object]] = [("", value)]
    while stack:
        path, node = stack.pop()
        if isinstance(node, float):
            if not math.isfinite(node):
                return f"{path or '<root>'}={node!r}"
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append((f"{path}.{k}" if path else str(k), v))
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                stack.append((f"{path}[{i}]", v))
    return None


# output_id is interpolated into a filename (outputs/<output_id>.json) and used
# as a coverage stem. Constrain it to a single safe path segment so a hostile
# manifest cannot steer verifier-side reads outside outputs/ via traversal. The
# grammar forbids path separators ('/' and '\\') and a leading dot (so '.' and
# '..' are rejected); because no separator can appear, an embedded '..' can
# never form a parent-directory step. The allowed body chars ('.', '_', ':',
# '-' + alnum) cover every real output_id (e.g. 'P6.1_trust_in_ai__DE__2026Q3',
# 'energy-score-2026-04-28T23:00:00Z', 'E0008-2026-05').
#
# LENGTH is bounded too (250 chars: NAME_MAX is 255 bytes on Linux and the id
# gains ".json"; the grammar is ASCII so chars == bytes). MEASURED 2026-09-01
# by the work-set red team: a 251-char id passed the alphabet check, reached
# `claimed_path.is_file()`, and Python 3.12's is_file() does NOT swallow
# ENAMETOOLONG — the OSError escaped to the verify() fail-closed wrapper as
# VERIFIER_INTERNAL_ERROR (exit 2), and the crash outranked every REJECT
# already collected, including a WORK_SET_VIOLATION recorded 30 lines
# earlier and a genuine 60.5 N physics mismatch. A producer could turn "the
# artifact is bad" into "the verifier could not conclude" with one long
# string. Refused here as OUTPUT_ID_UNSAFE before any filesystem call.
_OUTPUT_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,249}\Z")


# The outputs/ trigger has ONE owner (coverage_trigger), shared with
# BundleVerifier's outer gate so the two cannot drift apart.
_outputs_dir = outputs_dir


def _enumerate_output_files(bundle_dir: Path) -> set[str]:
    """The output_ids actually present as outputs/<id>.json files."""
    if not coverage_is_triggered(bundle_dir):
        return set()
    return {p.stem for p in _outputs_dir(bundle_dir).glob("*.json")}


def _check_coverage(
    bundle_dir: Path,
    declared_ids: list[str],
    failures: list[DispatchFailure],
    acceptance_out: dict | None = None,
) -> None:
    """§4a.4 coverage invariant. File-presence-triggered: only fires when an
    outputs/ directory exists. set(declared) must equal set(present).

    `acceptance_out` is a caller-owned accumulator recording that this rule was
    EVALUATED, written from inside the comparison rather than asserted by the
    caller. Same discipline as `verified_outputs` / `recomputed_outputs` below,
    and for the same reason: a face that states enforcement from a hardcoded
    list is a DECLARATION, and this repository keeps finding declarations that
    outlived the code they described — including this very guard, which
    THREAT_MODEL row 5 advertised while it sat below an early return in three
    places. If the check stops running, the face must stop claiming it.
    """
    if not coverage_is_triggered(bundle_dir):
        # NOT recorded as applied: the bundle carries no outputs/ tree, so
        # nothing was compared. The caller discloses that absence.
        return  # inert when the bundle carries no outputs/ tree
    present = _enumerate_output_files(bundle_dir)
    declared = set(declared_ids)
    if acceptance_out is not None:
        acceptance_out[acceptance_rule_ref()] = (
            "satisfied" if declared == present else "violated"
        )
    if declared == present:
        return
    missing_entry = present - declared  # file present, not declared (the omit attack)
    missing_file = declared - present  # declared, no file
    failures.append(
        DispatchFailure(
            check_name="spec_pinned_dispatch:coverage",
            reason_code="COVERAGE_MISMATCH",
            detail=(
                "manifest.outputs must cover exactly the outputs/ files "
                f"(§4a.4). present-but-undeclared={sorted(missing_entry)!r} "
                f"declared-but-absent={sorted(missing_file)!r}"
            ),
        )
    )


def run_spec_pinned_dispatch(
    bundle_dir: Path,
    manifest,
    anchor: SpecAnchor | None,
    work_set: WorkSet | None = None,
    *,
    verified_outputs: set[str] | None = None,
    recomputed_outputs: set[str] | None = None,
    resolved_primitives: set[str] | None = None,
    primitive_provenance_out: dict[str, dict] | None = None,
    in_bundle_source_root: Path | None = None,
    acceptance_out: dict | None = None,
    anchored_types_out: set[str] | None = None,
    resolved_types_out: set[str] | None = None,
) -> list[DispatchFailure]:
    """Run spec-pinned dispatch over manifest.outputs. Returns collected
    failures (empty == all covered outputs re-derived and agreed).

    DISPATCH engages only when manifest.outputs is non-empty. The §4a.4
    COVERAGE invariant does NOT: it runs on the empty-outputs path too, so a
    bundle that ships outputs/*.json while declaring none is refused rather
    than silently skipped. A bundle carrying no outputs/ tree at all is still
    wholly unaffected — that is the property the empty-outputs path exists to
    protect, and coverage is file-presence-triggered so it stays inert there.

    Two optional keyword-only caller-owned accumulators report what actually
    happened, at two different granularities. Both are deliberately NOT
    ``manifest.outputs``, which is a producer DECLARATION and says nothing about
    whether anything ran:

    * ``verified_outputs`` — output_ids that RECOMPUTED and COMPARED EQUAL. The
      measured "dispatch re-derived this" signal.
    * ``recomputed_outputs`` — output_ids for which the recompute primitive was
      INVOKED, whatever happened next (returned and agreed, returned and
      disagreed, or raised). Distinguishes "the primitive ran" from "dispatch
      never got that far" — a distinction the verdict face needs, because most
      REJECT paths here abandon the output BEFORE the primitive is invoked
      (AnchorViolation, UNKNOWN_TYPE, UNKNOWN_PRIMITIVE, CLAIMED_VALUE_MISSING,
      PINNED_INPUT_MISMATCH, OUTPUT_ENTRY_MALFORMED …). RECOMPUTE_ERROR is NOT
      one of them: it is raised from inside the call, so it counts as invoked.
      Without this the disclosure could only infer the count from the
      declaration and assert a recompute that never happened (adversarial
      audit, 2026-08-16).
    * ``resolved_primitives`` — primitive_ids the registry actually RESOLVED
      for this dispatch (whether or not the recompute then succeeded).
    * ``primitive_provenance_out`` — primitive_id -> {origin, source, sha256,
      tier, self_declared_tier, ref}. `tier` is the PUBLISHED taxonomy and is
      distribution-only; an outside primitive's own claim rides in
      `self_declared_tier` so it can never be read as our endorsement.
      derived from the RESOLVED INSTANCE at this seam (registry.derive_provenance),
      for the verdict face. A verdict that cannot say WHOSE code recomputed
      cannot be audited (the reasoning that put the anchor's provenance on the
      face).
    * ``in_bundle_source_root`` — the ORIGINAL (pre-snapshot) bundle root. A
      resolved primitive whose derived source resolves inside it is refused
      (PRIMITIVE_SOURCE_INSIDE_BUNDLE, incomplete) before recompute — producer
      code reached through a kit is the primitive twin of the in-bundle anchor
      tautology. Scoped to the primitive an output RESOLVES (an inert registered
      primitive launders nothing; a pilot verified in place legitimately ships
      its own primitive in-dir). None disables the check.
    * ``anchored_types_out`` — every type key the AUTHORITATIVE (auditor-
      anchored) spec set defines: the DENOMINATOR of the anchored-type coverage
      channel. Taken from `AnchoredSpecSet.by_type`, which
      `build_anchored_spec_set` populates only from specs whose (spec_id,
      on-disk sha) matched the auditor's `SpecAnchor` — so a producer cannot
      shrink it by editing the manifest's `outputs`. Written as soon as the
      anchored set is built, BEFORE the output loop, so the denominator is
      committed before any numerator exists.
    * ``resolved_types_out`` — type keys `anchored.resolve()` actually RETURNED
      a binding for: the NUMERATOR. Measured at the resolve seam rather than
      read off the declaration, for the same reason `resolved_primitives` is —
      a face may only claim a rule was reached if the reach happened.
      `anchored − resolved` is the set of rules the authority named that judged
      NOTHING, which is the retyping escape (§E6): retype an output onto a
      sibling type and its own rule runs zero times. This channel is the
      generic FALLBACK for a verifier holding no work-set: it can say a rule
      was never reached, never which claim reached it.

    ``work_set`` (positional, VERIFIER-HELD) is the mechanism, where the auditor
    supplies one: the complete multiset of output_ids the bundle must deliver,
    each pinned to its type (`audit_bundle/work_set.py`). It is checked FIRST,
    above the empty-outputs early return, because the total omission of
    `manifest.outputs` is the drop escape in its purest form and a guard under
    an early return is never in one place. A violation is a REJECT
    (`WORK_SET_VIOLATION`): the artifact did not deliver what was asked. A
    verifier holding no work-set is the unconfigured case — a disclosure on the
    face, never a refusal.
    """
    outputs = list(getattr(manifest, "outputs", ()) or ())
    failures: list[DispatchFailure] = []

    # --- THE WORK-SET, before anything else. ---
    # The producer's declaration is taken WHOLE, as a list: never projected to
    # a dict first, which is the projection that collapses a duplicated
    # output_id into one (the helper's own docstring names it). The check is
    # multiset-aware, so a dropped slot, a smuggled slot and a duplicated slot
    # are each a finding. `check_delivery` raises WorkSetError and nothing
    # else; the verifier's contract is a fail-closed VERDICT, so the boundary
    # maps it here. Anything that is NOT a WorkSetError — WorkSetIntegrityError
    # (the held set no longer re-derives under its own sha) or a crash — is the
    # verifier's own incapacity, which is a could-not-conclude, not evidence
    # against the artifact.
    if work_set is not None:
        try:
            work_set.check_delivery(outputs)
        except WorkSetError as exc:
            failures.append(
                DispatchFailure(
                    check_name="spec_pinned_dispatch:work_set",
                    reason_code="WORK_SET_VIOLATION",
                    detail=str(exc),
                )
            )
        except Exception as exc:  # noqa: BLE001 — fail-closed, never escape
            failures.append(
                DispatchFailure(
                    check_name="spec_pinned_dispatch:work_set",
                    reason_code="WORK_SET_CHECK_ERROR",
                    detail=f"WORK_SET_CHECK_ERROR: the verifier could not apply "
                    f"its work-set: {type(exc).__name__}: {exc}",
                    incomplete=True,
                )
            )

    if not outputs:
        # §4a.4 coverage invariant, hoisted ABOVE this early return.
        # It used to be reached only after dispatch engaged, so a TOTAL
        # omission of manifest.outputs skipped the very guard written to
        # catch omission: partial omission fired COVERAGE_MISMATCH, total
        # omission returned OK. File-presence-triggered, so a legacy bundle
        # carrying no outputs/ tree stays inert — the property this early
        # return exists to protect. (A held work-set has already been checked
        # above, so total omission against a work-set is a REJECT regardless.)
        _check_coverage(bundle_dir, [], failures, acceptance_out)
        return failures

    # --- Coverage invariant (§4a.4), file-presence-triggered. ---
    # ABOVE the anchor bind, because coverage needs no anchor: it compares the
    # producer's declaration against the files on disk and asks nothing of any
    # spec. It used to sit BELOW the `return failures` in the except clause
    # below, which is the same "guard under an early return" shape as the two
    # returns this function's empty-outputs branch already had to hoist past.
    # A bundle verified with no anchor (the path every migrated pilot takes
    # under the shipped anchor-less CLI) therefore never had its coverage
    # checked at all — a clean-ERROR rather than a fail-open, but the invariant
    # was dead on exactly the runs that are most common.
    declared_ids = [
        o.get("output_id") if isinstance(o, dict) else None for o in outputs
    ]
    _check_coverage(
        bundle_dir,
        [d for d in declared_ids if isinstance(d, str)],
        failures,
        acceptance_out,
    )

    # --- Build the auditor-anchored authoritative binding set (steps 3-5). ---
    # Any load-time failure (no anchor, malformed/ambiguous spec, monotone-
    # strictness violation) is terminal: record it and refuse to dispatch.
    try:
        anchored = build_anchored_spec_set(bundle_dir, manifest, anchor)
    except SpecBindingError as exc:
        failures.append(
            DispatchFailure(
                check_name="spec_pinned_dispatch:anchor",
                reason_code=type(exc).__name__,
                detail=str(exc),
                # AnchorNotSupplied is the ONLY load-time anchor failure that is
                # the verifier's own incapacity (nobody handed it an authority —
                # no anchor at all, or an anchor allowing nothing). Everything
                # else here — a substituted spec whose SHA the anchor does not
                # list, a malformed spec, an ambiguous type binding, a
                # monotone-strictness violation — is a property of the ARTIFACT
                # under an authority that WAS established, so it stays a REJECT.
                incomplete=isinstance(exc, AnchorNotSupplied),
            )
        )
        return failures

    # THE DENOMINATOR, committed here — before the output loop that produces the
    # numerator, and out of the anchored set rather than the manifest. Every key
    # in `by_type` came from a spec whose (spec_id, sha) the auditor's anchor
    # listed, so this is the authority's own table: the producer can decline to
    # exercise a row, which is exactly what the channel reports, but cannot
    # remove one from the count.
    #
    # NOTE the denominator's own edge: `by_type` is what the specs the producer
    # NAMED in `manifest.spec_files` define, with the anchor as a filter. A
    # work-set closes that edge where one is held (a claim the shrunk spec
    # would have judged is either missing — WORK_SET_VIOLATION — or delivered
    # under a type no authoritative spec defines — UNKNOWN_TYPE). Without a
    # work-set this channel cannot see a spec the producer stopped naming.
    if anchored_types_out is not None:
        anchored_types_out.update(anchored.by_type)

    _ensure_primitives_loaded()

    inputs = ParsedInputs(bundle_dir=bundle_dir)
    results: list[bool] = []  # exactly one per declared output (cardinality guard)

    for o in outputs:
        cn = "spec_pinned_dispatch"
        # --- Output entry shape ---
        if not isinstance(o, dict):
            failures.append(
                DispatchFailure(
                    cn, "OUTPUT_ENTRY_MALFORMED", f"output entry not an object: {o!r}"
                )
            )
            results.append(False)
            continue
        output_id = o.get("output_id")
        type_key = o.get("type")
        conforms_to = o.get("conforms_to")
        cn = f"spec_pinned_dispatch:{output_id}"
        if not isinstance(output_id, str) or not output_id:
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ENTRY_MALFORMED",
                    f"output_id not a non-empty string: {output_id!r}",
                )
            )
            results.append(False)
            continue
        if not _OUTPUT_ID_RE.match(output_id):
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ID_UNSAFE",
                    f"output_id {output_id[:64]!r}{'…' if len(output_id) > 64 else ''} "
                    f"(length {len(output_id)}) is not a safe filename segment "
                    "(grammar: [A-Za-z0-9][A-Za-z0-9._:-]{0,249}) — it is "
                    "interpolated into outputs/<output_id>.json, so path "
                    "separators, traversal and a name longer than the filesystem "
                    "can hold are refused to keep verifier-side reads inside "
                    "outputs/ and out of an OSError.",
                )
            )
            results.append(False)
            continue
        if not isinstance(type_key, str) or not type_key:
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ENTRY_MALFORMED",
                    f"output {output_id!r}: type not a non-empty string",
                )
            )
            results.append(False)
            continue
        # conforms_to is a non-load-bearing cross-check hint (§4a.2 option b:
        # resolution is by anchored-search, not by following this pointer). It
        # must be a string if present; it cannot redirect dispatch.
        if conforms_to is not None and not isinstance(conforms_to, str):
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ENTRY_MALFORMED",
                    f"output {output_id!r}: conforms_to not a string",
                )
            )
            results.append(False)
            continue

        # --- Type-substitution pin (§4a.3), read from the auditor's work-set.
        #     An output the work-set does NOT name has already been refused
        #     above (WORK_SET_VIOLATION), so `None` here is never
        #     "unconstrained" — the allow-by-default that let an unlisted
        #     output ride a valid sibling type to exit 0. ---
        if work_set is not None:
            required = work_set.required_type(output_id)
            if required is not None and required != type_key:
                failures.append(
                    DispatchFailure(
                        cn,
                        "ROLE_POLICY_VIOLATION",
                        f"output {output_id!r} claims type {type_key!r} but the "
                        f"auditor's work-set pins {required!r} — a weaker/other "
                        "type was substituted; fail-closed (§4a.3).",
                    )
                )
                results.append(False)
                continue

        # --- Resolve binding (Axis 1, auditor-anchored). ---
        try:
            binding = anchored.resolve(type_key)
        except UnknownType as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_TYPE", str(exc)))
            results.append(False)
            continue
        # THE NUMERATOR, measured at the seam where the reach actually happened.
        # Recorded on RESOLUTION, not on a successful comparison: a rule that
        # ran and disagreed is a REJECT, and the accounting must not ALSO refuse
        # to conclude about a channel that concluded perfectly well. The weaker
        # reading is the safe one here precisely because everything downstream
        # of this point already fails closed on its own terms.
        if resolved_types_out is not None:
            resolved_types_out.add(type_key)

        # --- Pinned-input enforcement (§4a.7, auditor-anchored). Every bundle
        #     file the recompute CONSUMES that the spec pins by SHA must match
        #     out-of-band, BEFORE the recompute reads it. The pinned hashes live
        #     in the auditor-anchored spec (its SHA is in the SpecAnchor), so a
        #     producer who swaps a pinned input and re-coheres the manifest still
        #     fails closed: matching would require editing the spec's pin, which
        #     changes the spec SHA the anchor lists (-> AnchorViolation upstream).
        #     Inert for any binding that pins nothing (pinned_inputs == ()). ---
        if binding.pinned_inputs:
            bundle_root = bundle_dir.resolve()
            pin_failed = False
            for rel, want_sha in binding.pinned_inputs:
                pinned_path = (bundle_dir / rel).resolve()
                try:
                    pinned_path.relative_to(bundle_root)
                except ValueError:
                    failures.append(
                        DispatchFailure(
                            cn,
                            "PINNED_INPUT_UNSAFE",
                            f"output {output_id!r}: pinned input {rel!r} resolves "
                            "outside the bundle — refusing the read.",
                        )
                    )
                    pin_failed = True
                    break
                if not pinned_path.is_file():
                    failures.append(
                        DispatchFailure(
                            cn,
                            "PINNED_INPUT_MISSING",
                            f"output {output_id!r}: auditor-pinned input {rel!r} is "
                            "absent from the bundle — fail-closed (§4a.7).",
                        )
                    )
                    pin_failed = True
                    break
                got_sha = hashlib.sha256(pinned_path.read_bytes()).hexdigest()
                if got_sha != want_sha:
                    failures.append(
                        DispatchFailure(
                            cn,
                            "PINNED_INPUT_MISMATCH",
                            f"output {output_id!r}: auditor-pinned input {rel!r} has "
                            f"SHA {got_sha} but the anchored spec requires "
                            f"{want_sha} — the recompute input was substituted "
                            "after the auditor pinned it; fail-closed (§4a.7).",
                        )
                    )
                    pin_failed = True
                    break
            if pin_failed:
                results.append(False)
                continue

        # --- Load the producer's claimed value (outputs/<id>.json {"value":…}). ---
        claimed_path = _outputs_dir(bundle_dir) / f"{output_id}.json"
        # Defense in depth: the grammar above already forbids separators and
        # traversal, but assert the resolved path stays inside outputs/ so even
        # a symlink under outputs/ or a platform-specific path quirk (e.g. a
        # Windows drive-relative segment) cannot steer the read outside it.
        outputs_root = _outputs_dir(bundle_dir).resolve()
        try:
            claimed_path.resolve().relative_to(outputs_root)
        except ValueError:
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ID_UNSAFE",
                    f"output {output_id!r}: claimed-value path resolves outside "
                    "outputs/ — refusing the read.",
                )
            )
            results.append(False)
            continue
        if not claimed_path.is_file():
            failures.append(
                DispatchFailure(
                    cn,
                    "CLAIMED_VALUE_MISSING",
                    f"output {output_id!r}: no outputs/{output_id}.json claimed-value file",
                )
            )
            results.append(False)
            continue
        try:
            # Admission-bounded load (RES-02): size-reject BEFORE allocation,
            # depth-scan BEFORE parse — the producer-claimed value is the most
            # bundle-controlled read on the dispatch path and must clear the
            # same gate as every other bundle JSON. InputInadmissible is a
            # ValueError, so a breach lands in the except arm below and keeps
            # the CLAIMED_VALUE_MALFORMED reason code (sweep convention).
            claimed_doc = admit_json_file(
                claimed_path, check_name="claimed_value_admission"
            )
            if not isinstance(claimed_doc, dict) or "value" not in claimed_doc:
                raise ValueError(
                    "claimed-value file must be a JSON object with a 'value' key"
                )
            claimed = claimed_doc["value"]
        except (
            json.JSONDecodeError,
            ValueError,
            UnicodeDecodeError,
            OSError,
            RecursionError,  # belt-and-suspenders; admission pre-empts the parser
        ) as exc:
            failures.append(
                DispatchFailure(
                    cn, "CLAIMED_VALUE_MALFORMED", f"output {output_id!r}: {exc}"
                )
            )
            results.append(False)
            continue

        # --- Resolve primitive + comparator (fail-closed on unknown). ---
        # D1: resolve through the parsed reference (name[@version][#sha256hex]).
        # A bare id is UNVERSIONED and behaves exactly as before; a version or
        # digest is an auditor-side constraint enforced HERE, fail-closed.
        try:
            ref = binding.resolved_ref()
        except MalformedPrimitiveRef as exc:
            # Belt-and-braces: parse_spec already refused this at load, so
            # reaching here means a Binding was constructed outside the loader.
            failures.append(
                DispatchFailure(
                    cn,
                    "MALFORMED_PRIMITIVE_REF",
                    f"MALFORMED_PRIMITIVE_REF: output {output_id!r}: {exc}",
                )
            )
            results.append(False)
            continue
        # `resolve_primitive` is read as the MODULE GLOBAL at call time, so
        # fault injection against this module still reaches resolution (the
        # liveness seam -- a silently skipped step is otherwise
        # indistinguishable from a passing one).
        try:
            primitive = resolve_primitive(ref.name)
        except UnknownPrimitive as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_PRIMITIVE", str(exc)))
            results.append(False)
            continue

        # R2 (adversarial pass 2026-08-29): bind the recompute callable EXACTLY
        # ONCE. The digest is taken from THIS object and THIS object is invoked
        # below. A second `getattr` at invocation let a `property` hand honest
        # code to the hasher and hostile code to the caller -- MEASURED as a
        # clean verdict with digest_status "matched" naming a file whose code
        # never ran. R3: the bind itself can raise, so it is wrapped.
        try:
            bound_recompute = primitive.recompute
        except Exception as exc:  # noqa: BLE001 - fail-closed, never escape
            failures.append(
                DispatchFailure(
                    cn,
                    "RECOMPUTE_BIND_ERROR",
                    f"RECOMPUTE_BIND_ERROR: output {output_id!r}: binding "
                    f"`recompute` on primitive {ref.name!r} raised "
                    f"{type(exc).__name__}: {exc}",
                )
            )
            results.append(False)
            continue

        try:
            _resolved, ref_record = resolve_primitive_ref(
                ref,
                resolver=lambda _n, _p=primitive: _p,
                bound_recompute=bound_recompute,
            )
        except UnknownPrimitive as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_PRIMITIVE", str(exc)))
            results.append(False)
            continue
        except PrimitiveRefViolation as exc:
            # The auditor pinned a version or a digest and the resolved code did
            # not satisfy it. A REFUSAL, never a comparison result. The code is
            # prefixed into the detail because a DispatchFailure routed to
            # Verdict.incomplete carries only `detail` downstream.
            failures.append(
                DispatchFailure(
                    cn,
                    exc.reason_code,
                    f"{exc.reason_code}: output {output_id!r}: {exc.detail}",
                )
            )
            results.append(False)
            continue
        if resolved_primitives is not None:
            resolved_primitives.add(binding.primitive_id)

        # WHOSE CODE is about to recompute — derived from the callable BOUND
        # ABOVE, which is the object invoked below (R2). Deriving from the
        # instance here would re-read the attribute and could describe
        # different code than the one that runs.
        prov = derive_provenance_of_callable(bound_recompute)

        # In-bundle-source REFUSAL, scoped to the primitive THIS output resolves
        # (not every registered primitive — a registered-but-unused primitive
        # sourced in the bundle is inert, and a pilot verified IN PLACE ships its
        # own auditor primitive inside its dir). Checked against the ORIGINAL
        # (pre-snapshot) bundle root, since the primitive's source is its load
        # path, never the snapshot. A recompute primitive read out of the bundle
        # under audit is producer code reached through a kit that imported out of
        # the bundle — recompute-and-compare against it is a tautology (the
        # code-side of SPEC_ANCHOR_INSIDE_BUNDLE). Refuse before recompute so the
        # bundle's own code never produces the agreement.
        src = prov.get("source")
        if in_bundle_source_root is not None and isinstance(src, str):
            try:
                resolved_src = Path(src).resolve()
                root = in_bundle_source_root.resolve()
                in_bundle = resolved_src == root or root in resolved_src.parents
            except OSError:
                in_bundle = False
            if in_bundle:
                failures.append(
                    DispatchFailure(
                        cn,
                        "PRIMITIVE_SOURCE_INSIDE_BUNDLE",
                        # Prefix the code into the detail: an `incomplete`
                        # DispatchFailure is routed to Verdict.incomplete, which
                        # reports VERIFIER_INCOMPLETE and carries the specific
                        # code only in detail — so the code must live there to
                        # reach the face. (Unlike the typed-check plugin path,
                        # which propagates the plugin's code since 2026-08-30,
                        # this arm still has no domain-code channel.)
                        "PRIMITIVE_SOURCE_INSIDE_BUNDLE: output "
                        f"{output_id!r}: recompute primitive "
                        f"{binding.primitive_id!r} resolves to code at {src!r}, "
                        f"inside the bundle under audit ({root}). A primitive "
                        "read out of the bundle is authored by the party it "
                        "constrains — recompute-and-compare is a tautology, the "
                        "code-side of the in-bundle anchor hole. Load it from an "
                        "auditor-held kit OUTSIDE the bundle.",
                        incomplete=True,
                    )
                )
                results.append(False)
                continue

        if primitive_provenance_out is not None:
            # D1: the ref record rides ALONGSIDE provenance, never merged into
            # it. `version_status`/`digest_status` keep the three states
            # distinguishable on the face -- unversioned, version-matched,
            # digest-pinned-and-matched -- so a reader can never mistake "the
            # auditor pinned nothing" for "the auditor pinned this and it
            # matched" (the labeling-up defect, D1 scoping Stage 1).
            #
            # D4 (§8b): the TIER rides here too. It is not decoration -- it
            # is what stops a declared version from reading as standardization.
            # `climate_emission_recompute@1` and `fintech_audit_recompute@1` are
            # the same shape of claim about revision identity, and only the tier
            # tells an auditor that the first is a reference implementation and
            # the second a guard-covered general shape. The declared VERSION is
            # already on the face as ref.version_declared, so it is not repeated.
            #
            # Read from the RESOLVED INSTANCE at this seam, like provenance and
            # for the same reason: a class-level read describes code that may not
            # be what dispatch holds. `getattr` only suppresses AttributeError,
            # so a raising descriptor is caught explicitly -- a disclosure must
            # never escape as an exception and skip the per-output guard (R3).
            #
            # WHOSE JUDGMENT THE TIER IS. `tier` means "tier in the PUBLISHED
            # taxonomy", which only the promotion process confers -- a
            # faithfulness test against an independently written producer, the
            # producer/verifier disjointness check, review. A primitive from a
            # kit has not been through that, so it cannot have one. Its own
            # assessment is still reported, in a field that does not imply our
            # endorsement.
            #
            # This finishes a rule that was already half-applied: a kit
            # declaring `primitive_tier = "GOLD"` was already dropped to None
            # (minting a new label onto our face), while a kit declaring "A"
            # passed straight through -- the MORE dangerous of the two, because
            # it borrows a value that looks legitimate. `origin` sat right there
            # to disambiguate, but a reader skimming for tier saw an "A". Both
            # cases now fail the same way, and the ambiguous one reads as NO
            # TIER rather than as a tier we conferred.
            #
            # A self-declared tier outside the taxonomy is NOT echoed either:
            # reporting arbitrary author-supplied strings is the same defect
            # with an extra field.
            try:
                declared_tier = getattr(primitive, "primitive_tier", None)
            except Exception:  # noqa: BLE001 - a disclosure, never a gate
                declared_tier = None
            if declared_tier not in ("A", "B", "C"):
                declared_tier = None
            # Deny by default: only "distribution" confers a tier. "unknown"
            # (no derivable source) is NOT distribution.
            ours = prov.get("origin") == "distribution"
            primitive_provenance_out[binding.primitive_id] = {
                **prov,
                "tier": declared_tier if ours else None,
                "self_declared_tier": None if ours else declared_tier,
                "ref": ref_record,
            }
        # KIT MANIFEST, scoped exactly as the in-bundle-source refusal above
        # is: a kit that registered this primitive WITHOUT declaring it in its
        # own KIT_REGISTERS only matters once a pinned spec actually BINDS it.
        # An undeclared id nothing binds is inert — it stays a disclosure on the
        # kit row, never fatal — for the same reason PRIMITIVE_SOURCE_INSIDE_
        # BUNDLE is scoped to the primitive THIS output resolves rather than to
        # every registered one.
        #
        # PLACED AFTER the provenance row above, deliberately. This refusal
        # exists to raise the question "whose code was about to judge this
        # output?", and `primitive_provenance` is the field that answers it.
        # Refusing before the row was written discarded that answer at the one
        # seam that most needs it (found by the fresh-context pass, 2026-08-29).
        # It is still before any recompute, which is what the refusal requires.
        #
        # INCOMPLETE (exit 2), not REJECT (exit 1). A manifest disagreement is a
        # property of the AUDITOR'S OWN KIT, never of the bundle: nothing has
        # been shown wrong with the artifact, so "this artifact is bad" would be
        # a mislabel. What IS true is that the code which judged this output was
        # not disclosed by the kit that supplied it, so the verdict cannot be
        # concluded — which is what exit 2 means here.
        #
        # THE OTHER DIRECTION IS DISCLOSURE-ONLY, but not because it is
        # unreachable — an earlier version of this comment said it "cannot reach
        # this point", which is false and was cited twice as a justification. An
        # id a kit DECLARED but did not add can still be registered (by an
        # earlier kit sharing a sibling module, or by the distribution), resolve
        # here, and be judged. It is not refused because it is not the defect
        # this guard names: the code that ran WAS declared, by someone. Only the
        # id nobody registered fails, and it fails as UNKNOWN_PRIMITIVE above.
        undeclared = _undeclared_kit_registration(ref.name)
        if undeclared is not None:
            failures.append(
                DispatchFailure(
                    cn,
                    "PRIMITIVE_UNDECLARED_BY_KIT",
                    # Prefixed into the detail for the same reason as the
                    # refusal above: an `incomplete` DispatchFailure is routed
                    # to Verdict.incomplete, which carries only `detail`.
                    "PRIMITIVE_UNDECLARED_BY_KIT: output "
                    f"{output_id!r}: recompute primitive {ref.name!r} was "
                    f"registered by kit {undeclared.get('kit_path')!r} "
                    f"(sha256 {undeclared.get('kit_sha256')}), whose manifest "
                    f"declares {undeclared.get('declared')!r} and does not "
                    "name it. The code that judged this output is not the code "
                    "the kit says it brings. Fix the kit's KIT_REGISTERS, or "
                    "load the kit that really owns this primitive. LEGIBILITY: "
                    "this catches a kit whose declaration and behaviour have "
                    "drifted, not a kit that misdeclares on purpose.",
                    incomplete=True,
                )
            )
            results.append(False)
            continue

        try:
            comparator = resolve_comparator(binding.comparator_kind)
        except (UnknownComparatorKind, UnknownComparatorParam) as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_COMPARATOR_KIND", str(exc)))
            results.append(False)
            continue

        # --- Recompute (Axis 2; try/except -> recorded failure, §4a.8). ---
        # Record the ATTEMPT before the call, not after it. Recording after the
        # try/except excluded RECOMPUTE_ERROR — the one path defined by the
        # primitive having run — so the verdict face could say dispatch
        # "refused or failed before any primitive ran" about an output whose
        # primitive ran and raised (adversarial audit, 2026-08-16).
        if recomputed_outputs is not None:
            recomputed_outputs.add(output_id)
        pack_section = {
            "output_id": output_id,
            "type": type_key,
            "params": dict(binding.comparator_params),
        }
        try:
            # R2: the SAME object that was hashed above. Never re-read the
            # attribute here — that is the divergence the pin exists to close.
            recomputed = bound_recompute(inputs, pack_section)
        except Exception as exc:  # noqa: BLE001 — any primitive error is fail-closed
            failures.append(
                DispatchFailure(
                    cn,
                    "RECOMPUTE_ERROR",
                    f"output {output_id!r}: primitive {binding.primitive_id!r} "
                    f"raised {type(exc).__name__}: {exc}",
                )
            )
            results.append(False)
            continue

        # --- Non-finite boundary (every comparator kind). A non-finite value
        #     on either side is a fail-closed REJECT, BEFORE the comparator runs,
        #     so `inf == inf` / a non-finite structured field can never be
        #     blessed GREEN by exact/set/structured (scalar_epsilon already
        #     guards in isolation). Recomputed side first (verifier saw it), then
        #     the producer's claimed side. ---
        nf = _first_nonfinite_path(recomputed.value)
        side = "recomputed"
        if nf is None:
            nf = _first_nonfinite_path(claimed)
            side = "claimed"
        if nf is not None:
            failures.append(
                DispatchFailure(
                    cn,
                    "NON_FINITE_VALUE",
                    f"output {output_id!r} (type {type_key!r}): non-finite "
                    f"{side} value at {nf} — a non-finite (inf/nan) result is "
                    f"never a verifiable claim (overflow/degenerate input)",
                )
            )
            results.append(False)
            continue

        # --- Compare (Axis 2; wrapped so a comparator that DOES raise is a
        #     recorded fail-closed REJECT, never an uncaught crash that
        #     escalates to a could-not-conclude verdict). The comparator
        #     contract is "never raises", but a deeply-nested claimed value read
        #     from outputs/<id>.json can drive _freeze/_cmp_* into RecursionError;
        #     this boundary enforces the contract for the whole verify path the
        #     same way the recompute call above is wrapped (§4a.8). ---
        try:
            ok, detail = comparator(
                recomputed.value, claimed, binding.comparator_params
            )
        except Exception as exc:  # noqa: BLE001 — any comparator error is fail-closed
            failures.append(
                DispatchFailure(
                    cn,
                    "COMPARATOR_ERROR",
                    f"output {output_id!r} (type {type_key!r}, comparator "
                    f"{binding.comparator_kind!r}): comparator raised "
                    f"{type(exc).__name__}: {exc}",
                )
            )
            results.append(False)
            continue
        if not ok:
            failures.append(
                DispatchFailure(
                    cn,
                    "RE_DERIVATION_MISMATCH",
                    f"output {output_id!r} (type {type_key!r}, "
                    f"primitive {binding.primitive_id!r}, comparator "
                    f"{binding.comparator_kind!r}): {detail}"
                    + (f" | {recomputed.detail}" if recomputed.detail else ""),
                )
            )
            results.append(False)
            continue

        results.append(True)
        if verified_outputs is not None:
            verified_outputs.add(output_id)

    # --- Cardinality guard (§4a.8): one result per declared output. ---
    if len(results) != len(outputs):
        failures.append(
            DispatchFailure(
                "spec_pinned_dispatch:cardinality",
                "CARDINALITY_VIOLATION",
                f"evaluated {len(results)} result(s) for {len(outputs)} declared "
                "output(s) — refusing to let an incomplete set aggregate to PASS.",
            )
        )

    return failures
