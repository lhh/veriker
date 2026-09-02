"""tests/claimset_ratchet.py — the per-field tamper ratchet for claimset coverage.

The claimset coverage gate proves ACCOUNTING: every claim-field element is
either plugin-reported covered or excused. Reporting is a promise by
verifier-distribution code — a plugin can declare a field it compares
vacuously (reads it, then never binds the value), and the gate cannot tell.
This harness is the executable check for that shape:

    for each covered claim-field element, apply a declared FORGING-PRODUCER
    mutation (then re-pin exactly what a producer legitimately re-pins: the
    manifest file sha, plus any pilot-supplied producer-side re-signing
    hook) and re-run verify. The verdict MUST go non-OK FOR A COMPARATOR
    REASON. A covered element whose mutation SURVIVES (still OK) is a FALSE
    COVERAGE DECLARATION.

Two element kinds, two mutation sets — kind comes from the DECLARATION
(`opaque_claim_files` membership), structure from the BYTES (`classify_kind`),
never from the filename:
  * structured elements: mutate the first instance cell under the field path
    (declared per value kind below);
  * opaque (whole-file) elements: a fixed battery of byte probes — flip the
    first, middle and last byte (deduplicated for tiny files), truncate the
    last byte, append one byte — and the element scores FLIPPED only if
    EVERY distinct probe flips for a comparator reason. Any surviving probe
    scores SURVIVED with the per-probe profile (a byte-0-only flip is named
    as a format/magic sniff). The conclusion is "flipped at all N probed
    mutations", never "bound as a whole" — a comparator that binds exactly
    the probed positions would pass; the probes are fixed and public by the
    doctrine that mutations are declared, never tuned.

ATTRIBUTION IS BAKED IN, not left to the caller. A flip is scored FLIPPED
only when a comparator actually refused the mutated value; a flip caused
solely by plumbing the mutation disturbed — a bare file-sha mismatch, a
manifest signature the `repin` hook did not re-establish, or the claimset
gate re-enumerating a changed universe (`_PLUMBING_CODES`) — is scored
INCONCLUSIVE, and so is any ERROR-state verdict (a plugin that CRASHES on
corrupt bytes, or a clean-ERROR, is could-not-conclude, not a refusal). A
caller checking only `not report.survived` therefore cannot be fooled by a
plumbing flip into crediting an unbound field; assert on `report.flipped`
and on the comparator's own reason appearing in `ElementOutcome.reasons`.

Honest limits, stated once here:
  * mutations are value-level / byte-level; a comparator tolerance wide
    enough to absorb the declared mutation is the producer-tolerance
    fail-open class, out of this harness's scope — the mutation set is
    declared below and never tuned until a run passes;
  * an element whose only instances are empty containers cannot be
    value-mutated without changing the payload SCHEMA (which trips the
    coverage gate itself, proving nothing about the comparator) — such
    elements are reported SKIPPED with the reason, never silently passed;
  * one instance cell is mutated per structured element (the first, in
    document order); a comparator that binds only SOME instances can pass —
    cell exhaustiveness is a battery-depth choice callers can raise later;
  * excused (withheld) elements are never probed: the battery says nothing
    about them, and `RatchetReport.excused` lists them so a caller cannot
    read a short battery as a complete one;
  * COST: every probe is a full bundle copy plus a full verify() — an opaque
    element costs up to five verifier runs, each re-invoking the pilot's
    pack (for a re-rendering pilot, five re-renders).

Reusable: pilot CI imports run_claimset_ratchet with the pilot's plugin
factory (fresh plugin instances per run — a verifier run must never share
plugin state with another) and an optional `repin` hook for producer-side
signatures and producer-committed digests. Stdlib + first-party only.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.claimset import (
    ClaimBytesKind,
    ClaimsetError,
    classify_kind,
    enumerate_claim_universe,
)
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier

_ARRAY_MARKER = "[]"

#: Explicit opt-in to the WEAK, fail-open scoring mode. Pass this as
#: `comparator_codes` to say "I have not classified this pilot's reason codes;
#: score any non-plumbing code as a comparator refusal." It exists so that
#: choice is WRITTEN DOWN at the call site and printed on the report, rather
#: than being what you get by forgetting an argument.
#:
#: Why the parameter has no default: the denylist mode credits any code nobody
#: has classified as "a comparator refused the mutated value". At least 15
#: could-not-conclude codes reach the scorer that way -- six sibling *_TIMEOUT
#: codes, and the *_UNREADABLE / *_PARSE_ERROR / *_KEY_MATERIAL_UNAVAILABLE
#: families -- so a forgotten argument silently credits coverage that was never
#: proven. A required argument turns that into a decision.
DENYLIST_SCORING = "DENYLIST_SCORING__FAIL_OPEN_ON_UNCLASSIFIED_CODES"

# Declared mutation per value kind — fixed BEFORE any run; never tuned to make
# a run pass. A comparator that absorbs these is reported, not accommodated.
_TAMPER_STRING_SUFFIX = "ΔTAMPERED"
_TAMPER_INT_DELTA = 1
_TAMPER_FLOAT_DELTA = 1.0
# Opaque (whole-file) elements get a fixed battery of byte probes — three
# positions plus two LENGTH mutations — and score FLIPPED only if EVERY
# distinct probe flips: a comparator that only sniffs a format magic flips on
# byte 0 and nowhere else, and is reported as exactly that; a comparator
# that ignores truncation/extension is caught by the length probes.
_OPAQUE_PROBES = ("first", "middle", "last", "truncate", "append")

# Verdict reason codes that indicate the flip was caused by the mutation's
# effect on PLUMBING (byte-integrity / manifest coherence / the claimset gate
# re-enumerating a changed universe) or by a check that COULD NOT CONCLUDE,
# rather than by a comparator refusing the mutated VALUE. A flip whose reasons
# are wholly within this set is scored INCONCLUSIVE, not FLIPPED — it is not
# evidence the field is bound.
#
# RE-DERIVED 2026-08-30, when `_step_typed_check_plugins` stopped overwriting
# every failing plugin's reason_code with the literal "plugin_failed". Before
# that, this set could not be honest: "plugin_failed" was the code for BOTH a
# genuine comparator refusal AND a crash AND a declared-but-unwired check, so
# it was un-classifiable and every plugin failure scored FLIPPED. Making the
# real codes visible is what makes the classification possible — that is the
# payoff of the propagation, not a side effect of it.
_PLUMBING_CODES = frozenset(
    {
        "BAD_FILE_SHA",
        "file_integrity",
        "CLAIMSET_ENUMERATION_FAILED",
        "CLAIMSET_COVERED_FIELD_UNKNOWN",
        "CLAIMSET_UNIVERSE_ANCHOR_MISMATCH",
        "VERIFIER_INCOMPLETE",
        # --- added 2026-08-30 with the reason_code propagation ---
        # After propagation, "plugin_failed" is emitted at exactly three sites
        # in _step_typed_check_plugins and NONE of them is a comparator
        # refusing a value:
        #   * the `except PluginFailed` arm — the plugin raised; there is no
        #     result object, so nothing was compared;
        #   * the declared-but-unwired arm — manifest.typed_checks names a
        #     check no registered plugin implements, so no check ran;
        #   * the degenerate-result fallback — a failing plugin whose own
        #     reason_code is empty or the "PASS" sentinel, i.e. malformed.
        # MEASURED: before this change one live caller
        # (test_ratchet_skips_empty_container_elements_loudly) scored a flip
        # FLIPPED on ("plugin_failed", "VERIFIER_INCOMPLETE") and reported
        # "verdict flipped for comparator reason(s): plugin_failed" — a
        # sentence that was false. That was a coverage credit for a field
        # nothing had bound.
        "plugin_failed",
        # A plugin that threw an unexpected exception. Already reached via the
        # ERROR-state branch below; listed so the classification does not
        # depend on which of the two paths gets there first.
        "VERIFIER_UNEXPECTED_PLUGIN_EXCEPTION",
        # A re-derivation that ran out of time did not finish, so it compared
        # nothing. REACHABLE-BUT-UNOBSERVED: zero occurrences in the 111
        # scored calls across the collected ratchet callers (2026-08-30), but
        # it has ~50 emission sites and any pack-backed claimset pilot can
        # reach it. Added as a forward guard, and labelled as one rather than
        # presented as a measured fix.
        "RE_DERIVATION_TIMEOUT",
        # A pack that exited cleanly having compared NOTHING (the vacuity leg)
        # and the two "there was nothing to run" skips. None is a refusal of a
        # value. RE_DERIVATION_NOT_COMPARED normally carries incomplete=True
        # and never reaches the propagation site -- but a plugin CAN emit it
        # with ok=False, and then it read as a comparator refusal.
        "RE_DERIVATION_NOT_COMPARED",
        "NO_PACK",
        "NO_INPUTS",
        # --- the CORE verifier's own lowercase vocabulary, added 2026-08-31 --
        # Membership is exact-string, and the core steps of verifier.py emit
        # LOWERCASE codes while the optional FileIntegrityManySmall plugin
        # emits the uppercase spelling. So "BAD_FILE_SHA" -- the very first
        # example this docstring names -- was classified while the core's own
        # "bad_file_sha" was NOT, and scored as a comparator refusal. Found by
        # a fresh-context red-team pass, 2026-08-31; the set had been
        # "re-derived" the previous day without catching it.
        #
        # Enumerated by AST over every reason_code= literal in verifier.py
        # rather than hand-listed: 9 lowercase codes, of which plugin_failed is
        # above. Every one is bundle integrity, path safety, or manifest/spec
        # structure -- none is a comparator refusing a CLAIMED VALUE.
        "bad_file_sha",
        "broken_cross_ref",
        "empty_spec_sha",
        "git_resolution_error",
        "missing_spec_blob",
        "path_escape",
        "sealed_spec_offline_copy_missing",
        "spec_git_fallback_disabled",
        # Manifest coverage mismatch, the one uppercase code verifier.py emits.
        "EXTRA_FILE_NOT_IN_MANIFEST",
    }
)


@dataclass
class ElementOutcome:
    element: str
    outcome: str  # FLIPPED | SURVIVED | SKIPPED | INCONCLUSIVE
    detail: str = ""
    mutated_file: str = ""
    reason_codes: "tuple[str, ...]" = ()
    # opaque elements only: per-probe (probe, outcome) profile over the
    # DISTINCT probes actually applied (tiny files collapse positions)
    positions: "tuple[tuple[str, str], ...]" = ()
    # (code, detail) of every verdict reason observed across the element's
    # probes — assert the pilot's OWN comparator reason appears here, not
    # merely "some non-plumbing code"
    reasons: "tuple[tuple[str, str], ...]" = ()


@dataclass
class RatchetReport:
    baseline_state: str
    outcomes: "list[ElementOutcome]" = field(default_factory=list)
    # elements the declaration EXCUSED — never probed; listed so a caller
    # cannot read a short battery as a complete one
    excused: "tuple[str, ...]" = ()
    # WHICH scoring mode produced these outcomes. "deny-by-default" means the
    # caller named its comparator's codes and anything else scored
    # INCONCLUSIVE; "denylist" means an unclassified code was credited as a
    # comparator refusal. A reader cannot tell the two apart from the outcome
    # counts, so the report says which one ran.
    scoring: str = "denylist"
    comparator_codes: "tuple[str, ...]" = ()

    @property
    def survived(self) -> "list[ElementOutcome]":
        return [o for o in self.outcomes if o.outcome == "SURVIVED"]

    @property
    def flipped(self) -> "list[ElementOutcome]":
        return [o for o in self.outcomes if o.outcome == "FLIPPED"]

    @property
    def skipped(self) -> "list[ElementOutcome]":
        return [o for o in self.outcomes if o.outcome == "SKIPPED"]

    @property
    def inconclusive(self) -> "list[ElementOutcome]":
        return [o for o in self.outcomes if o.outcome == "INCONCLUSIVE"]


def classify_ratchet_outcome(
    verdict_ok: bool,
    codes: "tuple[str, ...]",
    state: "str | None" = None,
    comparator_codes: "frozenset[str] | set[str] | str" = DENYLIST_SCORING,
) -> "tuple[str, str]":
    """Score one mutated-and-re-pinned verify() result. Attribution lives HERE,
    in the tool, not in each caller's assertion (Claims-lens finding):

    * verdict still OK → SURVIVED: the coverage declaration for this field is
      FALSE, nothing bound the mutated value;
    * verdict flipped but ONLY for plumbing / could-not-conclude reasons
      (`_PLUMBING_CODES`: a bare file-sha mismatch, a manifest signature the
      `repin` hook did not re-establish, the claimset gate re-enumerating a
      changed universe, a crashed or unwired plugin) → INCONCLUSIVE: not
      evidence the field is bound;
    * verdict flipped with at least one comparator reason → FLIPPED: a
      comparator refused the mutated value.

    TWO SCORING MODES, and which one ran is recorded on the report:

    * `comparator_codes={...}` — DENY-BY-DEFAULT, the form to use. The caller
      names the codes its OWN comparator emits when it refuses a value, and a
      flip is FLIPPED only if one of those appears. Anything else is
      INCONCLUSIVE. Every one of the 13 `run_claimset_ratchet` callers in this
      repo passes it.
    * `comparator_codes=DENYLIST_SCORING` — the WEAK mode, and it must now be
      asked for BY NAME. A code that is not in `_PLUMBING_CODES` is treated as
      a comparator refusal, so any could-not-conclude code nobody has
      classified is credited as coverage. `run_claimset_ratchet` requires the
      argument outright; this function keeps the sentinel as its default only
      because it is also called directly in unit tests.
    """
    if verdict_ok:
        return "SURVIVED", (
            "mutation verified OK — the coverage declaration for this field is "
            "FALSE (nothing bound its value)"
        )
    if state == VerdictState.ERROR.value:
        # could-not-conclude (a plugin crashed on the mutated bytes, or ran
        # cleanly and could not decide) is definitionally not evidence that a
        # comparator refused the value.
        return "INCONCLUSIVE", (
            "verdict is ERROR (could not conclude) on the mutated bundle "
            f"({', '.join(codes)}) — a crash or a clean-ERROR is not a comparator "
            "refusal; fix the plugin's handling of corrupt input"
        )
    if not codes:
        # A flip with NO stated reason cannot be attributed to a comparator.
        # This used to return FLIPPED ("no codes → not plumbing-only"), which
        # is the same fail-open as crediting `plugin_failed`: absence of a
        # plumbing code is not presence of a comparator refusal.
        return "INCONCLUSIVE", (
            "verdict flipped with no reason codes — nothing attributes the "
            "flip to a comparator refusing the mutated value"
        )
    if comparator_codes != DENYLIST_SCORING:
        hit = sorted(set(codes) & set(comparator_codes))
        if not hit:
            return "INCONCLUSIVE", (
                f"verdict flipped ({', '.join(codes)}) but none of the "
                f"caller-declared comparator codes "
                f"({', '.join(sorted(comparator_codes))}) appeared — not "
                "evidence this field's VALUE was refused"
            )
        return "FLIPPED", (
            f"verdict flipped for declared comparator reason(s): {', '.join(hit)}"
        )
    if _PLUMBING_CODES.issuperset(codes):
        return "INCONCLUSIVE", (
            "verdict flipped only for plumbing reasons "
            f"({', '.join(codes)}) — no comparator refused the mutated value; "
            "supply a producer-side `repin` hook"
        )
    return "FLIPPED", f"verdict flipped for comparator reason(s): {', '.join(codes)}"


def _mutate_value(value: object) -> "tuple[object, bool]":
    """(mutated, ok). Declared, kind-fixed mutations; a kind with no safe
    value-level mutation returns ok=False (reported SKIPPED upstream)."""
    if type(value) is bool:
        return (not value), True
    if type(value) is str:
        return value + _TAMPER_STRING_SUFFIX, True
    if type(value) is int:
        return value + _TAMPER_INT_DELTA, True
    if type(value) is float:
        return value + _TAMPER_FLOAT_DELTA, True
    if value is None:
        return _TAMPER_STRING_SUFFIX, True
    return value, False  # empty containers: schema-altering, skip


def _mutate_first_cell(doc: object, path: "tuple[str, ...]") -> bool:
    """Mutate the first instance cell matching the schema-level path (array
    positions match every index). Returns True when a cell was mutated."""
    if not path:
        return False
    head, rest = path[0], path[1:]
    if head == _ARRAY_MARKER:
        if type(doc) is not list:
            return False
        for i, item in enumerate(doc):
            if rest:
                if _mutate_first_cell(item, rest):
                    return True
            else:
                mutated, ok = _mutate_value(item)
                if ok:
                    doc[i] = mutated
                    return True
        return False
    if type(doc) is not dict or head not in doc:
        return False
    if rest:
        return _mutate_first_cell(doc[head], rest)
    mutated, ok = _mutate_value(doc[head])
    if ok:
        doc[head] = mutated
        return True
    return False


def _split_element(element: str) -> "tuple[str, tuple[str, ...]]":
    """Inverse of claimset.render_element for well-formed elements."""
    if ":" not in element:
        return element, ()
    key, _, rendered = element.partition(":")
    segments: list[str] = []
    for piece in rendered.split("."):
        # array markers only ever render at the END of a piece ("records[]",
        # "[][]"); the key name (possibly empty for a leading marker) comes
        # first, then its markers, in order
        n_markers = 0
        while piece.endswith(_ARRAY_MARKER):
            piece = piece[: -len(_ARRAY_MARKER)]
            n_markers += 1
        if piece:
            segments.append(piece)
        segments.extend([_ARRAY_MARKER] * n_markers)
    return key, tuple(segments)


def write_manifest_canonical(bundle_dir: Path, manifest: dict) -> None:
    """Re-emit manifest.json in the emitter's canonical form (indent=2,
    sort_keys, trailing newline). The ONE re-emitter: `repin` hooks must use
    it too, so a check that binds manifest formatting cannot flip for a
    formatting reason the battery caused."""
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _repin_file(bundle_dir: Path, rel: str) -> None:
    """Re-pin one file's sha in manifest.files (what every producer re-pins).
    LIMIT, stated: a flip attributable to a PRODUCER-COMMITTED digest elsewhere
    in the manifest (e.g. `payload.<artifact>_sha256`) is indistinguishable
    from a comparator refusal unless the caller's `repin` hook re-pins that
    digest too — a pilot whose pack compares the bundled artifact against such
    a digest MUST supply the hook, or its battery measures the digest pin."""
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    write_manifest_canonical(bundle_dir, manifest)


def _opaque_probe_plan(length: int) -> "list[str]":
    """The distinct probes for a non-empty opaque file of this length:
    position probes whose byte index collides are collapsed (a 1-byte file
    has one position; a 2-byte file has two), truncate needs ≥ 2 bytes (a
    1-byte file would become empty, which the enumerator refuses — that is
    the gate's refusal, not a comparator's), append always applies."""
    seen: set[int] = set()
    plan: list[str] = []
    for name, idx in (("first", 0), ("middle", length // 2), ("last", length - 1)):
        if idx not in seen:
            seen.add(idx)
            plan.append(name)
    if length >= 2:
        plan.append("truncate")
    plan.append("append")
    return plan


def _mutate_opaque_bytes(raw: bytes, probe: str) -> bytes:
    """Apply one declared probe to a non-empty opaque file."""
    if probe == "truncate":
        return raw[:-1]
    if probe == "append":
        return raw + b"\x01"
    idx = {"first": 0, "middle": len(raw) // 2, "last": len(raw) - 1}[probe]
    return raw[:idx] + bytes([raw[idx] ^ 0x01]) + raw[idx + 1 :]


def _mutate_claim_file(
    bundle_dir: Path,
    rel: str,
    path: "tuple[str, ...]",
    *,
    opaque: bool = False,
    position: str = "first",
) -> bool:
    """Apply the declared mutation to one claim file inside an (already
    copied) bundle. Kind comes from the DECLARATION (`opaque`), never the
    filename; for structured files single-document vs JSONL comes from the
    bytes (`classify_kind`), never the extension — the enumerator decides by
    content, so must the instrument that tests it."""
    target = bundle_dir / rel
    raw = target.read_bytes()
    if opaque:
        if not raw:
            return False
        target.write_bytes(_mutate_opaque_bytes(raw, position))
        return True
    kind, docs = classify_kind(raw, rel)
    if kind is ClaimBytesKind.JSONL:
        for doc in docs:
            if _mutate_first_cell(doc, path) if path else False:
                target.write_bytes(
                    b"\n".join(json.dumps(d).encode("utf-8") for d in docs) + b"\n"
                )
                return True
        return False
    if kind is not ClaimBytesKind.SINGLE_JSON:
        return False
    (doc,) = docs
    if not path:
        mutated, ok = _mutate_value(doc)
        if not ok:
            return False
        target.write_text(json.dumps(mutated), encoding="utf-8")
        return True
    if _mutate_first_cell(doc, path):
        target.write_text(json.dumps(doc), encoding="utf-8")
        return True
    return False


def run_claimset_ratchet(
    bundle_dir: "str | Path",
    make_verifier: "Callable[[], BundleVerifier]",
    tmp_dir: "str | Path",
    *,
    repin: "Callable[[Path], None] | None" = None,
    comparator_codes: "frozenset[str] | set[str] | str",
) -> RatchetReport:
    """Run the per-field tamper battery against one claimset-declaring bundle.

    make_verifier: factory returning a FRESH BundleVerifier (fresh plugin
    instances) per verify run. tmp_dir: scratch directory for per-mutation
    bundle copies. repin: optional pilot hook applying producer-side
    re-signing AND re-pinning of any producer-committed artifact digest to a
    mutated copy (called AFTER the file-sha re-pin; use
    write_manifest_canonical). Without it, a pack that compares the bundled
    artifact against a manifest digest flips at that digest, and the battery
    measures the digest pin, not the comparator.

    The baseline verify must be OK (a battery over a failing bundle proves
    nothing); covered elements are derived as universe − residuals, which the
    coverage gate has already forced to equal the plugin-reported set on any
    OK verdict.
    """
    src = Path(bundle_dir)
    tmp = Path(tmp_dir)
    baseline = make_verifier().verify(src)
    report = RatchetReport(
        baseline_state=baseline.state.value,
        scoring=(
            "denylist (FAIL-OPEN on unclassified codes)"
            if comparator_codes == DENYLIST_SCORING
            else "deny-by-default"
        ),
        comparator_codes=(
            () if comparator_codes == DENYLIST_SCORING else tuple(sorted(comparator_codes))
        ),
    )
    if baseline.state is not VerdictState.OK:
        raise ClaimsetError(
            "ratchet baseline verify is not OK "
            f"({baseline.state.value}: {[r.code for r in baseline.reasons]}) — "
            "a tamper battery over a failing bundle proves nothing"
        )
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    claimset = manifest.get("claimset")
    if not claimset:
        raise ClaimsetError("bundle declares no claimset — nothing to ratchet")
    claim_files = dict(claimset.get("claim_files", {}))
    opaque_files = dict(claimset.get("opaque_claim_files", {}))
    residuals = dict(claimset.get("residuals", {}))
    universe = enumerate_claim_universe(
        src,
        bundle_id=manifest.get("bundle_id", ""),
        claim_files=claim_files,
        manifest_files=dict(manifest["files"]),
        opaque_claim_files=opaque_files,
    )
    covered = [e for e in universe["elements"] if e not in residuals]
    report.excused = tuple(e for e in universe["elements"] if e in residuals)
    if not covered:
        raise ClaimsetError(
            "every claim-field element is excused — a tamper battery over an "
            "all-withheld universe proves nothing (and the gate refuses such a "
            "declaration as the vacuity exploit)"
        )

    def _run_one(n: int, element: str, rel: str, path, *, opaque: bool, position: str):
        copy_dir = tmp / f"mut_{n}_{position}"
        if copy_dir.exists():
            shutil.rmtree(copy_dir)
        shutil.copytree(src, copy_dir)
        try:
            if not _mutate_claim_file(
                copy_dir, rel, path, opaque=opaque, position=position
            ):
                return None, ()
            _repin_file(copy_dir, rel)
            if repin is not None:
                repin(copy_dir)
            verdict = make_verifier().verify(copy_dir)
            codes = tuple(r.code for r in verdict.reasons)
            pairs = tuple((r.code, (r.detail or "")[:240]) for r in verdict.reasons)
            outcome, detail = classify_ratchet_outcome(
                verdict.state is VerdictState.OK,
                codes,
                verdict.state.value,
                comparator_codes,
            )
            return (outcome, detail), pairs
        finally:
            shutil.rmtree(copy_dir, ignore_errors=True)

    for n, element in enumerate(covered):
        key, path = _split_element(element)
        is_opaque = key in opaque_files
        rel = opaque_files[key] if is_opaque else claim_files[key]
        if not is_opaque:
            scored, pairs = _run_one(n, element, rel, path, opaque=False, position="first")
            if scored is None:
                report.outcomes.append(
                    ElementOutcome(
                        element=element,
                        outcome="SKIPPED",
                        detail=(
                            "no value-level mutation exists (empty-container "
                            "instances only) — mutating would alter the schema, "
                            "which trips the coverage gate and proves nothing "
                            "about the comparator"
                        ),
                        mutated_file=rel,
                    )
                )
                continue
            outcome, detail = scored
            report.outcomes.append(
                ElementOutcome(
                    element=element,
                    outcome=outcome,
                    detail=detail,
                    mutated_file=rel,
                    reason_codes=tuple(c for c, _ in pairs),
                    reasons=pairs,
                )
            )
            continue

        # Opaque: the fixed probe battery, ALL distinct probes must flip. Any
        # surviving probe means the file is not bound at that probe (a byte-0
        # -only flip is a magic sniff; a surviving truncate/append means
        # length is unbound); any ERROR/plumbing-only probe with none
        # surviving is inconclusive; all flipped is FLIPPED.
        profile: list[tuple[str, str]] = []
        all_pairs: list[tuple[str, str]] = []
        details: list[str] = []
        for probe in _opaque_probe_plan((src / rel).stat().st_size):
            scored, pairs = _run_one(n, element, rel, path, opaque=True, position=probe)
            if scored is None:  # empty file — the enumerator refuses these
                profile.append((probe, "SKIPPED"))
                continue
            outcome, detail = scored
            profile.append((probe, outcome))
            details.append(f"{probe}: {detail}")
            for pr in pairs:
                if pr not in all_pairs:
                    all_pairs.append(pr)
        outcomes = {o for _, o in profile}
        if outcomes == {"FLIPPED"}:
            final = "FLIPPED"
            summary = (
                f"flipped at all {len(profile)} probed mutations "
                f"({', '.join(p for p, _ in profile)}) for comparator reasons"
            )
        elif "SURVIVED" in outcomes:
            survived_at = [pos for pos, o in profile if o == "SURVIVED"]
            flipped_at = [pos for pos, o in profile if o == "FLIPPED"]
            summary = f"mutation SURVIVED at {survived_at} — the file is not bound at those probes"
            if flipped_at == ["first"]:
                summary += " (flipped only at the first byte: a format/magic sniff, not a byte comparison)"
            elif flipped_at:
                summary += f" (flipped only at {flipped_at})"
            if any(p in survived_at for p in ("truncate", "append")):
                summary += " — length is unbound"
            final = "SURVIVED"
        else:
            final, summary = "INCONCLUSIVE", (
                "no probe survived but not every probe flipped for a "
                f"comparator reason: {profile}"
            )
        report.outcomes.append(
            ElementOutcome(
                element=element,
                outcome=final,
                detail=summary + (" | " + "; ".join(details) if details else ""),
                mutated_file=rel,
                reason_codes=tuple(c for c, _ in all_pairs),
                positions=tuple(profile),
                reasons=tuple(all_pairs),
            )
        )
    return report
