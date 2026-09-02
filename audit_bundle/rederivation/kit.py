"""audit_bundle/rederivation/kit.py — auditor-side primitive-kit loader.

The auditor's kit for an Axis-2 bundle is the ANCHOR BYTES plus the PRIMITIVE
REGISTRATIONS. `SpecAnchor.from_files` is the blessed construction for the
first half. `load_primitive_kit` is the blessed construction for the second:
it loads auditor-held registration modules so the shipped verifier can
re-derive a bundle whose pinned spec names a primitive that is not in the
distribution registry.

TRUST CONTRACT. A kit is CODE, not data. Loading one executes it in the
verifier process with the verifier's authority, so hold it exactly like you
hold the anchor: your committed copy, reviewed, never taken from the party
under audit. This loader enforces the structural half of that contract:

  * A kit path resolving inside `forbid_within` (the bundle dir; symlinks
    followed on both sides) is REFUSED before any byte is executed. A
    primitive read out of the bundle is authored by the party it constrains,
    the primitive-shaped twin of the in-bundle anchor tautology (measured
    2026-08-17 on examples/bom_minimal: a fully forged bundle verified clean
    against its own spec copy). A caller with genuinely no bundle passes
    `forbid_within=NO_BUNDLE`, which states the refusal as INAPPLICABLE; a
    directory that does not exist is refused rather than trivially satisfied.
  * The ENTRY bytes are read ONCE, sha256-recorded, and compiled FROM THOSE
    BYTES. The `kit_modules[].sha256` on the face is the hash of the entry
    code that was compiled, with no read-then-reread window. (The
    per-primitive `primitive_provenance.sha256` is a SEPARATE, later read of
    the recompute code object's source file at dispatch: it attests the
    resolved primitive's source, which for a thin entry that imports a
    sibling is the sibling, not this entry. Two different attestations on
    purpose: entry-load integrity vs. which-code-recomputed.)
  * A kit entry module whose execution registers NO new primitive is refused
    (anti-vacuity): a silent no-op kit reads as protection while providing
    none. List independent entry modules; a module that only re-imports what
    an earlier one registered is an operator error, not a kit.
  * Loading the same `(resolved path, sha256)` again in one process is a
    cached no-op (idempotent); the same path with DIFFERENT bytes is refused
    rather than silently re-executed over live registrations.

What it cannot enforce, stated plainly: the loader attests the ENTRY file's
bytes; a sibling module the entry file imports is attested per-primitive
instead (the registry derives each RESOLVED primitive's `{origin, source,
sha256}` from the instance at dispatch, see `registry.derive_provenance`),
and any RESOLVED primitive whose source resolves inside the bundle is
refused during dispatch (`PRIMITIVE_SOURCE_INSIDE_BUNDLE`). A library caller
can still bypass this loader and `register_primitive(...)` arbitrary code: a
kit is operator-trusted code, held like the anchor. The face makes an
external source legible (`origin: "external"` / the in-bundle refusal); it
does not vet the code.

The CLI kit, one tool that holds the method and applies it to whatever the
producer built, is the RESOLVED architecture for method distribution
(decided 2026-08-28). A pilot's own `verify.py` loading its own kit remains a
convenience over the SAME registration path, not a second mechanism.

This loader is a `compile()`/`exec()` surface in the shipped verifier.
Stdlib-only. Imported lazily by the CLI (only when `--primitives` or `--kit`
is given) so the default verify path's import closure is unchanged.
"""

from __future__ import annotations

import ast
import hashlib
import sys
import types
from pathlib import Path
from typing import Sequence

from .registry import _ensure_primitives_loaded, registered_primitives


class KitConstructionError(Exception):
    """`load_primitive_kit` was given an unusable kit module: missing,
    unreadable, resolving inside the directory the kit is meant to judge,
    raising during load, registering nothing, or carrying a malformed `KIT_*`
    manifest declaration. This is an OPERATOR error, not a bundle property.
    No verdict about any bundle was formed when this fires, so CLI callers
    map it to exit 2 (could not conclude), never exit 1."""


class _NoBundle:
    """Sentinel for `forbid_within`: THERE IS NO BUNDLE HERE, so the in-bundle
    containment refusal is INAPPLICABLE. That is stated as such, never
    accidentally satisfied.

    The refusal `load_primitive_kit` enforces is that a kit must not be read
    out of the bundle it audits. `veriker --kit` inspects a kit with no
    bundle in the picture at all, so there is no directory for the kit to be
    inside. A spike reached that state by handing the check
    `"/nonexistent/no-bundle"`, against which nothing can be inside; a
    caller with no bundle must instead SAY SO, by identity, so the row
    records the refusal as INAPPLICABLE rather than as satisfied.

    WHAT THE EXISTENCE REFUSAL BELOW DOES AND DOES NOT BUY, stated plainly
    because the first version of this docstring overclaimed it. Refusing a
    `forbid_within` that is not an existing directory closes the ACCIDENTAL
    case (a typo, a stale path, that spike literal) and forces a caller with
    no bundle to be explicit. It does NOT make the containment check
    substantive. The property that matters is that `forbid_within` IS THE
    BUNDLE UNDER AUDIT, and no check inside this loader can establish that:
    any existing directory that does not contain the kit passes.
    `containment: "checked"` on the row therefore means exactly "the kit
    path was compared against `containment_root` and is not inside it",
    nothing more. Supplying the right root is the CALLER's obligation. The
    CLI discharges it by passing the resolved `--bundle-dir` it is about to
    verify."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug affordance
        return "NO_BUNDLE"


NO_BUNDLE = _NoBundle()


# resolved path -> (sha256, row) for kits already executed in this process.
# Re-executing a kit file re-creates its classes as NEW objects, which
# `register_primitive` correctly rejects as a conflicting re-registration.
# Idempotence lives here, keyed on the exact bytes that ran.
_LOADED_KITS: dict[str, tuple[str, dict]] = {}

# primitive_id -> the kit row fragment describing the kit that registered it
# WITHOUT declaring it. Read at dispatch (see `undeclared_kit_registration`),
# which is the only place that knows whether a pinned spec actually binds
# the id.
#
# LIFETIME, stated: process-global and never cleared, on purpose. It
# describes the process-global primitive registry, which is also never
# cleared, so an entry stays true for exactly as long as the registration it
# describes does. The consequence in a long-lived process (a harness, a
# pilot `verify.py` verifying several bundles in one run) is that ONE
# undeclared registration makes every later bundle binding that id refuse,
# for the life of the process. That is the correct reading: the id really is
# registered, by a kit that really did not declare it. But it is a property
# worth knowing before embedding this loader in a long-running service. It
# is also what makes the `_LOADED_KITS` cache-hit path correct without
# re-seeding: a cache hit means the code already ran in THIS process, so the
# entry it made is still here.
_UNDECLARED_BY_KIT: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Kit manifest: a kit says WHAT IT ADDS, and the loader checks the claim
# ---------------------------------------------------------------------------
#
# Declared at module level, IN the kit file:
#
#     KIT_NAME      = "acme-fea-kit"      # label, not checkable
#     KIT_VERSION   = "2"                 # label, not checkable
#     KIT_REGISTERS = ("id_a", "id_b")    # CLAIM, compared against reality
#
# In the file, not a sidecar. A sidecar can drift from the code it
# describes, while a declaration parsed out of the same bytes that get
# hashed and compiled is the one a reviewer reads. Nothing constrains HOW a
# kit registers: a kit may register a family in a loop; only the declared
# SET must equal the actual SET, in BOTH directions.
#
# LEGIBILITY, NOT SECURITY. Loading a kit executes arbitrary code with the
# verifier's authority (the trust contract above is unchanged by any of
# this), so a hostile kit can declare one set and register another; a
# static read cannot stop that and does not try. What it catches is MISTAKE
# and DRIFT between a kit's stated contents and its actual ones. Felt et
# al., "Android Permissions Demystified" (CCS 2011), measured roughly a
# third of 940 applications declaring permissions they never used, from
# developers actively trying to get it right. That is the error class this
# addresses.
#
# A kit with NO manifest still loads: the row records `manifest: absent`,
# exactly as an outside primitive today carries a null tier rather than a
# guess.
#
# Two fields an early design proposed are deliberately ABSENT:
#   * "spec types served": a kit cannot know which spec types will bind its
#     primitives; that is the auditor's spec's business. Declaring it would
#     be an unverifiable field that reads as verifiable.
#   * "hash": `load_primitive_kit` already computes the entry's sha256 from
#     the bytes it compiles. A self-declared hash of yourself attests
#     nothing.

MANIFEST_ABSENT = "absent"
MANIFEST_UNCHECKED = "unchecked"
MANIFEST_MATCH = "match"
MANIFEST_MISMATCH = "mismatch"

#: Registered an id its own manifest does not declare.
KIT_MANIFEST_UNDECLARED_REGISTRATION = "KIT_MANIFEST_UNDECLARED_REGISTRATION"
#: Declared an id it never registered.
KIT_MANIFEST_UNFULFILLED_DECLARATION = "KIT_MANIFEST_UNFULFILLED_DECLARATION"


#: The manifest is these three names EXACTLY, not the whole `KIT_` prefix.
#: Claiming the prefix made a kit with an ordinary `KIT_ROOT = "/opt/kits"`
#: and no manifest at all report `unchecked` with a note about labels it
#: never wrote: a false report on honest input. A near-miss `KIT_*` name is
#: still NAMED on the row when no manifest key was found, so a typo
#: (`KIT_REGISTER`) surfaces instead of reading as silence.
MANIFEST_KEYS = ("KIT_NAME", "KIT_VERSION", "KIT_REGISTERS")


def _read_kit_declarations(
    source: bytes, entry: Path
) -> tuple[dict, tuple[str, ...], tuple[str, ...]]:
    """Module-level manifest declarations, read by PARSING, never by executing.

    Returns `(readable, unreadable, near_miss)`: a manifest-key ->
    literal-value mapping; the manifest keys BOUND at module level whose
    value the parser could not read; and other `KIT_*` names bound at
    module level, kept only to name a probable typo.

    Only module-level bindings count (a `KIT_REGISTERS` set inside an `if`
    or a function is not a declaration), and a later binding supersedes an
    earlier one, which is what straight-line execution would do.

    EVERY WAY A MANIFEST KEY CAN BE BOUND IS EITHER READ OR RECORDED
    UNREADABLE, never silently skipped. Reading only single-target
    `ast.Assign` reported `manifest: absent` for `KIT_REGISTERS =
    KIT_ALIAS = (...)` (chained), `KIT_NAME, KIT_REGISTERS = ...`
    (destructuring), `KIT_REGISTERS += (...)` and `from _manifest import
    KIT_REGISTERS`: four shapes a reviewer plainly reads as a declaration,
    each of which would have opted the kit out of the comparison in
    silence. They are UNREADABLE (the row says `unchecked`, naming the
    key), which is the honest report: a declaration is there and this
    parser cannot evaluate it."""
    try:
        tree = ast.parse(source, filename=str(entry))
    except (SyntaxError, ValueError) as exc:
        # exec() would fail on these bytes too; failing here is the same
        # operator error, reached one step earlier.
        raise KitConstructionError(
            f"kit module {str(entry)!r} could not be parsed: {exc!r}"
        ) from exc

    # name -> (readable: bool, value); last module-level binding wins.
    last: dict[str, tuple[bool, object]] = {}
    near_miss: list[str] = []

    def _bind(name: str, ok: bool, value: object = None) -> None:
        if name in MANIFEST_KEYS:
            last[name] = (ok, value)
        elif name.startswith("KIT_") and name not in near_miss:
            near_miss.append(name)

    def _names(target: ast.expr) -> list[str]:
        """Every name a single assignment target binds."""
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            out: list[str] = []
            for elt in target.elts:
                out.extend(_names(elt))
            return out
        if isinstance(target, ast.Starred):
            return _names(target.value)
        return []  # attribute/subscript targets bind no module-level name

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # The only shape whose value can be evaluated for this name.
                    try:
                        _bind(target.id, True, ast.literal_eval(node.value))
                    except (
                        ValueError,
                        TypeError,
                        SyntaxError,
                        MemoryError,
                        RecursionError,
                    ):
                        # A COMPUTED value is present but not statically
                        # readable. Recording that is not the same as recording
                        # "absent": "we could not read your declaration" is the
                        # legible outcome.
                        _bind(target.id, False)
                else:
                    # Destructuring: the name is bound, but to a component this
                    # parser will not try to pick apart.
                    for name in _names(target):
                        _bind(name, False)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            # `KIT_NAME: str = "..."` is the same declaration with an
            # annotation; reading only ast.Assign would report a manifest as
            # absent because of a type hint.
            if isinstance(node.target, ast.Name):
                try:
                    _bind(node.target.id, True, ast.literal_eval(node.value))
                except (
                    ValueError,
                    TypeError,
                    SyntaxError,
                    MemoryError,
                    RecursionError,
                ):
                    _bind(node.target.id, False)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                _bind(node.target.id, False)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    continue
                _bind(alias.asname or alias.name.split(".")[0], False)

    readable = {k: v for k, (ok, v) in last.items() if ok}
    unreadable = tuple(sorted(k for k, (ok, _v) in last.items() if not ok))
    return readable, unreadable, tuple(near_miss)


def _validated_manifest(
    readable: dict, unreadable: tuple[str, ...], entry: Path
) -> dict | None:
    """Normalise the parsed `KIT_*` declarations, or None when there are none.

    Raises KitConstructionError on a manifest that is present but malformed.
    A declaration nobody can compare is worse than no declaration, because
    it still reads to a human as one."""
    if not readable and not unreadable:
        return None

    def _label(key: str) -> str | None:
        val = readable.get(key)
        if val is None:
            return None
        if not isinstance(val, str) or not val.strip():
            raise KitConstructionError(
                f"kit module {str(entry)!r} declares {key} = {val!r}; it must be "
                "a non-empty string (it is a LABEL — no format is imposed)."
            )
        return val

    name = _label("KIT_NAME")
    version = _label("KIT_VERSION")

    if "KIT_REGISTERS" not in readable:
        # Labels only (or a computed KIT_REGISTERS): a manifest is PRESENT but
        # nothing checkable was declared. Reported as `unchecked`, distinct from
        # `absent`, so a reader is never told "no manifest" about a file that
        # visibly has KIT_NAME at the top.
        return {
            "name": name,
            "version": version,
            "registers": None,
            "unreadable": list(unreadable),
        }

    registers = readable["KIT_REGISTERS"]
    if not isinstance(registers, (list, tuple)):
        raise KitConstructionError(
            f"kit module {str(entry)!r} declares KIT_REGISTERS = {registers!r}; "
            "it must be a list or tuple of primitive_id strings."
        )
    if not registers:
        raise KitConstructionError(
            f"kit module {str(entry)!r} declares an EMPTY KIT_REGISTERS. A kit "
            "that registers nothing is already refused (anti-vacuity), so an "
            "empty declaration can only ever mismatch — it is a drafting error, "
            "not a claim."
        )
    ids: list[str] = []
    for item in registers:
        if not isinstance(item, str) or not item.strip():
            raise KitConstructionError(
                f"kit module {str(entry)!r} declares KIT_REGISTERS entry "
                f"{item!r}; every entry must be a non-empty primitive_id string."
            )
        ids.append(item)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise KitConstructionError(
            f"kit module {str(entry)!r} declares KIT_REGISTERS with repeated "
            f"id(s) {dupes!r}. The declaration is a SET; a repeat is a drafting "
            "error, and silently de-duplicating it would hide the mistake."
        )
    return {
        "name": name,
        "version": version,
        "registers": sorted(set(ids)),
        "unreadable": list(unreadable),
    }


def _manifest_row_fields(
    manifest: dict | None,
    actual: tuple[str, ...],
    registered_now: frozenset[str] = frozenset(),
    near_miss: tuple[str, ...] = (),
) -> dict:
    """The manifest half of a kit row: status, declaration, and, on a
    disagreement, BOTH directions of it, each with its own reason code.

    Both directions matter and neither implies the other. An UNDECLARED
    registration means the kit added a method its manifest does not mention
    (the reviewer's list is short). An UNFULFILLED declaration means the
    manifest promises a method the kit never registered (the reviewer's
    list is long, and a spec binding that id will reach `UNKNOWN_PRIMITIVE`
    at dispatch). Checking one direction only leaves the check half-inert.

    THE DENOMINATOR, stated because it is not the obvious one: `actual` is
    what the kit ADDED, the registry set-diff across its exec, not every
    `register_primitive` call it made. Two known cases pull them apart, and
    this list is not claimed to be exhaustive (an earlier draft said
    "exactly one", which was a universal claim about a process-global
    registry and was wrong):

      * ADDED IS SHORT. Two entry kits import a SHARED sibling module, so
        the second kit's `register_primitive` is idempotent (`sys.modules`
        handed it the same class object) and adds nothing. A declaration
        naming that id reads as UNFULFILLED although nobody misdeclared.
        Still reported: silently excusing it would need "declared, and
        registered by someone else" to count as this kit's, which is the
        claim the row exists to check. But the note says which case it is,
        so the reader is not sent hunting for a primitive that is sitting
        in the registry. `registered_now` is what makes that distinction.
      * ADDED IS LONG. A kit imports a module that SELF-REGISTERS on import
        (the idiom the distribution's own primitives use, and one several
        pilot primitive modules use too). Those ids land in the set-diff
        and are attributed to the kit, so a manifest that does not name
        them reads as UNDECLARED. That is consistent with `registered[]`,
        which has always meant "what appeared in the registry across this
        kit's exec", but it is a FALSE POSITIVE against the author's
        intent, and because it seeds `_UNDECLARED_BY_KIT` it can escalate
        to a refusal if a pinned spec binds such an id. The remedy for the
        kit author is to declare what the kit brings, transitively; the
        remedy for a reader is that the row names every id it attributed.
        `_ensure_primitives_loaded()` warms only the DISTRIBUTION registry
        before the snapshot, so this case is about a kit's own imports,
        not ours."""
    if manifest is None:
        note = (
            "no manifest declared (KIT_NAME / KIT_VERSION / KIT_REGISTERS); the "
            "kit loads, and what it registered is reported from the registry, "
            "not from a claim"
        )
        if near_miss:
            # Name the near-miss rather than staying silent. `KIT_REGISTER`
            # (singular) is a typo a reader would otherwise have to spot
            # unaided, and the row would say only "absent".
            note += (
                " — but this module binds "
                + ", ".join(near_miss)
                + " at module level; the manifest keys are KIT_NAME, "
                "KIT_VERSION and KIT_REGISTERS"
            )
        return {
            "manifest": MANIFEST_ABSENT,
            "manifest_declaration": None,
            "manifest_mismatch": None,
            "manifest_reason_codes": [],
            "manifest_note": note,
        }

    declaration = {
        "name": manifest["name"],
        "version": manifest["version"],
        "registers": manifest["registers"],
        # Module-level KIT_* names whose value is not a literal, so the parser
        # could not read them. Carried rather than dropped: "we could not read
        # this declaration" is a different fact from "there was none".
        "unreadable": manifest["unreadable"],
    }
    if manifest["registers"] is None:
        note = (
            "KIT_NAME/KIT_VERSION are labels; nothing checkable was declared "
            "(KIT_REGISTERS is the claim)"
        )
        if manifest["unreadable"]:
            note += " — declared but not statically readable: " + ", ".join(
                manifest["unreadable"]
            )
        return {
            "manifest": MANIFEST_UNCHECKED,
            "manifest_declaration": declaration,
            "manifest_mismatch": None,
            "manifest_reason_codes": [],
            "manifest_note": note,
        }

    declared = set(manifest["registers"])
    registered = set(actual)
    undeclared = sorted(registered - declared)
    unfulfilled = sorted(declared - registered)
    if not undeclared and not unfulfilled:
        return {
            "manifest": MANIFEST_MATCH,
            "manifest_declaration": declaration,
            "manifest_mismatch": None,
            "manifest_reason_codes": [],
            "manifest_note": None,
        }

    codes: list[str] = []
    if undeclared:
        codes.append(KIT_MANIFEST_UNDECLARED_REGISTRATION)
    if unfulfilled:
        codes.append(KIT_MANIFEST_UNFULFILLED_DECLARATION)
    parts = []
    if undeclared:
        parts.append("registered but NOT declared: " + ", ".join(undeclared))
    if unfulfilled:
        elsewhere = [pid for pid in unfulfilled if pid in registered_now]
        missing = [pid for pid in unfulfilled if pid not in registered_now]
        if missing:
            parts.append("declared but NEVER registered: " + ", ".join(missing))
        if elsewhere:
            parts.append(
                "declared but not added by THIS kit (already in the registry — "
                "an earlier kit or the distribution owns it): " + ", ".join(elsewhere)
            )
    return {
        "manifest": MANIFEST_MISMATCH,
        "manifest_declaration": declaration,
        "manifest_mismatch": {
            "undeclared": undeclared,
            "unfulfilled": unfulfilled,
        },
        "manifest_reason_codes": codes,
        "manifest_note": "; ".join(parts),
    }


def undeclared_kit_registration(primitive_id: str) -> dict | None:
    """The kit that registered `primitive_id` WITHOUT declaring it, or None.

    Read at dispatch, which is the only place that knows whether a pinned
    spec actually binds the id. A kit with no manifest makes no claim and
    therefore never appears here; only a kit that declared a
    KIT_REGISTERS set and then registered outside it does."""
    return _UNDECLARED_BY_KIT.get(primitive_id)


def load_primitive_kit(
    paths: Sequence[str | Path], *, forbid_within: str | Path | _NoBundle
) -> tuple[dict, ...]:
    """Execute auditor-side primitive registration modules; return provenance.

    Each entry in `paths` is a Python file the AUDITOR holds (e.g. a
    pilot's `auditor_kit.py`) whose import-time effect is
    `register_primitive(...)` calls, the same module-bottom idiom the
    distribution's own primitives use.

    `forbid_within` is the bundle directory the kit must not be read out
    of; it must be an EXISTING directory, or the `NO_BUNDLE` sentinel when
    there is no bundle in the picture (see `_NoBundle`). It is
    keyword-only and mandatory in both forms, so a caller cannot end up
    with the containment refusal silently unevaluated.

    Returns one row per entry module, in input order:
        {"path": <resolved str>, "sha256": <hex>, "registered": [primitive_id...],
         "containment": "checked" | "inapplicable_no_bundle",
         "containment_root": <resolved str> | None,
         "manifest": "match"|"mismatch"|"absent"|"unchecked",
         "manifest_declaration": {...} | None,
         "manifest_mismatch": {"undeclared": [...], "unfulfilled": [...]} | None,
         "manifest_reason_codes": [...], "manifest_note": str | None}
    (a cache-hit repeat load returns the row recorded when the code ran).

    A manifest DISAGREEMENT is reported, not raised: it is a fact about
    the kit that the caller decides what to do with (the CLI's `--kit`
    mode makes it the verdict; a bundle verify treats it as a disclosure
    until a pinned spec actually binds an undeclared id). A MALFORMED
    manifest is raised, because nothing can be compared against it.

    Raises KitConstructionError on any unusable input; registrations made
    before the failing entry remain in effect (process-global registry),
    which is safe because the caller treats the whole call as failed and
    concludes nothing about any bundle.
    """
    if not paths:
        raise KitConstructionError(
            "load_primitive_kit requires at least one kit module path — an "
            "empty kit registers nothing and would vacuously 'succeed'."
        )
    if forbid_within is NO_BUNDLE:
        # STATED inapplicable, not accidentally satisfied. See _NoBundle.
        forbid_root = None
    else:
        try:
            forbid_root = Path(forbid_within).resolve()
        except OSError as exc:
            raise KitConstructionError(
                f"forbid_within {str(forbid_within)!r} could not be resolved: {exc}"
            ) from exc
        if not forbid_root.is_dir():
            raise KitConstructionError(
                f"forbid_within {str(forbid_within)!r} resolves to "
                f"{str(forbid_root)!r}, which is not an existing directory. A "
                "containment check against a directory that is not there can "
                "only succeed, so it is refused as an operator error (a typo, a "
                "stale path, or a placeholder standing in for 'no bundle'). If "
                "there is genuinely no bundle, pass forbid_within=NO_BUNDLE, "
                "which records the refusal as INAPPLICABLE rather than as "
                "satisfied. NOTE: passing an existing directory does NOT by "
                "itself make the check substantive — it must be the bundle "
                "under audit, which only the caller can know."
            )

    # Warm the distribution registry BEFORE snapshotting, so `new` below is
    # what the kit genuinely ADDS. Without this, the snapshot is cold and a
    # kit that merely does `import audit_bundle.rederivation.primitives`
    # (or subclasses a distribution primitive, warming the registry as a
    # side effect) triggers ~all distribution self-registrations DURING its
    # exec, and the set-diff attributes every one of them to the kit: a
    # false face on honest input, and a camouflage channel that also
    # defeats the anti-vacuity check.
    _ensure_primitives_loaded()

    # "checked" means exactly: the kit path was compared against
    # `containment_root` and is not inside it. It does NOT assert that
    # `containment_root` is the bundle under audit; nothing in this loader
    # can establish that, and any existing directory not containing the kit
    # passes. Supplying the right root is the CALLER's obligation (the CLI
    # passes the resolved --bundle-dir it is about to verify). The root
    # travels on the row so a reader can see WHAT was checked rather than
    # trusting the word.
    containment = "inapplicable_no_bundle" if forbid_root is None else "checked"
    containment_root = None if forbid_root is None else str(forbid_root)

    rows: list[dict] = []
    for raw in paths:
        try:
            entry = Path(raw).resolve(strict=True)
        except OSError as exc:
            raise KitConstructionError(
                f"kit module {str(raw)!r} could not be resolved: {exc}"
            ) from exc
        if forbid_root is not None and entry.is_relative_to(forbid_root):
            raise KitConstructionError(
                f"kit module {str(raw)!r} resolves to {str(entry)!r}, INSIDE "
                f"the bundle directory {str(forbid_root)!r}. A primitive read "
                "out of the bundle is authored by the party it constrains — "
                "recompute-and-compare against it is a tautology. Point "
                "--primitives at YOUR committed copy of the kit."
            )
        try:
            source = entry.read_bytes()
        except OSError as exc:
            raise KitConstructionError(
                f"kit module {str(entry)!r} could not be read: {exc}"
            ) from exc
        sha = hashlib.sha256(source).hexdigest()

        cached = _LOADED_KITS.get(str(entry))
        if cached is not None:
            cached_sha, cached_row = cached
            if cached_sha != sha:
                raise KitConstructionError(
                    f"kit module {str(entry)!r} was already loaded in this "
                    f"process with different bytes (sha256 {cached_sha} vs "
                    f"{sha}). Refusing to silently re-execute changed kit code "
                    "over live registrations — run in a fresh process."
                )
            rows.append(dict(cached_row))
            continue

        # The manifest is read from the SAME bytes that are hashed above and
        # compiled below, BEFORE any of them execute. A declaration read out
        # of a separate later read could describe a different file.
        readable, unreadable, near_miss = _read_kit_declarations(source, entry)
        manifest = _validated_manifest(readable, unreadable, entry)

        before = registered_primitives()
        mod_name = f"audit_bundle_kit_{sha[:16]}"
        mod = types.ModuleType(mod_name)
        mod.__file__ = str(entry)
        parent = str(entry.parent)
        if parent not in sys.path:
            # A kit imports its pilot-dir siblings (its recompute module);
            # the dir is prepended so those imports, including any deferred
            # to recompute time, resolve. RESIDUAL, stated: this is a
            # FRONT-of-path insertion that persists for the process and is
            # NOT restored, so a kit's dir can shadow later top-level
            # imports. Not restored because a primitive may import a
            # sibling lazily during recompute (after this function
            # returns); a try/finally restore would break that. The
            # shipped verifier is offline and single-shot, which bounds
            # the blast radius, but this is a posture note, not a
            # non-issue.
            sys.path.insert(0, parent)
        sys.modules[mod_name] = mod
        try:
            exec(compile(source, str(entry), "exec"), mod.__dict__)
        except BaseException as exc:  # noqa: BLE001 - any kit error is fail-closed
            # BaseException, not Exception: a kit that calls sys.exit() (or
            # transitively imports a module that does, a common
            # `except ImportError: sys.exit("install X")` idiom) raises
            # SystemExit, which is NOT an Exception. Letting it through
            # here would propagate past the CLI's SystemExit re-raise and
            # terminate the tool at exit 0, the machine-readable GREEN,
            # having verified nothing and written no verdict. A kit that
            # exits is a broken kit, which is an operator error
            # (could-not-conclude), never a pass.
            sys.modules.pop(mod_name, None)
            raise KitConstructionError(
                f"kit module {str(entry)!r} raised during load: {exc!r}"
            ) from exc
        new = tuple(sorted(registered_primitives() - before))
        if not new:
            raise KitConstructionError(
                f"kit module {str(entry)!r} executed but registered no new "
                "primitive — a kit that registers nothing is a silent no-op "
                "that reads as protection. If its primitives were registered "
                "by an earlier entry module, drop this one from the list."
            )
        row = {
            "path": str(entry),
            "sha256": sha,
            "registered": list(new),
            "containment": containment,
            "containment_root": containment_root,
        }
        row.update(
            _manifest_row_fields(manifest, new, registered_primitives(), near_miss)
        )
        for pid in (row["manifest_mismatch"] or {}).get("undeclared", ()):
            _UNDECLARED_BY_KIT[pid] = {
                "kit_path": row["path"],
                "kit_sha256": sha,
                "kit_name": row["manifest_declaration"]["name"],
                "kit_version": row["manifest_declaration"]["version"],
                "declared": list(row["manifest_declaration"]["registers"] or ()),
            }
        _LOADED_KITS[str(entry)] = (sha, dict(row))
        rows.append(row)
    return tuple(rows)
