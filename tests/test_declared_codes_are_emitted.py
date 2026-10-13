"""Every reason code the verifier DECLARES must have a site that EMITS it.

Why this exists. The 2026-09-24 reason-code census (prompted by an outside
reader of the public drop) found 28 exception classes and 11 code constants
that no shipped code raised or emitted. Each check had been written twice --
a CamelCase `ManifestError` subclass "mirroring" a plugin's UPPER_SNAKE
reason code -- and only the string half was ever wired. Nothing tied the two
spellings together, so the dead half could not be noticed. `veriker/cli/verify.py`
turns a caught exception's class name into a reason code, so an unraised
class IS a code the verifier can never emit.

What counts, over the code that RUNS (`audit_bundle/` + the CLI package):
  * declared: an `Exception` subclass defined at module level, or a
    module-level UPPER_CASE name bound to an UPPER_SNAKE string literal;
  * emitted: a class is raised or constructed (`raise X`, `X(...)`), or its
    name is a string literal outside a docstring, or a subclass is emitted;
    a constant is loaded by name anywhere but its own binding, or its value
    appears as a string literal outside a docstring somewhere else.
`except X:` alone is NOT emission -- a handler for something nothing raises
is the defect this file exists to catch.

SCOPE. This catches drift in OUR code: an author declaring a code and never
wiring it. It is not an adversary control (a code assembled at runtime is
invisible to a static pass), and "emitted" means a site exists, not that the
site is reachable. The allowlist is exact in both directions: an entry that
is no longer dead, or no longer declared, fails too -- except where its file
is absent (the public drop does not ship gate/, o5/, emitter_premium/) and for
an `export-orphan`: a code whose only emitter the export removes, so it is
live here and dead in the drop. That second kind is a real defect in the
drop, listed so it stays visible rather than fixed silently.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_CODE_DIRS = ("audit_bundle", "veriker", "veriker/cli")  # internal tree / public drop
_CODE_VALUE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_TOKEN = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_BUILTIN_EXC = frozenset(
    {
        "Exception",
        "BaseException",
        "ValueError",
        "RuntimeError",
        "TypeError",
        "KeyError",
        "LookupError",
        "OSError",
        "ArithmeticError",
        "AssertionError",
    }
)

# (module path relative to the repo root, name) -> why it is declared but not emitted here.
ALLOWED_UNEMITTED: dict[tuple[str, str], str] = {
    (
        "audit_bundle/gate/chokepoint.py",
        "CapabilityNotExecuted",
    ): "caller-raised API: a rail adapter raises it to assert the effect did not occur",
    (
        "audit_bundle/verifier.py",
        "PluginFailed",
    ): "caller-raised API: a TypedCheck plugin raises it (ADR 2026-06-05 section 7)",
    (
        "audit_bundle/gate/dispatch_ledger.py",
        "RC_NOT_EXECUTED",
    ): "caller-supplied vocabulary: a RECONCILE resolution the operator passes in",
    (
        "audit_bundle/verdict.py",
        "INPUT_MALFORMED_MANIFEST",
    ): "pending D8 re-prefix (ADR section 7); manifest rejects emit malformed_manifest today",
    (
        "audit_bundle/verdict.py",
        "INPUT_MALFORMED_JSON",
    ): "pending D8 re-prefix (ADR section 7)",
    (
        "audit_bundle/verdict.py",
        "INPUT_FIELD_TYPE_MISMATCH",
    ): "pending D8 re-prefix (ADR section 7)",
    (
        "audit_bundle/verdict.py",
        "INPUT_MALFORMED_ASSEMBLY",
    ): "export-orphan: emitted only by audit_bundle/o5/, which the public drop excludes",
    **{
        (
            "audit_bundle/extensions/c14v3_rigor_profile.py",
            n,
        ): "reserved: C14 v0.3 schema reservation, no plugin yet"
        for n in (
            "REASON_CODE_STAMP_TRANSITION_FORBIDDEN",
            "REASON_CODE_STAMP_PROFILE_DEPRECATED_V0_2",
            "REASON_CODE_STAMP_PROFILE_PATH_CONFLICT",
            "REASON_CODE_STAMP_TIER_INVALID",
            "REASON_CODE_STAMP_PROFILE_DIGEST_MISMATCH",
        )
    },
    **{
        (
            "audit_bundle/extensions/c17_attested_serving.py",
            n,
        ): "reserved: C17 v0.3 default-unattested tag, no emitter yet"
        for n in (
            "BUNDLE_TAG_INFERENCE_UNATTESTED",
            "BUNDLE_TAG_INFERENCE_WEIGHTS_COMPROMISABLE_RESERVED",
        )
    },
}


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for n in ast.walk(tree):
        if (
            isinstance(
                n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            and n.body
        ):
            first = n.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                ids.add(id(first.value))
    return ids


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def unemitted(root: Path, code_dirs=_CODE_DIRS) -> set[tuple[str, str]]:
    """Declared-but-never-emitted codes under `root`, as (relative path, name)."""
    files = [
        p
        for d in code_dirs
        if (root / d).is_dir()
        for p in sorted((root / d).rglob("*.py"))
    ]
    classes: dict[str, tuple[str, list[str]]] = {}
    consts: dict[str, tuple[str, str, int]] = {}
    constructed: set[str] = set()
    loads: dict[str, int] = {}
    literals: dict[str, int] = {}
    for p in files:
        rel = p.relative_to(root).as_posix()
        tree = ast.parse(p.read_text(encoding="utf-8"))
        docs = _docstring_ids(tree)
        # an `__all__` entry is an export list, not an emission (it hid the six C18 classes)
        for n in tree.body:
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and any(
                isinstance(t, ast.Name) and t.id == "__all__"
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
            ):
                docs |= {id(c) for c in ast.walk(n) if isinstance(c, ast.Constant)}
        for n in tree.body:
            if isinstance(n, ast.ClassDef):
                classes.setdefault(n.name, (rel, [b for b in map(_name, n.bases) if b]))
            elif isinstance(n, (ast.Assign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                v = n.value
                if (
                    isinstance(v, ast.Constant)
                    and isinstance(v.value, str)
                    and _CODE_VALUE.match(v.value)
                ):
                    for t in targets:
                        if isinstance(t, ast.Name) and t.id.isupper():
                            consts.setdefault(t.id, (rel, v.value, n.lineno))
        for n in ast.walk(tree):
            if isinstance(n, ast.Raise) and n.exc is not None:
                nm = _name(n.exc.func if isinstance(n.exc, ast.Call) else n.exc)
                if nm:
                    constructed.add(nm)
            elif isinstance(n, ast.Call):
                nm = _name(n.func)
                if nm:
                    constructed.add(nm)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                loads[n.id] = loads.get(n.id, 0) + 1
            elif isinstance(n, ast.Attribute):
                loads[n.attr] = loads.get(n.attr, 0) + 1
            elif (
                isinstance(n, ast.Constant)
                and isinstance(n.value, str)
                and id(n) not in docs
            ):
                for tok in set(_TOKEN.findall(n.value)) | {n.value}:
                    literals[tok] = literals.get(tok, 0) + 1

    def is_exc(name: str, seen: frozenset = frozenset()) -> bool:
        if name in _BUILTIN_EXC:
            return True
        if name not in classes or name in seen:
            return False
        return any(is_exc(b, seen | {name}) for b in classes[name][1])

    excs = {n for n in classes if is_exc(n)}
    live = {n for n in excs if n in constructed or literals.get(n, 0) > 0}
    grew = True
    while grew:
        grew = False
        for n in excs - live:
            if any(n in classes[k][1] for k in live):
                live.add(n)
                grew = True
    dead = {(classes[n][0], n) for n in excs - live}
    for n, (rel, value, _) in consts.items():
        # the binding's own value literal counts once; any further occurrence is a use
        if loads.get(n, 0) == 0 and literals.get(value, 0) <= 1:
            dead.add((rel, n))
    return dead


def test_every_declared_code_is_emitted_or_allowlisted():
    dead = unemitted(_REPO)
    new = sorted(dead - ALLOWED_UNEMITTED.keys())
    assert not new, (
        "declared but never raised/emitted by shipped code -- wire it, delete it, "
        f"or allowlist it with a reason: {new}"
    )


def test_allowlist_has_no_stale_entries():
    # Entries for files the public drop does not ship are checked only where they exist;
    # an export-orphan is live in the internal tree and dead in the drop, by construction.
    dead = unemitted(_REPO)
    stale = sorted(
        k
        for k, why in ALLOWED_UNEMITTED.items()
        if (_REPO / k[0]).is_file() and not why.startswith("export-orphan") and k not in dead
    )
    assert not stale, (
        f"allowlisted but now emitted or no longer declared -- remove: {stale}"
    )


def test_known_answer_on_a_planted_tree(tmp_path):
    pkg = tmp_path / "audit_bundle"
    pkg.mkdir()
    (pkg / "mod.py").write_text(
        '"""Module docstring naming DOCSTRING_ONLY_CODE, which must not count."""\n'
        "class Base(Exception):\n    pass\n"
        "class LiveChild(Base):\n    pass\n"
        "class DeadErr(Exception):\n    '''Mentions DeadErr in a docstring only.'''\n"
        "class RaisedErr(ValueError):\n    pass\n"
        "class NamedAsCode(Exception):\n    pass\n"
        "class CaughtOnly(Exception):\n    pass\n"
        'DEAD_CODE = "DEAD_CODE"\n'
        'USED_CODE = "USED_CODE"\n'
        'LITERAL_CODE = "LITERAL_CODE"\n'
        'DOCSTRING_ONLY_CODE = "DOCSTRING_ONLY_CODE"\n'
        "class ExportedOnly(Exception):\n    pass\n"
        '__all__ = ["ExportedOnly", "DeadErr"]\n'
        "def f(x):\n"
        "    try:\n"
        "        raise RaisedErr(USED_CODE)\n"
        "    except CaughtOnly:\n"
        "        pass\n"
        "    if x:\n"
        "        raise LiveChild()\n"
        '    return ("LITERAL_CODE", "NamedAsCode")\n',
        encoding="utf-8",
    )
    assert unemitted(tmp_path) == {
        ("audit_bundle/mod.py", "DeadErr"),
        ("audit_bundle/mod.py", "CaughtOnly"),
        ("audit_bundle/mod.py", "DEAD_CODE"),
        ("audit_bundle/mod.py", "DOCSTRING_ONLY_CODE"),
        ("audit_bundle/mod.py", "ExportedOnly"),
    }
