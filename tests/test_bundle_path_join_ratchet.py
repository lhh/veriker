"""Every non-literal path join in the substrate is CLASSIFIED, and a new one
fails this test until it is.

WHY. The manifest-key crash class (`tests/test_manifest_key_fs_representable.py`)
was closed by INPUT axis first — NUL, lone surrogate, over-long component — and
only afterwards by FIELD axis: the two fields the red team named bypass the
chokepoint, eight more route through it, and a surrogate in one of those eight
still crashed with the first guard in place. The question that found the rest
was one grep: "which sites join a bundle-relative string onto a directory, and
which of them does the guard not cover?" This test IS that grep, run every
time, with the answer written down per site.

WHAT IT PINS. An AST census of every `X / Y` (pathlib join) under
`audit_bundle/` where `X` is a directory-like name (`*_dir`, `*_root`, `root`,
`base`, `dest`) and `Y` is NOT a string literal. Each such site carries a
disposition naming why a hostile string there cannot escape the verifier's
boundary as a crash-class ERROR:

  CHOKEPOINT       — `_safe_bundle_path` itself; runs `assert_fs_representable`
                     before it resolves.
  MANIFEST_KEY     — the joined string is a `files`/`spec_files` KEY, already
                     refused at the parse boundary.
  VERIFIER_CONST   — the joined string is a verifier-side constant, not
                     producer input.
  DISK_WALK        — the string came from `os.walk` over the sealed snapshot,
                     so it already names an existing on-disk object.
  PLUGIN_BOUNDARY  — inside a typed-check plugin or reference pack; a raise
                     is caught by `_step_typed_check_plugins` and reported as
                     the plugin having failed (a REJECT-class outcome), never
                     as VERIFIER_INTERNAL_ERROR.
  DISPATCH_PRIMITIVE — inside a re-derivation primitive; a raise is classified
                     by dispatch as "the checker crashed, it did not compare"
                     (`RE_DERIVATION_NOT_COMPARED` on that leg), never as a
                     crash-class ERROR over the whole verdict.
  AUDITOR_INPUT    — the string is auditor-supplied (a pinned spec input),
                     not the producer's.
  PRODUCER_TOOLING — emitter-side code that writes bundles; not on the verify
                     path at all.
  STORE_INTERNAL   — a content-addressed store keyed by a CID the store
                     itself minted.

The dispositions are CLAIMS about where a raise is contained, written down so
they can be falsified one at a time; the ones the manifest-key battery has
measured are the chokepoint and the manifest-carried fields. A site whose
disposition turns out to be wrong is fixed by moving the site behind the
chokepoint, not by relabelling it.

Sites are keyed by (file, enclosing function, join expression) — never by
line number, which drifts under every edit above it.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_SUBSTRATE = _PKG_ROOT / "audit_bundle"

_DIR_LIKE_NAMES = {"root", "base", "dest"}

# (relative file, enclosing function, unparsed join) -> disposition
_CLASSIFIED: dict[tuple[str, str, str], str] = {
    ("append_only_floor.py", "check_append_only_floor", "bundle_dir / path"): (
        "PLUGIN_BOUNDARY"
    ),
    ("bundle_manifest.py", "_safe_bundle_path", "bundle_dir / rel_path"): "CHOKEPOINT",
    ("claimset.py", "enumerate_claim_universe", "base / rel"): "MANIFEST_KEY",
    ("emitter/pipeline.py", "_write_file", "out_dir / rel_path"): "PRODUCER_TOOLING",
    ("extensions/c9_1_append_only_files.py", "check", "bundle_dir / rel_path"): (
        "PLUGIN_BOUNDARY"
    ),
    ("plugins/monotone_growth.py", "_resolve_corpus_path", "base / version"): (
        "PLUGIN_BOUNDARY"
    ),
    ("plugins/reference/AgentDryRunCheck.py", "check", "bundle_dir / rel"): (
        "VERIFIER_CONST"
    ),
    (
        "plugins/reference/agent_dry_run_pack.py",
        "compare",
        "bundle_dir / VERDICTS_REL",
    ): ("VERIFIER_CONST"),
    (
        "plugins/reference/agent_dry_run_pack.py",
        "compare",
        "bundle_dir / AGGREGATE_REL",
    ): ("VERIFIER_CONST"),
    (
        "plugins/reference/agent_dry_run_pack.py",
        "compare",
        "bundle_dir / COVERAGE_REL",
    ): ("VERIFIER_CONST"),
    (
        "plugins/reference/agent_dry_run_pack.py",
        "rederive",
        "bundle_dir / COVERAGE_REL",
    ): ("VERIFIER_CONST"),
    ("plugins/reference/aigov_rederivation.py", "_resolve_within", "root / rel"): (
        "PLUGIN_BOUNDARY"
    ),
    ("plugins/reference/control_rederivation.py", "_resolve_within", "root / rel"): (
        "PLUGIN_BOUNDARY"
    ),
    ("plugins/reference/span_re_derivation.py", "_resolve_within", "root / rel"): (
        "PLUGIN_BOUNDARY"
    ),
    (
        "rederivation/coverage_trigger.py",
        "outputs_dir",
        "bundle_dir / OUTPUTS_DIRNAME",
    ): ("VERIFIER_CONST"),
    ("rederivation/dispatch.py", "run_spec_pinned_dispatch", "bundle_dir / rel"): (
        "AUDITOR_INPUT"
    ),
    ("rederivation/primitives/_safepath.py", "resolve_within", "root / rel"): (
        "DISPATCH_PRIMITIVE"
    ),
    (
        "rederivation/primitives/fea_witness_cert.py",
        "_load_evidence",
        "bundle_dir / rel",
    ): ("VERIFIER_CONST"),
    (
        "rederivation/spec_binding.py",
        "build_anchored_spec_set",
        "spec_dir / Path(spec_path).name",
    ): "MANIFEST_KEY",
    ("snapshot.py", "materialize_sealed_snapshot", "bundle_dir / rel"): "DISK_WALK",
    ("snapshot.py", "materialize_sealed_snapshot", "snapshot_root / rel"): "DISK_WALK",
    (
        "snapshot.py",
        "materialize_sealed_snapshot",
        "snapshot_root / os.path.relpath(norm, root_s)",
    ): "DISK_WALK",
    (
        "snapshots/snapshot_store.py",
        "_path",
        "self.root / cid.scheme",
    ): "STORE_INTERNAL",
}

_DISPOSITIONS = {
    "CHOKEPOINT",
    "MANIFEST_KEY",
    "VERIFIER_CONST",
    "DISK_WALK",
    "PLUGIN_BOUNDARY",
    "DISPATCH_PRIMITIVE",
    "AUDITOR_INPUT",
    "PRODUCER_TOOLING",
    "STORE_INTERNAL",
}


def _dir_like(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        name = node.id
    elif isinstance(node, ast.Attribute):
        name = node.attr
    else:
        return False
    return name.endswith("_dir") or name.endswith("_root") or name in _DIR_LIKE_NAMES


def census() -> set[tuple[str, str, str]]:
    """Every (file, function, join) where a directory-like name is joined
    with a non-literal right-hand side, under audit_bundle/ (tests excluded)."""
    found: set[tuple[str, str, str]] = set()
    for path in sorted(_SUBSTRATE.rglob("*.py")):
        if "tests" in path.relative_to(_SUBSTRATE).parts or path.name.startswith(
            "test_"
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        owner: dict[int, str] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(fn):
                    owner.setdefault(id(child), fn.name)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Div)
                and _dir_like(node.left)
                and not isinstance(node.right, ast.Constant)
            ):
                found.add(
                    (
                        path.relative_to(_SUBSTRATE).as_posix(),
                        owner.get(id(node), "<module>"),
                        ast.unparse(node),
                    )
                )
    return found


def test_every_join_site_is_classified() -> None:
    actual = census()
    unclassified = sorted(actual - set(_CLASSIFIED))
    assert not unclassified, (
        "NEW non-literal path join(s) in the substrate with no disposition. A "
        "hostile string reaching `Path.resolve()` / `os.stat` unguarded escapes "
        "as VERIFIER_INTERNAL_ERROR, which outranks every REJECT. Route the "
        "site through `_safe_bundle_path`, or classify it in _CLASSIFIED with "
        f"the boundary that contains a raise there: {unclassified}"
    )


def test_no_classified_site_has_gone_stale() -> None:
    actual = census()
    stale = sorted(set(_CLASSIFIED) - actual)
    assert not stale, (
        "classified join site(s) no longer exist as written — the ratchet's "
        f"denominator is drifting; remove or re-key them: {stale}"
    )


def test_every_disposition_is_from_the_closed_vocabulary() -> None:
    bad = {k: v for k, v in _CLASSIFIED.items() if v not in _DISPOSITIONS}
    assert not bad, bad


def test_the_chokepoint_is_the_one_site_that_guards_itself() -> None:
    """The disposition CHOKEPOINT is a claim about ONE function. Pin that the
    function named still calls the guard before it resolves, so relabelling
    a site CHOKEPOINT cannot substitute for routing it through one."""
    src = (_SUBSTRATE / "bundle_manifest.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_safe_bundle_path"
    )
    # ast.walk is breadth-first, not source order: compare LINE numbers.
    calls = [
        (n.lineno, ast.unparse(n.func)) for n in ast.walk(fn) if isinstance(n, ast.Call)
    ]
    guard_line = min(ln for ln, c in calls if c == "assert_fs_representable")
    first_resolve = min(ln for ln, c in calls if c.endswith(".resolve"))
    assert guard_line < first_resolve, sorted(calls)
    chokepoints = [k for k, v in _CLASSIFIED.items() if v == "CHOKEPOINT"]
    assert chokepoints == [
        ("bundle_manifest.py", "_safe_bundle_path", "bundle_dir / rel_path")
    ]
