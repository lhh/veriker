"""One containment rule for producer-named paths — and the ratchet that keeps it one.

Before 2026-09-05 "this path stays inside this root and points at something a
blocking read can open" was written five ways in the package (plus three copies
in the standalone packs). Only `bundle_manifest._safe_bundle_path` carried the
object-type half (a FIFO or directory at a producer-named path hangs or crashes
a blocking read BEFORE any verdict); `_safepath.resolve_within`, two dispatch
sites and the emitter's write side carried containment only. Four tests here:

1. the contract of `audit_bundle._containment.contain`, over a real tmp tree
   (escape by `..`, absolute, symlink-out; NUL; directory; FIFO; contained
   symlink to a regular file; absence passes through);
2. behavioural parity between the substrate rule and the standalone packs'
   hand copy (`control_rederivation._resolve_within`, pinned across packs by
   test_reference_pack_parity): same refuse/accept verdict per vector;
3. a witness per rewired site through its own entry point;
4. a source ratchet: every `resolve()`+`relative_to(` containment idiom in
   `audit_bundle/` is the single source, a pinned pack copy, or on the frozen
   allow-list with the reason it is not a containment check.


"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle._containment import ContainmentError, contain  # noqa: E402


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "bundle"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "ok.json").write_bytes(b"{}")
    (root / "adir").mkdir()
    os.mkfifo(root / "fifo")
    (root / "link_in").symlink_to(root / "sub" / "ok.json")
    (root / "link_dir").symlink_to(root / "adir")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    (root / "link_out").symlink_to(outside)
    return root


# ---------------------------------------------------------------------------
# 1 — the contract
# ---------------------------------------------------------------------------

ACCEPT = ["sub/ok.json", "link_in", "sub/missing.json", "missing_dir/x.json"]
REFUSE = {
    "../outside.txt": "escape",
    "sub/../../outside.txt": "escape",
    "link_out": "escape",
    "sub/ok.json\x00": "unrepresentable",
    "adir": "not_regular",
    "link_dir": "not_regular",
    "fifo": "not_regular",
    "sub": "not_regular",
}


@pytest.mark.parametrize("rel", ACCEPT)
def test_accepts(tree: Path, rel: str):
    got = contain(tree, rel)
    assert got == (tree / rel).resolve()


def test_absolute_rel_is_an_escape(tree: Path, tmp_path: Path):
    with pytest.raises(ContainmentError) as ei:
        contain(tree, str(tmp_path / "outside.txt"))
    assert ei.value.reason == "escape"
    # an absolute path INSIDE the root is still refused as-built? No: it resolves
    # under the root, so containment holds — the rule is about where it lands.
    assert (
        contain(tree, str(tree / "sub" / "ok.json"))
        == (tree / "sub" / "ok.json").resolve()
    )


@pytest.mark.parametrize("rel,reason", list(REFUSE.items()), ids=list(REFUSE))
def test_refuses_with_a_reason(tree: Path, rel: str, reason: str):
    with pytest.raises(ContainmentError) as ei:
        contain(tree, rel)
    assert ei.value.reason == reason
    assert isinstance(ei.value, ValueError)


def test_writer_mode_checks_containment_only(tree: Path):
    assert contain(tree, "adir", require_regular=False) == (tree / "adir").resolve()
    assert contain(tree, "fifo", require_regular=False) == (tree / "fifo").resolve()
    with pytest.raises(ContainmentError) as ei:
        contain(tree, "../outside.txt", require_regular=False)
    assert ei.value.reason == "escape"


# ---------------------------------------------------------------------------
# 2 — parity with the standalone packs' hand copy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rel", ACCEPT + list(REFUSE))
def test_pack_copy_agrees_with_the_substrate_rule(tree: Path, rel: str):
    """The packs return None where the substrate raises; compare the verdict."""
    from audit_bundle.plugins.reference import control_rederivation as ctl

    try:
        contain(tree, rel)
        substrate = "accept"
    except ContainmentError:
        substrate = "refuse"
    pack = "accept" if ctl._resolve_within(tree, rel) is not None else "refuse"
    assert pack == substrate, (rel, pack, substrate)


# ---------------------------------------------------------------------------
# 3 — one witness per rewired site
# ---------------------------------------------------------------------------


def test_safepath_resolve_within_refuses_a_fifo_now(tree: Path):
    from audit_bundle.rederivation.primitives._safepath import resolve_within

    assert resolve_within(tree, "sub/ok.json") == (tree / "sub" / "ok.json").resolve()
    for rel in ("../outside.txt", "fifo", "adir"):
        with pytest.raises(ValueError):
            resolve_within(tree, rel)  # fifo/adir: was accepted, then a blocking read


def test_safe_bundle_path_keeps_its_vocabulary(tree: Path):
    from audit_bundle.bundle_manifest import UnsafeBundlePath, _safe_bundle_path

    assert (
        _safe_bundle_path(tree, "sub/ok.json") == (tree / "sub" / "ok.json").resolve()
    )
    assert (
        _safe_bundle_path(tree, "sub/missing.json")
        == (tree / "sub" / "missing.json").resolve()
    )
    with pytest.raises(UnsafeBundlePath, match="resolves outside bundle_dir"):
        _safe_bundle_path(tree, "../outside.txt")
    with pytest.raises(UnsafeBundlePath, match="non-regular file"):
        _safe_bundle_path(tree, "fifo")
    with pytest.raises(UnsafeBundlePath, match="directory"):
        _safe_bundle_path(tree, "adir")
    with pytest.raises(UnsafeBundlePath):
        _safe_bundle_path(tree, "sub/ok.json\x00")


def test_emitter_write_side_still_refuses_escape(tmp_path: Path):
    from audit_bundle.emitter.pipeline import _write_file
    from audit_bundle.integrity_ownership import UnsafeBundleRelPath

    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "victim").mkdir()
    (out / "esc").symlink_to(tmp_path / "victim")
    with pytest.raises(UnsafeBundleRelPath):
        _write_file(out, "esc/x.json", b"{}")
    assert not (tmp_path / "victim" / "x.json").exists()


# ---------------------------------------------------------------------------
# 4 — the source ratchet
# ---------------------------------------------------------------------------

#: Every `.relative_to(` call site in audit_bundle/ outside the single source,
#: with the reason it is not a hand-rolled containment check (or is a pinned
#: copy). A new resolve-then-relative_to guard anywhere else fails this test.
ALLOWED_RELATIVE_TO_SITES: dict[str, str] = {
    "audit_bundle/plugins/reference/control_rederivation.py": "standalone pack; _resolve_within is the family's pinned copy (test 2 above)",
    "audit_bundle/plugins/reference/aigov_rederivation.py": "standalone pack; pinned to control by test_reference_pack_parity",
    "audit_bundle/plugins/reference/span_re_derivation.py": "standalone pack; pinned to control by test_reference_pack_parity",
    "audit_bundle/conservation.py": "path ARITHMETIC inside a scandir walk the verifier drives (rel names for reporting), not a guard on a producer-named path",
    "audit_bundle/snapshot.py": "path arithmetic inside the snapshot scan (rel names), not a guard",
    "audit_bundle/snapshots/snapshot_store.py": "path arithmetic over the verifier's own content-addressed store layout",
    "audit_bundle/dsse/set_closure.py": "one rel-name computation for the closure set, and one DIRECTORY-walk escape check on entries the walk itself enumerated (not producer-named); file paths go through _safe_bundle_path",
    "audit_bundle/verifier.py": "_norm: normalises an absolute entry to a rel string for comparison; falls back on failure, guards nothing",
}
_SOURCE = "audit_bundle/_containment.py"


def _relative_to_sites() -> dict[str, int]:
    import ast

    seen: dict[str, int] = {}
    for path in sorted((_PKG_ROOT / "audit_bundle").rglob("*.py")):
        rel = path.relative_to(_PKG_ROOT).as_posix()
        tree_ = ast.parse(path.read_text(encoding="utf-8"))
        n = sum(
            1
            for node in ast.walk(tree_)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "relative_to"
        )
        if n:
            seen[rel] = n
    return seen


def test_no_sixth_containment_guard():
    seen = _relative_to_sites()
    assert _SOURCE in seen, (
        "the single source lost its relative_to — the ratchet measures nothing"
    )
    strays = {
        k: v
        for k, v in seen.items()
        if k != _SOURCE and k not in ALLOWED_RELATIVE_TO_SITES
    }
    assert not strays, (
        f"new relative_to sites — route a containment check through audit_bundle._containment or list it with its reason: {strays}"
    )
    present = {k for k in ALLOWED_RELATIVE_TO_SITES if (_PKG_ROOT / k).is_file()}
    stale = present - set(seen)
    assert not stale, (
        f"allow-list rows whose file no longer calls relative_to — delete them: {stale}"
    )
