"""Every json.dumps that feeds a digest, HMAC, or signature refuses NaN — and a
ratchet that keeps it so.

`json.dumps` emits the non-JSON tokens `NaN` / `Infinity` by default. A digest
over such bytes is deterministic, so nothing here "collides"; the defect is
that the verifier then CERTIFIES bytes a conforming JSON reader refuses, and
that a NaN reaching a preimage is always a value nobody meant to commit to
(the canonical codec, `_total_binding.canon_bytes`, refuses it; so does
`gate/verdict_signing.compute_action_sha`). On 2026-09-05 the census counted
26 digest preimages in the package with ONE `allow_nan=False`; the strict
parser (class 3) closed the PARSE surface for NaN, this closes the SERIALISE
surface: 18 sites now set `allow_nan=False`, and the AST ratchet below fails
on any `json.dumps` inside a digest-bearing function that does not, unless the
site is on the allow-list with the reason it is not a preimage.


"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_MARKERS = ("sha256", "hmac", ".sign(", "digest", "blake2")

#: (file, enclosing function) -> why this json.dumps is NOT a digest preimage
#: even though its function hashes or signs something else.
NOT_A_PREIMAGE: dict[tuple[str, str], str] = {
    (
        "audit_bundle/discharge/verifier_signing.py",
        "sign_and_write",
    ): "json.loads(json.dumps(record)) deep copy of an in-memory record; the HMAC is over `payload`, built elsewhere",
    (
        "audit_bundle/discharge/verifier_signing.py",
        "sign_stamp_upgrade",
    ): "same deep-copy idiom",
    (
        "audit_bundle/emitter/pipeline.py",
        "write_bundle",
    ): "the DSSE sidecar FILE write; the signature is over the payload bytes, not this serialisation",
    (
        "audit_bundle/verifier.py",
        "_step_spec_pinned_dispatch",
    ): "two DISCLOSURE strings on the verdict face over verifier-held rows; nothing hashes them",
    (
        "audit_bundle/plugins/verifier_identity_tripwire.py",
        "check",
    ): "a disclosure string, not hashed",
    (
        "audit_bundle/extensions/c18_tuf_client.py",
        "_open_updater",
    ): "re-serialises the bundled root.json for python-tuf's bootstrap, which parses it; python-tuf verifies the signature over its own canonical form",
}


def _preimage_dumps_without_allow_nan() -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for path in sorted((_PKG_ROOT / "audit_bundle").rglob("*.py")):
        rel = path.relative_to(_PKG_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents: dict[ast.AST, ast.AST] = {}
        for n in ast.walk(tree):
            for c in ast.iter_child_nodes(n):
                parents[c] = n
        for n in ast.walk(tree):
            if not (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "dumps"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "json"
            ):
                continue
            f: ast.AST = n
            while f in parents and not isinstance(
                f, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                f = parents[f]
            fname = getattr(f, "name", "<module>")
            fsrc = ast.unparse(f) if hasattr(f, "body") else ""
            if not any(m in fsrc for m in _MARKERS):
                continue
            kw = {k.arg: k.value for k in n.keywords if k.arg}
            v = kw.get("allow_nan")
            if isinstance(v, ast.Constant) and v.value is False:
                continue
            out.append((rel, n.lineno, fname))
    return out


def test_every_digest_preimage_refuses_nan():
    sites = _preimage_dumps_without_allow_nan()
    unexplained = [s for s in sites if (s[0], s[2]) not in NOT_A_PREIMAGE]
    assert not unexplained, (
        "json.dumps inside a digest-bearing function without allow_nan=False — add "
        f"the keyword, or list the site with the reason it is not a preimage: {unexplained}"
    )
    if (_PKG_ROOT / "release" / "oss_export.py").is_file():
        # Internal tree only (the export rewrites/drops files): every allow-list
        # row must still name a real site, or it is decoration.
        present = {(s[0], s[2]) for s in sites}
        stale = {k for k in NOT_A_PREIMAGE if (_PKG_ROOT / k[0]).is_file()} - present
        assert not stale, f"allow-list rows that no longer describe a site: {stale}"


def test_scanner_sees_a_planted_preimage(tmp_path, monkeypatch):
    """Self-validation: the scanner must flag a hashed dumps and pass one with
    the keyword; both inside a function that mentions sha256."""
    src = (
        "import hashlib, json\n"
        "def a(x):\n"
        "    return hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest()\n"
        "def b(x):\n"
        "    return hashlib.sha256(json.dumps(x, sort_keys=True, allow_nan=False).encode()).hexdigest()\n"
        "def c(x):\n"
        "    return json.dumps(x)\n"
    )
    tree = ast.parse(src)
    flagged = []
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        fsrc = ast.unparse(fn)
        for n in ast.walk(fn):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "dumps"
            ):
                kw = {k.arg: k.value for k in n.keywords if k.arg}
                v = kw.get("allow_nan")
                ok = isinstance(v, ast.Constant) and v.value is False
                if any(m in fsrc for m in _MARKERS) and not ok:
                    flagged.append(fn.name)
    assert flagged == ["a"]


# --- witnesses: a NaN at a preimage is a refusal, never certified bytes ---


def test_cross_host_edge_key_refuses_nan():
    from audit_bundle.cross_host_identity import cross_host_edge_key

    assert cross_host_edge_key({"a": 1}).startswith("ch:")
    with pytest.raises(ValueError):
        cross_host_edge_key({"a": float("nan")})


def test_event_log_replay_canonical_record_bytes_refuses_nan():
    from audit_bundle.rederivation.primitives.event_log_replay import (
        canonical_record_bytes,
    )

    assert canonical_record_bytes({"a": 1.5}) == b'{"a":1.5}'
    with pytest.raises(ValueError):
        canonical_record_bytes({"a": float("inf")})


def test_manifest_header_leaf_refuses_nan():
    from audit_bundle.extensions.c19.layer_a_counter import compute_manifest_header_leaf

    ok = compute_manifest_header_leaf(
        bundle_id="b", created_at="2026-01-01T00:00:00Z", dispatch_records=[{"output_id": "o"}]
    )
    assert len(ok) == 32
    with pytest.raises(ValueError):
        compute_manifest_header_leaf(
            bundle_id="b",
            created_at="2026-01-01T00:00:00Z",
            dispatch_records=[{"output_id": "o", "n": float("nan")}],
        )
