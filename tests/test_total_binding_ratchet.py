"""Advisory total-binding ratchet over the shipped verifier surfaces
(ADR-substrate-total-binding D6): audit_bundle/**, the pilots'
_build_bundle.py producers and in-bundle *_re_derivation.py packs, and cli/.

Flags the hand-subset smell — a digest/canon sink fed a dict-projection of
>=2 reads off one base object, or equality between two such projections —
and compares the occurrence set EXACTLY (both directions) against the
reviewed waiver list. A new smell fails; a stale waiver fails; growth is a
visible reviewed diff to this one constant. Author-mistake tooling, not an
enforcement boundary (documented evasions: tuple projections, manual update
loops, cross-function flows); the enforcement rank for a verifier is the
probe battery in audit_bundle._total_binding.probe_check plus planted
violations in its own suite.
"""

from __future__ import annotations

from pathlib import Path

from audit_bundle import _total_binding as tb

PKG_ROOT = Path(__file__).resolve().parents[1]

# (file, function, normalized-statement sha, AST location path) -> reviewed
# justification. Empty as of 2026-07-18: the initial scan over the scoped
# surfaces flagged nothing. Every future entry needs a justification that
# names why the projection is NOT a hand-subset of a universal property.
ALLOWLIST: dict = {}


def _scan() -> list:
    roots: list[Path] = []
    roots += sorted((PKG_ROOT / "audit_bundle").rglob("*.py"))
    roots += sorted((PKG_ROOT / "examples").glob("*/_build_bundle.py"))
    roots += sorted((PKG_ROOT / "examples").glob("*/*_re_derivation.py"))
    roots += sorted((PKG_ROOT / "veriker").glob("*.py"))
    hits: list = []
    for p in roots:
        if p.name == "_total_binding.py":
            continue
        try:
            hits.extend(
                tb.projection_digest_occurrences(
                    p.read_text(), str(p.relative_to(PKG_ROOT))
                )
            )
        except SyntaxError:
            continue
    return hits


def test_ratchet_shipped_surfaces():
    tb.ratchet_check(_scan(), ALLOWLIST)


def test_ratchet_scan_is_live():
    """A scan that matched nothing because it CANNOT match would make the
    ratchet vacuous — prove it fires on a planted smell."""
    planted = (
        "def bind(event):\n"
        '    return sha256({"op": event.op, "fields": event.fields})\n'
    )
    occ = tb.projection_digest_occurrences(planted, "planted.py")
    assert len(occ) == 1 and occ[0]["form"] == "sink-projection"
    try:
        tb.ratchet_check(occ, {})
    except tb.TotalBindingError as e:
        assert "NEW hand-subset smell" in str(e)
    else:  # pragma: no cover
        raise AssertionError("planted smell was not rejected")
