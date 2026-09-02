"""tests/test_primitive_face.py — the tier reaches the verdict face (ADR D4).

D4 (§8b): "All 24 public built-ins ship, each carrying its tier on the face
beside its identity and provenance." This asserts the FACE, not the declaration
— `test_primitive_declarations.py` already covers whether a tier is declared;
what matters here is whether a reader of a verdict ever sees it.

WHY THE TIER IS ON THE FACE AT ALL, since a reviewer will reasonably ask whether
it earns the bytes. `climate_emission_recompute@1` and `fintech_audit_recompute@1`
are the identical SHAPE of claim about revision identity, and a reader with only
the version cannot tell that the first is a reference implementation of a
Scope-3 roll-up and the second a guard-covered general shape. The tier is what
stops a declared version from reading as standardization — it is the field that
makes the version half safe to publish, not an ornament beside it.

The declared VERSION is deliberately NOT duplicated here: it is already on the
face as `ref.version_declared`, put there by D1.

UNIVERSAL, like its sibling: no primitive count, no id list, so it holds in the
drop (24 registered) as written for the internal tree (27).
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.plugin import RecomputedValue  # noqa: E402
from audit_bundle.rederivation import dispatch as D  # noqa: E402
from audit_bundle.rederivation import registry  # noqa: E402
from audit_bundle.rederivation.dispatch import run_spec_pinned_dispatch  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402

TIERS = ("A", "B", "C")


def _dispatch(primitive_id: str, resolver=None):
    """Drive one output through dispatch and return its provenance row.

    The row is written BEFORE the comparator runs, so a value mismatch does not
    hide it — which is what makes this usable against a real primitive whose
    inputs are absent."""
    spec = {
        "spec_id": "face",
        "description": "d",
        "types": {
            "t": {
                "primitive_id": primitive_id,
                "comparator": {"kind": "exact", "params": {}},
            }
        },
    }
    raw = json.dumps(spec).encode("utf-8")
    anchor = SpecAnchor(allowed={"face": hashlib.sha256(raw).hexdigest()})

    class _M:
        spec_files = ["t.spec.json"]
        outputs = [{"output_id": "o1", "type": "t"}]

    bundle = Path(tempfile.mkdtemp()) / "bundle"
    (bundle / "spec").mkdir(parents=True)
    (bundle / "outputs").mkdir()
    (bundle / "spec" / "t.spec.json").write_bytes(raw)
    (bundle / "outputs" / "o1.json").write_text(json.dumps({"value": [1, 2, 3]}))

    prov: dict = {}
    run_spec_pinned_dispatch(bundle, _M(), anchor, primitive_provenance_out=prov)
    return prov


def _real_ids() -> list[str]:
    """Distribution primitives only. A pilot's or a kit's primitive registers
    into the same global namespace and declares no tier — by design, and its
    face row reports None, which the stub cases below cover."""
    registry._ensure_primitives_loaded()
    return sorted(registry.distribution_primitives())


def test_there_is_something_to_check() -> None:
    assert _real_ids(), "empty distribution set would make the check vacuous"


@pytest.mark.parametrize("pid", _real_ids())
def test_every_registered_primitive_puts_its_tier_on_the_face(pid: str) -> None:
    """Against the REAL registry — no stub. A stub would only prove the row
    copies whatever the fixture declared."""
    prov = _dispatch(pid)
    assert pid in prov, f"{pid} never reached the provenance seam"
    row = prov[pid]
    assert row.get("tier") in TIERS, (
        f"{pid}'s face carries tier={row.get('tier')!r}. An auditor reading this "
        "verdict cannot tell a reference implementation from a citable standard."
    )
    assert row["tier"] == getattr(registry.resolve_primitive(pid), "primitive_tier")
    assert row["self_declared_tier"] is None, (
        f"{pid} is a distribution primitive; its tier is CONFERRED, so it must "
        "never appear as a self-declaration"
    )
    # D1's half is already there and must not have been displaced.
    assert row["ref"]["version_declared"] == getattr(
        registry.resolve_primitive(pid), "primitive_version"
    )


class _NoTier:
    primitive_id = "demo"
    primitive_version = "1"

    def recompute(self, inputs, pack_section):
        return RecomputedValue(value=[1, 2, 3], detail="")


class _BogusTier(_NoTier):
    primitive_tier = "GOLD"


class _RaisingTier(_NoTier):
    @property
    def primitive_tier(self):
        raise RuntimeError("hostile descriptor")


class _OutsiderClaimingTierA(_NoTier):
    """A kit borrowing OUR top label for itself."""

    primitive_tier = "A"


def test_an_outside_primitive_cannot_wear_a_conferred_tier(monkeypatch) -> None:
    """The tier means "tier in the PUBLISHED taxonomy", and only the promotion
    process confers one — a faithfulness test against an independently written
    producer, the disjointness check, review. A kit has been through none of
    that, so `tier` must be null however loudly the kit declares "A".

    Its own assessment is not discarded, just relocated to a field that cannot
    be mistaken for our endorsement. Before this, `origin: "external"` sat two
    lines away and was the only thing distinguishing a kit's self-assessment
    from a tier we conferred."""
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: _OutsiderClaimingTierA())
    row = _dispatch("demo")["demo"]
    assert row["origin"] != "distribution"
    assert row["tier"] is None
    assert row["self_declared_tier"] == "A"


def test_a_self_declared_tier_outside_the_taxonomy_is_not_echoed(monkeypatch) -> None:
    """Reporting arbitrary author-supplied strings is the same defect with an
    extra field."""
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: _BogusTier())
    row = _dispatch("demo")["demo"]
    assert row["tier"] is None
    assert row["self_declared_tier"] is None


@pytest.mark.parametrize("stub", [_NoTier(), _BogusTier(), _RaisingTier()])
def test_an_undeclarable_tier_is_None_not_a_guess(stub, monkeypatch) -> None:
    """Three ways a tier can fail to be readable — absent, outside the published
    taxonomy, and a raising descriptor — and all three must land as None.

    `GOLD` is the one that matters: passing an unrecognised string straight
    through would let a kit mint its own tier on a verdict face, which is the
    labeling-up defect with extra steps. And the raising descriptor must not
    escape dispatch — a disclosure that throws would skip the per-output guard
    (R3, primitive_ref.py)."""
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: stub)
    prov = _dispatch("demo")
    assert prov["demo"]["tier"] is None
