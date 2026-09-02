"""Drift guard + normative conformance for the vendored closed-universe
helper (audit_bundle/_closed_universe.py).

The canonical lives at
the internal design notes Guards
run on BOTH sides (the canonical suite hard-fails if this copy drifts); this
side skips the byte compare only in an installed-wheel run, where the
canonical tree does not exist and pretending to check would be theater.

The frozen digests below are computed INDEPENDENTLY in this file (plain
json+hashlib over the hand-built codec-v1 envelope) — never regenerated from
the codec under test — so a codec drift fails here even if the codec stays
self-consistent. Unlike v1's fixture, the vectors exercise the surfaces the
codec can actually drift on: a non-ASCII NFC string, a nested dict element,
and an UNSORTED input ordering (so the canonical sort path does real work);
the independent sort key uses ensure_ascii=False to match canon_bytes, which
v1's did not.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle import _closed_universe as cu

def _canonical_path() -> Path | None:
    """The canonical's location in the internal design notes tree, or None when this file
    sits too shallow for that tree to exist (an exported / installed-wheel
    tree). Computed lazily: indexing ``parents[4]`` at import time raised
    IndexError in the OSS export's collection gate, which turned the
    documented skip into a collection error."""
    parents = Path(__file__).resolve().parents
    if len(parents) <= 4:
        return None
    return (
        parents[4]
        / "the internal design notes"
        / "architecture"
        / "trinity"
        / "paired_events_ref"
        / "closed_universe.py"
    )


_CANONICAL = _canonical_path()
_VENDORED = Path(__file__).resolve().parents[1] / "audit_bundle" / "_closed_universe.py"


def test_vendored_copy_is_byte_identical_to_canonical():
    if _CANONICAL is None or not _CANONICAL.exists():
        pytest.skip("canonical not present (installed-wheel run)")
    assert _VENDORED.read_bytes() == _CANONICAL.read_bytes(), (
        "vendored _closed_universe.py drifted from the canonical — re-vendor "
        "deliberately, never patch the copy in place"
    )


# ---------------------------------------------------------------------------
# Frozen vector — independently computed, exercising sort/unicode/nesting
# ---------------------------------------------------------------------------

# deliberately UNSORTED input; includes a non-ASCII NFC string and a nested
# dict element, so canonical ordering and ensure_ascii handling both matter
_ELEMENTS_INPUT = ["zulu", {"stream": "héllo", "period": "2025-01"}, "alpha"]
_DOMAIN = "conformance:demo"
_REASONS_INPUT = ["z-reason", "a-reason"]
_SRC_SHA = "cd" * 32


def _canon_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _independent_universe_sha() -> str:
    elements = sorted(_ELEMENTS_INPUT, key=_canon_json)
    body = {
        "domain": _DOMAIN,
        "elements": elements,
        "n": 3,
        "provenance": "MEASURED_ENUMERATION",
        "reason_enum": sorted(_REASONS_INPUT),
        "source": "conformance fixture",
        "source_sha": _SRC_SHA,
        "version": 2,
    }
    envelope = {
        "_tb": 1,
        "domain": f"closed_universe:{_DOMAIN}",
        "excluded": [],
        "schema": None,
        "bound": body,
    }
    return hashlib.sha256(_canon_json(envelope)).hexdigest()


def _declare():
    return cu.declare_universe(
        _ELEMENTS_INPUT,
        domain=_DOMAIN,
        source="conformance fixture",
        provenance="MEASURED_ENUMERATION",
        reason_enum=_REASONS_INPUT,
        source_sha=_SRC_SHA,
    )


def test_universe_sha_matches_independent_computation():
    assert _declare()["universe_sha"] == _independent_universe_sha()


def test_element_sort_is_canonical_not_input_order():
    u = _declare()
    assert u["elements"][0] == "alpha"  # '"alpha"' < '"zulu"' < '{'
    assert u["elements"][-1] == {"stream": "héllo", "period": "2025-01"}


# ---------------------------------------------------------------------------
# Conformance smoke — accounting + anchored verification + fail-closed
# ---------------------------------------------------------------------------


def test_receipt_smoke_anchored_verify_and_coverage_row_interop():
    from audit_bundle.coverage.protocol import CoverageRow, validate_coverage_row

    u = _declare()
    from audit_bundle._total_binding import value_digest

    nested = {"stream": "héllo", "period": "2025-01"}
    covered = ["alpha", "zulu"]
    withheld = {value_digest(nested): "a-reason"}
    r = cu.build_receipt(u, covered, withheld)
    cu.verify_receipt(r, u, covered, withheld, expected_universe_sha=u["universe_sha"])
    cu.check_receipt_self_consistency(r)
    row = CoverageRow(**cu.to_coverage_row(r, "tick-0"))
    validate_coverage_row(row)  # §C4 sum invariants hold by construction
    binding = cu.coverage_row_binding(r)
    assert binding["receipt_sha"] == r["receipt_sha"]
    assert binding["source_sha"] == _SRC_SHA


def test_omission_fails_closed():
    u = _declare()
    with pytest.raises(cu.ClosedUniverseError):
        cu.build_receipt(u, ["alpha"], {})


def test_wrong_anchor_fails_closed():
    from audit_bundle._total_binding import value_digest

    u = _declare()
    nested = {"stream": "héllo", "period": "2025-01"}
    covered = ["alpha", "zulu"]
    withheld = {value_digest(nested): "a-reason"}
    r = cu.build_receipt(u, covered, withheld)
    with pytest.raises(cu.ClosedUniverseError):
        cu.verify_receipt(r, u, covered, withheld, expected_universe_sha="0" * 64)


# ---------------------------------------------------------------------------
# v3 conformance — the vendored copy's expected_reason_enum path, exercised
# HERE because this suite is independent of the canonical one: a re-vendor
# alone adds no tests (v3 claims-audit finding F1)
# ---------------------------------------------------------------------------


def test_v3_expected_reason_enum_pin_on_vendored_copy():
    """The port-3 witness shape against the VENDORED module: a widened
    committed vocabulary passes every door unpinned (same-custody anchor —
    the disclosed hole) and refuses at every door against the consumer's own
    vocabulary, including the §C4 row doors."""
    consumer_vocab = ["a-reason", "z-reason"]
    widened = cu.declare_universe(
        _ELEMENTS_INPUT,
        domain=_DOMAIN,
        source="conformance fixture",
        provenance="MEASURED_ENUMERATION",
        reason_enum=consumer_vocab + ["staged-elsewhere"],
        source_sha=_SRC_SHA,
    )
    from audit_bundle._total_binding import value_digest

    nested = {"stream": "héllo", "period": "2025-01"}
    covered = ["alpha"]
    withheld = {
        value_digest(nested): "a-reason",
        "zulu": "staged-elsewhere",  # the reason the consumer cannot count
    }
    r = cu.build_receipt(widened, covered, withheld)
    # unpinned, same-custody anchor: passes — the disclosed residual hole
    cu.verify_receipt(
        r, widened, covered, withheld,
        expected_universe_sha=widened["universe_sha"],
    )
    cu.to_coverage_row(r, "tick-0")
    # pinned with the consumer's own vocabulary: refuses at every door
    for door in (
        lambda: cu.validate_universe(
            widened, expected_reason_enum=consumer_vocab
        ),
        lambda: cu.verify_receipt(
            r, widened, covered, withheld,
            expected_universe_sha=widened["universe_sha"],
            expected_reason_enum=consumer_vocab,
        ),
        lambda: cu.check_receipt_self_consistency(
            r, expected_reason_enum=consumer_vocab
        ),
        lambda: cu.to_coverage_row(
            r, "tick-0", expected_reason_enum=consumer_vocab
        ),
        lambda: cu.coverage_row_binding(
            r, expected_reason_enum=consumer_vocab
        ),
    ):
        with pytest.raises(cu.ClosedUniverseError):
            door()
    # a bare-string expectation refuses, never char-splits
    with pytest.raises(cu.ClosedUniverseError):
        cu.validate_universe(widened, expected_reason_enum="a-reason")


# ---------------------------------------------------------------------------
# Dict elements, withheld by digest — the shape the audit-bundle WORK-SET uses
# (audit_bundle/work_set.py, 2026-09-01): elements are {"output_id", "type"}
# objects, so the withheld key is the element's value_digest, never a string.
# ---------------------------------------------------------------------------


def test_dict_elements_withheld_by_digest_and_delivered_anyway_is_surplus():
    from audit_bundle import _total_binding as tb

    elems = [{"output_id": "a", "type": "ta"}, {"output_id": "b", "type": "tb"}]
    uni = cu.declare_universe(
        elems, domain="d", source="s", provenance="SELF_AUTHORED", reason_enum=["R"]
    )
    b_digest = tb.value_digest(elems[1])
    receipt = cu.build_receipt(uni, [elems[0]], {b_digest: "R"})
    assert receipt["n_covered"] == 1 and receipt["n_withheld"] == 1
    assert receipt["withheld"][0]["element"] == elems[1]
    cu.verify_receipt(
        receipt,
        uni,
        [elems[0]],
        {b_digest: "R"},
        expected_universe_sha=uni["universe_sha"],
        expected_reason_enum=["R"],
    )
    # covering b AND withholding it is a double-count; covering both with b
    # withheld is a surplus. Both refuse.
    with pytest.raises(cu.ClosedUniverseError):
        cu.build_receipt(uni, elems, {b_digest: "R"})
    # a string key naming a dict element matches nothing
    with pytest.raises(cu.ClosedUniverseError, match="matches no universe element"):
        cu.build_receipt(uni, [elems[0]], {"b": "R"})


def test_provenance_source_sha_pairings_are_enforced():
    with pytest.raises(cu.ClosedUniverseError, match="SELF_AUTHORED"):
        cu.declare_universe(
            ["a"],
            domain="d",
            source="s",
            provenance="SELF_AUTHORED",
            reason_enum=["R"],
            source_sha="0" * 64,
        )
    with pytest.raises(cu.ClosedUniverseError, match="requires source_sha"):
        cu.declare_universe(
            ["a"],
            domain="d",
            source="s",
            provenance="EXTERNAL_STRUCTURE",
            reason_enum=["R"],
        )
    uni = cu.declare_universe(
        ["a"],
        domain="d",
        source="s",
        provenance="EXTERNAL_STRUCTURE",
        reason_enum=["R"],
        source_sha="0" * 64,
    )
    assert uni["provenance"] == "EXTERNAL_STRUCTURE" and uni["source_sha"] == "0" * 64


def test_a_mutated_universe_no_longer_verifies_under_its_held_sha():
    """What the work-set leans on at every use: the held sha is the
    pre-commitment, and a document edited after it is refused."""
    uni = cu.declare_universe(
        ["a", "b"],
        domain="d",
        source="s",
        provenance="SELF_AUTHORED",
        reason_enum=["R"],
    )
    held = uni["universe_sha"]
    receipt = cu.build_receipt(uni, ["a", "b"], {})
    uni["source"] = "edited"
    with pytest.raises(cu.ClosedUniverseError, match="re-derive its own universe_sha"):
        cu.verify_receipt(receipt, uni, ["a", "b"], {}, expected_universe_sha=held)
