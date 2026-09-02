"""D1 wiring — the ref grammar reaching spec load, the §4a.3 disjointness guard,
and dispatch. Written BEFORE the wiring (TDD).

The load-bearing case here is the ESCAPE the scoping pass found:
`_enforce_monotone_strictness` keyed on the RAW `primitive_id` string, so once
versions exist, `foo@1` and `foo@2` become different dict keys and a producer
could bind ONE primitive under two versions with NON-IDENTICAL comparators --
walking straight through the strength-substitution guard. The guard must key on
the parsed NAME.
"""

from __future__ import annotations

import pytest

from audit_bundle.rederivation.spec_binding import (
    MalformedSpec,
    MonotoneStrictnessViolation,
    parse_spec,
)

HEX64 = "a" * 64


def _spec(types: dict, spec_id: str = "d1.v1") -> dict:
    return {"spec_id": spec_id, "description": "d1 wiring fixture", "types": types}


def _t(pid: str, kind: str = "exact", params: dict | None = None) -> dict:
    body = {"primitive_id": pid, "comparator": {"kind": kind}}
    if params is not None:
        body["comparator"]["params"] = params
    return body


# ---------------------------------------------------------------------------
# Load-time parsing
# ---------------------------------------------------------------------------


def test_bare_ref_loads_unchanged():
    _, bindings = parse_spec(_spec({"t": _t("bom_recompute")}), "s.json")
    ref = bindings["t"].resolved_ref()
    assert (ref.name, ref.version, ref.digest) == ("bom_recompute", None, None)
    # the raw anchored bytes are preserved verbatim
    assert bindings["t"].primitive_id == "bom_recompute"


def test_versioned_ref_loads():
    _, bindings = parse_spec(_spec({"t": _t("bom_recompute@2")}), "s.json")
    ref = bindings["t"].resolved_ref()
    assert (ref.name, ref.version) == ("bom_recompute", "2")


def test_pinned_ref_loads():
    _, bindings = parse_spec(_spec({"t": _t(f"bom_recompute@2#{HEX64}")}), "s.json")
    ref = bindings["t"].resolved_ref()
    assert ref.digest == HEX64
    assert ref.is_pinned


@pytest.mark.parametrize(
    "bad",
    [
        "bom_recompute@",
        "bom_recompute#",
        "bom_recompute#deadbeef",
        "bom_recompute@1@2",
        f"bom_recompute#{HEX64}@1",
        "bom recompute",
    ],
)
def test_malformed_ref_refused_at_LOAD_not_dispatch(bad):
    """§4a.6 discipline: reject at load, not at dispatch. A ref that only fails
    at dispatch is a ref that can be smuggled past a spec review."""
    with pytest.raises(MalformedSpec):
        parse_spec(_spec({"t": _t(bad)}), "s.json")


# ---------------------------------------------------------------------------
# §4a.3 monotone strictness — the escape versioning would otherwise open
# ---------------------------------------------------------------------------


def test_two_versions_of_one_primitive_cannot_carry_different_comparators():
    """THE REGRESSION TEST for the scoping-pass finding. Keyed on the raw string
    this passes (two distinct keys); keyed on the parsed name it must refuse."""
    with pytest.raises(MonotoneStrictnessViolation):
        parse_spec(
            _spec(
                {
                    "strict": _t("bom_recompute@1", "exact"),
                    "weak": _t("bom_recompute@2", "set"),
                }
            ),
            "s.json",
        )


def test_bare_and_versioned_of_one_primitive_cannot_differ():
    with pytest.raises(MonotoneStrictnessViolation):
        parse_spec(
            _spec(
                {
                    "strict": _t("bom_recompute", "exact"),
                    "weak": _t("bom_recompute@2", "set"),
                }
            ),
            "s.json",
        )


def test_pin_variants_of_one_primitive_cannot_differ():
    """A digest pin is another way to write the same name -- it must not become
    a third escape hatch."""
    with pytest.raises(MonotoneStrictnessViolation):
        parse_spec(
            _spec(
                {
                    "strict": _t(f"bom_recompute#{HEX64}", "exact"),
                    "weak": _t("bom_recompute", "set"),
                }
            ),
            "s.json",
        )


def test_two_versions_with_identical_comparators_are_still_refused():
    """Refused by the REFERENCE-COHERENCE check rather than by monotone
    strictness -- the two guards are separate, and this case trips the second.

    (Renamed: this was `..._still_allowed_by_this_guard`, whose name asserted
    the opposite of its body. A reader scanning test names got the wrong
    behaviour, with the reconciliation buried in an inline comment.)"""
    with pytest.raises(MalformedSpec):
        parse_spec(
            _spec(
                {
                    "a": _t("bom_recompute@1", "exact"),
                    "b": _t("bom_recompute@2", "exact"),
                }
            ),
            "s.json",
        )


def test_same_name_same_version_is_fine():
    _, bindings = parse_spec(
        _spec({"a": _t("bom_recompute@1"), "b": _t("bom_recompute@1")}), "s.json"
    )
    assert len(bindings) == 2


def test_conflicting_versions_refused_at_load():
    """An anchored spec set that binds ONE name at two versions is unsatisfiable
    -- the registry holds exactly one instance per name, so one of the two must
    refuse at dispatch. Refuse the incoherent set at LOAD instead."""
    with pytest.raises(MalformedSpec) as exc:
        parse_spec(
            _spec({"a": _t("bom_recompute@1"), "b": _t("bom_recompute@2")}), "s.json"
        )
    assert "version" in str(exc.value).lower()


def test_conflicting_digests_refused_at_load():
    with pytest.raises(MalformedSpec):
        parse_spec(
            _spec(
                {
                    "a": _t(f"bom_recompute#{'a' * 64}"),
                    "b": _t(f"bom_recompute#{'b' * 64}"),
                }
            ),
            "s.json",
        )


def test_different_primitives_are_unaffected():
    _, bindings = parse_spec(
        _spec({"a": _t("bom_recompute@1", "exact"), "b": _t("ml_recompute@2", "set")}),
        "s.json",
    )
    assert len(bindings) == 2
