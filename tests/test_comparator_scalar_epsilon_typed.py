"""scalar_epsilon's `epsilon` is typed, not coerced (One F U19 census §2.1.4).

Before: `float(params["epsilon"])` at load (validate_comparator_params) AND in
the comparator, so `true` loaded as a 1.0 tolerance and a numeric string as its
value (census probe F run 10: `epsilon=True` -> `cmp(10.0 vs 10.9) ok=True`).
Now an epsilon must be a JSON number -- int or float, never bool or str -- and
anything else is the same refusal as a missing epsilon: ValueError at load
(-> MalformedSpec through parse_spec), `(False, "bad/missing epsilon param")`
in the comparator. The band kinds were already typed this way; this brings the
ninth committed scalar_epsilon consumer's kind in line.
"""

from __future__ import annotations

import sys

import pytest

sys.dont_write_bytecode = True

from audit_bundle.rederivation.comparators import (  # noqa: E402
    resolve_comparator,
    validate_comparator_params,
)
from audit_bundle.rederivation.spec_binding import (  # noqa: E402
    MalformedSpec,
    parse_spec,
)

_BAD = [True, False, "1e-9", "0.5", "1", None, [1], {"v": 1}]
_GOOD = [1e-9, 0.0, 0, 1, 0.5]


def _spec(params: dict) -> dict:
    return {
        "spec_id": "eps.typed.v1",
        "types": {
            "t": {
                "primitive_id": "demo",
                "comparator": {"kind": "scalar_epsilon", "params": params},
            }
        },
    }


@pytest.mark.parametrize("eps", _BAD, ids=repr)
def test_non_number_epsilon_refused_at_load(eps):
    with pytest.raises(ValueError):
        validate_comparator_params("scalar_epsilon", {"epsilon": eps})


@pytest.mark.parametrize("eps", _BAD, ids=repr)
def test_non_number_epsilon_refused_through_parse_spec_like_a_missing_one(eps):
    """Same class as 'bad/missing epsilon param': MalformedSpec at load."""
    with pytest.raises(MalformedSpec) as missing:
        parse_spec(_spec({}), "s.json", anchored=True)
    with pytest.raises(MalformedSpec) as bad:
        parse_spec(_spec({"epsilon": eps}), "s.json", anchored=True)
    assert type(bad.value) is type(missing.value)


@pytest.mark.parametrize("eps", _BAD, ids=repr)
def test_non_number_epsilon_refused_by_the_comparator_in_isolation(eps):
    """Defence in depth: a Binding built outside the loader still cannot carry a
    bool or string tolerance into a comparison. `True` used to PASS 10.0 vs 10.9."""
    ok, detail = resolve_comparator("scalar_epsilon")(10.0, 10.9, {"epsilon": eps})
    assert ok is False, detail
    assert "bad/missing epsilon param" in detail, detail
    ok_same, detail_same = resolve_comparator("scalar_epsilon")(
        10.0, 10.0, {"epsilon": eps}
    )
    assert ok_same is False, detail_same


def test_missing_epsilon_is_the_same_refusal_in_the_comparator():
    ok, detail = resolve_comparator("scalar_epsilon")(1.0, 1.0, {})
    assert ok is False and "bad/missing epsilon param" in detail


def test_huge_int_epsilon_refused_not_crashed():
    with pytest.raises(ValueError):
        validate_comparator_params("scalar_epsilon", {"epsilon": 10**400})
    ok, detail = resolve_comparator("scalar_epsilon")(1.0, 1.0, {"epsilon": 10**400})
    assert ok is False, detail


@pytest.mark.parametrize("eps", _GOOD, ids=repr)
def test_positive_arm_number_epsilon_still_accepted(eps):
    validate_comparator_params("scalar_epsilon", {"epsilon": eps})
    _, bindings = parse_spec(_spec({"epsilon": eps}), "s.json", anchored=True)
    assert bindings["t"].comparator_params == {"epsilon": eps}
    ok, detail = resolve_comparator("scalar_epsilon")(10.0, 10.0, {"epsilon": eps})
    assert ok is True, detail
    ok, detail = resolve_comparator("scalar_epsilon")(10.0, 12.0, {"epsilon": eps})
    assert ok is False, detail
