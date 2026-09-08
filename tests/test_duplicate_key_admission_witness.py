"""Witness for an OPEN finding: a pilot certifies bytes that parse two ways.

Measured 2026-09-04 on climate_emission_minimal. A producer emits

    {"value": 9999.99, "value": 52930.44}

for a manifest-bound output. Python's json.loads keeps the LAST duplicate, so
the verifier re-derives 52930.44 and returns PASS / exit 0. Many non-Python
JSON parsers keep the FIRST, and a human reading the certified file sees
9999.99. The sha256 in the manifest binds these bytes either way, so the
digest does not pick out a single meaning.

audit_bundle.strict_loads (hardened, exported 2026-09-04) refuses exactly this
input. 53 of the 54 pilots that hand-roll a canonicaliser parse producer JSON
with plain json.loads, so the class is fleet-wide, not local to this pilot.

The xfail below is STRICT on purpose: when a pilot adopts strict_loads this
test XPASSes and fails the suite, forcing the finding to be re-graded rather
than silently forgotten.
"""
from __future__ import annotations

import json

import pytest

import audit_bundle

DUPLICATE = b'{"value": 9999.99, "value": 52930.44}'


def test_hardened_parser_refuses_a_duplicate_object_key():
    """The guarantee we now export -- this is the available fix."""
    with pytest.raises(audit_bundle.TotalBindingError, match="duplicate object key"):
        audit_bundle.strict_loads(DUPLICATE)


def test_plain_json_loads_silently_resolves_the_ambiguity():
    """The behaviour every hand-rolled pilot canonicaliser inherits."""
    assert json.loads(DUPLICATE) == {"value": 52930.44}


@pytest.mark.xfail(
    strict=True,
    reason="OPEN 2026-09-04: pilots parse producer JSON with plain json.loads, "
           "so a bundle whose bytes carry two values for one key verifies PASS. "
           "Closing this means routing pilot reads through audit_bundle.strict_loads.",
)
def test_certified_bytes_should_have_exactly_one_meaning():
    audit_bundle.strict_loads(DUPLICATE)   # must refuse
    json.loads(DUPLICATE)                  # ...and every reader must agree
    raise AssertionError("unreachable while the finding is open")
