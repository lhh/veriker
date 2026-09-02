"""tests/test_null_container_refused.py — explicit JSON null on a container the
manifest's own dataclass type forbids it on.

MEASURED 2026-09-02 (the null-container scoping census, kept with the internal
design record): `validate_top_level_field_shapes` short-circuits
on `val is not None`, documenting that "JSON null is treated as absent". For six
fields it is not — the null reaches a consumer that assumes a container and the
verifier RAISES, so a determinate REJECT is replaced by VERIFIER_INTERNAL_ERROR
and its reasons are discarded.

**This is a diagnosis defect, not a fail-open.** The same census found ZERO
fields where null passes while deletion rejects, and no crasher reaches exit 0 —
nothing is admitted that would otherwise be refused. These tests pin the reason,
not a security boundary.

The six are exactly the fields whose `BundleManifest` type does not admit `None`
AND that carry no documented null-means-absent contract. `dispatch_records` is
the counterexample that keeps this list hand-written rather than derived from the
type alone: it also forbids `None`, and explicit-null there is a DOCUMENTED
forward-compatible legacy marker (`test_legacy_bundle_compat.py`). Controls below
pin both directions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.bundle_manifest import (  # noqa: E402
    MalformedManifest,
    validate_top_level_field_shapes,
)

_EXAMPLE = _PKG_ROOT / "examples" / "climate_emission_minimal" / "manifest.json"

# The six. Each crashed a real consumer before this guard; the crash site is
# named so a future reader can check the guard still stands between them.
REFUSED = {
    "files": "integrity_ownership.classify_path",
    "spec_files": "integrity_ownership._spec_pinned_offline_paths",
    "cross_refs": "verifier._step_cross_refs",
    "snapshots": "integrity_ownership.classify_path",
    "fragment_anchors": "bundle_manifest._validate_manifest_deep",
    "source_attributes": "verifier._step_typed_check_plugins",
}


def _raw() -> dict:
    return json.loads(_EXAMPLE.read_text())


@pytest.mark.parametrize("field", sorted(REFUSED))
def test_explicit_null_on_a_none_forbidding_container_is_refused(field):
    raw = _raw()
    raw[field] = None
    with pytest.raises(MalformedManifest, match=f"manifest.{field}"):
        validate_top_level_field_shapes(raw)


@pytest.mark.parametrize("field", sorted(REFUSED))
def test_the_refusal_says_null_and_not_merely_wrong_type(field):
    """The reason must name the null, or it reads as the pre-existing
    wrong-container message and the reader cannot tell which rule fired."""
    raw = _raw()
    raw[field] = None
    with pytest.raises(MalformedManifest, match="(?i)null"):
        validate_top_level_field_shapes(raw)


@pytest.mark.parametrize("field", sorted(REFUSED))
def test_absent_is_still_absent(field):
    """The guard is about explicit null ONLY. Deleting the key must go on
    behaving exactly as it did — row 20's first clause is 'absent may pass',
    and this change must not quietly become a required-field gate."""
    raw = _raw()
    raw.pop(field, None)
    validate_top_level_field_shapes(raw)  # must not raise


# --- controls: the fields where null is legal, and must stay legal -----------


def test_dispatch_records_null_is_still_accepted():
    """The documented forward-compatible legacy marker. `dispatch_records` also
    forbids None by type, which is exactly why the refused set is hand-written:
    deriving it from the annotation would break this contract."""
    raw = _raw()
    raw["dispatch_records"] = None
    validate_top_level_field_shapes(raw)  # must not raise


def test_verifier_identity_null_is_still_accepted():
    """`dict | None = None` — c18 reads null as ABSENT on purpose."""
    raw = _raw()
    raw["verifier_identity"] = None
    validate_top_level_field_shapes(raw)


def test_every_none_admitting_field_still_accepts_null():
    """All 14 fields whose declared type admits None were measured null==absent
    with zero crashes. None of them may be caught by this guard."""
    import dataclasses

    from audit_bundle.bundle_manifest import (
        _TOP_LEVEL_FIELD_SHAPES,
        BundleManifest,
    )

    fields = {f.name: f for f in dataclasses.fields(BundleManifest)}
    admits = [
        n
        for n in _TOP_LEVEL_FIELD_SHAPES
        if n in fields and "None" in str(fields[n].type)
    ]
    assert len(admits) == 14, admits
    for name in admits:
        raw = _raw()
        raw[name] = None
        validate_top_level_field_shapes(raw)  # must not raise


def test_the_refused_set_is_disjoint_from_the_none_admitting_fields():
    """A ratchet on the list itself: nothing whose type admits None may ever be
    added to REFUSED, because that is the documented-legal direction."""
    import dataclasses

    from audit_bundle.bundle_manifest import BundleManifest

    fields = {f.name: f for f in dataclasses.fields(BundleManifest)}
    for name in REFUSED:
        assert "None" not in str(fields[name].type), (
            f"{name} declares a None-admitting type; refusing null there "
            f"contradicts its own annotation"
        )
