"""tests/test_primitive_ref_redteam_regressions.py — regressions for the three
SEVERE defects the D1 fresh-context adversarial pass found (2026-08-29).

All three were CONFIRMED BY EXECUTION before any fix was written; these tests
were committed BEFORE the fixes, so the ordering is falsifiable from git.

R1 [FAIL OPEN] Pin-stripping by producer type-selection. `_enforce_ref_coherence`
    permitted a BARE spelling alongside a pinned one ("bare imposes nothing").
    That is true about SATISFIABILITY and false about AUTHORITY: dispatch
    resolves the binding from the producer-supplied `type`, so the producer
    chose whether the auditor's pin was evaluated at all. Measured: pinned type
    -> PRIMITIVE_DIGEST_UNAVAILABLE, bare type -> [] on the same anchored spec,
    same registry, same code.

R2 [FAIL OPEN] The digest bound a different object than the one invoked.
    `derive_provenance` did `getattr(primitive, "recompute")` for hashing and
    dispatch did `primitive.recompute(...)` for invocation -- two separate
    attribute reads. A `property`/descriptor returns a different callable to
    each. Measured: pin MATCHED, face named honest.py, and the value that
    verified was produced by hostile code in another file. No compile(), no
    co_filename rewrite -- plain Python.

R3 [FAIL CLOSED, contract breach] An exception from the version attribute read
    escaped `run_spec_pinned_dispatch` entirely -- no DispatchFailure recorded,
    the cardinality guard skipped, contradicting the module's own "every
    per-output evaluation is wrapped" contract. Measured: RuntimeError escaped.
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
from audit_bundle.rederivation.dispatch import run_spec_pinned_dispatch  # noqa: E402
from audit_bundle.rederivation.spec_binding import MalformedSpec, parse_spec  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402

HEX_A = "a" * 64
HEX_B = "b" * 64


def _run(spec: dict, outputs: list[dict], stub, monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    raw = json.dumps(spec).encode("utf-8")
    anchor = SpecAnchor(allowed={spec["spec_id"]: hashlib.sha256(raw).hexdigest()})

    class _M:
        spec_files = ["t.spec.json"]

    _M.outputs = outputs
    bundle = tmp / "bundle"
    (bundle / "spec").mkdir(parents=True)
    (bundle / "outputs").mkdir()
    (bundle / "spec" / "t.spec.json").write_bytes(raw)
    for o in outputs:
        (bundle / "outputs" / f"{o['output_id']}.json").write_text(
            json.dumps({"value": [1, 2, 3]})
        )
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: stub)
    prov: dict = {}
    fails = run_spec_pinned_dispatch(
        bundle, _M(), anchor, primitive_provenance_out=prov
    )
    return [f.reason_code for f in fails], prov


class _Stub:
    primitive_id = "demo"

    def recompute(self, inputs, pack_section):
        return RecomputedValue(value=[1, 2, 3], detail="")


# ---------------------------------------------------------------------------
# R1 — a pin is a property of the NAME, not of one binding
# ---------------------------------------------------------------------------


def _spec_two_spellings(a: str, b: str) -> dict:
    return {
        "spec_id": "pinstrip",
        "description": "d",
        "types": {
            "t_pinned": {"primitive_id": a, "comparator": {"kind": "exact", "params": {}}},
            "t_bare": {"primitive_id": b, "comparator": {"kind": "exact", "params": {}}},
        },
    }


def test_R1_bare_alongside_pinned_is_refused_at_load():
    """The fix. Once ANY binding pins a name, a bare binding of that same name
    is an unpinned door to the same code and must be refused."""
    with pytest.raises(MalformedSpec) as exc:
        parse_spec(_spec_two_spellings(f"demo#{HEX_A}", "demo"), "s.json")
    assert "demo" in str(exc.value)


def test_R1_bare_alongside_versioned_is_refused_at_load():
    with pytest.raises(MalformedSpec):
        parse_spec(_spec_two_spellings("demo@1", "demo"), "s.json")


def test_R1_versioned_alongside_pinned_only_is_refused_at_load():
    """`demo@1` and `demo#sha` constrain the same name differently -- one
    imposes a version and no digest, the other a digest and no version. The
    weaker spelling is still a door."""
    with pytest.raises(MalformedSpec):
        parse_spec(_spec_two_spellings(f"demo#{HEX_A}", "demo@1"), "s.json")


def test_R1_identical_spellings_remain_fine():
    """Anti-overreach: the guard must not refuse a legitimate spec that binds
    one name identically from two types."""
    _, b = parse_spec(_spec_two_spellings(f"demo#{HEX_A}", f"demo#{HEX_A}"), "s.json")
    assert len(b) == 2


def test_R1_all_bare_remains_fine():
    _, b = parse_spec(_spec_two_spellings("demo", "demo"), "s.json")
    assert len(b) == 2


def test_R1_different_names_unaffected():
    _, b = parse_spec(_spec_two_spellings(f"demo#{HEX_A}", "other"), "s.json")
    assert len(b) == 2


# ---------------------------------------------------------------------------
# R2 — the digest must bind the object that is INVOKED
# ---------------------------------------------------------------------------


def test_R2_pin_binds_the_invoked_callable_not_a_second_getattr(tmp_path, monkeypatch):
    """A `recompute` property that hands honest code to the hasher and hostile
    code to the caller must NOT produce a green verdict with digest_status
    'matched'. Fixed by binding the callable ONCE and both hashing and invoking
    that same object."""
    honest_file = tmp_path / "honest_mod.py"
    honest_file.write_text(
        "from audit_bundle.plugin import RecomputedValue\n"
        "def honest(inputs, pack):\n"
        "    return RecomputedValue(value=[1, 2, 3], detail='')\n"
    )
    pin = hashlib.sha256(honest_file.read_bytes()).hexdigest()
    sys.path.insert(0, str(tmp_path))
    try:
        import honest_mod  # type: ignore
    finally:
        sys.path.remove(str(tmp_path))

    def hostile(inputs, pack):
        return RecomputedValue(value=[1, 2, 3], detail="")

    class _Sneaky:
        primitive_id = "demo"

        @property
        def recompute(self):
            caller = sys._getframe(1).f_code.co_name
            return honest_mod.honest if "provenance" in caller else hostile

    spec = {
        "spec_id": "toctou",
        "description": "d",
        "types": {
            "t": {
                "primitive_id": f"demo#{pin}",
                "comparator": {"kind": "exact", "params": {}},
            }
        },
    }
    codes, prov = _run(spec, [{"output_id": "o", "type": "t"}], _Sneaky(), monkeypatch)

    row = next(iter(prov.values()), {})
    matched = row.get("ref", {}).get("digest_status") == "matched"
    assert not (
        codes == [] and matched
    ), f"FAIL OPEN: pin reported matched while a different callable ran. {prov}"


def test_R2_an_honest_primitive_still_passes_its_pin(monkeypatch):
    """Anti-vacuity for R2: the fix must not break the legitimate case, or the
    test above passes because pinning stopped working entirely."""
    from audit_bundle.rederivation import registry

    registry._ensure_primitives_loaded()
    stub = _Stub()
    sha = registry.derive_provenance(stub)["sha256"]
    assert sha, "the stub must have a derivable source digest"
    spec = {
        "spec_id": "honest",
        "description": "d",
        "types": {
            "t": {
                "primitive_id": f"demo#{sha}",
                "comparator": {"kind": "exact", "params": {}},
            }
        },
    }
    codes, prov = _run(spec, [{"output_id": "o", "type": "t"}], stub, monkeypatch)
    assert codes == [], f"honest pinned run must pass, got {codes}"
    row = next(iter(prov.values()))
    assert row["ref"]["digest_status"] == "matched"


# ---------------------------------------------------------------------------
# R3 — no exception may escape the per-output loop
# ---------------------------------------------------------------------------


def test_R3_raising_version_attribute_is_recorded_not_propagated(monkeypatch):
    """§4a.8: every per-output evaluation is wrapped so an error becomes a
    RECORDED failure, never a crash. A descriptor that raises on the version
    read escaped run_spec_pinned_dispatch entirely -- results abandoned, the
    cardinality guard skipped."""

    class _Raiser:
        primitive_id = "demo"

        @property
        def primitive_version(self):
            raise RuntimeError("boom")

        def recompute(self, inputs, pack_section):
            return RecomputedValue(value=[1, 2, 3], detail="")

    spec = {
        "spec_id": "raise",
        "description": "d",
        "types": {
            "t": {"primitive_id": "demo@1", "comparator": {"kind": "exact", "params": {}}}
        },
    }
    codes, _ = _run(spec, [{"output_id": "o", "type": "t"}], _Raiser(), monkeypatch)
    assert codes, "an exception must be RECORDED, not propagated"
    assert all(isinstance(c, str) for c in codes)


def test_R3_raising_recompute_attribute_is_recorded_not_propagated(monkeypatch):
    """The same hole one attribute over: binding the callable once means the
    BIND itself can now raise, and that read must be wrapped too."""

    class _Raiser:
        primitive_id = "demo"

        @property
        def recompute(self):
            raise RuntimeError("boom")

    spec = {
        "spec_id": "raise2",
        "description": "d",
        "types": {
            "t": {"primitive_id": "demo", "comparator": {"kind": "exact", "params": {}}}
        },
    }
    codes, _ = _run(spec, [{"output_id": "o", "type": "t"}], _Raiser(), monkeypatch)
    assert codes, "a raising recompute bind must be RECORDED, not propagated"
