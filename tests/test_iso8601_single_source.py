"""One ISO-8601 parser on the verdict path — and the ratchet that keeps it one.

Before 2026-09-05 the package held fourteen `fromisoformat` sites with five
behaviours for the same naive input. Three tests here:

1. the contract of `audit_bundle.iso8601` itself, table-driven, including the
   two behaviours that were WRONG at a live site (naive read in the verifier's
   local zone; an explicit +09:00 offset silently replaced by UTC);
2. a witness per rewired site, through the site's own entry point, so a copy
   that quietly grows back is caught where it would bite;
3. a source ratchet: every `fromisoformat` / `strptime` in `audit_bundle/` is
   either the single source, a standalone reference pack's pinned copy
   (tests/test_reference_pack_parity.py holds those equal to the source), or on
   the frozen allow-list below with a reason. A fifteenth copy fails this test.


"""

from __future__ import annotations

import datetime as _dt
import os
import re
import sys
import time
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.iso8601 import parse_iso8601_utc, parse_iso8601_utc_ms  # noqa: E402

UTC = _dt.timezone.utc
_T0 = _dt.datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 1 — the contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-01-01T00:00:00Z", _T0),
        ("2026-01-01T00:00:00+00:00", _T0),
        ("2026-01-01T00:00:00.250Z", _T0.replace(microsecond=250_000)),
        ("2026-01-01T00:00:00.123456+00:00", _T0.replace(microsecond=123_456)),
        # An explicit non-UTC offset is CONVERTED (nine hours), never dropped.
        ("2026-01-01T09:00:00+09:00", _T0),
        ("2025-12-31T19:00:00-05:00", _T0),
    ],
)
def test_accepts_and_normalises_to_utc(value, expected):
    got = parse_iso8601_utc(value)
    assert got == expected
    assert got.tzinfo is not None and got.utcoffset() == _dt.timedelta(0)


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-01T00:00:00",  # naive: no zone, not comparable
        "2026-01-01T00:00:00.5",  # naive with fraction
        "2026-01-01",  # a date is not an instant
        "",
        None,
        1_767_225_600,
        b"2026-01-01T00:00:00Z",
        "not-a-timestamp",
        "2026-13-01T00:00:00Z",
        "2026-01-01T00:00:00z",  # lowercase z is not ISO-8601
        "2026-01-01 00:00:00Z ",  # trailing space
    ],
)
def test_refuses(value):
    with pytest.raises(ValueError):
        parse_iso8601_utc(value)
    with pytest.raises(ValueError):
        parse_iso8601_utc_ms(value)


def test_ms_form_truncates_toward_zero_like_every_prior_site():
    assert (
        parse_iso8601_utc_ms("2026-01-01T00:00:00.9999Z")
        == int(_T0.timestamp() * 1000) + 999
    )
    # toward zero, not floor: -0.5 ms -> 0 (a floor would say -1)
    assert parse_iso8601_utc_ms("1969-12-31T23:59:59.9995Z") == 0


@pytest.fixture
def tokyo(monkeypatch):
    """The verifier machine's zone must not reach a verdict."""
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    yield
    monkeypatch.delenv("TZ", raising=False)
    time.tzset()


def test_verifier_machine_zone_never_reaches_the_answer(tokyo):
    assert parse_iso8601_utc("2026-01-01T00:00:00Z") == _T0
    with pytest.raises(ValueError):
        parse_iso8601_utc("2026-01-01T00:00:00")


# ---------------------------------------------------------------------------
# 2 — one witness per rewired site, through the site's own entry point
# ---------------------------------------------------------------------------


def test_scrabble_refuses_naive_instead_of_reading_it_in_local_time(tokyo):
    from audit_bundle.rederivation.primitives.scrabble import _parse_iso

    assert _parse_iso("2026-01-01T00:00:00Z") == _T0
    with pytest.raises(ValueError):
        _parse_iso("2026-01-01T00:00:00")  # was: 2025-12-31T15:00:00+00:00 under Tokyo


def test_peerreview_converts_an_explicit_offset_instead_of_dropping_it():
    from audit_bundle.extensions.c19.cross_host_peerreview import _extract_send_bound_ms

    ev = {
        "kind": "rfc3161_tsa",
        "rfc3161_tsa": {"send_timestamp_gentime": "2026-01-01T09:00:00+09:00"},
    }
    ms, radi = _extract_send_bound_ms(ev)
    assert (ms, radi) == (int(_T0.timestamp() * 1000), 0)  # was: nine hours later
    with pytest.raises(ValueError):
        _extract_send_bound_ms(
            {
                "kind": "rfc3161_tsa",
                "rfc3161_tsa": {"send_timestamp_gentime": "2026-01-01T09:00:00"},
            }
        )
    with pytest.raises(
        ValueError
    ):  # neither gentime present -> refuse, not AttributeError
        _extract_send_bound_ms({"kind": "rfc3161_tsa", "rfc3161_tsa": {}})


def test_tuf_naive_expiry_is_a_refusal_not_a_type_error():
    from audit_bundle.extensions import c18_tuf_client as tuf

    naive = {"signed": {"expires": "2999-01-01T00:00:00"}}
    with pytest.raises(tuf.TUFRootExpired):
        tuf._assert_root_not_expired(naive)  # was: TypeError on `<=`
    with pytest.raises(tuf.TUFRootExpired):
        tuf._assert_root_expiry_within_window(naive)  # was: TypeError on `-`
    ok = {"signed": {"expires": "2999-01-01T00:00:00Z"}}
    tuf._assert_root_not_expired(ok)


def test_fulcio_optional_window_keeps_none_and_refuses_naive():
    from audit_bundle.extensions.fulcio_identity import _parse_iso

    assert _parse_iso(None) is None
    assert _parse_iso("") is None
    assert _parse_iso("2026-01-01T00:00:00Z") == _T0
    with pytest.raises(ValueError):
        _parse_iso("2026-01-01T00:00:00")  # was: a naive object


def test_stamp_lattice_keeps_its_none_on_failure_contract():
    from audit_bundle.plugins.stamp_lattice import _parse_iso8601_to_aware

    assert _parse_iso8601_to_aware("2026-01-01T00:00:00Z") == _T0
    assert _parse_iso8601_to_aware("2026-01-01T09:00:00+09:00") == _T0
    assert _parse_iso8601_to_aware("2026-01-01T00:00:00") is None
    assert _parse_iso8601_to_aware("") is None
    assert _parse_iso8601_to_aware(None) is None


def test_tsa_gentime_keeps_its_none_on_failure_contract():
    from audit_bundle.extensions.c19.tsa_roughtime_bls import _gentime_iso_to_ms

    assert _gentime_iso_to_ms("2026-01-01T00:00:00Z") == int(_T0.timestamp() * 1000)
    assert _gentime_iso_to_ms("2026-01-01T00:00:00") is None  # was: assumed UTC
    assert _gentime_iso_to_ms(None) is None
    assert _gentime_iso_to_ms("garbage") is None


def test_pre_commit_log_refuses_naive():
    from audit_bundle.extensions.c19.pre_commit_log import (
        verify_pre_commit_predates_rotation,
    )

    ok = dict(
        pre_commit_issuance_iso8601="2026-01-01T00:00:00Z",
        rotation_at_iso8601="2026-01-01T01:00:00Z",
        assurance_profile="offline-auditor-minimal",
    )
    verify_pre_commit_predates_rotation(**ok)  # positive arm: the window is inside bounds
    with pytest.raises(ValueError):
        verify_pre_commit_predates_rotation(
            **{**ok, "pre_commit_issuance_iso8601": "2026-01-01T00:00:00"}
        )  # was: assumed UTC


# The retention site's witness lives in tests/test_emitter_premium_retention.py:
# that module is premium and this file ships in the open drop, which refuses a
# premium import at export time.


# ---------------------------------------------------------------------------
# 3 — the source ratchet
# ---------------------------------------------------------------------------

#: Every `fromisoformat(` / `strptime(` call site in audit_bundle/ that is NOT the
#: single source. Each entry carries the reason it is allowed to exist. Adding
#: one is a decision recorded here, not a paste.
ALLOWED_PARSE_SITES: dict[str, str] = {
    # The standalone packs are import-nothing by contract; their copy is pinned
    # body-identical to the source by tests/test_reference_pack_parity.py.
    "audit_bundle/plugins/reference/control_rederivation.py": "standalone pack, pinned copy",
    "audit_bundle/plugins/reference/aigov_rederivation.py": "standalone pack, pinned copy",
    # A DATE-token heuristic in the agent ladder: `date.fromisoformat` over a
    # calendar date has no zone to get wrong. Not an instant on a verdict path.
    "audit_bundle/plugins/reference/agent_ladder.py": "date tokens, not instants",
}
_SOURCE = "audit_bundle/iso8601.py"
_CALL = re.compile(r"\b(fromisoformat|strptime)\s*\(")


def test_no_fifteenth_parser():
    seen: dict[str, int] = {}
    for path in sorted((_PKG_ROOT / "audit_bundle").rglob("*.py")):
        rel = path.relative_to(_PKG_ROOT).as_posix()
        n = len(_CALL.findall(path.read_text(encoding="utf-8")))
        if n:
            seen[rel] = n
    assert _SOURCE in seen, (
        "the single source lost its parser — the ratchet is measuring nothing"
    )
    strays = {
        k: v for k, v in seen.items() if k != _SOURCE and k not in ALLOWED_PARSE_SITES
    }
    assert not strays, f"new hand-rolled timestamp parse sites: {strays}"
    # A row whose FILE is absent is not stale (the open-drop export ships a
    # subset of the package, and this test ships with it).
    if not (_PKG_ROOT / "release" / "oss_export.py").is_file():
        # Exported clone: the export REWRITES some shipped files (and drops
        # others), so "this row no longer parses loosely" is not a fact about
        # our source there. The strays check above is the guard and ran in
        # full; only this hygiene half is internal-tree-only.
        return
    present = {k for k in ALLOWED_PARSE_SITES if (_PKG_ROOT / k).is_file()}
    missing = present - set(seen)
    assert not missing, (
        f"allow-list names sites that no longer parse anything: {missing}"
    )


def test_ratchet_sees_a_planted_copy(tmp_path, monkeypatch):
    """Self-validation: the regex must fire on the shapes the census found."""
    for shape in (
        'dt = datetime.fromisoformat(s.replace("Z", "+00:00"))',
        "datetime.datetime.fromisoformat(value)",
        'datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")',
        "date.fromisoformat(t)",
    ):
        assert _CALL.search(shape), shape
    assert not _CALL.search("isoformat()")
    assert not _CALL.search("fromisoformat_like = 1")
