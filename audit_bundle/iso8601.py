"""audit_bundle.iso8601 — the ONE parser for an ISO-8601 instant on a verdict path.

Why one: a 2026-09-05 census found fourteen `fromisoformat` sites in this package
giving FIVE different answers for the same naive input ``2026-01-01T00:00:00``
(no offset) — assume UTC; assume the VERIFIER MACHINE's local zone (the verdict
then depends on the auditor's TZ); return a naive object that raises TypeError on
its first comparison; refuse; and, at one site, ``replace(tzinfo=utc)`` on an
input carrying an explicit ``+09:00``, silently discarding the offset (nine hours
wrong, measured). Every one of those was a hand-rolled copy of the same six lines.

Contract — refuse, never guess:

* input must be a non-empty ``str``;
* ``Z`` and ``±HH:MM`` offsets are accepted, fractional seconds are accepted;
* a NAIVE timestamp (no offset) is REFUSED with ``ValueError``. An instant with
  no zone is not comparable across producer and verifier, and every softening
  of that rule (assume UTC / assume local) is a direction an adversary or a
  misconfigured host can push a verdict. Refuse > skew;
* the result is timezone-aware and normalised to UTC via ``astimezone`` — an
  explicit non-UTC offset is CONVERTED, never dropped.

The body of :func:`parse_iso8601_utc` is deliberately byte-identical (after
docstring/string normalisation) to the copy the standalone reference packs carry
(``plugins/reference/control_rederivation._parse_iso8601_utc``): those packs are
import-nothing by contract and keep their own copy, and
``tests/test_reference_pack_parity.py`` pins their copy to THIS function. Change
this body and that test tells you which copies to change with it.

Stdlib only (§C5 core verify() path).
"""

from __future__ import annotations

from datetime import datetime, timezone

__all__ = ["parse_iso8601_utc", "parse_iso8601_utc_ms"]


def parse_iso8601_utc(value: str) -> "datetime":
    """Parse an ISO-8601 instant to a timezone-aware UTC datetime.

    Raises ``ValueError`` on: a non-string or empty input, any malformed
    string, and a NAIVE timestamp (no ``Z`` / offset). Accepts the ``Z``
    suffix, offset notation, and fractional seconds; an explicit non-UTC
    offset is converted to UTC (``astimezone``), never discarded.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("not a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(normalized)  # raises ValueError on malformed input
    if dt.tzinfo is None:
        raise ValueError(f"{value!r} has no UTC offset")
    return dt.astimezone(timezone.utc)


def parse_iso8601_utc_ms(value: str) -> int:
    """:func:`parse_iso8601_utc`, as integer milliseconds since the Unix epoch.
    Same refusals. Sub-millisecond precision is truncated toward zero, which is
    what every prior hand-rolled ``int(dt.timestamp() * 1000)`` site did."""
    return int(parse_iso8601_utc(value).timestamp() * 1000)
