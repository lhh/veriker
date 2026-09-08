"""audit_bundle.strict_json — the ONE strict JSON parser for producer bytes.

``json.loads`` is a laundering surface. It accepts three things a conforming
JSON reader does not, and each is a way for one byte string to carry two
meanings while every sha over it stays valid:

* **duplicate object keys** — stdlib keeps the LAST; a first-wins reader and a
  human see the other value. Measured 2026-09-04: ``{"value": 0.992,
  "value": 0.8875}`` in a manifest-bound output verified exit 0 while the
  declared figure read 99.2%;
* **``NaN`` / ``Infinity`` / ``-Infinity`` tokens** — not JSON (RFC 8259); a
  strict consumer refuses bytes this verifier certified;
* **arbitrarily long integer tokens** — a parse-time resource bound the
  canonical codec (``_total_binding``) refuses at 600 digits.

Before 2026-09-05 this package held four hand-rolled ``object_pairs_hook``
parsers with three different guard sets, and the manifest entry point, the
shared admission loader, and forty-odd other sites parsed producer bytes with a
bare ``json.loads``. This module is the single source for the PARSER-level
refusals. It deliberately does NOT own size, depth, node-count, or type
policy: those stay with the caller that has the policy (``admission`` bounds
bytes and depth before the parser runs; ``_total_binding`` runs its codec walk
after). Compose, do not fold.

Contract:

* :func:`strict_json_loads` takes ``bytes`` or ``str``; a ``bytes`` input is
  decoded as UTF-8 (``UnicodeDecodeError`` propagates);
* the three semantic refusals raise :class:`StrictJSONError` (a ``ValueError``)
  with ``.kind`` in ``{"duplicate_key", "non_finite", "int_too_long"}`` and
  ``.key`` set for a duplicate — so a caller can map the refusal into its own
  vocabulary without matching message text;
* SYNTAX errors propagate unchanged as ``json.JSONDecodeError`` (also a
  ``ValueError``). A caller that must tell "not JSON at all" from "JSON-shaped
  but corrupt" (``claimset`` does) can; a caller that does not care catches
  ``ValueError`` once.

``audit_bundle._total_binding.strict_loads`` is the vendored canonical codec
and keeps its own three hooks so the module stays a leaf with no package
imports; ``tests/test_strict_json_single_source.py`` holds the two in
behavioural agreement over one vector table.

Stdlib only (§C5 core verify() path).
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["StrictJSONError", "strict_json_loads", "MAX_INT_DIGITS"]

#: Same bound as the canonical codec's ``_INT_DIGITS``: an integer token longer
#: than this is refused at the lexer, before ``int()`` allocates.
MAX_INT_DIGITS = 600


class StrictJSONError(ValueError):
    """A semantic refusal by the strict parser (never a syntax error)."""

    def __init__(self, kind: str, message: str, *, key: str | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.key = key


def _pairs(pairs: list) -> dict:
    d: dict = {}
    for k, v in pairs:
        if k in d:
            raise StrictJSONError(
                "duplicate_key", f"duplicate object key {k!r} in input", key=k
            )
        d[k] = v
    return d


def _int(s: str) -> int:
    if len(s.lstrip("-")) > MAX_INT_DIGITS:
        raise StrictJSONError(
            "int_too_long", f"integer token longer than {MAX_INT_DIGITS} digits"
        )
    return int(s)


def _const(name: str) -> Any:
    raise StrictJSONError("non_finite", f"non-standard JSON token {name!r} rejected")


def strict_json_loads(data: "bytes | str") -> Any:
    """Parse JSON refusing duplicate keys, non-finite tokens, and oversized ints.

    Raises :class:`StrictJSONError` for those three; ``json.JSONDecodeError``
    for malformed syntax; ``UnicodeDecodeError`` for non-UTF-8 bytes;
    ``TypeError`` for any other input type.
    """
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8")
    elif isinstance(data, str):
        text = data
    else:
        raise TypeError(
            f"strict_json_loads takes bytes or str, not {type(data).__name__}"
        )
    return json.loads(
        text, object_pairs_hook=_pairs, parse_int=_int, parse_constant=_const
    )
