"""audit_bundle/multi_root/roots.py — declared trust roots and independence accounting.

A verifier that consults eleven authorities has eleven signatures to check and, very
possibly, one administrative principal behind five of them. Counting authorities
measures breadth. Counting DECLARED ROOTS measures independence, and the two diverge
exactly where an attacker with one credential moves several systems together: a
threshold that counts labels is one key.

This module holds the declaration and the arithmetic, nothing else:

  * `RootTable` — authority id -> declared root id, plus ONE distinguished root: the
    proposer's. Declared before any run, so the root count cannot be tuned to the
    result. An authority the table does not name has no root and is refused
    (`UndeclaredAuthority`) — deny-by-default, never "no root, so unconstrained".
  * `RootTable.collapse` — re-declare one authority under another declared root. This
    is how "does the code-provenance service collapse into the transparency log when
    they are the same service?" becomes a measured quantity rather than a footnote:
    run under both tables and diff.
  * `independence_metrics` — authority count vs distinct-root count over the rows an
    admission produced.
  * `blast_radius` — for each non-proposer root, what is lost when it is removed.

What this module does NOT do: establish that a declared root IS independent. A
declaration is a bound assumption the consumer makes and must defend; the module
makes the assumption legible and holds it fixed across the run.

Stdlib only. Imports nothing from `verifier`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping

__all__ = [
    "RootTable",
    "UndeclaredAuthority",
    "RootTableError",
    "independence_metrics",
    "blast_radius",
]


class RootTableError(ValueError):
    """The declaration is malformed. Raised at declare time, never at lookup."""


class UndeclaredAuthority(KeyError):
    """An authority id the table does not name. Refused rather than defaulted."""


def _nonempty_str(x: object, what: str) -> str:
    if not isinstance(x, str) or not x:
        raise RootTableError(f"{what} must be a non-empty str, got {x!r}")
    return x


class RootTable:
    """Immutable authority -> root declaration with one distinguished proposer root.

    Construct with `RootTable.declare(...)`. Instances are immutable: the mapping is
    copied at construction and only exposed through methods, so no holder can re-root
    an authority after the run starts.
    """

    __slots__ = ("_roots", "_proposer", "_map")

    def __init__(self, roots: tuple, proposer_root: str, mapping: dict):
        self._roots = roots
        self._proposer = proposer_root
        self._map = mapping

    @classmethod
    def declare(
        cls,
        authority_root: Mapping[str, str],
        *,
        proposer_root: str,
        roots: Iterable[str] | None = None,
    ) -> "RootTable":
        """Declare the table.

        authority_root: authority id -> root id. Every value must be a declared root.
        proposer_root:  the root the proposing party's own systems sit under. ESTABLISHED
                        (in `propositions.py`) needs a confirming chain with no link here.
        roots:          the declared root ids, in declaration order. Defaults to the
                        sorted set of values — pass it explicitly so a root that no
                        authority currently populates is still declared.
        """
        if not isinstance(authority_root, Mapping):
            raise RootTableError(
                f"authority_root must be a mapping, got {type(authority_root).__name__}"
            )
        mapping = {}
        for a, r in authority_root.items():
            mapping[_nonempty_str(a, "authority id")] = _nonempty_str(r, f"root of {a!r}")
        declared = tuple(roots) if roots is not None else tuple(sorted(set(mapping.values())))
        if not declared:
            raise RootTableError("a root table with no roots is refused")
        seen: set = set()
        for r in declared:
            _nonempty_str(r, "root id")
            if r in seen:
                raise RootTableError(f"root {r!r} declared twice")
            seen.add(r)
        _nonempty_str(proposer_root, "proposer_root")
        if proposer_root not in seen:
            raise RootTableError(
                f"proposer_root {proposer_root!r} is not a declared root {list(declared)!r}"
            )
        undeclared = sorted({r for r in mapping.values() if r not in seen}, key=repr)
        if undeclared:
            raise RootTableError(
                f"authorities are rooted under undeclared roots {undeclared!r}"
            )
        return cls(declared, proposer_root, mapping)

    # -- lookups -------------------------------------------------------------

    @property
    def roots(self) -> tuple:
        return self._roots

    @property
    def proposer_root(self) -> str:
        return self._proposer

    @property
    def authorities(self) -> tuple:
        return tuple(self._map)

    def root_of(self, authority: str) -> str:
        try:
            return self._map[authority]
        except (KeyError, TypeError):
            raise UndeclaredAuthority(
                f"authority {authority!r} is not in the declared root table "
                f"{sorted(self._map, key=repr)!r}; an undeclared authority has no root"
            ) from None

    def is_proposer(self, root: str) -> bool:
        return root == self._proposer

    def is_declared_root(self, root: object) -> bool:
        return root in self._roots

    def authorities_under(self, root: str) -> tuple:
        return tuple(a for a, r in self._map.items() if r == root)

    # -- re-declaration -------------------------------------------------------

    def collapse(self, authority: str, into: str) -> "RootTable":
        """A new table with `authority` re-rooted under the declared root `into`.

        The open question "are these two services the same root?" is answered by running
        under both tables. The original is untouched.
        """
        current = self.root_of(authority)  # refuses an undeclared authority
        if into not in self._roots:
            raise RootTableError(f"cannot collapse into undeclared root {into!r}")
        if self.is_proposer(current) != self.is_proposer(into):
            # Red-team witness (2026-09-06): collapse("erp", R-BANK) relabelled the
            # proposer's own vendor master as independent and a proposition ESTABLISHED
            # off content the payer fully controls. A collapse asks whether two
            # INDEPENDENT services are one root; it never moves an authority across the
            # proposer boundary in either direction.
            raise RootTableError(
                f"collapse of {authority!r} from {current!r} into {into!r} would change its "
                "proposer status; a collapse merges independent roots, it never re-labels "
                "the proposer's systems as independent (or the reverse)"
            )
        mapping = dict(self._map)
        mapping[authority] = into
        return RootTable(self._roots, self._proposer, mapping)

    def __repr__(self) -> str:
        return (
            f"RootTable(roots={self._roots!r}, proposer_root={self._proposer!r}, "
            f"authorities={len(self._map)})"
        )


# ---------------------------------------------------------------------------
# accounting
# ---------------------------------------------------------------------------


def independence_metrics(rows: Iterable[Mapping]) -> dict:
    """Authority count vs distinct-root count over admission rows.

    Counts only rows ADMITTED and not stale — a record the verifier could not use
    contributes neither an authority nor a root, however loudly it was reached.
    Row shape is `roster.py`'s: `record_id`, `authority`, `root`, `disposition`, `stale`.
    """
    rows = list(rows)
    adm = [r for r in rows if r.get("disposition") == "ADMITTED" and not r.get("stale")]
    return {
        "expected_records": len(rows),
        "admitted": len(adm),
        "stale": sum(1 for r in rows if r.get("stale")),
        "unusable": sum(1 for r in rows if r.get("disposition") == "UNUSABLE"),
        "unreached": sum(1 for r in rows if r.get("disposition") == "UNREACHED"),
        "authorities_admitted": sorted({r["authority"] for r in adm}, key=repr),
        "authority_count": len({r["authority"] for r in adm}),
        "roots_admitted": sorted({r["root"] for r in adm}, key=repr),
        "distinct_root_count": len({r["root"] for r in adm}),
    }


def blast_radius(
    run_without: Callable[[str], Mapping],
    base: Mapping,
    table: RootTable,
    *,
    roots: Iterable[str] | None = None,
) -> dict:
    """For each non-proposer root, which propositions lose ESTABLISHED when it is removed.

    run_without(root) -> a run result with `states` (proposition -> state dict carrying
    `state`) and `overall` (carrying `decision`), the same shape as `base`. The proposer's
    root is never removed: its removal is not a configuration, it is a different proposer.
    """
    out = {}
    for root in (roots if roots is not None else table.roots):
        if table.is_proposer(root):
            continue
        r = run_without(root)
        lost = [
            p
            for p, s in base["states"].items()
            if s["state"] == "ESTABLISHED" and r["states"][p]["state"] != "ESTABLISHED"
        ]
        out[root] = {
            "propositions_losing_independent_establishment": lost,
            "decision": r["overall"]["decision"],
        }
    return out
