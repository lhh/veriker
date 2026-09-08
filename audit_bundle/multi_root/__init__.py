"""audit_bundle.multi_root — more than one trust root in the same verdict.

Three stages, three modules, in the order a run passes through them:

  roots         declared authority -> root table with one distinguished proposer root;
                authority count vs distinct-root count; root collapse as a measurement.
  roster        admission: one row per EXPECTED record (ADMITTED / UNUSABLE / UNREACHED),
                the roster committed as a closed universe with a receipt, per-proposition
                `present − verified` as coverage channels.
  propositions  findings carrying a provenance chain graded by S1's min-rule; the state
                rule (CONTRADICTED / CANNOT_CONCLUDE{UNREACHED, INSUFFICIENT} /
                ESTABLISHED); the decision lattice on `_degradation.Severity`; the
                tri-state `Verdict`.

Origin: a pre-registered payment-authorization probe (2026-09-05) that surveyed these
six mechanisms as absent and built them locally first; they were lifted here once its
own provenance table named what it had transcribed.

All authorities a consumer wires here are the consumer's. Nothing in this package
establishes that a declared root is independent; it holds the declaration fixed and
does the arithmetic honestly.
"""

from .roots import RootTable, RootTableError, UndeclaredAuthority, blast_radius, independence_metrics
from .roster import (
    ADMITTED,
    ROOT_NOT_ENABLED,
    UNREACHED,
    UNUSABLE,
    Admission,
    Expected,
    Roster,
    RosterError,
    admission_channels,
    admit,
    admit_nothing,
    admitted,
)
from .propositions import (
    CANNOT_CONCLUDE,
    CONFIRMS,
    CONTRADICTED,
    CONTRADICTS,
    ESTABLISHED,
    HOLD,
    INSUFFICIENT_Q,
    REFUSE,
    RELEASE,
    SILENT,
    UNREACHED_Q,
    ProvenanceError,
    effective_root,
    finding,
    grade_chain,
    improves,
    overall,
    proposition_states,
    state_vector,
    to_verdict,
)

__all__ = [
    "RootTable", "RootTableError", "UndeclaredAuthority", "blast_radius", "independence_metrics",
    "ADMITTED", "UNUSABLE", "UNREACHED", "ROOT_NOT_ENABLED", "Admission", "Expected", "Roster",
    "RosterError", "admission_channels", "admit", "admit_nothing", "admitted",
    "CONFIRMS", "CONTRADICTS", "SILENT", "ESTABLISHED", "CONTRADICTED", "CANNOT_CONCLUDE",
    "UNREACHED_Q", "INSUFFICIENT_Q", "REFUSE", "HOLD", "RELEASE", "ProvenanceError",
    "effective_root", "finding", "grade_chain", "improves", "overall", "proposition_states",
    "state_vector", "to_verdict",
]
