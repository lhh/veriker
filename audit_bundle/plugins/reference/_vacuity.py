"""audit_bundle/plugins/reference/_vacuity.py — "did this check check anything?"

ONE predicate, applied everywhere a reference check claims re-derivation
coverage. It exists because the same hole was found and patched three separate
times during the 2026-08-16 adversarial review, each time as an instance:

  1. a ``re_derive/*_pack.py`` whose whole body is ``sys.exit(0)`` satisfied
     ``--require-rederivation`` (fixed by refusing pack exit status as coverage);
  2. one decoy fragment anchor quoting its own snapshot suppressed the
     absence disclosure (documented residual — needs a claim inventory);
  3. ``payload/spans.json`` containing ``[]`` made a VERIFIER-DISTRIBUTION
     script iterate zero records and exit 0, which reported coverage and
     passed ``--require-rederivation`` at exit 0 with a clean verdict face.

The generalization: *"a check completed"* is not *"a check checked something"*.
Every coverage signal that is an exit status or a mere file-existence test is
vacuously satisfiable by an empty input, and the producer supplies the input.

``SensorReDerivationCheck`` already had this right — it returns ``NO_TRACES``
when ``raw_traces/`` is absent OR empty. Its three siblings guarded existence
only. Rather than copy that condition into each of them (which is how the
asymmetry arose in the first place), they now share this module.

Stdlib only: this sits on the core verify path.
"""

from __future__ import annotations

from pathlib import Path

from audit_bundle.admission import admit_json_file


def json_unit_count(path: Path) -> int | None:
    """Number of re-derivable units in a JSON payload, or None if unreadable.

    A list counts its elements; a dict counts its keys. Anything else (a bare
    scalar, malformed bytes) returns None — "cannot tell", which callers must
    treat as NOT coverage, never as coverage. Deliberately conservative: this
    predicate only ever REMOVES a coverage claim, so a parse failure here can
    never turn a red verdict green. The real structural validation stays in the
    re-derivation script, which runs afterwards and owns the reject.
    """
    # Admission-bounded, never a raw json.loads: this reads a BUNDLE-CONTROLLED
    # path, so it must size-reject before allocation and depth-scan before parse
    # like every other bundle-JSON read on the verify path
    # (tests/test_bundle_json_admission_ratchet.py enforces this, and caught the
    # first version of this module). InputInadmissible is a ValueError, so a
    # hostile shape lands in the except arm and reads as "cannot tell" — which
    # is NOT coverage, the conservative direction.
    try:
        doc = admit_json_file(path, check_name="rederivation_vacuity_probe")
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    if isinstance(doc, (list, dict)):
        return len(doc)
    return None


def is_vacuous(path: Path) -> bool:
    """True when re-deriving `path` would compare NOTHING.

    Callers use this to return their ``NO_*`` opt-out reason — ok=True, no
    coverage reported — instead of running a script that trivially exits 0 over
    an empty collection and calling the result re-derivation.
    """
    count = json_unit_count(path)
    return count is None or count == 0
