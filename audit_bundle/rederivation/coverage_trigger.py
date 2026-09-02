"""The ONE predicate deciding whether the §4a.4 coverage invariant is live.

A leaf module on purpose. Two call sites must agree exactly:

  * ``BundleVerifier._step_spec_pinned_dispatch`` — the OUTER gate, which
    returns early when a bundle declares no outputs;
  * ``dispatch._check_coverage`` — the INNER trigger, which decides whether
    coverage compares anything.

If the outer gate is ever narrower than the inner trigger, the inner guard
becomes unreachable again — silently. That is not hypothetical: the fail-open
this module exists to prevent was a coverage guard sitting below an early
return, in THREE separate places, and the repair's first draft re-spelled this
predicate inline in the verifier rather than sharing it, which would have made
a fourth copy free to drift.

Duplicated helpers drift; the fix is a shared definition PLUS a parity test
(tests/test_coverage_trigger_parity.py), not a comment asking the next author
to remember. Kept dependency-free (stdlib ``pathlib`` only) so the verifier can
ask the question without importing the dispatch machinery — the lazy-import
property a plain S0 verify relies on.
"""

from __future__ import annotations

from pathlib import Path

OUTPUTS_DIRNAME = "outputs"


def outputs_dir(bundle_dir: Path) -> Path:
    """The canonical outputs/ tree for a bundle."""
    return bundle_dir / OUTPUTS_DIRNAME


def coverage_is_triggered(bundle_dir: Path) -> bool:
    """True when the bundle carries an outputs/ tree for coverage to check.

    File-presence-triggered, deliberately: a legacy bundle carrying no
    outputs/ tree at all stays wholly inert, which is the property the
    empty-outputs early returns exist to protect.

    NOTE the residual this predicate cannot close: the path it tests is
    PRODUCER-CONTROLLED. Renaming outputs/ leaves nothing to trigger on. See
    THREAT_MODEL.md row 5 — closing that needs the AUDITOR's anchor to state
    the expected output_ids, not a scan of a directory the producer names.
    """
    return outputs_dir(bundle_dir).is_dir()


# --------------------------------------------------------------------------
# The rule's IDENTITY, owned here for the same reason the trigger is.
# --------------------------------------------------------------------------
#
# A verdict that only says "veriker 0.1.4" makes the acceptance behaviour a
# property of WHOSE BUILD RAN. That is the re-weld the primitive contract
# versioning exists to avoid (PRIMITIVES.md, "What `@version` means"): a
# version only its author can supply welds a stated behaviour to one
# implementation. So the coverage invariant is named and revisioned like a
# primitive contract — an identifier ANY conforming verifier may declare, and
# a consumer may require, without knowing our release history.
#
# Monotonic integer, exact string equality — never semver. Revision 1 is the
# behaviour THREAT_MODEL.md row 5 describes: file-presence-triggered on
# outputs/, `set(manifest.outputs[].output_id) == set(outputs/*.json)`,
# fail-closed whether one entry is dropped or the whole array is deleted.
# Bump it only when that stated behaviour changes, and publish the new
# referent FIRST.
ACCEPTANCE_RULE_ID = "coverage_exact_outputs"
ACCEPTANCE_RULE_VERSION = "1"


def acceptance_rule_ref() -> str:
    """`coverage_exact_outputs@1` — the token a verdict face carries and a
    consumer keys on."""
    return f"{ACCEPTANCE_RULE_ID}@{ACCEPTANCE_RULE_VERSION}"
