"""Parity: the OUTER gate and the INNER §4a.4 coverage trigger must agree.

The fail-open being guarded here was a coverage check sitting BELOW an early
return -- in three separate places (BundleVerifier._step_spec_pinned_dispatch,
run_spec_pinned_dispatch's empty-outputs branch, and its anchor-bind except
clause). Each hoist is only as good as the agreement between the condition that
lets execution through and the condition that decides coverage compares
anything. If the outer gate is ever NARROWER than the inner trigger, the inner
guard silently becomes unreachable and the fail-open returns.

The repo's own lesson about duplicated helpers is that the fix is a PARITY
TEST, not a comment and not de-duplication alone. So: one shared predicate
(audit_bundle.rederivation.coverage_trigger.coverage_is_triggered), and these
tests pin that nobody re-spells it.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from audit_bundle import verifier as verifier_mod
from audit_bundle.rederivation import dispatch as dispatch_mod
from audit_bundle.rederivation.coverage_trigger import (
    coverage_is_triggered,
    outputs_dir,
)

_PKG = Path(verifier_mod.__file__).resolve().parent


def test_trigger_agrees_with_enumeration(tmp_path):
    """Whenever the trigger says live, enumeration must be able to answer, and
    whenever it says inert, enumeration must be empty."""
    # no outputs/ tree at all
    b = tmp_path / "none"
    b.mkdir()
    assert not coverage_is_triggered(b)
    assert dispatch_mod._enumerate_output_files(b) == set()

    # outputs/ exists but empty -> triggered, nothing present
    b2 = tmp_path / "empty"
    (b2 / "outputs").mkdir(parents=True)
    assert coverage_is_triggered(b2)
    assert dispatch_mod._enumerate_output_files(b2) == set()

    # outputs/ with a file -> triggered, and that file is what coverage counts
    b3 = tmp_path / "one"
    (b3 / "outputs").mkdir(parents=True)
    (b3 / "outputs/alpha.json").write_text("{}")
    assert coverage_is_triggered(b3)
    assert dispatch_mod._enumerate_output_files(b3) == {"alpha"}


def test_an_empty_outputs_dir_is_not_a_coverage_failure(tmp_path):
    """The hoist must not turn `outputs/` existing but EMPTY into a refusal:
    declared == present == empty set. A bundle is not guilty of omission for
    carrying an empty directory."""
    b = tmp_path / "b"
    (b / "outputs").mkdir(parents=True)
    failures: list = []
    dispatch_mod._check_coverage(b, [], failures)
    assert failures == [], failures


def test_a_present_undeclared_file_IS_a_coverage_failure(tmp_path):
    """The control for the test above: the same call, one file present."""
    b = tmp_path / "b"
    (b / "outputs").mkdir(parents=True)
    (b / "outputs/ghost.json").write_text("{}")
    failures: list = []
    dispatch_mod._check_coverage(b, [], failures)
    assert [f.reason_code for f in failures] == ["COVERAGE_MISMATCH"], failures


def test_nobody_re_spells_the_outputs_trigger():
    """No module may hand-roll `<bundle_dir> / "outputs"` or test that path's
    is_dir() itself. Both call sites go through coverage_trigger, so a future
    change to what counts as an outputs tree lands in ONE place.

    This is the ratchet. The verifier's copy of this literal is exactly what
    made hoisting the guard inside dispatch a no-op the first time.
    """
    offenders: list[str] = []
    allowed = {"coverage_trigger.py"}
    for path in sorted(_PKG.rglob("*.py")):
        if path.name in allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # match: <anything> / "outputs"
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant)
                and node.right.value == "outputs"
            ):
                offenders.append(f"{path.relative_to(_PKG)}:{node.lineno}")
    assert not offenders, (
        "hand-rolled outputs/ path construction outside coverage_trigger.py: "
        f"{offenders}. Import outputs_dir/coverage_is_triggered instead — a "
        "second spelling of this predicate is how the coverage guard became "
        "unreachable."
    )


def test_the_outer_gate_calls_the_shared_predicate():
    """Sanity: if the verifier stopped calling it, every test above would still
    pass while the outer gate drifted freely."""
    src = inspect.getsource(verifier_mod.BundleVerifier._step_spec_pinned_dispatch)
    assert "coverage_is_triggered(bundle_dir)" in src, src[:400]


def test_outputs_dir_is_the_one_definition(tmp_path):
    assert outputs_dir(tmp_path) == tmp_path / "outputs"
    assert dispatch_mod._outputs_dir is outputs_dir
