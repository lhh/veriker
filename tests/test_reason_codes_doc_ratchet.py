"""REASON_CODES.md must document every reason code `audit_bundle/` emits.

A one-time reconciliation rots. This file shipped publicly calling itself
"canonical" while omitting 16 of its own distribution codes -- including
COVERAGE_MISMATCH, the code THREAT_MODEL.md names for the coverage attack. The
gap is only interesting if it cannot reopen, so it is a test.

SCOPE, stated: this ratchets the DISTRIBUTION surface (`audit_bundle/`) only.
Pilot-local codes under `examples/` are deliberately NOT ratcheted here --
requiring 79 pilot codes in a distribution doc would re-create the confusion
this file's header just corrected. There is no pilot-side counterpart: a kit
registers primitives, and primitives do not emit reason codes.
"""

from __future__ import annotations

import ast
import pathlib
import re

from audit_bundle.rederivation.reason_codes import classify

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DOC = _ROOT / "audit_bundle" / "plugins" / "REASON_CODES.md"
_EMIT = re.compile(r'reason_code\s*=\s*"([A-Z][A-Z0-9_]*)"')


def _reason_code_arg_positions() -> dict[str, int]:
    """Where `reason_code` sits POSITIONALLY in each failure constructor.

    INTROSPECTED, never hand-listed. A hardcoded index silently rots the day
    someone inserts a field, and this ratchet's whole defect was a detector
    that could not see the shape the code actually used.
    """
    import dataclasses
    import importlib

    positions: dict[str, int] = {}
    for module_name, cls_name in (
        ("audit_bundle.rederivation.dispatch", "DispatchFailure"),
        ("audit_bundle.plugin", "PluginResult"),
        ("audit_bundle.verifier", "VerifyFailure"),
    ):
        cls = getattr(importlib.import_module(module_name), cls_name, None)
        if cls is None or not dataclasses.is_dataclass(cls):
            continue
        names = [f.name for f in dataclasses.fields(cls)]
        if "reason_code" in names:
            positions[cls_name] = names.index("reason_code")
    return positions


def _emitted_core_codes() -> set[str]:
    codes: set[str] = set()
    positions = _reason_code_arg_positions()
    for path in sorted((_ROOT / "audit_bundle").rglob("*.py")):
        # reason_codes.py DEFINES the vocabulary; its `_FAMILY_SUFFIXES` and
        # `_BARE_ALIASES` tables hold the LEGACY spellings by design. Scanning
        # it would demand documentation for codes that were deleted from the
        # fleet -- the opposite of what this ratchet is for.
        if path.name == "reason_codes.py":
            continue
        text = path.read_text(errors="ignore")
        codes.update(_EMIT.findall(text))
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if classify(node.value):
                    codes.add(node.value)
            # POSITIONAL emission -- added 2026-08-30 after a fresh-context
            # pass. `audit_bundle/rederivation/dispatch.py` builds EVERY one of
            # its failures as `DispatchFailure(check_name, "CODE", detail)`,
            # which neither the `reason_code="LIT"` regex nor the collapsible-
            # constant sweep can see. 15 of its codes were undocumented and
            # this ratchet was green over all of them. It is the identical
            # blind spot the reverted kit check had, in the guard written to
            # replace it.
            if isinstance(node, ast.Call):
                fn = None
                if isinstance(node.func, ast.Name):
                    fn = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn = node.func.attr
                idx = positions.get(fn)
                if idx is not None and len(node.args) > idx:
                    arg = node.args[idx]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        codes.add(arg.value)
    return codes


def test_every_core_reason_code_is_documented():
    doc = _DOC.read_text()
    missing = sorted(
        c for c in _emitted_core_codes()
        if not re.search(rf"\b{re.escape(c)}\b", doc)
    )
    assert not missing, (
        "REASON_CODES.md is missing reason codes emitted by audit_bundle/: "
        f"{missing}. Add each with its emitting file and the condition that "
        "fires it -- derived from the code, not from memory."
    )


def test_the_canonical_four_are_documented():
    doc = _DOC.read_text()
    for code in ("RE_DERIVED", "RE_DERIVATION_MISMATCH",
                 "RE_DERIVATION_TIMEOUT", "RE_DERIVATION_NOT_COMPARED"):
        assert re.search(rf"\b{code}\b", doc), f"{code} undocumented"


def test_the_doc_no_longer_claims_to_be_canonical_over_pilot_codes():
    """ANTI-REGRESSION on the CLAIM, not just the content. The header used to
    say these were "the canonical reason codes" while documenting none of the
    pilot-local ones."""
    doc = _DOC.read_text()
    assert "These are the canonical reason codes emitted by" not in doc
    assert "DISTRIBUTION codes only" in doc


def test_the_ratchet_sees_POSITIONAL_emission(tmp_path, monkeypatch):
    """MUTANT CONTROL. The defect this detector was blind to, planted.

    A detector never shown a positive case is not evidence, and this one was
    green over 15 real undocumented codes for its whole life. Plant a
    positional `DispatchFailure(cn, "CODE", detail)` and the scan must return
    the code.
    """
    src = tmp_path / "audit_bundle"
    src.mkdir()
    (src / "planted.py").write_text(
        "from audit_bundle.rederivation.dispatch import DispatchFailure\n"
        "def f(cn):\n"
        "    return DispatchFailure(cn, 'PLANTED_POSITIONAL_CODE', 'detail')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "tests.test_reason_codes_doc_ratchet._ROOT", tmp_path, raising=False
    )
    assert "PLANTED_POSITIONAL_CODE" in _emitted_core_codes(), (
        "the doc ratchet still cannot see positional emission -- which is the "
        "shape dispatch.py uses for every one of its failures"
    )


def test_the_positional_index_is_introspected_not_hardcoded():
    """The index must come from the dataclass, so inserting a field ahead of
    `reason_code` cannot silently point the detector at the wrong argument."""
    positions = _reason_code_arg_positions()
    assert positions, "no failure constructors were introspected at all"
    for cls_name, idx in positions.items():
        assert isinstance(idx, int) and idx >= 0, f"{cls_name} index {idx!r}"
    assert "DispatchFailure" in positions, (
        "DispatchFailure is the constructor whose positional emission this "
        "ratchet exists to see"
    )
