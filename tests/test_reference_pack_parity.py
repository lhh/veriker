"""Parity harness for the standalone reference re-derivation packs.

`audit_bundle/plugins/reference/{aigov,control,span,energy}_*.py` are stdlib-only,
import-nothing verifiers by contract (the AB4 "duplicated, never imported"
doctrine: each pack must be auditable as ONE file). The unpriced cost of that
contract is that nothing holds the copies in agreement — and on 2026-09-05 the
census found the AI-governance pack had lost three `observed_at` guards its
sibling carried.

This file is the fix shape that already worked twice in this tree
(`integrity_ownership` for five complement skip-sets; the C18 tristate test for
three locators): ONE positive source plus a harness pinning every copy to it.
The source is `control_rederivation.py`. Every other pack's copy of a shared
helper must have a body IDENTICAL to control's after normalisation, and
`aigov._verify` must emit exactly the reason-code vocabulary `control._verify`
does. A pack that needs to diverge edits this file in the same commit and says
why — the divergence then has a name and a reviewer, instead of a comment saying
"mirrors X" that no test reads.

Normalisation is the helper-drift detector's: docstrings dropped, every str/bytes
constant blanked (text similarity is dominated by error-message strings, and the
hardened copy is precisely the one carrying more of them), then `ast.unparse`.
Wording differences are invisible; a missing guard is not.

The self-validation test is the load-bearing half: a comparator that stops
distinguishing a dropped `raise` turns every other test here into green dead code.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_REF_DIR = _PKG_ROOT / "audit_bundle" / "plugins" / "reference"

#: The positive source. Every other pack is pinned TO this one.
SOURCE = "control_rederivation.py"

#: helper -> packs (besides SOURCE) that must carry an identical copy.
#: Derived from the 2026-09-05 census of identical bodies; extend when a pack
#: gains a copy, never trim to make a drift pass.
SHARED: dict[str, tuple[str, ...]] = {
    "_admit_depth_scan": (
        "aigov_rederivation.py",
        "span_re_derivation.py",
        "energy_score_pack.py",
    ),
    "_admit_pairs": (
        "aigov_rederivation.py",
        "span_re_derivation.py",
        "energy_score_pack.py",
    ),
    "_admit_int": (
        "aigov_rederivation.py",
        "span_re_derivation.py",
        "energy_score_pack.py",
    ),
    "_admit_const": (
        "aigov_rederivation.py",
        "span_re_derivation.py",
        "energy_score_pack.py",
    ),
    "_admit_loads": (
        "aigov_rederivation.py",
        "span_re_derivation.py",
        "energy_score_pack.py",
    ),
    "_admitted_json": (
        "aigov_rederivation.py",
        "span_re_derivation.py",
        "energy_score_pack.py",
    ),
    "_resolve_within": ("aigov_rederivation.py", "span_re_derivation.py"),
    "_canonical": ("aigov_rederivation.py",),
    "sign_attestation": ("aigov_rederivation.py",),
    "_signature_ok": ("aigov_rederivation.py",),
    "_load_verifier_hmac_key": ("aigov_rederivation.py",),
    "_parse_iso8601_utc": ("aigov_rederivation.py",),
    "sha256_file": ("aigov_rederivation.py",),
    "run_test_fn": ("aigov_rederivation.py",),
    "main": ("aigov_rederivation.py",),
}

#: module constants that must agree across every pack AND with the substrate's
#: `AdmissionLimits` defaults (the packs re-declare the numbers by hand).
SHARED_CONSTANTS = ("_ADMIT_MAX_BYTES", "_ADMIT_MAX_DEPTH", "_ADMIT_MAX_INT_DIGITS")
ALL_PACKS = (
    SOURCE,
    "aigov_rederivation.py",
    "span_re_derivation.py",
    "energy_score_pack.py",
)


# ---------------------------------------------------------------------------
# Normalisation — the helper-drift detector's, inlined so this test has no
# dependency on the internal-only tools/ tree.
# ---------------------------------------------------------------------------


class _Blank(ast.NodeTransformer):
    def visit_Constant(self, node):
        if isinstance(node.value, (str, bytes)):
            return ast.copy_location(ast.Constant(value="_"), node)
        return node

    def visit_JoinedStr(self, node):
        return ast.copy_location(ast.Constant(value="_"), node)


def _normalised_body(fn: ast.FunctionDef) -> str:
    fn = ast.parse(ast.unparse(fn)).body[0]
    body = fn.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:] or [ast.Pass()]
    fn.body = body
    fn = ast.fix_missing_locations(_Blank().visit(fn))
    return ast.unparse(fn)


def _functions(path: Path) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def _const_arith(node: ast.AST):
    """Evaluate a literal or a pure arithmetic expression over literals
    (`16 * 1024 * 1024`); anything else -> None. No names, no calls."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add, ast.Sub, ast.Pow)):
        left, right = _const_arith(node.left), _const_arith(node.right)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            op = node.op
            if isinstance(op, ast.Mult):
                return left * right
            if isinstance(op, ast.Add):
                return left + right
            if isinstance(op, ast.Sub):
                return left - right
            return left**right
    return None


def _module_constants(path: Path) -> dict[str, object]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: dict[str, object] = {}
    for n in tree.body:
        if (
            isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name)
        ):
            val = _const_arith(n.value)
            if val is not None:
                out[n.targets[0].id] = val
    return out


def _reason_vocabulary(fn: ast.FunctionDef) -> set[str]:
    """Every `CODE:` prefix the function can emit — the leading UPPER_SNAKE token of
    each string / f-string it returns or raises. This is the pack's contract with
    its wrapper (`[<PACK>_REDERIVE_FAIL] <reason>: ...`) and with every test that
    scores a reason code."""
    codes: set[str] = set()
    for node in ast.walk(fn):
        first: str | None = None
        if (
            isinstance(node, ast.JoinedStr)
            and node.values
            and isinstance(node.values[0], ast.Constant)
        ):
            first = (
                node.values[0].value if isinstance(node.values[0].value, str) else None
            )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            first = node.value
        if first is None:
            continue
        head, sep, _ = first.partition(":")
        if (
            sep
            and head
            and head.replace("_", "").isupper()
            and head.replace("_", "").isalnum()
        ):
            codes.add(head)
    return codes


# ---------------------------------------------------------------------------
# Self-validation: the comparator must SEE a dropped guard and must NOT see
# wording. If either arm fails, every test below is decoration.
# ---------------------------------------------------------------------------


def test_normalisation_sees_a_dropped_guard_and_ignores_wording():
    hardened = ast.parse(
        "def f(s):\n"
        '    """Explains the guard at length."""\n'
        "    if not s:\n"
        '        raise ValueError("empty input is refused because ...")\n'
        "    if len(s) > 4:\n"
        '        raise ValueError("too long")\n'
        "    return s\n"
    ).body[0]
    reworded = ast.parse(
        "def f(s):\n"
        "    if not s:\n"
        '        raise ValueError("nope")\n'
        "    if len(s) > 4:\n"
        '        raise ValueError(f"{s!r} exceeds the bound")\n'
        "    return s\n"
    ).body[0]
    downgraded = ast.parse(
        "def f(s):\n"
        '    """Explains the guard at length."""\n'
        "    if len(s) > 4:\n"
        '        raise ValueError("too long")\n'
        "    return s\n"
    ).body[0]
    assert _normalised_body(hardened) == _normalised_body(reworded)
    assert _normalised_body(hardened) != _normalised_body(downgraded)


def test_reason_vocabulary_extractor_reads_fstrings_and_plain_strings():
    fn = ast.parse(
        "def _verify():\n"
        "    x = 1\n"
        "    if x:\n"
        '        return (f"ALPHA_CODE: {x} detail", [])\n'
        '    return ("BETA: plain", [])\n'
    ).body[0]
    assert _reason_vocabulary(fn) == {"ALPHA_CODE", "BETA"}


# ---------------------------------------------------------------------------
# The pins
# ---------------------------------------------------------------------------


def test_every_shared_helper_names_a_function_that_exists():
    """Scaffolding referents must exist: a pin on a name no pack defines pins
    nothing and reads green."""
    src = _functions(_REF_DIR / SOURCE)
    for helper, packs in SHARED.items():
        assert helper in src, f"{SOURCE} has no {helper}"
        for pack in packs:
            assert helper in _functions(_REF_DIR / pack), f"{pack} has no {helper}"


@pytest.mark.parametrize(
    "helper,pack",
    [(h, p) for h, packs in SHARED.items() for p in packs],
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_shared_helper_is_identical_to_the_source_copy(helper: str, pack: str):
    src = _normalised_body(_functions(_REF_DIR / SOURCE)[helper])
    cpy = _normalised_body(_functions(_REF_DIR / pack)[helper])
    assert cpy == src, (
        f"{pack}:{helper} has drifted from {SOURCE}:{helper}. If the divergence is "
        f"deliberate, record it in tests/test_reference_pack_parity.py in the same "
        f"commit — the isolation contract is real, silent drift is the defect."
    )


def test_admission_constants_agree_across_packs_and_with_the_substrate():
    from audit_bundle.admission import AdmissionLimits
    from audit_bundle.strict_json import MAX_INT_DIGITS

    expected = {
        "_ADMIT_MAX_BYTES": AdmissionLimits().max_bytes,
        "_ADMIT_MAX_DEPTH": AdmissionLimits().max_depth,
        "_ADMIT_MAX_INT_DIGITS": MAX_INT_DIGITS,
    }
    for pack in ALL_PACKS:
        consts = _module_constants(_REF_DIR / pack)
        for name in SHARED_CONSTANTS:
            assert consts.get(name) == expected[name], (
                pack,
                name,
                consts.get(name),
                expected[name],
            )


def test_aigov_verify_emits_exactly_controls_reason_vocabulary():
    """The two `_verify` bodies legitimately differ in domain wording and test_fn
    registries. They must NOT differ in which refusals exist. Set equality, both
    directions: a code control has that aigov lacks is a lost guard (the 2026-09-05
    finding); a code aigov has that control lacks is the same drift the other way."""
    ctrl = _reason_vocabulary(_functions(_REF_DIR / SOURCE)["_verify"])
    aigov = _reason_vocabulary(
        _functions(_REF_DIR / "aigov_rederivation.py")["_verify"]
    )
    assert ctrl, "control._verify emits no reason codes — extractor broken"
    assert aigov == ctrl, {
        "control_only (lost in aigov)": sorted(ctrl - aigov),
        "aigov_only (lost in control)": sorted(aigov - ctrl),
    }


def test_standalone_timestamp_parser_is_identical_to_the_substrate_source():
    """The packs cannot import `audit_bundle.iso8601` (import-nothing contract),
    so they carry a copy of `parse_iso8601_utc`. Pin the copy to the substrate
    body: change one, this names the others. The substrate module is the
    positive source for the whole package; SOURCE (control) is the positive
    source for the packs; the two are held equal here."""
    substrate = _functions(_PKG_ROOT / "audit_bundle" / "iso8601.py")["parse_iso8601_utc"]
    pack = _functions(_REF_DIR / SOURCE)["_parse_iso8601_utc"]
    # Names differ by design; compare bodies under the pack's name.
    substrate.name = pack.name
    assert _normalised_body(pack) == _normalised_body(substrate)


def test_the_ported_guards_are_reachable_in_aigov():
    """A vocabulary pin is a string-level check. Confirm the guard is wired: the
    pack's `_parse_iso8601_utc` refuses a naive timestamp, which is what makes
    OBSERVED_AT_UNPARSEABLE reachable from producer data at all."""
    aigov = importlib.import_module("audit_bundle.plugins.reference.aigov_rederivation")
    with pytest.raises(ValueError):
        aigov._parse_iso8601_utc("2026-05-01T00:00:00")
    assert (
        aigov._parse_iso8601_utc("2026-05-01T00:00:00Z").utcoffset().total_seconds()
        == 0
    )
