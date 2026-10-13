"""Declared inputs: every binding param is read by someone, and a primitive supplies
no default for a value the asker owns (the declared-inputs contract).

Driven end to end through the public witness_cert_minimal pilot: its three
`fea_witness_certificate*` primitives declare `expects = {equilibrium_tol, epsilon,
input_anchor, conditioning_bound}` and `expects_optional = {quantity}`; its comparators
are `rational_sqrt_band` and `rational_band`. Each cell writes a VARIANT spec into the
bundle and anchors the auditor on exactly that variant, so the spec under test is the
auditor's own instruction, not a producer substitution.

The witness: before this contract, an auditor who added `"expected": 0` to a
`rational_band` binding got exit 0 — the key was read by nobody. The null mutant below
neuters the check and shows the witness verifies clean without it.

D2 (a primitive with no `expects` at all) is refused, PRIMITIVE_UNDECLARED, exit 2.
Its witness: a primitive that reads a comparator key (`epsilon`) without declaring it
would otherwise be handed an empty params view and run on nothing, silently; the null
mutant restores that empty view and shows it.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "witness_cert_minimal"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "witness_cert.spec.json"
_SPEC_NAME = "witness_cert.spec.json"
_BAND_TYPE = "witness_cert_u_norm_inf"  # the rational_band binding

from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.rederivation import dispatch  # noqa: E402
from audit_bundle.rederivation.comparators import (  # noqa: E402
    _COMPARATOR_REGISTRY,
    comparator_param_keys,
)
from audit_bundle.rederivation.primitives import fea_witness_cert as fwc  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("wc") / "bundle"
    subprocess.run(
        [sys.executable, str(_PILOT_DIR / "_build_bundle.py"), "--out-dir", str(out)],
        check=True,
        capture_output=True,
        cwd=str(_PKG_ROOT),
    )
    return out


def _variant(edit) -> bytes:
    """The committed spec with `edit(type_key, params)` applied to every binding."""
    doc = json.loads(_SPEC_SRC.read_bytes())
    for type_key, t in doc["types"].items():
        edit(type_key, t["comparator"]["params"])
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _verify_with_spec(built: Path, tmp_path: Path, spec_bytes: bytes):
    """Copy the honest bundle, ship `spec_bytes` as its spec, and anchor the AUDITOR
    on exactly those bytes."""
    import shutil

    bundle = tmp_path / "bundle"
    shutil.copytree(built, bundle)
    (bundle / "spec" / _SPEC_NAME).write_bytes(spec_bytes)
    mpath = bundle / "manifest.json"
    m = json.loads(mpath.read_bytes())
    m["spec_files"][_SPEC_NAME] = hashlib.sha256(spec_bytes).hexdigest()
    mpath.write_bytes(json.dumps(m, indent=2, sort_keys=True).encode("utf-8"))
    anchor = SpecAnchor(
        allowed={
            json.loads(spec_bytes)["spec_id"]: hashlib.sha256(spec_bytes).hexdigest()
        }
    )
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor,
        require_rederivation=True,
    )
    return verifier.verify(bundle)


def _text(result) -> str:
    return " ".join(f"{r.code} {getattr(r, 'detail', '')}" for r in result.reasons)


def _noop(_t, _p):
    return None


# --- the committed spec still verifies ------------------------------------------------


def test_committed_spec_verifies(built, tmp_path):
    result = _verify_with_spec(built, tmp_path, _variant(_noop))
    assert result.ok, _text(result)


# --- a key nobody reads is refused, as could-not-conclude ---------------------


def _add_expected(t, p):
    if t == _BAND_TYPE:
        p["expected"] = 0


def test_unread_key_is_unknown_spec_param(built, tmp_path):
    result = _verify_with_spec(built, tmp_path, _variant(_add_expected))
    assert not result.ok
    assert result.state is VerdictState.ERROR, _text(result)
    assert "UNKNOWN_SPEC_PARAM" in _text(result)
    assert "'expected'" in _text(result)


def test_misspelt_primitive_key_is_refused(built, tmp_path):
    def misspell(_t, p):
        p["equilibirum_tol"] = p.pop("equilibrium_tol")

    result = _verify_with_spec(built, tmp_path, _variant(misspell))
    assert not result.ok
    assert result.state is VerdictState.ERROR, _text(result)
    assert "UNKNOWN_SPEC_PARAM" in _text(result)


def test_omitted_expected_key_is_missing_spec_param(built, tmp_path):
    """conditioning_bound used to default to False inside the primitive."""

    def omit(_t, p):
        p.pop("conditioning_bound")

    result = _verify_with_spec(built, tmp_path, _variant(omit))
    assert not result.ok
    assert result.state is VerdictState.ERROR, _text(result)
    assert "MISSING_SPEC_PARAM" in _text(result)
    assert "'conditioning_bound'" in _text(result)


def test_stated_null_anchor_is_accepted(built, tmp_path):
    """Unanchored mode stays expressible: the auditor STATES it (null + no
    conditioning bound), the declaration check lets it through, and the
    primitive runs in unanchored mode. (This bundle's claims carry a certified
    interval, which only the conditioning form accepts, so the verdict itself is
    a claim-shape mismatch; that is not what this cell tests.)"""

    def unanchor(_t, p):
        p["input_anchor"] = None
        p["conditioning_bound"] = False

    result = _verify_with_spec(built, tmp_path, _variant(unanchor))
    text = _text(result)
    assert "UNKNOWN_SPEC_PARAM" not in text and "MISSING_SPEC_PARAM" not in text, text
    assert "witness certificate (UNANCHORED" in text, text


def test_null_mutant_reopens_dc2_17(built, tmp_path, monkeypatch):
    """Neuter the check (the unread key counts as read): the witness
    verifies CLEAN. That is the defect the contract closes, and it shows the
    refusal above comes from the check and nothing incidental."""
    real = dispatch.comparator_param_keys
    monkeypatch.setattr(
        dispatch, "comparator_param_keys", lambda kind: real(kind) | {"expected"}
    )
    result = _verify_with_spec(built, tmp_path, _variant(_add_expected))
    assert result.ok, _text(result)


# --- the primitive sees only what it declared ------------------------------------------


def test_primitive_sees_only_declared_params(built, tmp_path, monkeypatch):
    """Shrink the primitive's declaration so `conditioning_bound` is read only by
    the band comparator: it stays a legal binding param, and the primitive no
    longer receives it (the certificate then refuses for lack of it, which is the
    point: reading past a declaration reads nothing)."""
    seen: list[set] = []
    cls = fwc.FeaWitnessCertificate
    real = cls.recompute

    def spy(self, inputs, pack_section):
        seen.append(set(pack_section["params"]))
        return real(self, inputs, pack_section)

    monkeypatch.setattr(cls, "recompute", spy)
    monkeypatch.setattr(
        cls, "expects", frozenset({"equilibrium_tol", "epsilon", "input_anchor"})
    )
    result = _verify_with_spec(built, tmp_path, _variant(_noop))
    assert "UNKNOWN_SPEC_PARAM" not in _text(result), _text(result)
    assert seen and all("conditioning_bound" not in s for s in seen), seen


def test_numeric_model_on_a_band_kind_is_unread(built, tmp_path):
    """`numeric_model` is documentary and only `scalar_epsilon` reads it; on a band
    binding nobody reads it, so it is refused like any other unread key."""

    def tag(_t, p):
        p["numeric_model"] = "binary64_exact"

    result = _verify_with_spec(built, tmp_path, _variant(tag))
    assert result.state is VerdictState.ERROR, _text(result)
    assert "UNKNOWN_SPEC_PARAM" in _text(result) and "'numeric_model'" in _text(result)


# --- a primitive with no declaration is refused (D2) ----------------------------------


def _comparator_keys_only() -> bytes:
    """The committed spec with every binding reduced to the keys its COMPARATOR reads
    (`epsilon`, `conditioning_bound` stated False): nothing a primitive-only key could trip, so the
    only thing between an undeclared primitive and running is the D2 check."""
    doc = json.loads(_SPEC_SRC.read_bytes())
    for t in doc["types"].values():
        keep = comparator_param_keys(t["comparator"]["kind"])
        t["comparator"]["params"] = {
            k: v for k, v in t["comparator"]["params"].items() if k in keep
        }
        # A conditioning bound needs an input anchor at spec load; state the plain
        # band instead, so the binding carries comparator keys only.
        t["comparator"]["params"]["conditioning_bound"] = False
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _undeclare_and_spy(monkeypatch) -> list[set]:
    """Remove fea_witness_certificate's declaration (as a third-party primitive
    written before the contract would lack one) and record what params it is
    handed each time it runs."""
    seen: list[set] = []
    cls = fwc.FeaWitnessCertificate
    real = cls.recompute

    def spy(self, inputs, pack_section):
        seen.append(set(pack_section["params"]))
        return real(self, inputs, pack_section)

    monkeypatch.setattr(cls, "recompute", spy)
    monkeypatch.delattr(cls, "expects")
    monkeypatch.delattr(cls, "expects_optional", raising=False)
    return seen


def test_undeclared_primitive_is_refused_before_it_runs(built, tmp_path, monkeypatch):
    seen = _undeclare_and_spy(monkeypatch)
    result = _verify_with_spec(built, tmp_path, _comparator_keys_only())
    assert not result.ok
    assert result.state is VerdictState.ERROR, _text(result)
    assert "PRIMITIVE_UNDECLARED" in _text(result), _text(result)
    assert seen == [], seen  # never run


def test_null_mutant_undeclared_runs_on_an_empty_view(built, tmp_path, monkeypatch):
    """Neuter D2 (an undeclared primitive counts as declaring nothing, the
    pre-D2 rule): the primitive RUNS, and is handed no params although every
    binding states `epsilon` and `conditioning_bound`. No refusal names this;
    that silence is what the check removes."""
    seen = _undeclare_and_spy(monkeypatch)
    real = dispatch._declared_inputs

    def pre_d2(primitive):
        out = real(primitive)
        if isinstance(out, dispatch._Undeclared):
            return frozenset(), frozenset()
        return out

    monkeypatch.setattr(dispatch, "_declared_inputs", pre_d2)
    result = _verify_with_spec(built, tmp_path, _comparator_keys_only())
    assert "PRIMITIVE_UNDECLARED" not in _text(result), _text(result)
    assert seen and all(s == set() for s in seen), seen


def _override_every_primitive(monkeypatch, *, restate: bool) -> list[set]:
    """Resolve every witness_cert primitive to a SUBCLASS that overrides `recompute`
    (red-team F1, 2026-09-28): a kit primitive built on a declared base, the shape
    the kit tests already use. The base's `expects` is inherited unless `restate`.
    Built with `type()` so the source ratchet below does not name this double."""
    seen: list[set] = []
    real_resolve = dispatch.resolve_primitive

    def resolve(name):
        base = type(real_resolve(name))

        def recompute(self, inputs, pack_section):
            seen.append(set(pack_section["params"]))
            return base.recompute(self, inputs, pack_section)

        body = {"recompute": recompute}
        if restate:
            body["expects"] = base.expects
        return type("KitOverride", (base,), body)()

    monkeypatch.setattr(dispatch, "resolve_primitive", resolve)
    return seen


def test_an_override_does_not_inherit_its_bases_declaration(
    built, tmp_path, monkeypatch
):
    seen = _override_every_primitive(monkeypatch, restate=False)
    result = _verify_with_spec(built, tmp_path, _variant(_noop))
    assert result.state is VerdictState.ERROR, _text(result)
    assert "PRIMITIVE_UNDECLARED" in _text(result), _text(result)
    assert seen == [], seen  # never run


def test_an_override_that_restates_the_declaration_runs(built, tmp_path, monkeypatch):
    seen = _override_every_primitive(monkeypatch, restate=True)
    result = _verify_with_spec(built, tmp_path, _variant(_noop))
    assert result.ok, _text(result)
    assert seen and all("epsilon" in s for s in seen), seen


def test_null_mutant_an_inherited_declaration_covers_the_override(
    built, tmp_path, monkeypatch
):
    """Neuter the MRO rule (any `expects` reachable by getattr counts, the rule
    before 2026-09-28): the override RUNS under a declaration written for a
    computation it replaced, and no refusal names it."""
    seen = _override_every_primitive(monkeypatch, restate=False)
    monkeypatch.setattr(
        dispatch, "_declares_for_its_recompute", lambda p: hasattr(p, "expects")
    )
    result = _verify_with_spec(built, tmp_path, _variant(_noop))
    assert "PRIMITIVE_UNDECLARED" not in _text(result), _text(result)
    assert seen, seen


def _rec(self, inputs, pack_section):
    return None


@pytest.mark.parametrize(
    "make, declared",
    [
        # base states it; subclass inherits both expects and recompute
        (
            lambda: type(
                "C", (type("B", (), {"expects": frozenset(), "recompute": _rec}),), {}
            )(),
            True,
        ),
        # subclass overrides recompute, inherits expects
        (
            lambda: type(
                "C",
                (type("B", (), {"expects": frozenset(), "recompute": _rec}),),
                {"recompute": _rec},
            )(),
            False,
        ),
        # a mixin earlier in the MRO supplies recompute; expects sits on a later base
        (
            lambda: type(
                "C",
                (
                    type("M", (), {"recompute": _rec}),
                    type("B", (), {"expects": frozenset()}),
                ),
                {},
            )(),
            False,
        ),
        # expects on the subclass, recompute on the base: it describes the recompute that runs
        (
            lambda: type(
                "C", (type("B", (), {"recompute": _rec}),), {"expects": frozenset()}
            )(),
            True,
        ),
        # recompute stored on the instance needs expects on the instance
        (lambda: _with(recompute=_rec), False),
        (lambda: _with(recompute=_rec, expects=frozenset()), True),
        # the class's own recompute bound to this instance (a monkeypatch undo) runs
        # the code the class declared for; any other bound method does not
        (lambda: _bound_on_instance(own=True, same_instance=True), True),
        (lambda: _bound_on_instance(own=False, same_instance=True), False),
        (lambda: _bound_on_instance(own=True, same_instance=False), False),
        # a slotted primitive with no __dict__ reads its classes
        (
            lambda: type(
                "S", (), {"__slots__": (), "expects": frozenset(), "recompute": _rec}
            )(),
            True,
        ),
    ],
)
def test_expects_must_describe_the_recompute_that_runs(make, declared):
    out = dispatch._declared_inputs(make())
    assert isinstance(out, dispatch._Undeclared) is not declared, out


def _bound_on_instance(*, own: bool, same_instance: bool):
    from types import MethodType

    def _other(self, inputs, pack_section):
        return None

    cls = type("B", (), {"expects": frozenset(), "recompute": _rec})
    p, q = cls(), cls()
    p.recompute = MethodType(_rec if own else _other, p if same_instance else q)
    return p


def test_a_monkeypatch_undo_leaves_the_primitive_declared(monkeypatch):
    """Found by the full suite 2026-09-28: `monkeypatch.setattr` on an instance
    restores by `setattr`, leaving the bound class method in the instance
    `__dict__`. Before the bound-method exemption every later test in the same
    process saw PRIMITIVE_UNDECLARED on that registry singleton (the OSS run gate,
    serial, failed three work-set tests after the detail-disclosure test)."""
    cls = type("B", (), {"expects": frozenset(), "recompute": _rec})
    p = cls()
    with monkeypatch.context() as m:
        m.setattr(p, "recompute", lambda inputs, pack_section: None)
        assert isinstance(dispatch._declared_inputs(p), dispatch._Undeclared)
    assert "recompute" in vars(p)  # the leftover this test is about
    assert not isinstance(dispatch._declared_inputs(p), dispatch._Undeclared)


def _classes_missing_expects(source: str) -> list[tuple[int, str]]:
    """Classes whose OWN body defines `recompute` but states no `expects` -- the
    rule dispatch applies at run time (`_declares_for_its_recompute`): whatever the
    bases, an override does not inherit its base's declaration, and subclassing the
    `ReDerivationPrimitive` Protocol supplies only an annotation, not a value. A
    Protocol definition itself is exempt."""
    import ast

    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef):
            continue
        if any(ast.unparse(b).split(".")[-1] == "Protocol" for b in node.bases):
            continue
        own = set()
        for n in node.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                own.add(n.name)
            elif isinstance(n, ast.Assign):
                own.update(t.id for t in n.targets if isinstance(t, ast.Name))
            elif (
                isinstance(n, ast.AnnAssign)
                and isinstance(n.target, ast.Name)
                and n.value is not None
            ):
                own.add(n.target.id)
        if "recompute" in own and "expects" not in own:
            out.append((node.lineno, node.name))
    return out


def test_every_primitive_class_in_the_tree_declares_expects():
    """Ratchet over the source tree (tests included: their doubles reach dispatch
    too). Every class that defines `recompute` states `expects` in its own body.
    The refusal above is the runtime net; this names the class at review time."""
    missing = []
    for path in sorted(_PKG_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            found = _classes_missing_expects(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        missing += [f"{path.relative_to(_PKG_ROOT)}:{ln} {name}" for ln, name in found]
    assert not missing, (
        "classes that define `recompute` with no `expects` of their own (state "
        "`expects = frozenset()` if it reads no binding param, or restate the "
        f"base's): {missing}"
    )


def test_the_tree_ratchet_sees_every_undeclared_shape():
    """Planted control: each route the red team found past the first ratchet (a
    base-less class was the only shape it inspected) is named; a restated or
    stated declaration and the Protocol definition are not."""
    src = (
        "from typing import Protocol\n"
        "class ReDerivationPrimitive(Protocol):\n"
        "    expects: frozenset[str]\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class Bare:\n"
        "    primitive_id = 'a'\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class ViaProtocol(ReDerivationPrimitive):\n"
        "    primitive_id = 'b'\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class ViaObject(object):\n"
        "    primitive_id = 'c'\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class Base:\n"
        "    primitive_id = 'd'\n"
        "    expects = frozenset()\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class Override(Base):\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class Restated(Base):\n"
        "    expects = Base.expects\n"
        "    def recompute(self, inputs, pack_section): ...\n"
        "class Inherits(Base):\n"
        "    primitive_id = 'e'\n"
    )
    assert [n for _, n in _classes_missing_expects(src)] == [
        "Bare",
        "ViaProtocol",
        "ViaObject",
        "Override",
    ]


# --- a malformed declaration is could-not-conclude, never an escape --------------------


class _P:
    pass


def _with(**attrs):
    p = _P()
    for k, v in attrs.items():
        setattr(p, k, v)
    return p


class _Raising:
    @property
    def expects(self):
        raise RuntimeError("hostile")


class _HostileSet(frozenset):
    def __iter__(self):
        raise RuntimeError("hostile __iter__")


@pytest.mark.parametrize(
    "prim, fragment",
    [
        (_with(expects="alpha"), "must be a set of str"),
        (_with(expects=frozenset({""})), "non-empty str"),
        (_with(expects=frozenset({1})), "non-empty str"),
        (_with(expects=frozenset({"a"}), expects_optional=frozenset({"a"})), "overlap"),
        (_Raising(), "raised RuntimeError"),
        (_with(expects=_HostileSet({"a"})), "iterating `expects` raised RuntimeError"),
        (_with(expects=frozenset(f"k{i}" for i in range(300))), "limit 256"),
    ],
)
def test_malformed_declaration(prim, fragment):
    out = dispatch._declared_inputs(prim)
    assert isinstance(out, str) and fragment in out, out


def test_absent_expects_is_undeclared_not_empty():
    assert isinstance(dispatch._declared_inputs(_P()), dispatch._Undeclared)
    only_optional = _with(expects_optional=frozenset({"q"}))
    assert isinstance(dispatch._declared_inputs(only_optional), dispatch._Undeclared)


def test_stated_empty_expects_and_absent_optional():
    assert dispatch._declared_inputs(_with(expects=frozenset())) == (
        frozenset(),
        frozenset(),
    )
    assert dispatch._declared_inputs(_with(expects=frozenset({"a"}))) == (
        frozenset({"a"}),
        frozenset(),
    )


# --- comparator_param_keys covers every key a comparator reads (derived) ---------------


def _keys_read(fn) -> set[str]:
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    out: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "params"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            out.add(node.args[0].value)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "params"
            and isinstance(node.slice, ast.Constant)
        ):
            out.add(node.slice.value)
    return out


@pytest.mark.parametrize("kind", sorted(_COMPARATOR_REGISTRY))
def test_comparator_param_keys_equal_what_the_comparator_reads(kind):
    fn = _COMPARATOR_REGISTRY[kind]
    read = _keys_read(fn)
    # helpers the band comparators delegate to read params too; follow one level
    import audit_bundle.rederivation.comparators as C

    for name in dir(C):
        obj = getattr(C, name)
        if callable(obj) and name.startswith("_") and name in fn.__code__.co_names:
            try:
                read |= _keys_read(obj)
            except (OSError, TypeError):
                pass
    if kind not in ("exact", "set"):  # the two kinds that take no params
        assert read, (
            f"{kind}: derived no reads — the walker is blind, not the comparator"
        )
    declared = comparator_param_keys(kind)
    assert read == declared, (
        f"{kind}: reads {sorted(read)} but comparator_param_keys says {sorted(declared)} "
        "— a key declared and never read is let through unread; a key read and not "
        "declared is refused on a valid binding"
    )
