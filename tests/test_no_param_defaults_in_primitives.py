"""No re-derivation primitive supplies a default for a binding param.

A binding param is the ASKER's (a tolerance, a confidence level, a coverage floor, a
root digest). A primitive that reads one as `params.get("alpha", 0.975)` computes at a
value nobody stated whenever the spec is silent or misspelt — an `alhpa` typo in the expected-shortfall pilot
case, and `conditioning_bound` defaulting to False inside fea_witness_cert. The
contract (the declared-inputs contract) is that the primitive DECLARES the key in
`expects`, dispatch refuses a binding that omits it, and the primitive reads it
without a default.

WHAT THIS RATCHETS: over every module in this tree that defines a primitive
(`primitive_id = ...`, tests and bundle builders excluded — the same population the
literal census walked), no call `<params>.get("<key>", <non-None literal>)` where the
receiver is the params mapping (`params`, `*.params`, or a subscript `[...]["params"]`).

WHAT IT DOES NOT: it does not see a default written any other way (`or 0.975`,
`if k not in params: k = ...`), nor a demand the primitive holds as a module constant,
nor one it reads out of the producer's own bundle. Those are a reviewer's
job; they exist in numbers this test cannot see.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_EXCLUDE = {"tests", "test", "spikes", "__pycache__"}


def _primitive_modules() -> list[Path]:
    out = []
    for p in sorted(_ROOT.rglob("*.py")):
        rel = p.relative_to(_ROOT)
        if (
            _EXCLUDE & set(rel.parts)
            or p.name.startswith("test_")
            or p.name == "_build_bundle.py"
        ):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if "primitive_id" in text and (
            "primitive_id =" in text or "primitive_id: str =" in text
        ):
            out.append(p)
    return out


def _is_params_receiver(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "params"
    if isinstance(node, ast.Attribute):
        return node.attr == "params"
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value == "params"
    if isinstance(node, ast.Call):  # pack_section.get("params") / ... or {}
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "params"
        )
    if isinstance(node, ast.BoolOp):
        return any(_is_params_receiver(v) for v in node.values)
    return False


def _defaults(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and len(node.args) == 2
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and not (
                isinstance(node.args[1], ast.Constant) and node.args[1].value is None
            )
            and _is_params_receiver(node.func.value)
        ):
            hits.append(
                f"{path.relative_to(_ROOT)}:{node.lineno} params.get({node.args[0].value!r}, ...)"
            )
    return hits


def test_population_covers_every_registered_primitive_module():
    """Non-vacuity without a fleet count (the public drop ships fewer examples):
    every module that registers a built-in primitive is in the walked population."""
    from audit_bundle.rederivation import registry

    registry._ensure_primitives_loaded()
    walked = {p.resolve() for p in _primitive_modules()}
    sources = set()
    for pid in registry.registered_primitives():
        mod = type(registry.resolve_primitive(pid)).__module__
        f = getattr(__import__(mod, fromlist=["_"]), "__file__", None)
        if f and Path(f).resolve().is_relative_to(_ROOT):
            sources.add(Path(f).resolve())
    assert sources, "no built-in primitive module found — the check is blind"
    missing = sorted(str(s.relative_to(_ROOT)) for s in sources - walked)
    assert not missing, f"walker misses primitive modules: {missing}"


def test_no_primitive_defaults_a_binding_param():
    hits = [h for p in _primitive_modules() for h in _defaults(p)]
    assert not hits, (
        "a primitive supplies a default for a binding param; declare it in "
        "`expects` and read it without a default (the declared-inputs contract):\n  "
        + "\n  ".join(hits)
    )


def test_the_walker_sees_a_planted_default(tmp_path):
    """Null control: the pattern this ratchet exists for is detected."""
    p = tmp_path / "m.py"
    p.write_text(
        'class P:\n    primitive_id = "x"\n'
        "    def recompute(self, inputs, pack_section):\n"
        '        params = pack_section.get("params") or {}\n'
        '        a = params.get("alpha", 0.975)\n'
        '        b = pack_section["params"].get("beta", 1)\n'
    )
    global _ROOT
    saved, _ROOT = _ROOT, tmp_path
    try:
        assert len(_defaults(p)) == 2
    finally:
        _ROOT = saved
