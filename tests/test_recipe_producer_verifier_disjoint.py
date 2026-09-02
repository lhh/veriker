"""tests/test_recipe_producer_verifier_disjoint.py — STRUCTURAL guard for the
recipe-book Gate B (producer↔verifier non-tautology).

Every promoted re-derivation recipe ships a `test_recipe_<shape>_promoted.py` that
proves the verifier's recompute agrees with the producer's INDEPENDENTLY-emitted
artifact (not f(x)==f(x)). That non-tautology rests on a structural property that
the per-recipe tests cannot themselves observe: the producer build script
(`examples/<pilot>/_build_bundle.py`) must compute its emitted artifact WITHOUT
importing the verifier's recompute path — neither the core primitives
(`audit_bundle.rederivation.primitives.*`) nor the pilot's re-export shim
(`<shape>_recompute`, which now re-exports the core class).

If a future edit wired a promoted pilot's producer to import the core `compute_*`
(e.g. "to avoid duplicating the algorithm"), the producer artifact would become
the verifier's own output, every promoted test would silently degrade to
f(x)==f(x) while still passing GREEN, and the drift-detection capability the
recipe-book advertises would be hollow. This guard fails closed on exactly that
regression.

Scope (widened 2026-08-29): TWO discovery sources, because the original one was
a proxy that missed cases.

  (1) PROMOTED recipes — auto-discovered from tests/test_recipe_*_promoted.py.
  (2) DISTRIBUTION-BINDING pilots — any pilot whose spec_pinned/*.spec.json binds
      a primitive_id that ships in audit_bundle/rederivation/primitives/.

(1) alone was the wrong criterion. What earns the guard is CLAIMING THE
CORE-REGISTRY PROPERTY — i.e. binding a distribution primitive — not happening to
have a promoted test. Six primitives predate the promotion loop and never got
one (climate_emission, fea_vonmises, fea_witness_cert, spectra_span, and the two
gaci_*), so their pilots sat outside the guard while still binding core code.
examples/climate_emission_minimal was in fact violating: its _build_bundle.py
imported compute_total straight from the core primitive, so its claimed total was
the verifier's own output (fixed 2026-08-29 by examples/climate_emission_minimal/
_producer_compute.py).

Non-promoted pilots that bind NO distribution primitive may still legitimately
share a demo-local recompute helper between producer and their own verify path —
they claim no core-registry property, so they remain out of scope.

Mechanism: static AST import analysis (no execution). For each pilot we read
`_PILOT_DIR` / `_BUILD_SCRIPT`, identify the pilot's re-export shim module stems
(the `*_recompute.py` files whose source imports the core primitives package),
then assert that NO module in the producer's compute surface imports the core
primitives package, and that the build script imports no shim stem.

WIDENED TWICE on 2026-08-29, both times by an adversarial pass finding the guard
enforcing the letter of its rule:

  * The surface is no longer `_build_bundle.py` alone. A pilot that moves its
    arithmetic into a sibling module left an entry script whose only local
    import was inert, and the file computing the claim was never opened. See
    `_producer_modules` for the two sources that close it and for the residual
    it does NOT close.
  * `from x.y import z` now contributes `x.y.z` and not only `x.y`. See
    `_imported_module_paths` for the one spelling that walked straight past.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
_TESTS_DIR = _PKG_ROOT / "tests"
_EXAMPLES_DIR = _PKG_ROOT / "examples"

_CORE_PRIMITIVES_PKG = "audit_bundle.rederivation.primitives"
_PRIMITIVE_ID_RE = re.compile(r'primitive_id\s*(?::\s*str)?\s*=\s*"([^"]+)"')
_PILOT_DIR_RE = re.compile(
    r'_PILOT_DIR\s*=\s*_PKG_ROOT\s*/\s*"examples"\s*/\s*"([^"]+)"'
)


def _promoted_pilot_dirs() -> list[tuple[str, Path]]:
    """Auto-discover (test_name, pilot_dir) for every promoted recipe."""
    out: list[tuple[str, Path]] = []
    for test_path in sorted(_TESTS_DIR.glob("test_recipe_*_promoted.py")):
        m = _PILOT_DIR_RE.search(test_path.read_text(encoding="utf-8"))
        assert m, (
            f"{test_path.name} has no recognizable _PILOT_DIR assignment; the "
            f"disjointness guard cannot locate its producer build script"
        )
        pilot_dir = _EXAMPLES_DIR / m.group(1)
        assert pilot_dir.is_dir(), (
            f"{test_path.name} points at missing pilot {pilot_dir}"
        )
        out.append((test_path.name, pilot_dir))
    return out


def _distribution_primitive_ids() -> set[str]:
    """primitive_ids shipping in the distribution, read STATICALLY from the
    primitives package (no import — the guard stays a pure AST/text analysis)."""
    ids: set[str] = set()
    prim_dir = _PKG_ROOT / "audit_bundle" / "rederivation" / "primitives"
    for py in prim_dir.glob("*.py"):
        ids |= set(_PRIMITIVE_ID_RE.findall(py.read_text(encoding="utf-8")))
    return ids


def _distribution_binding_pilot_dirs() -> list[tuple[str, Path]]:
    """(reason, pilot_dir) for every pilot whose auditor spec binds a primitive
    that ships in the distribution — i.e. every pilot claiming the core-registry
    property, whether or not it has a promoted test."""
    dist = _distribution_primitive_ids()
    assert len(dist) >= 20, (
        f"only {len(dist)} distribution primitive_ids parsed — the static scan "
        f"broke and the guard would be silently scoped to nothing"
    )
    out: list[tuple[str, Path]] = []
    for pilot_dir in sorted(_EXAMPLES_DIR.iterdir()):
        if not pilot_dir.is_dir():
            continue
        bound: set[str] = set()
        for spec_path in sorted(pilot_dir.glob("spec_pinned/*.spec.json")):
            try:
                spec = json.loads(spec_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):  # pragma: no cover - defensive
                continue
            for tdef in (spec.get("types") or {}).values():
                pid = tdef.get("primitive_id")
                if pid in dist:
                    bound.add(pid)
        if bound:
            out.append((f"binds distribution primitive(s) {sorted(bound)}", pilot_dir))
    return out


def _shim_module_stems(pilot_dir: Path) -> set[str]:
    """Module stems in pilot_dir that re-export the core primitives (shims)."""
    stems: set[str] = set()
    for py in pilot_dir.glob("*_recompute.py"):
        if _CORE_PRIMITIVES_PKG in py.read_text(encoding="utf-8"):
            stems.add(py.stem)
    return stems


def _imported_module_paths(py_path: Path) -> set[str]:
    """Every module path a file can reach by import, as dotted strings.

    WIDENED 2026-08-29 after an adversarial pass: `from x.y import z` now yields
    BOTH `x.y` and `x.y.z`. Recording only `node.module` let one spelling walk
    straight past this guard --

        from audit_bundle.rederivation import primitives

    -- whose `node.module` is `audit_bundle.rederivation`, which matches
    neither the package nor its dotted prefix, while
    `primitives/__init__.py` eagerly imports every primitive module, so
    `primitives.fea_vonmises.compute_sigma_vm_max(...)` was fully reachable
    from a producer the guard had just called clean.
    """
    plain, from_imports = _imported_symbols(py_path)
    paths: set[str] = set(plain)
    for module, names in from_imports.items():
        paths.add(module)
        for name in names:
            paths.add(f"{module}.{name}")
    return paths


def _imported_symbols(py_path: Path) -> tuple[set[str], dict[str, set[str]]]:
    """The single import walk both guards read.

    Returns `(plain_imports, {module: names bound by `from module import ...`})`.
    `_imported_module_paths` is DERIVED from this rather than walking the tree a
    second time: two walks of the same tree is the duplicated-helper shape this
    codebase keeps finding, and here the copies would answer the same question
    at different granularities, so a drift would be invisible until a producer
    used the spelling only one of them saw.

    level>0 (relative) has no absolute module name to resolve; these pilots are
    top-level scripts where a relative import cannot bind, so absolute-only is
    the whole population rather than a gap.
    """
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    plain: set[str] = set()
    from_imports: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                plain.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                from_imports.setdefault(node.module, set()).update(
                    alias.name for alias in node.names
                )
    return plain, from_imports


def _producer_modules(pilot_dir: Path, build_script: Path) -> list[Path]:
    """The producer's whole compute surface, not just its entry script.

    WIDENED 2026-08-29 after an adversarial pass. Scanning `_build_bundle.py`
    alone was a guard against the letter of the rule: a pilot that moves its
    arithmetic into a sibling module leaves an entry script whose only local
    import is inert, and the file that actually computes the claim is never
    opened. Two sources close it:

      (1) ONE HOP -- every pilot-local module the build script imports by name.
      (2) NAMING  -- every `_producer*.py` in the pilot dir, so a producer copy
          that is loaded some other way is still read.

    RESIDUAL, named rather than implied: a module loaded through
    `importlib.util.spec_from_file_location` is invisible to a static import
    walk. examples/climate_emission_minimal loads `_producer_compute.py` exactly
    that way; source (2) is what covers it, and a future pilot that both hides
    its producer behind importlib AND declines the `_producer*` naming would sit
    outside this guard again.
    """
    found = {build_script}
    for name in sorted(_imported_module_paths(build_script)):
        local = pilot_dir / f"{name}.py"
        if local.is_file():
            found.add(local)
    for local in sorted(pilot_dir.glob("_producer*.py")):
        found.add(local)
    return sorted(found)


def test_promoted_recipes_have_tests():
    """Sanity: the guard found promoted recipes to protect (else it's vacuous)."""
    pilots = _promoted_pilot_dirs()
    assert len(pilots) >= 10, (
        f"expected the full promoted set, found only {len(pilots)} "
        f"test_recipe_*_promoted.py — guard may be silently scoped to nothing"
    )


def test_promoted_producers_do_not_import_verifier_recompute():
    """The load-bearing guard: no promoted producer imports the core primitives
    or its pilot's re-export shim."""
    violations: list[str] = []
    for test_name, pilot_dir in _promoted_pilot_dirs():
        build_script = pilot_dir / "_build_bundle.py"
        if not build_script.is_file():
            # Some pilots build via a differently-named producer; the promoted
            # test names the real one in _BUILD_SCRIPT. Fall back to that.
            test_src = (_TESTS_DIR / test_name).read_text(encoding="utf-8")
            bm = re.search(r'_BUILD_SCRIPT\s*=\s*_PILOT_DIR\s*/\s*"([^"]+)"', test_src)
            assert bm, (
                f"{test_name}: no _build_bundle.py and no _BUILD_SCRIPT to fall back to"
            )
            build_script = pilot_dir / bm.group(1)
        assert build_script.is_file(), f"{test_name}: producer {build_script} missing"

        shim_stems = _shim_module_stems(pilot_dir)
        for module in _producer_modules(pilot_dir, build_script):
            imported = _imported_module_paths(module)
            core_hits = {
                p
                for p in imported
                if p == _CORE_PRIMITIVES_PKG or p.startswith(_CORE_PRIMITIVES_PKG + ".")
            }
            shim_hits = imported & shim_stems
            rel = module.relative_to(_EXAMPLES_DIR).as_posix()

            if core_hits:
                violations.append(
                    f"{rel} imports the CORE primitives "
                    f"{sorted(core_hits)} — producer artifact would equal the "
                    f"verifier's recompute, making {test_name} a tautology"
                )
            if shim_hits and module == build_script:
                violations.append(
                    f"{rel} imports the re-export shim "
                    f"{sorted(shim_hits)} (which re-exports the core primitive) — "
                    f"same tautology risk for {test_name}"
                )

    assert not violations, "producer↔verifier disjointness broken:\n  " + "\n  ".join(
        violations
    )


def test_distribution_binding_pilots_are_discovered():
    """Sanity: source (2) found pilots to protect (else it is vacuous)."""
    pilots = _distribution_binding_pilot_dirs()
    assert len(pilots) >= 15, (
        f"expected the distribution-binding set, found only {len(pilots)} — "
        f"spec discovery may be silently scoped to nothing"
    )


def test_distribution_binding_producers_do_not_import_verifier_recompute():
    """The widened guard: no producer of a pilot that BINDS a distribution
    primitive may compute its claim with the verifier's own code.

    This is the criterion the promoted-test proxy missed — see the module
    docstring for the climate_emission_minimal case it failed to catch.
    """
    violations: list[str] = []
    for reason, pilot_dir in _distribution_binding_pilot_dirs():
        build_script = pilot_dir / "_build_bundle.py"
        if not build_script.is_file():
            continue  # producer named elsewhere; source (1) covers promoted ones
        shim_stems = _shim_module_stems(pilot_dir)
        for module in _producer_modules(pilot_dir, build_script):
            imported = _imported_module_paths(module)
            core_hits = {
                p
                for p in imported
                if p == _CORE_PRIMITIVES_PKG or p.startswith(_CORE_PRIMITIVES_PKG + ".")
            }
            shim_hits = imported & shim_stems
            rel = module.relative_to(_EXAMPLES_DIR).as_posix()
            if core_hits:
                violations.append(
                    f"{rel} imports the CORE primitives "
                    f"{sorted(core_hits)} while {pilot_dir.name} {reason} — the "
                    f"claimed value would be the verifier's own output (f(x)==f(x))"
                )
            if shim_hits and module == build_script:
                violations.append(
                    f"{rel} imports the re-export shim "
                    f"{sorted(shim_hits)} while {pilot_dir.name} {reason} — same "
                    f"tautology"
                )

    assert not violations, (
        "producer↔verifier disjointness broken (distribution-binding scope):\n  "
        + "\n  ".join(violations)
    )
