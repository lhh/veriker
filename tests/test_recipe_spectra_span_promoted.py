"""tests/test_recipe_spectra_span_promoted.py — the `extractive span` shape is
PROMOTED into the shippable core registry (PRIMITIVES.md).

BACKFILL (2026-08-29). `spectra_span_recompute` is one of the primitives that
predate the promotion loop and never got a `test_recipe_*_promoted.py`. That
mattered twice over: the disjointness guard auto-discovers from these files, so
the primitive sat outside the structural non-tautology guard's promoted-test
source. (Its discovery was separately widened to key on binding a distribution
primitive; this file closes the promoted-test half.)

IT POINTS AT THE PUBLIC PILOT, and that is the difference from its sibling
`test_recipe_fea_vonmises_promoted.py`. That one exercises a pilot excluded from
the open drop, so it had to be publish-excluded too — it names its pilot inside
test functions, the standalone COLLECTION gate passes, and the failure only
appears at RUN time in a clean clone. This file targets
`examples/span_claim_minimal`, which ships, so it runs in the drop like any
other test.

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing resolving the recompute is core
  auto-registration (run_spec_pinned_dispatch -> _ensure_primitives_loaded ->
  import primitives -> spectra_span self-registers). Unpromoted, dispatch would
  fail UNKNOWN_PRIMITIVE.

  PRODUCER PROVENANCE, which is weaker than faithfulness and is named that way
  on purpose. The claimed span is segmented by
  `examples/span_claim_minimal/_producer_extract.py`, and neither producer module
  imports the primitive (asserted below by AST). But that copy and the verifier's
  are the same rule and, as far as can be measured, the same function — a
  differential fuzz in the pilot's own battery finds no input on which they
  differ. So this proves the claim was not ROUTED THROUGH the verifier's code. It
  does NOT prove two behaviourally different programs agreed, and calling it
  "not f(x)==f(x)" would be selling a structural fact in the vocabulary of a
  behavioural one.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed span -> RE_DERIVATION_MISMATCH.
  3. Tampered SOURCE DOCUMENT -> RE_DERIVATION_MISMATCH. Run against a spec with
     `pinned_inputs` stripped, on purpose: with the pins in place the auditor
     refuses this before the recompute reads anything (PINNED_INPUT_MISMATCH),
     which would measure the pin instead of the re-derivation. The pinned
     behaviour is covered by the pilot's own battery.

Stdlib-only orchestration; the build runs the pilot's real producer.
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/spectra_span.py) is
# deliberately NOT imported here. The claim comes from the producer artifact, and
# the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "span_claim_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "span_claim.spec.json"
_OUTPUT_ID = "quoted_span"
_CLAIM_REL = f"outputs/{_OUTPUT_ID}.json"
_RECORD_REL = "payload/extraction_record.json"
_POINTER_REL = "inputs/span_claim.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_span: str | None = None) -> Path:
    cmd = [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)]
    if claimed_span is not None:
        cmd += ["--claimed-span", claimed_span]
    subprocess.run(cmd, check=True, capture_output=True)
    return out_dir


def _corpus_rel(bundle_dir: Path) -> str:
    cid = json.loads((bundle_dir / _POINTER_REL).read_bytes())["source_cid"]
    return f"corpus/{cid}.txt"


def _realign(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _unpinned_spec(bundle_dir: Path, tmp_path: Path) -> Path:
    """The auditor's spec with `pinned_inputs` removed, re-shipped in the bundle
    so its bytes still match the anchor."""
    spec = json.loads(_SPEC_SRC.read_bytes())
    for tdef in spec["types"].values():
        tdef.pop("pinned_inputs", None)
    spec["spec_id"] = "span.claim.minimal.unpinned.v1"
    raw = (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")

    out = tmp_path / "unpinned.spec.json"
    out.write_bytes(raw)
    (bundle_dir / "spec" / _SPEC_SRC.name).write_bytes(raw)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["spec_files"][_SPEC_SRC.name] = _sha256(raw)
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out


def _verify(bundle_dir: Path, spec_src: Path = _SPEC_SRC):
    anchor = SpecAnchor.from_files([spec_src], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    """Honest bundle: the CORE primitive re-derives the PRODUCER's independently
    extracted span, resolved purely by auto-registration."""
    result = _verify(_build(tmp_path / "bundle"))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_claim_is_the_producers_own_artifact(tmp_path):
    """Non-tautology, asserted structurally: the claim equals the producer's own
    emitted record, and the producer never imports the verifier's recompute."""
    bundle_dir = _build(tmp_path / "bundle")
    claimed = json.loads((bundle_dir / _CLAIM_REL).read_bytes())["value"]
    produced = json.loads((bundle_dir / _RECORD_REL).read_bytes())["span"]
    assert claimed == produced, "claim was not taken from the producer's payload"

    # AST, not substring. The sibling promoted tests assert
    # `"audit_bundle.rederivation.primitives" not in src`, which is a text
    # search over a file that DISCUSSES the rule in its own docstring: run it
    # against a producer that documents why it must not import the primitive and
    # it fails on the documentation. (Measured here — that assertion is what
    # this test failed on first.) A producer that imported the package while
    # never naming it in prose would pass the text search and fail this.
    for module in ("_build_bundle.py", "_producer_extract.py"):
        tree = ast.parse((_PILOT_DIR / module).read_text(encoding="utf-8"))
        targets: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                targets.add(node.module)
                targets |= {f"{node.module}.{a.name}" for a in node.names}
        offending = {
            t
            for t in targets
            if t == "audit_bundle.rederivation.primitives"
            or t.startswith("audit_bundle.rederivation.primitives.")
        }
        assert not offending, (
            f"{module} imports the core primitives {sorted(offending)} — the "
            f"claimed span would be the verifier's own output and this test "
            f"would be f(x)==f(x)"
        )


def test_promoted_tampered_claim_fails(tmp_path):
    bundle_dir = _build(
        tmp_path / "bundle",
        claimed_span="The reviewers confirmed the contractor met every tolerance",
    )
    result = _verify(bundle_dir)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_source_document_fails(tmp_path):
    """Edit the sentence at the quoted position. The claim is untouched and the
    manifest is realigned, so only the re-derivation can object.

    Deliberately run UNPINNED — see the module docstring, surface 3."""
    bundle_dir = _build(tmp_path / "bundle")
    corpus_rel = _corpus_rel(bundle_dir)
    lines = (bundle_dir / corpus_rel).read_text(encoding="utf-8").split("\n")
    lines[2] = "The reviewers declined to endorse the figure."
    (bundle_dir / corpus_rel).write_text("\n".join(lines), encoding="utf-8")
    _realign(bundle_dir, corpus_rel)

    result = _verify(bundle_dir, spec_src=_unpinned_spec(bundle_dir, tmp_path))
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)
