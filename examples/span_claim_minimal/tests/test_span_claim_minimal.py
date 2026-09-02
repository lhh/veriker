"""Battery for span_claim_minimal — is this quotation really in that document?

What this pilot demonstrates, and what each surface below pins down:

  THE PUBLIC VERIFIER RUNS THE METHOD. `spectra_span_recompute` ships in the
  distribution. This is the public bundle it runs on: no demo-local
  `register_primitive`, no import of the primitive module, nothing but core
  auto-registration.

  TWO PINS, TWO QUESTIONS, BOTH LOAD-BEARING. Which document, and which sentence
  of it. Each has a counterfactual arm below showing the identical bundle
  verifying CLEAN once that pin is removed — so neither is decoration.

  THE READ IS CONTAINED. `source_cid` is bundle-controlled and interpolated into
  a path. A `..` traversal is refused rather than read, and the test proves that
  with the pins REMOVED, so it is the primitive's own containment being measured
  and not the pin catching the tamper first.

  WHAT A PASS DOES NOT SAY. `spectra_v1` normalizes away case and ALL
  punctuation. The committed fixture is built so this can be shown rather than
  described: sentence 2 of the source turns on a pair of commas, and a
  quotation that removes them says something else and still passes.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_PILOT = Path(__file__).resolve().parents[1]
_PKG_ROOT = _PILOT.parents[1]
for p in (str(_PKG_ROOT), str(_PILOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402

import _producer_extract as extractor  # noqa: E402

_BUILD = _PILOT / "_build_bundle.py"
_SPEC_SRC = _PILOT / "spec_pinned" / "span_claim.spec.json"
_OUTPUT_ID = "quoted_span"
_CLAIM_REL = f"outputs/{_OUTPUT_ID}.json"
_POINTER_REL = "inputs/span_claim.json"
_RECORD_REL = "payload/extraction_record.json"

#: The committed source's content address, read from the committed bundle rather
#: than restated -- a second copy of an identifier is a second thing to drift.
_CID = json.loads((_PILOT / "bundle" / _POINTER_REL).read_bytes())["source_cid"]
_CORPUS_REL = f"corpus/{_CID}.txt"

#: A quotation that is not in the source at all.
_HALLUCINATION = "The reviewers confirmed the contractor met every tolerance"

#: The same sentence with the two commas taken out and NOTHING else changed --
#: same words, same order, same case, same apostrophe. It says something
#: DIFFERENT (only the reviewers with telemetry access endorsed the figure) and
#: normalizes identically. Derived from the honest span rather than retyped, so
#: it cannot drift into being a multi-change variant: an earlier draft also
#: upper-cased two words and dropped an apostrophe, which made the shipped
#: demonstration broader than the claim the README makes about it.
_HONEST_SPAN = json.loads(
    (Path(__file__).resolve().parents[1] / "bundle" / "outputs" / "quoted_span.json")
    .read_bytes()
)["value"]
_REWORDED = _HONEST_SPAN.replace(",", "")


def _load_verify_module():
    """The pilot's verify.py by PATH under a pilot-unique module name (a bare
    `import verify` collides across pilots)."""
    spec = importlib.util.spec_from_file_location(
        "span_claim_minimal__verify", _PILOT / "verify.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(out_dir: Path, *, claimed_span=None, fragment_id=None) -> Path:
    cmd = [sys.executable, str(_BUILD), "--out-dir", str(out_dir)]
    if claimed_span is not None:
        cmd += ["--claimed-span", claimed_span]
    if fragment_id is not None:
        cmd += ["--fragment-id", str(fragment_id)]
    subprocess.run(cmd, check=True, capture_output=True)
    return out_dir


def _verify(bundle_dir: Path, spec_src: Path = _SPEC_SRC):
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier

    anchor = SpecAnchor.from_files([spec_src], forbid_within=bundle_dir)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def _realign(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _repoint(bundle_dir: Path, **fields) -> None:
    doc = json.loads((bundle_dir / _POINTER_REL).read_bytes())
    doc.update(fields)
    (bundle_dir / _POINTER_REL).write_bytes(
        (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    _realign(bundle_dir, _POINTER_REL)


def _unpin(bundle_dir: Path, tmp_path: Path, *, drop=("corpus", "pointer")) -> Path:
    """Re-ship the auditor's spec with SPECIFIC pins removed.

    `drop` names which pins to lift: "corpus" (which document) or "pointer"
    (which sentence of it). Both live under one type, so an earlier draft that
    popped `pinned_inputs` wholesale removed BOTH on every arm — and each
    counterfactual then rested on the tamper happening to leave the other pinned
    file untouched, rather than on the ablation isolating anything. Naming them
    separately makes each arm an actual single-pin ablation.

    The verifier resolves the authoritative spec from manifest.spec_files and
    checks its bytes against the anchor, so the bundle's own copy has to be
    swapped and re-pinned too. Returns the auditor spec path to anchor on.
    """
    spec = json.loads(_SPEC_SRC.read_bytes())
    for tdef in spec["types"].values():
        pins = tdef.get("pinned_inputs") or {}
        kept = {
            rel: sha
            for rel, sha in pins.items()
            if not (
                (rel.startswith("corpus/") and "corpus" in drop)
                or (rel == _POINTER_REL and "pointer" in drop)
            )
        }
        assert len(kept) == len(pins) - len(drop), (
            f"expected to drop {len(drop)} pin(s), dropped {len(pins) - len(kept)} "
            f"— the spec's pin names changed and this ablation is no longer "
            f"removing what it says"
        )
        if kept:
            tdef["pinned_inputs"] = kept
        else:
            tdef.pop("pinned_inputs", None)
    spec["spec_id"] = "span.claim.minimal.unpinned." + "-".join(sorted(drop)) + ".v1"
    raw = (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")

    unpinned = tmp_path / "unpinned.spec.json"
    unpinned.write_bytes(raw)
    (bundle_dir / "spec" / _SPEC_SRC.name).write_bytes(raw)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["spec_files"][_SPEC_SRC.name] = hashlib.sha256(raw).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return unpinned


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _details(result) -> str:
    return " | ".join(f.detail for f in result.failures)


def _rewrite_source_to_contain(bundle_dir: Path, sentence: str) -> None:
    """Edit the committed document so the quoted position holds `sentence`."""
    lines = (bundle_dir / _CORPUS_REL).read_text(encoding="utf-8").split("\n")
    lines[2] = sentence + "."
    (bundle_dir / _CORPUS_REL).write_text("\n".join(lines), encoding="utf-8")
    _realign(bundle_dir, _CORPUS_REL)


#: A plausible-but-wrong content address: 64 hex characters that are NOT the
#: sha256 of the decoy's bytes. Naming the decoy `decoy.txt` (an earlier draft)
#: would only have shown that the verifier resolves any name it is handed; this
#: shows the stronger thing the README claims -- a sha-SHAPED name is not
#: checked against the content it names.
_DECOY_CID = "f" * 64


def _add_decoy_corpus(bundle_dir: Path, sentence: str) -> None:
    """Ship a SECOND document beside the pinned one, containing `sentence`."""
    decoy = bundle_dir / "corpus" / f"{_DECOY_CID}.txt"
    decoy.write_text(f"alpha.\nbeta.\n{sentence}.\n", encoding="utf-8")
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][f"corpus/{_DECOY_CID}.txt"] = hashlib.sha256(decoy.read_bytes()).hexdigest()
    assert _DECOY_CID != m["files"][f"corpus/{_DECOY_CID}.txt"], (
        "the decoy's name must NOT be its own digest, or the test proves nothing"
    )
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


# --------------------------------------------------------------------------- #
# The honest bundle
# --------------------------------------------------------------------------- #


def test_honest_bundle_passes(tmp_path):
    result = _verify(_build(tmp_path / "b"))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_pilot_verify_entry_point_passes(tmp_path):
    mod = _load_verify_module()
    bundle = _build(tmp_path / "b")
    assert mod.make_verifier(bundle).verify(bundle).ok


def test_committed_bundle_passes():
    """The bundle checked into the repo is the one the README's commands run."""
    result = _verify(_PILOT / "bundle")
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# Gate B — the claim is the producer's, never the verifier's
# --------------------------------------------------------------------------- #


def _import_targets(path: Path) -> set[str]:
    """Every module path a file can reach, as dotted strings.

    `from x.y import z` yields BOTH `x.y` and `x.y.z`. Recording only
    `node.module` would miss one spelling entirely --
    `from audit_bundle.rederivation import primitives` has module
    `audit_bundle.rederivation`, and `primitives/__init__.py` eagerly imports
    every primitive module, so the verifier's extractor would be one attribute
    access away from a producer this check had just called clean.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, (
                f"{path.name}: relative import — this is a top-level script "
                "where that cannot bind, and it would be invisible to the check "
                "below"
            )
            if node.module:
                targets.add(node.module)
                targets |= {f"{node.module}.{a.name}" for a in node.names}
    return targets


def test_producer_does_not_import_the_verifier():
    """AST, not substring: both producer modules DISCUSS the rule in prose, so a
    text search matches its own documentation and proves nothing."""
    for mod in ("_build_bundle.py", "_producer_extract.py"):
        offending = {
            m
            for m in _import_targets(_PILOT / mod)
            if m == "audit_bundle.rederivation.primitives"
            or m.startswith("audit_bundle.rederivation.primitives.")
        }
        assert not offending, (
            f"{mod} imports the verifier's own primitive {sorted(offending)} — the "
            f"comparison would be f(x) == f(x)"
        )


def test_the_emitted_record_and_the_claim_agree(tmp_path):
    """A build-time consistency check, and NOT a disjointness proof.

    Both sides come from one value in `_build_bundle.py`, so this establishes
    that the span survives its round-trip into `payload/` unchanged and nothing
    more. It is filed away from Gate B on purpose. The disjointness claim is
    carried by `test_producer_does_not_import_the_verifier`; the agreement
    between producer and shipped verifier is carried by the honest PASS.
    """
    bundle = _build(tmp_path / "b")
    claimed = json.loads((bundle / _CLAIM_REL).read_bytes())["value"]
    emitted = json.loads((bundle / _RECORD_REL).read_bytes())["span"]
    assert claimed == emitted


def test_the_payload_record_is_not_bound_by_verification(tmp_path):
    """Dispatch reads the pointer, the corpus and the claim. It never opens
    `payload/extraction_record.json`, which is covered only by a
    producer-authored manifest SHA — so a payload contradicting the claim rides
    to a clean PASS. Anything a reader takes from that file, they take on the
    producer's word.

    Note what this does NOT undermine here, and does in the sibling
    `event_log_replay_minimal`: this pilot's pins fix which document and which
    sentence are under attestation, so an unbound payload is a loose ornament
    rather than a hole in the attestation itself."""
    bundle = _build(tmp_path / "b")
    path = bundle / _RECORD_REL
    doc = json.loads(path.read_bytes())
    doc["span"] = "something the document does not say at all"
    doc["fragment_count"] = 99
    path.write_bytes((json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    _realign(bundle, _RECORD_REL)

    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# The segmentation rule, as pinned
# --------------------------------------------------------------------------- #


def test_the_two_segmenters_agree_on_everything_tried():
    """HOW MUCH THE DUPLICATION BUYS, measured rather than assumed — and it is
    LESS here than in this pilot's siblings.

    The producer's `segment()` and the verifier's `_sentence_segments` are the
    same rule, and as far as can be measured the same function: the 20,000
    random documents below find no input on which they disagree. So an honest
    PASS shows the claim was
    not ROUTED THROUGH the verifier's code — structural, about where the value
    came from — and NOT that two behaviourally different programs agreed. If a
    future edit makes them diverge, this test is where it shows up.

    The verifier is imported here because this is an auditor-side test. The
    producer may not import it, which is what
    `test_producer_does_not_import_the_verifier` enforces.
    """
    import random
    import string

    from audit_bundle.rederivation.primitives import spectra_span

    alphabet = list(string.ascii_letters + string.digits + " .!?,\t\n'\"-")
    rng = random.Random(7)  # fixed seed: a flaky differential test is useless
    divergences = []
    for _ in range(20000):
        doc = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        if extractor.segment(doc) != spectra_span._sentence_segments(doc):
            divergences.append(doc)
    assert not divergences, divergences[:5]


def test_the_verifier_is_the_stricter_of_the_two(tmp_path):
    """The one real asymmetry between the copies, and it runs the safe way.

    Shown by BEHAVIOUR, not by grepping the sources. An earlier draft asserted
    `"resolve_within" in verifier_src and "out of range" in verifier_src` — a
    substring test on source text, the exact method this file condemns eighty
    lines above, and one whose docstring was wrong as well: the producer DOES
    range-check `fragment_id` (`_producer_extract.py`), so the only genuine
    asymmetry is path containment.

    Here it is exercised: a document placed OUTSIDE `corpus/` is read by the
    producer's extractor, which has no containment rule, and refused by the
    verifier's, which does. A pilot whose CHECKER were the laxer side would be
    the dangerous shape."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("A sentence the corpus does not contain.\n", encoding="utf-8")

    # The producer follows the traversal and reads the out-of-tree file.
    assert (
        extractor.extract(corpus, "../outside", 0)
        == "A sentence the corpus does not contain"
    )

    # The verifier refuses the same path.
    from audit_bundle.rederivation.primitives._safepath import resolve_within

    with pytest.raises(ValueError, match="resolves outside"):
        resolve_within(corpus, "../outside.txt")


def test_a_decimal_is_not_a_sentence_boundary():
    """The terminator rule excludes a `.` sitting between digits. The committed
    document contains `3.5 mm` precisely so this is exercised by the shipped
    fixture and not only by a unit test: without the exception the source would
    cut into six fragments and every fragment_id after the first would shift."""
    source = (_PILOT / "bundle" / _CORPUS_REL).read_text(encoding="utf-8")
    fragments = extractor.segment(source)
    assert len(fragments) == 5
    assert "3.5 mm" in fragments[1]


# --------------------------------------------------------------------------- #
# Tamper surfaces
# --------------------------------------------------------------------------- #


def test_mutant_hallucinated_quotation_fails(tmp_path):
    """THE MUTANT CONTROL. A quotation that is not in the document at all."""
    bundle = _build(tmp_path / "b", claimed_span=_HALLUCINATION)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"RE_DERIVATION_MISMATCH"}, _reason_codes(result)


def test_mutant_fails_through_the_shipped_entry_point(tmp_path):
    """The same mutant through `verify.py` itself: FAIL on stdout, exit 1."""
    bundle = _build(tmp_path / "b", claimed_span=_HALLUCINATION)
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "RE_DERIVATION_MISMATCH" in proc.stdout


# --------------------------------------------------------------------------- #
# Pin 1 — WHICH DOCUMENT
# --------------------------------------------------------------------------- #


def test_hallucination_with_the_source_rewritten_is_refused_by_the_pin(tmp_path):
    """Hallucinate a quotation, then edit the source document until the
    re-derivation returns it. The claim and the document now agree perfectly."""
    bundle = _build(tmp_path / "b", claimed_span=_HALLUCINATION)
    _rewrite_source_to_contain(bundle, _HALLUCINATION)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"PINNED_INPUT_MISMATCH"}, _reason_codes(result)


def test_the_same_rewritten_source_passes_UNPINNED(tmp_path):
    """The counterfactual. With `pinned_inputs` removed the identical bundle
    verifies CLEAN — the re-derivation really does reproduce the claim, from the
    document the producer supplied. The pin is what fixes WHICH document."""
    bundle = _build(tmp_path / "b", claimed_span=_HALLUCINATION)
    _rewrite_source_to_contain(bundle, _HALLUCINATION)
    # Lift ONLY the corpus pin. The pointer pin stays in force and is satisfied,
    # so what this measures is the corpus pin's own contribution.
    result = _verify(bundle, spec_src=_unpin(bundle, tmp_path, drop=("corpus",)))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# Pin 2 — WHICH SENTENCE OF IT
# --------------------------------------------------------------------------- #


def test_a_decoy_document_beside_the_pinned_one_is_refused(tmp_path):
    """The attack the corpus pin alone does NOT stop. Leave the pinned document
    untouched, ship a second one beside it, and repoint `source_cid`. Only the
    pin on the POINTER refuses this — and note what does not: the corpus
    filename is the sha256 of its own content by this pilot's convention, but
    the primitive resolves the name it is given and never checks that the name
    matches the bytes, so `decoy` resolves happily."""
    bundle = _build(tmp_path / "b", claimed_span=_HALLUCINATION)
    _add_decoy_corpus(bundle, _HALLUCINATION)
    _repoint(bundle, source_cid=_DECOY_CID)
    result = _verify(bundle)
    assert not result.ok
    assert _reason_codes(result) == {"PINNED_INPUT_MISMATCH"}, _reason_codes(result)


def test_the_same_decoy_passes_UNPINNED(tmp_path):
    """The counterfactual for pin 2, and the reason pinning the corpus alone
    would have been a false sense of security."""
    bundle = _build(tmp_path / "b", claimed_span=_HALLUCINATION)
    _add_decoy_corpus(bundle, _HALLUCINATION)
    _repoint(bundle, source_cid=_DECOY_CID)
    # Lift ONLY the pointer pin. The corpus pin stays in force -- and is
    # satisfied, because the pinned document was never touched. That is exactly
    # the point: pinning the document alone would have let this through.
    result = _verify(bundle, spec_src=_unpin(bundle, tmp_path, drop=("pointer",)))
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# --------------------------------------------------------------------------- #
# The read is contained — measured with the pins REMOVED
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "escape",
    [
        pytest.param("../inputs/span_claim", id="one-level-up-inside-the-bundle"),
        pytest.param("../../../../../../etc/passwd", id="traversal-out-of-the-bundle"),
        pytest.param("/etc/passwd", id="absolute-path"),
    ],
)
def test_source_cid_cannot_steer_a_read_out_of_the_corpus(tmp_path, escape):
    """`source_cid` is bundle-controlled and interpolated into a path, so a
    hostile bundle could otherwise turn the verifier's read into an
    arbitrary-file oracle on the AUDITOR's machine.

    THREE payloads, because one was not enough. An earlier draft tested only
    `../inputs/span_claim`, which resolves one directory up and stays INSIDE the
    bundle — so it never exercised the threat the containment rule is written
    for. The other two are the ones `_safepath.resolve_within` names: a traversal
    out of the bundle root, and an absolute path that discards the root entirely.
    Both name a file that exists on the auditor's machine, so a missing-file
    error could not be mistaken for containment.

    Run with the POINTER pin removed on purpose. With it in place this tamper is
    caught before the recompute reads anything, which would make the test a
    measurement of the pin rather than of the containment."""
    bundle = _build(tmp_path / "b")
    _repoint(bundle, source_cid=escape)
    result = _verify(bundle, spec_src=_unpin(bundle, tmp_path, drop=("pointer",)))
    assert not result.ok
    assert _reason_codes(result) == {"RECOMPUTE_ERROR"}, _reason_codes(result)
    assert "resolves outside" in _details(result), _details(result)


def test_fragment_id_out_of_range_is_refused(tmp_path):
    """Also measured unpinned, for the same reason."""
    bundle = _build(tmp_path / "b")
    _repoint(bundle, fragment_id=99)
    result = _verify(bundle, spec_src=_unpin(bundle, tmp_path, drop=("pointer",)))
    assert not result.ok
    assert _reason_codes(result) == {"RECOMPUTE_ERROR"}, _reason_codes(result)
    assert "out of range" in _details(result)


# --------------------------------------------------------------------------- #
# The scope limit, demonstrated rather than described
# --------------------------------------------------------------------------- #


def test_a_quotation_that_changes_what_the_sentence_says_PASSES(tmp_path):
    """THE SCOPE LIMIT WITH TEETH.

    `spectra_v1` normalizes by NFC, casefold, DROPPING ALL PUNCTUATION,
    collapsing whitespace and stripping. The committed sentence is

        The reviewers, who had access to the raw telemetry, endorsed the
        contractor's figure

    -- a non-restrictive clause: ALL the reviewers endorsed it, and the
    telemetry access is an aside. Take the two commas out and the clause becomes
    restrictive: only the reviewers who had telemetry access endorsed it. That
    is a different claim about the same words, and this comparator cannot see
    the difference, so the bundle verifies CLEAN.

    Not a defect in the primitive — it is what the anchored normalization
    profile says it does. Shipped as a passing test so that adopting the profile
    is a decision rather than an assumption."""
    bundle = _build(tmp_path / "b", claimed_span=_REWORDED)
    result = _verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]

    # And the variant really is the minimal one the prose describes: it differs
    # from the honest span ONLY by the removal of commas. Without this, a
    # multi-change variant would demonstrate something broader than the claim.
    assert _REWORDED != _HONEST_SPAN
    assert "," in _HONEST_SPAN and "," not in _REWORDED
    assert _HONEST_SPAN.replace(",", "") == _REWORDED
    assert _HONEST_SPAN.count(",") == 2


# --------------------------------------------------------------------------- #
# The anchor may not come from inside the bundle
# --------------------------------------------------------------------------- #


def test_anchor_taken_from_inside_the_bundle_is_refused(tmp_path):
    bundle = _build(tmp_path / "b")
    with pytest.raises(Exception) as exc:
        SpecAnchor.from_files([bundle / "spec" / _SPEC_SRC.name], forbid_within=bundle)
    assert "INSIDE" in str(exc.value).upper() or "within" in str(exc.value).lower()


def test_bundle_dir_at_the_pilot_root_is_COULD_NOT_CONCLUDE_not_a_reject():
    """An unusable anchor is an OPERATOR error — no verdict about the artifact
    was formed — so it must route to could-not-conclude (exit 2), NEVER to a
    REJECT (exit 1). Letting it escape `main()` as a traceback also exits 1,
    which is the same wrong answer wearing a stack trace."""
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(_PILOT)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "COULD NOT CONCLUDE" in proc.stdout
    assert "Traceback" not in proc.stderr


# --------------------------------------------------------------------------- #
# Reachable by the shipped CLI with no pilot code
# --------------------------------------------------------------------------- #


def _cli(bundle_dir: Path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "veriker.cli.verify",
            "--bundle-dir",
            str(bundle_dir),
            "--spec-anchor",
            str(_SPEC_SRC),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_the_shipped_CLI_verifies_this_bundle(tmp_path):
    proc = _cli(_build(tmp_path / "b"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_shipped_CLI_rejects_the_mutant(tmp_path):
    proc = _cli(_build(tmp_path / "b", claimed_span=_HALLUCINATION))
    assert proc.returncode == 1, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# Nothing re-derived must not read as PASS
# --------------------------------------------------------------------------- #


def test_deleting_manifest_outputs_no_longer_makes_the_dispatch_inert(tmp_path):
    """THE FAIL-OPEN THIS PILOT USED TO SHIP, now closed in the substrate.

    `manifest.outputs` is a producer-authored declaration of what to check.
    Deleting it -- three lines -- USED TO make spec-pinned dispatch inert:
    every pinned byte still matched, every plugin still passed, and a
    `BundleVerifier` returned ok=True having re-derived nothing at all. The
    adversary who can realign the manifest for any other tamper in this file
    could do this one instead, and it was strictly easier.

    Two stacked early returns on `not outputs` -- one in
    `BundleVerifier._step_spec_pinned_dispatch`, one in
    `run_spec_pinned_dispatch` -- skipped the SS4a.4 coverage invariant, the
    guard written to catch exactly this. Partial omission (drop one entry of
    several) engaged dispatch and fired COVERAGE_MISMATCH; total omission
    returned OK. Both returns are now file-presence-triggered, so a bundle
    that ships outputs/*.json while declaring none is refused, and a bundle
    with no outputs/ tree at all stays inert as before.

    This assertion is INVERTED from the one this test shipped with. It is not
    a relaxed expectation: the pilot-level mitigation below is now defence in
    depth behind a substrate fix, rather than the only thing standing between
    a forged claim and a clean PASS.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    assert manifest.pop("outputs", None), "fixture declares no outputs to delete"
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    result = _verify(bundle)
    assert not result.ok, "deleting manifest.outputs must no longer read as clean"
    assert "COVERAGE_MISMATCH" in {r.code for r in result.reasons}, [
        (r.check_name, r.code) for r in result.reasons
    ]


def test_the_shipped_entry_point_REFUSES_the_inert_bundle(tmp_path):
    """And the closure, now STRONGER than when this test was written.

    `verify.py` builds its verifier with `require_rederivation=True`, which
    used to be the only thing refusing this bundle -- and it refused as
    COULD NOT CONCLUDE at exit 2, on the reasoning that nothing had been shown
    wrong with the artifact and the verifier had merely been prevented from
    concluding.

    That reasoning no longer holds, so neither does the exit code. The
    coverage invariant now shows something IS wrong with the artifact: it
    ships an output file its own manifest does not declare. That is an
    artifact-side finding, so it is a REJECT at exit 1 naming
    COVERAGE_MISMATCH, not a could-not-conclude.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest.pop("outputs", None)
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    assert "COVERAGE_MISMATCH" in proc.stdout, proc.stdout


def test_require_rederivation_still_owns_the_no_outputs_tree_case(tmp_path):
    """The case the coverage invariant CANNOT see, and the flag still does.

    SS4a.4 coverage triggers on files present at `outputs/*.json`. A producer
    who removes the declaration AND the tree leaves coverage nothing to count
    -- and the same is true of the cheaper restages coverage misses (rename
    `outputs/` to `results/`, nest a subdir, change the extension). Here
    nothing is re-derived and nothing is provably wrong with the artifact, so
    this is a COULD NOT CONCLUDE at exit 2, and `require_rederivation=True` is
    the only reason it is not a clean PASS.

    This replaces the exit-2 assertion that the coverage hoist moved to exit 1
    in the test above: without it, no test in this battery would pin the
    entry point's NO_RE_DERIVATION_PERFORMED -> exit 2 mapping any more.
    """
    bundle = _build(tmp_path / "b")
    mp = bundle / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest.pop("outputs", None)
    if isinstance(manifest.get("files"), dict):
        for rel in [k for k in manifest["files"] if k.startswith("outputs/")]:
            manifest["files"].pop(rel)
    shutil.rmtree(bundle / "outputs", ignore_errors=True)
    mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))

    proc = subprocess.run(
        [sys.executable, str(_PILOT / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert "COULD NOT CONCLUDE" in proc.stdout
    assert "VERIFIER_INCOMPLETE" in proc.stdout
