"""Closed spec declarations: an unknown key in a binding spec is a refusal.

One F U19 census (input_declaration_census/CENSUS.md §2.1.1), U20 item B1.
`spec_binding.parse_spec` used to read each type body and each comparator object
with `.get()` and nothing else, so a key it did not know was silently ignored.
The strongest census finding (`probes/F/probe_pins.out` `[p4_typo_key] ok=True`):
an auditor who misspells `pinned_inputs` as `pinned_imputs` drops EVERY pin, and
a decoy forgery the pins would have refused verifies clean. Each of those objects
is now closed with the shared `assert_exact_keys` (UNKNOWN_SPEC_KEY).

The spec object's TOP level stays open, by declared intent: it is a shared
auditor document whose other sections other auditor-side readers own (the gaci
agent's anchored spec carries ten). The two keys spec_binding reads there are
required, so their misspelling fails closed; that is pinned below too. Open is
NOT open to the keys spec_binding reads one level down: a top-level
`pinned_inputs` (the B1 review's witness -- ignored, the type ran unpinned, the
decoy RELEASEd exit 0), `primitive_id`, `comparator`, `kind` or `params` is
refused with UNKNOWN_SPEC_KEY, same class/exit as the closure below it. That
refused set is `_SPEC_TOP_KEYS_REFUSED`, derived from the closure's own key sets
and pinned by the AST test equal to the keys `parse_spec` reads below the top.

Blame follows the declaration's author (One F rule 8, H4): the spec under test
here is anchored by the AUDITOR (the anchor is built from an out-of-bundle copy
of exactly those bytes), so the error is the auditor's -> could-not-conclude
(ERROR, exit 2), the same verdict class as MISSING_SPEC_PARAM. A stray key in an
in-bundle spec the anchor does NOT list is artifact bytes -> REJECT, so a producer
cannot plant one to demote an AnchorViolation REJECT to an ERROR.

Arms:
  * witness  -- the census typo + decoy, now refused (was ok=True);
  * control  -- the same decoy under the committed full-pin spec is refused
                (PINNED_INPUT_MISMATCH), so the decoy really is a forgery;
  * positive -- every committed binding spec still parses (counted, printed);
  * mutant   -- `assert_exact_keys` neutered: the witness verifies clean again,
                while the positive arm still parses everything; and the
                top-level refusal neutered: the top-level-pin witness RELEASEs
                again.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_EX = _PKG_ROOT / "examples" / "span_claim_minimal"
_SPEC_SRC = _EX / "spec_pinned" / "span_claim.spec.json"
_SPEC_NAME = "span_claim.spec.json"
_TYPE = "extracted_span"

from audit_bundle.admission import admit_json_file  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.rederivation import spec_binding  # noqa: E402
from audit_bundle.rederivation.spec_binding import (  # noqa: E402
    AnchorNotSupplied,
    MalformedSpec,
    SpecAnchor,
    UnknownSpecKey,
    parse_spec,
)
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

# The committed denominator, measured 2026-10-07 (U20 B1). Internal tree: 83
# auditor specs under examples/*/spec_pinned/, 89 committed binding specs under
# examples/ in all, 0 committed JSON binding specs under tests/ (the tests build
# theirs in Python, and those reach this parser whenever the suite runs). The
# open drop ships a subset of the pilots (release/oss_export.py
# GENERIC_SHIP_EXAMPLES; release/ itself never ships, which is how the tree is
# told apart): 46 and 52 there, measured in the export's own run gate. A walker
# that finds fewer has lost files, not gained correctness.
_INTERNAL_TREE = (_PKG_ROOT / "release" / "oss_export.py").is_file()
_MIN_SPEC_PINNED = 83 if _INTERNAL_TREE else 46
_MIN_EXAMPLES_BINDING_SPECS = 89 if _INTERNAL_TREE else 52

_SHA = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731

_CID = "27200c803e93cbf0b19f784798c11b80203e15bc553c8e2895ce55ea2d115b53"
_FORGED_DOC = (
    b"Nothing about this matters.\n"
    b"The contractor's figure was wrong and the reviewers rejected it.\n"
)
_FCID = _SHA(_FORGED_DOC)


def _spec_doc() -> dict:
    return json.loads(_SPEC_SRC.read_bytes())


def _bytes(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def _repoint(bundle: Path) -> None:
    """The census decoy (probe_pins.py `repoint`): ship a second document beside
    the pinned corpus, repoint the pointer at it, and claim its sentence."""
    (bundle / f"corpus/{_FCID}.txt").write_bytes(_FORGED_DOC)
    (bundle / "inputs/span_claim.json").write_text(
        json.dumps(
            {"fragment_id": 1, "schema": "span-claim-v1", "source_cid": _FCID},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (bundle / "outputs/quoted_span.json").write_text(
        json.dumps(
            {"value": "The contractor's figure was wrong and the reviewers rejected it"}
        )
        + "\n"
    )


def _stage(
    tmp_path: Path,
    *,
    bundle_spec: bytes,
    anchor_spec: bytes | None = None,
    mutate=None,
) -> tuple[Path, Path]:
    """Copy the committed bundle, ship `bundle_spec` as its spec, re-cohere the
    manifest, and write the AUDITOR's anchor copy `anchor_spec` (default: the
    same bytes) OUTSIDE the bundle. Returns (bundle, anchor_path)."""
    bundle = tmp_path / "bundle"
    shutil.copytree(_EX / "bundle", bundle)
    anchor_path = tmp_path / "anchor.spec.json"
    anchor_path.write_bytes(bundle_spec if anchor_spec is None else anchor_spec)
    (bundle / "spec" / _SPEC_NAME).write_bytes(bundle_spec)
    if mutate is not None:
        mutate(bundle)
    mpath = bundle / "manifest.json"
    m = json.loads(mpath.read_text())
    files = {}
    for p in sorted(bundle.rglob("*")):
        rel = p.relative_to(bundle).as_posix()
        if p.is_file() and not rel.startswith("spec/") and rel != "manifest.json":
            files[rel] = _SHA(p.read_bytes())
    m["files"] = files
    m["spec_files"] = {_SPEC_NAME: _SHA(bundle_spec)}
    mpath.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    return bundle, anchor_path


def _verify(
    tmp_path: Path,
    *,
    bundle_spec: bytes,
    anchor_spec: bytes | None = None,
    mutate=None,
):
    """`_stage`, then verify through the library with the anchor read from the
    out-of-bundle copy (`SpecAnchor.from_files`)."""
    bundle, anchor_path = _stage(
        tmp_path, bundle_spec=bundle_spec, anchor_spec=anchor_spec, mutate=mutate
    )
    anchor = SpecAnchor.from_files([anchor_path], forbid_within=bundle)
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor,
        require_rederivation=True,
    ).verify(bundle)


def _text(result) -> str:
    return " | ".join(f"{r.code} {getattr(r, 'detail', '')}" for r in result.reasons)


def _typo_doc() -> dict:
    doc = _spec_doc()
    body = doc["types"][_TYPE]
    body["pinned_imputs"] = body.pop("pinned_inputs")
    return doc


def _top_pin_doc() -> dict:
    """The B1 review's witness: the type's pins moved to the spec TOP level,
    where nothing reads them."""
    doc = _spec_doc()
    doc["pinned_inputs"] = doc["types"][_TYPE].pop("pinned_inputs")
    return doc


# --- baseline + control ------------------------------------------------------


def test_committed_spec_verifies_clean(tmp_path):
    result = _verify(tmp_path, bundle_spec=_SPEC_SRC.read_bytes())
    assert result.ok, _text(result)


def test_control_decoy_is_a_forgery_the_pins_refuse(tmp_path):
    """The decoy under the COMMITTED full-pin spec: refused by the pins. This is
    what the typo silently switched off."""
    result = _verify(tmp_path, bundle_spec=_SPEC_SRC.read_bytes(), mutate=_repoint)
    assert not result.ok
    assert result.state is VerdictState.REJECT, _text(result)
    assert "PINNED_INPUT_MISMATCH" in _text(result)


# --- the witness ---------------------------------------------------------------


def test_witness_pinned_imputs_typo_refuses_not_passes(tmp_path):
    """Census p4: `pinned_imputs` + the decoy forgery verified ok=True before.
    Now the auditor's misspelt spec is refused, as the AUDITOR's error."""
    result = _verify(tmp_path, bundle_spec=_bytes(_typo_doc()), mutate=_repoint)
    text = _text(result)
    assert not result.ok, "the census decoy passes again: " + text
    assert result.state is VerdictState.ERROR, text
    assert "UNKNOWN_SPEC_KEY" in text and "'pinned_imputs'" in text, text
    # Blame: nothing about the bundle is asserted, so no REJECT-side failure.
    assert all(r.code == "VERIFIER_INCOMPLETE" for r in result.reasons), text


def _extra_body(doc):
    doc["types"][_TYPE]["note_from_anyone"] = "x"


def _extra_comparator(doc):
    # census p7: an `epsilon` one level too high, beside `params`, read by nobody
    doc["types"][_TYPE]["comparator"]["epsilon"] = 0.5


def _misspelt_params(doc):
    # `parms`: before, the profile then read as absent and the spec was refused
    # as MalformedSpec (REJECT) for that; now the stray key is named first, as
    # the auditor's error (ERROR). For a kind whose params are all optional
    # (`exact` + `numeric_model`), `parms` used to be silently ignored.
    cmp_ = doc["types"][_TYPE]["comparator"]
    cmp_["parms"] = cmp_.pop("params")


@pytest.mark.parametrize(
    "edit, key",
    [
        (_extra_body, "'note_from_anyone'"),
        (_extra_comparator, "'epsilon'"),
        (_misspelt_params, "'parms'"),
    ],
    ids=["type-body", "comparator-object", "misspelt-params"],
)
def test_unknown_key_at_every_closed_level_is_error(tmp_path, edit, key):
    doc = _spec_doc()
    edit(doc)
    result = _verify(tmp_path, bundle_spec=_bytes(doc))
    text = _text(result)
    assert not result.ok, text
    assert result.state is VerdictState.ERROR, text
    assert "UNKNOWN_SPEC_KEY" in text and key in text, text
    assert all(r.code == "VERIFIER_INCOMPLETE" for r in result.reasons), text


def test_unanchored_spec_with_stray_key_is_reject_not_error(tmp_path):
    """Refuse, never demote. The auditor anchors the COMMITTED spec; the bundle
    ships a substituted copy carrying a stray key. Those bytes are not the
    auditor's, so the stray key is the artifact's: REJECT. Before the closure the
    same bundle was an AnchorViolation REJECT; an ERROR here would hand the
    producer a REJECT -> could-not-conclude lever."""
    doc = _spec_doc()
    doc["types"][_TYPE]["note_from_anyone"] = "x"
    result = _verify(
        tmp_path,
        bundle_spec=_bytes(doc),
        anchor_spec=_SPEC_SRC.read_bytes(),
    )
    text = _text(result)
    assert not result.ok, text
    assert result.state is VerdictState.REJECT, text
    assert any(
        r.code == "MalformedSpec" and "UNKNOWN_SPEC_KEY" in r.detail
        for r in result.failures
    ), text


# --- the spec object's top level: open by declared intent, fail-closed where read


def test_top_level_shared_sections_are_admitted(tmp_path):
    """A section another auditor-side reader owns (gaci keeps `calibration`,
    `sources`, `layers`, ... in its anchored spec) rides the same anchored bytes
    and is not refused: the top level is a shared document."""
    doc = _spec_doc()
    doc["calibration"] = {"held_out_f1_floor": 0.7}
    doc["method_version"] = "x-1.0"
    result = _verify(tmp_path, bundle_spec=_bytes(doc))
    assert result.ok, _text(result)


def test_top_level_misspelt_types_fails_closed_not_open(tmp_path):
    """The two top-level keys spec_binding reads are REQUIRED, so their
    misspelling cannot silently drop a rule: the spec stops being a binding
    spec and nothing resolves. (Blame is REJECT today -- a rule-8 residue of the
    pre-existing `AnchorViolation` path, recorded, not changed here.)"""
    doc = _spec_doc()
    doc["typs"] = doc.pop("types")
    result = _verify(tmp_path, bundle_spec=_bytes(doc))
    assert not result.ok, _text(result)
    assert any(r.code == "AnchorViolation" for r in result.failures), _text(result)


def test_witness_top_level_pinned_inputs_refuses_not_releases(tmp_path):
    """The B1 review's MAJOR: `pinned_inputs` at the spec TOP level was ignored
    (open top level), the type ran unpinned and the census decoy RELEASEd. It
    is a key spec_binding reads one level down, so it is refused at the top --
    as the AUDITOR's error, the anchored-closure class."""
    result = _verify(tmp_path, bundle_spec=_bytes(_top_pin_doc()), mutate=_repoint)
    text = _text(result)
    assert not result.ok, "the top-level-pin decoy releases again: " + text
    assert result.state is VerdictState.ERROR, text
    assert "UNKNOWN_SPEC_KEY" in text and "top level" in text, text
    assert "'pinned_inputs'" in text, text
    assert all(r.code == "VERIFIER_INCOMPLETE" for r in result.reasons), text


def test_witness_top_level_pinned_inputs_cli_exits_2(tmp_path):
    """The reviewer's own command: `veriker/cli/verify.py --bundle-dir ...
    --require-rederivation --spec-anchor <out-of-bundle copy>` on the staged
    top-level-pin decoy. Was exit 0 / RELEASE; now exit 2 with the code."""
    bundle, anchor_path = _stage(
        tmp_path, bundle_spec=_bytes(_top_pin_doc()), mutate=_repoint
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
            "--bundle-dir",
            str(bundle),
            "--require-rederivation",
            "--spec-anchor",
            str(anchor_path),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, (proc.returncode, out)
    assert "UNKNOWN_SPEC_KEY" in out and "decision  RELEASE" not in out, out


def _top_key_doc(key: str) -> dict:
    doc = _spec_doc()
    body = doc["types"][_TYPE]
    if key in body:
        doc[key] = copy.deepcopy(body[key])
    elif key in body["comparator"]:
        doc[key] = copy.deepcopy(body["comparator"][key])
    else:  # pragma: no cover -- every refused key is read by the committed spec
        raise AssertionError(key)
    return doc


@pytest.mark.parametrize("key", sorted(spec_binding._SPEC_TOP_KEYS_REFUSED))
def test_every_lower_level_key_is_refused_at_the_top(tmp_path, key):
    """Every key in the refused set, written (as a COPY, so the type itself is
    still complete) at the top level of an anchored spec: ERROR, named."""
    result = _verify(tmp_path, bundle_spec=_bytes(_top_key_doc(key)))
    text = _text(result)
    assert not result.ok, text
    assert result.state is VerdictState.ERROR, text
    assert "UNKNOWN_SPEC_KEY" in text and repr(key) in text, text
    assert all(r.code == "VERIFIER_INCOMPLETE" for r in result.reasons), text


def test_unanchored_top_level_pin_is_reject_not_error(tmp_path):
    """Refuse, never demote, at the top level too: the auditor anchors the
    COMMITTED spec and the bundle ships a copy with its pins moved to the top.
    Those bytes are the artifact's -> REJECT (MalformedSpec), not ERROR."""
    result = _verify(
        tmp_path,
        bundle_spec=_bytes(_top_pin_doc()),
        anchor_spec=_SPEC_SRC.read_bytes(),
        mutate=_repoint,
    )
    text = _text(result)
    assert not result.ok, text
    assert result.state is VerdictState.REJECT, text
    assert any(
        r.code == "MalformedSpec" and "UNKNOWN_SPEC_KEY" in r.detail
        for r in result.failures
    ), text


def test_explicit_empty_pinned_inputs_is_a_declared_limit():
    """ACCEPTED declared limit (B1 review MINOR): `"pinned_inputs": {}` reads
    as "pin nothing". An explicit empty map is a declaration by the auditor,
    not a silent drop (`null`, by contrast, is refused)."""
    doc = _spec_doc()
    doc["types"][_TYPE]["pinned_inputs"] = {}
    _, bindings = parse_spec(doc, "s.json", anchored=True)
    assert bindings[_TYPE].pinned_inputs == ()


# --- parse_spec directly: the class follows whose declaration it is ----------


def test_parse_spec_class_follows_the_anchor():
    doc = _typo_doc()
    # A site that cannot see the anchor uses the could-not-conclude class.
    with pytest.raises(UnknownSpecKey) as default:
        parse_spec(copy.deepcopy(doc), "s.json")
    assert isinstance(default.value, AnchorNotSupplied)
    with pytest.raises(UnknownSpecKey):
        parse_spec(copy.deepcopy(doc), "s.json", anchored=True)
    with pytest.raises(MalformedSpec) as unanchored:
        parse_spec(copy.deepcopy(doc), "s.json", anchored=False)
    assert not isinstance(unanchored.value, AnchorNotSupplied)
    assert "UNKNOWN_SPEC_KEY" in str(unanchored.value)


def test_present_null_pinned_inputs_is_refused():
    """`"pinned_inputs": null` used to read as 'pin nothing' -- the same silent
    drop as the typo, spelled as a value."""
    doc = _spec_doc()
    doc["types"][_TYPE]["pinned_inputs"] = None
    with pytest.raises(MalformedSpec, match="got null"):
        parse_spec(doc, "s.json", anchored=True)


def test_optional_keys_may_be_omitted():
    doc = _spec_doc()
    _, bindings = parse_spec(copy.deepcopy(doc), "s.json", anchored=True)
    assert bindings[_TYPE].pinned_inputs, "the committed spec's pins must load"
    del doc["description"]
    del doc["types"][_TYPE]["pinned_inputs"]
    del doc["types"][_TYPE]["comparator"]["params"]["profile"]
    doc["types"][_TYPE]["comparator"] = {"kind": "exact"}
    _, bindings = parse_spec(doc, "s.json", anchored=True)
    assert bindings[_TYPE].pinned_inputs == ()


# --- declared = read: the closed key sets are derived from the parser --------


def _reads_by_name() -> dict[str, set[str]]:
    """Every string key `parse_spec` reads off `raw` / `body` / `comparator`, by
    `.get("k")`, `["k"]` or `"k" in X`, taken from its source."""
    tree = ast.parse(inspect.getsource(spec_binding.parse_spec))
    reads: dict[str, set[str]] = {"raw": set(), "body": set(), "comparator": set()}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in reads
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            reads[node.func.value.id].add(node.args[0].value)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in reads
            and isinstance(node.slice, ast.Constant)
        ):
            reads[node.value.id].add(node.slice.value)
        elif (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Constant)
            and len(node.comparators) == 1
            and isinstance(node.ops[0], ast.In)
            and isinstance(node.comparators[0], ast.Name)
            and node.comparators[0].id in reads
        ):
            reads[node.comparators[0].id].add(node.left.value)
    return reads


def test_closed_key_sets_equal_the_keys_the_parser_reads():
    reads = _reads_by_name()
    # The top-level refusal set is exactly the keys read BELOW the top level
    # and not at it -- it cannot drift from the parser in either direction.
    assert set(spec_binding._SPEC_TOP_KEYS_REFUSED) == (
        (reads["body"] | reads["comparator"]) - reads["raw"]
    ), reads
    assert {"pinned_inputs", "primitive_id", "comparator", "kind", "params"} <= (
        spec_binding._SPEC_TOP_KEYS_REFUSED
    )
    assert reads["raw"] == set(spec_binding._SPEC_KEYS_READ), reads
    assert reads["body"] == set(
        spec_binding._TYPE_KEYS_REQUIRED | spec_binding._TYPE_KEYS_OPTIONAL
    ), reads
    assert reads["comparator"] == set(
        spec_binding._COMPARATOR_KEYS_REQUIRED | spec_binding._COMPARATOR_KEYS_OPTIONAL
    ), reads


# --- positive arm: every committed spec still parses -------------------------


def _is_binding_spec(doc: object) -> bool:
    return isinstance(doc, dict) and "types" in doc and "spec_id" in doc


def _committed_binding_specs() -> dict[str, list[Path]]:
    """Binding specs (a JSON object with `spec_id` and `types`, the gate
    `build_anchored_spec_set` applies) under examples/ and tests/."""
    found: dict[str, list[Path]] = {"spec_pinned": [], "examples": [], "tests": []}
    found["spec_pinned"] = sorted(_PKG_ROOT.glob("examples/*/spec_pinned/*.spec.json"))
    for root_name in ("examples", "tests"):
        for p in sorted((_PKG_ROOT / root_name).rglob("*.json")):
            try:
                doc = json.loads(p.read_bytes())
            except (ValueError, UnicodeDecodeError, OSError):
                continue
            if _is_binding_spec(doc):
                found[root_name].append(p)
    return found


def _parse_all(paths: list[Path]) -> list[str]:
    bad = []
    for p in paths:
        # The real loader's two steps: admission-bounded strict parse, then
        # parse_spec as the anchored authority (the strictest class).
        raw = admit_json_file(p, check_name="spec_admission")
        try:
            parse_spec(raw, str(p.relative_to(_PKG_ROOT)), anchored=True)
        except Exception as exc:  # noqa: BLE001 -- report every failure
            bad.append(f"{p.relative_to(_PKG_ROOT)}: {type(exc).__name__}: {exc}")
    return bad


def test_positive_arm_every_committed_spec_still_parses():
    found = _committed_binding_specs()
    counts = {k: len(v) for k, v in found.items()}
    print(f"\n[closed-keys positive arm] binding specs parsed: {counts}")
    assert counts["spec_pinned"] >= _MIN_SPEC_PINNED, counts
    assert counts["examples"] >= _MIN_EXAMPLES_BINDING_SPECS, counts
    for p in found["spec_pinned"]:
        assert _is_binding_spec(json.loads(p.read_bytes())), p
    every = sorted(
        set(found["spec_pinned"]) | set(found["examples"]) | set(found["tests"])
    )
    bad = _parse_all(every)
    assert not bad, (
        f"{len(bad)}/{len(every)} committed specs no longer parse:\n" + "\n".join(bad)
    )


# --- mutant control ------------------------------------------------------------


def test_mutant_neutered_closure_reopens_the_witness(tmp_path, monkeypatch):
    """NULL MUTANT. Neuter `assert_exact_keys` inside spec_binding: the census
    typo + decoy verifies clean again (the witness goes red), while every
    committed spec still parses (the positive arm stays green). A guard whose
    removal changes nothing would not be evidence."""
    monkeypatch.setattr(spec_binding, "assert_exact_keys", lambda _m, _r: None)
    result = _verify(tmp_path, bundle_spec=_bytes(_typo_doc()), mutate=_repoint)
    assert result.ok, (
        "with the closure neutered the census decoy must verify clean -- if it "
        "does not, the witness is not measuring the closure: " + _text(result)
    )
    found = _committed_binding_specs()
    every = sorted(
        set(found["spec_pinned"]) | set(found["examples"]) | set(found["tests"])
    )
    assert not _parse_all(every)


def test_mutant_neutered_top_level_refusal_reopens_the_witness(
    tmp_path, monkeypatch
):
    """NULL MUTANT for the top-level refusal: with
    `_refuse_misplaced_top_level_keys` neutered, the top-level-pin decoy goes
    back to RELEASE (the review's witness, ok=True), while every committed
    spec still parses."""
    monkeypatch.setattr(
        spec_binding, "_refuse_misplaced_top_level_keys", lambda *_a, **_k: None
    )
    result = _verify(tmp_path, bundle_spec=_bytes(_top_pin_doc()), mutate=_repoint)
    assert result.ok, (
        "with the top-level refusal neutered the decoy must RELEASE -- if it "
        "does not, the witness is not measuring the refusal: " + _text(result)
    )
    found = _committed_binding_specs()
    every = sorted(
        set(found["spec_pinned"]) | set(found["examples"]) | set(found["tests"])
    )
    assert not _parse_all(every)
