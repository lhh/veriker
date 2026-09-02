"""Round-trip integration test for examples/pii_redaction_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True and RE_DERIVED in successes.
  5. Tamper test A: mutate bioes_logits.json so a different tag wins Viterbi.
  6. Re-run; assert result.ok is False.
  7. Tamper test B: mutate bias_vector in redaction_output.json.
  8. Re-run; assert result.ok is False.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "pii_redaction_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "pii_redaction_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "PIIRedactionReDerivationCheck",
    _PILOT_DIR / "PIIRedactionReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

PIIRedactionReDerivationCheck = _check_mod.PIIRedactionReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            PIIRedactionReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"REDACT", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_pii_redaction_build_and_verify(tmp_path: Path) -> None:
    """Build a clean bundle and verify it — result.ok must be True, and the
    plugin directly returns RE_DERIVED on success."""
    bundle_dir = tmp_path / "pii_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )

    # Plugin's own success reason_code is not exposed via VerifyResult (only failures
    # propagate). Invoke the plugin directly to confirm the contracted success code.
    from audit_bundle.verifier import _load_manifest

    direct = PIIRedactionReDerivationCheck().check(
        bundle_dir, _load_manifest(bundle_dir)
    )
    assert direct.ok is True
    assert direct.reason_code == "RE_DERIVED", (
        f"Expected RE_DERIVED; got {direct.reason_code}: {direct.detail}"
    )


def test_pii_redaction_manifest_has_pii_span_fragments(tmp_path: Path) -> None:
    """Built manifest must contain OpaqueFragment(kind_tag=pii_span) anchors."""
    bundle_dir = tmp_path / "pii_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    pii_frags = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "pii_span"
    ]
    assert len(pii_frags) >= 3, (
        f"Expected >= 3 OpaqueFragment(kind_tag=pii_span) anchors; got {len(pii_frags)}"
    )


def test_pii_redaction_manifest_has_redact_dispatch(tmp_path: Path) -> None:
    """Built manifest must contain a dispatch_record with op.kind=REDACT."""
    bundle_dir = tmp_path / "pii_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])
    kinds = [r.get("op", {}).get("kind") for r in records]
    assert "REDACT" in kinds, (
        f"Expected a dispatch_record with op.kind=REDACT; found kinds: {kinds}"
    )


# ---------------------------------------------------------------------------
# Tamper test A: flip logits so Viterbi decodes a different tag sequence
# ---------------------------------------------------------------------------


def test_pii_redaction_tamper_logits_fails(tmp_path: Path) -> None:
    """Mutating bioes_logits.json so the gold tag is no longer the Viterbi
    argmax must cause result.ok=False with RE_DERIVATION_MISMATCH."""
    bundle_dir = tmp_path / "pii_tamper_logits"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    logits_path = bundle_dir / "payload" / "bioes_logits.json"
    logits_obj = json.loads(logits_path.read_text(encoding="utf-8"))
    logits = logits_obj["logits"]

    # Target tokens inside the bundled spans. Token 0 in the synthetic fixture
    # is "Contact" — background O — so mutating it leaves the decode unchanged.
    output_obj = json.loads(
        (bundle_dir / "payload" / "redaction_output.json").read_text(encoding="utf-8")
    )
    span_token_indices = [
        i
        for s in output_obj["spans"]
        for i in range(s["token_start"], s["token_end"] + 1)
    ]
    assert span_token_indices, "fixture must have at least one in-span token"
    for idx in span_token_indices:
        for j in range(33):
            logits[idx][j] = 0.0
        logits[idx][32] = 5.0  # force O on every in-span token
    logits_obj["logits"] = logits

    new_bytes = (json.dumps(logits_obj, indent=2) + "\n").encode("utf-8")
    logits_path.write_bytes(new_bytes)

    # Update manifest SHA so FileIntegrityManySmall doesn't mask the re-derivation failure
    import hashlib

    new_sha = hashlib.sha256(new_bytes).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/bioes_logits.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after mutating bioes_logits.json"
    )
    combined = " ".join(
        [f.reason_code for f in result.failures] + [f.detail for f in result.failures]
    ).upper()
    assert "RE_DERIVATION_MISMATCH" in combined, (
        f"Expected RE_DERIVATION_MISMATCH in failures; got {result.failures}"
    )


# ---------------------------------------------------------------------------
# Tamper test B: mutate bias_vector so original spans are no longer Viterbi argmax
# ---------------------------------------------------------------------------


def test_pii_redaction_tamper_bias_vector_fails(tmp_path: Path) -> None:
    """Mutating bias_vector in redaction_output.json (without regenerating
    consistent spans) is caught by the verifier-held bias_vector pin — the
    checker never decodes under a bundle-supplied bias_vector, so any
    divergence from the pinned constant is a dedicated, early failure."""
    bundle_dir = tmp_path / "pii_tamper_bias"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    output_path = bundle_dir / "payload" / "redaction_output.json"
    output_obj = json.loads(output_path.read_text(encoding="utf-8"))

    # Large negative span_entry bias (index 1); irrespective of its effect on
    # decode, this no longer matches the verifier-held pin ([0]*6).
    output_obj["bias_vector"] = [0.0, -100.0, 0.0, 0.0, 0.0, 0.0]

    new_bytes = (json.dumps(output_obj, indent=2) + "\n").encode("utf-8")
    output_path.write_bytes(new_bytes)

    # Update manifest SHA
    import hashlib

    new_sha = hashlib.sha256(new_bytes).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/redaction_output.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "Expected result.ok=False after mutating bias_vector"
    combined = " ".join(
        [f.reason_code for f in result.failures] + [f.detail for f in result.failures]
    ).upper()
    assert "PII_REDACTION_BIAS_VECTOR_MISMATCH" in combined, (
        f"Expected PII_REDACTION_BIAS_VECTOR_MISMATCH in failures; got {result.failures}"
    )


# ---------------------------------------------------------------------------
# Tamper test C: bias_vector substitution WITH a self-consistent re-decode —
# the strongest producer attack. Before the pin, a producer could substitute
# an adversarial bias_vector and regenerate spans/redacted_text decoded under
# it, so span/redacted-text comparison alone would PASS. Only the
# verifier-held pin catches this now.
# ---------------------------------------------------------------------------


def test_pii_redaction_bias_vector_substitution_only_pin_catches(
    tmp_path: Path,
) -> None:
    """Substitute an adversarial bias_vector AND regenerate spans/redacted_text
    consistently decoded under it (using the pack's own _viterbi/_decode_spans/
    _reconstruct_redacted). This is internally self-consistent — a checker
    that trusted the bundle's bias_vector for decoding would find the
    (adversarial) spans equal to the (adversarial) re-derivation and PASS.
    Only the verifier-held bias_vector pin catches the substitution."""
    bundle_dir = tmp_path / "pii_tamper_bias_consistent"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    output_path = bundle_dir / "payload" / "redaction_output.json"
    output_obj = json.loads(output_path.read_text(encoding="utf-8"))
    logits_obj = json.loads(
        (bundle_dir / "payload" / "bioes_logits.json").read_text(encoding="utf-8")
    )
    tokens_obj = json.loads(
        (bundle_dir / "payload" / "tokens.json").read_text(encoding="utf-8")
    )

    pack_mod = _import_module_from_path(
        "pii_redaction_re_derivation",
        _PILOT_DIR / "pii_redaction_re_derivation.py",
    )

    # Adversarial bias vector, large enough to overwhelm the fixture's strong
    # per-token logit peaks (5.0 gold vs -2.0 background) and flip the decode:
    # strongly discourage staying in O, strongly encourage entering a span.
    adversarial_bias = [-30.0, 30.0, 0.0, 0.0, -30.0, 0.0]
    assert adversarial_bias != output_obj["bias_vector"]

    tag_seq = pack_mod._viterbi(logits_obj["logits"], adversarial_bias)
    adversarial_spans_raw = pack_mod._decode_spans(tag_seq, output_obj["categories"])
    adversarial_redacted = pack_mod._reconstruct_redacted(
        tokens_obj["tokens"], adversarial_spans_raw
    )

    # Prove this is a REAL attack: the adversarial decode differs from the
    # honest bundled spans (otherwise substituting the bias_vector would be a
    # no-op, not an attack).
    honest_spans_cmp = [
        {k: s[k] for k in ("token_start", "token_end", "category")}
        for s in output_obj["spans"]
    ]
    assert adversarial_spans_raw != honest_spans_cmp, (
        "fixture did not produce a distinguishing adversarial decode; "
        "strengthen adversarial_bias"
    )

    output_obj["bias_vector"] = adversarial_bias
    output_obj["spans"] = [{**s, "confidence": 0.5} for s in adversarial_spans_raw]
    output_obj["redacted_text"] = adversarial_redacted

    new_bytes = (json.dumps(output_obj, indent=2) + "\n").encode("utf-8")
    output_path.write_bytes(new_bytes)

    import hashlib

    new_sha = hashlib.sha256(new_bytes).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/redaction_output.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False for a self-consistent adversarial "
        "bias_vector substitution"
    )
    combined = " ".join(
        [f.reason_code for f in result.failures] + [f.detail for f in result.failures]
    ).upper()
    assert "PII_REDACTION_BIAS_VECTOR_MISMATCH" in combined, (
        "Expected the verifier-held pin (not a generic span mismatch) to "
        f"catch this; got {result.failures}"
    )


# ---------------------------------------------------------------------------
# Tamper test D: model_sha absent must fail-closed
# ---------------------------------------------------------------------------


def test_pii_redaction_model_sha_absent_fails(tmp_path: Path) -> None:
    """Deleting model_sha from redaction_output.json must fail-closed
    (PII_REDACTION_MODEL_SHA_ABSENT). The builder's model_sha is a documented
    placeholder pending real §C9.1 checkpoint-SHA pinning — this check can
    only assert presence, not truth, but presence must not be silently
    droppable."""
    bundle_dir = tmp_path / "pii_tamper_model_sha"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    output_path = bundle_dir / "payload" / "redaction_output.json"
    output_obj = json.loads(output_path.read_text(encoding="utf-8"))
    del output_obj["model_sha"]

    new_bytes = (json.dumps(output_obj, indent=2) + "\n").encode("utf-8")
    output_path.write_bytes(new_bytes)

    import hashlib

    new_sha = hashlib.sha256(new_bytes).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/redaction_output.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "Expected result.ok=False when model_sha is absent"
    combined = " ".join(
        [f.reason_code for f in result.failures] + [f.detail for f in result.failures]
    ).upper()
    assert "PII_REDACTION_MODEL_SHA_ABSENT" in combined, (
        f"Expected PII_REDACTION_MODEL_SHA_ABSENT in failures; got {result.failures}"
    )
