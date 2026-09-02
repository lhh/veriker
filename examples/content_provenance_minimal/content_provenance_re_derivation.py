#!/usr/bin/env python3
"""content_provenance_re_derivation.py — stdlib re-derivation pack for content provenance domain.

SCOPE BOUNDARY:
This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.

Re-derivation primitive (one sentence):
  Re-hash the published content bytes and re-check they match the producer-signed
  manifest hash, and assert the provenance chain (producer id + declared generation
  inputs) is intact and unaltered.

§C5 (auditor independence) + AB4 (duplicate-don't-import).
Stdlib only — no 3rd-party deps.  HMAC-SHA256 via stdlib hmac + hashlib.

Reading order:
  1. Reads payload/provenance_result.json from --bundle-dir.
  2. Reads artifact/content.txt and artifact/provenance.json.
  3. Asserts content_sha in payload matches sha256(artifact/content.txt).
  4. Asserts provenance_sha in payload matches sha256(artifact/provenance.json).
  5. Re-computes HMAC-SHA256(synthetic_key, content_bytes + "\n" + canonical
     JSON of the manifest WITHOUT producer_hmac) and asserts it matches the
     producer_hmac field in the provenance manifest — the signature covers the
     manifest core, so producer_id / generation_inputs / content_sha / created_at
     cannot be rewritten without the key. Also asserts the manifest's OWN
     content_sha field names the re-hashed content.
  6. Asserts the payload's OWN producer_hmac claim (payload/provenance_result.json's
     producer_hmac field) also equals the re-derived HMAC — the payload's signature
     claim is a distinct committed value from artifact/provenance.json and must be
     independently bound, not left as an extracted-but-unchecked field.
  7. Asserts provenance chain fields (producer_id, generation_inputs) match
     between payload and provenance manifest.

  8. Asserts the payload's OWN provenance_status claim equals the status this
     pack re-derived by running every check above (CONTENT_PROVENANCE_VERIFIED on
     the success path) — the field a downstream consumer actually reads must
     agree with the re-derivation, not merely be present.

Exit codes:
  0  all assertions passed (CONTENT_PROVENANCE_VERIFIED)
  1  mismatch found — description written to stderr (CONTENT_PROVENANCE_ALTERED /
     CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH / CONTENT_PROVENANCE_STATUS_MISMATCH)

On a full match the pack prints ONE machine-readable stdout line naming the
payload fields whose values it compared on this run, keyed by bundle-relative
file — accumulated as each comparison passes, never a constant:

    [COMPARED] {"payload/provenance_result.json": ["content_sha", ...]}

The pilot's plugin reports claim-field coverage for exactly those fields. Field
paths use the claimset rendering (object keys joined by ".", every array
position "[]").
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

# Synthetic producer key — must match _build_bundle.py exactly (AB4 pattern).
# Fixed bytes, deterministic, local-only demo.
_SYNTHETIC_PRODUCER_KEY = b"SYNTHETIC_PRODUCER_KEY_LOCAL_DEMO_ONLY_NOT_A_SECRET"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _producer_hmac(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 over data using key.  Returns hex string."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _fail(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _signing_input(content_bytes: bytes, manifest_core: dict) -> bytes:
    """Must match _build_bundle.py exactly (AB4): content bytes, a newline, the
    canonical JSON of the provenance manifest without its producer_hmac field."""
    core = json.dumps(manifest_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return content_bytes + b"\n" + core


def _canonical(value: object) -> str:
    """Type-strict comparison form: Python's == treats True == 1 and 1.0 == 1 as
    equal, so two JSON documents that differ in TYPE would compare equal. The
    canonical JSON text does not."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _leaf_paths(obj: object, prefix: str) -> list[str]:
    """Claimset-rendered leaf paths under `prefix` for a value whose WHOLE
    structure was just compared by equality: object keys join with ".", every
    array position renders "[]", a scalar or empty container is a leaf. Mirrors
    the enumerator's convention so an equality over a nested value reports the
    same elements the gate enumerates."""
    if isinstance(obj, dict) and obj:
        out: list[str] = []
        for key, val in obj.items():
            out.extend(_leaf_paths(val, f"{prefix}.{key}"))
        return out
    if isinstance(obj, list) and obj:
        seen: list[str] = []
        for item in obj:
            for path in _leaf_paths(item, f"{prefix}[]"):
                if path not in seen:
                    seen.append(path)
        return seen
    return [prefix]


def _emit_compared(compared: "set[str]") -> None:
    """Print the payload fields whose values this run COMPARED, as one
    machine-readable stdout line, after every comparison succeeded. The set is
    accumulated in main() as each comparison passes, so a removed or skipped
    comparison drops out of the line and the pilot's plugin stops reporting
    that field (the coverage gate then refuses to conclude). No
    producer-controlled string is interpolated."""
    print(
        "[COMPARED] "
        + json.dumps({"payload/provenance_result.json": sorted(compared)}, sort_keys=True)
    )


# ---------------------------------------------------------------------------
# Main verification logic
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Content provenance re-derivation check"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Load payload/provenance_result.json ---
    payload_path = bundle_dir / "payload" / "provenance_result.json"
    if not payload_path.exists():
        # Domain pilot opted out — not a failure
        return 0

    try:
        payload = json.loads(payload_path.read_bytes())
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(
            f"content_provenance_re_derivation: failed to read payload/provenance_result.json: {exc}"
        )

    compared: set[str] = set()

    # --- Extract committed values from payload ---
    try:
        committed_content_sha: str = payload["content_sha"]
        committed_provenance_sha: str = payload["provenance_sha"]
        committed_producer_id: str = payload["producer_id"]
        committed_generation_inputs: dict = payload["generation_inputs"]
        committed_producer_hmac: str = payload["producer_hmac"]
        committed_status: str = payload["provenance_status"]
    except KeyError as exc:
        return _fail(
            f"content_provenance_re_derivation: payload/provenance_result.json missing field {exc}"
        )

    # --- Load artifact/content.txt ---
    content_path = bundle_dir / "artifact" / "content.txt"
    if not content_path.exists():
        return _fail(
            "content_provenance_re_derivation: artifact/content.txt not found in bundle_dir"
        )
    content_bytes = content_path.read_bytes()

    # --- Load artifact/provenance.json ---
    provenance_path = bundle_dir / "artifact" / "provenance.json"
    if not provenance_path.exists():
        return _fail(
            "content_provenance_re_derivation: artifact/provenance.json not found in bundle_dir"
        )
    provenance_bytes = provenance_path.read_bytes()

    try:
        provenance_manifest = json.loads(provenance_bytes)
    except json.JSONDecodeError as exc:
        return _fail(
            f"content_provenance_re_derivation: artifact/provenance.json is not valid JSON: {exc}"
        )

    # --- Assert content_sha matches actual file (detects post-signing alteration) ---
    actual_content_sha = _sha256(content_bytes)
    if actual_content_sha != committed_content_sha:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  content_sha in payload         : {committed_content_sha!r}\n"
            f"  sha256(artifact/content.txt)   : {actual_content_sha!r}\n"
            f"  Content bytes do not match committed hash — post-signing alteration detected"
        )
    compared.add("content_sha")

    # --- Assert provenance_sha matches actual file ---
    actual_provenance_sha = _sha256(provenance_bytes)
    if actual_provenance_sha != committed_provenance_sha:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  provenance_sha in payload         : {committed_provenance_sha!r}\n"
            f"  sha256(artifact/provenance.json)  : {actual_provenance_sha!r}\n"
            f"  Provenance manifest does not match committed hash — tamper detected"
        )
    compared.add("provenance_sha")

    # --- The manifest's OWN content_sha must name the re-hashed content ---
    manifest_content_sha = provenance_manifest.get("content_sha", "")
    if manifest_content_sha != f"sha256:{actual_content_sha}":
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  content_sha in manifest        : {manifest_content_sha!r}\n"
            f"  sha256(artifact/content.txt)   : sha256:{actual_content_sha}\n"
            f"  The provenance manifest names content other than the published bytes"
        )

    # --- Re-derive the HMAC over content + manifest core and assert it matches
    # the manifest's producer_hmac. The signature covers every manifest field
    # except itself, so identity / inputs / timestamps are bound to the key.
    manifest_core = {k: v for k, v in provenance_manifest.items() if k != "producer_hmac"}
    rederived_hmac_hex = _producer_hmac(
        _SYNTHETIC_PRODUCER_KEY, _signing_input(content_bytes, manifest_core)
    )
    expected_hmac_field = f"hmac-sha256:{rederived_hmac_hex}"
    manifest_hmac_field: str = provenance_manifest.get("producer_hmac", "")
    if manifest_hmac_field != expected_hmac_field:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  producer_hmac in manifest      : {manifest_hmac_field!r}\n"
            f"  re-derived hmac                : {expected_hmac_field!r}\n"
            f"  Producer HMAC mismatch — content or manifest not signed by the committed "
            f"producer key, or altered after signing"
        )

    # --- Assert the payload's OWN producer_hmac claim also equals the re-derived
    # HMAC.  This is a distinct committed value from artifact/provenance.json's
    # producer_hmac field (checked above) — payload/provenance_result.json is the
    # verification payload a downstream consumer actually reads, and its signature
    # claim must be independently bound, not merely extracted and left unchecked.
    # Fails closed on a missing or empty claim (never equals a real hmac-sha256:… value).
    if not committed_producer_hmac or committed_producer_hmac != expected_hmac_field:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH\n"
            f"  producer_hmac in payload        : {committed_producer_hmac!r}\n"
            f"  re-derived hmac                 : {expected_hmac_field!r}\n"
            f"  Payload's own producer_hmac claim does not match the re-derived HMAC — "
            f"the payload's signature claim was not signed by the committed producer key, "
            f"or was replaced after signing.  (This is checked independently of "
            f"artifact/provenance.json's producer_hmac field, a different committed file.)"
        )
    compared.add("producer_hmac")

    # --- Assert provenance chain: producer_id ---
    manifest_producer_id = provenance_manifest.get("producer_id", "")
    if _canonical(manifest_producer_id) != _canonical(committed_producer_id):
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  producer_id in payload    : {committed_producer_id!r}\n"
            f"  producer_id in manifest   : {manifest_producer_id!r}\n"
            f"  Producer identity mismatch — provenance chain altered"
        )
    compared.add("producer_id")

    # --- Assert provenance chain: generation_inputs ---
    manifest_generation_inputs = provenance_manifest.get("generation_inputs", {})
    if _canonical(manifest_generation_inputs) != _canonical(committed_generation_inputs):
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  generation_inputs in payload  : {json.dumps(committed_generation_inputs, sort_keys=True)}\n"
            f"  generation_inputs in manifest : {json.dumps(manifest_generation_inputs, sort_keys=True)}\n"
            f"  Generation inputs mismatch — provenance chain altered"
        )
    # The dict equality above bound every leaf of generation_inputs.
    compared.update(_leaf_paths(committed_generation_inputs, "generation_inputs"))

    # --- Assert the payload's OWN provenance_status equals the re-derived one.
    # Every check above passed, so the re-derived status is VERIFIED; the
    # status the payload states — the field a downstream consumer reads — must
    # agree with the re-derivation, not merely be present.
    rederived_status = "CONTENT_PROVENANCE_VERIFIED"
    if committed_status != rederived_status:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_STATUS_MISMATCH\n"
            f"  provenance_status in payload : {committed_status!r}\n"
            f"  re-derived status            : {rederived_status!r}\n"
            f"  The payload's stated provenance status disagrees with the re-derivation"
        )
    compared.add("provenance_status")

    # All checks passed
    _emit_compared(compared)
    return 0


if __name__ == "__main__":
    sys.exit(main())
