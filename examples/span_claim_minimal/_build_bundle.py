"""_build_bundle.py — the PRODUCER for span_claim_minimal.

Emits an extractive-quotation bundle: a source document, a pointer at one
sentence of it, and the producer's claim that a given piece of text IS that
sentence.

    python examples/span_claim_minimal/_build_bundle.py --out-dir DIR

The claimed span comes from `_producer_extract.py`, the quoting tool's own copy
of the segmentation rule. This module must never import
`audit_bundle.rederivation.primitives.*` — the verifier's own code — or the claim
would be the verifier's recompute and the comparison would be an identity.
Enforced by `tests/test_span_claim_minimal.py` (AST) and repo-wide by
`tests/test_recipe_producer_verifier_disjoint.py`.

THE DOMAIN IS SYNTHETIC. Five sentences of a fictional bridge-survey note,
written here. Nothing in it is a real finding about a real structure.

CONTENT-ADDRESSED SOURCE. The corpus file is named for the sha256 of its own
bytes. That is a convention of this pilot, NOT something the verifier checks: the
primitive resolves `corpus/<source_cid>.txt` and reads it, and does not confirm
that the name matches the content. What actually fixes which document is being
quoted is the auditor's SHA pin, and `--decoy-corpus` below exists to show that
the naming convention alone would not have.

LAYOUT. The bundle is written to `bundle/`, a SUBDIRECTORY, while the auditor's
spec stays in the sibling `spec_pinned/`. An anchor taken from inside the bundle
it judges lets the producer author both sides of the comparison, and
`SpecAnchor.from_files(..., forbid_within=...)` refuses it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

import _producer_extract as extractor  # noqa: E402

_BUNDLE_ID = "span-claim-minimal-0001"
_CREATED_AT = "2026-08-29T00:00:00Z"
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_TYPED_CHECKS = ["file_integrity_many_small"]

_SPEC_SRC = _HERE / "spec_pinned" / "span_claim.spec.json"

_OUTPUT_ID = "quoted_span"
_TYPE_KEY = "extracted_span"

# --- The committed source. Sentence 3 carries a pair of commas that change what
#     the sentence says: with them, ALL the reviewers endorsed the figure;
#     without them, only the ones who had telemetry access did. The spectra_v1
#     normalization drops punctuation, so both readings normalize alike — which
#     is a scope limit this pilot demonstrates rather than describes.
#     Sentence 2 carries a decimal, so the segmentation rule's digit-adjacency
#     exception is exercised by the committed fixture and not only by a unit test.
_SOURCE_TEXT = (
    "Sensor array B was installed along the north span in March.\n"
    "The deck displacement recorded at midspan averaged 3.5 mm over the survey "
    "window.\n"
    "The reviewers, who had access to the raw telemetry, endorsed the "
    "contractor's figure.\n"
    "Two units reported intermittently and were excluded from the aggregate.\n"
    "No corrosion was observed at the anchorages.\n"
)

_DEFAULT_FRAGMENT_ID = 2


def _canonical(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def source_cid(text: str = _SOURCE_TEXT) -> str:
    """The corpus filename: the sha256 of the document's own bytes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build(
    out_dir: Path,
    fragment_id: int = _DEFAULT_FRAGMENT_ID,
    claimed_span: str | None = None,
    source_text: str = _SOURCE_TEXT,
    cid: str | None = None,
) -> None:
    out_dir = Path(out_dir).resolve()
    cid = cid if cid is not None else source_cid(source_text)

    corpus_rel = f"corpus/{cid}.txt"
    files = {corpus_rel: source_text.encode("utf-8")}

    # The producer extracts with its OWN segmentation, from the bytes it is
    # about to commit.
    fragments = extractor.segment(source_text)
    honest = extractor.segment(source_text)[fragment_id]
    claim = honest if claimed_span is None else claimed_span

    files["inputs/span_claim.json"] = _canonical(
        {
            "schema": "span-claim-v1",
            "source_cid": cid,
            "fragment_id": fragment_id,
        }
    )
    files["payload/extraction_record.json"] = _canonical(
        {
            "schema": "span-extraction-record-v1",
            "fragment_count": len(fragments),
            "fragment_id": fragment_id,
            "span": claim,
        }
    )

    spec_files: dict[str, bytes] = {}
    extra: dict = {}
    if _SPEC_SRC.is_file():
        spec_files[_SPEC_SRC.name] = _SPEC_SRC.read_bytes()
        files[f"outputs/{_OUTPUT_ID}.json"] = _canonical({"value": claim})
        extra["outputs"] = [
            {
                "output_id": _OUTPUT_ID,
                "type": _TYPE_KEY,
                "conforms_to": f"spec/{_SPEC_SRC.name}",
            }
        ]

    write_bundle(
        out_dir,
        BundleContent(
            bundle_id=_BUNDLE_ID,
            created_at=_CREATED_AT,
            schema_version=_SCHEMA_VERSION,
            files=files,
            spec_files=spec_files,
            typed_checks=_TYPED_CHECKS,
            extra_manifest_fields=extra,
        ),
    )
    print(f"Bundle written to {out_dir}")
    print(f"  source_cid      : {cid}")
    print(f"  fragments       : {len(fragments)}")
    print(f"  fragment_id     : {fragment_id}")
    print(f"  claimed span    : {claim!r}")
    print(f"  claims declared : {len(extra.get('outputs', []))}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the span_claim_minimal bundle")
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=_HERE / "bundle",
        help="where to write the bundle (default: the committed bundle/ subdir)",
    )
    ap.add_argument(
        "--fragment-id",
        type=int,
        default=_DEFAULT_FRAGMENT_ID,
        help="which sentence of the source document to quote",
    )
    ap.add_argument(
        "--claimed-span",
        default=None,
        help="claim this text instead of the sentence actually at --fragment-id "
        "(used to build a hallucinated or reworded quotation consistently)",
    )
    args = ap.parse_args()
    build(args.out_dir.resolve(), args.fragment_id, args.claimed_span)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
