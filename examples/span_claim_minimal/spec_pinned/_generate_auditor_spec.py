"""_generate_auditor_spec.py — AUDITOR-side generator for this pilot's binding
spec.

Run when the committed source document or the quoted fragment changes:

    python examples/span_claim_minimal/spec_pinned/_generate_auditor_spec.py

TWO PINS, and they answer two different questions (§4a.7 `pinned_inputs`):

  corpus/<cid>.txt        WHICH DOCUMENT. Without it a producer can hallucinate
                          a quotation and then edit the source so the
                          re-derivation returns the hallucination. That attack
                          verifies clean.

  inputs/span_claim.json  WHICH SENTENCE OF IT. The pointer is part of the
                          auditor's QUESTION, not part of the producer's answer.
                          Pinning the corpus alone is not enough: a producer can
                          leave the pinned document untouched, ship a second one
                          beside it and repoint `source_cid` at that. The
                          content-addressed filename does not stop this — the
                          primitive resolves the name it is given and does not
                          check that the name matches the bytes.

The producer's claimed TEXT (outputs/quoted_span.json) is deliberately NOT
pinned. That is the answer, and pinning it would leave nothing to verify.

READ THIS COMMAND FOR WHAT IT IS. The generator runs the producer and pins the
bytes that run emitted, so the pins record which document and which sentence an
earlier producer run used. That is acceptable in an exemplar the repository must
also be able to rebuild; it is not the posture for a real engagement, where the
auditor holds the source document independently and hashes their own copy.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PILOT = _HERE.parent
_PKG_ROOT = _HERE.resolve().parents[2]
for p in (str(_PKG_ROOT), str(_PILOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import _build_bundle as producer  # noqa: E402

_SPEC_ID = "span.claim.minimal.v1"
_TYPE_KEY = "extracted_span"
_PRIMITIVE_ID = "spectra_span_recompute"

_DESCRIPTION = (
    "Auditor binding spec for span_claim_minimal, a synthetic extractive "
    "quotation. The representative re-derived output is the SOURCE fragment: "
    "read inputs/span_claim.json {source_cid, fragment_id}, load "
    "corpus/<source_cid>.txt, cut it at sentence terminators [.!?]+ that are "
    "not adjacent to a digit, strip each piece and drop the empties, and return "
    "the piece at fragment_id. The comparator is text_normalized[spectra_v1], "
    "authority-pinned here and not producer-asserted. TWO INPUTS ARE PINNED BY "
    "SHA (section 4a.7) and they answer different questions: corpus/<cid>.txt "
    "fixes WHICH DOCUMENT, because otherwise a producer can hallucinate a "
    "quotation and edit the source until the re-derivation returns it; and "
    "inputs/span_claim.json fixes WHICH SENTENCE OF IT, because the pointer is "
    "part of the auditor's question rather than the producer's answer — pinning "
    "the corpus alone leaves a producer free to ship a second document beside "
    "the pinned one and repoint source_cid at it, and the content-addressed "
    "filename does not prevent that (the primitive resolves the name it is "
    "given and never checks that the name matches the bytes). The claimed TEXT "
    "is deliberately not pinned; it is the answer. SCOPE LIMIT an adopter is "
    "accepting, stated because the comparator hides it: spectra_v1 normalizes "
    "by NFC, casefold, DROPPING ALL PUNCTUATION, collapsing whitespace and "
    "stripping. So a PASS certifies the words and their order, NOT the "
    "punctuation or the case — and a comma that changes what a sentence means "
    "can be added or removed inside a quotation this check accepts. Segmentation "
    "is the terminator regex alone: no abbreviation, quotation or list handling."
)

#: Every bundle file the bound primitive reads, except the corpus path, which is
#: computed below because its NAME depends on the committed document.
_CONSUMED = ("inputs/span_claim.json",)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle"
        producer.build(bundle)
        rels = list(_CONSUMED) + [f"corpus/{producer.source_cid()}.txt"]
        pinned = {
            rel: hashlib.sha256((bundle / rel).read_bytes()).hexdigest()
            for rel in sorted(rels)
        }

    spec = {
        "spec_id": _SPEC_ID,
        "description": _DESCRIPTION,
        "types": {
            _TYPE_KEY: {
                "primitive_id": _PRIMITIVE_ID,
                "comparator": {
                    "kind": "text_normalized",
                    "params": {"profile": "spectra_v1"},
                },
                "pinned_inputs": pinned,
            }
        },
    }
    (_HERE / "span_claim.spec.json").write_bytes(
        (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    print("wrote span_claim.spec.json")
    for rel, sha in pinned.items():
        print(f"  pinned {rel}: {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
