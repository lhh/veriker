"""_producer_extract.py — the QUOTING TOOL's own span extraction.

This module is the producer's half of `span_claim_minimal`. It is a separately
maintained implementation of the rule the auditor pinned: cut the source
document at sentence terminators that are not adjacent to a digit, strip each
piece, drop the empties, and take the one the claim points at.

It must never import `audit_bundle.rederivation.primitives.*`. If it did, the
claimed span would BE the verifier's recompute and an honest PASS would prove
nothing. Enforced by this pilot's AST test and, repo-wide, by
`tests/test_recipe_producer_verifier_disjoint.py`.

The producer does NOT reproduce the verifier's path containment, and should not
try to: keeping a bundle-controlled `source_cid` from steering a read outside
`corpus/` is a property the CHECKER needs on ITS machine, not something a
producer can offer on the producer's behalf.

HOW MUCH THE DUPLICATION BUYS HERE, stated narrowly, because it is LESS than in
this pilot's siblings. `segment()` below and the verifier's `_sentence_segments`
are the same rule and, as far as can be measured, the same function: a
differential fuzz over 200,000 random documents found zero inputs on which they
disagree (`test_the_two_segmenters_agree_on_everything_tried` runs a shorter
version of it in the battery). So an honest PASS here shows the claim was not
ROUTED THROUGH the verifier's code — a structural guarantee about where the
number came from — and not that two behaviourally different programs agreed.
Compare `fea_vonmises_minimal`, whose two copies differ by a summation
compensation term, and `event_log_replay_minimal`, whose verifier accepts an
op-set its producer refuses.

The one asymmetry that IS real runs the safe way: the verifier additionally
contains the read inside `corpus/` and range-checks `fragment_id`, neither of
which this module does. The checker is the stricter of the two.

Stdlib-only.
"""

from __future__ import annotations

import re
from pathlib import Path

#: A run of sentence terminators, but not one sitting between digits — so a
#: decimal like "3.5" is not a sentence boundary.
_TERMINATOR = re.compile(r"(?<!\d)[.!?]+(?!\d)")


def segment(document: str) -> list[str]:
    """Cut a document into fragments on the terminator rule alone.

    No abbreviation, quotation or list handling: "Fig. 4" would be cut in two.
    That crudeness is the pinned rule, not an oversight, and the verifier's copy
    is crude in exactly the same way.
    """
    return [piece.strip() for piece in _TERMINATOR.split(document) if piece.strip()]


def extract(corpus_dir: Path, source_cid: str, fragment_id: int) -> str:
    """Return the fragment the claim points at."""
    document = (corpus_dir / f"{source_cid}.txt").read_text(encoding="utf-8")
    fragments = segment(document)
    if fragment_id < 0 or fragment_id >= len(fragments):
        raise ValueError(
            f"fragment_id={fragment_id} is out of range for a document with "
            f"{len(fragments)} fragment(s)"
        )
    return fragments[fragment_id]
