"""caselaw_gate_kb_recompute.py -- verifier-side case-law citation credibility-gate
re-derivation primitive, over a VERBATIM-rooted court-record corpus.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir pilot: the recompute primitive lives HERE (verifier-distribution code,
registered from the pilot's verify.py), NOT in audit_bundle/rederivation/primitives/.

RELATION TO caselaw_citation_gate_minimal
-----------------------------------------
Same gate ALGORITHM (resolve cite -> verbatim-substring misquote check -> decision).
The ONE difference is the misquote YARDSTICK:

    _minimal:  corpus record carries `holding_text` -- a human PARAPHRASE of the
               holding. The misquote check then verifies the producer's quote
               against ANOTHER human's paraphrase. That is the circularity called
               out as the load-bearing open question in
               CREDIBILITY_GATE_VKERNEL_INTEGRATION_ASSESSMENT.md.

    this pilot: corpus record carries `rooted_text` -- a VERBATIM SPAN of the
               court's actual opinion, fetched from CourtListener and frozen with
               provenance (see _root_corpus.py). The misquote check verifies the
               producer's quote appears verbatim IN THE COURT'S OWN WORDS. The
               yardstick is the opinion itself, not a summary of it.

DOMAIN
------
An AI legal assistant (the producer) drafts a filing and asserts supporting
citations, then claims an overall gate decision:

    AUTO_APPROVE     -- every asserted citation is rooted; safe to file as-is.
    ROUTE_TO_HUMAN   -- at least one citation is unresolved or misquoted;
                        a human must review before filing.

For each asserted citation, in assertion order:

    UNRESOLVED   the normalized reporter cite is ABSENT from the rooted corpus
                 -> possible fabrication, OR an authority CourtListener could not
                 root that is still in the human-root queue (default-deny to a
                 human, never auto-reject).
    MISQUOTE     the cite resolves, but the producer's quoted holding is NOT found
                 verbatim (after whitespace/case normalization) anywhere in the
                 rooted opinion text -> real source, fabricated/inverted quote
                 (the Mata v. Avianca shape).
    ROOTED       the cite resolves AND the quoted holding is a normalized substring
                 of the court's verbatim opinion text.

    decision = AUTO_APPROVE  iff  every citation is ROOTED, else ROUTE_TO_HUMAN.

SCOPE (honest framing -- read before believing more than is claimed)
--------------------------------------------------------------------
The verifier proves the gate decision is RE-DERIVABLE and TAMPER-EVIDENT under the
auditor-anchored rule: given THIS rooted corpus, a producer cannot claim
AUTO_APPROVE while hiding a fabricated or misquoted citation -- the recompute
disagrees and dispatch fails closed.

It does NOT establish that the rooting itself is correct -- that the captured
opinion text is the genuine, complete opinion for that cite is a trust-root
concern (corpus genuineness, out of scope for the verifier's re-derivation),
mitigated here by per-record CourtListener provenance
(cluster_id / opinion_id / url / retrieved_at) but NOT machine-proven. See README
"What this proves / does not".

Stdlib-only (§C5 contract). Importable WITHOUT audit_bundle on sys.path (the
RecomputedValue import is deferred into recompute()), so the spec-pinned builder
can import compute_gate_verdict() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path

# Status constants -- also the verdict vocabulary the `exact` comparator sees.
ROOTED = "ROOTED"
UNRESOLVED = "UNRESOLVED"
MISQUOTE = "MISQUOTE"

AUTO_APPROVE = "AUTO_APPROVE"
ROUTE_TO_HUMAN = "ROUTE_TO_HUMAN"

_CORPUS_REL = "corpus/rooted_records.json"
_ASSERTIONS_REL = "assertions/citation_assertions.json"


# ---------------------------------------------------------------------------
# Normalization -- internal to the resolve/misquote logic (NOT the comparator).
# ---------------------------------------------------------------------------


def _norm(text: str) -> str:
    """Casefold + collapse all runs of whitespace to a single space + strip.

    Applied to reporter cites (for corpus membership) and to opinion / quoted
    text (for the verbatim-misquote substring test). Whitespace collapse is what
    lets a clean one-line quote match against opinion text that wraps the same
    words across newlines. Deliberately conservative: it does NOT strip
    punctuation, so a quote must track the court's actual wording, not a loose
    paraphrase that happens to share keywords.
    """
    return " ".join(str(text).casefold().split())


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier -- ONE source)
# ---------------------------------------------------------------------------


def compute_gate_verdict(corpus: list, assertions: list) -> dict:
    """Canonical case-law credibility-gate re-derivation over a verbatim corpus.

    `corpus`     -- list of rooted records, each with at least `reporter_cite`
                    and `rooted_text` (verbatim opinion text), and optionally `cites`
                    (all parallel reporter cites the record is reachable by).
    `assertions` -- list of producer-asserted citations, each with `id`,
                    `reporter_cite`, and `quoted_holding`.

    Returns the representative verdict object:

        {
          "decision": "AUTO_APPROVE" | "ROUTE_TO_HUMAN",
          "citations": [ {"id", "reporter_cite", "status"}, ... ]  # assertion order
        }

    This is the PRODUCER's definition. The verifier does NOT call it -- it
    re-derives with `_recompute_gate_verdict_independent` below, written
    separately. Sharing one definition (as this pilot did until 2026-08-29)
    made the check f(x) == f(x): a tampered VALUE was still caught, but an
    error in the gate RULE was baked into claim and re-derivation alike. The
    two must never be unified.

    Fail-closed: raises ValueError/TypeError/KeyError if the corpus or assertion
    records are malformed (the verifier must not invent a verdict).
    """
    if not isinstance(corpus, list):
        raise TypeError("corpus must be a JSON array of rooted records")
    if not isinstance(assertions, list):
        raise TypeError("assertions must be a JSON array of asserted citations")

    # Index the rooted corpus by EVERY cite the record is reachable by (primary
    # `reporter_cite` plus any `cites` parallels), so a producer who cites a parallel
    # reporter (e.g. Alice as "573 U.S. 208" when the record resolved via the S.Ct.
    # parallel "134 S. Ct. 2347") still matches the same authority. A cite that maps
    # to two different records is a fixture defect -- fail closed rather than guess.
    index: dict[str, dict] = {}
    for rec in corpus:
        if not isinstance(rec, dict):
            raise TypeError(f"corpus record not an object: {rec!r}")
        rec_cites = rec.get("cites") or [rec["reporter_cite"]]
        for cite in rec_cites:
            key = _norm(cite)
            if key in index and index[key] is not rec:
                raise ValueError(f"cite maps to two corpus records: {cite!r}")
            index[key] = rec

    citations: list[dict] = []
    for a in assertions:
        if not isinstance(a, dict):
            raise TypeError(f"assertion not an object: {a!r}")
        cite = a["reporter_cite"]
        rec = index.get(_norm(cite))
        if rec is None:
            status = UNRESOLVED
        else:
            quoted = _norm(a["quoted_holding"])
            rooted_text = _norm(rec["rooted_text"])
            if quoted and quoted in rooted_text:
                status = ROOTED
            else:
                status = MISQUOTE
        citations.append(
            {
                "id": a["id"],
                "reporter_cite": cite,
                "status": status,
            }
        )

    decision = (
        AUTO_APPROVE
        if citations and all(c["status"] == ROOTED for c in citations)
        else ROUTE_TO_HUMAN
    )
    return {"decision": decision, "citations": citations}


def _recompute_gate_verdict_independent(corpus: list, assertions: list) -> dict:
    """Verifier-side gate re-derivation, written SEPARATELY from the producer.

    `compute_gate_verdict` above stays the PRODUCER's definition and is
    untouched. This function never calls it. The two implement the same gate
    rule and MUST NEVER BE UNIFIED: sharing one definition made the check
    f(x) == f(x), so an error in the RULE ITSELF -- parallel-cite resolution,
    normalization, when the gate may auto-approve -- was baked into the claimed
    verdict and the re-derivation alike and could not be caught. A tampered
    VALUE was still caught either way; method independence was not.

    Expressed differently on purpose: the parallel-cite index is built by
    iterating each record's full cite list into (key, record) pairs and
    rejecting a key that resolves to a second record, and the decision is
    derived by counting non-rooted statuses rather than by an all().
    """
    if not isinstance(corpus, list):
        raise TypeError("corpus must be a JSON array of rooted records")
    if not isinstance(assertions, list):
        raise TypeError("assertions must be a JSON array of asserted citations")

    by_cite: dict[str, dict] = {}
    for record in corpus:
        if not isinstance(record, dict):
            raise TypeError(f"corpus record not an object: {record!r}")
        reachable = record.get("cites") or [record["reporter_cite"]]
        for parallel in reachable:
            key = _norm(parallel)
            previous = by_cite.get(key)
            if previous is not None and previous is not record:
                raise ValueError(f"cite maps to two corpus records: {parallel!r}")
            by_cite[key] = record

    resolved: list[dict] = []
    unrooted = 0
    for assertion in assertions:
        if not isinstance(assertion, dict):
            raise TypeError(f"assertion not an object: {assertion!r}")
        asserted_cite = assertion["reporter_cite"]
        match = by_cite.get(_norm(asserted_cite))
        if match is None:
            status = UNRESOLVED
        else:
            claim_text = _norm(assertion["quoted_holding"])
            authority_text = _norm(match["rooted_text"])
            status = ROOTED if (len(claim_text) > 0 and claim_text in authority_text) else MISQUOTE
        if status != ROOTED:
            unrooted += 1
        resolved.append(
            {"id": assertion["id"], "reporter_cite": asserted_cite, "status": status}
        )

    approvable = len(resolved) > 0 and unrooted == 0
    return {
        "decision": AUTO_APPROVE if approvable else ROUTE_TO_HUMAN,
        "citations": resolved,
    }


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered from the pilot's verify.py before verify)
# ---------------------------------------------------------------------------


class CaselawGateKbRecompute:
    """Verifier-side primitive re-deriving the citation gate over verbatim opinions."""

    primitive_id: str = "caselaw_gate_kb_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the gate verdict from the committed corpus + assertions.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the verdict object; the verifier's `exact`
        comparator compares it to the producer's claimed verdict.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        corpus_path = bundle_dir / _CORPUS_REL
        assertions_path = bundle_dir / _ASSERTIONS_REL
        for p in (corpus_path, assertions_path):
            if not p.is_file():
                raise FileNotFoundError(f"required evidence missing in bundle: {p}")

        corpus = json.loads(corpus_path.read_bytes())
        assertions = json.loads(assertions_path.read_bytes())

        verdict = _recompute_gate_verdict_independent(corpus, assertions)
        n_rooted = sum(1 for c in verdict["citations"] if c["status"] == ROOTED)
        return RecomputedValue(
            value=verdict,
            detail=(
                f"re-derived gate over {len(verdict['citations'])} citation(s) vs "
                f"{len(corpus)} verbatim-rooted record(s): "
                f"{n_rooted} rooted -> decision={verdict['decision']}"
            ),
        )
