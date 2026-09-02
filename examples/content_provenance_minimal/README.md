# content_provenance_minimal — Content Provenance Audit Bundle Pilot

## SCOPE BOUNDARY (read first)

**This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.**

## Honest claim

> A published content artifact carries a producer-signed manifest binding it to its
> producer identity and generation inputs; the verifier re-confirms the artifact's
> bytes match the signed hash and the provenance chain is intact.  Any post-signing
> alteration fails closed.  Synthetic producer key; local-only demo.

## What this demonstrates

This pilot demonstrates **structural re-derivation of content provenance for AI-era
information integrity** — the C2PA-style problem.  A synthetic news-style text
artifact is produced by a synthetic AI writing system, signed with a producer HMAC
key, and wrapped in a provenance manifest declaring the producer identity and
generation inputs.  The audit bundle binds:

- the published content bytes (`artifact/content.txt`)
- the producer-signed provenance manifest (`artifact/provenance.json`)
- the verification payload (`payload/provenance_result.json`:
  content_sha, provenance_sha, producer_id, generation_inputs, producer_hmac)

...such that an independent verifier can:

1. Re-hash `artifact/content.txt` and assert the SHA matches both the payload's
   `content_sha` and the `content_sha` field inside the provenance manifest.
2. Re-compute `HMAC-SHA256(synthetic_key, content_bytes + "\n" + canonical(manifest
   core))` — the manifest core being every field of `artifact/provenance.json`
   except `producer_hmac` — and assert it matches the manifest's `producer_hmac`
   field, detecting any post-signing alteration to the content bytes OR to the
   producer identity, generation inputs, content_sha or timestamp the manifest
   declares. (Until 2026-08-21 the signature covered the content bytes only, so
   `producer_id` and `generation_inputs` were rewritable with no key — found by a
   red-team pass on the claimset adoption and fixed; the manifest's own
   `content_sha` field is now also checked against the re-hashed content.)
3. Assert the payload's **own** `producer_hmac` claim
   (`payload/provenance_result.json`'s `producer_hmac` field) also equals the
   re-derived HMAC.  This is checked independently of step 2 — the payload's
   signature claim is a distinct committed value from `artifact/provenance.json`
   and is bound separately, so it cannot be replaced with an arbitrary string
   while the artifact manifest's own field stays honest.
4. Assert the provenance chain fields (`producer_id`, `generation_inputs`) are
   intact and match between the payload and the manifest.

**Fail-closed on tamper**: any modification to content bytes or the provenance
manifest causes a `CONTENT_PROVENANCE_ALTERED` failure; a modification to the
payload's own `producer_hmac` claim causes a `CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH`
failure — including when only the payload's claim is forged and the artifact
manifest's copy is left honest (see Step 4 below).

## Claim-field coverage (claimset)

`payload/provenance_result.json` is the claim file, declared structured:
`manifest.claimset.claim_files = {"provenance_result": "payload/provenance_result.json"}`
(the same key the informational `manifest.payload` entry already uses). Its
nine observed fields (the field set the shipped bytes carry — the enumerator is
instance-measured, not schema-derived) are all covered; there are no residuals:

| fields | binding |
|---|---|
| `content_sha`, `provenance_sha` | equality with `sha256(artifact/content.txt)` / `sha256(artifact/provenance.json)` re-hashed by the pack |
| `producer_hmac` | equality with the HMAC the pack re-derives over the content bytes (shared synthetic key — the within-trust-domain limit stated below) |
| `producer_id`, `generation_inputs.model_id`, `generation_inputs.note`, `generation_inputs.prompt_sha`, `generation_inputs.temperature` | type-strict (canonical-JSON) equality with the corresponding fields of `artifact/provenance.json`, whose core is under the producer signature (the `generation_inputs` object is compared whole, which binds every leaf; Python `==` would have let `true` equal `1` and `1.0` equal `1`) |
| `provenance_status` | equality with the status the pack re-derives by running every check above — `CONTENT_PROVENANCE_VERIFIED` on the success path (`[CONTENT_PROVENANCE_STATUS_MISMATCH]` otherwise). This field was unread until the coverage gate named it; it is the field a downstream consumer reads, so a stated status that disagrees with the re-derivation is refused |

`ContentProvenanceReDerivationCheck` reports coverage ONLY when the pack exited
0, and only for the fields the pack's `[COMPARED]` stdout line names — a set
the pack accumulates as each comparison passes and emits from its success
return (never a constant in the plugin). An exit 0 without that line is
could-not-conclude. The per-field tamper battery in
`tests/test_content_provenance_minimal.py` requires every field to flip under
the pack's own refusal (`[CONTENT_PROVENANCE_ALTERED]`,
`[CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH]` for `producer_hmac`,
`[CONTENT_PROVENANCE_STATUS_MISMATCH]` for `provenance_status`), never via a
file-sha mismatch. The spec-pinned overlay lane (`spec_pinned_check.py`) does
not wire the pack and drops the declaration, so that lane's verdict carries the
honest "claimset: not declared" disclosure; `verify.py` wires it and prints the
receipt line under PASS.

## Honest scope and limitations

**Synthetic fixtures only.**  The content text and provenance manifest are
deterministic synthetic constructs generated at build time.  No real AI model was
invoked and no real publisher is involved.

**Does NOT detect factual inaccuracy.**  The check verifies content provenance
(unaltered bytes from the declared producer), not factual truth.  See scope
boundary above.

**Does NOT validate a real C2PA or COSE signature.**  The signing primitive used
here is HMAC-SHA256 with a hardcoded synthetic key — a structural stand-in that
demonstrates the binding pattern without requiring a real public-key infrastructure.
Production deployment would replace this with an ed25519 or ECDSA producer signing
key and a proper trust anchor.

**The synthetic producer key is NOT a secret — and it ships in-bundle-adjacent, not
out-of-band.**  `_SYNTHETIC_PRODUCER_KEY` is a hardcoded constant duplicated in both
`_build_bundle.py` (the producer/builder side) and `content_provenance_re_derivation.py`
(the verifier side) for reproducibility, and both copies live in this same repo
checkout.  Given that, the HMAC re-derivation this pilot performs proves
**within-trust-domain tamper-evidence** — that the committed bytes were not altered
after the demo producer signed them — and it is what closes the specific defect this
pilot's fix addresses (a payload signature claim that was extracted but never checked
against the re-derived value).  It does **not** prove **producer-forge-resistance**:
because the verifier holds the same key material as the producer, in a live deployment
where an attacker also has access to that shared secret, the attacker could forge a
consistent-looking HMAC from scratch.  Closing that gap requires an exogenous,
verifier-wired key delivered out-of-band (mirroring `examples/gxp_part11_minimal`'s
Pattern-2 exogenous-key architecture; see `tests/test_gxp_rederivation_exogenous_key.py`)
or a real asymmetric signing scheme (ed25519/ECDSA — see the C2PA note above) where the
verifier only ever needs a public key.  This minimal pilot has not been upgraded to
either; a production system would load the producer's signing key (or public key) from
a secure store the verifier does not also control.

**Does NOT bind to a real transparency log.**  The bundle carries no Sigstore Rekor
entries, no SCITT transparency receipts, and no external timestamp anchors.

## False-but-unaltered scope boundary — explicit test

The test suite (`tests/test_content_provenance_minimal.py`) includes a test named
`test_false_content_passes_provenance_check`.  This test:

1. Builds a bundle with the standard (factually fabricated) news article.
2. Runs the verifier.
3. Asserts the result is **PASS** (`result.ok is True`).

This is the correct behavior.  The verifier proves provenance, not truth.  The
article's claim about a battery breakthrough is fabricated, but because the bytes
are unaltered and the producer HMAC is valid, the provenance check passes.  This
is explicitly by design and documents the scope boundary.

## Prerequisites

Python 3.10+.  No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/content_provenance_minimal/_build_bundle.py --out-dir /tmp/content_prov_bundle
```

Expected output:

```
Bundle written to /tmp/content_prov_bundle
  content artifact : artifact/content.txt (... bytes)
  content sha256   : <hex>
  producer id      : NexiWriter/1.0-synthetic
  producer hmac    : hmac-sha256:<first 16 chars>...
  provenance       : artifact/provenance.json
  payload          : payload/provenance_result.json
  manifest         : /tmp/content_prov_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/content_provenance_minimal/verify.py --bundle-dir /tmp/content_prov_bundle
```

Expected stdout: `PASS — content provenance verified: ...`.  Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                                 | Contract clause                           |
|----------------------------------------|-------------------------------------------|
| `file_integrity_many_small`            | §C9 per-file SHA walk                     |
| `content_provenance_re_derivation`     | §C6 content provenance re-derivation      |

## Step 3 — Tamper-flow demo

Overwrite the content file with garbage bytes:

```bash
printf "TAMPERED_CONTENT" > /tmp/content_prov_bundle/artifact/content.txt
```

Re-run the verifier:

```bash
python examples/content_provenance_minimal/verify.py --bundle-dir /tmp/content_prov_bundle
```

Expected exit code: `1`.  The verifier detects:
- `BAD_FILE_SHA` from `file_integrity_many_small` (content hash no longer matches manifest)
- `CONTENT_PROVENANCE_ALTERED` from `content_provenance_re_derivation` (SHA + HMAC mismatch)

## Step 4 — Payload-signature-forgery demo (strongest producer)

Step 3 tampers a file the manifest's per-file SHA walk also catches. The stronger
attack is a producer that forges only the payload's `producer_hmac` claim and then
re-hashes its own tampered `payload/provenance_result.json` into `manifest.json`,
so `file_integrity_many_small`'s SHA walk sees a self-consistent bundle and stays
silent — `artifact/provenance.json`'s own `producer_hmac` field is left untouched
and honest throughout.  This is exactly the defect this pilot's fix closes: the
payload's own signature claim, independently of the artifact manifest's copy.

`tests/test_content_provenance_minimal.py::test_forged_payload_hmac_honest_manifest_sha_fails`
builds this bundle programmatically and asserts the verifier still fails closed with
`CONTENT_PROVENANCE_PAYLOAD_HMAC_MISMATCH`, even though `file_integrity_many_small`
alone would report `PASS`.

## File layout

```
examples/content_provenance_minimal/
├── _build_bundle.py                        # builds the audit bundle from synthetic fixtures
├── verify.py                               # runs TypedCheck plugins; exits 0 on PASS
├── ContentProvenanceReDerivationCheck.py   # TypedCheck plugin (subprocess wrapper)
├── content_provenance_re_derivation.py     # re-derivation implementation (stdlib only)
├── pilot.json                              # pilot metadata
└── README.md                               # this file

tests/
└── test_content_provenance_minimal.py      # happy-path + tamper + scope-boundary tests
```

## AI-era disinformation context

This pilot supports the "AI-era disinformation" brief slide with an honest claim:
the V-Kernel substrate can prove content provenance (who produced what and that it
is unaltered), which is a necessary but not sufficient condition for information
integrity.  Truth-detection is explicitly out of scope and requires a separate,
domain-specific fact-checking layer.

The provenance layer and fact-checking layers are complementary: provenance proves
"this content came from this system unaltered," fact-checking proves "this claim is
accurate."  Neither subsumes the other.
