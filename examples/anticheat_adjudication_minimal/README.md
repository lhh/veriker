# anticheat_adjudication_minimal — Competitive-Game Ban-Adjudication Audit Bundle

Minimal domain pilot: a threshold-rule anti-cheat ban-adjudication engine (CS2/VAC
archetype), bundled for V-Kernel audit verification with **adjudicator-responsibility
attestation** binding.

## What this pilot does — and does NOT — prove (read first)

The anti-cheat nightmare has two layers, and this pilot only touches one:

1. **Detection** — *is this player actually cheating?* (ML / heuristics / kernel
   telemetry / statistical anomaly models). False positives live here. **This pilot
   does nothing for detection.** It does not improve accuracy or lower the
   false-positive rate. If the policy is wrong, the verifier faithfully attests a
   wrong verdict.
2. **Adjudication / accountability** — *once flagged, can the ban be justified,
   disputed, and trusted?* This is the layer the pilot demonstrates.

The verifier proves two things and nothing more:
- the ban verdict **followed the committed detection policy** over the committed
  evidence (re-derivable by an independent party), and
- the named adjudicator's signature **genuinely binds** to that verdict — a post-hoc
  verdict flip is detectable even when file SHAs are re-aligned.

It does **not** prove the policy correctly distinguishes cheaters from skilled players.

## The problem being addressed (no fabricated statute — documented industry pain)

Competitive games ban players from opaque, unappealable verdicts:

- Valve's VAC policy is *no appeals*; bans reverse only via opaque internal
  investigation, and Valve **deliberately does not disclose the detected cheat**
  because revealing detection signatures helps cheaters evade.
- Anti-cheat providers "rarely offer concrete evidence" (Irdeto), so neither the
  dev's support team nor the player can verify an accusation — *"who's telling the
  truth?"* is unanswerable by design. Cheaters lie about "false bans" online and
  cannot be refuted.
- Legal teams reportedly want ~100% proof before banning, forcing expensive manual
  replay review.
- False positives are real and costly (the Modern Warfare 2 incident wrongly banned
  ~12,000 players after a DLL update).

The vise: **disclose evidence → cheaters reverse-engineer your detector; don't
disclose → every banned player screams "false ban" and you can't refute them.**

The V-Kernel move is **commit-without-disclose**: at ban time the system commits the
evidence (SHA-pinned + fragment-anchored), the policy contract, and the verdict, plus
an HMAC-signed adjudicator attestation. An independent arbiter (esports league, court,
the player under NDA) can verify *the verdict followed the stated policy over evidence
that existed at ban time and was not fabricated post-hoc* — **without** the bundle
having to reveal the detection signatures to the public. This shifts the dispute from
he-said-she-said to **"show me the receipt."** A genuine false positive can be handed a
receipt; a lying cheater cannot produce one showing the verdict violated policy.

> **Demo vs. production disclosure.** This demo commits the HMAC key and the full
> detection policy *inside* the bundle so the pilot is end-to-end reproducible (same
> choice as `prior_auth_minimal`). In production the attestation key is HSM-backed and
> held by the arbiter, and the disclosure scope is a deployment decision: a public
> bundle can carry only committed hashes + verdict + policy *identifier*, while the
> raw signals and full policy are revealed selectively to the arbiter. The substrate
> shape is identical; only what travels with the bundle changes.

## The policy is auditor-pinned — "you cannot change the rule after the ban"

The re-derivation confirms the verdict follows from the policy **as committed in the
bundle**. That alone does not stop a *producer* who substitutes a laxer policy,
re-derives a consistent (all-clear) claim, re-mints the HMACs, and repairs every
manifest SHA — a coherent bundle the manifest-only checks pass. The property "a rule
fixed before the match, unchanged since" requires the policy to be pinned to the
**auditor's** anchor, not merely to the producer-written manifest.

The anchored spec-pinned path (`spec_pinned_check.py`) does exactly that. The auditor
spec (`spec_pinned/anticheat_adjudication.spec.json`) carries a `pinned_inputs` map:

```json
"pinned_inputs": { "evidence/detection_policy.json": "<sha256>" }
```

The verifier (§4a.7) re-hashes the committed policy and fails closed
(`PINNED_INPUT_MISMATCH`) if it differs from the pinned SHA — **before** the recompute
even reads it. Because that pin lives inside the SHA-anchored spec, an attacker who
edits the pin to match a swapped policy changes the spec's SHA, which the auditor
anchor no longer lists → `AnchorViolation`. Both moves fail closed. This closes the
gap between the legacy `verify.py` (no anchor — a coherent policy swap passes) and the
claim the product makes: run the **anchored** path (`spec_pinned_check.py` /
`make_verifier(anchor)`) whenever "the rule was fixed before the ban" is load-bearing.
Tests: `tests/test_anticheat_adjudication_policy_anchor.py`.

## Differentiator vs. other decision pilots

Same **decision-adjudication + HMAC-attestation shape family** as `prior_auth_minimal`
(provider sign-off), `fintech_audit_minimal` / `cloudflare_ai_gateway_minimal` /
`ibm_jurisdictional_routing_minimal` (policy-rule admission). The distinct surface here
is the *adversarial-dispute* framing: a `review` verdict (flag-for-human, do **not**
auto-ban) is the explicit false-positive guard, and the adjudicator attestation
distinguishes an **automated detector-version** sign-off from a **human moderator**
sign-off — answering "who stands behind this ban" cryptographically.

## Re-derivation primitive

```
for each flagged case (from evidence/detection_signals.jsonl):
    for each rule (sorted by rule_id, from evidence/detection_policy.json):
        if every condition holds (signal >= / <= threshold, AND'd):
            emit { model_recommendation: rule.verdict, matched_rule_id: rule.rule_id }
            break
    if no rule matched: emit { model_recommendation: "clear", matched_rule_id: null }

assert derived verdicts == payload/ban_decisions.json (model_recommendation + matched_rule_id)
assert payload/ban_decisions.json.final_verdict == derived model_recommendation
assert payload/adjudication_provenance.jsonl.model_recommendation
       == payload/ban_decisions.json.model_recommendation   (no drift between the copies)

for each row in payload/adjudication_provenance.jsonl:
    expected_hmac = HMAC-SHA256(
        key=payload/attestation_key.hex,
        msg="{adjudicator_id}|{case_id}|{final_verdict}|{attestation_timestamp}|{adjudicator_type}"
    )
    assert expected_hmac == row.attestation_hmac
```

`adjudicator_type` (`automated` vs. `human`) is bound into the HMAC message. WHO
stands behind a ban — an automated detector-version sign-off or a human moderator
sign-off — is the responsible-actor property this pilot exists to demonstrate;
this field has no other copy anywhere in the bundle to cross-check against, so the
HMAC binding is the only thing standing between it and free forgery.

`final_verdict` in `payload/ban_decisions.json` is bound to the independently
re-derived `model_recommendation` — this pilot's honest construction never lets an
adjudicator override the model recommendation (the adjudicator adopts it as-is),
so `final_verdict IS model_recommendation` with no slack. Before this fix,
`final_verdict` was never read by the checker at all: a producer could ship any
value there with zero consequence, even though it is the field the pilot's own
verdict claim is named after.

## Honesty rail — what the attestation HMAC does and does not prove

`payload/attestation_key.hex` **ships inside the bundle** (see File layout below).
Per this repo's signing vocabulary ("sign", §C-series): an `_hmac`
scheme is **symmetric tamper-evidence within a trust domain — any key holder can
mint — NOT non-repudiation**. Because the key travels with the bundle, the trust
domain here is "anyone who has the bundle," which includes the bundle's own
producer. Re-verifying the HMAC (now over `adjudicator_id`, `case_id`,
`final_verdict`, `attestation_timestamp`, and `adjudicator_type` together) proves
the five fields are **internally self-consistent as shipped** and catches a
downstream party who edits the record without also recomputing its signature
(Tamper B/C below). It does **not** give non-repudiation, and it does **not**
protect against an adversarial *producer*: a producer who fabricates the entire
bundle — including a false `adjudicator_type` — holds the same key the verifier
uses and can mint a self-consistent forgery from scratch. Closing that gap
requires an exogenous, verifier-wired key delivered out-of-band (this minimal
pilot has not been migrated to that architecture, same posture as
`prior_auth_minimal`); do not read a green `PASS` here as proof that the named
adjudicator type actually reviewed the case — only that the shipped record has
not been altered in transit without also updating its own signature.

### The synthetic policy + cases

| Rule (sorted by `rule_id`) | Conditions | Verdict |
|---|---|---|
| `rule-A-aimbot-snap` | `snap_variance_deg ≤ 0.5` AND `flick_reaction_ms ≤ 80` | `ban` |
| `rule-B-triggerbot` | `flick_reaction_ms ≤ 50` AND `headshot_ratio ≥ 0.9` | `ban` |
| `rule-C-wallhack-prefire` | `prefire_rate ≥ 0.6` | `ban` |
| `rule-D-suspicious-review` | `hit_ratio ≥ 0.75` AND `flick_reaction_ms ≤ 130` | `review` |
| *(default)* | — | `clear` |

6 cases: 3 `ban` (aimbot / triggerbot / wallhack), 1 `review` (a skilled pro with high
hit-ratio but human reaction time — flagged for human review, **not** auto-banned), 2
`clear`. Thresholds are illustrative synthetic values, not lifted from any real vendor.

## Prerequisites

Python 3.11+. No third-party dependencies. Run all commands from the
**v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/anticheat_adjudication_minimal/_build_bundle.py --out-dir /tmp/anticheat_bundle
```

Expected output:

```
Bundle written to /tmp/anticheat_bundle
  flagged cases        : 6
  detection rules      : 4
  decisions            : 6 (ban=3 review=1 clear=2)
  provenance rows      : 6
  fragment anchors     : 30 OpaqueFragment (kind_tag=detection_signal)
  dispatch records     : 3 (COMPUTE + DETECTION_EVAL + ADJUDICATOR_ATTEST)
  manifest files       : <N>
  manifest             : /tmp/anticheat_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/anticheat_adjudication_minimal/verify.py --bundle-dir /tmp/anticheat_bundle
```

Must print `PASS` and exit 0. Registers three plugins:

| Plugin | Contract clause |
|---|---|
| `file_integrity_many_small` | §C9 per-file SHA walk |
| `anticheat_re_derivation` | §C6 verdict re-derivation + adjudicator HMAC re-verify |
| `dispatch_record_wellformed` | §C15 op-kind + effect well-formedness |

## Step 3 — Tamper-flow demo

**Tamper A — detection signal content (decision-policy mismatch):**
Relax a banned player's signals below all thresholds, then re-align the manifest SHA so
`file_integrity_many_small` does not mask the re-derivation failure:

```python
import json, hashlib
from pathlib import Path
p = Path('/tmp/anticheat_bundle/evidence/detection_signals.jsonl')
lines = p.read_text().splitlines()
row = json.loads(lines[0])
row['signals'] = {"hit_ratio":0.4,"headshot_ratio":0.3,"prefire_rate":0.05,
                  "flick_reaction_ms":250.0,"snap_variance_deg":4.0}  # now re-derives 'clear'
lines[0] = json.dumps(row, sort_keys=True)
p.write_text('\n'.join(lines) + '\n')
mp = Path('/tmp/anticheat_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['evidence/detection_signals.jsonl'] = hashlib.sha256(p.read_bytes()).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
```

Re-run `verify.py` — expect exit 1, reason `RE_DERIVATION_MISMATCH`.

**Tamper B — final verdict (HMAC mismatch):**
Flip a `ban` to `clear` in a provenance row without recomputing its HMAC:

```python
import json, hashlib
from pathlib import Path
p = Path('/tmp/anticheat_bundle/payload/adjudication_provenance.jsonl')
lines = p.read_text().splitlines()
for i, line in enumerate(lines):
    row = json.loads(line)
    if row['final_verdict'] == 'ban':
        row['final_verdict'] = 'clear'   # post-hoc flip; HMAC no longer valid
        lines[i] = json.dumps(row, sort_keys=True)
        break
p.write_text('\n'.join(lines) + '\n')
mp = Path('/tmp/anticheat_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['payload/adjudication_provenance.jsonl'] = hashlib.sha256(p.read_bytes()).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
```

Re-run `verify.py` — expect exit 1, reason `ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID`.
The adjudicator's identity is cryptographically bound to their verdict — a post-hoc
flip is detectable even when SHA alignment is correct. This is the "show me the receipt"
property.

**Tamper C — ban_decisions.json final_verdict (re-derivation mismatch), everything
else honest:**
Flip `final_verdict` directly in `payload/ban_decisions.json` — leave evidence,
policy, `model_recommendation`/`matched_rule_id`, and the entire
`adjudication_provenance.jsonl` / HMAC chain untouched:

```python
import json, hashlib
from pathlib import Path
p = Path('/tmp/anticheat_bundle/payload/ban_decisions.json')
decisions = json.loads(p.read_text())
for d in decisions:
    if d['final_verdict'] == 'ban':
        d['final_verdict'] = 'clear'   # flip ban -> no-ban; nothing else changes
        break
p.write_text(json.dumps(decisions, indent=2, sort_keys=True) + '\n')
mp = Path('/tmp/anticheat_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['payload/ban_decisions.json'] = hashlib.sha256(p.read_bytes()).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
```

Re-run `verify.py` — expect exit 1, reason family `RE_DERIVATION_MISMATCH`
with detail tag `ANTICHEAT_FINAL_VERDICT_MISMATCH`. Before this fix, `final_verdict`
was never read by the checker at all, so this exact mutation passed silently — the
confirmed verifier defect this pilot now closes.

**Tamper D — adjudicator_type (HMAC mismatch):**
Relabel a `human` sign-off as `automated` (or vice versa) without recomputing its
HMAC:

```python
import json, hashlib
from pathlib import Path
p = Path('/tmp/anticheat_bundle/payload/adjudication_provenance.jsonl')
lines = p.read_text().splitlines()
for i, line in enumerate(lines):
    row = json.loads(line)
    if row['adjudicator_type'] == 'human':
        row['adjudicator_type'] = 'automated'   # relabel; HMAC no longer valid
        lines[i] = json.dumps(row, sort_keys=True)
        break
p.write_text('\n'.join(lines) + '\n')
mp = Path('/tmp/anticheat_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['payload/adjudication_provenance.jsonl'] = hashlib.sha256(p.read_bytes()).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
```

Re-run `verify.py` — expect exit 1, reason `ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID`.
Before this fix, `adjudicator_type` was excluded from the HMAC message and had no
other copy in the bundle, so this exact mutation passed silently — the second
confirmed verifier defect this pilot now closes.

## Fragment anchors

| Anchor key shape | kind_tag | Locator fields |
|---|---|---|
| `<case_id>-sig-<signal_name>` | `detection_signal` | `finding_id`, `player_id`, `match_id`, `signal_type`, `value` |

## File layout

```
examples/anticheat_adjudication_minimal/
├── _build_bundle.py                    # synthesizes fixtures + builds audit bundle
├── verify.py                           # pilot-local plugin registration + verifier wrap
├── anticheat_re_derivation.py          # stdlib re-derivation + HMAC re-verify pack (§C6)
├── AnticheatReDerivationCheck.py       # TypedCheck plugin (subprocess wrapper)
└── README.md

Bundle output (/tmp/anticheat_bundle/):
  evidence/
  ├── detection_signals.jsonl           # 6 flagged cases (server-side detection signals)
  └── detection_policy.json             # 4 threshold rules (committed policy contract)
  payload/
  ├── ban_decisions.json                # ban / review / clear outcomes (model output)
  ├── adjudication_provenance.jsonl      # adjudicator attestation log (the differentiator)
  └── attestation_key.hex               # synthetic HMAC key committed to bundle (demo only)
  manifest.json                         # SHA-pinned for every file above
```

Tests: `tests/test_anticheat_adjudication_minimal.py`
