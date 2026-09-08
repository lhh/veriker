# anticheat_adjudication_minimal — verify benchmark

Purpose: replace the prose-only "~0.27s clean verify" claim with a measured,
reproducible artifact before the figure goes near a customer (Jared's flag,
2026-07-21). Numbers below are the record; re-run to reproduce.

## Environment

- Machine: the internal design notes dev host (Linux 6.6 WSL2), single core, warm page cache.
- Python 3.12.3, stdlib only, no third-party deps, no network on the verdict path.
- Bundle: the shipped 6-case pilot (`_build_bundle.py`), plus synthetic
  case-count scale-ups (case/adjudicator/timestamp templates repeated).
- Two clocks reported: **cold** = full `python verify.py` subprocess incl.
  interpreter startup; **warm in-process** = `BundleVerifier.verify()` only.

## Cold clean verify (what the demo actually runs)

`python examples/anticheat_adjudication_minimal/verify.py --bundle-dir <6-case>`,
10 timed runs after 2 warmup runs, cold interpreter each run:

| stat | seconds |
|---|---|
| median | 0.106 |
| mean | 0.135 |
| min | 0.095 |
| max | 0.194 |

The prose "~0.27s" is conservative on this host. Safe public phrasing stays
**"sub-second on a real bundle"** — never "at any scale" (see cap below).

## Scaling curve (warm, in-process, re-derivation + full SHA walk)

| cases | median verify (s) | bundle bytes | result |
|---|---|---|---|
| 6 | 0.054 | 20 KB | PASS |
| 100 | 0.074 | 278 KB | PASS |
| 1,000 | 0.252 | 2.7 MB | PASS |
| 5,000 | 0.746 | 13.7 MB | PASS |
| 10,000 | — | 27.4 MB | **REJECT: INPUT_SIZE_EXCEEDED** |

Roughly linear (~0.13 ms/case amortized). The verifier enforces a **16 MB
per-input cap**, so a single bundle tops out near ~6,000 cases (each case emits
5 fragment anchors → the anchor file dominates size). Batches above that MUST be
sharded into multiple bundles; this is a real operational constraint, not a
verify-speed limit.

## Bearing on the pitch's economics claim

"Sample becomes the population" holds: at Xbox's 332,000 appeals, per-appeal
re-derivation is ~0.15 ms, so verification is not the cost — emission and human
handling of the cases that fail to re-derive are. But do NOT imply a single
monolithic 332K-case verify: at the 16 MB cap that is ~60+ sharded bundles.
State it as per-appeal cost, or as a sharded batch, never as one run.

## Reproduce

Cold: loop `python examples/anticheat_adjudication_minimal/verify.py
--bundle-dir /tmp/anticheat_bundle` and time each invocation.
Scale: monkeypatch `_build_bundle._CASES / _ADJUDICATORS / _TIMESTAMPS` to N
repeated entries, build, and time `BundleVerifier([...]).verify(bundle_dir)`
in-process. All raw commands are in the session that produced this file
(2026-07-21).
