# totalsegmentator_minimal — CT→multi-organ-segmentation deterministic-inference audit bundle

Domain pilot: V-kernel audit bundle for TotalSegmentator (Apache 2.0,
wasserth/TotalSegmentator), the open-source CT segmentation library used by
~300,000 researchers and ~100,000 daily inference runs across radiology
research. Demonstrates that the domain-agnostic S0 integrator handles a
**Python-deep-learning re-derivation** where the deterministic function is a
PyTorch nnUNetv2 model + 165 MB of pinned weights, not a stdlib computation
like `audio_minimal` or an external CLI like `hyperframes_render_minimal`.

The re-derivation primitive is `totalsegmentator(input=..., output=...,
task="total", fast=True, ml=True, device="cpu")` with the full PyTorch
determinism incantation applied in-process before any torch op executes.
Same input + same toolchain + same weights → bit-identical multi-label NIfTI
segmentation bytes. This is the design claim; it requires `torch` +
TotalSegmentator weights to exercise, which are **not** part of the default test
run (the shipped `tests/` SKIP when `torch` is absent), so it is not validated by
CI here. Observed bit-identical cross-process on a developer environment
(`linux x86_64 / python 3.13 / torch 2.12.0+cpu`); reproduce locally by
installing the optional stack and running the pilot's own tests.

## Why this pilot exists

Medical AI has an open-source-and-reproducibility gap: independent audits
report ~74% of published medical-AI studies rely on private datasets or do
not share their code (Wu, Wu, Sun, arXiv 2603.03367, March 2026). At the
same time, adversarial medical-image fabrication is becoming meaningfully
harder to detect: a March 2026 study reported radiologists spontaneously
identified AI-generated chest X-rays at only ~41% when unaware of the
study's purpose (Tordjman et al., Mount Sinai, *Radiology* / RSNA, March
2026). The infrastructure response is consolidating around AI Bill of
Materials — content-addressed, verifiable records of what model produced
what output from what inputs with what tooling (Radanliev et al.,
*Operationalising Artificial Intelligence Bills of Materials*, Frontiers
in Computer Science, accepted January 2026; adjacent IETF work in
`draft-sharif-ai-model-lifecycle-attestation`).

A V-kernel audit bundle wrapped around TotalSegmentator is one concrete
shape of that response: every emitted bundle re-runs to the committed sha256
in any verifier process, or the verifier reports
`RE_DERIVATION_MISMATCH`. The verifier also binds the
delivered `payload/segmentation.nii.gz` bytes directly to the manifest's
committed sha256 (`TOTALSEGMENTATOR_PAYLOAD_SHA_MISMATCH` on drift) — the
file-integrity walk alone only checks self-consistency against its own
`manifest.files` entry, which a producer could re-align to whatever it
ships; the payload-binding check is what stops a bundle from certifying a
segmentation that isn't the file actually delivered. Substrate is Apache
2.0; neutral-governance donation commitment is on file (≤ 2027-03-31).

TotalSegmentator itself is a research tool, not an FDA-cleared device. This
pilot does NOT claim FDA clearance; it claims that *the audit-trail
substrate around the tool is verifiable enough to be a candidate for the
SaMD-shaped regulatory pathway*, which is a substrate-posture claim, not a
clinical-clearance claim.

## Prerequisites

- Python 3.10+
- `torch` (CPU build matched to torchvision — install from PyTorch CPU index)
- `TotalSegmentator`, `nnunetv2`, `nibabel`, `SimpleITK`
- TotalSegmentator task=297 weights (~135 MB; auto-downloaded from
  github.com/wasserth/TotalSegmentator/releases on first inference)

Install:

```bash
pip install --upgrade --index-url https://download.pytorch.org/whl/cpu torch torchvision
pip install TotalSegmentator nnunetv2 nibabel SimpleITK
```

All commands below run from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/totalsegmentator_minimal/_build_bundle.py --out-dir /tmp/ts_bundle
```

Expected output:

```
Bundle written to /tmp/ts_bundle
  schema_version       : vcp-v1.1-canary4
  bundle_id            : totalsegmentator-minimal-rc
  segmentation_sha     : <hex prefix>...
  checkpoint_sha       : <hex prefix>...
  manifest files       : 3
  spec_files           : 1
```

First build is ~60-90 s (model weight download + inference). Subsequent
builds ~15-30 s on a warm cache.

Optional: substitute a real CT volume via `--ct-path /path/to/ct.nii.gz`.
The phantom is the default for fast pytest; a real CT is the live-demo path.

## Step 2 — Verify

```bash
python examples/totalsegmentator_minimal/verify.py --bundle-dir /tmp/ts_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                              | Contract clause                                                                            |
|-------------------------------------|--------------------------------------------------------------------------------------------|
| `spec_sha_pin`                      | §C1 per-file SHA walk over `spec/`                                                         |
| `file_integrity_many_small`         | §C9 per-file SHA walk over `files/`                                                        |
| `totalsegmentator_re_derivation`    | §C6 CT → multi-label segmentation re-derivation via pinned torch + TotalSegmentator + nnUNetv2 weights |

## Step 3 — Tamper-flow demo

Mutate one byte in `source/phantom.nii.gz`, re-align its manifest SHA so
`file_integrity_many_small` passes, and the re-derivation plugin catches the
divergence in isolation because re-running inference on the tampered phantom
produces a segmentation whose sha256 no longer matches the committed one.

A second tamper shape: substitute different bytes as
`payload/segmentation.nii.gz` itself (not the input) while re-aligning its
`manifest.files` entry (self-consistent) and leaving
`manifest.payload.segmentation_sha256` honest. `file_integrity_many_small`
still passes (the substitute matches its own manifest entry), but the
payload-binding check in `totalsegmentator_re_derivation.py` hashes the
delivered file directly and fails with
`TOTALSEGMENTATOR_PAYLOAD_SHA_MISMATCH` before inference is even re-run.

Pytest exercises both end-to-end — see `tests/test_totalsegmentator_minimal.py`.

## Why the re-derivation pack imports torch (and isn't stdlib-only)

The `hyperframes_render_minimal` pack is stdlib-only because it shells to
`npx hyperframes` — the determinism contract lives in the external Node-based
CLI. TotalSegmentator has no equivalent boundary that is deterministic from
env vars alone: `torch.use_deterministic_algorithms(True)` and
`torch.set_num_threads(1)` must be applied in-process before any torch op
executes. The pack imports torch + totalsegmentator and applies these flags
itself. Process isolation from the verifier process is preserved by invoking
the pack via subprocess from `TotalSegmentatorReDerivationCheck.py`, mirroring
the hyperframes shape.

## File layout

```
examples/totalsegmentator_minimal/
├── README.md                              (this file)
├── SPLASH_NARRATIVE.md                    (Apache 2.0 splash draft — TotalSegmentator + V-kernel)
├── pilot.json
├── _build_bundle.py                       (renders fixture + assembles bundle)
├── fixture/
│   ├── phantom.nii.gz                     (committed deterministic 96^3 CT-like phantom)
│   ├── config.json                        (task=total, fast=True, ml=True, device=cpu)
│   └── make_phantom.py                    (regenerator — not used at build time)
├── totalsegmentator_re_derivation.py      (in-process determinism pack — imports torch)
├── TotalSegmentatorReDerivationCheck.py   (TypedCheck wrapper, subprocess-isolates the pack)
└── verify.py                              (pilot verifier entry)
```

## Determinism notes — what's pinned, what isn't

Pinned in `spec/tooling.json` (drift surfaces as `TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH`):

- `torch`, `torchvision`, `TotalSegmentator`, `nnunetv2`, `nibabel`, `SimpleITK`
- Python interpreter version (major.minor.micro)
- Platform (linux x86_64 vs darwin arm64 vs etc.)
- Model checkpoint sha256 (the actual neural network parameters)
- Weights URL (github.com/wasserth/TotalSegmentator/releases v2.0.0-weights)

The full task-297 weights ZIP is hosted at the canonical project release on
GitHub. TotalSegmentator v1 hosted weights on Zenodo (URLs survive as
commented references in `libs.py`); v2 moved to GitHub releases.

NOT pinned (out of scope for this pilot):

- CUDA / cuDNN / GPU driver versions — pilot is CPU-only by design.
  GPU determinism is a future tier.
- BLAS backend (MKL vs OpenBLAS vs Accelerate). On most Linux x86_64 PyTorch
  CPU builds this is MKL, but the bundle does not explicitly assert it.
- glibc / OS minor versions. Cross-machine `linux x86_64 → linux x86_64`
  determinism is validated empirically same-machine N=2; cross-machine is an
  open empirical question.

## Round-trip test

```bash
python -m pytest tests/test_totalsegmentator_minimal.py -v
```

Four test cases:
- `test_clean_bundle_passes` — build + verify → `ok=True`.
- `test_tamper_input_ct_fails_rederivation` — flip a voxel in
  `source/phantom.nii.gz`, re-align manifest SHA → verifier returns `ok=False`
  with `RE_DERIVATION_MISMATCH`.
- `test_tamper_payload_swap_fails_binding` — substitute different bytes as
  `payload/segmentation.nii.gz`, re-align its `manifest.files` entry
  (self-consistent) but leave `manifest.payload.segmentation_sha256` honest →
  verifier returns `ok=False` with `TOTALSEGMENTATOR_PAYLOAD_SHA_MISMATCH`.
- `test_tamper_tooling_spec_fails_spec_sha` — append whitespace to
  `spec/tooling.json` without re-aligning `manifest.spec_files` →
  `SPEC_SHA_MISMATCH` from `SpecShaPinCheck`.

The clean-pass and re-derivation tamper cases each invoke a live inference,
so the full pytest run takes 60-120 s on a warm-cache CPU. The payload-swap
tamper case fails before inference is re-run (the binding check is placed
ahead of the inference step), so it adds negligible time.
