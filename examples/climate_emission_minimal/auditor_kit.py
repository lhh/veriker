"""auditor_kit.py — this pilot's auditor-side primitive kit.

The auditor's kit for an Axis-2 bundle is the ANCHOR BYTES plus the PRIMITIVE
REGISTRATIONS. This module is the second half for climate_emission_minimal: its
import-time effect registers the pilot-local `climate_attribution_recompute`
primitive, so the SHIPPED CLI can re-derive a PRODUCER's climate bundle with
nothing pilot-shaped beyond the kit:

    <the top-level verify CLI> --bundle-dir /path/to/PRODUCERS/climate_bundle \
        --spec-anchor examples/climate_emission_minimal/spec_pinned/climate.spec.json \
                      examples/climate_emission_minimal/spec_pinned/climate_emission.spec.json \
        --primitives  examples/climate_emission_minimal/auditor_kit.py

`--bundle-dir` is the PRODUCER's bundle (built elsewhere), never this example
directory: this dir is itself bundle-shaped, so `--bundle-dir
examples/climate_emission_minimal` would resolve `--primitives …/auditor_kit.py`
INSIDE the bundle and be refused (PRIMITIVES_ARG_INVALID) — which is the guard
working, not a bug. The pilot's own `verify.py` loads THIS kit and builds the
anchor from the committed spec, so it is the one-command equivalent of the call
above (one registration path, byte-identical verdict).

Hold this file the way you hold the anchor: it is CODE the verifier executes
(the CLI records its sha256 on the verdict face, refuses a kit path inside the
bundle, and refuses any registered primitive whose SOURCE resolves inside the
bundle). INDEPENDENCE CAVEAT: for a shipped demo the recompute
(`climate_attribution_recompute.compute_attribution`) is the SAME function
`_build_bundle.py` calls to write the claimed output — builder and checker share
one definition, so this exemplar shows the WIRING, not method-independent
re-derivation. A real engagement holds an auditor recompute written against the
spec, independently of the producer's builder.
"""

from __future__ import annotations

# MANIFEST — what this kit says it adds, read by PARSING this file (never by
# executing it) and compared against what it actually registered. KIT_NAME and
# KIT_VERSION are labels, imposing no format; KIT_REGISTERS is the CLAIM, and a
# disagreement with reality in either direction is reported on the verdict face.
# It is LEGIBILITY, not a defence: this file is code the verifier executes with
# its own authority, so it catches drift between the declaration and the
# behaviour, not a kit that misdeclares deliberately.
KIT_NAME = "climate-emission-minimal"
KIT_VERSION = "1"
KIT_REGISTERS = ("climate_attribution_recompute",)

import sys  # noqa: E402
from pathlib import Path  # noqa: E402

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
_PKG_ROOT = _HERE.parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from climate_attribution_recompute import ClimateAttributionRecompute  # noqa: E402

register_primitive(ClimateAttributionRecompute())
