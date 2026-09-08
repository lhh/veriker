"""auditor_kit.py — this pilot's auditor-side primitive kit.

Registers the equilibrium-residual certificate primitive. Held by the auditor
alongside the anchored spec; the verifier refuses a kit path inside the bundle
and refuses any primitive whose source resolves inside the bundle.

INDEPENDENCE NOTE (this pilot, unlike most in the fleet, is clean here):
the registered primitive shares NO code with the producer. The producer's two
modules (_producer_solve.py, _producer_surrogate.py) solve for corner loads;
this primitive only evaluates residuals of loads already published. They are
different computations, not two copies of one computation, so a bug in the
producer's model cannot propagate into the check.
"""

from __future__ import annotations

KIT_NAME = "corner_load-equilibrium-minimal"
KIT_VERSION = "1"
KIT_REGISTERS = (
    "corner_load_vertical_residual_recompute",
    "corner_load_pitch_residual_recompute",
    "corner_load_roll_residual_recompute",
    "corner_load_transfer_split_recompute",
)

import sys  # noqa: E402
from pathlib import Path  # noqa: E402

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
_PKG_ROOT = _HERE.parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from equilibrium_residual_recompute import (  # noqa: E402
    PitchResidualRecompute,
    RollResidualRecompute,
    TransferSplitRecompute,
    VerticalResidualRecompute,
)

register_primitive(VerticalResidualRecompute())
register_primitive(PitchResidualRecompute())
register_primitive(RollResidualRecompute())
register_primitive(TransferSplitRecompute())
