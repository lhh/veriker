"""V-kernel Audit Bundle."""

from ._total_binding import (
    MAX_CANON_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    MAX_RAW_BYTES,
    MAX_STR_CODEPOINTS,
    TotalBindingError,
    canon_bytes,
    strict_loads,
    value_digest,
)
from ._version import RELEASE_STATUS, __version__

__all__ = [
    "RELEASE_STATUS",
    "__version__",
    # Canonicalisation. Exported so pilots BIND to the hardened implementation
    # instead of hand-rolling `json.dumps(sort_keys=True, separators=(",", ":"))`,
    # which admits NaN/Infinity (invalid JSON), unbounded input, cycles via
    # dataclasses, and duplicate object keys. See tools/helper_drift.py.
    "canon_bytes",
    "value_digest",
    "strict_loads",
    "TotalBindingError",
    "MAX_RAW_BYTES",
    "MAX_CANON_BYTES",
    "MAX_DEPTH",
    "MAX_NODES",
    "MAX_STR_CODEPOINTS",
]
