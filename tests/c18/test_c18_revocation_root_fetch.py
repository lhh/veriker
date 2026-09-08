"""WS-6b: fetch_revocation_root load-path tests.

Makes the embedded revocation_root.json LOAD-BEARING: a consumer resolves the
revocation-root role via the same `fetch_sigstore_trust_root` pattern, closing
the WS-6b criterion. Self-contained (no python-tuf / toy repo — fetch_revocation_root
reads the bundled file directly; the heavyweight TUF-protocol path is covered by
test_c18_tuf_protocol.py).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.extensions.c18_tuf_bootstrap import (
    fetch_revocation_root_bootstrap_unverified,
)
from audit_bundle.extensions.c18_tuf_client import (
    ROLE_REVOCATION_ROOT,
    TUFBootstrapPlaceholderPresent,
    TUFClientError,
    TUFRoleSeparationViolation,
    fetch_revocation_root,
    validate_revocation_root_document,
)

_BUNDLED = (
    Path(__file__).resolve().parents[2]
    / "audit_bundle"
    / "extensions"
    / "_tuf_root"
    / "revocation_root.json"
)


def test_fetch_revocation_root_loads_bundled_2of3_role() -> None:
    # The shipped bundled file is pre-ceremony bootstrap material (empty sigs);
    # the structural shape is still asserted, but the loader now requires the
    # explicit bootstrap opt-in to return placeholder trust material.
    role = fetch_revocation_root_bootstrap_unverified()
    assert role["role_name"] == ROLE_REVOCATION_ROOT
    rr = role["signed"]["roles"][ROLE_REVOCATION_ROOT]
    assert rr["threshold"] == 2
    assert len(rr["keyids"]) == 3 and len(set(rr["keyids"])) == 3
    assert role["rotation_policy"]["max_validity_days"] <= 90


def test_fetch_revocation_root_fails_closed_on_bootstrap_placeholder() -> None:
    """Fail-closed default: the pre-ceremony bundled file has empty signatures,
    so the loader REFUSES it without the explicit bootstrap opt-in. The
    protection is always-on at the API boundary, not only in the release gate."""
    role = fetch_revocation_root_bootstrap_unverified()
    with pytest.raises(TUFBootstrapPlaceholderPresent):
        validate_revocation_root_document(role, source="bundled")
    # And the strict fetcher never reads the bundled file: no trust dir -> closed.
    with pytest.raises(TUFClientError, match="PERSISTENT trust_dir"):
        fetch_revocation_root(feed_url="http://127.0.0.1:9/never")


def test_validator_grades_expiry_against_now() -> None:
    """Strict validation refuses an expired revocation root and one that expires
    further ahead than its own rotation policy allows; both parsed fine before."""
    from audit_bundle.extensions.c18_tuf_client import TUFRootExpired

    import re

    doc = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    for sig in doc.get("signatures", []):
        sig["sig"] = "aa" * 32
    # Fill every ceremony placeholder so the ONLY refusal left is the expiry.
    ph = re.compile(r"^(sha256:)?TBD")

    def fill(node):
        if isinstance(node, dict):
            return {k: fill(v) for k, v in node.items()}
        if isinstance(node, list):
            return [fill(v) for v in node]
        if isinstance(node, str) and ph.match(node):
            return ("sha256:" if node.startswith("sha256:") else "") + "ab" * 32
        return node

    doc = fill(doc)
    doc["signed"]["expires"] = "2019-01-01T00:00:00Z"
    with pytest.raises(TUFRootExpired):
        validate_revocation_root_document(doc, source="test")
    doc["signed"]["expires"] = "2999-01-01T00:00:00Z"
    with pytest.raises(TUFClientError, match="max_validity_days"):
        validate_revocation_root_document(doc, source="test")
    # non-strict (bootstrap) still returns it — the caller owns the consequence
    role = validate_revocation_root_document(doc, source="test", strict=False)
    assert role["role_name"] == ROLE_REVOCATION_ROOT


def test_fetch_revocation_root_rejects_tbd_value_even_when_signed(
    tmp_path: Path,
) -> None:
    """Even with signatures present, an unfilled TBD-* value is refused by
    default (a filled signature does not excuse a placeholder digest/key)."""
    doc = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    # Give it non-empty signatures so the empty-sig check passes...
    for sig in doc.get("signatures", []):
        sig["sig"] = "aa" * 32
    # ...but plant a TBD-* placeholder value somewhere.
    doc["pinned_revocation_list_signer_fingerprint"] = "TBD-AT-CEREMONY"
    bad = tmp_path / "revocation_root.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(TUFBootstrapPlaceholderPresent, match="TBD"):
        validate_revocation_root_document(doc, source="test")
    # ...and the bootstrap-unverified variant still returns it.
    role = fetch_revocation_root_bootstrap_unverified(bundled_path=bad)
    assert role["role_name"] == ROLE_REVOCATION_ROOT


def test_bootstrap_loader_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(TUFClientError, match="missing"):
        fetch_revocation_root_bootstrap_unverified(bundled_path=tmp_path / "nope.json")


def test_fetch_revocation_root_wrong_role_name_is_separation_violation(
    tmp_path: Path,
) -> None:
    doc = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    doc["role_name"] = "sigstore-trust-root"  # wrong role in this file
    with pytest.raises(TUFRoleSeparationViolation):
        validate_revocation_root_document(doc, source="test")


def test_fetch_revocation_root_threshold_not_2_fails_closed(tmp_path: Path) -> None:
    doc = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    doc["signed"]["roles"][ROLE_REVOCATION_ROOT]["threshold"] = 1  # 1-of-3 not allowed
    with pytest.raises(TUFClientError, match="threshold"):
        validate_revocation_root_document(doc, source="test")


def test_fetch_revocation_root_expiry_over_90_days_fails_closed(tmp_path: Path) -> None:
    doc = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    doc["rotation_policy"]["max_validity_days"] = 365  # exceeds the <=90 ceiling
    with pytest.raises(TUFClientError, match="max_validity_days"):
        validate_revocation_root_document(doc, source="test")
