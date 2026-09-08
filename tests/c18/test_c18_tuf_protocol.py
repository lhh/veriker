"""Integration regression guard for the C18 substrate-verifier TUF client.

This is the test whose ABSENCE allowed finding E-1 to ship: nothing drove a real
`ngclient.Updater.refresh()` through the shipped `fetch_release_manifest`, so an
incompatible python-tuf API change (tuf 7.0 made `Updater(bootstrap=...)` a
REQUIRED keyword-only arg) silently disabled the entire TUF protocol path while
fail-closing every fetch.

These tests build a spec-compliant toy TUF repo with python-tuf's own metadata
API (no mocks), serve it over localhost, and drive the SHIPPED code path. They
will FAIL if a future python-tuf release breaks the wrapper again.

Mirrors redteam/streamE_tuf_protocol/ (the adversarial PoCs); this is the
CI-resident positive guard.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# python-tuf is a hard dep for the substrate-verifier path (pyproject: tuf>=6.0),
# but the stdlib-only verifier does not need it — skip cleanly if absent.
pytest.importorskip("tuf")

from tests.fixtures.tuf_toy_repo import (  # noqa: E402
    RELEASE_TARGET,
    ToyTUFRepo,
    serve,
)

if sys.platform == "win32":
    # python-tuf 7.0's Updater symlinks root.json; Windows blocks os.symlink
    # without privilege. The substrate runs on Linux OCI — shim symlink->copy so
    # the protocol runs in CI on Windows too. No effect on the code under test.
    from tests.fixtures import tuf_winshim

    tuf_winshim.install()

GOOD_DIGEST = "sha256:" + "ab" * 32


@pytest.fixture()
def served_repo(tmp_path):
    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST)
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        yield repo, root_path, base
    finally:
        httpd.shutdown()


def test_shipped_fetch_runs_full_tuf_protocol(served_repo, tmp_path, monkeypatch):
    """E-1 GUARD: the shipped fetch_release_manifest must actually drive
    ngclient.Updater.refresh() and return the release manifest — not raise
    before the protocol runs (which is what the missing bootstrap= did)."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base = served_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)

    out = tc.fetch_release_manifest(
        release_version="v0.3.0",
        feed_url=base,
        trust_dir=tmp_path / "trust",
    )
    content = Path(out["target_path"]).read_text(encoding="utf-8")
    assert f"image_digest={GOOD_DIGEST}" in content
    assert out["target_name"] == RELEASE_TARGET


def test_rollback_rejected_on_persistent_trust_dir(served_repo, tmp_path, monkeypatch):
    """PROTOCOL GUARD: with a persistent trust dir (the production
    --tuf-trust-bundle path), python-tuf must reject a feed that rolls metadata
    back to an older, validly-signed version."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base = served_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    trust = tmp_path / "trust"

    # First fetch establishes versions 1..N; bump the repo to v5 then fetch.
    repo.build(
        timestamp_version=5,
        snapshot_version=5,
        targets_version=5,
        image_digest=GOOD_DIGEST,
    )
    tc.fetch_release_manifest(release_version="v0.3.0", feed_url=base, trust_dir=trust)

    # Attacker rolls the feed back to v3 (older, still validly signed).
    repo.build(
        timestamp_version=3,
        snapshot_version=3,
        targets_version=3,
        image_digest=GOOD_DIGEST,
    )
    with pytest.raises(tc.TUFClientError):
        tc.fetch_release_manifest(
            release_version="v0.3.0", feed_url=base, trust_dir=trust
        )


def test_ephemeral_trust_dir_rejected_by_default(served_repo, monkeypatch):
    """1b GUARD: with no trust_dir, the call must FAIL CLOSED — an ephemeral
    per-call dir silently disables rollback/freeze protection."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base = served_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)

    with pytest.raises(tc.TUFClientError, match="PERSISTENT trust_dir"):
        tc.fetch_release_manifest(release_version="v0.3.0", feed_url=base)

    # Explicit opt-in still works (one-shot/test use).
    out = tc.fetch_release_manifest(
        release_version="v0.3.0", feed_url=base, allow_ephemeral_trust_dir=True
    )
    assert f"image_digest={GOOD_DIGEST}" in Path(out["target_path"]).read_text("utf-8")


def test_missing_payload_type_rejected(tmp_path, monkeypatch):
    """M7 GUARD: a target whose signed metadata omits custom.payload_type must
    be rejected — the allowlist was documented fail-closed but never enforced,
    and absence must not evade the gate."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, payload_type=None)
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFTargetUnknownPayloadType):
            tc.fetch_release_manifest(
                release_version="v0.3.0", feed_url=base, trust_dir=tmp_path / "trust"
            )
    finally:
        httpd.shutdown()


def test_unknown_payload_type_rejected(tmp_path, monkeypatch):
    """M7 GUARD: a declared-but-unrecognized payload_type is rejected."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, payload_type="application/x-evil")
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFTargetUnknownPayloadType):
            tc.fetch_release_manifest(
                release_version="v0.3.0", feed_url=base, trust_dir=tmp_path / "trust"
            )
    finally:
        httpd.shutdown()


def test_toy_repo_payload_type_matches_shipped_constant():
    """The toy repo's literal must track the shipped allowlist entry — drift
    here would green the toy feed while a real feed minted with the constant
    fails (or vice versa)."""
    from audit_bundle.extensions import c18_tuf_client as tc
    from tests.fixtures import tuf_toy_repo as tr

    assert tr.RELEASE_MANIFEST_PAYLOAD_TYPE == tc.RELEASE_MANIFEST_PAYLOAD_TYPE
    assert tc.RELEASE_MANIFEST_PAYLOAD_TYPE in tc.ACCEPTABLE_PAYLOAD_TYPES


def test_threshold_downgrade_on_rotation_rejected(served_repo, tmp_path, monkeypatch):
    """PROTOCOL GUARD (CVE-2020-6174 class): a root rotation signed by fewer than
    the OLD root's threshold must be rejected."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base = served_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    trust = tmp_path / "trust"

    tc.fetch_release_manifest(release_version="v0.3.0", feed_url=base, trust_dir=trust)
    # root v2 (threshold 1) signed by only 1 of the 2 old signing keys.
    repo.rebuild_root(new_version=2, new_threshold=1, signed_by_indices=(0,))
    with pytest.raises(tc.TUFClientError):
        tc.fetch_release_manifest(
            release_version="v0.3.0", feed_url=base, trust_dir=trust
        )


# ===========================================================================
# The three role documents ride the TUF chain, not a regex (2026-09-02)
# ===========================================================================
#
# Until this battery existed, only the release MANIFEST.txt went through
# ngclient. `fetch_sigstore_trust_root`, `fetch_plugin_allowlist` and
# `fetch_revocation_root` were `json.loads` of a local file behind a
# `^(sha256:)?TBD` regex — an attacker who could write the file (a site-packages
# dir, an export, a rebuilt image layer) owned all three roles. Now each is a
# TARGET of the same repository, authenticated by the root-anchored targets /
# snapshot / timestamp chain, hash-pinned, payload-typed, and only THEN
# structurally validated.

import json  # noqa: E402

_ROOT_DIR = _PKG_ROOT / "audit_bundle" / "extensions" / "_tuf_root"


def _filled(doc):
    """Replace every unfilled ceremony placeholder in a bundled role doc with a
    syntactically valid value, so the toy feed models a POST-ceremony role."""
    import re

    ph = re.compile(r"^(sha256:)?TBD")

    def walk(node):
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str) and ph.match(node):
            return ("sha256:" if node.startswith("sha256:") else "") + "ab" * 32
        return node

    out = walk(doc)
    for sig in out.get("signatures", []) or []:
        if isinstance(sig, dict) and not sig.get("sig"):
            sig["sig"] = "cd" * 64
    # A post-ceremony role is CURRENT: the bundled revocation root's expiry
    # (2026-08-18) is already in the past, and strict validation grades it.
    if isinstance(out.get("signed"), dict) and "expires" in out["signed"]:
        from datetime import datetime, timedelta, timezone

        out["signed"]["expires"] = (
            (datetime.now(timezone.utc) + timedelta(days=30))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    return out


def role_docs() -> dict[str, dict]:
    """The bundled role documents with every placeholder filled. The two
    signed-shape roles are NOT yet signed with real keys — `sign_role_docs`
    does that, and every served feed must call it AFTER its last mutation of
    `signed`, because the strict fetchers verify the documents' own 2-of-3."""
    return {
        name: _filled(json.loads((_ROOT_DIR / fname).read_text(encoding="utf-8")))
        for name, fname in (
            ("sigstore-trust-root", "sigstore_trust_root.json"),
            ("plugin-allowlist", "plugin_allowlist.json"),
            ("revocation-root", "revocation_root.json"),
        )
    }


def sign_role_docs(docs: dict[str, dict]) -> dict[str, object]:
    """Re-key and really sign the signed-shape role documents (2 of 3 fresh
    Ed25519 keys each). Returns the keys per role for tests that need them."""
    from tests.fixtures.dsse_trust_material import (  # noqa: PLC0415
        RevocationRootKeys,
        sign_role_document,
    )

    out: dict[str, object] = {}
    for role in ("sigstore-trust-root", "revocation-root"):
        if role in docs and isinstance(docs[role].get("signed"), dict):
            keys = RevocationRootKeys.generate()
            sign_role_document(docs[role], role, keys)
            out[role] = keys
    return out


def signed_role_docs() -> dict[str, dict]:
    docs = role_docs()
    sign_role_docs(docs)
    return docs


def _role_targets(docs, *, payload_types=None):
    from audit_bundle.extensions import c18_tuf_client as tc

    pt = payload_types or tc.ROLE_TARGET_PAYLOAD_TYPES
    return {
        tc.ROLE_TARGET_NAMES[role]: (json.dumps(doc).encode("utf-8"), pt.get(role))
        for role, doc in docs.items()
    }


@pytest.fixture()
def served_role_repo(tmp_path):
    repo = ToyTUFRepo(tmp_path / "repo")
    docs = signed_role_docs()
    repo.build(image_digest=GOOD_DIGEST, extra_targets=_role_targets(docs))
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        yield repo, root_path, base, docs
    finally:
        httpd.shutdown()


_FETCHERS = {
    "sigstore-trust-root": "fetch_sigstore_trust_root",
    "plugin-allowlist": "fetch_plugin_allowlist",
    "revocation-root": "fetch_revocation_root",
}


@pytest.mark.parametrize("role", sorted(_FETCHERS))
def test_R1_role_document_is_fetched_through_the_tuf_chain(
    served_role_repo, tmp_path, monkeypatch, role
):
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base, docs = served_role_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    got = getattr(tc, _FETCHERS[role])(feed_url=base, trust_dir=tmp_path / "trust")
    # The value itself says which chain authenticated it (the bootstrap loaders
    # return a bare dict; a consumer can tell the two apart by shape).
    assert got["document"] == docs[role]
    assert got["document"]["role_name"] == role
    assert got["target_name"] == tc.ROLE_TARGET_NAMES[role]
    assert got["feed_url"] == base
    assert "sha256" in got["target_info"]["hashes"]
    assert "TUF chain" in got["authenticated_by"]


@pytest.mark.parametrize("role", sorted(_FETCHERS))
def test_R2_tampered_role_bytes_on_the_cdn_are_refused(
    served_role_repo, tmp_path, monkeypatch, role
):
    """Attacker controls the target CDN but not the metadata feed: the served
    role bytes change, the signed hash does not, the download must fail."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base, docs = served_role_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    evil = dict(docs[role])
    evil["role_name"] = role  # same role, different content
    evil["_attacker"] = "owns the cdn"
    repo.extra_target_disk_paths[tc.ROLE_TARGET_NAMES[role]].write_bytes(
        json.dumps(evil).encode("utf-8")
    )
    with pytest.raises(tc.TUFClientError):
        getattr(tc, _FETCHERS[role])(feed_url=base, trust_dir=tmp_path / "trust")


def test_R3_a_signed_role_document_with_a_placeholder_is_still_refused(
    tmp_path, monkeypatch
):
    """TUF authenticates the bytes; it does not make an unfilled ceremony value
    into trust material. The placeholder gate runs on the VERIFIED bytes."""
    from audit_bundle.extensions import c18_tuf_client as tc

    docs = role_docs()
    docs["sigstore-trust-root"]["signed"]["targets"]["rekor.pub"][
        "expected_sha256_at_v0_3_cut"
    ] = "sha256:TBD-AT-CEREMONY"
    sign_role_docs(docs)  # really signed, and STILL refused: the placeholder gate
    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, extra_targets=_role_targets(docs))
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFBootstrapPlaceholderPresent, match="TBD"):
            tc.fetch_sigstore_trust_root(feed_url=base, trust_dir=tmp_path / "trust")
    finally:
        httpd.shutdown()


def test_R4_role_target_with_the_wrong_payload_type_is_refused(tmp_path, monkeypatch):
    """Exactness, not membership: a role document served under ANOTHER role's
    (acceptable) payload type is refused."""
    from audit_bundle.extensions import c18_tuf_client as tc

    docs = signed_role_docs()
    swapped = dict(tc.ROLE_TARGET_PAYLOAD_TYPES)
    swapped["plugin-allowlist"] = tc.ROLE_TARGET_PAYLOAD_TYPES["revocation-root"]
    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(
        image_digest=GOOD_DIGEST,
        extra_targets=_role_targets(docs, payload_types=swapped),
    )
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFTargetUnknownPayloadType):
            tc.fetch_plugin_allowlist(feed_url=base, trust_dir=tmp_path / "trust")
        # The other two are untouched and still fetch.
        tc.fetch_revocation_root(feed_url=base, trust_dir=tmp_path / "trust")
    finally:
        httpd.shutdown()


def test_R5_role_target_absent_from_the_feed_is_refused(
    served_repo, tmp_path, monkeypatch
):
    """The plain served_repo carries only the release manifest: a role fetch
    must fail closed, never fall back to the bundled file."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base = served_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    for fetcher in _FETCHERS.values():
        with pytest.raises(tc.TUFConsistentSnapshotMissing):
            getattr(tc, fetcher)(feed_url=base, trust_dir=tmp_path / "trust")


def test_R6_strict_fetchers_take_no_local_path():
    """The bypass the audit proved: `fetch_plugin_allowlist(bundled_path=...)`
    returned whatever was at the path. Strict fetchers no longer accept one."""
    import inspect

    from audit_bundle.extensions import c18_tuf_client as tc

    for fetcher in _FETCHERS.values():
        params = inspect.signature(getattr(tc, fetcher)).parameters
        assert "bundled_path" not in params, fetcher
        assert set(params) >= {"feed_url", "trust_dir"}, fetcher


def test_R7_release_manifest_payload_type_is_exact(tmp_path, monkeypatch):
    """A release manifest declaring an SPDX payload type is not a release manifest."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, payload_type="application/vnd.spdx+json")
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFTargetUnknownPayloadType):
            tc.fetch_release_manifest(
                release_version="v0.3.0", feed_url=base, trust_dir=tmp_path / "trust"
            )
    finally:
        httpd.shutdown()


def test_R8_root_threshold_requires_distinct_keyids():
    from audit_bundle.extensions import c18_tuf_client as tc

    keys = {
        f"k{i}": {"keytype": "ed25519", "keyval": {"public": "aa" * 32}}
        for i in range(3)
    }
    good = {
        "signed": {
            "roles": {"root": {"threshold": 2, "keyids": ["k0", "k1", "k2"]}},
            "keys": keys,
        }
    }
    tc._assert_root_threshold(good)
    dup = {
        "signed": {
            "roles": {"root": {"threshold": 2, "keyids": ["k0", "k0", "k0"]}},
            "keys": keys,
        }
    }
    with pytest.raises(tc.TUFRootSignatureThresholdNotMet, match="distinct"):
        tc._assert_root_threshold(dup)


@pytest.mark.parametrize(
    "kwargs, exc",
    [
        ({"snap_expiry_days": 30}, "TUFSnapshotStale"),
        ({"ts_expiry_days": 3}, "TUFTimestampStale"),
    ],
)
def test_R9_declared_staleness_windows_are_enforced(tmp_path, monkeypatch, kwargs, exc):
    """MAX_SNAPSHOT_STALENESS_DAYS / MAX_TIMESTAMP_STALENESS_HOURS were constants
    read by nothing (a checkpoint marked the row PASS by citing the constant).
    python-tuf enforces whatever expiry the publisher signed; the client caps it."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, **kwargs)
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(getattr(tc, exc)):
            tc.fetch_release_manifest(
                release_version="v0.3.0", feed_url=base, trust_dir=tmp_path / "trust"
            )
    finally:
        httpd.shutdown()


def test_R10_an_expired_revocation_root_does_not_ride_the_chain(tmp_path, monkeypatch):
    """Red-team finding (2026-09-02): a revocation root with expires=2019-01-01 was
    returned by fetch_revocation_root through a valid chain — the expiry was parsed
    for shape only. The chain authenticates bytes; it does not make stale trust
    material current."""
    from audit_bundle.extensions import c18_tuf_client as tc

    docs = role_docs()
    docs["revocation-root"]["signed"]["expires"] = "2019-01-01T00:00:00Z"
    sign_role_docs(docs)  # signed over the stale expiry: the expiry is graded first
    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, extra_targets=_role_targets(docs))
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFRootExpired):
            tc.fetch_revocation_root(feed_url=base, trust_dir=tmp_path / "trust")
    finally:
        httpd.shutdown()


def test_R11_a_sigstore_trust_root_whose_own_2of3_does_not_verify_is_refused(
    tmp_path, monkeypatch
):
    """Process-lens finding (2026-09-02): the sigstore-trust-root document was
    flat, unsigned JSON, so the Rekor log key's pin rested on the release TARGETS
    key alone (threshold 1) while the prose said 2-of-3. The document now carries
    its own quorum, and the strict fetcher verifies it AFTER the chain: a served
    document with placeholder-shaped signatures (`_filled`'s `cd..`) is refused
    as under-signed, the same refusal the revocation root gets."""
    from audit_bundle.extensions import c18_tuf_client as tc

    docs = role_docs()  # filled, NOT signed with real keys
    repo = ToyTUFRepo(tmp_path / "repo")
    repo.build(image_digest=GOOD_DIGEST, extra_targets=_role_targets(docs))
    root_path = repo.write_bundled_root(tmp_path / "bundled_root.json")
    httpd, base = serve(tmp_path / "repo")
    try:
        monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
        with pytest.raises(tc.TUFRevocationRootSignatureInvalid):
            tc.fetch_sigstore_trust_root(feed_url=base, trust_dir=tmp_path / "trust")
        with pytest.raises(tc.TUFRevocationRootSignatureInvalid):
            tc.fetch_revocation_root(feed_url=base, trust_dir=tmp_path / "trust2")
    finally:
        httpd.shutdown()


def test_R12_a_signed_role_fetch_names_its_signers_on_the_envelope(
    served_role_repo, tmp_path, monkeypatch
):
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base, docs = served_role_repo
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    got = tc.fetch_sigstore_trust_root(feed_url=base, trust_dir=tmp_path / "trust")
    signers = got["role_signed_by"]
    assert len(signers) == 2
    assert set(signers) <= set(docs["sigstore-trust-root"]["signed"]["keys"])
    unsigned = tc.fetch_plugin_allowlist(feed_url=base, trust_dir=tmp_path / "trust")
    assert unsigned["role_signed_by"] == ()
    assert "NONE" in unsigned["signatures"]


def test_R13_a_served_root_rotation_past_the_90d_cap_is_refused(
    served_repo, tmp_path, monkeypatch
):
    """Claims lens (2026-09-02): the runbook said `_enforce_metadata_windows` caps
    root at 90 days; only the BUNDLED root was capped (`load_bundled_root`), so a
    served rotation to a long-lived root rode the chain. The fetched root.json is
    now held to MAX_ROOT_EXPIRY_DAYS too."""
    from audit_bundle.extensions import c18_tuf_client as tc

    repo, root_path, base = served_repo
    repo.rebuild_root(new_version=2, root_expiry_days=120)
    monkeypatch.setattr(tc, "_EMBEDDED_ROOT_PATH", root_path)
    with pytest.raises(tc.TUFRootExpired, match="fetched root.json"):
        tc.fetch_release_manifest(
            release_version="v0.3.0", feed_url=base, trust_dir=tmp_path / "trust"
        )
