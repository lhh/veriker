"""The open-drop CLI runs the DSSE sealing lane from auditor-held material.

Until 2026-09-02 `veriker/cli/verify.py` printed `DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO` on
every sealed bundle and told the reader to write the wiring themselves: the core's
`DsseVerifyContext` was a Protocol with no constructor in the open drop, and the
revocation resolver every caller passed was a test lambda. `--dsse-allowlist`,
`--dsse-revocation-list` and `--dsse-revocation-root` (or `-tuf`) now build the
context (`audit_bundle.dsse.context`) and hand the lane to `BundleVerifier.verify`.

What this battery pins, all through the shipped CLI in a subprocess:
  * sealed bundle + good material -> exit 0; the face names where the allowlist,
    the root (signers, pinned list signer, expiry) and the list came from;
  * the revocation ROOT is a real 2-of-3 role document: one valid signature of
    threshold two is refused; an expired root is refused; a list signed by a root
    keyid that is NOT the pinned list signer is refused (deny-by-default);
  * trust material inside the bundle under verdict is refused (row 14/15);
  * an unusable context is exit 2 (operator), a failing gate is exit 1 (bundle);
  * no --dsse-* flags: the sealed bundle still fails closed as before.

Stage 5 (fresh pass on the wiring commits, 2026-09-02), D13-D18:
  * one private key listed under two keyids does not reach threshold 2, and a
    role keyid that is not the sha256 of its own key is refused (a keyid is a
    hash, never a label);
  * `--dsse-now` may not sit more than 300 s behind the wall clock: a backdated
    clock un-revoked a key and un-staled an expired list; the root's expiry is
    graded against the SAME clock as the list.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.dsse.pae import kid_from_raw32
from tests.fixtures.dsse_trust_material import (
    NOW,
    RevocationRootKeys,
    _keyid,
    _raw,
    revocation_root_document,
    sealed_bundle,
    signed_revocation_list,
    write_material,
)

_PKG_ROOT = Path(__file__).resolve().parents[1]
_CLI = _PKG_ROOT / "veriker" / "cli" / "verify.py"


def _run(bundle_dir: Path, *args: str) -> tuple[int, dict, str, str]:
    face_path = bundle_dir.parent / "face.json"
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [
            sys.executable,
            str(_CLI),
            "--bundle-dir",
            str(bundle_dir),
            "--verdict-out",
            str(face_path),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
        env=env,
        timeout=120,
        check=False,
    )
    face = json.loads(face_path.read_text()) if face_path.exists() else {}
    return proc.returncode, face, proc.stdout, proc.stderr


def _lane(paths: dict[str, Path]) -> list[str]:
    return [
        "--dsse-allowlist",
        str(paths["allowlist"]),
        "--dsse-revocation-list",
        str(paths["list"]),
        "--dsse-revocation-root",
        str(paths["root"]),
        "--dsse-now",
        str(NOW),
    ]


@pytest.fixture()
def material(tmp_path):
    keys = RevocationRootKeys.generate()
    signer = Ed25519PrivateKey.generate()
    bundle = tmp_path / "bundle"
    sealed_bundle(bundle, signer)
    paths = write_material(tmp_path / "trust", keys, signer)
    return keys, signer, bundle, paths


def test_D1_sealed_bundle_with_auditor_material_reaches_exit_0(material) -> None:
    keys, signer, bundle, paths = material
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 0, (out, err)
    gates = {g["gate"]: g for g in face["cli_gates"]}
    assert gates["dsse_sidecar_guard"]["status"] == "DELEGATED"
    assert gates["dsse_context"]["status"] == "HELD"
    prov = "\n".join(gates["dsse_context"]["provenance"])
    assert "pinned_list_signer=" + keys.pinned_keyid in prov
    assert "threshold=2" in prov
    assert f"verifier_now: {NOW}" in prov
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" not in face["reason_codes"]
    assert "Ed25519 gate delegated to verify()" in out


def test_D2_revoked_signing_key_is_a_bundle_reject(tmp_path, material) -> None:
    keys, signer, bundle, paths = material
    kid = kid_from_raw32(signer.public_key().public_bytes_raw())
    paths["list"].write_bytes(
        signed_revocation_list(
            keys.list_signer, revocations=[{"kid": kid, "not_after": NOW - 1}]
        )
    )
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 1, (out, err)
    assert "DSSE_KEY_REVOKED" in json.dumps(face)


def test_D3_post_cutover_bundle_without_a_seal_is_refused(tmp_path, material) -> None:
    keys, signer, bundle, paths = material
    (bundle / "bundle.dsse.json").unlink()
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 1, (out, err)
    assert "DSSE_ENVELOPE_ABSENT" in json.dumps(face)


def test_D4_pre_cutover_bundle_is_refused_under_the_strict_lane(
    tmp_path, material
) -> None:
    """Supplying trust material asks for a sealed bundle; an unsealed pre-cutover
    bundle does not satisfy the lane (require_dsse=True, allow_legacy=False)."""
    keys, signer, bundle, paths = material
    legacy = tmp_path / "legacy"
    sealed_bundle(legacy, signer, schema_version="vcp-v1.1", seal=False)
    rc, face, out, err = _run(legacy, *_lane(paths))
    assert rc == 1, (out, err)
    assert "SCHEMA_PRE_CUTOVER_REFUSED" in json.dumps(face)


def test_D5_allowlist_inside_the_bundle_is_refused(material) -> None:
    keys, signer, bundle, paths = material
    inside = bundle / "allowlist.json"
    inside.write_bytes(paths["allowlist"].read_bytes())
    rc, face, out, err = _run(bundle, *_lane({**paths, "allowlist": inside}))
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "inside the bundle" in err


def test_D6_root_with_one_of_two_signatures_is_refused(material) -> None:
    keys, signer, bundle, paths = material
    paths["root"].write_text(json.dumps(revocation_root_document(keys, sign_with=(0,))))
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "TUFRevocationRootSignatureInvalid" in err


def test_D6b_same_key_signing_twice_does_not_reach_threshold(material) -> None:
    keys, signer, bundle, paths = material
    doc = revocation_root_document(keys, sign_with=(0, 0))
    paths["root"].write_text(json.dumps(doc))
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "TUFRevocationRootSignatureInvalid" in err


def test_D7_expired_root_is_refused(material) -> None:
    keys, signer, bundle, paths = material
    paths["root"].write_text(
        json.dumps(revocation_root_document(keys, expires_in_days=-1))
    )
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "TUFRootExpired" in err


def test_D8_list_signed_by_a_root_key_that_is_not_the_pinned_signer_is_refused(
    material,
) -> None:
    """The three root keyids sign the ROLE; only the pinned signer signs LISTS."""
    keys, signer, bundle, paths = material
    paths["list"].write_bytes(signed_revocation_list(keys.root[1]))
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "not the pinned" in err


def test_D9_pinned_signer_absent_from_keys_is_refused(material) -> None:
    keys, signer, bundle, paths = material
    paths["root"].write_text(
        json.dumps(revocation_root_document(keys, list_pinned_signer_under_keys=False))
    )
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "TUFRevocationRootSignerUnpinned" in err


def test_D10_wrong_allowlist_key_is_a_bundle_reject(tmp_path, material) -> None:
    keys, signer, bundle, paths = material
    other = Ed25519PrivateKey.generate()
    from tests.fixtures.dsse_trust_material import allowlist_json

    paths["allowlist"].write_bytes(allowlist_json(other))
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 1, (out, err)
    assert "DSSE_UNKNOWN_KID" in json.dumps(face)


def test_D11_no_flags_keeps_the_stdlib_fail_closed(material) -> None:
    keys, signer, bundle, paths = material
    rc, face, out, err = _run(bundle)
    assert rc == 1
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" in face["reason_codes"]
    gates = {g["gate"]: g["status"] for g in face["cli_gates"]}
    assert gates["dsse_sidecar_guard"] == "FAIL"
    assert "dsse_context" not in gates


def test_D12_partial_flags_are_an_operator_error(material) -> None:
    keys, signer, bundle, paths = material
    rc, face, out, err = _run(bundle, "--dsse-allowlist", str(paths["allowlist"]))
    assert rc == 2
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "missing" in err


# ---------------------------------------------------------------------------
# Stage 5 closures (fresh pass on the wiring commits, 2026-09-02)
# ---------------------------------------------------------------------------


def _keyentry(sk):
    return {"keyid_hash_algorithms": ["sha256", "sha512"], "keytype": "ed25519",
            "keyval": {"public": _raw(sk).hex()}, "scheme": "ed25519"}


def _doc(keyids, keys_map, signers, pinned):
    base = revocation_root_document(RevocationRootKeys.generate())
    signed = dict(base["signed"])
    signed["keys"] = keys_map
    signed["roles"] = {"revocation-root": {"keyids": keyids, "threshold": 2}}
    signed["pinned_revocation_list_signer_fingerprint"] = pinned
    msg = rfc8785.dumps(signed)
    out = dict(base)
    out["signed"] = signed
    out["signatures"] = [{"keyid": kid, "sig": sk.sign(msg).hex()} for kid, sk in signers]
    return out


def test_D13_one_key_under_two_keyids_does_not_reach_threshold(material) -> None:
    keys, signer, bundle, paths = material
    k_one, k_other = keys.root[0], keys.root[2]
    a, b, c = "approver-alice", "approver-bob", _keyid(k_other)
    keys_map = {a: _keyentry(k_one), b: _keyentry(k_one), c: _keyentry(k_other),
                keys.pinned_keyid: _keyentry(keys.list_signer)}
    paths["root"].write_text(json.dumps(_doc([a, b, c], keys_map, [(a, k_one), (b, k_one)], keys.pinned_keyid)))
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]


def test_D14_role_keyid_that_is_not_the_hash_of_its_key_is_refused(material) -> None:
    keys, signer, bundle, paths = material
    k0, k1, k2 = keys.root
    a = "approver-alice"  # a free label for a real, distinct key
    keys_map = {a: _keyentry(k0), _keyid(k1): _keyentry(k1), _keyid(k2): _keyentry(k2),
                keys.pinned_keyid: _keyentry(keys.list_signer)}
    doc = _doc([a, _keyid(k1), _keyid(k2)], keys_map, [(a, k0), (_keyid(k1), k1)], keys.pinned_keyid)
    paths["root"].write_text(json.dumps(doc))
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]


def test_D15_backdated_verifier_clock_is_an_operator_error(material) -> None:
    keys, signer, bundle, paths = material
    wall = int(time.time())
    lane = _lane(paths)[:-1] + [str(wall - 3600)]
    rc, face, out, err = _run(bundle, *lane)
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "backdat" in err.lower() or "backdat" in out.lower()


def test_D16_a_revoked_key_cannot_be_unrevoked_by_the_operator_clock(tmp_path, material) -> None:
    keys, signer, bundle, paths = material
    wall = int(time.time())
    rl = signed_revocation_list(keys.list_signer,
        revocations=[{"kid": kid_from_raw32(_raw(signer)), "not_after": wall - 1}],
        issued_at=wall - 10000, expires=wall + 10**6)
    paths = write_material(tmp_path / "trust2", keys, signer, revocation_list=rl)
    rc, face, out, err = _run(bundle, *(_lane(paths)[:-1] + [str(wall)]))
    assert rc == 1, (out, err)
    assert "DSSE_KEY_REVOKED" in json.dumps(face)
    rc2, face2, out2, err2 = _run(bundle, *(_lane(paths)[:-1] + [str(wall - 5000)]))
    assert rc2 != 0, (out2, err2)


def test_D17_a_wall_clock_stale_list_is_not_rescued_by_the_operator_clock(tmp_path, material) -> None:
    keys, signer, bundle, paths = material
    wall = int(time.time())
    # Expired 10 days ago; the backdated clock sits 20 days back. Chosen so the
    # root-window guard (root expiry <= 90 d ahead of the clock) stays quiet and
    # ONLY the backdate refusal stands between this list and exit 0.
    rl = signed_revocation_list(keys.list_signer, issued_at=wall - 100 * 86400, expires=wall - 10 * 86400)
    paths = write_material(tmp_path / "trust2", keys, signer, revocation_list=rl)
    rc, face, out, err = _run(bundle, *_lane(paths)[:-2])  # default (wall) clock
    assert rc == 1, (out, err)
    assert "DSSE_REVOCATION_LIST_STALE" in json.dumps(face)
    rc2, face2, out2, err2 = _run(bundle, *(_lane(paths)[:-1] + [str(wall - 20 * 86400)]))
    assert rc2 == 2, (out2, err2)
    assert "backdated" in err2 or "behind the wall clock" in err2


def test_D18_root_expiry_is_graded_against_the_same_clock_as_the_list(material) -> None:
    """A forward-dated verifier clock past the root's expiry refuses the root."""
    keys, signer, bundle, paths = material
    paths["root"].write_text(json.dumps(revocation_root_document(keys, expires_in_days=2)))
    wall = int(time.time())
    rc, face, out, err = _run(bundle, *(_lane(paths)[:-1] + [str(wall + 3 * 86400)]))
    assert rc == 2, (out, err)
    assert "TUFRootExpired" in err


def test_D13b_the_signature_counter_itself_counts_keys_not_labels(material) -> None:
    """Library-level control for the count guard, independent of the keyid rule
    (which refuses the same document earlier on the CLI path): one key under two
    labels, fed straight to the signature verifier, is ONE signer."""
    from audit_bundle.extensions import c18_tuf_client as tc

    keys, signer, bundle, paths = material
    k_one, k_other = keys.root[0], keys.root[2]
    a, b, c = "approver-alice", "approver-bob", _keyid(k_other)
    keys_map = {a: _keyentry(k_one), b: _keyentry(k_one), c: _keyentry(k_other)}
    doc = _doc([a, b, c], keys_map, [(a, k_one), (b, k_one)], keys.pinned_keyid)
    with pytest.raises(tc.TUFRevocationRootSignatureInvalid, match="distinct role KEYS"):
        tc.verify_revocation_root_signatures(doc)
    # And the honest shape: two DIFFERENT keys under their own labels verify.
    good = _doc(
        [_keyid(k_one), _keyid(keys.root[1]), c],
        {_keyid(k_one): _keyentry(k_one), _keyid(keys.root[1]): _keyentry(keys.root[1]), c: _keyentry(k_other)},
        [(_keyid(k_one), k_one), (_keyid(keys.root[1]), keys.root[1])],
        keys.pinned_keyid,
    )
    assert len(tc.verify_revocation_root_signatures(good)) == 2


def test_D19_tuf_trust_dir_inside_the_bundle_is_refused_before_any_fetch(material) -> None:
    """Claims lens (2026-09-02): "every path is refused inside the bundle under
    verdict" was false for `--dsse-revocation-root-tuf`: the trust DIRECTORY was
    never containment-checked, and the TUF client WRITES fetched metadata under it.
    Now it is refused before any network or file access — no feed is needed here."""
    keys, signer, bundle, paths = material
    lane = _lane(paths)
    i = lane.index("--dsse-revocation-root")
    lane[i] = "--dsse-revocation-root-tuf"
    lane[i + 1] = str(bundle / "trust")
    rc, face, out, err = _run(bundle, *lane, "--dsse-tuf-feed-url", "http://127.0.0.1:9/never")
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "inside the bundle under verdict" in err
    assert not (bundle / "trust").exists()


def test_D20_a_depth_bombed_revocation_list_is_a_typed_refusal(material) -> None:
    """Process lens (2026-09-02): with the allowlist and root reads bounded, the
    revocation LIST still went through a raw `json.loads` — a 300k-deep file was
    a RecursionError (exit 2 VERIFIER_INTERNAL_ERROR, untyped). Now the list is
    admitted through the same bounded loader first."""
    keys, signer, bundle, paths = material
    paths["list"].write_text("[" * 300_000 + "]" * 300_000)
    rc, face, out, err = _run(bundle, *_lane(paths))
    assert rc == 2, (out, err)
    assert "DSSE_CONTEXT_ARG_INVALID" in face["reason_codes"]
    assert "VERIFIER_INTERNAL_ERROR" not in json.dumps(face)
    assert "RecursionError" not in err
