"""Toy TUF repository builder + local HTTP server for streamE protocol attacks.

Builds a minimal but SPEC-COMPLIANT TUF repo (root / timestamp / snapshot /
targets) using python-tuf's own metadata API + securesystemslib signers, so the
attacks exercise the REAL `ngclient.Updater` state machine — not a mock.

Design notes:
  - Root role: 3 ed25519 keys, threshold 2 (mirrors C18 MIN_ROOT_THRESHOLD=2,
    MIN_ROOT_KEY_COUNT=3 so load_bundled_root's pre-checks pass).
  - timestamp / snapshot / targets: one online key each.
  - consistent_snapshot configurable. When True, metadata is written as
    `{version}.root.json`, `{version}.snapshot.json`, `{version}.targets.json`
    and targets as `{sha256}.{path}` — exactly what ngclient expects.
  - The release target is `vkernel-release/v0.3.0/MANIFEST.txt` containing an
    `image_digest=sha256:...` line, matching what host_digest_verify.py parses.

This module is import-only infrastructure; the attack scripts drive it.
Run paths are repo-relative (no absolute writes outside the repo) per the
worktree-isolation gotcha.
"""

from __future__ import annotations

import http.server
import json
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

RELEASE_TARGET = "vkernel-release/v0.3.0/MANIFEST.txt"
# Mirrors c18_tuf_client.RELEASE_MANIFEST_PAYLOAD_TYPE (kept literal here so
# the toy repo models an INDEPENDENT feed; the protocol test asserts the two
# agree end-to-end through the shipped fetch path).
RELEASE_MANIFEST_PAYLOAD_TYPE = "application/vnd.nexi.vkernel.release-manifest"
GOOD_IMAGE_DIGEST = "sha256:" + "ab" * 32
EVIL_IMAGE_DIGEST = (
    "sha256:" + "ev".replace("e", "e").replace("v", "f") * 32
)  # all-f-ish


def _expiry(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


class ToyTUFRepo:
    """An in-memory-built, on-disk-served toy TUF repo.

    Keys are stable across rebuilds within one instance so we can model
    root rotation (root N -> N+1) using the SAME key objects.
    """

    def __init__(self, repo_dir: Path, *, consistent_snapshot: bool = True):
        self.repo_dir = repo_dir
        self.md_dir = repo_dir / "metadata"
        self.tg_dir = repo_dir / "targets"
        self.md_dir.mkdir(parents=True, exist_ok=True)
        self.tg_dir.mkdir(parents=True, exist_ok=True)
        self.consistent_snapshot = consistent_snapshot

        # Stable key material.
        self.root_signers = [CryptoSigner.generate_ed25519() for _ in range(3)]
        self.extra_root_signer = CryptoSigner.generate_ed25519()  # for rotation tests
        self.ts_signer = CryptoSigner.generate_ed25519()
        self.snap_signer = CryptoSigner.generate_ed25519()
        self.tg_signer = CryptoSigner.generate_ed25519()

        self.md: dict[str, Metadata] = {}

    # ---- target content -----------------------------------------------------

    def _manifest_bytes(self, image_digest: str) -> bytes:
        return (f"release_version=v0.3.0\nimage_digest={image_digest}\n").encode(
            "utf-8"
        )

    def _write_target(self, data: bytes, target: TargetFile, path: str) -> None:
        if self.consistent_snapshot:
            digest = target.hashes["sha256"]
            name = f"{digest}.{Path(path).name}"
            out = self.tg_dir / Path(path).parent / name
        else:
            out = self.tg_dir / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        self.last_target_disk_path = out

    # ---- mix-and-match tamper helpers ---------------------------------------

    def tamper_target_payload(self, new_bytes: bytes) -> None:
        """Overwrite the SERVED target file bytes WITHOUT updating any metadata.

        Models an attacker who controls the target CDN (target_base_url) but
        not the metadata feed: snapshot/targets still pin the original sha256.
        """
        self.last_target_disk_path.write_bytes(new_bytes)

    def forge_targets_keep_snapshot(
        self, evil_digest: str, *, use_legit_key: bool = False
    ) -> None:
        """Serve a forged targets.json (evil content) at the SAME version, with
        snapshot.json left untouched (version-pinning the same version).

        use_legit_key=False (default): sign with a FRESH attacker key the repo
        never authorized — models a keyless attacker doing metadata mix-and-match.
        The targets-role signature check must reject it.

        use_legit_key=True: sign with the real targets key — models targets-KEY
        COMPROMISE. Shows snapshot version-pins but does NOT hash-pin targets,
        so same-version content swaps ride on the targets signature alone
        (standard TUF property, relevant only under key compromise).
        """
        tv = self.md["targets"].signed.version
        data = self._manifest_bytes(evil_digest)
        tf = TargetFile.from_data(RELEASE_TARGET, data, ["sha256"])
        tf.unrecognized_fields["custom"] = {
            "payload_type": RELEASE_MANIFEST_PAYLOAD_TYPE
        }
        targets = Targets(version=tv, expires=_expiry(7))
        targets.targets[RELEASE_TARGET] = tf
        md = Metadata(targets)
        signer = self.tg_signer if use_legit_key else CryptoSigner.generate_ed25519()
        md.sign(signer)
        # Overwrite the SERVED targets metadata only; snapshot untouched.
        if self.consistent_snapshot:
            (self.md_dir / f"{tv}.targets.json").write_bytes(self._serialize(md))
        else:
            (self.md_dir / "targets.json").write_bytes(self._serialize(md))
        self._write_target(data, tf, RELEASE_TARGET)

    # ---- build root v1 ------------------------------------------------------

    def build(
        self,
        *,
        root_version: int = 1,
        root_threshold: int = 2,
        root_signer_indices: tuple[int, ...] = (0, 1),
        root_key_indices: tuple[int, ...] = (0, 1, 2),
        targets_version: int = 1,
        snapshot_version: int = 1,
        timestamp_version: int = 1,
        image_digest: str = GOOD_IMAGE_DIGEST,
        target_name: str = RELEASE_TARGET,
        ts_expiry_days: int = 1,
        snap_expiry_days: int = 7,
        root_expiry_days: int = 80,
        sign_root_with: tuple[int, ...] | None = None,
        payload_type: str | None = RELEASE_MANIFEST_PAYLOAD_TYPE,
        extra_targets: dict[str, tuple[bytes, str | None]] | None = None,
    ) -> None:
        """Build the four roles and write them to disk.

        root_key_indices  -> which of self.root_signers are LISTED in root role
        root_signer_indices -> which keys actually SIGN (for threshold tests)
        sign_root_with     -> override the signing set (defaults to root_signer_indices)
        payload_type       -> signed custom.payload_type on the release target;
                              pass None to model a feed that omits it (the
                              client must fail closed)
        """
        # ---- targets ----
        data = self._manifest_bytes(image_digest)
        tf = TargetFile.from_data(target_name, data, ["sha256"])
        if payload_type is not None:
            # TUF-spec `custom` rides the signed targets metadata; python-tuf
            # carries it via unrecognized_fields.
            tf.unrecognized_fields["custom"] = {"payload_type": payload_type}
        targets = Targets(version=targets_version, expires=_expiry(snap_expiry_days))
        targets.targets[target_name] = tf
        # Additional signed targets (the C18 role documents ride the SAME
        # targets role: sigstore-trust-root / plugin-allowlist / revocation-root).
        # `extra_targets` maps target name -> (bytes, payload_type | None).
        extra_files: list[tuple[bytes, TargetFile, str]] = []
        for name, (blob, ptype) in (extra_targets or {}).items():
            xf = TargetFile.from_data(name, blob, ["sha256"])
            if ptype is not None:
                xf.unrecognized_fields["custom"] = {"payload_type": ptype}
            targets.targets[name] = xf
            extra_files.append((blob, xf, name))
        self.md["targets"] = Metadata(targets)
        self.md["targets"].sign(self.tg_signer)
        self._write_target(data, tf, target_name)
        self.extra_target_disk_paths: dict[str, Path] = {}
        for blob, xf, name in extra_files:
            self._write_target(blob, xf, name)
            self.extra_target_disk_paths[name] = self.last_target_disk_path

        # ---- snapshot ----
        snapshot = Snapshot(
            version=snapshot_version,
            expires=_expiry(snap_expiry_days),
            meta={"targets.json": MetaFile(version=targets_version)},
        )
        self.md["snapshot"] = Metadata(snapshot)
        self.md["snapshot"].sign(self.snap_signer)

        # ---- timestamp ----
        timestamp = Timestamp(
            version=timestamp_version,
            expires=_expiry(ts_expiry_days),
            snapshot_meta=MetaFile(version=snapshot_version),
        )
        self.md["timestamp"] = Metadata(timestamp)
        self.md["timestamp"].sign(self.ts_signer)

        # ---- root ----
        root = Root(
            version=root_version,
            expires=_expiry(root_expiry_days),
            consistent_snapshot=self.consistent_snapshot,
        )
        for i in root_key_indices:
            root.add_key(self.root_signers[i].public_key, "root")
        root.add_key(self.ts_signer.public_key, "timestamp")
        root.add_key(self.snap_signer.public_key, "snapshot")
        root.add_key(self.tg_signer.public_key, "targets")
        root.roles["root"].threshold = root_threshold

        self.md["root"] = Metadata(root)
        signers = sign_root_with if sign_root_with is not None else root_signer_indices
        for i in signers:
            self.md["root"].sign(self.root_signers[i], append=True)

        self._write_all()

    def rebuild_root(
        self,
        *,
        new_version: int,
        new_threshold: int | None = None,
        listed_key_indices: tuple[int, ...] = (0, 1, 2),
        signed_by_indices: tuple[int, ...] = (0, 1),
        include_extra_key: bool = False,
        root_expiry_days: int = 80,
    ) -> None:
        """Produce a NEW root version (rotation). Reuses online keys.

        signed_by_indices indexes into self.root_signers for the OLD-key
        signatures; if include_extra_key, the extra_root_signer is added as a
        listed key and also signs (models attacker-introduced key).
        """
        root = Root(
            version=new_version,
            expires=_expiry(root_expiry_days),
            consistent_snapshot=self.consistent_snapshot,
        )
        for i in listed_key_indices:
            root.add_key(self.root_signers[i].public_key, "root")
        if include_extra_key:
            root.add_key(self.extra_root_signer.public_key, "root")
        root.add_key(self.ts_signer.public_key, "timestamp")
        root.add_key(self.snap_signer.public_key, "snapshot")
        root.add_key(self.tg_signer.public_key, "targets")
        if new_threshold is not None:
            root.roles["root"].threshold = new_threshold

        md = Metadata(root)
        for i in signed_by_indices:
            md.sign(self.root_signers[i], append=True)
        if include_extra_key:
            md.sign(self.extra_root_signer, append=True)
        self.md["root"] = md
        self._write_root(md)

    # ---- disk layout --------------------------------------------------------

    def _serialize(self, md: Metadata) -> bytes:
        return md.to_bytes(JSONSerializer())

    def _write_root(self, md: Metadata) -> None:
        v = md.signed.version
        (self.md_dir / f"{v}.root.json").write_bytes(self._serialize(md))
        # Non-consistent root.json mirror (ngclient bootstraps from versioned).
        (self.md_dir / "root.json").write_bytes(self._serialize(md))

    def _write_all(self) -> None:
        self._write_root(self.md["root"])
        if self.consistent_snapshot:
            sv = self.md["snapshot"].signed.version
            tv = self.md["targets"].signed.version
            (self.md_dir / f"{sv}.snapshot.json").write_bytes(
                self._serialize(self.md["snapshot"])
            )
            (self.md_dir / f"{tv}.targets.json").write_bytes(
                self._serialize(self.md["targets"])
            )
        else:
            (self.md_dir / "snapshot.json").write_bytes(
                self._serialize(self.md["snapshot"])
            )
            (self.md_dir / "targets.json").write_bytes(
                self._serialize(self.md["targets"])
            )
        # timestamp is never versioned
        (self.md_dir / "timestamp.json").write_bytes(
            self._serialize(self.md["timestamp"])
        )

    def bundled_root_json(self) -> dict[str, Any]:
        """The public root.json a client would embed (== root v as on disk)."""
        return json.loads((self.md_dir / "root.json").read_text(encoding="utf-8"))

    def write_bundled_root(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self._serialize(self.md["root"]))
        return path


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass


def serve(repo_dir: Path) -> tuple[http.server.HTTPServer, str]:
    """Start an HTTP server rooted at repo_dir. Returns (server, base_url)."""
    handler = lambda *a, **k: _QuietHandler(*a, directory=str(repo_dir), **k)  # noqa: E731
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, f"http://127.0.0.1:{port}"
