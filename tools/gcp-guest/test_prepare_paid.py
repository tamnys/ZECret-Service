"""Focused paid-overlay staging and fail-closed input tests."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid

import prepare
import prepare_paid as paid


class PaidOverlayTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="zrpc-paid-overlay-", dir=prepare.ROOT)
        self.root = Path(self.scratch.name)
        self.base = self.root / "free-stage"
        self.base.mkdir()
        source = prepare.PROFILE / "rootfs"
        for relative in (
            "etc/fstab",
            "usr/lib/udev/rules.d/65-gce-disk-naming.rules",
            "usr/lib/tmpfiles.d/zrpc.conf",
            *(str(paid.UNIT_DIR / unit) for unit in paid.GUARDED_UNITS),
        ):
            target = self.base / "rootfs" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, target)
        wrapper = self.base / "rootfs" / paid.UNIT_DIR / "zrpc-wrapper.service"
        with wrapper.open("ab") as stream:
            stream.write(b"ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec wrapper "
                         b"--platform gcp-tdx --access free-demo\n")
        cookie = self.base / "rootfs" / paid.UNIT_DIR / "zrpc-cookie.service"
        with cookie.open("ab") as stream:
            stream.write(b"ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec cookie\n")
        lock_bytes = b"{}\n"
        (self.base / "inputs.lock.json").write_bytes(lock_bytes)
        lock_sha256 = paid.sha256(lock_bytes)
        seed = prepare.repart_seed(lock_bytes)
        descriptor = prepare.open_stage_directory(self.base)
        try:
            entries = prepare.staged_inventory(descriptor)
        finally:
            import os
            os.close(descriptor)
        manifest = {
            "schema_version": 1,
            "status": "staged-unbuilt-unapproved",
            "input_lock_sha256": lock_sha256,
            "repart_seed": str(seed),
            "repart_seed_derivation": {
                "algorithm": "UUIDv5",
                "namespace": str(uuid.NAMESPACE_URL),
                "name": prepare.REPART_SEED_NAME_PREFIX + lock_sha256,
            },
            "debian_snapshot": {},
            "entries": entries,
            "remaining_gates": [],
            "image_built": False,
            "private_mode_approved": False,
        }
        encoded = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        (self.base / "candidate-manifest.json").write_bytes(encoded)
        self.base_sha256 = paid.sha256(encoded)
        self.base_bytes = len(encoded)
        self.inputs = self.root / "public-inputs"
        self.inputs.mkdir()
        public = b"public DER fixture"
        helper = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00" + b"\x00" * 40
        (self.inputs / "issuer.der").write_bytes(public)
        binary = self.inputs / "zrpc-payment-crypto"
        binary.write_bytes(helper)
        binary.chmod(0o555)
        self.lock = self.root / "paid.lock.json"
        self.lock.write_text(json.dumps({
            "schema_version": 1,
            "base_stage_manifest_sha256": self.base_sha256,
            "issuer_name": "issuer.example",
            "artifacts": {
                role: {"path": filename, "sha256": hashlib.sha256((self.inputs / filename).read_bytes()).hexdigest(),
                       "size": (self.inputs / filename).stat().st_size}
                for role, filename in paid.FILES.items()
            },
        }))
        self.output = self.root / "paid-overlay"

    def tearDown(self):
        self.scratch.cleanup()

    def stage(self):
        return paid.stage(self.base, self.base_sha256, self.base_bytes,
                          self.lock, self.inputs, self.output)

    def test_paid_overlay_is_pinned_and_never_enables_free_access(self):
        result = self.stage()
        self.assertEqual(result["status"], paid.STATUS)
        second = paid.stage(self.base, self.base_sha256, self.base_bytes,
                            self.lock, self.inputs, self.root / "second-overlay")
        self.assertEqual(result["manifest_sha256"], second["manifest_sha256"])
        self.assertEqual(paid.verify(self.output, result["manifest_sha256"],
                                     result["manifest_bytes"])["status"],
                         "paid-overlay-matches-pinned-manifest")
        rootfs = self.output / "rootfs"
        fstab = (rootfs / "etc/fstab").read_text()
        self.assertIn("google-zrpc-spent-data /var/lib/zrpc-spent ext4 rw,nosuid,nodev,noexec,", fstab)
        self.assertNotIn("/var/lib/zrpc-spent ext4 rw,nosuid,nodev,noexec,x-systemd.makefs", fstab)
        rules = (rootfs / "usr/lib/udev/rules.d/65-gce-disk-naming.rules").read_text()
        self.assertIn("zrpc-gcp-disk-id --spent $devnode", rules)
        for unit, service in paid.GUARDED_UNITS.items():
            contents = (rootfs / paid.UNIT_DIR / unit).read_text()
            self.assertIn("--paid-mark-start " + service, contents)
            self.assertIn("--paid-exec " + service, contents)
            self.assertNotIn("--access free-demo", contents)
            if service == "wrapper":
                self.assertIn("--access ticket-required", contents)
                self.assertIn("ReadWritePaths=/var/lib/zrpc-spent", contents)
                self.assertIn("RequiresMountsFor=/var/lib/zrpc-spent", contents)
            else:
                self.assertIn("InaccessiblePaths=/var/lib/zrpc-spent ", contents)
        self.assertEqual((rootfs / "etc/zrpc/issuer.der").stat().st_mode & 0o777, 0o444)
        self.assertEqual((rootfs / "usr/lib/zrpc/zrpc-payment-crypto").stat().st_mode & 0o777, 0o555)
        manifest = json.loads((self.output / "candidate-manifest.json").read_bytes())
        paths = set(manifest["entries"])
        self.assertFalse(any("private" in path or "spent.db" in path
                             or "ticket" in path for path in paths))
        self.assertEqual(set(json.loads((self.output / "paid-inputs.lock.json").read_bytes())["artifacts"]),
                         {"issuer_public_der", "crypto_helper"})
        with (rootfs / "etc/fstab").open("ab") as stream:
            stream.write(b"# changed\n")
        with self.assertRaises(ValueError):
            paid.verify(self.output, result["manifest_sha256"], result["manifest_bytes"])

    def test_rejects_wrong_lock_and_changed_free_disk_rule(self):
        locked = json.loads(self.lock.read_text())
        locked["artifacts"]["crypto_helper"]["sha256"] = "0" * 64
        self.lock.write_text(json.dumps(locked))
        with self.assertRaises(ValueError):
            self.stage()
        locked["artifacts"]["crypto_helper"]["sha256"] = paid.sha256(
            (self.inputs / "zrpc-payment-crypto").read_bytes())
        self.lock.write_text(json.dumps(locked))
        source = self.base / "rootfs/usr/lib/udev/rules.d/65-gce-disk-naming.rules"
        with source.open("ab") as stream:
            stream.write(b"# changed\n")
        with self.assertRaises(ValueError):
            self.stage()

    def test_rejects_issuer_name_with_unit_argument_separator(self):
        locked = json.loads(self.lock.read_text())
        locked["issuer_name"] = "issuer.example --access free-demo"
        self.lock.write_text(json.dumps(locked))
        with self.assertRaises(ValueError):
            self.stage()

    def test_rejects_output_nested_in_verified_free_stage(self):
        with self.assertRaises(ValueError):
            paid.stage(self.base, self.base_sha256, self.base_bytes,
                       self.lock, self.inputs, self.base / "paid-overlay")
        self.assertFalse((self.base / "paid-overlay").exists())


if __name__ == "__main__":
    unittest.main()
