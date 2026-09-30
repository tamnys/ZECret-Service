"""Focused paid-overlay staging and fail-closed input tests."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock
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
        (self.base / "rootfs/etc/zrpc").mkdir(parents=True)
        (self.base / "rootfs/usr/lib/zrpc").mkdir(parents=True)
        auditor = self.base / "audit-rootfs.py"
        auditor.write_bytes((Path(__file__).with_name("audit-rootfs.py").read_bytes()
                             .replace(b"__STAGED_MOUNT_SHA256__", b"0" * 64)))
        auditor.chmod(0o555)
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
        self.native_bundle = self.root / "native-bundle"
        self.native_bundle.mkdir()
        self.native_revision = "a" * 40
        self.native_manifest = "b" * 64
        self.native_inspect = mock.patch.object(
            paid.export_rust_inputs, "inspect", return_value={
                "source_commit": self.native_revision,
                "reproduction_manifest_sha256": self.native_manifest,
                "payment_crypto_sha256": paid.sha256(helper),
            })
        self.inspection = self.native_inspect.start()
        self.addCleanup(self.native_inspect.stop)
        self.lock = self.root / "paid.lock.json"
        self.lock.write_text(json.dumps({
            "schema_version": 1,
            "base_stage_manifest_sha256": self.base_sha256,
            "native_source_commit": self.native_revision,
            "native_rust_manifest_sha256": self.native_manifest,
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
                          self.lock, self.inputs, self.native_bundle,
                          self.native_revision, self.output)

    def test_paid_overlay_is_pinned_and_never_enables_free_access(self):
        result = self.stage()
        self.assertEqual(result["status"], paid.STATUS)
        second = paid.stage(self.base, self.base_sha256, self.base_bytes,
                            self.lock, self.inputs, self.native_bundle,
                            self.native_revision, self.root / "second-overlay")
        self.assertEqual(result["manifest_sha256"], second["manifest_sha256"])
        self.inspection.assert_any_call(self.native_bundle, self.native_revision)
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

    def test_paid_stage_uses_selected_source_reader_in_builder(self):
        reader = mock.Mock()
        paid.stage(self.base, self.base_sha256, self.base_bytes,
                   self.lock, self.inputs, self.native_bundle,
                   self.native_revision, self.output, selected_output=reader)
        self.inspection.assert_called_once_with(
            self.native_bundle, self.native_revision, selected_output=reader)

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

    def test_rejects_helper_not_in_native_receipt(self):
        self.inspection.return_value["payment_crypto_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "verified native receipt"):
            self.stage()

    def test_rejects_output_nested_in_verified_free_stage(self):
        with self.assertRaises(ValueError):
            paid.stage(self.base, self.base_sha256, self.base_bytes,
                       self.lock, self.inputs, self.native_bundle,
                       self.native_revision, self.base / "paid-overlay")
        self.assertFalse((self.base / "paid-overlay").exists())

    def test_apply_creates_pinned_paid_stage_without_changing_free_stage(self):
        overlay = self.stage()
        applied = self.root / "paid-stage"
        result = paid.apply(self.base, self.base_sha256, self.base_bytes,
                            self.output, overlay["manifest_sha256"],
                            overlay["manifest_bytes"], applied)
        self.assertEqual(result["status"], "paid-stage-staged-unbuilt-unapproved")
        prepare.verify_stage(applied, result["manifest_sha256"], result["manifest_bytes"])
        self.assertEqual((applied / "rootfs/etc/zrpc/issuer.der").read_bytes(),
                         (self.inputs / "issuer.der").read_bytes())
        self.assertEqual((applied / "paid-overlay-manifest.json").read_bytes(),
                         (self.output / "candidate-manifest.json").read_bytes())
        auditor = (applied / "audit-rootfs.py").read_bytes()
        self.assertIn(b"PAID_PINNED_FILES = {'etc/fstab':", auditor)
        self.assertIn(paid.sha256((self.inputs / "issuer.der").read_bytes()).encode(), auditor)
        self.assertNotIn(prepare.PINNED_DISK_FILES["etc/fstab"].encode(), auditor)
        self.assertEqual((self.base / "rootfs/etc/fstab").read_bytes(),
                         (prepare.PROFILE / "rootfs/etc/fstab").read_bytes())
        key = applied / "rootfs/etc/zrpc/issuer.der"
        key.chmod(0o644)
        with key.open("ab") as stream:
            stream.write(b"changed")
        key.chmod(0o444)
        with self.assertRaises(ValueError):
            prepare.verify_stage(applied, result["manifest_sha256"], result["manifest_bytes"])

    def test_overlay_rejects_extra_file_even_when_manifest_is_rewritten(self):
        self.stage()
        extra = self.output / "rootfs/etc/zrpc/private.key"
        extra.write_bytes(b"must never be staged\n")
        root_fd = prepare.open_stage_directory(self.output)
        try:
            manifest = json.loads((self.output / "candidate-manifest.json").read_bytes())
            manifest["entries"] = prepare.staged_inventory(root_fd)
        finally:
            os.close(root_fd)
        encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (self.output / "candidate-manifest.json").write_bytes(encoded)
        with self.assertRaisesRegex(ValueError, "unreviewed path"):
            paid.verify(self.output, paid.sha256(encoded), len(encoded))


if __name__ == "__main__":
    unittest.main()
