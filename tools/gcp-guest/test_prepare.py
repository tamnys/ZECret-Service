"""Synthetic input/packaging tests; no image build or hardware evidence."""
import copy
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("prepare", Path(__file__).with_name("prepare.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
audit_spec = importlib.util.spec_from_file_location("audit_rootfs", Path(__file__).with_name("audit-rootfs.py"))
audit_rootfs = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit_rootfs)

class CandidateTests(unittest.TestCase):
    def setUp(self):
        cache = prepare.ROOT / ".codex-tmp"
        cache.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gcp-guest-synthetic-", dir=cache)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        artifacts = {}
        for role in prepare.ROLES:
            if role in prepare.BINARIES:
                data = bytearray(b"SYNTHETIC_NOT_EXECUTABLE".ljust(64, b"_"))
                data[:6] = b"\x7fELF\x02\x01"
                data[18:20] = b"\x3e\x00"
            elif role == "package_manifest":
                self.synthetic_deb = b"!<arch>\nSYNTHETIC_NOT_A_DEB"
                self.synthetic_deb_sha = hashlib.sha256(self.synthetic_deb).hexdigest()
                (self.inputs / "debs").mkdir()
                (self.inputs / "debs" / (self.synthetic_deb_sha + ".deb")).write_bytes(self.synthetic_deb)
                data = json.dumps([{"name": name, "version": "1.0~synthetic", "architecture": "amd64", "filename": f"pool/main/s/{name}/{name}_1.0~synthetic_amd64.deb", "size": len(self.synthetic_deb), "sha256": self.synthetic_deb_sha, "path": f"debs/{self.synthetic_deb_sha}.deb"} for name in ("systemd", "systemd-boot-efi", "systemd-cryptsetup")]).encode()
            else:
                data = b"SYNTHETIC_NOT_A_SIGNED_ARTIFACT"
            (self.inputs / role).write_bytes(data)
            artifacts[role] = {"path": role, "sha256": hashlib.sha256(data).hexdigest()}
        # Values exercise branches only and are never production defaults.
        self.lock = {"schema_version": 2, "mkosi_source_commit": prepare.SOURCE_COMMIT, "source_date_epoch": 1, "kernel_version": "synthetic", "snapshot": "https://snapshot.debian.org/archive/debian/20200101T000000Z/", "artifacts": artifacts, "runtime": {"listen_port": 8443, "max_connections": 2, "max_quotes": 1, "quote_spacing_ms": 1, "node_startup_timeout_secs": 1, "node_poll_interval_ms": 1}}

    def tearDown(self):
        self.temporary.cleanup()

    def test_missing_identity_changed_artifact_and_escape_fail(self):
        for change in (lambda lock: lock.pop("snapshot"), lambda lock: lock["artifacts"].pop("kernel"), lambda lock: lock["artifacts"]["wrapper"].update(sha256="00" * 32), lambda lock: lock["artifacts"]["kernel"].update(path="../kernel"), lambda lock: lock["runtime"].update(max_quotes=0), lambda lock: lock.update(snapshot="https://deb.debian.org/debian")):
            lock = copy.deepcopy(self.lock)
            change(lock)
            with self.assertRaises(ValueError):
                prepare.validate_lock(lock, self.inputs)

    def test_staging_is_explicitly_unbuilt_and_masks_administration(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        output = self.root / "candidate"
        package_manifest = json.loads((self.inputs / "package_manifest").read_text())
        archives = {(item["name"], item["version"], item["architecture"]): self.inputs / item["path"] for item in package_manifest}
        # Staging layout is synthetic. This mock cannot establish archive trust.
        with mock.patch.object(prepare.debian_snapshot, "verify_snapshot", return_value=({"synthetic": True}, archives)):
            report = prepare.stage(lock_path, self.inputs, output)
        self.assertFalse(report["image_built"])
        self.assertFalse(report["private_mode_approved"])
        self.assertIn("real TDX acceptance", report["remaining_gates"])
        units = output / "rootfs/usr/lib/systemd/system"
        wrapper = (units / "zrpc-wrapper.service").read_text()
        self.assertIn("--platform gcp-tdx", wrapper)
        self.assertIn("--check wrapper", wrapper)
        config = (output / "mkosi.conf").read_text()
        self.assertIn("PackageDirectories=packages", config)
        self.assertIn("Packages=systemd-boot-efi=1.0~synthetic,systemd-cryptsetup=1.0~synthetic,systemd=1.0~synthetic", config)
        self.assertEqual((output / "rootfs/etc/systemd/system/ssh.service").readlink(), Path("/dev/null"))
        with self.assertRaises(ValueError):
            prepare.stage(lock_path, self.inputs, output)

    def test_unverified_snapshot_cannot_stage(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        with self.assertRaises(ValueError):
            prepare.stage(lock_path, self.inputs, self.root / "candidate")
        self.assertFalse((self.root / "candidate").exists())

    def test_manifest_version_cannot_inject_mkosi_settings(self):
        path = self.inputs / "package_manifest"
        packages = json.loads(path.read_text())
        packages[0]["version"] = "1.0\nRepositoryKeyCheck=no"
        path.write_text(json.dumps(packages))
        self.lock["artifacts"]["package_manifest"]["sha256"] = prepare.digest(path)
        with self.assertRaisesRegex(ValueError, "invalid package identity"):
            prepare.validate_lock(self.lock, self.inputs)

    def test_signed_index_and_package_bytes_must_agree(self):
        manifest = json.loads((self.inputs / "package_manifest").read_text())
        paragraphs = []
        for package in manifest:
            paragraphs.append("\n".join((f"Package: {package['name']}", f"Version: {package['version']}", "Architecture: amd64", f"Filename: {package['filename']}", f"Size: {package['size']}", f"SHA256: {package['sha256']}")))
        index = self.inputs / "packages_index"
        index.write_bytes(lzma.compress(("\n\n".join(paragraphs) + "\n").encode()))
        self.lock["source_date_epoch"] = 1577836800
        release = self.inputs / "snapshot_inrelease"
        release.write_text("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nCodename: trixie\nArchitectures: amd64\nComponents: main\nDate: Wed, 01 Jan 2020 00:00:00 UTC\nSHA256:\n " + prepare.digest(index) + f" {index.stat().st_size} main/binary-amd64/Packages.xz\n-----BEGIN PGP SIGNATURE-----\nSYNTHETIC\n")
        paths = {"snapshot_inrelease": release, "packages_index": index}
        with mock.patch.object(prepare.debian_snapshot, "verify_signature"):
            snapshot, archives = prepare.debian_snapshot.verify_snapshot(self.lock, paths, self.inputs, manifest)
            self.assertEqual(snapshot["package_count"], 3)
            self.assertEqual(len(archives), 3)
            index.write_bytes(index.read_bytes() + b"TAMPER")
            with self.assertRaisesRegex(ValueError, "index differs"):
                prepare.debian_snapshot.verify_snapshot(self.lock, paths, self.inputs, manifest)

    def test_reviewed_debian_keyring_hash(self):
        self.assertEqual(prepare.debian_snapshot.sha256(prepare.debian_snapshot.KEYRING), prepare.debian_snapshot.KEYRING_SHA256)

    def test_unpinned_gpgv_executable_is_rejected(self):
        with mock.patch.object(prepare.debian_snapshot.shutil, "which", return_value="/bin/true"):
            with self.assertRaisesRegex(ValueError, "gpgv executable differs"):
                prepare.debian_snapshot.verify_signature(self.inputs / "snapshot_inrelease")

    def test_known_admin_package_is_rejected(self):
        path = self.inputs / "package_manifest"
        packages = json.loads(path.read_text())
        packages.append({"name": "openssh-server", "version": "1.0~synthetic", "architecture": "amd64", "filename": "pool/main/o/openssh/openssh-server_1.0~synthetic_amd64.deb", "size": 1, "sha256": "aa" * 32, "path": "debs/" + "aa" * 32 + ".deb"})
        path.write_text(json.dumps(packages))
        self.lock["artifacts"]["package_manifest"]["sha256"] = prepare.digest(path)
        with self.assertRaises(ValueError):
            prepare.validate_lock(self.lock, self.inputs)

    def test_duplicate_fields_cannot_override_a_digest(self):
        path = self.root / "duplicate.json"
        path.write_text('{"sha256":"first","sha256":"second"}')
        with self.assertRaises(ValueError):
            prepare.read_json(path)

    def test_rootfs_audit_rejects_admin_and_boot_companions(self):
        root = self.root / "synthetic-root"
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "usr/lib/zrpc").mkdir(parents=True)
        for unit in audit_rootfs.MASKED_UNITS:
            (root / "etc/systemd/system" / unit).symlink_to("/dev/null")
        (root / "etc/passwd").write_text("root:x:0:0::/:/usr/sbin/nologin\nzrpc-node:x:101:101::/:/usr/sbin/nologin\nzrpc-wrapper:x:102:102::/:/usr/sbin/nologin\n")
        (root / "etc/shadow").write_text("root:!:0:0:0:0:0:0:\nzrpc-node:!:0:0:0:0:0:0:\nzrpc-wrapper:!:0:0:0:0:0:0:\n")
        for name in prepare.BINARIES.values():
            (root / "usr/lib/zrpc" / name).write_text("SYNTHETIC")
            (root / "usr/lib/zrpc" / name).chmod(0o555)
        audit_rootfs.audit(root)
        (root / "boot").mkdir()
        companion = root / "boot/unapproved.addon.efi"
        companion.write_bytes(b"SYNTHETIC")
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        companion.unlink()
        (root / "etc/systemd/system/ssh.service").unlink()
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)

if __name__ == "__main__":
    unittest.main()
