"""Synthetic input/packaging tests; no image build or hardware evidence."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
import uuid
from types import SimpleNamespace
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
            if role in prepare.BINARIES or role == prepare.EARLY_INIT_ROLE:
                data = bytearray(b"SYNTHETIC_NOT_EXECUTABLE".ljust(64, b"_"))
                data[:6] = b"\x7fELF\x02\x01"
                data[18:20] = b"\x3e\x00"
            elif role == "package_manifest":
                self.synthetic_deb = b"!<arch>\nSYNTHETIC_NOT_A_DEB"
                self.synthetic_deb_sha = hashlib.sha256(self.synthetic_deb).hexdigest()
                (self.inputs / "debs").mkdir()
                (self.inputs / "debs" / (self.synthetic_deb_sha + ".deb")).write_bytes(self.synthetic_deb)
                # The reviewed kernel identity has deliberately synthetic archive bytes.
                packages = []
                for name in ("systemd", "systemd-boot-efi", "systemd-cryptsetup", "systemd-resolved", "udev", "e2fsprogs", "dmsetup", "kmod", "mount", "libc6", "libjson-c5", "libssl3t64", prepare.KERNEL_PACKAGE):
                    version = prepare.KERNEL_PACKAGE_VERSION if name == prepare.KERNEL_PACKAGE else "1.0~synthetic"
                    packages.append({"name": name, "version": version, "architecture": "amd64", "filename": f"pool/main/s/{name}/{name}_{version}_amd64.deb", "size": len(self.synthetic_deb), "sha256": self.synthetic_deb_sha, "path": f"debs/{self.synthetic_deb_sha}.deb"})
                data = json.dumps(packages).encode()
            else:
                data = b"SYNTHETIC_NOT_A_SIGNED_ARTIFACT"
            (self.inputs / role).write_bytes(data)
            artifacts[role] = {"path": role, "sha256": hashlib.sha256(data).hexdigest()}
        # Values exercise branches only and are never production defaults.
        self.lock = {"schema_version": 6, "mkosi_source_commit": prepare.SOURCE_COMMIT, "source_date_epoch": 1, "kernel_version": prepare.KERNEL_VERSION, "snapshot": "https://snapshot.debian.org/archive/debian/20200101T000000Z/", "artifacts": artifacts, "runtime": {"listen_port": 8443, "max_connections": 2, "max_quotes": 1, "quote_spacing_ms": 1, "node_startup_timeout_secs": 1, "node_poll_interval_ms": 1}}
        # Keep the test-only manifest separate from mutable input bytes. This
        # exercises the same source-closure check without treating synthetic
        # packages as a production input.
        self.closure = self.root / "synthetic-package-closure.lock.json"
        self.closure.write_bytes((self.inputs / "package_manifest").read_bytes())
        self.closure_patch = mock.patch.object(prepare, "PACKAGE_CLOSURE_LOCK", self.closure)
        self.closure_patch.start()
        self.closure_hash_patch = mock.patch.object(prepare, "PACKAGE_CLOSURE_SHA256", prepare.digest(self.closure))
        self.closure_hash_patch.start()
        # These candidate fixtures are intentionally not signed Debian .debs.
        # The archive parser and signed membership are tested separately.
        self.disk_verify_patch = mock.patch.object(prepare, "verify_disk_tool_archives")
        self.disk_verify_patch.start()
        self.disk_stage_patch = mock.patch.object(prepare, "stage_disk_tool",
                                            side_effect=self.synthetic_disk_tool)
        self.disk_stage_patch.start()
        self.mount_identity_patch = mock.patch.object(
            prepare, "mount_package_identity",
            return_value=(len(b"SYNTHETIC"), hashlib.sha256(b"SYNTHETIC").hexdigest()),
        )
        self.mount_identity_patch.start()
        self.audit_mount_hash_patch = mock.patch.object(
            audit_rootfs, "EXPECTED_MOUNT_SHA256", hashlib.sha256(b"SYNTHETIC").hexdigest())
        self.audit_mount_hash_patch.start()
        self.audit_mount_owner_patch = mock.patch.object(
            audit_rootfs, "MOUNT_OWNER", (os.getuid(), os.getgid()))
        self.audit_mount_owner_patch.start()
        self.audit_disk_elf_patch = mock.patch.dict(
            audit_rootfs.SIGNED_DISK_ELFS,
            {name: (len(b"SYNTHETIC"), hashlib.sha256(b"SYNTHETIC").hexdigest(), mode)
             for name, (_, _, mode) in audit_rootfs.SIGNED_DISK_ELFS.items()},
            clear=True,
        )
        self.audit_disk_elf_patch.start()

    def synthetic_disk_tool(self, rootfs, artifacts):
        for relative, (_, _, mode) in audit_rootfs.SIGNED_DISK_ELFS.items():
            path = rootfs / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"SYNTHETIC")
            path.chmod(mode)

    def tearDown(self):
        self.audit_mount_owner_patch.stop()
        self.audit_mount_hash_patch.stop()
        self.mount_identity_patch.stop()
        self.audit_disk_elf_patch.stop()
        self.disk_stage_patch.stop()
        self.disk_verify_patch.stop()
        self.closure_hash_patch.stop()
        self.closure_patch.stop()
        self.temporary.cleanup()

    def stage_synthetic_candidate(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        output = self.root / "candidate"
        package_manifest = json.loads((self.inputs / "package_manifest").read_text())
        archives = {(item["name"], item["version"], item["architecture"]): self.inputs / item["path"] for item in package_manifest}
        # Only the snapshot service is mocked; these are deliberately not
        # authenticated Debian archives or executable guest binaries.
        with mock.patch.object(prepare.debian_snapshot, "verify_snapshot", return_value=({"synthetic": True}, archives)):
            report = prepare.stage(lock_path, self.inputs, output)
        return output, report

    def test_verify_stage_matches_only_pinned_source_inputs(self):
        output, report = self.stage_synthetic_candidate()
        zebra_config = tomllib.loads((output / "rootfs/etc/zrpc/zebra.toml").read_text())
        self.assertIs(zebra_config["network"]["cache_dir"], False)
        self.assertEqual(zebra_config["state"]["cache_dir"], "/var/lib/zebra")
        preset = output / "rootfs/etc/systemd/system-preset/00-zrpc.preset"
        self.assertEqual(
            [line for line in preset.read_text().splitlines() if line and not line.startswith("#")],
            ["disable e2scrub_reap.service", "disable e2scrub_all.timer",
             "disable remote-cryptsetup.target",
             "disable remote-fs.target", "disable remote-veritysetup.target"],
        )
        recorded_sha = report["manifest_sha256"]
        recorded_bytes = report["manifest_bytes"]
        manifest = output / "candidate-manifest.json"
        self.assertEqual(recorded_sha, prepare.digest(manifest))
        self.assertEqual(recorded_bytes, manifest.stat().st_size)
        self.assertNotIn("manifest_sha256", json.loads(manifest.read_text()))
        result = prepare.verify_stage(output, recorded_sha, recorded_bytes)
        self.assertEqual(result["status"], "staged-inputs-match-pinned-manifest")
        self.assertFalse(result["image_built"])
        self.assertFalse(result["private_mode_approved"])
        cli = subprocess.run(
            [sys.executable, str(Path(prepare.__file__)), "verify-stage", "--output", str(output),
             "--expected-manifest-sha256", recorded_sha, "--expected-manifest-bytes", str(recorded_bytes)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        self.assertEqual(json.loads(cli.stdout), result)
        with self.assertRaisesRegex(ValueError, "recorded regular file"):
            prepare.verify_stage(output, recorded_sha, recorded_bytes + 1)
        with self.assertRaisesRegex(ValueError, "recorded digest"):
            prepare.verify_stage(output, "0" * 64, recorded_bytes)

    def test_verify_stage_rejects_changed_added_and_missing_inputs(self):
        output, report = self.stage_synthetic_candidate()
        recorded_sha = report["manifest_sha256"]
        recorded_bytes = report["manifest_bytes"]

        def replace_mask(candidate):
            mask = candidate / "rootfs/etc/systemd/system/systemd-udev-load-credentials.service"
            mask.unlink()
            mask.symlink_to("/usr/lib/systemd/system/systemd-udev-load-credentials.service")

        def replace_generator_mask(candidate):
            mask = candidate / "rootfs/etc/systemd/system/systemd-network-generator.service"
            mask.unlink()
            mask.symlink_to("/usr/lib/systemd/system/systemd-network-generator.service")

        def add_hook(candidate):
            override = candidate / "mkosi.conf.d"
            override.mkdir()
            (override / "99-unreviewed.conf").write_text("[Validation]\nSecureBoot=no\n")

        def change_mode(candidate):
            (candidate / "mkosi.conf").chmod(0o755)

        def add_build_output(candidate, name):
            directory = candidate / name
            directory.mkdir(exist_ok=True)
            (directory / "poison").write_bytes(b"unreviewed build input")

        cases = [
            ("config", lambda candidate: (candidate / "mkosi.conf").write_text("SecureBoot=no\n")),
            ("build-source", lambda candidate: (candidate / "mkosi.conf").write_text(
                (candidate / "mkosi.conf").read_text().replace("\nBuildSources=\n", "\n"))),
            ("hook", add_hook),
            ("binary", lambda candidate: (candidate / "artifacts/wrapper").write_bytes(b"different guest binary")),
            ("mask", replace_mask),
            ("network-generator-mask", replace_generator_mask),
            ("resolved-credential-override", lambda candidate: (
                candidate / "rootfs/etc/systemd/system/systemd-resolved.service.d/10-no-credentials.conf"
            ).write_text("[Service]\nImportCredential=network.dns\n")),
            ("mode", change_mode),
            ("missing", lambda candidate: (candidate / "audit-rootfs.py").unlink()),
            ("seal", lambda candidate: (candidate / "seal-shadow.py").unlink()),
            ("shadow", lambda candidate: (candidate / "rootfs/etc/shadow").chmod(0o600)),
            ("lock", lambda candidate: (candidate / "inputs.lock.json").write_bytes(b"{}")),
            ("output", lambda candidate: add_build_output(candidate, "output")),
            ("work", lambda candidate: add_build_output(candidate, "work")),
            ("cache", lambda candidate: add_build_output(candidate, "package-cache")),
            ("peer-cache", lambda candidate: (candidate / "rootfs/etc/zrpc/zebra.toml").write_text(
                (candidate / "rootfs/etc/zrpc/zebra.toml").read_text().replace("cache_dir = false", "cache_dir = true"))),
        ]
        for name, change in cases:
            with self.subTest(change=name):
                candidate = self.root / f"changed-{name}"
                shutil.copytree(output, candidate, symlinks=True)
                change(candidate)
                with self.assertRaises(ValueError):
                    prepare.verify_stage(candidate, recorded_sha, recorded_bytes)

    def test_verify_stage_rejects_forbidden_manifest_claims_even_with_matching_hash(self):
        output, report = self.stage_synthetic_candidate()
        manifest = output / "candidate-manifest.json"
        original = manifest.read_bytes()
        recorded_sha = report["manifest_sha256"]
        recorded_bytes = report["manifest_bytes"]

        def reject_rewritten(data):
            manifest.write_bytes(data)
            with self.assertRaises(ValueError):
                prepare.verify_stage(output, hashlib.sha256(data).hexdigest(), len(data))

        changed_gate = original.replace(b"real TDX acceptance", b"fake TDX acceptance")
        self.assertNotEqual(changed_gate, original)
        manifest.write_bytes(changed_gate)
        with self.assertRaisesRegex(ValueError, "recorded digest"):
            prepare.verify_stage(output, recorded_sha, recorded_bytes)

        changed = json.loads(original)
        changed["image_built"] = True
        reject_rewritten(json.dumps(changed).encode())
        changed["image_built"] = False
        changed["private_mode_approved"] = True
        reject_rewritten(json.dumps(changed).encode())
        changed["private_mode_approved"] = False
        changed["status"] = "approved"
        reject_rewritten(json.dumps(changed).encode())
        reject_rewritten(original.replace(b'"schema_version": 1,', b'"schema_version": 1, "schema_version": 1,', 1))
        changed = json.loads(original)
        changed["entries"]["../unreviewed"] = {"type": "directory", "mode": 493}
        reject_rewritten(json.dumps(changed).encode())

        manifest.write_bytes(original)
        manifest.unlink()
        manifest.symlink_to("inputs.lock.json")
        with self.assertRaises(OSError):
            prepare.verify_stage(output, recorded_sha, recorded_bytes)
        root_link = self.root / "candidate-symlink"
        root_link.symlink_to(output, target_is_directory=True)
        with self.assertRaises(ValueError):
            prepare.verify_stage(root_link, recorded_sha, recorded_bytes)

    def test_staging_rejects_changed_copied_boot_profile(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        output = self.root / "candidate"
        package_manifest = json.loads((self.inputs / "package_manifest").read_text())
        archives = {(item["name"], item["version"], item["architecture"]): self.inputs / item["path"] for item in package_manifest}
        original_copy2 = shutil.copy2

        def changed_copy(source, destination, *args, **kwargs):
            result = original_copy2(source, destination, *args, **kwargs)
            if Path(source) == prepare.PROFILE / "mkosi.conf":
                copied = Path(destination)
                copied.write_text(copied.read_text().replace("SecureBoot=yes", "SecureBoot=no"))
            return result

        with mock.patch.object(prepare.debian_snapshot, "verify_snapshot", return_value=({"synthetic": True}, archives)), mock.patch.object(prepare.shutil, "copy2", side_effect=changed_copy):
            with self.assertRaisesRegex(ValueError, "staged input differs from pinned manifest"):
                prepare.stage(lock_path, self.inputs, output)
        self.assertFalse((output / "candidate-manifest.json").exists())

    def test_staging_rejects_changed_copied_rootfs(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        output = self.root / "candidate"
        package_manifest = json.loads((self.inputs / "package_manifest").read_text())
        archives = {(item["name"], item["version"], item["architecture"]): self.inputs / item["path"] for item in package_manifest}
        original_copytree = shutil.copytree

        def changed_copy(source, destination, *args, **kwargs):
            result = original_copytree(source, destination, *args, **kwargs)
            if Path(source) == prepare.PROFILE / "rootfs":
                (Path(destination) / "usr/lib/systemd/system/zrpc.target").write_text("[Unit]\nDescription=changed during copy\n")
            return result

        with mock.patch.object(prepare.debian_snapshot, "verify_snapshot", return_value=({"synthetic": True}, archives)), mock.patch.object(prepare.shutil, "copytree", side_effect=changed_copy):
            with self.assertRaisesRegex(ValueError, "staged input differs from pinned manifest"):
                prepare.stage(lock_path, self.inputs, output)
        self.assertFalse((output / "candidate-manifest.json").exists())

    def test_missing_identity_changed_artifact_and_escape_fail(self):
        for change in (lambda lock: lock.update(schema_version=5), lambda lock: lock.pop("snapshot"), lambda lock: lock["artifacts"].update(initrd={"path": "initrd", "sha256": "00" * 32}), lambda lock: lock["artifacts"].update(kernel={"path": "kernel", "sha256": "00" * 32}), lambda lock: lock["artifacts"].update(base_tree={"path": "base_tree", "sha256": "00" * 32}), lambda lock: lock["artifacts"]["wrapper"].update(sha256="00" * 32), lambda lock: lock["artifacts"]["wrapper"].update(path="../wrapper"), lambda lock: lock.update(kernel_version="other-abi"), lambda lock: lock["runtime"].update(max_quotes=0), lambda lock: lock.update(snapshot="https://deb.debian.org/debian")):
            lock = copy.deepcopy(self.lock)
            change(lock)
            with self.assertRaises(ValueError):
                prepare.validate_lock(lock, self.inputs)

    def test_missing_early_init_artifact_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["artifacts"].pop("early_init")
        with self.assertRaisesRegex(ValueError, "exact complete input role set required"):
            prepare.validate_lock(lock, self.inputs)

    def test_missing_or_changed_disk_helper_artifact_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["artifacts"].pop("disk_id")
        with self.assertRaisesRegex(ValueError, "exact complete input role set required"):
            prepare.validate_lock(lock, self.inputs)
        helper = self.inputs / "disk_id"
        helper.write_bytes(helper.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "input digest or path mismatch"):
            prepare.validate_lock(self.lock, self.inputs)

    def test_missing_or_changed_public_disk_rule_rejected(self):
        profile = self.root / "changed-profile"
        shutil.copytree(prepare.PROFILE, profile, symlinks=True)
        rule = profile / "rootfs/usr/lib/udev/rules.d/65-gce-disk-naming.rules"
        rule.write_bytes(rule.read_bytes() + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "measured public-disk boot input differs"):
            prepare.validate_boot_profile(profile)
        shutil.copyfile(prepare.PROFILE / "rootfs/usr/lib/udev/rules.d/65-gce-disk-naming.rules", rule)
        rule.unlink()
        with self.assertRaisesRegex(ValueError, "measured public-disk boot input differs"):
            prepare.validate_boot_profile(profile)

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
        self.assertTrue(any("operator-owned signing key" in gate for gate in report["remaining_gates"]))
        for unit in ("systemd-sysext.service", "systemd-sysext.socket", "systemd-sysext@.service",
                     "systemd-udev-load-credentials.service", "systemd-network-generator.service"):
            self.assertEqual((output / "rootfs/etc/systemd/system" / unit).readlink(), Path("/dev/null"))
        self.assertEqual(set(prepare.RETAINED_UNIT_LINKS), set(audit_rootfs.RETAINED_UNIT_LINKS))
        for relative, target in prepare.RETAINED_UNIT_LINKS.items():
            self.assertEqual((output / "rootfs/etc/systemd/system" / relative).readlink(),
                             Path("/usr/lib/systemd/system") / target)
        self.assertEqual((output / "rootfs/etc/systemd/system/ctrl-alt-del.target").readlink(),
                         Path("/dev/null"))
        self.assertEqual(
            (output / "rootfs/etc/systemd/system/systemd-resolved.service.d/10-no-credentials.conf").read_bytes(),
            audit_rootfs.RESOLVED_CREDENTIAL_DROPIN_BYTES,
        )
        units = output / "rootfs/usr/lib/systemd/system"
        wrapper = (units / "zrpc-wrapper.service").read_text()
        self.assertIn("--platform gcp-tdx", wrapper)
        self.assertIn("ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec wrapper", wrapper)
        for name in ("zrpc-wrapper", "zrpc-node", "zrpc-cookie", "zrpc-gcp-quote"):
            unit = (units / f"{name}.service").read_text()
            self.assertIn("NoExecPaths=/run /tmp /var /dev\n", unit)
            self.assertIn("ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec ", unit)
            self.assertNotIn("ExecStartPre=/usr/lib/zrpc/zrpc-gcp-guard --check", unit)
        config = (output / "mkosi.conf").read_text()
        self.assertIn(
            "\n[Validation]\n"
            "SecureBootCertificate=artifacts/secure_boot_certificate\n"
            "SecureBootKey=/run/zrpc-build-signing/secure-boot.key\n"
            "[Output]\n", config,
        )
        self.assertEqual(config.count("SecureBootKey="), 1)
        self.assertFalse((output / "artifacts/secure_boot_key").exists())
        self.assertFalse((output / "rootfs/run/zrpc-build-signing").exists())
        self.assertIn("PackageDirectories=packages", config)
        self.assertIn("PackageCacheDirectory=package-cache", config)
        self.assertEqual(config.count("CleanPackageMetadata=yes\n"), 1)
        self.assertEqual(config.count("RemoveFiles="), 1)
        self.assertIn("RemoveFiles=" + ",".join(prepare.ROOT_REMOVE_FILES) + "\n", config)
        self.assertEqual(config.count("FinalizeScripts=seal-shadow.py,sanitize-mount.py,audit-rootfs.py\n"), 1)
        self.assertIn(
            "\n[Build]\nBuildSources=\nWorkspaceDirectory=work\n"
            "PackageCacheDirectory=package-cache\n"
            f"Environment=SYSTEMD_REPART_MKFS_OPTIONS_EXT4=-Ehash_seed={report['repart_seed']}\n",
            config,
        )
        self.assertEqual(config.count("\nBuildSources=\n"), 1)
        for script in (output / "seal-shadow.py", output / "sanitize-mount.py",
                       output / "audit-rootfs.py",
                       output / "mkosi.images/initrd/sanitize-mount.py",
                       output / "mkosi.images/initrd/audit-initrd.py"):
            self.assertNotIn("SRCDIR", script.read_text())
            self.assertNotIn("/work/src", script.read_text())
        for script in (output / "sanitize-mount.py", output / "audit-rootfs.py",
                       output / "mkosi.images/initrd/sanitize-mount.py",
                       output / "mkosi.images/initrd/audit-initrd.py"):
            self.assertIn(hashlib.sha256(b"SYNTHETIC").hexdigest(), script.read_text())
        self.assertEqual((output / "seal-shadow.py").stat().st_mode & 0o777, 0o555)
        for name, (size, expected_sha, source_mode, staged_mode) in prepare.ACCOUNT_OUTPUTS.items():
            source = prepare.PROFILE / "rootfs/etc" / name
            staged = output / "rootfs/etc" / name
            self.assertEqual((source.stat().st_size, prepare.digest(source), source.stat().st_mode & 0o777),
                             (size, expected_sha, source_mode))
            self.assertEqual((staged.stat().st_size, prepare.digest(staged), staged.stat().st_mode & 0o777),
                             (size, expected_sha, staged_mode))
            self.assertEqual(report["entries"]["rootfs/etc/" + name],
                             {"type": "file", "sha256": expected_sha, "mode": staged_mode})
        self.assertTrue((output / "package-cache").is_dir())
        self.assertNotIn("BaseTrees=", config)
        self.assertFalse((output / "artifacts/base_tree.tar").exists())
        self.assertFalse((output / "artifacts/kernel").exists())
        self.assertFalse((output / "artifacts/initrd").exists())
        self.assertFalse((output / "rootfs/usr/lib/modules").exists())
        self.assertIn("Packages=dmsetup=1.0~synthetic,e2fsprogs=1.0~synthetic,kmod=1.0~synthetic,libc6=1.0~synthetic,libjson-c5=1.0~synthetic,libssl3t64=1.0~synthetic,linux-image-6.12.107+deb13-cloud-amd64=6.12.107-1,mount=1.0~synthetic,systemd-boot-efi=1.0~synthetic,systemd-cryptsetup=1.0~synthetic,systemd-resolved=1.0~synthetic,systemd=1.0~synthetic,udev=1.0~synthetic", config)
        self.assertIn("Initrds=output/initrd.cpio.zst", config)
        self.assertIn(f'Seed={report["repart_seed"]}', config)
        self.assertEqual((output / "inputs.lock.json").read_bytes(), lock_path.read_bytes())
        self.assertEqual(report["input_lock_sha256"], hashlib.sha256(lock_path.read_bytes()).hexdigest())
        self.assertEqual(uuid.UUID(report["repart_seed"]).version, 5)
        self.assertEqual(report["repart_seed_derivation"]["algorithm"], "UUIDv5")
        self.assertIn("Dependencies=initrd", config)
        self.assertIn("KernelModulesInitrdInclude=^drivers/md/dm-verity[.]ko[.]xz$", config)
        self.assertIn("rd.modules_load=dm-verity", config)
        initrd = (output / "mkosi.images/initrd/mkosi.conf").read_text()
        self.assertIn("MakeInitrd=yes", initrd)
        self.assertIn("Packages=dmsetup=1.0~synthetic,kmod=1.0~synthetic,mount=1.0~synthetic,systemd=1.0~synthetic,systemd-cryptsetup=1.0~synthetic,udev=1.0~synthetic", initrd)
        self.assertIn("ExtraTrees=rootfs", initrd)
        self.assertIn("FinalizeScripts=sanitize-mount.py,audit-initrd.py", initrd)
        for relative in ("/usr/sbin/unix_chkpwd", "/usr/bin/umount",
                         "/usr/bin/perl", "/usr/bin/perl5.40.1",
                         "/var/log/journal", "/var/mail",
                         "/var/cache/ldconfig/aux-cache",
                         "/var/log/alternatives.log",
                         "/usr/lib/systemd/system/systemd-sysext.service",
                         "/usr/lib/systemd/system/systemd-sysext.socket",
                         "/usr/lib/systemd/system/systemd-sysext@.service",
                         "/usr/lib/systemd/system/sockets.target.wants/systemd-sysext.socket",
                         "/usr/lib/systemd/system/systemd-confext.service",
                         "/usr/lib/systemd/system/systemd-udev-load-credentials.service",
                         "/etc/systemd/system/sysinit.target.wants/systemd-sysext.service",
                         "/etc/systemd/system/sockets.target.wants/systemd-sysext.socket",
                         "/etc/systemd/system/sysinit.target.wants/systemd-confext.service",
                         "/etc/systemd/system/sysinit.target.wants/systemd-udev-load-credentials.service",
                         "/usr/lib/systemd/system/systemd-pstore.service",
                         "/etc/systemd/system/sysinit.target.wants/systemd-pstore.service",
                         "/usr/lib/systemd/system/systemd-network-generator.service",
                         "/etc/systemd/system/sysinit.target.wants/systemd-network-generator.service"):
            self.assertIn(relative, prepare.INITRD_REMOVE_FILES)
            self.assertIn(relative, initrd)
        audit = output / "mkosi.images/initrd/audit-initrd.py"
        expected_init_hash = self.lock["artifacts"]["early_init"]["sha256"]
        self.assertIn(expected_init_hash, audit.read_text())
        self.assertNotIn("__STAGED_INIT_SHA256__", audit.read_text())
        self.assertEqual(audit.stat().st_mode & 0o777, 0o555)
        staged_init = output / "mkosi.images/initrd/rootfs/init"
        self.assertEqual(prepare.digest(staged_init), expected_init_hash)
        self.assertEqual(staged_init.stat().st_mode & 0o777, 0o555)
        self.assertFalse((output / "rootfs/init").exists())
        self.assertNotIn("Include=mkosi-initrd", initrd)
        self.assertNotIn("linux-image", initrd)
        esp = (output / "repart/30-esp.conf").read_text()
        self.assertIn("CopyFiles=/efi:/", esp)
        self.assertIn("Minimize=guess", esp)
        self.assertNotIn("CopyFiles=/boot:/", esp)
        self.assertEqual((output / "rootfs/etc/systemd/system/ssh.service").readlink(), Path("/dev/null"))
        self.assertEqual((output / "rootfs/etc/systemd/system/systemd-sysusers.service").readlink(), Path("/dev/null"))
        self.assertIn("zrpc-wrapper.service", (units / "zrpc.target").read_text())
        with self.assertRaises(ValueError):
            prepare.stage(lock_path, self.inputs, output)

    def test_repart_seed_is_stable_for_exact_lock_bytes_and_changes_with_lock(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        package_manifest = json.loads((self.inputs / "package_manifest").read_text())
        archives = {(item["name"], item["version"], item["architecture"]): self.inputs / item["path"] for item in package_manifest}
        with mock.patch.object(prepare.debian_snapshot, "verify_snapshot", return_value=({"synthetic": True}, archives)):
            first = prepare.stage(lock_path, self.inputs, self.root / "candidate-one")
            second = prepare.stage(lock_path, self.inputs, self.root / "candidate-two")
            lock_path.write_text(json.dumps(self.lock, indent=2))
            changed = prepare.stage(lock_path, self.inputs, self.root / "candidate-three")
        self.assertEqual(first["repart_seed"], second["repart_seed"])
        self.assertNotEqual(first["repart_seed"], changed["repart_seed"])
        self.assertEqual(first["input_lock_sha256"], second["input_lock_sha256"])
        self.assertNotEqual(first["input_lock_sha256"], changed["input_lock_sha256"])

    def test_boot_recipe_rejects_missing_uki_or_verity_commitment(self):
        profile = self.root / "profile"
        profile.mkdir()
        shutil.copy2(prepare.PROFILE / "mkosi.conf", profile / "mkosi.conf")
        shutil.copytree(prepare.PROFILE / "mkosi.images", profile / "mkosi.images")
        shutil.copytree(prepare.PROFILE / "repart", profile / "repart")
        shutil.copytree(prepare.PROFILE / "rootfs", profile / "rootfs")
        (profile / "input-identities.json").write_text("{}")
        shutil.copy2(prepare.PROFILE / "package-closure.lock.json", profile / "package-closure.lock.json")
        prepare.validate_boot_profile(profile)
        changes = (
            ("repart/30-esp.conf", "CopyFiles=/efi:/", "CopyFiles=/boot:/"),
            ("repart/30-esp.conf", "Minimize=guess", "Minimize=off"),
            ("repart/10-root.conf", "Verity=data", "Verity=off"),
            ("repart/10-root.conf", "Minimize=guess", "Minimize=best"),
            ("repart/20-root-verity.conf", "Verity=hash", "Verity=off"),
            ("repart/20-root-verity.conf", "Minimize=best", "Minimize=off"),
            ("mkosi.conf", "SecureBoot=yes", "SecureBoot=no"),
            ("mkosi.conf", "SectorSize=512", "SectorSize=4096"),
            ("mkosi.conf", "SectorSize=512\n", ""),
            ("mkosi.conf", "KernelModulesInitrd=yes", "KernelModulesInitrd=no"),
            ("mkosi.conf", "KernelModulesInitrdInclude=^drivers/md/dm-verity[.]ko[.]xz$", "KernelModulesInitrdInclude=.*"),
            ("mkosi.conf", "KernelModulesInitrdExclude=.*", "KernelModulesInitrdExclude="),
            ("mkosi.conf", "systemd.import_credentials=no", "systemd.import_credentials=yes"),
            ("mkosi.conf", "systemd.import_credentials=no ", ""),
            ("mkosi.conf", "systemd.import_credentials=no", "systemd.import_credentials=no systemd.import_credentials=yes"),
            ("mkosi.conf", "pstore.backend=none ", ""),
            ("mkosi.conf", "pstore.backend=none", "pstore.backend=efi_pstore"),
            ("mkosi.conf", "pstore.backend=none", "pstore.backend=none pstore.backend=efi_pstore"),
            ("mkosi.conf", "Dependencies=initrd", "Dependencies="),
            ("mkosi.conf", "Bootloader=uki", "Bootloader=systemd-boot"),
            ("mkosi.conf", "ExtraTrees=rootfs", "ExtraTrees=rootfs\nPostOutputScripts=unreviewed.sh"),
            ("mkosi.conf", "CleanPackageMetadata=yes", "CleanPackageMetadata=auto"),
            ("mkosi.conf", "RemoveFiles=/usr/sbin/unix_chkpwd,", "RemoveFiles="),
            ("mkosi.images/initrd/mkosi.conf", "MakeInitrd=yes", "MakeInitrd=no"),
            ("mkosi.images/initrd/mkosi.conf", "Ssh=no", "Ssh=yes"),
            ("mkosi.images/initrd/mkosi.conf", "rescue.target,", ""),
            ("mkosi.images/initrd/mkosi.conf", "getty.target.wants/getty@tty1.service,", ""),
            ("mkosi.images/initrd/mkosi.conf", "autovt@.service,", ""),
            ("mkosi.images/initrd/mkosi.conf", "multi-user.target.wants/getty.target,", ""),
            ("mkosi.images/initrd/mkosi.conf", "boot/loader,", ""),
            ("mkosi.images/initrd/mkosi.conf", "var/log/journal,", ""),
            ("mkosi.images/initrd/mkosi.conf", "var/mail,", ""),
            ("mkosi.images/initrd/mkosi.conf", "etc/ssh,", ""),
            ("mkosi.images/initrd/mkosi.conf", "20-systemd-ssh-generator.conf,", ""),
            ("mkosi.images/initrd/mkosi.conf", "usr/sbin/unix_chkpwd,", ""),
            ("mkosi.images/initrd/mkosi.conf", "usr/bin/umount,", ""),
            ("mkosi.images/initrd/mkosi.conf", "usr/bin/perl,", ""),
            ("mkosi.images/initrd/mkosi.conf", "usr/bin/perl5.40.1,", ""),
            ("mkosi.images/initrd/mkosi.conf", "RemoveFiles=/usr/lib/systemd/system/rescue.service", "RemoveFiles=/usr/lib/systemd/system/other.service"),
        )
        for name, original, altered in changes:
            path = profile / name
            good = path.read_text()
            self.assertIn(original, good)
            path.write_text(good.replace(original, altered))
            with self.assertRaises(ValueError):
                prepare.validate_boot_profile(profile)
            path.write_text(good)
        (profile / "repart/40-unreviewed.conf").write_text("[Partition]\nType=swap\n")
        with self.assertRaises(ValueError):
            prepare.validate_boot_profile(profile)
        (profile / "repart/40-unreviewed.conf").unlink()
        (profile / "mkosi.conf.d").mkdir()
        with self.assertRaises(ValueError):
            prepare.validate_boot_profile(profile)
        (profile / "mkosi.conf.d").rmdir()
        (profile / "mkosi.images/initrd/mkosi.postinst").write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "unexpected initrd subimage input"):
            prepare.validate_boot_profile(profile)
        (profile / "mkosi.images/initrd/mkosi.postinst").unlink()
        for source in ("boot", "lib/modules", "usr/lib/modules"):
            path = profile / "rootfs" / source
            path.mkdir(parents=True)
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "ExtraTrees must not supply"):
                prepare.validate_boot_profile(profile)
            path.rmdir()
        for name in prepare.ACCOUNT_OUTPUTS:
            path = profile / "rootfs/etc" / name
            good = path.read_bytes()
            path.write_bytes(b"X" + good[1:])
            with self.subTest(account=name), self.assertRaisesRegex(ValueError, "reviewed guest account source differs"):
                prepare.validate_boot_profile(profile)
            path.write_bytes(good)
        sysusers = profile / "rootfs/usr/lib/sysusers.d/zrpc.conf"
        original = sysusers.read_bytes()
        sysusers.write_bytes(original + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "project sysusers source differs"):
            prepare.validate_boot_profile(profile)

    def test_unverified_snapshot_cannot_stage(self):
        lock_path = self.root / "synthetic.lock.json"
        lock_path.write_text(json.dumps(self.lock))
        with self.assertRaises(ValueError):
            prepare.stage(lock_path, self.inputs, self.root / "candidate")
        self.assertFalse((self.root / "candidate").exists())

    def test_snapshot_hold_clears_at_seven_days(self):
        selected = datetime(2026, 9, 20, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "seven-day hold"):
            prepare.debian_snapshot.require_snapshot_age(
                selected, selected + timedelta(days=7, seconds=-1)
            )
        prepare.debian_snapshot.require_snapshot_age(selected, selected + timedelta(days=7))

    def test_preflight_rejects_unshare_without_a_new_network_namespace(self):
        parent_net = Path("/proc/self/ns/net").readlink().as_posix()
        with mock.patch.object(prepare.platform, "system", return_value="Linux"), mock.patch.object(
            prepare.platform, "machine", return_value="x86_64"
        ), mock.patch.object(prepare.shutil, "which", return_value="/usr/bin/unshare"), mock.patch.object(
            prepare.subprocess, "run", side_effect=[
                mock.Mock(returncode=0), mock.Mock(returncode=0, stdout=parent_net + "\n"),
                mock.Mock(returncode=1, stdout="")
            ]
        ):
            report = prepare.preflight()
        self.assertEqual(report["status"], "blocked")
        self.assertIn("outer build network namespace isolation unavailable", report["blockers"])

    def test_preflight_rejects_denied_or_unobserved_mount_probe(self):
        parent_net = Path("/proc/self/ns/net").readlink().as_posix()
        child_net = "net:[999999999]" if parent_net != "net:[999999999]" else "net:[999999998]"
        for mount_result in (mock.Mock(returncode=1, stdout=""),
                             mock.Mock(returncode=0, stdout="unobserved\n")):
            with self.subTest(mount_result=mount_result.stdout), mock.patch.object(
                prepare.platform, "system", return_value="Linux"
            ), mock.patch.object(prepare.platform, "machine", return_value="x86_64"), mock.patch.object(
                prepare.shutil, "which", return_value="/usr/bin/tool"
            ), mock.patch.object(prepare.subprocess, "run", side_effect=[
                mock.Mock(returncode=0), mock.Mock(returncode=0, stdout=child_net + "\n"),
                mount_result,
            ]) as run:
                report = prepare.preflight()
            self.assertEqual(report["status"], "blocked")
            self.assertIn("isolated tmpfs mount/unmount unavailable", report["blockers"])
            self.assertIn("--mount", run.call_args.args[0])
            self.assertIn("--propagation", run.call_args.args[0])

    def test_preflight_can_report_only_capabilities_after_mount_probe(self):
        parent_net = Path("/proc/self/ns/net").readlink().as_posix()
        child_net = "net:[999999999]" if parent_net != "net:[999999999]" else "net:[999999998]"
        with mock.patch.object(prepare.platform, "system", return_value="Linux"), mock.patch.object(
            prepare.platform, "machine", return_value="x86_64"
        ), mock.patch.object(prepare.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(
            prepare.subprocess, "run", side_effect=[
                mock.Mock(returncode=0), mock.Mock(returncode=0, stdout=child_net + "\n"),
                mock.Mock(returncode=0, stdout="zrpc-isolated-tmpfs-ok\n"),
            ]
        ):
            report = prepare.preflight()
        self.assertEqual(report["status"], "capabilities-present-input-review-required")
        self.assertIs(report["image_built"], False)
        self.assertIs(report["private_mode_approved"], False)

    def test_mount_probe_refuses_parent_namespaces_before_mount_call(self):
        marker = self.root / "mount-was-invoked"
        mount_tool = self.root / "synthetic-mount-tool"
        mount_tool.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        mount_tool.chmod(0o700)
        result = subprocess.run(
            [sys.executable, "-c", prepare.MOUNT_PROBE_SCRIPT,
             Path("/proc/self/ns/user").readlink().as_posix(),
             Path("/proc/self/ns/mnt").readlink().as_posix(),
             str(mount_tool), str(mount_tool)],
            capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

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
        self.lock["artifacts"]["snapshot_inrelease"]["sha256"] = prepare.digest(release)
        paths = {"snapshot_inrelease": release, "packages_index": index}
        with mock.patch.object(prepare.debian_snapshot, "verify_signature"):
            snapshot, archives = prepare.debian_snapshot.verify_snapshot(self.lock, paths, self.inputs, manifest)
            self.assertEqual(snapshot["package_count"], len(manifest))
            self.assertEqual(len(archives), len(manifest))
            held_snapshot = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            self.lock["snapshot"] = f"https://snapshot.debian.org/archive/debian/{held_snapshot}/"
            with self.assertRaisesRegex(ValueError, "seven-day hold"):
                prepare.debian_snapshot.verify_snapshot(self.lock, paths, self.inputs, manifest)
            self.lock["snapshot"] = "https://snapshot.debian.org/archive/debian/20200101T000000Z/"
            index.write_bytes(index.read_bytes() + b"TAMPER")
            with self.assertRaisesRegex(ValueError, "index exceeds reviewed size"):
                prepare.debian_snapshot.verify_snapshot(self.lock, paths, self.inputs, manifest)

    def test_reviewed_debian_keyring_hash(self):
        self.assertEqual(prepare.debian_snapshot.sha256(prepare.debian_snapshot.KEYRING), prepare.debian_snapshot.KEYRING_SHA256)

    def test_unpinned_gpgv_executable_is_rejected(self):
        with mock.patch.object(prepare.debian_snapshot.shutil, "which", return_value="/bin/true"):
            with self.assertRaisesRegex(ValueError, "gpgv executable differs"):
                prepare.debian_snapshot.verify_signature(self.inputs / "snapshot_inrelease")

    def test_gpgv_uses_reviewed_bytes_after_source_paths_change(self):
        # The test executable only reports a synthetic status after reading the
        # original keyring. It is not evidence of a Debian archive signature.
        keyring_bytes = b"REVIEWED PUBLIC KEY"
        program_bytes = ("#!/bin/sh\n"
                         "[ \"$(cat \"$4\")\" = 'REVIEWED PUBLIC KEY' ] || exit 9\n"
                         f"printf '[GNUPG:] VALIDSIG 0 {prepare.debian_snapshot.TRIXIE_ARCHIVE_FINGERPRINT}\\n'\n").encode()
        keyring = self.root / "keyring"
        program = self.root / "gpgv"
        original_run = subprocess.run
        for replacement in (False, True):
            with self.subTest(replace_pathname=replacement):
                keyring.write_bytes(keyring_bytes)
                program.write_bytes(program_bytes)
                program.chmod(0o700)
                malicious_program = b"#!/bin/sh\ntouch " + str(self.root / "poison-ran").encode() + b"\nexit 1\n"

                def change_source_then_run(argv, **kwargs):
                    self.assertTrue(argv[0].startswith("/proc/self/fd/"))
                    self.assertTrue(argv[4].startswith("/proc/self/fd/"))
                    if replacement:
                        poisoned_keyring = self.root / "poison-keyring"
                        poisoned_program = self.root / "poison-gpgv"
                        poisoned_keyring.write_bytes(b"POISONED PUBLIC KEY")
                        poisoned_program.write_bytes(malicious_program)
                        poisoned_program.chmod(0o700)
                        os.replace(poisoned_keyring, keyring)
                        os.replace(poisoned_program, program)
                    else:
                        keyring.write_bytes(b"POISONED PUBLIC KEY")
                        program.write_bytes(malicious_program)
                    return original_run(argv, **kwargs)

                with mock.patch.object(prepare.debian_snapshot, "KEYRING", keyring), \
                        mock.patch.object(prepare.debian_snapshot, "KEYRING_SHA256", hashlib.sha256(keyring_bytes).hexdigest()), \
                        mock.patch.object(prepare.debian_snapshot, "KEYRING_SIZE", len(keyring_bytes)), \
                        mock.patch.object(prepare.debian_snapshot, "GPGV_SHA256", hashlib.sha256(program_bytes).hexdigest()), \
                        mock.patch.object(prepare.debian_snapshot, "GPGV_SIZE", len(program_bytes)), \
                        mock.patch.object(prepare.debian_snapshot.shutil, "which", return_value=str(program)), \
                        mock.patch.object(prepare.debian_snapshot.subprocess, "run", side_effect=change_source_then_run):
                    prepare.debian_snapshot.verify_signature(self.inputs / "snapshot_inrelease")
                self.assertFalse((self.root / "poison-ran").exists())

    def test_known_admin_package_is_rejected(self):
        path = self.inputs / "package_manifest"
        packages = json.loads(path.read_text())
        packages.append({"name": "openssh-server", "version": "1.0~synthetic", "architecture": "amd64", "filename": "pool/main/o/openssh/openssh-server_1.0~synthetic_amd64.deb", "size": 1, "sha256": "aa" * 32, "path": "debs/" + "aa" * 32 + ".deb"})
        path.write_text(json.dumps(packages))
        self.lock["artifacts"]["package_manifest"]["sha256"] = prepare.digest(path)
        with self.assertRaises(ValueError):
            prepare.validate_lock(self.lock, self.inputs)

    def test_signed_package_selection_cannot_change_reviewed_closure(self):
        path = self.inputs / "package_manifest"
        packages = json.loads(path.read_text())
        package = next(item for item in packages if item["name"] == "systemd")
        package["version"] = "2.0~synthetic"
        path.write_text(json.dumps(packages))
        self.lock["artifacts"]["package_manifest"]["sha256"] = prepare.digest(path)
        with mock.patch.object(prepare.debian_snapshot, "verify_snapshot") as verify:
            with self.assertRaisesRegex(ValueError, "source-reviewed candidate closure"):
                prepare.validate_lock(self.lock, self.inputs)
            verify.assert_not_called()
        # Replacing both caller input and the source lock cannot bypass the
        # reviewed digest embedded in the staging code.
        self.closure.write_bytes(path.read_bytes())
        with self.assertRaisesRegex(ValueError, "source-reviewed candidate closure"):
            prepare.validate_lock(self.lock, self.inputs)
        # The lock must also exist as a regular source file. An input-controlled
        # symlink cannot redirect which closure the builder accepts.
        self.closure.rename(self.root / "moved-closure.json")
        self.closure.symlink_to(self.root / "moved-closure.json")
        with self.assertRaisesRegex(ValueError, "source-reviewed candidate closure"):
            prepare.validate_lock(self.lock, self.inputs)

    def test_missing_required_guest_package_is_rejected(self):
        path = self.inputs / "package_manifest"
        packages = json.loads(path.read_text())
        for required in ("systemd-resolved", "udev", "e2fsprogs", "dmsetup", "kmod", prepare.KERNEL_PACKAGE):
            path.write_text(json.dumps([p for p in packages if p["name"] != required]))
            self.lock["artifacts"]["package_manifest"]["sha256"] = prepare.digest(path)
            with self.assertRaisesRegex(ValueError, "kernel package" if required == prepare.KERNEL_PACKAGE else "guest package surface"):
                prepare.validate_lock(self.lock, self.inputs)

    def test_other_kernel_package_version_or_architecture_is_rejected(self):
        path = self.inputs / "package_manifest"
        original = json.loads(path.read_text())
        for name, version, architecture, append in (
            ("linux-image-unsigned-6.12.107+deb13-cloud-amd64", prepare.KERNEL_PACKAGE_VERSION, "amd64", False),
            ("linux-image-6.12.108+deb13-cloud-amd64", prepare.KERNEL_PACKAGE_VERSION, "amd64", False),
            (prepare.KERNEL_PACKAGE, "6.12.107-2", "amd64", False),
            (prepare.KERNEL_PACKAGE, prepare.KERNEL_PACKAGE_VERSION, "all", False),
            ("linux-image-unsigned-6.12.107+deb13-cloud-amd64", prepare.KERNEL_PACKAGE_VERSION, "amd64", True),
        ):
            packages = copy.deepcopy(original)
            alternate = packages[-1].copy()
            alternate.update(name=name, version=version, architecture=architecture)
            if append:
                packages.append(alternate)
            else:
                packages[-1] = alternate
            path.write_text(json.dumps(packages))
            self.lock["artifacts"]["package_manifest"]["sha256"] = prepare.digest(path)
            with self.subTest(name=name, version=version, architecture=architecture, append=append):
                with self.assertRaisesRegex(ValueError, "exact signed Debian cloud kernel package required"):
                    prepare.validate_lock(self.lock, self.inputs)

    def test_duplicate_fields_cannot_override_a_digest(self):
        path = self.root / "duplicate.json"
        path.write_text('{"sha256":"first","sha256":"second"}')
        with self.assertRaises(ValueError):
            prepare.read_json(path)

    def synthetic_guest_root(self, suffix=""):
        root = self.root / f"synthetic-root{suffix}"
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "usr/lib/zrpc").mkdir(parents=True)
        (root / "usr/bin").mkdir(parents=True)
        (root / "usr/bin/mount").write_bytes(b"SYNTHETIC")
        (root / "usr/bin/mount").chmod(0o555)
        units = root / "usr/lib/systemd/system"
        units.mkdir(parents=True)
        source_units = prepare.PROFILE / "rootfs/usr/lib/systemd/system"
        for unit in audit_rootfs.APPLIANCE_UNITS:
            shutil.copyfile(source_units / unit, units / unit)
        # Debian's installed multi-user target has runlevel aliases. Their
        # drop-ins and dependency directories affect this appliance's boot.
        (units / "multi-user.target").write_text("[Unit]\nDescription=Synthetic multi-user target\n")
        for alias in ("runlevel2.target", "runlevel3.target", "runlevel4.target"):
            (units / alias).symlink_to("multi-user.target")
        (root / "etc/systemd/system/default.target").symlink_to(
            "/usr/lib/systemd/system/zrpc.target")
        wants = root / "etc/systemd/system/multi-user.target.wants"
        wants.mkdir()
        for unit in ("systemd-networkd.service", "systemd-resolved.service"):
            (wants / unit).symlink_to("/usr/lib/systemd/system/" + unit)
        for relative, target in audit_rootfs.RETAINED_UNIT_LINKS.items():
            path = root / "etc/systemd/system" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to("/usr/lib/systemd/system/" + target)
        for unit in audit_rootfs.MASKED_UNITS:
            (root / "etc/systemd/system" / unit).symlink_to("/dev/null")
        resolved_dropins = root / "etc/systemd/system/systemd-resolved.service.d"
        resolved_dropins.mkdir()
        shutil.copyfile(
            prepare.PROFILE / "rootfs/etc/systemd/system/systemd-resolved.service.d"
            / audit_rootfs.RESOLVED_CREDENTIAL_DROPIN,
            resolved_dropins / audit_rootfs.RESOLVED_CREDENTIAL_DROPIN,
        )
        (root / "etc/passwd").write_text(
            "root:x:0:0::/:/usr/sbin/nologin\n"
            "systemd-network:x:998:998::/:/usr/sbin/nologin\n"
            "systemd-resolve:x:997:997::/:/usr/sbin/nologin\n"
            "zrpc-node:x:101:101::/nonexistent:/usr/sbin/nologin\n"
            "zrpc-wrapper:x:102:102::/nonexistent:/usr/sbin/nologin\n")
        (root / "etc/shadow").write_text(
            "root:!*:0:0:0:0:0:0:\n"
            "systemd-network:!:0:0:0:0:0:0:\n"
            "systemd-resolve:!:0:0:0:0:0:0:\n"
            "zrpc-node:!:0:0:0:0:0:0:\n"
            "zrpc-wrapper:!:0:0:0:0:0:0:\n")
        (root / "etc/group").write_text(
            "root:x:0:\n"
            "systemd-network:x:998:\n"
            "systemd-resolve:x:997:\n"
            "zrpc-node:x:101:\n"
            "zrpc-wrapper:x:102:\n"
            "zrpc-cookie:x:103:zrpc-node,zrpc-wrapper\n")
        for name in prepare.BINARIES.values():
            (root / "usr/lib/zrpc" / name).write_text("SYNTHETIC")
            (root / "usr/lib/zrpc" / name).chmod(0o555)
        for relative in ("etc/fstab", "usr/lib/udev/rules.d/65-gce-disk-naming.rules"):
            source = prepare.PROFILE / "rootfs" / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        self.synthetic_disk_tool(root, None)
        return root

    def test_rootfs_audit_rejects_appliance_unit_overrides(self):
        changed = (
            ("etc/systemd/system/zrpc-wrapper.service.d/override.conf", b"[Service]\nExecStart=\n"),
            ("usr/local/lib/systemd/system/zrpc-wrapper.service", b"[Service]\nExecStart=/bin/false\n"),
            ("usr/lib/systemd/system/service.d/override.conf", b"[Service]\nProtectSystem=no\n"),
            ("etc/systemd/system/zrpc-.service.d/override.conf", b"[Service]\nNoNewPrivileges=no\n"),
            ("etc/systemd/system/zrpc-gcp-.service.d/override.conf", b"[Service]\nUser=root\n"),
            ("run/systemd/system/zrpc-node.service.d/override.conf", b"[Service]\nExecStart=\n"),
            ("etc/systemd/system/zrpc.target.wants/rogue.service", b"SYNTHETIC"),
            ("etc/systemd/system/zrpc.target.upholds/rogue.service", b"SYNTHETIC"),
            ("etc/systemd/system/default.target.d/override.conf", b"[Unit]\nRequires=rogue.service\n"),
            ("etc/systemd/system/default.target.upholds/rogue.service", b"SYNTHETIC"),
            ("etc/systemd/system/runlevel2.target.d/override.conf", b"[Unit]\nWants=rogue.service\n"),
            ("usr/lib/systemd/system/runlevel3.target.requires/rogue.service", b"SYNTHETIC"),
            ("etc/systemd/system/runlevel4.target.upholds/rogue.service", b"SYNTHETIC"),
            ("usr/lib/systemd/system/target.d/override.conf", b"[Unit]\nWants=rogue.service\n"),
            ("etc/systemd/system/multi-user.target.wants/rogue.service", b"SYNTHETIC"),
            ("usr/local/lib/systemd/system/multi-user.target.wants/rogue.service", b"SYNTHETIC"),
        )
        for index, (relative, contents) in enumerate(changed):
            with self.subTest(relative=relative):
                root = self.synthetic_guest_root(f"-{index}")
                audit_rootfs.audit(root)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                with self.assertRaisesRegex(ValueError, "appliance unit override or dependency|appliance boot dependencies|appliance unit replaced|postinst-generated path remains"):
                    audit_rootfs.audit(root)

        root = self.synthetic_guest_root("-replacement")
        (root / "etc/systemd/system/zrpc-wrapper.service").symlink_to(
            "/usr/lib/systemd/system/zrpc-wrapper.service")
        with self.assertRaisesRegex(ValueError, "appliance unit replaced"):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-multi-user")
        (root / "etc/systemd/system/multi-user.target").write_text(
            "[Unit]\nWants=rogue.service\n")
        with self.assertRaisesRegex(ValueError, "appliance unit replaced"):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-alias")
        (root / "etc/systemd/system/alias.service").symlink_to(
            "/usr/lib/systemd/system/zrpc-wrapper.service")
        with self.assertRaisesRegex(ValueError, "unreviewed appliance unit alias"):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-default")
        default = root / "etc/systemd/system/default.target"
        default.unlink()
        default.symlink_to("/usr/lib/systemd/system/multi-user.target")
        with self.assertRaisesRegex(ValueError, "appliance default target differs"):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-missing")
        (root / "usr/lib/systemd/system/zrpc-wrapper.service").unlink()
        with self.assertRaisesRegex(ValueError, "appliance unit missing or mutable"):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-redirected-parent")
        (root / "usr/local/lib").mkdir(parents=True)
        (root / "usr/local/lib/systemd").symlink_to("/var/lib/zebra")
        with self.assertRaisesRegex(ValueError, "postinst-generated path remains"):
            audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_retained_link_substitution(self):
        for index, relative in enumerate(audit_rootfs.RETAINED_UNIT_LINKS):
            with self.subTest(relative=relative):
                root = self.synthetic_guest_root(f"-retained-link-{index}")
                path = root / "etc/systemd/system" / relative
                path.unlink()
                path.symlink_to("/usr/lib/systemd/system/rogue.service")
                with self.assertRaisesRegex(ValueError, "retained system unit link differs"):
                    audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-retained-extra")
        (root / "etc/systemd/system/sockets.target.wants/rogue.socket").symlink_to(
            "/usr/lib/systemd/system/rogue.socket")
        with self.assertRaisesRegex(ValueError, "retained system unit wants differ"):
            audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_base_tree_kernel_cmdline(self):
        root = self.synthetic_guest_root()
        audit_rootfs.audit(root)
        # These represent files inherited from a checksum-pinned base tree.
        # Both regular files and dangling links can become mkosi cmdline input.
        for name in ("etc/kernel/cmdline", "usr/lib/kernel/cmdline"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("init=/bin/sh\n")
            with self.assertRaisesRegex(ValueError, "unreviewed kernel command line source"):
                audit_rootfs.audit(root)
            path.unlink()
            path.symlink_to("/nonexistent/cmdline")
            with self.assertRaisesRegex(ValueError, "unreviewed kernel command line source"):
                audit_rootfs.audit(root)
            path.unlink()
        audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_disk_rule_and_helper_loss(self):
        for relative in ("usr/lib/udev/rules.d/65-gce-disk-naming.rules",
                         "usr/lib/systemd/system/zrpc-gcp-disk-trigger.service",
                         "etc/fstab"):
            root = self.synthetic_guest_root("-disk-" + relative.replace("/", "-"))
            path = root / relative
            path.write_bytes(path.read_bytes() + b"# changed\n")
            with self.assertRaisesRegex(ValueError, "public-disk rule, fstab, or trigger differs"):
                audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-disk-helper")
        (root / "usr/lib/zrpc/zrpc-gcp-disk-id").unlink()
        with self.assertRaisesRegex(ValueError, "guest executable missing or mutable"):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-disk-elf")
        nvme = root / "usr/sbin/nvme"
        nvme.chmod(0o755)
        nvme.write_bytes(b"TAMPERED")
        nvme.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "public-disk tool ELF differs"):
            audit_rootfs.audit(root)

    def test_rootfs_audit_requires_exact_non_privileged_mount_helper(self):
        root = self.synthetic_guest_root("-mount")
        audit_rootfs.audit(root)
        mount = root / "usr/bin/mount"
        mount.chmod(0o755)
        mount.write_bytes(b"TAMPERED")
        mount.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "non-privileged signed mount ELF differs"):
            audit_rootfs.audit(root)
        mount.chmod(0o755)
        mount.write_bytes(b"SYNTHETIC")
        mount.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "non-privileged signed mount ELF differs"):
            audit_rootfs.audit(root)
        mount.unlink()
        mount.symlink_to("/var/lib/zebra/mount")
        with self.assertRaisesRegex(ValueError, "non-privileged signed mount ELF differs"):
            audit_rootfs.audit(root)

    def test_rootfs_audit_requires_privileged_package_files_absent(self):
        root = self.synthetic_guest_root("-privileged-package-files")
        audit_rootfs.audit(root)
        for relative in prepare.ROOT_REMOVE_FILES:
            if relative in (*prepare.REMOVED_GENERATED_UNIT_DIRECTORIES,
                            *prepare.REMOVED_GENERATED_UNIT_LINKS):
                continue
            with self.subTest(relative=relative):
                path = root / relative.lstrip("/")
                path.parent.mkdir(parents=True, exist_ok=True)
                generated_directory = relative in ("/opt", "/usr/local", "/etc/opt")
                if generated_directory:
                    path.mkdir()
                else:
                    path.write_bytes(b"SYNTHETIC")
                expected = ("postinst-generated path remains: " + relative.lstrip("/")
                            if generated_directory else
                            "build-generated file remains: " + relative.lstrip("/")
                            if relative in ("/var/cache/ldconfig/aux-cache", "/var/log/alternatives.log")
                            else "administrative binary present")
                with self.assertRaisesRegex(ValueError, expected):
                    audit_rootfs.audit(root)
                if generated_directory:
                    path.rmdir()
                else:
                    path.unlink()
        cache = root / "var/cache/ldconfig/aux-cache"
        cache.symlink_to("/var/lib/zebra/aux-cache")
        with self.assertRaisesRegex(ValueError, "build-generated file remains: var/cache/ldconfig/aux-cache"):
            audit_rootfs.audit(root)

        cache.unlink()
        privileged = {
            root / "usr/bin/unreviewed-setuid": stat.S_ISUID,
            root / "usr/bin/unreviewed-setgid": stat.S_ISGID,
        }
        for path in privileged:
            path.write_bytes(b"SYNTHETIC")
        original_lstat = Path.lstat

        def privileged_lstat(candidate):
            info = original_lstat(candidate)
            if candidate in privileged:
                return SimpleNamespace(st_mode=info.st_mode | privileged[candidate])
            return info

        with mock.patch.object(Path, "lstat", privileged_lstat):
            with self.assertRaises(ValueError) as caught:
                audit_rootfs.audit(root)
        self.assertEqual(str(caught.exception),
                         "setuid/setgid executable remains: "
                         "['usr/bin/unreviewed-setgid', 'usr/bin/unreviewed-setuid']")

    def test_rootfs_audit_requires_package_manager_metadata_absent(self):
        for name in ("var/lib/dpkg", "var/lib/apt", "var/cache/apt"):
            with self.subTest(name=name):
                root = self.synthetic_guest_root("-package-metadata-" + name.replace("/", "-"))
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir()
                with self.assertRaisesRegex(ValueError, "package-manager metadata remains: " + name):
                    audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_generated_unit_paths(self):
        expected = tuple(path.removeprefix("/") for path in
                         (*prepare.REMOVED_GENERATED_UNIT_DIRECTORIES,
                          *prepare.REMOVED_GENERATED_UNIT_LINKS))
        directories = {path.removeprefix("/") for path in
                       prepare.REMOVED_GENERATED_UNIT_DIRECTORIES}
        self.assertEqual(expected, audit_rootfs.REMOVED_GENERATED_UNIT_PATHS)
        for index, relative in enumerate(expected):
            with self.subTest(relative=relative):
                root = self.synthetic_guest_root(f"-generated-unit-{index}")
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative in directories:
                    path.mkdir()
                else:
                    path.symlink_to("/usr/lib/systemd/system/rogue.socket")
                with self.assertRaisesRegex(ValueError, "generated startup path remains: " + relative):
                    audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_admin_and_boot_companions(self):
        self.assertEqual(set(audit_rootfs.MASKED_UNITS), set(prepare.MASKS))
        root = self.synthetic_guest_root()
        audit_rootfs.audit(root)
        group = root / "etc/group"
        good_group = group.read_text()
        group.write_text(good_group.replace("zrpc-node,zrpc-wrapper", "zrpc-node,zrpc-wrapper,attacker"))
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        group.write_text(good_group)
        passwd = root / "etc/passwd"
        good_passwd = passwd.read_text()
        passwd.write_text(good_passwd + "alias:x:102:103::/nonexistent:/usr/sbin/nologin\n")
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        passwd.write_text(good_passwd)
        sysusers_mask = root / "etc/systemd/system/systemd-sysusers.service"
        sysusers_mask.unlink()
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        sysusers_mask.symlink_to("/dev/null")
        update_mask = root / "etc/systemd/system/systemd-sysupdate.timer"
        update_mask.unlink()
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        update_mask.symlink_to("/dev/null")
        for unit in ("systemd-sysext.socket", "systemd-sysext@.service",
                     "systemd-udev-load-credentials.service",
                     "systemd-network-generator.service"):
            mask = root / "etc/systemd/system" / unit
            mask.unlink()
            with self.assertRaisesRegex(ValueError, "administrative unit unmasked"):
                audit_rootfs.audit(root)
            mask.symlink_to("/usr/lib/systemd/system/" + unit)
            with self.assertRaisesRegex(ValueError, "administrative unit unmasked"):
                audit_rootfs.audit(root)
            mask.unlink()
            mask.symlink_to("/dev/null")
        (root / "boot").mkdir()
        companion = root / "boot/unapproved.addon.efi"
        companion.write_bytes(b"SYNTHETIC")
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        companion.unlink()
        (root / "etc/systemd/system/ssh.service").unlink()
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_resolved_credential_override_drift(self):
        dropin = "etc/systemd/system/systemd-resolved.service.d/10-no-credentials.conf"
        root = self.synthetic_guest_root("-resolved-missing")
        (root / dropin).unlink()
        with self.assertRaisesRegex(ValueError, "resolved credential override differs"):
            audit_rootfs.audit(root)

        root = self.synthetic_guest_root("-resolved-substituted")
        (root / dropin).write_text("[Service]\nImportCredential=network.dns\n")
        with self.assertRaisesRegex(ValueError, "resolved credential override differs"):
            audit_rootfs.audit(root)

        for index, relative in enumerate((
            "etc/systemd/system/systemd-resolved.service.d/99-restore.conf",
            "run/systemd/system.control/systemd-resolved.service.d/99-restore.conf",
            "run/systemd/system/dbus-org.freedesktop.resolve1.service.d/99-restore.conf",
            "usr/local/lib/systemd/system/systemd-resolved.service",
        )):
            with self.subTest(relative=relative):
                root = self.synthetic_guest_root(f"-resolved-override-{index}")
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("[Service]\nImportCredential=network.dns\n")
                with self.assertRaisesRegex(
                    ValueError, "postinst-generated path remains|resolved credential override differs|"
                                "appliance unit override or dependency|appliance unit replaced"
                ):
                    audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_missing_or_privileged_network_accounts(self):
        cases = (
            ("etc/passwd", "systemd-network:x:998:998::/:/usr/sbin/nologin\n", ""),
            ("etc/shadow", "systemd-resolve:!:0:0:0:0:0:0:\n", ""),
            ("etc/shadow", "systemd-network:!:", "systemd-network:$6$unlocked:"),
            ("etc/passwd", "systemd-resolve:x:997:997:", "systemd-resolve:x:0:997:"),
            ("etc/passwd", "systemd-network:x:998:998:", "systemd-network:x:998:0:"),
            ("etc/group", "systemd-resolve:x:997:\n", ""),
            ("etc/group", "systemd-network:x:998:\n", "systemd-network:x:101:\n"),
        )
        for index, (relative, old, new) in enumerate(cases):
            with self.subTest(relative=relative, old=old, new=new):
                root = self.synthetic_guest_root(f"-network-account-{index}")
                audit_rootfs.audit(root)
                path = root / relative
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaises(ValueError):
                    audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_unlocked_or_unmatched_extra_accounts(self):
        cases = (
            ("extra:x:500:500::/nonexistent:/usr/sbin/nologin\n", ""),
            ("root-alias:x:0:500::/nonexistent:/usr/sbin/nologin\n",
             "root-alias:!:0:0:0:0:0:0:\n"),
            ("root-group-alias:x:500:0::/nonexistent:/usr/sbin/nologin\n",
             "root-group-alias:!:0:0:0:0:0:0:\n"),
            ("extra:x:500:500::/nonexistent:/usr/sbin/nologin\n",
             "extra:$6$unlocked:0:0:0:0:0:0:\n"),
            ("extra:x:500:500::/nonexistent:/usr/sbin/nologin\n",
             "extra:!:0:0:0:0:0:0:\norphan:!:0:0:0:0:0:0:\n"),
        )
        for index, (passwd_line, shadow_lines) in enumerate(cases):
            with self.subTest(index=index):
                root = self.synthetic_guest_root(f"-extra-account-{index}")
                audit_rootfs.audit(root)
                with (root / "etc/passwd").open("a") as passwd:
                    passwd.write(passwd_line)
                with (root / "etc/shadow").open("a") as shadow:
                    shadow.write(shadow_lines)
                with self.assertRaises(ValueError):
                    audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-extra-group-zero")
        with (root / "etc/group").open("a") as groups:
            groups.write("root-group-alias:x:0:\n")
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-root-group-member")
        groups = root / "etc/group"
        groups.write_text(groups.read_text().replace("root:x:0:\n",
                                                    "root:x:0:zrpc-wrapper\n"))
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)
        root = self.synthetic_guest_root("-unreviewed-service-group")
        with (root / "etc/group").open("a") as groups:
            groups.write("disk:x:6:zrpc-wrapper\n")
        with self.assertRaises(ValueError):
            audit_rootfs.audit(root)

    def test_rootfs_audit_rejects_global_efi_boot_inputs(self):
        root = self.synthetic_guest_root()
        audit_rootfs.audit(root)
        efi = root / "efi"
        efi.mkdir()
        audit_rootfs.audit(root)
        for relative in (
            "loader/addons/unreviewed.addon.efi",
            "loader/credentials/unreviewed.cred",
            "loader/loader.conf",
        ):
            path = efi / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"SYNTHETIC")
            with self.assertRaisesRegex(ValueError, "unapproved EFI boot input"):
                audit_rootfs.audit(root)
            path.unlink()
        (efi / "loader/credentials").rmdir()
        (efi / "loader/addons").rmdir()
        (efi / "loader").rmdir()
        audit_rootfs.audit(root)
        efi.rmdir()
        efi.symlink_to("/unreviewed-esp")
        with self.assertRaisesRegex(ValueError, "unapproved EFI boot input"):
            audit_rootfs.audit(root)

if __name__ == "__main__":
    unittest.main()
