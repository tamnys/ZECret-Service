"""Synthetic initrd surface checks; no generated cpio or boot is exercised."""

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "audit_initrd", Path(__file__).with_name("audit-initrd.py")
)
audit_initrd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_initrd)


class InitrdAuditTests(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[2] / ".codex-tmp"
        cache.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gcp-initrd-audit-", dir=cache)
        self.root = Path(self.temporary.name) / "initrd"
        self.root.mkdir()
        for relative in ("proc", "etc/systemd/system", "usr/lib/systemd/system",
                         "usr/lib/systemd/system-generators", "usr/bin", "usr/sbin"):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        self.init_bytes = b"synthetic Rust PID1 artifact"
        (self.root / "init").write_bytes(self.init_bytes)
        (self.root / "init").chmod(0o555)
        self.init_sha256 = hashlib.sha256(self.init_bytes).hexdigest()
        self.mount = self.root / "usr/bin/mount"
        self.mount_bytes = b"synthetic signed Debian mount ELF"
        self.mount.write_bytes(self.mount_bytes)
        self.mount.chmod(0o555)
        self.mount_sha256 = hashlib.sha256(self.mount_bytes).hexdigest()
        self.mount_owner_override = 0
        self.mount_mode_override = None
        (self.root / "etc/initrd-release").symlink_to("/etc/os-release")
        (self.root / "etc/os-release").symlink_to("../usr/lib/os-release")
        (self.root / "usr/lib/os-release").write_text("ID=debian\n")
        (self.root / "usr/lib/systemd/systemd-udevd").symlink_to("../../bin/udevadm")
        for relative in audit_initrd.REQUIRED_EXECUTABLES:
            path = self.root / relative
            path.write_bytes(b"synthetic executable")
            path.chmod(0o755)
        for relative in audit_initrd.REQUIRED_UNITS:
            (self.root / relative).write_text("[Unit]\nDescription=Synthetic\n")

    def tearDown(self):
        self.temporary.cleanup()

    def audit(self):
        # The managed container creates workspace files as a non-root uid. Model
        # mkosi's root-owned initrd entry without changing the production
        # audit's fixed uid-0 policy.
        original_fstat = audit_initrd.os.fstat

        def synthetic_mount_metadata(descriptor):
            metadata = original_fstat(descriptor)
            if self.mount.exists():
                mount_metadata = self.mount.stat()
                if (metadata.st_dev, metadata.st_ino) == (mount_metadata.st_dev, mount_metadata.st_ino):
                    return SimpleNamespace(
                        st_mode=(metadata.st_mode if self.mount_mode_override is None
                                 else self.mount_mode_override),
                        st_uid=self.mount_owner_override,
                    )
            return metadata

        with mock.patch.object(audit_initrd.os, "fstat", synthetic_mount_metadata):
            audit_initrd.audit(self.root, self.init_sha256, self.mount_sha256)

    def test_synthetic_minimum_passes(self):
        self.audit()

    def test_retained_mount_identity_and_metadata_fail_closed(self):
        self.mount.unlink()
        with self.assertRaisesRegex(ValueError, "required file missing or redirected: usr/bin/mount"):
            self.audit()
        self.mount.symlink_to("../lib/os-release")
        with self.assertRaisesRegex(ValueError, "required file missing or redirected: usr/bin/mount"):
            self.audit()
        self.mount.unlink()
        os.mkfifo(self.mount)
        with self.assertRaisesRegex(ValueError, "required file missing or redirected: usr/bin/mount"):
            self.audit()
        self.mount.unlink()
        self.mount.write_bytes(self.mount_bytes)
        self.mount.chmod(0o555)

        self.mount.chmod(0o755)
        self.mount.write_bytes(b"substituted mount")
        self.mount.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "mount differs from pinned package artifact"):
            self.audit()
        self.mount.chmod(0o755)
        self.mount.write_bytes(self.mount_bytes)
        self.mount.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "mount ownership or permissions differ"):
            self.audit()
        self.mount.chmod(0o555)

        self.mount_owner_override = 501
        with self.assertRaisesRegex(ValueError, "mount ownership or permissions differ"):
            self.audit()
        self.mount_owner_override = 0
        self.mount_mode_override = stat.S_IFREG | 0o4555
        with self.assertRaisesRegex(ValueError, "mount ownership or permissions differ"):
            self.audit()
        self.mount_mode_override = None
        self.audit()

    def test_generated_getty_default_instance_alias_rejected(self):
        alias = self.root / "etc/systemd/system/getty.target.wants/getty@tty1.service"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("/usr/lib/systemd/system/getty@.service")
        with self.assertRaisesRegex(ValueError, "administrative unit remains"):
            self.audit()

    def test_pstore_service_and_generated_startup_alias_rejected(self):
        service = self.root / "usr/lib/systemd/system/systemd-pstore.service"
        service.write_text("[Service]\nExecStart=/usr/lib/systemd/systemd-pstore\n")
        with self.assertRaisesRegex(ValueError, "diagnostic unit remains: usr/lib/systemd/system/systemd-pstore.service"):
            self.audit()
        service.unlink()

        wants = self.root / "etc/systemd/system/sysinit.target.wants/systemd-pstore.service"
        wants.parent.mkdir(parents=True)
        wants.symlink_to("/usr/lib/systemd/system/systemd-pstore.service")
        with self.assertRaisesRegex(ValueError, "diagnostic unit remains: etc/systemd/system/sysinit.target.wants/systemd-pstore.service"):
            self.audit()
        wants.unlink()

        alias = wants.with_name("unreviewed.service")
        alias.symlink_to("/usr/lib/systemd/system/systemd-pstore.service")
        with self.assertRaisesRegex(ValueError, "diagnostic unit remains: etc/systemd/system/sysinit.target.wants/unreviewed.service"):
            self.audit()
        alias.unlink()
        self.audit()

    def test_network_generator_and_generated_startup_alias_rejected(self):
        service = self.root / "usr/lib/systemd/system/systemd-network-generator.service"
        service.write_text("[Service]\nImportCredential=network.network.*\n")
        with self.assertRaisesRegex(ValueError, "mutable configuration unit remains: usr/lib/systemd/system/systemd-network-generator.service"):
            self.audit()
        service.unlink()

        wants = self.root / "etc/systemd/system/sysinit.target.wants/systemd-network-generator.service"
        wants.parent.mkdir(parents=True)
        wants.symlink_to("/usr/lib/systemd/system/systemd-network-generator.service")
        with self.assertRaisesRegex(ValueError, "mutable configuration unit remains: etc/systemd/system/sysinit.target.wants/systemd-network-generator.service"):
            self.audit()
        wants.unlink()

        alias = wants.with_name("unreviewed.service")
        alias.symlink_to("/usr/lib/systemd/system/systemd-network-generator.service")
        with self.assertRaisesRegex(ValueError, "mutable configuration unit remains: etc/systemd/system/sysinit.target.wants/unreviewed.service"):
            self.audit()
        alias.unlink()
        self.audit()

    def test_extension_and_credential_startup_units_rejected(self):
        for relative in (
            "usr/lib/systemd/system/systemd-sysext.service",
            "usr/lib/systemd/system/systemd-sysext.socket",
            "usr/lib/systemd/system/systemd-sysext@.service",
            "usr/lib/systemd/system/sockets.target.wants/systemd-sysext.socket",
            "usr/lib/systemd/system/systemd-confext.service",
            "usr/lib/systemd/system/systemd-udev-load-credentials.service",
            "etc/systemd/system/sysinit.target.wants/systemd-sysext.service",
            "etc/systemd/system/sockets.target.wants/systemd-sysext.socket",
            "etc/systemd/system/sysinit.target.wants/systemd-confext.service",
            "etc/systemd/system/sysinit.target.wants/systemd-udev-load-credentials.service",
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to("/usr/lib/systemd/system/systemd-sysext.service")
                with self.assertRaisesRegex(ValueError, "administrative unit remains"):
                    self.audit()
                path.unlink()
        alias = self.root / "etc/systemd/system/sysinit.target.wants/unreviewed.service"
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to("/usr/lib/systemd/system/systemd-confext.service")
        with self.assertRaisesRegex(ValueError, "administrative unit remains"):
            self.audit()

    def test_signed_systemd_ssh_config_alias_rejected(self):
        alias = self.root / "etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf")
        with self.assertRaisesRegex(ValueError, "unexpected content remains: etc/ssh"):
            self.audit()

    def test_signed_systemd_ssh_tmpfiles_rule_rejected(self):
        rule = self.root / "usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf"
        rule.parent.mkdir(parents=True)
        rule.write_text("L$ /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf - - - - "
                        "/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf\n")
        with self.assertRaisesRegex(ValueError, "forbidden file remains: usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf"):
            self.audit()

    def test_generated_journal_and_mail_directories_rejected_even_when_empty(self):
        for relative, mode in (("var/log/journal", 0o2755),
                               ("var/mail", 0o2775)):
            with self.subTest(relative=relative):
                directory = self.root / relative
                directory.mkdir(parents=True)
                directory.chmod(mode)
                with self.assertRaisesRegex(ValueError, f"forbidden directory remains: {relative}"):
                    self.audit()
                directory.rmdir()
                self.audit()

    def test_unneeded_package_executables_removed_from_initrd(self):
        for relative in ("usr/bin/perl", "usr/bin/perl5.40.1",
                         "usr/bin/umount", "usr/sbin/losetup",
                         "usr/sbin/swapon", "usr/sbin/swapoff"):
            with self.subTest(relative=relative):
                executable = self.root / relative
                executable.write_bytes(b"synthetic Perl executable")
                executable.chmod(0o755)
                with self.assertRaisesRegex(ValueError, f"administrative executable remains: {relative}"):
                    self.audit()
                executable.unlink()
                self.audit()

    def test_mkosi_boot_loader_placeholder_rejected(self):
        marker = self.root / "boot/loader/entries.srel"
        marker.parent.mkdir(parents=True)
        marker.write_text("type1\n")
        with self.assertRaisesRegex(ValueError, "unexpected content remains: boot"):
            self.audit()

    def test_required_boot_components_and_ownership_fail_closed(self):
        for relative in audit_initrd.REQUIRED_EXECUTABLES:
            with self.subTest(relative=relative):
                path = self.root / relative
                path.unlink()
                with self.assertRaisesRegex(ValueError, "required file missing"):
                    self.audit()
                path.write_bytes(b"synthetic executable")
                path.chmod(0o755)
        path = self.root / "usr/lib/systemd/systemd-veritysetup"
        path.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "permissions differ"):
            self.audit()

    def test_initrd_identity_symlinks_and_root_redirection_fail_closed(self):
        init = self.root / "init"
        init.unlink()
        init.symlink_to("/usr/lib/systemd/systemd")
        with self.assertRaisesRegex(ValueError, "required file missing or redirected"):
            self.audit()
        init.unlink()
        init.write_bytes(self.init_bytes)
        init.chmod(0o555)
        release = self.root / "etc/os-release"
        release.unlink()
        release.symlink_to("/etc/os-release")
        with self.assertRaisesRegex(ValueError, "initrd entry missing or redirected"):
            self.audit()
        release.unlink()
        release.symlink_to("../usr/lib/os-release")
        udevd = self.root / "usr/lib/systemd/systemd-udevd"
        udevd.unlink()
        udevd.symlink_to("/usr/bin/other")
        with self.assertRaisesRegex(ValueError, "initrd entry missing or redirected"):
            self.audit()
        udevd.unlink()
        udevd.symlink_to("../../bin/udevadm")
        user_bin = self.root / "usr/bin"
        user_bin.rename(self.root / "usr/actual-bin")
        user_bin.symlink_to("actual-bin")
        with self.assertRaisesRegex(ValueError, "directory missing or redirected"):
            self.audit()

    def test_rescue_shell_alias_and_privileged_file_fail_closed(self):
        for relative in ("usr/lib/systemd/system/rescue.target",
                         "usr/lib/systemd/system/multi-user.target.wants/getty.target",
                         "usr/lib/systemd/system/runlevel1.target", "usr/bin/sh"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to("../rescue.target")
                with self.assertRaises(ValueError):
                    self.audit()
                path.unlink()
        path = self.root / "usr/lib/systemd/system/innocent.target"
        path.symlink_to("rescue.target")
        with self.assertRaisesRegex(ValueError, "administrative unit"):
            self.audit()
        path.unlink()
        path = self.root / "usr/bin/unreviewed"
        path.write_bytes(b"synthetic")
        # The managed workspace mount strips setuid bits, so synthesize just
        # that metadata while exercising the full tree walk.
        original_lstat = Path.lstat

        def lstat_with_setuid(candidate):
            info = original_lstat(candidate)
            if candidate == path:
                return SimpleNamespace(st_mode=info.st_mode | stat.S_ISUID)
            return info

        with mock.patch.object(Path, "lstat", lstat_with_setuid):
            with self.assertRaisesRegex(ValueError, "privileged file"):
                self.audit()

    def test_signed_package_privileged_executables_fail_closed(self):
        # These exact paths and bits occur in the signed Debian initrd inputs.
        for relative, privilege_bit, expected in (
            ("usr/sbin/unix_chkpwd", stat.S_ISGID, "privileged file remains"),
            ("usr/bin/umount", stat.S_ISUID, "administrative executable remains"),
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.write_bytes(b"synthetic package executable")
                original_lstat = Path.lstat

                def lstat_with_privilege(candidate):
                    info = original_lstat(candidate)
                    if candidate == path:
                        return SimpleNamespace(st_mode=info.st_mode | privilege_bit)
                    return info

                with mock.patch.object(Path, "lstat", lstat_with_privilege):
                    with self.assertRaisesRegex(ValueError, f"{expected}: {relative}"):
                        self.audit()
                path.unlink()

    def test_early_boot_payloads_and_credentials_fail_closed(self):
        for relative in ("usr/lib/modules/kernel/drivers/md/dm-verity.ko.xz",
                         "boot/vmlinuz-unreviewed",
                         "usr/lib/zrpc/zebrad", "etc/credstore/key.cred"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic")
                with self.assertRaises(ValueError):
                    self.audit()
                path.unlink()
                parent = path.parent
                while parent != self.root and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent
        credentials = self.root / "usr/lib/credstore"
        credentials.symlink_to("/tmp/other")
        with self.assertRaisesRegex(ValueError, "credential store"):
            self.audit()

    def test_early_init_identity_and_base_companions_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "artifact identity absent"):
            audit_initrd.audit(self.root)
        with self.assertRaisesRegex(ValueError, "mount artifact identity absent"):
            audit_initrd.audit(self.root, self.init_sha256)
        init = self.root / "init"
        init.chmod(0o755)
        init.write_bytes(b"changed PID1")
        init.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "differs from pinned artifact"):
            self.audit()
        init.chmod(0o755)
        init.write_bytes(self.init_bytes)
        init.chmod(0o555)
        extra = self.root / ".extra"
        extra.mkdir()
        with self.assertRaisesRegex(ValueError, "stub companion tree"):
            self.audit()


if __name__ == "__main__":
    unittest.main()
