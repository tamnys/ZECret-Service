"""Synthetic initrd surface checks; no generated cpio or boot is exercised."""

import hashlib
import importlib.util
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

    def test_synthetic_minimum_passes(self):
        audit_initrd.audit(self.root, self.init_sha256)

    def test_generated_getty_default_instance_alias_rejected(self):
        alias = self.root / "etc/systemd/system/getty.target.wants/getty@tty1.service"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("/usr/lib/systemd/system/getty@.service")
        with self.assertRaisesRegex(ValueError, "administrative unit remains"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_signed_systemd_ssh_config_alias_rejected(self):
        alias = self.root / "etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf")
        with self.assertRaisesRegex(ValueError, "unexpected content remains: etc/ssh"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_signed_systemd_ssh_tmpfiles_rule_rejected(self):
        rule = self.root / "usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf"
        rule.parent.mkdir(parents=True)
        rule.write_text("L$ /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf - - - - "
                        "/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf\n")
        with self.assertRaisesRegex(ValueError, "forbidden file remains: usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_mkosi_boot_loader_placeholder_rejected(self):
        marker = self.root / "boot/loader/entries.srel"
        marker.parent.mkdir(parents=True)
        marker.write_text("type1\n")
        with self.assertRaisesRegex(ValueError, "unexpected content remains: boot"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_required_boot_components_and_ownership_fail_closed(self):
        for relative in audit_initrd.REQUIRED_EXECUTABLES:
            with self.subTest(relative=relative):
                path = self.root / relative
                path.unlink()
                with self.assertRaisesRegex(ValueError, "required file missing"):
                    audit_initrd.audit(self.root, self.init_sha256)
                path.write_bytes(b"synthetic executable")
                path.chmod(0o755)
        path = self.root / "usr/lib/systemd/systemd-veritysetup"
        path.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "permissions differ"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_initrd_identity_symlinks_and_root_redirection_fail_closed(self):
        init = self.root / "init"
        init.unlink()
        init.symlink_to("/usr/lib/systemd/systemd")
        with self.assertRaisesRegex(ValueError, "required file missing or redirected"):
            audit_initrd.audit(self.root, self.init_sha256)
        init.unlink()
        init.write_bytes(self.init_bytes)
        init.chmod(0o555)
        release = self.root / "etc/os-release"
        release.unlink()
        release.symlink_to("/etc/os-release")
        with self.assertRaisesRegex(ValueError, "initrd entry missing or redirected"):
            audit_initrd.audit(self.root, self.init_sha256)
        release.unlink()
        release.symlink_to("../usr/lib/os-release")
        udevd = self.root / "usr/lib/systemd/systemd-udevd"
        udevd.unlink()
        udevd.symlink_to("/usr/bin/other")
        with self.assertRaisesRegex(ValueError, "initrd entry missing or redirected"):
            audit_initrd.audit(self.root, self.init_sha256)
        udevd.unlink()
        udevd.symlink_to("../../bin/udevadm")
        user_bin = self.root / "usr/bin"
        user_bin.rename(self.root / "usr/actual-bin")
        user_bin.symlink_to("actual-bin")
        with self.assertRaisesRegex(ValueError, "directory missing or redirected"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_rescue_shell_alias_and_privileged_file_fail_closed(self):
        for relative in ("usr/lib/systemd/system/rescue.target",
                         "usr/lib/systemd/system/multi-user.target.wants/getty.target",
                         "usr/lib/systemd/system/runlevel1.target", "usr/bin/sh"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to("../rescue.target")
                with self.assertRaises(ValueError):
                    audit_initrd.audit(self.root, self.init_sha256)
                path.unlink()
        path = self.root / "usr/lib/systemd/system/innocent.target"
        path.symlink_to("rescue.target")
        with self.assertRaisesRegex(ValueError, "administrative unit"):
            audit_initrd.audit(self.root, self.init_sha256)
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
                audit_initrd.audit(self.root, self.init_sha256)

    def test_signed_package_privileged_executables_fail_closed(self):
        # These exact paths and bits occur in the signed Debian initrd inputs.
        for relative, privilege_bit in (
            ("usr/sbin/unix_chkpwd", stat.S_ISGID),
            ("usr/bin/mount", stat.S_ISUID),
            ("usr/bin/umount", stat.S_ISUID),
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
                    with self.assertRaisesRegex(ValueError, f"privileged file remains: {relative}"):
                        audit_initrd.audit(self.root, self.init_sha256)
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
                    audit_initrd.audit(self.root, self.init_sha256)
                path.unlink()
                parent = path.parent
                while parent != self.root and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent
        credentials = self.root / "usr/lib/credstore"
        credentials.symlink_to("/tmp/other")
        with self.assertRaisesRegex(ValueError, "credential store"):
            audit_initrd.audit(self.root, self.init_sha256)

    def test_early_init_identity_and_base_companions_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "artifact identity absent"):
            audit_initrd.audit(self.root)
        init = self.root / "init"
        init.chmod(0o755)
        init.write_bytes(b"changed PID1")
        init.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "differs from pinned artifact"):
            audit_initrd.audit(self.root, self.init_sha256)
        init.chmod(0o755)
        init.write_bytes(self.init_bytes)
        init.chmod(0o555)
        extra = self.root / ".extra"
        extra.mkdir()
        with self.assertRaisesRegex(ValueError, "stub companion tree"):
            audit_initrd.audit(self.root, self.init_sha256)


if __name__ == "__main__":
    unittest.main()
