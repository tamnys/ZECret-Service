"""Synthetic raw ext4 policy negatives; no fixture is a boot or release."""

import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import inspect_raw_forbidden as forbidden


HERE = Path(__file__).resolve().parent
POLICY_SPEC = importlib.util.spec_from_file_location("audit_rootfs_policy", HERE / "audit-rootfs.py")
POLICY = importlib.util.module_from_spec(POLICY_SPEC)
POLICY_SPEC.loader.exec_module(POLICY)


def entry(inode, kind="directory", mode=0o755, uid=0, gid=0, size=None, **extra):
    return {"inode": inode, "type": kind, "mode": mode, "uid": uid,
            "gid": gid, "size": size, **extra}


def listing(*rows):
    return ("\n".join(rows) + "\n\n").encode()


class RawForbiddenTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-forbidden-")
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.image = self.scratch / "root.img"
        self.image.write_bytes(b"synthetic copied ext4")
        self.reader = Path("/synthetic/signed-debugfs")

    def fake_run(self, outputs):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv[2])
            stdout, stderr = outputs[argv[2]]
            kwargs["stdout"].write(stdout)
            kwargs["stderr"].write(stderr)
            return types.SimpleNamespace(returncode=0)

        return calls, run

    def test_policy_constants_match_source_audit(self):
        for name in ("FORBIDDEN_BINARIES", "FORBIDDEN_NVME_SURFACE",
                     "APPLIANCE_UNITS", "MASKED_UNITS", "PROTECTED_UNITS",
                     "UNIT_DIRS"):
            self.assertEqual(getattr(forbidden, name), getattr(POLICY, name))

    def test_exact_inode_listing_and_bounded_output(self):
        output = listing(
            "/2/040755/0/0/.//", "/2/040755/0/0/..//",
            "/13/040755/502/20/etc//", "/15/120755/502/20/mask/9/",
            "/16/100644/502/20/zebra.toml/7/",
        )
        calls, run = self.fake_run({"ls -p <2>": (output, forbidden.READER_BANNER)})
        limits = []
        def checked_run(*args, **kwargs):
            with mock.patch.object(forbidden.resource, "setrlimit",
                                   side_effect=lambda *_args: limits.append(_args)):
                kwargs["preexec_fn"]()
            return run(*args, **kwargs)
        with mock.patch.object(forbidden.subprocess, "run", side_effect=checked_run):
            observed = forbidden.list_directory(self.reader, self.image, 2, 2,
                                                self.scratch, self.image.stat().st_size)
        self.assertEqual(calls, ["ls -p <2>"])
        self.assertEqual(observed["etc"], entry(13, uid=502, gid=20))
        self.assertEqual(observed["mask"], entry(15, "symlink", 0o755,
                                                 uid=502, gid=20, size=9))
        self.assertEqual(observed["zebra.toml"], entry(16, "file", 0o644,
                                                       uid=502, gid=20, size=7))
        bound = self.image.stat().st_size * 8 + 1
        self.assertEqual(limits, [(forbidden.resource.RLIMIT_FSIZE, (bound, bound))])

    def test_deleted_ext4_slots_are_ignored_only_with_zero_metadata(self):
        dots = ["/2/040755/0/0/.//", "/2/040755/0/0/..//"]
        live = "/13/100644/0/0/config/1/"
        for empty in ("/0/000000/0/0//0/", "/0/000000/0/0/old-name/0/"):
            with self.subTest(empty=empty), mock.patch.object(
                    forbidden.subprocess, "run", side_effect=self.fake_run({
                        "ls -p <2>": (listing(*dots, empty, live),
                                      forbidden.READER_BANNER),
                    })[1]):
                observed = forbidden.list_directory(
                    self.reader, self.image, 2, 2,
                    self.scratch, self.image.stat().st_size)
                self.assertEqual(set(observed), {".", "..", "config"})
        for malformed in ("/0/000755/0/0//0/", "/0/000000/1/0//0/",
                          "/0/000000/0/0//1/", "/0/000000/0/0/bad\rname/0/"):
            with self.subTest(malformed=malformed), mock.patch.object(
                    forbidden.subprocess, "run", side_effect=self.fake_run({
                        "ls -p <2>": (listing(*dots, malformed),
                                      forbidden.READER_BANNER),
                    })[1]):
                with self.assertRaisesRegex(ValueError, "listing is malformed"):
                    forbidden.list_directory(self.reader, self.image, 2, 2,
                                             self.scratch, self.image.stat().st_size)

    def test_listing_rejects_malformed_duplicate_control_and_extra_output(self):
        base = ["/2/040755/0/0/.//", "/2/040755/0/0/..//"]
        bad = (
            listing(*base, "/12/100644/0/0/file/1/", "/13/100644/0/0/file/1/"),
            listing(*base, "/12/100644/0/0/bad\rname/1/"),
            listing(*base, "/12/100644/0/0/bad/name/1/"),
            listing(*base, "/12/108644/0/0/file/1/"),
            listing(*base).removesuffix(b"\n") + b"extra\n",
            ("\n".join(base) + "\n").encode(),
            listing(base[0], "/99/040755/0/0/..//"),
        )
        for output in bad:
            with self.subTest(output=output), \
                    mock.patch.object(forbidden.subprocess, "run",
                                      side_effect=self.fake_run({
                                          "ls -p <2>": (output, forbidden.READER_BANNER),
                                      })[1]):
                with self.assertRaises(ValueError):
                    forbidden.list_directory(self.reader, self.image, 2, 2,
                                             self.scratch, self.image.stat().st_size)
        for stderr in (forbidden.READER_BANNER + b"warning\n", b""):
            with mock.patch.object(forbidden.subprocess, "run",
                                   side_effect=self.fake_run({
                                       "ls -p <2>": (listing(*base), stderr),
                                   })[1]):
                with self.assertRaisesRegex(ValueError, "unexpected diagnostics"):
                    forbidden.list_directory(self.reader, self.image, 2, 2,
                                             self.scratch, self.image.stat().st_size)

    def test_walk_returns_inventory_without_following_symlink(self):
        outputs = {
            "ls -p <2>": (listing("/2/040755/0/0/.//", "/2/040755/0/0/..//",
                                  "/13/040755/0/0/etc//"), forbidden.READER_BANNER),
            "ls -p <13>": (listing("/13/040755/0/0/.//", "/2/040755/0/0/..//",
                                   "/15/120755/0/0/shortcut/9/"), forbidden.READER_BANNER),
            "ea_list <2>": (b"", forbidden.READER_BANNER),
            "ea_list <13>": (b"", forbidden.READER_BANNER),
            "ea_list <15>": (b"", forbidden.READER_BANNER),
        }
        calls, run = self.fake_run(outputs)
        with mock.patch.object(forbidden.subprocess, "run", side_effect=run), \
                mock.patch.object(forbidden, "_check_surfaces"):
            observed = forbidden.inspect(self.reader, self.image, self.scratch)
        self.assertEqual(calls, ["ls -p <2>", "ls -p <13>",
                                 "ea_list <2>", "ea_list <13>", "ea_list <15>"])
        self.assertEqual(observed[""], entry(2))
        self.assertEqual(observed["etc"], entry(13))
        self.assertEqual(observed["etc/shortcut"], entry(15, "symlink", size=9))

    def test_raw_inode_xattr_rejected_by_signed_reader(self):
        output = listing("/2/040755/0/0/.//", "/2/040755/0/0/..//",
                         "/13/100644/0/0/config/1/")
        attributes = b'Extended attributes:\n  user.zrpc_probe (6) = "marker"\n'
        calls, run = self.fake_run({
            "ls -p <2>": (output, forbidden.READER_BANNER),
            "ea_list <2>": (b"", forbidden.READER_BANNER),
            "ea_list <13>": (attributes, forbidden.READER_BANNER),
        })
        with mock.patch.object(forbidden.subprocess, "run", side_effect=run), \
                mock.patch.object(forbidden, "_check_surfaces"):
            with self.assertRaisesRegex(ValueError, "unreviewed extended attributes"):
                forbidden.inspect(self.reader, self.image, self.scratch)
        self.assertEqual(calls, ["ls -p <2>", "ea_list <2>", "ea_list <13>"])

    def test_duplicate_directory_inode_and_conflicting_dot_fail(self):
        root = listing("/2/040755/0/0/.//", "/2/040755/0/0/..//",
                       "/13/040755/0/0/etc//", "/13/040755/0/0/usr//")
        child = listing("/13/040755/0/0/.//", "/2/040755/0/0/..//")
        calls, run = self.fake_run({
            "ls -p <2>": (root, forbidden.READER_BANNER),
            "ls -p <13>": (child, forbidden.READER_BANNER),
        })
        with mock.patch.object(forbidden.subprocess, "run", side_effect=run), \
                mock.patch.object(forbidden, "_check_surfaces"):
            with self.assertRaisesRegex(ValueError, "linked more than once"):
                forbidden.inspect(self.reader, self.image, self.scratch)
        self.assertEqual(calls.count("ls -p <13>"), 1)
        wrong_dot = listing("/13/040700/0/0/.//", "/2/040755/0/0/..//")
        calls, run = self.fake_run({
            "ls -p <2>": (listing("/2/040755/0/0/.//", "/2/040755/0/0/..//",
                                   "/13/040755/0/0/etc//"), forbidden.READER_BANNER),
            "ls -p <13>": (wrong_dot, forbidden.READER_BANNER),
        })
        with mock.patch.object(forbidden.subprocess, "run", side_effect=run), \
                mock.patch.object(forbidden, "_check_surfaces"):
            with self.assertRaisesRegex(ValueError, "metadata differs"):
                forbidden.inspect(self.reader, self.image, self.scratch)

    def test_unit_symlink_target_is_read_by_inode_and_exact_banner(self):
        target = b"/usr/lib/systemd/system/zrpc.target"
        symlink = entry(15, "symlink", 0o777, size=len(target))
        content = (b"Inode: 15   Type: symlink    Mode:  0777   Flags: 0x0\n"
                   + b"User: 0   Group: 0   Project: 0   Size: "
                   + str(len(target)).encode() + b"\nFast link dest: \""
                   + target + b"\"\n")
        calls, run = self.fake_run({
            "stat <15>": (content, forbidden.READER_BANNER),
        })
        with mock.patch.object(forbidden.subprocess, "run", side_effect=run):
            self.assertEqual(forbidden._unit_target(
                self.reader, self.image, symlink, self.scratch,
                self.image.stat().st_size, env=forbidden.ENV, pass_fds=()),
                target.decode())
        self.assertEqual(calls, ["stat <15>"])
        for output in (content + b'Fast link dest: "extra"\n', b"Inode: 15\n"):
            with mock.patch.object(forbidden.subprocess, "run", side_effect=self.fake_run({
                    "stat <15>": (output, forbidden.READER_BANNER),
                })[1]):
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    forbidden._unit_target(self.reader, self.image, symlink,
                                           self.scratch, self.image.stat().st_size,
                                           env=forbidden.ENV, pass_fds=())

    def baseline_inventory(self):
        data = {"": entry(2), "efi": entry(10),
                "usr": entry(11), "usr/bin": entry(12),
                "usr/bin/mount": entry(13, "file", 0o555, size=10),
                "usr/lib": entry(14), "usr/lib/systemd": entry(15),
                forbidden.VENDOR_UNITS: entry(16),
                "etc": entry(17), "etc/systemd": entry(18),
                "etc/udev": entry(83), "etc/udev/rules.d": entry(84),
                forbidden.CONFIGURED_UNITS: entry(19),
                forbidden.CONFIGURED_UNITS + "/systemd-resolved.service.d": entry(20),
                forbidden.CONFIGURED_UNITS + "/systemd-resolved.service.d/10-no-credentials.conf":
                    entry(21, "file", 0o644, size=27),
                forbidden.CONFIGURED_UNITS + "/multi-user.target.wants": entry(22),
                forbidden.CONFIGURED_UNITS + "/default.target":
                    entry(23, "symlink", 0o777, size=38,
                          target="/usr/lib/systemd/system/zrpc.target"),
                forbidden.CONFIGURED_UNITS + "/multi-user.target.wants/systemd-networkd.service":
                    entry(24, "symlink", 0o777, size=51,
                          target="/usr/lib/systemd/system/systemd-networkd.service"),
                forbidden.CONFIGURED_UNITS + "/multi-user.target.wants/systemd-resolved.service":
                    entry(25, "symlink", 0o777, size=50,
                          target="/usr/lib/systemd/system/systemd-resolved.service"),
                }
        for index, unit in enumerate(forbidden.APPLIANCE_UNITS, 30):
            data[forbidden.VENDOR_UNITS + "/" + unit] = entry(index, "file", 0o644, size=1)
        for index, unit in enumerate(forbidden.MASKED_UNITS, 100):
            data[forbidden.CONFIGURED_UNITS + "/" + unit] = entry(
                index, "symlink", 0o777, size=9, target="/dev/null")
        for index, name in enumerate(forbidden.RETAINED_WANTS, 200):
            data.setdefault(forbidden.CONFIGURED_UNITS + "/" + name, entry(index))
        for index, (path, target) in enumerate(forbidden.RETAINED_UNIT_LINKS.items(), 210):
            data.setdefault(path, entry(index, "symlink", 0o777,
                                        size=len(target), target=target))
        return data

    def test_retained_unit_links_require_exact_targets_and_complete_wants(self):
        baseline = self.baseline_inventory()
        forbidden._check_surfaces(baseline)
        for path in forbidden.RETAINED_UNIT_LINKS:
            with self.subTest(path=path, changed="target"):
                altered = {**baseline, path: {**baseline[path], "target": "/dev/null"}}
                with self.assertRaisesRegex(ValueError, "appliance unit symlink differs"):
                    forbidden._check_surfaces(altered)
            with self.subTest(path=path, changed="missing"):
                altered = dict(baseline)
                altered.pop(path)
                with self.assertRaisesRegex(ValueError, "appliance boot dependencies differ|appliance unit symlink differs"):
                    forbidden._check_surfaces(altered)
        for name in forbidden.RETAINED_WANTS:
            parent = forbidden.CONFIGURED_UNITS + "/" + name
            with self.subTest(path=parent, changed="extra"):
                altered = {**baseline, parent + "/unexpected.service":
                           entry(250, "symlink", 0o777, size=36,
                                 target="/usr/lib/systemd/system/rogue.service")}
                with self.assertRaisesRegex(ValueError, "appliance boot dependencies differ"):
                    forbidden._check_surfaces(altered)

    def test_nested_retained_link_target_is_read_by_inode(self):
        target = forbidden.RETAINED_UNIT_LINKS[
            forbidden.CONFIGURED_UNITS +
            "/network-online.target.wants/systemd-networkd-wait-online.service"]
        outputs = {
            "ls -p <2>": (listing("/2/040755/0/0/.//", "/2/040755/0/0/..//",
                                  "/13/040755/0/0/etc//"), forbidden.READER_BANNER),
            "ls -p <13>": (listing("/13/040755/0/0/.//", "/2/040755/0/0/..//",
                                   "/14/040755/0/0/systemd//"), forbidden.READER_BANNER),
            "ls -p <14>": (listing("/14/040755/0/0/.//", "/13/040755/0/0/..//",
                                   "/15/040755/0/0/system//"), forbidden.READER_BANNER),
            "ls -p <15>": (listing("/15/040755/0/0/.//", "/14/040755/0/0/..//",
                                   "/16/040755/0/0/network-online.target.wants//"),
                            forbidden.READER_BANNER),
            "ls -p <16>": (listing("/16/040755/0/0/.//", "/15/040755/0/0/..//",
                                   "/80/120777/0/0/systemd-networkd-wait-online.service/"
                                   + str(len(target)) + "/"), forbidden.READER_BANNER),
            "stat <80>": (b"Inode: 80   Type: symlink    Mode:  0777   Flags: 0x0\n"
                          + b"User: 0   Group: 0   Project: 0   Size: "
                          + str(len(target)).encode() + b"\nFast link dest: \""
                          + target.encode() + b"\"\n", forbidden.READER_BANNER),
        }
        calls, run = self.fake_run(outputs)
        with mock.patch.object(forbidden.subprocess, "run", side_effect=run), \
                mock.patch.object(forbidden, "_check_surfaces"), \
                mock.patch.object(forbidden, "reject_xattrs"):
            inventory = forbidden.inspect(self.reader, self.image, self.scratch)
        path = (forbidden.CONFIGURED_UNITS +
                "/network-online.target.wants/systemd-networkd-wait-online.service")
        self.assertEqual(inventory[path]["target"], target)
        self.assertIn("stat <80>", calls)

    def test_raw_policy_rejects_administrative_boot_credentials_and_setuid(self):
        data = self.baseline_inventory()
        forbidden._check_surfaces(data)
        cases = {
            "usr/bin/sudo": entry(70, "file", 0o755, size=1),
            "usr/lib/systemd/system/nvmf-autoconnect.service": entry(71, "file", size=1),
            "etc/kernel/cmdline": entry(72, "file", size=1),
            "etc/kernel": entry(86, "symlink", size=9),
            "efi/addon.efi": entry(73, "file", size=1),
            "etc/udev/rules.d/override.rules": entry(74, "file", size=1),
            "boot/anything.cred": entry(75, "file", size=1),
            "usr/lib/extensions/extra": entry(76, "file", size=1),
            "etc/credstore/secret": entry(77, "file", size=1),
            "etc/credstore": entry(85, "symlink", size=9),
            "usr/bin/hidden": entry(78, "file", 0o4755, size=1),
            "usr/lib/systemd/system/zrpc-node.service.d": entry(79),
        }
        for path, item in cases.items():
            with self.subTest(path=path), self.assertRaises(ValueError):
                forbidden._check_surfaces({**data, path: item})

    def test_unit_alias_and_redirected_load_path_fail(self):
        data = self.baseline_inventory()
        for path, item in (
            (forbidden.VENDOR_UNITS + "/other.service",
             entry(80, "symlink", size=17, target="zrpc-node.service")),
            ("etc/systemd/system.control", entry(81, "symlink", size=13)),
            (forbidden.CONFIGURED_UNITS + "/zrpc-node.service",
             entry(82, "file", size=1)),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                forbidden._check_surfaces({**data, path: item})
        unmasked = dict(data)
        unmasked.pop(forbidden.CONFIGURED_UNITS + "/ssh.service")
        with self.assertRaisesRegex(ValueError, "administrative unit unmasked"):
            forbidden._check_surfaces(unmasked)


if __name__ == "__main__":
    unittest.main()
