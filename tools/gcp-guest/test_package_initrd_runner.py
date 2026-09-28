"""Focused fail-closed checks for the package-backed initrd runner."""

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "package_initrd_runner", HERE / "package_initrd_runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class PackageInitrdRunnerTest(unittest.TestCase):
    def source_bundle(self, root, members):
        revision = "a" * 40
        bundle = Path(root)
        (bundle / "guest-inputs").mkdir()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as contents:
            for name, data in members:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                contents.addfile(entry, io.BytesIO(data))
        (bundle / "source.tar").write_bytes(archive.getvalue())
        manifest = {"source_commit": revision, "source_tree": "b" * 40,
                    "source_archive_sha256": runner.sha256(archive.getvalue())}
        manifest_bytes = json.dumps(manifest).encode()
        (bundle / "manifest.json").write_bytes(manifest_bytes)
        report = {"status": "diagnostic-unsigned-x86_64-rust-inputs-unapproved",
                  "source_commit": revision, "source_tree": "b" * 40,
                  "reproduction_manifest_sha256": runner.sha256(manifest_bytes),
                  "image_built": False, "private_mode_approved": False}
        (bundle / "guest-inputs/diagnostic-rust-inputs.json").write_text(
            json.dumps(report))
        return revision

    def test_read_only_receipt_archive_rejects_mutation_and_unsupported_reads(self):
        with tempfile.TemporaryDirectory() as scratch:
            revision = self.source_bundle(scratch, [("tools/gcp-guest/prepare.py", b"reviewed")])
            selected = runner.ReceiptSourceArchive(Path(scratch), revision)
            self.assertEqual(selected.output(["show", f"{revision}:tools/gcp-guest/prepare.py"]),
                             b"reviewed")
            self.assertEqual(selected.output(["show", "-s", "--format=%T", revision]),
                             ("b" * 40 + "\n").encode())
            with self.assertRaisesRegex(ValueError, "unsupported"):
                selected.output(["fetch", "origin"])
            with self.assertRaisesRegex(ValueError, "unsafe"):
                selected.output(["show", f"{revision}:../prepare.py"])
            (Path(scratch) / "source.tar").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "differs from Rust receipt"):
                runner.ReceiptSourceArchive(Path(scratch), revision)

    def test_receipt_archive_rejects_duplicate_and_escaping_members(self):
        for members, reason in (
            ([("tools/gcp-guest/prepare.py", b"a"),
              ("tools/gcp-guest/prepare.py", b"b")], "duplicate member"),
            ([("../prepare.py", b"a")], "unsafe member"),
        ):
            with self.subTest(members=members), tempfile.TemporaryDirectory() as scratch:
                revision = self.source_bundle(scratch, members)
                with self.assertRaisesRegex(ValueError, reason):
                    runner.ReceiptSourceArchive(Path(scratch), revision)

    def test_changed_verifier_module_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as scratch:
            revision = self.source_bundle(scratch, [
                ("tools/gcp-guest/prepare_initrd_basetree_profile.py", b"changed"),
                (runner.SCRIPT, (HERE / "package_initrd_runner.py").read_bytes()),
            ])
            selected = runner.ReceiptSourceArchive(Path(scratch), revision)
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError(
                    "Git must not run inside the no-route builder")):
                with self.assertRaisesRegex(ValueError, "source binder differs"):
                    runner.source_module(revision, selected)

    def test_bound_verifier_uses_receipt_archive_without_git(self):
        spec = importlib.util.spec_from_file_location(
            "test_initrd_source_profile", HERE / "prepare_initrd_basetree_profile.py")
        profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile)
        checkout = HERE.parents[1]
        files = set(profile.SOURCE_FILES) | {runner.SCRIPT}
        members = [(path, (checkout / path).read_bytes()) for path in sorted(files)]
        with tempfile.TemporaryDirectory() as scratch:
            revision = self.source_bundle(scratch, members)
            selected = runner.ReceiptSourceArchive(Path(scratch), revision)
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError(
                    "Git must not run inside the no-route builder")):
                bound = runner.source_module(revision, selected)
            self.assertEqual(bound._BOUND_REVISION, revision)
            self.assertFalse(selected.report["private_mode_approved"])

    def test_production_config_uses_signed_package_versions_and_inherited_settings(self):
        static = (HERE.parents[1] / runner.SUBIMAGE).read_bytes()
        prepare = types.SimpleNamespace(
            validate_boot_profile=lambda: None,
            PROFILE=Path("/reviewed/deploy/gcp/guest"),
            INITRD_PACKAGES={"systemd", "udev"},
        )
        source = types.SimpleNamespace(
            guest=types.SimpleNamespace(
                prepare=prepare,
                SNAPSHOT="https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                SIGNED_RELEASE_EPOCH=1789199741,
            ),
            rust_inputs=types.SimpleNamespace(regular_bytes=lambda path: static),
            _BOUND_REVISION="a" * 40,
        )
        selected_source = types.SimpleNamespace(output=lambda args: static)
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch) / "profile"
            data, static_hash = runner.config_bytes(source, selected_source, profile, [
                {"name": "systemd", "version": "257.9-1"},
                {"name": "udev", "version": "257.9-1"},
            ])
        self.assertEqual(static_hash, runner.sha256(static))
        self.assertTrue(data.startswith(static))
        self.assertEqual(data.count(b"RemoveFiles="), 1)
        for relative in (b"/usr/bin/perl,", b"/usr/bin/perl5.40.1,"):
            self.assertIn(relative, static)
            self.assertIn(relative, data)
        self.assertIn(b"Distribution=debian\nRelease=trixie\nArchitecture=x86-64", data)
        self.assertIn(b"Packages=systemd=257.9-1,udev=257.9-1", data)
        self.assertIn(b"SourceDateEpoch=1789199741", data)
        self.assertIn(b"CacheOnly=always\nIncremental=no", data)
        self.assertNotIn(b"BaseTrees=", data)
        with self.assertRaisesRegex(ValueError, "misses production initrd package"):
            runner.config_bytes(source, selected_source, profile,
                                [{"name": "systemd", "version": "257.9-1"}])
        changed_source = types.SimpleNamespace(
            output=lambda args: static.replace(b"/usr/bin/perl,", b""))
        with self.assertRaisesRegex(ValueError, "production initrd source differs"):
            runner.config_bytes(source, changed_source, profile, [
                {"name": "systemd", "version": "257.9-1"},
                {"name": "udev", "version": "257.9-1"},
            ])

    def test_installed_manifest_rejects_package_outside_signed_closure(self):
        source = types.SimpleNamespace(guest=types.SimpleNamespace(
            prepare=types.SimpleNamespace(unique_object=dict,
                                          INITRD_PACKAGES={"systemd"})))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "initrd.manifest"
            manifest = {"manifest_version": 1,
                        "config": {"distribution": "debian", "release": "trixie",
                                   "architecture": "x86-64", "name": "image"},
                        "packages": [{"type": "deb", "name": "systemd",
                                      "version": "257.9-1", "architecture": "amd64"}]}
            path.write_text(json.dumps(manifest))
            digest, names = runner.installed_manifest(path, [
                {"name": "systemd", "version": "257.9-1", "architecture": "amd64"}], source)
            self.assertEqual(digest, runner.sha256(path.read_bytes()))
            self.assertEqual(names, ("systemd",))
            manifest["packages"][0]["version"] = "257.10-1"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "unlocked package"):
                runner.installed_manifest(path, [
                    {"name": "systemd", "version": "257.9-1", "architecture": "amd64"}], source)
            manifest["packages"][0]["version"] = "257.9-1"
            manifest["config"]["name"] = "initrd"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "manifest is unsupported"):
                runner.installed_manifest(path, [
                    {"name": "systemd", "version": "257.9-1", "architecture": "amd64"}], source)

    def test_signed_payload_plan_uses_only_exact_installed_package_subset(self):
        identities = [{"name": name, "version": "1", "architecture": "amd64",
                       "size": 3, "sha256": runner.sha256(name.encode())}
                      for name in ("alpha", "beta", "gamma")]
        archives = [(identity, name.encode()) for identity, name in
                    zip(identities, ("alpha", "beta", "gamma"))]
        rows = [
            {"path": ".", "kind": "directory", "uid": 0, "gid": 0,
             "output_mode": 0o755},
            {"path": "usr/bin/helper", "kind": "file", "uid": 0, "gid": 0,
             "output_mode": 0o755, "size": 6,
             "sha256": runner.sha256(b"helper")},
            {"path": "etc/helper", "kind": "symlink", "uid": 0, "gid": 0,
             "output_mode": 0o777, "target": "../usr/bin/helper"},
        ]
        source_plan = mock.Mock(return_value=(None, rows))
        source = types.SimpleNamespace(
            preflight=types.SimpleNamespace(authenticated_archives=lambda *_: archives),
            root_tree=types.SimpleNamespace(source_plan=source_plan))
        expected, selected = runner.signed_payload_plan(
            source, "metadata", "archives", ("alpha", "gamma"), b"Rust /init")
        self.assertEqual([row["name"] for row in selected], ["alpha", "gamma"])
        self.assertEqual([row[0]["name"] for row in source_plan.call_args.args[0]],
                         ["alpha", "gamma"])
        self.assertEqual(expected["usr/bin/helper"]["sha256"],
                         runner.sha256(b"helper"))
        self.assertEqual(expected["etc/helper"]["target"],
                         "../usr/bin/helper")
        self.assertEqual(expected["init"], {
            "kind": "file", "uid": 0, "gid": 0, "mode": 0o500,
            "size": len(b"Rust /init"), "sha256": runner.sha256(b"Rust /init")})
        with self.assertRaisesRegex(ValueError, "subset differs"):
            runner.signed_payload_plan(
                source, "metadata", "archives", ("alpha", "missing"), b"Rust /init")
        source_plan.return_value = (None, rows + [{"path": "init"}])
        with self.assertRaisesRegex(ValueError, "conflicts with pinned Rust"):
            runner.signed_payload_plan(
                source, "metadata", "archives", ("alpha", "gamma"), b"Rust /init")

    def test_signed_payload_delta_records_every_changed_path_without_approval(self):
        digest = runner.sha256
        expected = {
            "init": {"kind": "file", "uid": 0, "gid": 0, "mode": 0o500,
                     "size": 4, "sha256": digest(b"init")},
            "usr/bin/helper": {"kind": "file", "uid": 0, "gid": 0,
                               "mode": 0o755, "size": 6,
                               "sha256": digest(b"helper")},
            "usr/lib/required": {"kind": "file", "uid": 0, "gid": 0,
                                 "mode": 0o644, "size": 8,
                                 "sha256": digest(b"required")},
        }
        observed = {
            "init": expected["init"],
            "usr/bin/helper": {**expected["usr/bin/helper"],
                               "sha256": digest(b"changed")},
            "usr/bin/unreviewed": {"kind": "file", "uid": 0, "gid": 0,
                                   "mode": 0o755, "size": 4,
                                   "sha256": digest(b"code")},
            "etc/systemd/system/sysinit.target.wants/unreviewed.service": {
                "kind": "symlink", "uid": 0, "gid": 0, "mode": 0o777,
                "target": "/usr/lib/systemd/system/unreviewed.service"},
        }
        identity = [{"name": "systemd", "version": "1", "architecture": "amd64",
                     "size": 123, "sha256": digest(b"signed deb")}]
        cpio_sha = digest(b"actual compressed CPIO")
        summary, rows = runner.signed_payload_delta(
            expected, observed, identity, cpio_sha)
        self.assertEqual([(row["path"], row["difference"]) for row in rows], [
            ("etc/systemd/system/sysinit.target.wants/unreviewed.service", "added"),
            ("usr/bin/helper", "changed"),
            ("usr/bin/unreviewed", "added"),
            ("usr/lib/required", "missing"),
        ])
        self.assertEqual(rows[1]["signed_payload"]["sha256"], digest(b"helper"))
        self.assertEqual(rows[1]["observed_cpio"]["sha256"], digest(b"changed"))
        self.assertEqual(summary["difference_count"], 4)
        self.assertEqual(summary["cpio_sha256"], cpio_sha)
        self.assertEqual(summary["installed_package_names"], ["systemd"])
        self.assertFalse(summary["generated_effects_fully_audited"])
        self.assertFalse(summary["private_mode_approved"])
        changed = dict(observed)
        changed["usr/bin/helper"] = {**expected["usr/bin/helper"], "mode": 0o700}
        changed_summary, changed_rows = runner.signed_payload_delta(
            expected, changed, identity, cpio_sha)
        self.assertNotEqual(changed_summary["difference_sha256"],
                            summary["difference_sha256"])
        self.assertEqual(changed_rows[1]["observed_cpio"]["mode"], 0o700)
        changed["usr/bin/helper"] = {
            "kind": "symlink", "uid": 0, "gid": 0, "mode": 0o777,
            "target": "/usr/bin/unreviewed"}
        changed_summary, changed_rows = runner.signed_payload_delta(
            expected, changed, identity, cpio_sha)
        self.assertEqual(changed_rows[1]["signed_payload"]["kind"], "file")
        self.assertEqual(changed_rows[1]["observed_cpio"]["target"],
                         "/usr/bin/unreviewed")
        self.assertNotEqual(changed_summary["difference_sha256"],
                            summary["difference_sha256"])
        changed_identity = [{**identity[0], "sha256": digest(b"different signed deb")}]
        changed_summary, _ = runner.signed_payload_delta(
            expected, observed, changed_identity, cpio_sha)
        self.assertNotEqual(changed_summary["installed_package_identity_sha256"],
                            summary["installed_package_identity_sha256"])
        self.assertNotEqual(changed_summary["difference_sha256"],
                            summary["difference_sha256"])
        with self.assertRaisesRegex(ValueError, "lacks bound inputs"):
            runner.signed_payload_delta(expected, observed, identity, "unbound")

    def test_mkosi_output_requires_exact_compressed_alias(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "output"
            output.mkdir()
            (output / "initrd.cpio.zst").write_bytes(b"diagnostic")
            (output / "initrd.manifest").write_bytes(b"{}")
            alias = output / "initrd"
            alias.symlink_to("initrd.cpio.zst")
            runner.checked_output_layout(output)

            alias.unlink()
            alias.symlink_to("../outside")
            with self.assertRaisesRegex(ValueError, "alias differs"):
                runner.checked_output_layout(output)
            alias.unlink()
            alias.write_bytes(b"unexpected regular alias")
            with self.assertRaisesRegex(ValueError, "alias differs"):
                runner.checked_output_layout(output)
            alias.unlink()
            alias.symlink_to("initrd.cpio.zst")
            (output / "unexpected").write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "output set differs"):
                runner.checked_output_layout(output)

    def test_loopback_check_rejects_parent_namespace_and_non_loopback_route(self):
        with mock.patch.object(runner.sys, "platform", "linux"), mock.patch.object(
                runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                runner.os, "readlink", side_effect=["net:[1]", "mnt:[2]"]):
            with self.assertRaisesRegex(ValueError, "do not differ"):
                runner.check_loopback_only_ip_state("net:[1]", "mnt:[3]")
        with mock.patch.object(runner.sys, "platform", "linux"), mock.patch.object(
                runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]), mock.patch.object(
                runner.socket, "if_nameindex", return_value=[(1, "lo")]), mock.patch.object(
                runner.Path, "read_text", side_effect=["Iface\neth0 00000000 0 0 0 0 0 0 0 0 0\n", ""]):
            with self.assertRaisesRegex(ValueError, "non-loopback route"):
                runner.check_loopback_only_ip_state("net:[1]", "mnt:[2]")

    def test_loopback_check_accepts_empty_route_tables_but_rejects_bad_header(self):
        common = (mock.patch.object(runner.sys, "platform", "linux"),
                  mock.patch.object(runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")),
                  mock.patch.object(runner.socket, "if_nameindex", return_value=[(1, "lo")]))
        with common[0], common[1], common[2], mock.patch.object(
                runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]), mock.patch.object(
                runner.Path, "read_text", side_effect=["", ""]):
            report = runner.check_loopback_only_ip_state("net:[1]", "mnt:[2]")
            self.assertTrue(report["loopback_only_ip_state_observed"])
            self.assertFalse(report["network_egress_excluded"])
        with common[0], common[1], common[2], mock.patch.object(
                runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]), mock.patch.object(
                runner.Path, "read_text", side_effect=["Broken\n", ""]):
            with self.assertRaisesRegex(ValueError, "IPv4 route table malformed"):
                runner.check_loopback_only_ip_state("net:[1]", "mnt:[2]")

    def test_fresh_mkosi_cache_and_work_directories_reject_reuse(self):
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch) / "profile"
            runner.fresh_sibling(profile, "-package-cache")
            cache = Path(scratch) / "profile-package-cache"
            self.assertEqual(cache.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(cache.iterdir()), [])
            with self.assertRaises(FileExistsError):
                runner.fresh_sibling(profile, "-package-cache")
            (Path(scratch) / "profile-work").symlink_to(cache)
            with self.assertRaises(FileExistsError):
                runner.fresh_sibling(profile, "-work")

    def test_mkosi_scratch_requires_private_writable_directory(self):
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch)
            target = parent / "tmp"
            target.mkdir(mode=0o700)
            self.assertEqual(runner.checked_mkosi_tmpdir(
                target, expected_uid=runner.os.getuid()), str(target))
            self.assertEqual(list(target.iterdir()), [])
            target.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "private storage"):
                runner.checked_mkosi_tmpdir(
                    target, expected_uid=runner.os.getuid())
            target.chmod(0o700)
            with mock.patch.object(runner.os, "fstatvfs", return_value=types.SimpleNamespace(
                    f_flag=runner.os.ST_RDONLY)):
                with self.assertRaisesRegex(ValueError, "private storage"):
                    runner.checked_mkosi_tmpdir(
                        target, expected_uid=runner.os.getuid())
            with self.assertRaisesRegex(ValueError, "root-owned"):
                runner.checked_mkosi_tmpdir(target, expected_uid=-1)
            redirect = parent / "redirect"
            redirect.symlink_to(parent)
            with self.assertRaises(OSError):
                runner.checked_mkosi_tmpdir(
                    redirect / "tmp", expected_uid=runner.os.getuid())

    def test_loopback_observation_does_not_claim_egress_exclusion(self):
        with (mock.patch.object(runner.sys, "platform", "linux"),
              mock.patch.object(runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")),
              mock.patch.object(runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]),
              mock.patch.object(runner.socket, "if_nameindex", return_value=[(1, "lo")]),
              mock.patch.object(runner.Path, "read_text", side_effect=["Iface\n", ""])):
            observed = runner.check_loopback_only_ip_state("net:[1]", "mnt:[2]")
        self.assertTrue(observed["loopback_only_ip_state_observed"])
        self.assertFalse(observed["outer_namespace_separation_verified"])
        self.assertFalse(observed["builder_mounts_verified"])
        self.assertFalse(observed["network_egress_excluded"])


if __name__ == "__main__":
    unittest.main()
