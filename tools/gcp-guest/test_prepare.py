"""Synthetic input/packaging tests; no image build or hardware evidence."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
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
                # The reviewed kernel identity has deliberately synthetic archive bytes.
                packages = []
                for name in ("systemd", "systemd-boot-efi", "systemd-cryptsetup", "systemd-resolved", "udev", "e2fsprogs", "dmsetup", "kmod", prepare.KERNEL_PACKAGE):
                    version = prepare.KERNEL_PACKAGE_VERSION if name == prepare.KERNEL_PACKAGE else "1.0~synthetic"
                    packages.append({"name": name, "version": version, "architecture": "amd64", "filename": f"pool/main/s/{name}/{name}_{version}_amd64.deb", "size": len(self.synthetic_deb), "sha256": self.synthetic_deb_sha, "path": f"debs/{self.synthetic_deb_sha}.deb"})
                data = json.dumps(packages).encode()
            else:
                data = b"SYNTHETIC_NOT_A_SIGNED_ARTIFACT"
            (self.inputs / role).write_bytes(data)
            artifacts[role] = {"path": role, "sha256": hashlib.sha256(data).hexdigest()}
        # Values exercise branches only and are never production defaults.
        self.lock = {"schema_version": 5, "mkosi_source_commit": prepare.SOURCE_COMMIT, "source_date_epoch": 1, "kernel_version": prepare.KERNEL_VERSION, "snapshot": "https://snapshot.debian.org/archive/debian/20200101T000000Z/", "artifacts": artifacts, "runtime": {"listen_port": 8443, "max_connections": 2, "max_quotes": 1, "quote_spacing_ms": 1, "node_startup_timeout_secs": 1, "node_poll_interval_ms": 1}}
        # Keep the test-only manifest separate from mutable input bytes. This
        # exercises the same source-closure check without treating synthetic
        # packages as a production input.
        self.closure = self.root / "synthetic-package-closure.lock.json"
        self.closure.write_bytes((self.inputs / "package_manifest").read_bytes())
        self.closure_patch = mock.patch.object(prepare, "PACKAGE_CLOSURE_LOCK", self.closure)
        self.closure_patch.start()
        self.closure_hash_patch = mock.patch.object(prepare, "PACKAGE_CLOSURE_SHA256", prepare.digest(self.closure))
        self.closure_hash_patch.start()

    def tearDown(self):
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
            mask = candidate / "rootfs/etc/systemd/system/ssh.service"
            mask.unlink()
            mask.symlink_to("/usr/lib/systemd/system/ssh.service")

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
            ("hook", add_hook),
            ("binary", lambda candidate: (candidate / "artifacts/wrapper").write_bytes(b"different guest binary")),
            ("mask", replace_mask),
            ("mode", change_mode),
            ("missing", lambda candidate: (candidate / "audit-rootfs.py").unlink()),
            ("lock", lambda candidate: (candidate / "inputs.lock.json").write_bytes(b"{}")),
            ("output", lambda candidate: add_build_output(candidate, "output")),
            ("work", lambda candidate: add_build_output(candidate, "work")),
            ("cache", lambda candidate: add_build_output(candidate, "package-cache")),
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
        for change in (lambda lock: lock.update(schema_version=4), lambda lock: lock.pop("snapshot"), lambda lock: lock["artifacts"].update(initrd={"path": "initrd", "sha256": "00" * 32}), lambda lock: lock["artifacts"].update(kernel={"path": "kernel", "sha256": "00" * 32}), lambda lock: lock["artifacts"].update(base_tree={"path": "base_tree", "sha256": "00" * 32}), lambda lock: lock["artifacts"]["wrapper"].update(sha256="00" * 32), lambda lock: lock["artifacts"]["wrapper"].update(path="../wrapper"), lambda lock: lock.update(kernel_version="other-abi"), lambda lock: lock["runtime"].update(max_quotes=0), lambda lock: lock.update(snapshot="https://deb.debian.org/debian")):
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
        self.assertIn("ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec wrapper", wrapper)
        for name in ("zrpc-wrapper", "zrpc-node", "zrpc-cookie", "zrpc-gcp-quote"):
            unit = (units / f"{name}.service").read_text()
            self.assertIn("NoExecPaths=/run /tmp /var /dev\n", unit)
            self.assertIn("ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec ", unit)
            self.assertNotIn("ExecStartPre=/usr/lib/zrpc/zrpc-gcp-guard --check", unit)
        config = (output / "mkosi.conf").read_text()
        self.assertIn("PackageDirectories=packages", config)
        self.assertIn("PackageCacheDirectory=package-cache", config)
        self.assertTrue((output / "package-cache").is_dir())
        self.assertNotIn("BaseTrees=", config)
        self.assertFalse((output / "artifacts/base_tree.tar").exists())
        self.assertFalse((output / "artifacts/kernel").exists())
        self.assertFalse((output / "artifacts/initrd").exists())
        self.assertFalse((output / "rootfs/usr/lib/modules").exists())
        self.assertIn("Packages=dmsetup=1.0~synthetic,e2fsprogs=1.0~synthetic,kmod=1.0~synthetic,linux-image-6.12.107+deb13-cloud-amd64=6.12.107-1,systemd-boot-efi=1.0~synthetic,systemd-cryptsetup=1.0~synthetic,systemd-resolved=1.0~synthetic,systemd=1.0~synthetic,udev=1.0~synthetic", config)
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
        self.assertIn("Packages=dmsetup=1.0~synthetic,kmod=1.0~synthetic,systemd=1.0~synthetic,systemd-cryptsetup=1.0~synthetic,udev=1.0~synthetic", initrd)
        self.assertIn("FinalizeScripts=audit-initrd.py", initrd)
        audit = output / "mkosi.images/initrd/audit-initrd.py"
        self.assertEqual(audit.read_bytes(), (Path(__file__).with_name("audit-initrd.py")).read_bytes())
        self.assertEqual(audit.stat().st_mode & 0o777, 0o555)
        self.assertNotIn("Include=mkosi-initrd", initrd)
        self.assertNotIn("linux-image", initrd)
        esp = (output / "repart/30-esp.conf").read_text()
        self.assertIn("CopyFiles=/efi:/", esp)
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
        (profile / "rootfs").mkdir()
        (profile / "input-identities.json").write_text("{}")
        shutil.copy2(prepare.PROFILE / "package-closure.lock.json", profile / "package-closure.lock.json")
        prepare.validate_boot_profile(profile)
        changes = (
            ("repart/30-esp.conf", "CopyFiles=/efi:/", "CopyFiles=/boot:/"),
            ("repart/10-root.conf", "Verity=data", "Verity=off"),
            ("repart/20-root-verity.conf", "Verity=hash", "Verity=off"),
            ("mkosi.conf", "SecureBoot=yes", "SecureBoot=no"),
            ("mkosi.conf", "KernelModulesInitrd=yes", "KernelModulesInitrd=no"),
            ("mkosi.conf", "KernelModulesInitrdInclude=^drivers/md/dm-verity[.]ko[.]xz$", "KernelModulesInitrdInclude=.*"),
            ("mkosi.conf", "KernelModulesInitrdExclude=.*", "KernelModulesInitrdExclude="),
            ("mkosi.conf", "Dependencies=initrd", "Dependencies="),
            ("mkosi.conf", "Bootloader=uki", "Bootloader=systemd-boot"),
            ("mkosi.conf", "ExtraTrees=rootfs", "ExtraTrees=rootfs\nPostOutputScripts=unreviewed.sh"),
            ("mkosi.images/initrd/mkosi.conf", "MakeInitrd=yes", "MakeInitrd=no"),
            ("mkosi.images/initrd/mkosi.conf", "Ssh=no", "Ssh=yes"),
            ("mkosi.images/initrd/mkosi.conf", "rescue.target,", ""),
            ("mkosi.images/initrd/mkosi.conf", "multi-user.target.wants/getty.target,", ""),
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

    def synthetic_guest_root(self):
        root = self.root / "synthetic-root"
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "usr/lib/zrpc").mkdir(parents=True)
        for unit in audit_rootfs.MASKED_UNITS:
            (root / "etc/systemd/system" / unit).symlink_to("/dev/null")
        (root / "etc/passwd").write_text("root:x:0:0::/:/usr/sbin/nologin\nzrpc-node:x:101:101::/nonexistent:/usr/sbin/nologin\nzrpc-wrapper:x:102:102::/nonexistent:/usr/sbin/nologin\n")
        (root / "etc/shadow").write_text("root:!:0:0:0:0:0:0:\nzrpc-node:!:0:0:0:0:0:0:\nzrpc-wrapper:!:0:0:0:0:0:0:\n")
        (root / "etc/group").write_text("root:x:0:\nzrpc-node:x:101:\nzrpc-wrapper:x:102:\nzrpc-cookie:x:103:zrpc-node,zrpc-wrapper\n")
        for name in prepare.BINARIES.values():
            (root / "usr/lib/zrpc" / name).write_text("SYNTHETIC")
            (root / "usr/lib/zrpc" / name).chmod(0o555)
        return root

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
