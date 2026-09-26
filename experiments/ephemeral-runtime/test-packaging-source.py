#!/usr/bin/env python3
"""Synthetic refusal tests for the source-only packaging overlay."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    "packaging_source", HERE / "prepare-packaging-source.py")
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)
runtime = packaging.import_companion("prepare-image-source.py")

RECIPE = """inherit systemd
SRC_DIR = '${REPO_ROOT}/dstack'
DSTACK_SERVICES = "dstack-guest-agent.socket dstack-guest-agent.service dstack-prepare.service app-compose.service wg-checker.service"
do_unpack() {
    mkdir -p ${S}
    rsync -a --exclude="target" ${SRC_DIR}/ ${S}/
}
do_unpack[nostamp] = "1"
do_install() {
    install -m 0755 ${CARGO_BINDIR}/dstack-guest-agent ${D}${bindir}
    install -m 0755 ${S}/basefiles/dstack-prepare.sh ${D}${bindir}
    if true; then
        install -m 0644 ${S}/basefiles/dstack-guest-agent.socket ${D}${systemd_system_unitdir}
    fi
}
"""


def synthetic_elf(machine=62):
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 16, 3)
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<I", data, 20, 1)
    return bytes(data)


class PackagingSourceTests(unittest.TestCase):
    def test_recipe_accounts_for_each_generated_dropin_and_binary(self):
        candidate = packaging.candidate_guest_recipe(
            RECIPE, runtime, "a" * 64, "b" * 64, "c" * 64)
        self.assertIn("inherit systemd useradd", candidate)
        self.assertIn('GROUPADD_PARAM:${PN} = "-r zrpc-wrapper"', candidate)
        self.assertIn("zrpc-quote-proxy.service", candidate)
        self.assertNotIn('rsync -a --exclude="target"', candidate)
        self.assertIn('rsync -a --files-from="${REPO_ROOT}/zrpc-dstack-files.txt"',
                      candidate)
        self.assertIn('sha256sum -c -- "${REPO_ROOT}/zrpc-dstack.sha256"', candidate)
        self.assertIn('do_unpack[cleandirs] = "${WORKDIR}/dstack"', candidate)
        self.assertIn('[ "${S}" = "${WORKDIR}/dstack" ] || exit 1', candidate)
        self.assertIn('stale_files=$(find "${S}" -mindepth 1 -print -quit)', candidate)
        self.assertIn('source_links=$(find "${SRC_DIR}" -type l -print -quit)', candidate)
        self.assertIn('copied_links=$(find "${S}" -type l -print -quit)', candidate)
        self.assertIn('mode_file="${SRC_DIR}/$relative_path"', candidate)
        self.assertIn('mode_file="${S}/$relative_path"', candidate)
        self.assertIn('[ ! -L "${REPO_ROOT}/$manifest" ]', candidate)
        self.assertIn('"' + "a" * 64 + '"', candidate)
        self.assertIn('"' + "b" * 64 + '"', candidate)
        self.assertIn('"' + "c" * 64 + '"', candidate)
        for name in (packaging.GUARD_NAME, packaging.BRIDGE_NAME):
            self.assertIn(f"${{S}}/zrpc/{name} ${{D}}${{bindir}}/{name}", candidate)
            self.assertIn(f"${{bindir}}/{name}", candidate)
        for source_path in runtime.dropins():
            package_path = "${sysconfdir}/systemd/system/" + str(
                source_path.relative_to("basefiles"))
            self.assertIn(f"install -m 0644 ${{S}}/{source_path} "
                          f"${{D}}{package_path}", candidate)
            self.assertIn(package_path, candidate)
        self.assertIn("${S}/basefiles/sysbox.service.d/zrpc-private-profile.conf",
                      candidate)
        self.assertIn("${S}/basefiles/docker.socket.d/zrpc-private-profile.conf",
                      candidate)
        self.assertIn('DSTACK_SERVICES = "', candidate)

    def test_recipe_drift_and_separate_sysbox_contract_refuse(self):
        with self.assertRaises(packaging.Refusal):
            packaging.candidate_guest_recipe(
                RECIPE.replace("inherit systemd", "inherit sysvinit"), runtime,
                "a" * 64, "b" * 64, "c" * 64)
        originals = {
            packaging.GUEST_RECIPE: RECIPE,
            packaging.SYSBOX_RECIPE: "".join(
                f"install -m 0644 ${{WORKDIR}}/{unit}.service "
                "${D}${systemd_system_unitdir}\n"
                for unit in ("sysbox", "sysbox-mgr", "sysbox-fs")),
            packaging.BASE_RECIPE: "dstack-guest dstack-sysbox",
            packaging.PROD_RECIPE: 'include dstack-rootfs-base.inc\nIMAGE_FEATURES += "nologin"\n',
        }
        packaging.verify_meta_contract(originals)
        originals[packaging.SYSBOX_RECIPE] = originals[packaging.SYSBOX_RECIPE].replace(
            "sysbox-fs.service", "other.service")
        with self.assertRaisesRegex(packaging.Refusal, "Sysbox recipe"):
            packaging.verify_meta_contract(originals)

    def test_binary_hash_machine_type_and_link_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "guard"
            source.write_bytes(synthetic_elf())
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(packaging.verify_binary(source, expected), synthetic_elf())
            with self.assertRaisesRegex(packaging.Refusal, "SHA-256 mismatch"):
                packaging.verify_binary(source, "0" * 64)
            link = Path(temporary) / "link"
            link.symlink_to(source)
            with self.assertRaisesRegex(packaging.Refusal, "regular file"):
                packaging.verify_binary(link, expected)
            source.write_bytes(synthetic_elf(machine=183))
            with self.assertRaisesRegex(packaging.Refusal, "not x86_64"):
                packaging.verify_binary(
                    source, hashlib.sha256(source.read_bytes()).hexdigest())
            source.write_bytes(b"ELF")
            with self.assertRaisesRegex(packaging.Refusal, "ELF header"):
                packaging.verify_binary(
                    source, hashlib.sha256(source.read_bytes()).hexdigest())

    def test_child_manifest_refuses_tamper_and_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            overlay = Path(temporary)
            filename = Path("basefiles/test.service")
            target = overlay / filename
            target.parent.mkdir()
            target.write_text("unit")
            manifest = {
                "source_commit": packaging.DSTACK_COMMIT,
                "source_commit_object_verified": True,
                "source_tree_verified": False,
                "built_image": False,
                "private_accepted": False,
                "candidate_sha256": {str(filename): packaging.digest(b"unit")},
            }
            receipt = overlay / "candidate-manifest.json"
            receipt.write_text(json.dumps(manifest))
            packaging.verify_child_manifest(
                overlay, {filename}, packaging.DSTACK_COMMIT, "built_image")
            target.write_text("changed")
            with self.assertRaisesRegex(packaging.Refusal, "hash mismatch"):
                packaging.verify_child_manifest(
                    overlay, {filename}, packaging.DSTACK_COMMIT, "built_image")
            target.write_text("unit")
            manifest["private_accepted"] = True
            receipt.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(packaging.Refusal, "incomplete or accepting"):
                packaging.verify_child_manifest(
                    overlay, {filename}, packaging.DSTACK_COMMIT, "built_image")
            manifest["private_accepted"] = False
            manifest["built_image"] = True
            receipt.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(packaging.Refusal, "incomplete or accepting"):
                packaging.verify_child_manifest(
                    overlay, {filename}, packaging.DSTACK_COMMIT, "built_image")

    def test_wrong_meta_source_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(packaging.Refusal, "not at the pinned commit"):
                packaging.pinned_meta(Path(temporary))

    def test_staged_git_objects_exclude_modified_and_untracked_checkout_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "input"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "basefiles").mkdir()
            tracked = repo / "basefiles" / "guest.sh"
            tracked.write_text("#!/bin/sh\nprintf original\\n\n")
            tracked.chmod(0o755)
            (repo / "guest-link").symlink_to("basefiles/guest.sh")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "base"],
                           check=True)
            commit = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            tracked.write_text("modified checkout\n")
            (repo / "basefiles" / "untracked.sh").write_text("untracked\n")
            staged = root / "stage"
            tree_oid, entries = packaging.stage_git_tree(repo, commit, staged)
            self.assertEqual(len(tree_oid), 40)
            self.assertIn(Path("basefiles/guest.sh"), entries)
            self.assertEqual((staged / "basefiles" / "guest.sh").read_text(),
                             "#!/bin/sh\nprintf original\\n\n")
            self.assertTrue((staged / "basefiles" / "guest.sh").stat().st_mode & 0o100)
            self.assertFalse((staged / "basefiles" / "untracked.sh").exists())
            self.assertEqual((staged / "guest-link").readlink(), Path("basefiles/guest.sh"))

    def test_replace_refs_cannot_substitute_pinned_tree_or_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "input"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            source = repo / "guest.txt"
            source.write_text("original pinned bytes\n")
            subprocess.run(["git", "-C", str(repo), "add", "guest.txt"], check=True)
            identity = ["-c", "user.name=Test", "-c", "user.email=test@example.invalid"]
            subprocess.run(["git", "-C", str(repo), *identity,
                            "commit", "-qm", "original"], check=True)
            original = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            original_blob = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD:guest.txt"],
                text=True).strip()
            source.write_text("replacement bytes\n")
            subprocess.run(["git", "-C", str(repo), "add", "guest.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), *identity,
                            "commit", "-qm", "replacement"], check=True)
            replacement = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            replacement_blob = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD:guest.txt"],
                text=True).strip()
            subprocess.run(["git", "-C", str(repo), "reset", "--hard", original],
                           check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "-C", str(repo), "replace", original, replacement],
                           check=True)
            subprocess.run(["git", "-C", str(repo), "replace", original_blob,
                            replacement_blob], check=True)
            default_git_env = os.environ.copy()
            default_git_env.pop("GIT_NO_REPLACE_OBJECTS", None)
            self.assertEqual(subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                text=True, env=default_git_env).strip(), original)
            self.assertEqual(subprocess.check_output(
                ["git", "-C", str(repo), "show", "HEAD:guest.txt"],
                text=True, env=default_git_env), "replacement bytes\n")
            self.assertEqual(subprocess.check_output(
                ["git", "-C", str(repo), "cat-file", "blob", original_blob],
                text=True, env=default_git_env), "replacement bytes\n")
            staged = root / "stage"
            packaging.stage_git_tree(repo, original, staged)
            self.assertEqual((staged / "guest.txt").read_text(),
                             "original pinned bytes\n")

    def test_source_manifests_bind_exact_staged_paths_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            dstack = staged / "dstack"
            dstack.mkdir()
            (dstack / "tracked.rs").write_text("pinned")
            list_digest, checksums_digest, modes_digest = packaging.dstack_copy_manifests(staged)
            names = (staged / packaging.SOURCE_FILE_LIST).read_text()
            checksums = (staged / packaging.SOURCE_CHECKSUMS).read_text()
            modes = (staged / packaging.SOURCE_MODES).read_text()
            self.assertEqual(names, "tracked.rs\n")
            self.assertEqual(checksums, packaging.digest(b"pinned") + "  tracked.rs\n")
            self.assertEqual(modes, "644\ttracked.rs\n")
            self.assertEqual(packaging.digest(names.encode()), list_digest)
            self.assertEqual(packaging.digest(checksums.encode()), checksums_digest)
            self.assertEqual(packaging.digest(modes.encode()), modes_digest)
            candidate = packaging.candidate_guest_recipe(
                RECIPE, runtime, list_digest, checksums_digest, modes_digest)
            self.assertIn('"${REPO_ROOT}/' + packaging.SOURCE_FILE_LIST + '"', candidate)
            self.assertIn('"${REPO_ROOT}/' + packaging.SOURCE_CHECKSUMS + '"', candidate)
            self.assertIn('"${REPO_ROOT}/' + packaging.SOURCE_MODES + '"', candidate)
            (dstack / "extra.rs").write_text("unlisted")
            self.assertNotIn("extra.rs", names)

    def test_generated_unpack_copies_only_checked_files_and_refuses_stale_or_linked_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged"
            staged.mkdir()
            dstack = staged / "dstack"
            dstack.mkdir()
            tracked = dstack / "tracked.rs"
            tracked.write_text("pinned")
            list_digest, checksums_digest, modes_digest = packaging.dstack_copy_manifests(staged)
            candidate = packaging.candidate_guest_recipe(
                RECIPE, runtime, list_digest, checksums_digest, modes_digest)
            body = candidate.split("do_unpack() {\n", 1)[1].split("\n}\n", 1)[0]

            def clean_destination(name: str) -> Path:
                destination = root / name / "dstack"
                destination.mkdir(parents=True)
                return destination

            def run_unpack(destination: Path,
                           tamper_copied_mode: bool = False) -> subprocess.CompletedProcess:
                script = (body.replace("${REPO_ROOT}", str(staged))
                          .replace("${SRC_DIR}", str(dstack))
                          .replace("${S}", str(destination))
                          .replace("${WORKDIR}", str(destination.parent)))
                if tamper_copied_mode:
                    script = (
                        'rsync() { command rsync "$@" || return; '
                        'for arg do destination="$arg"; done; '
                        'chmod 755 "$destination/tracked.rs"; }\n' + script)
                return subprocess.run(["sh", "-eu", "-c", script],
                                      capture_output=True, text=True, check=False)

            copied = clean_destination("copied")
            self.assertEqual(run_unpack(copied).returncode, 0)
            self.assertEqual((copied / "tracked.rs").read_text(), "pinned")
            (dstack / "extra.rs").write_text("unlisted")
            copied_extra = clean_destination("copied-extra")
            self.assertEqual(run_unpack(copied_extra).returncode, 0)
            self.assertFalse((copied_extra / "extra.rs").exists())
            copied_mode_tamper = clean_destination("copied-mode-tamper")
            mode_tamper_result = run_unpack(copied_mode_tamper, True)
            self.assertNotEqual(mode_tamper_result.returncode, 0)
            self.assertEqual((copied_mode_tamper / "tracked.rs").stat().st_mode & 0o777,
                             0o755)
            tracked.chmod(0o755)
            self.assertNotEqual(run_unpack(clean_destination("copied-chmod")).returncode, 0)
            tracked.chmod(0o644)
            tracked.write_text("changed")
            self.assertNotEqual(run_unpack(clean_destination("copied-changed")).returncode, 0)
            tracked.write_text("pinned")
            external = root / "external"
            external.write_text("pinned")
            tracked.unlink()
            tracked.symlink_to(external)
            self.assertNotEqual(run_unpack(clean_destination("copied-linked")).returncode, 0)
            tracked.unlink()
            tracked.write_text("pinned")
            stale = clean_destination("stale")
            (stale / "extra.rs").write_text("old")
            self.assertNotEqual(run_unpack(stale).returncode, 0)
            wrong_location = root / "wrong-location"
            wrong_location.mkdir()
            self.assertNotEqual(run_unpack(wrong_location).returncode, 0)
            list_path = staged / packaging.SOURCE_FILE_LIST
            held_manifest = staged / "held-files.txt"
            list_path.rename(held_manifest)
            list_path.symlink_to(held_manifest)
            self.assertNotEqual(run_unpack(clean_destination("copied-linked-manifest")).returncode,
                                0)


if __name__ == "__main__":
    unittest.main()
