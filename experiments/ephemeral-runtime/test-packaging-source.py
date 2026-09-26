#!/usr/bin/env python3
"""Synthetic refusal tests for the source-only packaging overlay."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
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
    rsync -a --exclude="target" ${SRC_DIR}/ ${S}/
}
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
        candidate = packaging.candidate_guest_recipe(RECIPE, runtime)
        self.assertIn("inherit systemd useradd", candidate)
        self.assertIn('GROUPADD_PARAM:${PN} = "-r zrpc-wrapper"', candidate)
        self.assertIn("zrpc-quote-proxy.service", candidate)
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
            packaging.candidate_guest_recipe(RECIPE.replace("inherit systemd", "inherit sysvinit"),
                                             runtime)
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


if __name__ == "__main__":
    unittest.main()
