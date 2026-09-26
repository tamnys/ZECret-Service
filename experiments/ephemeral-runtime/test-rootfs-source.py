"""Synthetic shell checks for the unbuilt pinned production-rootfs correction."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "rootfs_source", Path(__file__).with_name("prepare-rootfs-source.py")
)
rootfs_source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rootfs_source)
PROD = 'include dstack-rootfs-base.inc\nIMAGE_FEATURES += "nologin"\n'
BASE = "disable_login() {\n    :\n}\n"


class RootfsSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".codex-tmp").mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "rootfs"
        self.root.mkdir()
        for path in rootfs_source.ADMIN_FILES:
            target = self.root / path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("SYNTHETIC_ONLY")
        for path in rootfs_source.OPTIONAL_FILES:
            target = self.root / path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("SYNTHETIC_ONLY")
        sulogin = self.root / "usr/sbin/sulogin"
        sulogin.unlink()
        sulogin.symlink_to("/usr/sbin/sulogin.util-linux")
        self.unrelated = self.root / "usr/lib/systemd/system/dstack-prepare.service"
        self.unrelated.parent.mkdir(parents=True, exist_ok=True)
        self.unrelated.write_text("SYNTHETIC_ONLY")
        candidate = rootfs_source.candidate_prod(PROD, BASE)
        self.function = "zrpc_remove_local_admin() {" + candidate.split(
            "zrpc_remove_local_admin() {", 1
        )[1]

    def run_function(
        self, root: Path | str | None = None, *, expanded_recipe: bool = False
    ) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        function = self.function
        if expanded_recipe:
            assert root is not None
            function = function.replace("${IMAGE_ROOTFS}", str(root)).replace(
                "${WORKDIR}", self.scratch.name
            )
            environment.pop("IMAGE_ROOTFS", None)
            environment.pop("WORKDIR", None)
        else:
            if root is None:
                environment.pop("IMAGE_ROOTFS", None)
            else:
                environment["IMAGE_ROOTFS"] = str(root)
            environment["WORKDIR"] = self.scratch.name
        return subprocess.run(
            ["sh", "-c", "set -eu\n" + function + "\nzrpc_remove_local_admin\n"],
            env=environment,
            capture_output=True,
            check=False,
        )

    def test_exact_observed_paths_are_removed_and_masked(self) -> None:
        self.assertEqual(self.run_function(self.root).returncode, 0)
        for path in (*rootfs_source.ADMIN_FILES, *rootfs_source.OPTIONAL_FILES):
            target = self.root / path.lstrip("/")
            self.assertFalse(target.exists() or target.is_symlink(), path)
        for unit in rootfs_source.MASK_UNITS:
            target = self.root / "etc/systemd/system" / unit
            self.assertTrue(target.is_symlink(), unit)
            self.assertEqual(os.readlink(target), "/dev/null")
        self.assertTrue(self.unrelated.is_file())

    def test_recipe_expansion_needs_no_shell_exports(self) -> None:
        self.assertEqual(self.run_function(self.root, expanded_recipe=True).returncode, 0)
        self.assertFalse((self.root / rootfs_source.ADMIN_FILES[0].lstrip("/")).exists())
        self.assertEqual(
            os.readlink(self.root / "etc/systemd/system/rescue.target"), "/dev/null"
        )
        self.assertTrue(self.unrelated.is_file())

    def test_missing_path_and_preexisting_override_refuse_before_removal(self) -> None:
        missing = self.root / rootfs_source.ADMIN_FILES[0].lstrip("/")
        missing.unlink()
        self.assertNotEqual(self.run_function(self.root).returncode, 0)
        surviving = self.root / rootfs_source.ADMIN_FILES[1].lstrip("/")
        self.assertTrue(surviving.is_file())
        missing.write_text("SYNTHETIC_ONLY")
        override = self.root / "etc/systemd/system/rescue.target"
        override.parent.mkdir(parents=True, exist_ok=True)
        override.write_text("SYNTHETIC_ONLY")
        self.assertNotEqual(self.run_function(self.root).returncode, 0)
        self.assertTrue(surviving.is_file())
        self.assertEqual(override.read_text(), "SYNTHETIC_ONLY")

    def test_root_and_source_refusals(self) -> None:
        self.assertNotEqual(self.run_function().returncode, 0)
        alias = Path(self.scratch.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertNotEqual(self.run_function(alias).returncode, 0)
        self.assertNotEqual(self.run_function(self.root / "..").returncode, 0)
        self.assertTrue((self.root / rootfs_source.ADMIN_FILES[0].lstrip("/")).is_file())
        with self.assertRaises(ValueError):
            rootfs_source.candidate_prod(PROD + "unreviewed\n", BASE)
        with self.assertRaises(ValueError):
            rootfs_source.candidate_prod(PROD, "disable_login_missing")

    def test_internal_parent_symlinks_refuse_before_mutation(self) -> None:
        for parent in ("usr", "etc"):
            with self.subTest(parent=parent):
                original = self.root / parent
                original.mkdir(exist_ok=True)
                canary = original / "OUTSIDE_CANARY"
                canary.write_text("SYNTHETIC_ONLY")
                outside = Path(self.scratch.name) / f"outside-{parent}"
                original.rename(outside)
                original.symlink_to(outside, target_is_directory=True)
                try:
                    self.assertNotEqual(self.run_function(self.root).returncode, 0)
                    self.assertEqual((outside / "OUTSIDE_CANARY").read_text(), "SYNTHETIC_ONLY")
                    if parent == "usr":
                        self.assertTrue((outside / "lib/systemd/system/emergency.service").is_file())
                    else:
                        self.assertFalse((outside / "systemd/system/rescue.target").exists())
                finally:
                    original.unlink()
                    outside.rename(original)


if __name__ == "__main__":
    unittest.main()
