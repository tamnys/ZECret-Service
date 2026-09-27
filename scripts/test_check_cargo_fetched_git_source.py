"""Networkless tests for the fetched dstack Git-object and manifest gate."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-cargo-fetched-git-source.py")
spec = importlib.util.spec_from_file_location("check_cargo_fetched_git_source", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def git(repository, *arguments):
    return subprocess.check_output(["git", "-C", str(repository), *arguments], stderr=subprocess.DEVNULL).decode().strip()


def commit(repository):
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(repository), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                   check=True, stdout=subprocess.DEVNULL)
    revision = git(repository, "rev-parse", "HEAD")
    return revision, git(repository, "rev-parse", "HEAD^{tree}")


def fixture(repository):
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
    (repository / "Cargo.toml").write_text('[workspace]\nmembers = ["event", "types"]\n'
                                           '[workspace.package]\nversion = "0.5.9"\n')
    (repository / "event").mkdir()
    (repository / "event/Cargo.toml").write_text('[package]\nname = "cc-eventlog"\n'
                                                 'version.workspace = true\n')
    (repository / "types").mkdir()
    (repository / "types/Cargo.toml").write_text('[package]\nname = "dstack-sdk-types"\n'
                                                 'version = "0.1.2"\n')
    return commit(repository)


class FetchedGitSourceTests(unittest.TestCase):
    def test_pinned_tree_and_package_manifests_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            revision, tree = fixture(repository)
            result = gate.check_fetched_tree(repository, revision, tree, gate.GATE["PACKAGES"])
        self.assertEqual(result, {
            "cc-eventlog": {"manifest_path": "event/Cargo.toml", "version": "0.5.9"},
            "dstack-sdk-types": {"manifest_path": "types/Cargo.toml", "version": "0.1.2"},
        })

    def test_wrong_tree_is_rejected_before_manifest_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            revision, _ = fixture(repository)
            with self.assertRaisesRegex(gate.Refusal, "tree differs"):
                gate.check_fetched_tree(repository, revision, "0" * 40, gate.GATE["PACKAGES"])

    def test_changed_package_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            fixture(repository)
            (repository / "types/Cargo.toml").write_text('[package]\nname = "dstack-sdk-types"\n'
                                                         'version = "0.1.3"\n')
            revision, tree = commit(repository)
            with self.assertRaisesRegex(gate.Refusal, "identity differs"):
                gate.check_fetched_tree(repository, revision, tree, gate.GATE["PACKAGES"])

    def test_duplicate_package_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            fixture(repository)
            (repository / "copy").mkdir()
            (repository / "copy/Cargo.toml").write_text('[package]\nname = "cc-eventlog"\n'
                                                        'version = "0.5.9"\n')
            revision, tree = commit(repository)
            with self.assertRaisesRegex(gate.Refusal, "identity differs"):
                gate.check_fetched_tree(repository, revision, tree, gate.GATE["PACKAGES"])

    def test_symlink_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            fixture(repository)
            (repository / "link").mkdir()
            (repository / "link/Cargo.toml").symlink_to("../types/Cargo.toml")
            revision, tree = commit(repository)
            with self.assertRaisesRegex(gate.Refusal, "regular Git blob"):
                gate.check_fetched_tree(repository, revision, tree, gate.GATE["PACKAGES"])

    def test_missing_commit_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            _, tree = fixture(repository)
            with self.assertRaisesRegex(gate.Refusal, "object inspection failed"):
                gate.check_fetched_tree(repository, "0" * 40, tree, gate.GATE["PACKAGES"])


if __name__ == "__main__":
    unittest.main()
