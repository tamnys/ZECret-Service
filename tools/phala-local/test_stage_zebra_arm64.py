import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name("stage_zebra_arm64.py")
SPEC = importlib.util.spec_from_file_location("stage_zebra_arm64", SOURCE)
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class LocalZebraStageTests(unittest.TestCase):
    def test_release_hold_requires_explicit_local_exception(self):
        held = {"status": "held-metadata-only-unapproved"}
        with self.assertRaisesRegex(ValueError, "explicit local-only exception"):
            stage.require_local_age_policy(held, False)
        self.assertTrue(stage.require_local_age_policy(held, True))
        self.assertFalse(stage.require_local_age_policy(
            {"status": "age-eligible-metadata-only-unapproved"}, False))

    def test_lock_cannot_add_private_approval_or_change_release(self):
        original, _ = stage.load_lock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            for change in ({"private_mode_approved": True}, {"tag": "v6.4.3"},
                           {"status": "approved"}):
                changed = {**original, **change}
                path.write_text(json.dumps(changed))
                with patch.object(stage, "LOCK_PATH", path):
                    with self.assertRaises(ValueError):
                        stage.load_lock()

    def test_signed_manifest_must_name_and_hash_arm64_archive(self):
        lock, _ = stage.load_lock()
        good = (lock["asset"]["sha256"] + "  " + stage.ARCHIVE_NAME + "\n" +
                "5" * 64 + "  zebrad-6.4.2-x86_64-unknown-linux-gnu.tar.gz\n")
        stage.parse_manifest(good.encode(), lock["asset"])
        for payload in (good.replace(lock["asset"]["sha256"], "0" * 64),
                        good + good.splitlines()[0] + "\n",
                        good.replace(stage.ARCHIVE_NAME, "unexpected.tar.gz")):
            with self.assertRaises(ValueError):
                stage.parse_manifest(payload.encode(), lock["asset"])

    def test_wrong_machine_cannot_be_staged_as_arm64(self):
        data = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                member = tarfile.TarInfo("zebrad")
                member.size = len(data)
                package.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, "ARM64 ELF"):
                stage.extract_member(archive, "zebrad", Path(directory) / "zebrad",
                                     len(data), hashlib.sha256(data).hexdigest())

    def test_authenticated_statement_must_bind_exact_build_and_subject(self):
        lock, _ = stage.load_lock()
        identity = ("https://github.com/" + lock["signer_workflow"] +
                    "@refs/tags/" + lock["tag"])
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": stage.ARCHIVE_NAME,
                         "digest": {"sha256": lock["asset"]["sha256"]}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {"workflow": {
                        "ref": "refs/tags/" + lock["tag"],
                        "repository": "https://github.com/" + lock["repository"],
                        "path": ".github/workflows/release-binaries.yml"}},
                    "internalParameters": {"github": {
                        "event_name": "release", "repository_id": "205255683",
                        "runner_environment": "github-hosted"}},
                    "resolvedDependencies": [{
                        "uri": "git+https://github.com/" + lock["repository"] +
                               "@refs/tags/" + lock["tag"],
                        "digest": {"gitCommit": lock["source_commit"]}}]},
                "runDetails": {"builder": {"id": identity}}}}

        def encoded(value):
            payload = base64.b64encode(json.dumps(value).encode()).decode()
            return json.dumps({"dsseEnvelope": {"payload": payload}}).encode()

        stage.validate_statement(lock, encoded(statement))
        for path, value in (("subject", [{"name": "other", "digest": {"sha256": "0" * 64}}]),
                            ("builder", {"id": identity + "-other"}),
                            ("commit", "0" * 40)):
            changed = copy.deepcopy(statement)
            if path == "subject":
                changed["subject"] = value
            elif path == "builder":
                changed["predicate"]["runDetails"]["builder"] = value
            else:
                changed["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = value
            with self.assertRaisesRegex(ValueError, "reviewed build"):
                stage.validate_statement(lock, encoded(changed))

    def test_bad_archive_rejected_without_output(self):
        lock, digest = stage.load_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            (raw / stage.ARCHIVE_NAME).write_bytes(b"changed release")
            output = root / "stage"
            preflight = {"checked_at_utc": "2026-09-30T00:00:00Z",
                         "eligible_at_utc": "2026-10-02T19:59:10Z"}
            with patch.object(stage, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "differs from reviewed identity"):
                    stage.stage(lock, digest, raw, output, preflight, True)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
