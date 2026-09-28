"""Account audit failures show names only and never shadow contents."""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "audit_rootfs_accounts", Path(__file__).with_name("audit-rootfs.py"))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class AccountMismatchDiagnosticTests(unittest.TestCase):
    def test_reviewed_root_cannot_change_shell_or_shadow_lock(self):
        reviewed = Path(__file__).resolve().parents[2] / "deploy/gcp/guest/rootfs/etc"
        with tempfile.TemporaryDirectory(prefix="root-account-audit-") as temporary:
            root = Path(temporary)
            etc = root / "etc"
            etc.mkdir()
            for name in ("passwd", "group", "shadow"):
                shutil.copyfile(reviewed / name, etc / name)
            audit.audit_accounts(root)
            changes = (
                ("passwd", "root:x:0:0::/root:/usr/sbin/nologin",
                 "root:x:0:0::/root:/bin/sh"),
                ("shadow", "root:!*:", "root:!:",),
                ("shadow", "root:!*:", "root:*:",),
                ("shadow", "root:!*:", "root:!other:",),
            )
            for name, old, new in changes:
                with self.subTest(name=name, change=new):
                    path = etc / name
                    original = path.read_text()
                    self.assertEqual(original.count(old), 1)
                    path.write_text(original.replace(old, new, 1))
                    with self.assertRaisesRegex(ValueError, "guest root login policy differs"):
                        audit.audit_accounts(root)
                    path.write_text(original)

    def test_name_difference_rejects_without_shadow_contents(self):
        with tempfile.TemporaryDirectory(prefix="account-audit-") as temporary:
            root = Path(temporary)
            etc = root / "etc"
            etc.mkdir()
            (etc / "passwd").write_text(
                "root:x:0:0:root:/root:/usr/sbin/nologin\n"
                "passwd-only:x:100:100::/nonexistent:/usr/sbin/nologin\n")
            (etc / "shadow").write_text(
                "root:!:0:0:99999:7:::\n"
                "shadow-only:!SECRET_CANARY:0:0:99999:7:::\n")
            (etc / "group").write_text("root:x:0:\n")
            with self.assertRaisesRegex(ValueError, "guest passwd and shadow accounts differ") as caught:
                audit.audit_accounts(root)
            message = str(caught.exception)
            self.assertIn("passwd_only=['passwd-only']", message)
            self.assertIn("shadow_only=['shadow-only']", message)
            self.assertNotIn("SECRET_CANARY", message)


if __name__ == "__main__":
    unittest.main()
