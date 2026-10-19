"""Legacy tool-folder ACL compatibility. Real changes stay in temporary folders."""

from contextlib import nullcontext
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from renprofile.errors import OperationError, RenProfileError
from renprofile.host import Host
from renprofile.native import Native, JOB_SDDL


class StoragePermissionTests(unittest.TestCase):
    def setUp(self):
        self.native = Native()
        self.sid = self.native.current_sid()
        self.temp = tempfile.TemporaryDirectory(prefix="renprofile-storage-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "RenProfile-Py"
        self.root.mkdir()

    def descriptor(self, acl):
        return self.native.security_descriptor("O:" + self.sid + acl)

    def test_equivalent_allow_order_and_current_maintenance_account_are_accepted(self):
        for acl in (
                "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",
                "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)",
                JOB_SDDL + "(A;OICI;FA;;;" + self.sid + ")"):
            with self.subTest(acl=acl):
                descriptor = self.descriptor(acl)
                with patch.object(self.native, "security", return_value=descriptor):
                    Host(self.native, None).check_job(self.root)

    def test_inherited_unprotected_or_publicly_writable_acl_requires_repair(self):
        for acl in (
                "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                JOB_SDDL + "(A;OICI;FA;;;BU)",
                "D:P(A;OICI;FA;;;SY)"):
            with self.subTest(acl=acl):
                self.assertFalse(Host.private_dacl(self.descriptor(acl), self.sid))

    def test_legacy_owner_from_a_different_account_is_normalized_automatically(self):
        old = self.native.security_descriptor("O:S-1-5-21-1-2-3-1001" + JOB_SDDL)
        repaired = self.native.security_descriptor("O:BA" + JOB_SDDL)
        proxy = Mock(wraps=self.native)
        proxy.privileges.return_value = nullcontext()
        proxy.security.side_effect = [old, repaired]
        proxy.repair_directory_security.return_value = None
        Host(proxy, None).prepare_storage(self.root)
        proxy.repair_directory_security.assert_called_once_with(self.root)

    def test_native_repair_uses_administrators_owner_and_does_not_propagate(self):
        def verify(handle, object_type, flags, owner, group, dacl, sacl):
            self.assertEqual(object_type, 1)
            self.assertEqual(flags, 0x80000005)
            self.assertEqual(self.native.sid_text(owner), "S-1-5-32-544")
            self.assertTrue(dacl)
            return 0
        with patch.object(self.native, "set_security_info", side_effect=verify), \
                patch.object(self.native, "create_file", wraps=self.native.create_file) as opened:
            self.native.repair_directory_security(self.root)
        self.assertEqual(opened.call_args.args[1], 0x02000000)

    def test_native_acl_repair_preserves_child_and_external_link_target_permissions(self):
        child = self.root / "old-record.txt"
        child.write_bytes(b"original recovery data")
        child_dir = self.root / "child"
        child_dir.mkdir()
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        link = self.root / "external-link"
        self.native.junction(link, outside)
        before = {str(p): self.native.security(p) for p in (child, child_dir, outside)}
        # Grant the test runner itself access so this test needs no elevation.
        template = self.native.security_descriptor(JOB_SDDL + "(A;OICI;FA;;;" + self.sid + ")")
        try:
            self.native.set_directory_security(self.root, template)
            Host(self.native, None).check_job(self.root)
            self.assertEqual({str(p): self.native.security(p) for p in (child, child_dir, outside)}, before)
            self.assertEqual(child.read_bytes(), b"original recovery data")
        finally:
            os.rmdir(link)

    def test_startup_preparation_repairs_inherited_acl_and_keeps_old_records(self):
        record = self.root / "old-recovery.json"
        record.write_text("keep")
        proxy = Mock(wraps=self.native)
        proxy.privileges.return_value = nullcontext()
        template = self.native.security_descriptor(JOB_SDDL + "(A;OICI;FA;;;" + self.sid + ")")
        proxy.repair_directory_security.side_effect = lambda p: self.native.set_directory_security(p, template)
        Host(proxy, None).prepare_storage(self.root)
        self.assertEqual(record.read_text(), "keep")
        Host(proxy, None).prepare_storage(self.root)
        proxy.repair_directory_security.assert_called_once()

    def test_repair_failure_identifies_exact_tool_directory(self):
        proxy = Mock(wraps=self.native)
        proxy.privileges.return_value = nullcontext()
        proxy.repair_directory_security.side_effect = PermissionError("test denial")
        with self.assertRaises(OperationError) as caught:
            Host(proxy, None).prepare_storage(self.root)
        self.assertIn(str(self.root), str(caught.exception))

    def test_missing_managed_recovery_record_is_never_created(self):
        missing = self.root / "job-20261019-000000-aaaaaaaaaaaa"
        with patch.dict(os.environ, {"ProgramData": self.temp.name}):
            with self.assertRaises(RenProfileError):
                Host(self.native, None).prepare_record(missing)
        self.assertFalse(missing.exists())
