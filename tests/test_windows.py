"""Real Windows smoke checks confined to temporary files. No registry writes."""

import os
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import Mock

from renprofile.host import Host
from renprofile.errors import DirectoryRenameError, RenProfileError
from renprofile.model import Action


@unittest.skipUnless(os.name == "nt", "Windows APIs")
class WindowsSmokeTests(unittest.TestCase):
    def setUp(self):
        from renprofile.native import Native
        self.native = Native()
        self.tmp = tempfile.TemporaryDirectory(prefix="renprofile-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_token_unicode_shortpath_and_security(self):
        self.assertRegex(self.native.current_sid(), r"^S-1-")
        self.assertIsInstance(self.native.elevated(), bool)
        self.assertTrue(self.native.security(self.root))
        self.assertTrue(Host.dacl(self.native.job_security()))
        self.assertRegex(self.native.descriptor_owner(self.native.security(self.root)), r"^S-1-")
        target = self.root / "旧 用户 $1"
        target.mkdir()
        short = self.native.short_path(str(target))
        if short:
            self.assertTrue(os.path.samefile(short, target))

    def test_real_junction_and_rename_preserve_directory_identity(self):
        host = Host(self.native, None)
        old, new = self.root / "旧用户", self.root / "新用户 $1"
        old.mkdir()
        (old / "keep.txt").write_text("same data", encoding="utf-8")
        identity = host.identity(old)
        folder = Action("directory", before=str(old), after=str(new))
        link = Action("junction", name=str(old), after=str(new))
        host.transition_file(folder, identity)
        self.assertEqual(host.identity(new), identity)
        try:
            host.transition_file(link, identity)
            self.assertEqual((old / "keep.txt").read_text(encoding="utf-8"), "same data")
            host.transition_file(link, identity)  # existing correct link is safe
            host.transition_file(link, identity, undo=True)
            self.assertTrue((new / "keep.txt").exists())
        finally:
            if os.path.lexists(old) and os.lstat(old).st_reparse_tag == 0xA0000003:
                os.rmdir(old)
        host.transition_file(folder, identity, undo=True)
        self.assertEqual(host.identity(old), identity)
        self.assertTrue((old / "keep.txt").exists())

    def test_read_only_registry_open_and_machine_identifier(self):
        from renprofile.registry import Registry
        registry = Registry(self.native)
        with registry.open("SOFTWARE", r"Microsoft\Windows\CurrentVersion") as key:
            self.assertGreaterEqual(registry.w.QueryInfoKey(key)[0], 0)
        self.assertTrue(Host(self.native, registry).machine())

    def test_locked_child_reproduces_access_denied_then_rename_succeeds_after_release(self):
        """A child held by another process can yield error 5, even with full ACLs."""
        from ctypes import wintypes as w
        old, new = self.root / "亿洋", self.root / "YiYang"
        old.mkdir()
        hive = old / "NTUSER.DAT"
        hive.write_bytes(b"ordinary test file, not a real user hive")
        host = Host(self.native, None)
        identity = host.identity(old)
        handle = self.native.create_file(str(hive), 0x80000000, 0x3, None, 3, 0, None)
        self.assertNotEqual(handle, w.HANDLE(-1).value)
        action = Action("directory", before=str(old), after=str(new))
        try:
            # A root-only access probe is insufficient to rule out child locks.
            self.native.probe_directory_rename(old)
            with self.assertRaises(DirectoryRenameError) as caught:
                host.transition_file(action, identity)
            self.assertEqual(caught.exception.winerror, 5)
            self.assertTrue(old.is_dir())
            self.assertFalse(new.exists())
            self.assertEqual(host.identity(old), identity)
            self.assertIn(os.getpid(), {p["pid"] for p in caught.exception.users})
        finally:
            self.native.close(handle)
        host.transition_file(action, identity)
        self.assertEqual(host.identity(new), identity)
        self.assertEqual((new / "NTUSER.DAT").read_bytes(), b"ordinary test file, not a real user hive")

    def test_directory_probe_detects_a_handle_without_delete_sharing(self):
        from ctypes import wintypes as w
        old = self.root / "held-directory"
        old.mkdir()
        handle = self.native.create_file(str(old), 0x80000000, 0x3, None, 3, 0x02000000, None)
        self.assertNotEqual(handle, w.HANDLE(-1).value)
        try:
            with self.assertRaises(OSError) as caught:
                self.native.probe_directory_rename(old)
            self.assertEqual(caught.exception.winerror, 32)
            self.assertTrue(old.is_dir())
        finally:
            self.native.close(handle)
        self.native.probe_directory_rename(old)

    def test_native_rename_never_replaces_an_existing_target(self):
        old, new = self.root / "old", self.root / "occupied"
        old.mkdir()
        new.mkdir()
        (old / "data.txt").write_text("source", encoding="utf-8")
        (new / "keep.txt").write_text("target", encoding="utf-8")
        with self.assertRaises(OSError):
            self.native.rename_directory(old, new)
        self.assertEqual((old / "data.txt").read_text(encoding="utf-8"), "source")
        self.assertEqual((new / "keep.txt").read_text(encoding="utf-8"), "target")

    def test_process_enumeration_includes_this_test_process(self):
        processes = self.native.processes_for(self.native.current_sid())
        self.assertIn(os.getpid(), {pid for pid, _ in processes})

    def manual_fixture(self):
        old, new, job = self.root / "亿洋", self.root / "YiYang", self.root / "job"
        new.mkdir()
        (new / "NTUSER.DAT").write_bytes(b"temporary test data, not a real hive")
        registry = Mock()
        registry.profiles.return_value = [{"sid": "test-offline-sid", "path": str(old)}]
        registry.w.OpenKey.return_value = nullcontext()
        registry.w.QueryValueEx.return_value = (1, 4)
        native = Mock(wraps=self.native)
        native.probe_directory_rename.side_effect = AssertionError("must not request rename access")
        native.rename_directory.side_effect = AssertionError("must never rename")
        host = Host(native, registry)
        host.require_offline = Mock()  # No real profile/SID access in these tests.
        return host, old, new, job

    def test_manual_preflight_uses_existing_new_folder_without_rename_access(self):
        host, old, new, job = self.manual_fixture()
        from ctypes import wintypes as w
        handle = self.native.create_file(str(new / "NTUSER.DAT"), 0x80000000, 0x3, None, 3, 0, None)
        self.assertNotEqual(handle, w.HANDLE(-1).value)
        try:
            identity, control_set = host.preflight_manual(str(old), str(new), "test-offline-sid", job)
            self.assertEqual(identity, host.identity(new))
            self.assertEqual(control_set, r"SYSTEM\ControlSet001")
            host.native.probe_directory_rename.assert_not_called()
            host.native.rename_directory.assert_not_called()
            self.assertFalse(old.exists())
        finally:
            self.native.close(handle)

    def test_manual_preflight_rejects_an_unrenamed_or_wrong_destination(self):
        host, old, new, job = self.manual_fixture()
        with self.assertRaisesRegex(RenProfileError, "请先手动改好"):
            host.preflight_manual(str(old), str(self.root / "missing"), "test-offline-sid", job)
        old.mkdir()
        (old / "keep.txt").write_text("do not touch", encoding="utf-8")
        with self.assertRaisesRegex(RenProfileError, "原文件夹仍在"):
            host.preflight_manual(str(old), str(new), "test-offline-sid", job)
        self.assertEqual((old / "keep.txt").read_text(encoding="utf-8"), "do not touch")

    def test_manual_retry_accepts_its_compatibility_junction(self):
        host, old, new, job = self.manual_fixture()
        self.native.junction(old, new)
        try:
            identity, _ = host.preflight_manual(str(old), str(new), "test-offline-sid", job)
            self.assertEqual(identity, host.identity(new))
            self.assertTrue(os.path.samefile(old, new))
        finally:
            os.rmdir(old)  # Only the temporary compatibility link.

    def test_manual_preflight_leaves_a_junction_to_another_folder_untouched(self):
        host, old, new, job = self.manual_fixture()
        other = self.root / "other"
        other.mkdir()
        self.native.junction(old, other)
        try:
            with self.assertRaises(RenProfileError):
                host.preflight_manual(str(old), str(new), "test-offline-sid", job)
            self.assertTrue(os.path.samefile(old, other))
        finally:
            os.rmdir(old)


if __name__ == "__main__":
    unittest.main()
