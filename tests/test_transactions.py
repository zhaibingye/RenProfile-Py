"""Transactions use temporary folders and a fake registry, never real profiles."""
from contextlib import contextmanager, nullcontext
import ctypes
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from renprofile.engine import Engine
from renprofile.errors import ManualRenameRequired, RenProfileError, ConflictError
from renprofile.host import Host
from renprofile.journal import Journal
from renprofile.model import Action, snapshot
from renprofile.native import Native
from renprofile.registry import Registry

SID = "S-1-5-21-1-2-3-1001"
KEY = r"Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + SID


class FakeRegistry(Registry):
    def __init__(self, old):
        self.values = {("SOFTWARE", KEY, "ProfileImagePath"): snapshot((2, old)),
                       ("USER", "Environment", "PATH"): snapshot((2, old + r"\bin"))}
        self.mount_depth, self.mount_calls, self.scans = 0, 0, 0
        self.fail_name = self.deny_probe = None
        self.partial_failure = False
        self.fail_unload_at = None
        self.mount_bases, self.writes = [], []
        self.mounts = {}

    def profiles(self):
        return [{"sid": SID, "path": self.values["SOFTWARE", KEY, "ProfileImagePath"]["data"]}]

    def get(self, root, key, name):
        return self.values.get((root, key, name))

    def set(self, root, key, name, value):
        if name == self.fail_name:
            self.fail_name = None  # recoverable single failure, not a denied rollback
            if self.partial_failure:
                self.values[root, key, name] = value
            raise PermissionError("simulated write denied")
        self.writes.append((name, self.mount_depth))
        self.values[root, key, name] = value

    def check_writable(self, action):
        if action.name == self.deny_probe:
            raise PermissionError("simulated access denied")

    @contextmanager
    def mounted(self, base, hives, journal=None):
        self.mount_depth += 1
        self.mount_calls += 1
        self.mount_bases.append(str(base))
        try:
            yield self
        finally:
            self.mount_depth -= 1
            if self.mount_calls == self.fail_unload_at:
                raise OSError("unload failed")

    def scan_fixture(self, registry, rewrite, hives):
        self.scans += 1
        actions = []
        for (root, key, name), before in self.values.items():
            if root == "USER":
                after = snapshot((before["kind"], rewrite.data(before["data"], before["kind"])))
                if before != after:
                    actions.append(Action("value", root, key, name, before, after))
        return actions, []


class FakeNative:
    def __init__(self):
        self.real = Native()
    def __getattr__(self, name):
        return getattr(self.real, name)
    def privileges(self):
        return nullcontext()
    def secure_directory(self, path):
        Path(path).mkdir()
    def short_path(self, path):
        return ""
    def clear_profile_locks(self, root, workspace, emit=lambda text: None):
        # Transaction fixtures never terminate processes on the test machine.
        return {"terminated": [], "remaining": [], "diagnostic": "fixture"}


class TestHost(Host):
    def __init__(self, registry):
        super().__init__(FakeNative(), registry)
        self.file_actions = []
        self.rename_failure = False
    def machine(self):
        return "isolated-test-machine"
    def lock(self):
        return nullcontext()
    def check_job(self, job):
        pass
    def require_offline(self, sid, path):
        if sid != SID or self.registry.profiles()[0]["path"] != str(path):
            raise ConflictError("wrong SID mapping")
    def preflight(self, old, new, sid, job):
        self.require_offline(sid, old)
        if not Path(old).is_dir() or os.path.lexists(new):
            raise RenProfileError("invalid automatic rename")
        return self.identity(old), r"SYSTEM\ControlSet001"
    def preflight_manual(self, old, new, sid, job):
        self.require_offline(sid, old)
        if os.path.lexists(old):
            self.check_junction(old, new)
        return self.identity(new), r"SYSTEM\ControlSet001"
    def transition_file(self, action, identity, undo=False):
        self.file_actions.append((action.kind, undo))
        if self.registry.mount_depth:
            raise AssertionError("directory operation with mounted hives")
        if action.kind == "directory" and not undo and self.rename_failure:
            raise PermissionError("directory locked")
        return super().transition_file(action, identity, undo)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="renprofile-v4-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.old, self.new, self.root = self.base / "亿洋", self.base / "YiYang", self.base / "jobs"
        self.old.mkdir()
        (self.old / "NTUSER.DAT").write_bytes(b"ordinary fixture, not a real hive")
        self.registry = FakeRegistry(str(self.old))
        self.host = TestHost(self.registry)
        self.logs = []
        self.engine = Engine(self.host, self.registry, emit=self.logs.append)
        self.original = self.registry.values.copy()
        self.scanner = patch("renprofile.engine.scan", side_effect=self.registry.scan_fixture)
        self.scanner.start()
        self.addCleanup(self.scanner.stop)
        # Remove only our temporary compatibility link, before tempdir cleanup.
        self.addCleanup(self.unlink)

    def unlink(self):
        if os.path.lexists(self.old) and os.path.isjunction(self.old):
            os.rmdir(self.old)

    def migrate(self):
        return self.engine.migrate(SID, str(self.new), self.root)

    def assert_restored(self):
        self.assertTrue(self.old.is_dir())
        self.assertFalse(os.path.isjunction(self.old))
        self.assertFalse(self.new.exists())
        self.assertEqual(self.registry.values, self.original)

    def last_job(self):
        return next(p for p in self.root.iterdir() if p.name.startswith("job-"))

    def test_success_renames_data_preserves_identity_and_commits_binding_last(self):
        identity = self.host.identity(self.old)
        result = self.migrate()
        self.assertEqual(self.host.identity(self.new), identity)
        self.assertEqual((self.old / "NTUSER.DAT").read_bytes(), b"ordinary fixture, not a real hive")
        self.assertEqual(self.registry.profiles()[0]["path"], str(self.new))
        self.assertEqual(self.registry.writes[-1], ("ProfileImagePath", 0))
        self.assertEqual(Journal.read_status(result["job"])["status"], "completed")
        plan = json.loads((result["job"] / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["actions"], [], "no reusable scan is persisted")
        self.assertEqual(plan["format"], 4)
        self.engine.rollback(result["job"])
        self.engine.rollback(result["job"])
        self.assert_restored()

    def test_required_binding_failure_restores_directory_and_optional_settings(self):
        self.registry.fail_name = "ProfileImagePath"
        with self.assertRaisesRegex(RenProfileError, "已回滚"):
            self.migrate()
        self.assert_restored()
        report = Journal.read_status(self.last_job())
        self.assertEqual(report["status"], "rolled_back")
        self.assertIn("ProfileImagePath", report["failure_context"])

    def test_occupants_are_released_before_loading_hives_and_again_after_a_new_lock(self):
        real_rename = self.host.native.real.rename_directory
        calls = []

        def release(root, workspace, emit):
            calls.append((str(root), self.registry.mount_depth))
            return {"terminated": [], "remaining": [], "diagnostic": "fixture"}

        attempts = []
        def rename(old, new):
            attempts.append((old, new))
            if len(attempts) == 1:
                raise ctypes.WinError(5)
            real_rename(old, new)

        with patch.object(self.host.native, "clear_profile_locks", side_effect=release), \
                patch.object(self.host.native, "rename_directory", side_effect=rename):
            result = self.migrate()
        self.assertEqual(calls, [(str(self.old), 0), (str(self.old), 0)])
        self.assertEqual(len(attempts), 2)
        self.assertEqual(Journal.read_status(result["job"])["status"], "completed")

    def test_repeated_denial_still_has_one_rename_intent_and_manual_fallback(self):
        with patch.object(self.host.native, "clear_profile_locks", wraps=self.host.native.clear_profile_locks) as release, \
                patch.object(self.host.native, "rename_directory", side_effect=ctypes.WinError(5)):
            with self.assertRaises(ManualRenameRequired) as caught:
                self.migrate()
        self.assertEqual(release.call_count, 3)
        with Journal(caught.exception.job) as journal:
            rows = journal.db.execute("SELECT action FROM actions").fetchall()
            self.assertEqual(sum(json.loads(raw)["kind"] == "directory" for (raw,) in rows), 1)
        self.assert_restored()

    def test_required_binding_permission_failure_is_before_scan_and_move(self):
        self.registry.deny_probe = "ProfileImagePath"
        with self.assertRaises(PermissionError):
            self.migrate()
        self.assertEqual(self.registry.scans, 0)
        self.assertFalse(self.root.exists())
        self.assert_restored()

    def test_optional_access_denied_during_precheck_preserves_setting_and_succeeds(self):
        self.registry.deny_probe = "PATH"
        result = self.migrate()
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(self.registry.get("USER", "Environment", "PATH"), self.original["USER", "Environment", "PATH"])
        self.host.check_junction(str(self.old), str(self.new))
        self.assertEqual(Journal.read_status(result["job"])["status"], "completed")

    def test_optional_write_denied_without_side_effect_can_be_preserved(self):
        self.registry.fail_name = "PATH"
        result = self.migrate()
        self.assertEqual(result["skipped"], 1)
        self.engine.rollback(result["job"])
        self.assert_restored()

    def test_partial_write_failure_is_never_mislabeled_as_a_skipped_setting(self):
        self.registry.fail_name, self.registry.partial_failure = "PATH", True
        with self.assertRaisesRegex(RenProfileError, "已回滚"):
            self.migrate()
        self.assert_restored()

    def test_locked_folder_never_changes_registry(self):
        self.host.rename_failure = True
        with self.assertRaisesRegex(RenProfileError, "已回滚"):
            self.migrate()
        self.assert_restored()
        self.assertEqual(self.registry.writes, [])

    def manual_request(self):
        with patch.object(self.host.native, "rename_directory", side_effect=ctypes.WinError(5)):
            with self.assertRaises(ManualRenameRequired) as caught:
                self.migrate()
        return caught.exception

    def test_real_child_lock_offers_manual_continue_after_releasing_software_hives(self):
        handle = self.host.native.create_file(str(self.old / "NTUSER.DAT"), 0x80000000, 3, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            with self.assertRaises(ManualRenameRequired) as caught:
                self.migrate()
        finally:
            self.host.native.close(handle)
        request = caught.exception
        self.assertEqual(self.registry.mount_depth, 0)
        self.assertEqual(self.registry.writes, [])
        self.assert_restored()
        report = Journal.read_status(request.job)
        self.assertEqual(report["status"], "rolled_back")
        self.assertTrue(report["manual_rename_pending"])

    def test_continue_before_manual_rename_does_not_rescan_or_create_another_job(self):
        request = self.manual_request()
        with self.assertRaisesRegex(RenProfileError, "还没有检测到"):
            self.engine.migrate(SID, str(self.new), self.root, manual_job=request.job)
        self.assertEqual(self.registry.scans, 1)
        self.assertEqual(len(list(self.root.iterdir())), 1)
        self.assert_restored()

    def test_manual_continue_uses_fresh_scan_and_never_attempts_directory_rename_again(self):
        request = self.manual_request()
        self.old.rename(self.new)
        self.registry.values["USER", "Environment", "PATH"] = snapshot((2, str(self.old) + r"\updated"))
        with patch.object(self.host.native, "rename_directory", side_effect=AssertionError("must not rename twice")):
            result = self.engine.migrate(SID, str(self.new), self.root, manual_job=request.job)
        self.assertNotEqual(str(result["job"]), request.job)
        self.assertEqual(self.registry.scans, 2)
        self.assertEqual(self.registry.mount_bases[-2:], [str(self.new), str(self.new)])
        self.assertEqual(self.registry.get("USER", "Environment", "PATH")["data"], str(self.new) + r"\updated")
        self.assertEqual(self.registry.profiles()[0]["path"], str(self.new))

    def test_manual_continue_rejects_a_different_folder_even_with_an_ntuser_file(self):
        request = self.manual_request()
        self.old.rename(self.base / "original-saved-elsewhere")
        self.new.mkdir()
        (self.new / "NTUSER.DAT").write_bytes(b"wrong folder")
        with self.assertRaisesRegex(RenProfileError, "不是原来那个"):
            self.engine.migrate(SID, str(self.new), self.root, manual_job=request.job)
        self.assertEqual(self.registry.writes, [])
        self.assertEqual(self.registry.scans, 1)

    def test_restart_and_402_failure_record_can_be_adopted_without_cached_scan(self):
        request = self.manual_request()
        with Journal(request.job) as journal:
            journal.db.execute("DELETE FROM meta WHERE key='manual_rename_pending'")
            journal.db.commit()
        self.old.rename(self.new)
        result = self.migrate()  # No in-memory request and no explicit manual_job.
        self.assertEqual(result["manual_source"], request.job)
        self.assertEqual(self.registry.scans, 2)

    def test_failed_rollback_never_offers_manual_continue(self):
        with patch.object(self.host.native, "rename_directory", side_effect=ctypes.WinError(5)), \
                patch.object(self.engine, "_rollback", side_effect=RenProfileError("recovery blocked")):
            with self.assertRaisesRegex(RenProfileError, "自动恢复未完成") as caught:
                self.migrate()
        self.assertNotIsInstance(caught.exception, ManualRenameRequired)
        self.assertEqual(Journal.read_status(self.last_job())["status"], "recovery_required")

    def test_scan_unload_failure_is_before_rename(self):
        self.registry.fail_unload_at = 1
        with self.assertRaisesRegex(RenProfileError, "卸载扫描"):
            self.migrate()
        self.assert_restored()
        self.assertEqual(self.host.file_actions, [])

    def test_update_unload_failure_restores_before_binding_commit(self):
        self.registry.fail_unload_at = 2
        with self.assertRaisesRegex(RenProfileError, "卸载更新"):
            self.migrate()
        self.assert_restored()
        self.assertNotIn("ProfileImagePath", [name for name, depth in self.registry.writes])

    def test_real_mount_cleanup_logic_never_marks_failed_unload_as_rolled_back(self):
        self.registry.w = Mock(HKEY_USERS=123)
        self.registry.native = Mock()
        self.registry.native.unload.return_value = 5
        mounted = Registry.mounted.__get__(self.registry, Registry)
        with patch.object(self.registry, "mounted", mounted):
            with self.assertRaisesRegex(RenProfileError, "自动恢复未完成"):
                self.migrate()
        job = self.last_job()
        self.assertEqual(Journal.read_status(job)["status"], "recovery_required")
        self.assertEqual(self.host.file_actions, [])
        self.registry.mounts.clear()  # A subsequent app process only has the journal.
        self.registry.native.unload.return_value = 0
        self.engine.rollback(job)
        self.assertEqual(Journal.read_status(job)["status"], "rolled_back")
        self.assert_restored()

    def test_retry_uses_new_job_and_scans_fresh_values(self):
        self.registry.fail_name = "ProfileImagePath"
        with self.assertRaises(RenProfileError):
            self.migrate()
        first = self.last_job()
        self.registry.values["USER", "Environment", "PATH"] = snapshot((2, str(self.old) + r"\changed"))
        result = self.migrate()
        self.assertNotEqual(first, result["job"])
        self.assertEqual(self.registry.scans, 2)
        self.assertEqual(self.registry.get("USER", "Environment", "PATH")["data"], str(self.new) + r"\changed")
        self.assertEqual(Journal.read_status(first)["status"], "rolled_back")

    def test_previous_manual_rename_is_adopted_without_second_directory_move(self):
        self.old.rename(self.new)
        result = self.migrate()
        self.assertNotIn(("directory", False), self.host.file_actions)
        self.assertEqual(self.registry.profiles()[0]["path"], str(self.new))
        self.engine.rollback(result["job"])
        self.assertTrue(self.new.is_dir())
        self.host.check_junction(str(self.old), str(self.new))
        self.assertEqual(self.registry.values, self.original)

    def test_interrupted_intent_after_move_recovers_from_disk_without_rescanning(self):
        result = self.migrate()
        job = result["job"]
        with Journal(job) as journal:
            journal.set("status", "applying")
            journal.db.execute("UPDATE actions SET state='pending'")
            journal.db.commit()
        scanner_count = self.registry.scans
        self.engine.rollback(job)
        self.assert_restored()
        self.assertEqual(self.registry.scans, scanner_count)

    def test_legacy_manual_record_undoes_state_repository_write_using_original_value(self):
        self.old.rename(self.new)
        self.root.mkdir()
        job = self.root / "legacy"
        job.mkdir()
        plan = {"format": 2, "machine": self.host.machine(), "old": str(self.old), "new": str(self.new),
                "sid": SID, "identity": self.host.identity(self.new), "manual_rename": True,
                "hive_files": {"USER": "NTUSER.DAT"}, "system_path": r"SYSTEM\ControlSet001"}
        (job / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        action = Action("value", "SOFTWARE", r"Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache", "Path",
                        snapshot((1, str(self.old))), snapshot((1, str(self.new))))
        self.registry.values[action.root, action.key, action.name] = action.after
        with Journal(job, create=True) as journal:
            journal.intent(action)
        self.engine.rollback(job)
        self.assertEqual(self.registry.get(action.root, action.key, action.name), action.before)
        self.host.check_junction(str(self.old), str(self.new))


if __name__ == "__main__":
    unittest.main()
