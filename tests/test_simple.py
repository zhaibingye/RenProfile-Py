import json
import ctypes
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import sqlite3
import unittest
from unittest.mock import Mock, patch

from renprofile.engine import Engine
from renprofile.errors import ManualRenameRequired, RenProfileError
from renprofile.journal import Journal
from renprofile.simple import SimpleService, new_folder_path
from test_transactions import FakeRegistry, TestHost, SID


class SimpleWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="renprofile-simple-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.old, self.new = self.base / "Old", self.base / "New"
        self.old.mkdir()
        (self.old / "NTUSER.DAT").write_bytes(b"fake hive, never mounted")
        self.registry = FakeRegistry(str(self.old))
        self.host = TestHost(self.registry)
        self.engine = Engine(self.host, self.registry, emit=lambda text: None)
        self.service = SimpleService(self.engine, self.base / "jobs")
        self.profile = {"sid": SID, "path": str(self.old)}
        scanner = patch("renprofile.engine.scan", side_effect=self.registry.scan_fixture)
        scanner.start()
        self.addCleanup(scanner.stop)
        self.addCleanup(self.unlink)

    def unlink(self):
        if os.path.lexists(self.old) and os.path.isjunction(self.old):
            os.rmdir(self.old)

    def failed_job(self):
        self.registry.fail_name = "ProfileImagePath"
        with self.assertRaises(RenProfileError):
            self.service.migrate(self.profile, "New")
        return next(self.service.root.iterdir())

    def test_success_removes_only_its_records_and_empty_root(self):
        result = self.service.migrate(self.profile, "New")
        self.assertTrue(result.cleaned)
        self.assertFalse(self.service.root.exists())
        self.assertTrue(self.new.is_dir())
        self.assertTrue(os.path.samefile(self.old, self.new))

    def test_failure_keeps_original_values_for_recovery(self):
        job = self.failed_job()
        self.assertTrue((job / "journal.sqlite3").is_file())
        record = self.service.pending()[0]
        self.assertEqual(record["state"], "rolled_back")
        self.assertIn("ProfileImagePath", record["diagnostic"])
        self.assertEqual(record["sid"], SID)
        with self.assertRaises(RenProfileError):
            self.service.cleanup(job)

    def test_explicit_restore_cleans_rolled_back_record(self):
        job = self.failed_job()
        self.service.restore(job)
        self.assertFalse(job.exists())
        self.assertTrue(self.old.is_dir())

    def test_success_after_failed_attempt_creates_fresh_scan_and_preserves_failure_record(self):
        failed = self.failed_job()
        result = self.service.migrate(self.profile, "New")
        self.assertTrue(result.cleaned)
        self.assertTrue(failed.exists())
        self.assertEqual(self.registry.scans, 2)

    def test_manual_continue_success_cleans_both_automatic_attempt_and_new_job(self):
        with patch.object(self.host.native, "rename_directory", side_effect=ctypes.WinError(5)):
            with self.assertRaises(ManualRenameRequired) as caught:
                self.service.migrate(self.profile, "New")
        request = caught.exception
        self.old.rename(self.new)
        result = self.service.continue_manual(request.job)
        self.assertTrue(result.cleaned)
        self.assertFalse(self.service.root.exists())
        self.assertTrue(self.new.is_dir())
        self.assertTrue(os.path.samefile(self.old, self.new))

    def test_failure_after_manual_continue_keeps_users_rename_and_recovery_data(self):
        with patch.object(self.host.native, "rename_directory", side_effect=ctypes.WinError(5)):
            with self.assertRaises(ManualRenameRequired) as caught:
                self.service.migrate(self.profile, "New")
        self.old.rename(self.new)
        self.registry.fail_name = "ProfileImagePath"
        with self.assertRaisesRegex(RenProfileError, "手动改好的文件夹保持不变"):
            self.service.continue_manual(caught.exception.job)
        self.assertTrue(self.new.is_dir())
        self.assertTrue(os.path.samefile(self.old, self.new))
        self.assertEqual(self.registry.profiles()[0]["path"], str(self.old))
        self.assertTrue(Path(caught.exception.job).is_dir())

    def test_interrupted_operation_requires_recovery_instead_of_blind_replay(self):
        failed = self.failed_job()
        with Journal(failed) as journal:
            journal.set("status", "applying")
        with self.assertRaisesRegex(RenProfileError, "先点击"):
            self.service.migrate(self.profile, "New")
        self.assertEqual(self.registry.scans, 1)

    def test_corrupt_journal_keeps_sid_and_blocks_new_work_for_that_user(self):
        failed = self.failed_job()
        (failed / "journal.sqlite3").write_bytes(b"damaged recovery log")
        record = self.service.pending()[0]
        self.assertEqual(record.get("sid"), SID)
        self.assertEqual(record["state"], "unknown")
        with self.assertRaises(RenProfileError):
            self.service.migrate(self.profile, "New")
        self.assertEqual(self.registry.scans, 1)

    def test_engine_checks_unfinished_jobs_even_without_gui_service(self):
        failed = self.failed_job()
        with Journal(failed) as journal:
            journal.set("status", "recovery_required")
        with self.assertRaises(RenProfileError):
            self.engine.migrate(SID, str(self.new), self.service.root)
        self.assertEqual(self.registry.scans, 1)

    def test_cleanup_failure_is_not_reported_as_failed_migration(self):
        with patch("renprofile.simple.shutil.rmtree", side_effect=PermissionError("locked backup")):
            result = self.service.migrate(self.profile, "New")
        self.assertFalse(result.cleaned)
        self.assertEqual(Journal.read_status(result.job)["status"], "completed")
        self.assertEqual(self.service.pending(), [])
        self.assertFalse(self.service.root.exists())

    def test_partial_backup_deletion_is_only_retried_as_cleanup(self):
        def partial_delete(target):
            (Path(target) / "plan.json").unlink()
            raise PermissionError("simulated partial cleanup")
        with patch("renprofile.simple.shutil.rmtree", side_effect=partial_delete):
            result = self.service.migrate(self.profile, "New")
        self.assertFalse(result.cleaned)
        self.assertTrue(Path(result.job).name.startswith("cleanup-"))
        self.assertFalse((Path(result.job) / "plan.json").exists())
        with patch.object(self.engine, "rollback", side_effect=AssertionError("cleanup must not roll back")):
            self.service.restore(result.job)
        self.assertTrue(self.new.is_dir())
        self.assertFalse(Path(result.job).exists())

    def test_explicit_recovery_repairs_a_hot_sqlite_journal_after_process_crash(self):
        job = self.failed_job()
        with Journal(job) as journal:
            journal.set("status", "applying")
            journal.set("last_error", "before-crash")
        code = """import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute('PRAGMA cache_size=1')
c.execute('PRAGMA synchronous=FULL')
c.execute('BEGIN IMMEDIATE')
c.execute('UPDATE meta SET value=? WHERE key=?', ('x' * 2000000, 'last_error'))
os._exit(0)
"""
        subprocess.run([sys.executable, "-B", "-c", code, str(job / "journal.sqlite3")], check=True, timeout=15)
        with self.assertRaises(sqlite3.OperationalError):
            Journal.read_status(job)
        self.service.restore(job)
        self.assertTrue(self.old.is_dir())
        self.assertFalse(self.new.exists())
        self.assertFalse(job.exists())

    def test_completed_job_restore_only_cleans_does_not_undo_success(self):
        with patch.object(self.service, "cleanup", side_effect=PermissionError("locked")):
            result = self.service.migrate(self.profile, "New")
        with patch.object(self.engine, "rollback", side_effect=AssertionError("must not undo success")):
            self.service.restore(result.job)
        self.assertTrue(self.new.is_dir())
        self.assertFalse(Path(result.job).exists())

    def test_cleanup_rejects_outside_directory(self):
        self.failed_job()
        outside = self.base / "job-20261018-000000-aaaaaaaaaaaa"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep")
        with self.assertRaises(RenProfileError):
            self.service.cleanup(outside)
        self.assertEqual((outside / "keep.txt").read_text(), "keep")

    def test_cleanup_rejects_junction_without_touching_destination(self):
        job = self.failed_job()
        link = job / "unexpected"
        self.host.native.junction(link, self.old)
        try:
            with self.assertRaises(RenProfileError):
                self.service.cleanup(job)
            self.assertTrue((self.old / "NTUSER.DAT").exists())
        finally:
            os.rmdir(link)

    def test_stale_gui_path_is_not_used_as_scan_source(self):
        result = self.service.migrate({"sid": SID, "path": r"C:\Users\NotThisUser"}, "New")
        self.assertEqual(result.old, str(self.old))
        self.assertEqual(self.registry.mount_bases[0], str(self.old))

    def test_invalid_names_fail_before_backups(self):
        for name in ("", r"C:\Users\New", r"sub\New", "CON", "Old"):
            with self.subTest(name=name), self.assertRaises(RenProfileError):
                self.service.migrate(self.profile, name)
        self.assertFalse(self.service.root.exists())
        self.assertEqual(new_folder_path(r"C:\Users\Old", " New "), r"C:\Users\New")


class GuiWorkflowTests(unittest.TestCase):
    def test_no_arguments_opens_gui(self):
        from renprofile.cli import main
        with patch("renprofile.gui.main", return_value=0) as gui:
            self.assertEqual(main([]), 0)
            gui.assert_called_once_with()

    def test_gui_never_mixes_history_into_current_details(self):
        import tkinter as tk
        from renprofile.gui import App
        root = tk.Tk()
        root.withdraw()
        service = Mock()
        service.profiles.return_value = [{"path": r"C:\Users\Example", "sid": "internal-sid"}]
        service.pending.side_effect = AssertionError("refresh must not load history")
        app = App(root, service)
        try:
            root.update_idletasks()
            self.assertEqual(app.logs, [])
            self.assertEqual(app.start_button["text"], "开始改名")
            self.assertNotIn("internal-sid", app.user_box["values"][0])
            app.refresh()
            service.pending.assert_not_called()
            app.name.set("NewName")
            self.assertIn(r"C:\Users\NewName", app.preview.get())
            self.assertEqual(str(app.start_button["state"]), "normal")
            height = int(root.geometry().split("x")[1].split("+")[0])
            self.assertLessEqual(root.winfo_reqheight(), height)
            app.logs.append("previous attempt")
            with patch("renprofile.gui.threading.Thread"):
                app.run_task(lambda: None, "migrate")
            self.assertNotIn("previous attempt", "\n".join(app.logs))
        finally:
            app.busy = False
            app.close()

    def test_manual_fallback_dialog_continues_without_repeated_error_popups(self):
        import tkinter as tk
        from renprofile.gui import App
        from renprofile.simple import MigrationResult
        root = tk.Tk()
        root.withdraw()
        service = Mock()
        service.profiles.return_value = [{"path": r"C:\Users\Old", "sid": SID}]
        app = App(root, service)
        request = ManualRenameRequired(SID, r"C:\Users\Old", r"C:\Users\New", "saved-manual-job")
        try:
            with patch("renprofile.gui.messagebox.showerror") as errors, patch("renprofile.gui.messagebox.showinfo"):
                app.events.put(("error", request))
                app.poll()
                self.assertIs(app.manual_request, request)
                self.assertEqual(app.manual_button["text"], "我已改名，继续迁移")
                with patch.object(app, "run_task") as run:
                    app.manual_button.invoke()
                    action, kind = run.call_args.args
                    self.assertEqual(kind, "manual_migrate")
                    action()
                self.assertEqual(service.continue_manual.call_args.args[0], request.job)
                app.events.put(("error", RenProfileError("还没有检测到手动改名完成")))
                app.poll()
                self.assertIn("还没有检测到", app.manual_hint.get())
                self.assertEqual(str(app.manual_button["state"]), "normal")
                app.events.put(("manual_migrate", MigrationResult(request.old, request.new, 0, True)))
                app.poll()
                self.assertIsNone(app.manual_window)
                self.assertIsNone(app.manual_request)
                errors.assert_not_called()
        finally:
            app.busy = False
            app.close()
