from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from renprofile.cli import main
from renprofile.errors import RenProfileError
from renprofile.journal import Journal
from renprofile.model import Action, snapshot
from renprofile.registry import Registry
from renprofile.status import collect_status, format_status, gap_summary


def make_plan(gaps=None):
    return {"sid": "S-1-5-21-1-2-3-1001", "old": r"C:\Users\Old", "new": r"C:\Users\New",
            "keep_junction": True, "actions": [], "gaps": gaps or []}


def machine_gaps(count=1):
    return [{"root": "SYSTEM", "key": rf"Control\Class\{{test}}\Properties{i:03}",
             "error": "[WinError 5] 拒绝访问。"} for i in range(count)]


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="renprofile-status-test-")
        self.addCleanup(self.tmp.cleanup)
        self.job = Path(self.tmp.name)
        self.plan = make_plan(machine_gaps(120))
        (self.job / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")

    def test_default_summary_limits_examples_and_does_not_report_command_failure(self):
        output = format_status(collect_status(self.job, self.plan))
        self.assertIn("planned（仅生成记录，尚未执行改名）", output)
        self.assertIn("机器注册表 120，用户 hive 0", output)
        self.assertEqual(output.count("[WinError 5]"), 3)
        self.assertIn("不表示本次 status 命令执行失败", output)
        self.assertIn("重新扫描并建立新任务", output)
        self.assertFalse((self.job / "journal.sqlite3").exists())

    def test_full_gap_list_is_explicitly_requested(self):
        output = format_status(collect_status(self.job, self.plan), show_gaps=True)
        self.assertEqual(output.count("[WinError 5]"), 120)
        self.assertIn("Properties119", output)

    def test_json_retains_legacy_fields_and_full_diagnostics(self):
        report = collect_status(self.job, self.plan)
        decoded = json.loads(format_status(report, as_json=True))
        self.assertEqual(decoded["scan_gaps"], self.plan["gaps"])
        self.assertEqual(decoded["registry_actions"], 0)
        self.assertEqual(decoded["scan_gap_summary"]["machine"], 120)

    def test_user_hive_gaps_never_offer_bypass(self):
        self.plan["gaps"].append({"root": "USER", "key": "Protected", "error": "denied"})
        output = format_status(collect_status(self.job, self.plan))
        self.assertIn("此记录仅用于查看或恢复", output)
        self.assertNotIn("--allow-scan-gaps", output)

    def test_manual_simple_status_describes_settings_migration_and_actual_gap_policy(self):
        self.plan.update(manual_rename=True, simple=True)
        self.plan["gaps"].append({"root": "USER", "key": "Protected", "error": "denied"})
        output = format_status(collect_status(self.job, self.plan))
        self.assertIn("尚未迁移设置", output)
        self.assertIn("重新扫描并建立新任务", output)
        self.assertNotIn("当前计划不能执行", output)
        self.assertNotIn("默认 apply 会阻止执行", output)

    def test_unknown_gap_root_is_not_classified_as_machine(self):
        counts = gap_summary([{"root": "OTHER", "key": "x", "error": "unknown"}])
        self.assertEqual(counts["other"], 1)
        self.assertEqual(counts["machine"], 0)

    def test_completed_status_does_not_claim_that_it_has_not_run(self):
        with Journal(self.job, create=True) as journal:
            journal.set("status", "completed")
        output = format_status(collect_status(self.job, self.plan))
        self.assertIn("completed（执行日志显示已完成）", output)
        self.assertNotIn("尚未执行改名", output)
        self.assertNotIn("默认 apply 会阻止执行", output)

    def test_recovery_state_preserves_original_error_and_advises_rollback(self):
        with Journal(self.job, create=True) as journal:
            journal.set("status", "recovery_required")
            journal.set("recovery_error", "simulated recovery block")
        output = format_status(collect_status(self.job, self.plan))
        self.assertIn("点击“恢复”", output)
        self.assertIn("simulated recovery block", output)
        self.assertNotIn("可选择 apply", output)

    def test_existing_journal_is_opened_in_read_only_mode_and_left_unchanged(self):
        with Journal(self.job, create=True) as journal:
            journal.set("status", "rolled_back")
        before = (self.job / "journal.sqlite3").read_bytes()
        original_connect = sqlite3.connect
        with patch("renprofile.journal.sqlite3.connect", wraps=original_connect) as connect:
            self.assertEqual(Journal.read_status(self.job)["status"], "rolled_back")
        self.assertIn("mode=ro", connect.call_args.args[0])
        self.assertTrue(connect.call_args.kwargs["uri"])
        self.assertEqual((self.job / "journal.sqlite3").read_bytes(), before)

    def test_legacy_rolled_back_journal_reveals_last_action_as_a_clue_without_values(self):
        action = Action("value", "SOFTWARE", r"Vendor\Protected", "InstallPath",
                        snapshot((2, "private-original")), snapshot((2, "private-new")))
        with Journal(self.job, create=True) as journal:
            seq = journal.intent(action)
            journal.mark(seq, "undone")
            journal.set("status", "rolled_back")
            journal.set("last_error", "[WinError 5] denied")
        before = (self.job / "journal.sqlite3").read_bytes()
        report = collect_status(self.job, self.plan)
        output = format_status(report)
        self.assertIn(r"HKLM\SOFTWARE\Vendor\Protected", output)
        self.assertIn("InstallPath", output)
        self.assertIn("定位线索", output)
        self.assertIn("可能在其后的", output)
        self.assertNotIn("private-original", json.dumps(report))
        self.assertNotIn("private-new", json.dumps(report))
        self.assertEqual((self.job / "journal.sqlite3").read_bytes(), before)

    def test_precise_unload_failure_does_not_blame_last_successful_registry_write(self):
        with Journal(self.job, create=True) as journal:
            journal.intent(Action("value", "USER", "Environment", "PATH", None, snapshot((2, "value"))))
            journal.set("status", "recovery_required")
            journal.set("failure_context", "卸载用户注册表文件：new-folder")
        output = format_status(collect_status(self.job, self.plan))
        self.assertIn("失败步骤：卸载用户注册表文件", output)
        self.assertNotIn("旧版日志最后记录的操作", output)

    def test_invalid_database_is_not_silently_repaired_or_marked_planned(self):
        path = self.job / "journal.sqlite3"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.commit()
        connection.close()
        before = path.read_bytes()
        with self.assertRaises(sqlite3.OperationalError):
            Journal.read_status(self.job)
        self.assertEqual(path.read_bytes(), before)

    def test_recovery_open_does_not_create_tables_in_an_unrecognized_database(self):
        path = self.job / "journal.sqlite3"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.commit()
        connection.close()
        before = path.read_bytes()
        with self.assertRaises(sqlite3.OperationalError):
            Journal(self.job)
        self.assertEqual(path.read_bytes(), before)
        path.unlink()  # Constructor failure must also release the file handle.

    def test_plan_mismatch_is_still_rejected_by_read_only_status(self):
        with Journal(self.job, create=True):
            pass
        (self.job / "plan.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(RenProfileError):
            Journal.read_status(self.job)

    def test_cli_status_returns_success_for_recorded_scan_gaps_without_writing(self):
        with patch("renprofile.cli.Native") as native, patch("renprofile.cli.Registry"), \
                patch("renprofile.cli.Host"), patch("renprofile.cli.Engine") as engine:
            native.return_value.elevated.return_value = True
            engine.return_value.load.return_value = (self.job, self.plan)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(["status", "--work-dir", str(self.job)])
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertIn("扫描缺口：120 项", out.getvalue())
        self.assertEqual({p.name for p in self.job.iterdir()}, {"plan.json"})


class RegistryAccessTests(unittest.TestCase):
    def test_read_only_open_requests_only_query_and_enumeration(self):
        registry = Registry.__new__(Registry)
        registry.location = Mock(return_value=("HKLM", r"SYSTEM\ControlSet001\Control\Class"))
        registry.w = Mock(KEY_QUERY_VALUE=1, KEY_ENUMERATE_SUB_KEYS=8, KEY_WOW64_64KEY=0x100, KEY_WRITE=0x20006)
        registry.open("SYSTEM", r"Control\Class")
        rights = registry.w.OpenKey.call_args.args[3]
        self.assertEqual(rights, 0x109)
        self.assertFalse(rights & 0x20000)  # READ_CONTROL is not needed to scan.
        self.assertFalse(rights & 0x10)  # KEY_NOTIFY is not needed to scan.
        registry.open("SYSTEM", r"Control\Class", write=True)
        self.assertEqual(registry.w.OpenKey.call_args.args[3] & 0x20006, 0x20006)


if __name__ == "__main__":
    unittest.main()
