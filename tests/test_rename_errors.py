import queue
import unittest
from unittest.mock import Mock

from renprofile.errors import DirectoryRenameError, OperationError, RenProfileError
from renprofile.gui import App, friendly_error
from renprofile.host import Host


class RenameErrorTests(unittest.TestCase):
    def test_gui_shows_the_real_directory_problem_after_engine_rollback(self):
        original = DirectoryRenameError(r"C:\Users\亿洋", r"C:\Users\YiYang", 5,
                                        [{"pid": 123, "name": "Example", "service": ""}])
        wrapper = RenProfileError(f"执行失败，已回滚已记录的修改：{original}")
        wrapper.__cause__ = original
        message = friendly_error(wrapper)
        self.assertIn("WinError 5", message)
        self.assertIn("Example（PID 123）", message)
        self.assertIn("只登录维护管理员", message)
        self.assertIn("已恢复之前记录的改动", message)

    def test_probe_failure_does_not_claim_any_registry_changes(self):
        message = friendly_error(DirectoryRenameError("old", "new", 32))
        self.assertIn("文件夹被程序占用", message)
        self.assertNotIn("已恢复之前", message)

    def test_manual_migration_error_explains_that_users_rename_is_preserved(self):
        error = RenProfileError("迁移失败，已回滚软件修改的设置；手动改名的文件夹未变，旧路径兼容入口已保留：denied")
        message = friendly_error(error)
        self.assertIn("手动改好的文件夹", message)
        self.assertIn("旧路径兼容入口保留", message)
        self.assertNotIn("改名没有完成", message)

    def test_registry_error_location_is_visible_in_gui_after_rollback(self):
        original = OperationError("打开注册表项以写入值", r"HKLM\SOFTWARE\Protected [值：Path]",
                                  PermissionError("[WinError 5] 拒绝访问"))
        wrapper = RenProfileError("迁移失败，已回滚软件修改的设置")
        wrapper.__cause__ = original
        message = friendly_error(wrapper)
        self.assertIn("打开注册表项以写入值", message)
        self.assertIn(r"HKLM\SOFTWARE\Protected", message)
        self.assertIn("WinError 5", message)
        self.assertIn("已回滚", message)

    def test_failed_recovery_never_gets_relabelled_as_successful_rollback(self):
        original = OperationError("写入注册表值", "test-target", PermissionError("denied"))
        wrapper = RenProfileError("执行失败；自动恢复未完成")
        wrapper.__cause__ = original
        self.assertIn("自动恢复未完成", friendly_error(wrapper))
        self.assertNotIn("已回滚", friendly_error(wrapper))

    def test_occupancy_query_failure_never_masks_the_original_windows_code(self):
        native = Mock()
        native.rename_diagnostics.side_effect = RuntimeError("diagnostic unavailable")
        error = OSError("denied")
        error.winerror = 5
        diagnostic = Host(native, None).directory_error("old", "new", error)
        self.assertEqual(diagnostic.winerror, 5)
        self.assertIn("diagnostic unavailable", str(diagnostic))

    def test_gui_keeps_progress_and_engine_log_messages_in_original_order(self):
        app = App.__new__(App)
        app.events, app.logs, app.root, app.status = queue.Queue(), [], Mock(), Mock()
        app.events.put(("detail", "prepare"))
        app.events.put(("progress", "renaming"))
        app.events.put(("detail", "failed"))
        app.poll()
        self.assertEqual(app.logs, ["prepare", "renaming", "failed"])


if __name__ == "__main__":
    unittest.main()
