"""One fresh scan and one transaction per click. Saved jobs are recovery only."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid

from . import __version__
from .errors import DirectoryRenameError, ManualRenameRequired, RenProfileError, OperationError
from .host import is_reparse, plain_path
from .journal import Journal
from .model import Action, describe_action
from .paths import PathRewriter, validate_pair, within
from .recovery import JOB_NAME, Recovery, read_record
from .registry import HIVE_FILES
from .scanner import scan


def save_json(path, data):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def denied(error):
    return isinstance(error, PermissionError) or getattr(error, "winerror", None) == 5


class Engine(Recovery):
    def migrate(self, sid, new, root, *, manual_job=None):
        """No job/plan input: every attempt reads the current SID mapping."""
        root = Path(root)
        with self.host.lock(), self.host.native.privileges():
            profiles = [p for p in self.registry.profiles() if p["sid"] == sid]
            if len(profiles) != 1:
                raise RenProfileError("找不到所选用户，请刷新列表。")
            old, new = validate_pair(profiles[0]["path"], new)
            if within(str(root), old) or within(str(root), new):
                raise RenProfileError("工具数据目录必须位于目标用户文件夹之外。")
            self.require_no_pending(root, sid)
            # Adopt an earlier manual rename only after SID/path/identity checks.
            manual = Path(new).is_dir() and (not os.path.lexists(old) or is_reparse(old))
            previous_job, previous = None, None
            if manual_job is None and manual and root.exists():
                # Reopening the app after the user's manual rename must retain
                # the recorded directory identity, without reusing scan actions.
                for candidate in sorted(root.iterdir(), reverse=True):
                    if not JOB_NAME.fullmatch(candidate.name):
                        continue
                    record = read_record(candidate)
                    if (record.get("manual_rename_pending") and record["sid"] == sid
                            and record["old"].casefold() == old.casefold()
                            and record["new"].casefold() == new.casefold()):
                        manual_job = candidate
                        break
            if manual_job is not None:
                previous_job, previous = self.load(manual_job)
                report = Journal.read_status(previous_job)
                if (not report.get("manual_rename_pending") or previous["sid"] != sid
                        or previous["old"].casefold() != old.casefold()
                        or previous["new"].casefold() != new.casefold()):
                    raise RenProfileError("这条记录不能用于手动改名后继续，请重新选择用户和名称。")
                if not manual:
                    raise RenProfileError(f"还没有检测到手动改名完成。\n请把 {old} 改名为 {new}，然后再点击继续。")
            preflight = self.host.preflight_manual if manual else self.host.preflight
            identity, control_set = preflight(old, new, sid, root)
            if previous is not None and identity != previous["identity"]:
                raise RenProfileError("新位置不是原来那个用户文件夹，或文件夹权限已变化。请只重命名原文件夹，再继续。")
            self.registry.system_path = control_set
            source = new if manual else old
            hives = {key: relative for key, relative in HIVE_FILES.items()
                     if (Path(source) / relative).is_file()}
            if "USER" not in hives or (Path(source) / "NTUSER.MAN").exists():
                raise RenProfileError("找不到普通用户的 NTUSER.DAT，无法迁移此用户。")
            for relative in hives.values():
                plain_path(Path(source) / relative)
            critical_key = r"Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + sid
            before = self.registry.get("SOFTWARE", critical_key, "ProfileImagePath")
            if before is None or before["kind"] not in (1, 2):
                raise RenProfileError("用户的 ProfileImagePath 缺失或类型不正确。")
            binding = Action("value", "SOFTWARE", critical_key, "ProfileImagePath",
                             before, {"kind": before["kind"], "data": new})
            # Fail before moving the folder if the required binding cannot open.
            self.registry.check_writable(binding)
            self.host.prepare_storage(root)
            short_old = previous.get("short_old", "") if previous is not None else (
                "" if manual else self.host.native.short_path(old))
            job = root / ("job-" + datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:12])
            self.host.native.secure_directory(job)
            plan = {"format": 4, "version": __version__, "created_utc": datetime.now(timezone.utc).isoformat(),
                    "machine": self.host.machine(), "sid": sid, "old": old, "new": new,
                    "identity": identity, "system_path": control_set, "hive_files": hives,
                    "keep_junction": True, "manual_rename": manual, "simple": True, "short_old": short_old,
                    "manual_source": str(previous_job) if previous_job else "",
                    "actions": [], "gaps": []}
            # Metadata only. There is deliberately no saved scan to execute later.
            save_json(job / "plan.json", plan)
            self.emit(f"RenProfile {__version__}｜本次任务：{job.name}")
            self.emit(f"原目录：{old}\n新目录：{new}")
            if manual:
                self.emit("检测到之前已改好的文件夹，本次补全设置。")
            with Journal(job, create=True) as journal:
                step = "检查当前用户设置"
                try:
                    journal.set("status", "scanning")
                    self.emit("1/3 正在重新扫描当前设置……")
                    rewrite = PathRewriter(old, new, short_old)
                    with self.registry.mounted(source, hives, journal=journal):
                        actions, preserved = scan(self.registry, rewrite, hives)
                        writable = []
                        for action in actions:
                            try:
                                self.registry.check_writable(action)
                                writable.append(action)
                            except (OSError, OperationError) as error:
                                if not denied(error):
                                    raise
                                preserved.append(self._preserved(action, error))
                        step = "卸载扫描使用的用户注册表文件"
                    self.host.require_offline(sid, old)
                    journal.set("preserved", json.dumps(preserved, ensure_ascii=False))
                    journal.set("status", "applying")
                    if not manual:
                        self.emit("2/3 正在修改文件夹名称……")
                        folder = Action("directory", before=old, after=new)
                        step = describe_action(folder)
                        self._file(journal, folder, identity)
                    link = Action("junction", name=old, after=new)
                    step = describe_action(link)
                    self._file(journal, link, identity)
                    self.emit("3/3 正在更新设置并校验……")
                    step = "加载新目录的用户注册表文件"
                    with self.registry.mounted(new, hives, journal=journal):
                        for action in writable:
                            step = describe_action(action, control_set)
                            current = self.registry.get(action.root, action.key, action.name)
                            if current != action.before:
                                preserved.append(self._preserved(action, "扫描后已变化，保留当前值"))
                                continue
                            seq = journal.intent(action)
                            try:
                                self.registry.transition(action)
                            except (OSError, OperationError) as error:
                                # Only a proven no-op denial may be skipped. A
                                # partial write/flush failure must roll back.
                                if not denied(error) or self.registry.get(action.root, action.key, action.name) != action.before:
                                    raise
                                journal.mark(seq, "undone")
                                preserved.append(self._preserved(action, error))
                            else:
                                journal.mark(seq, "done")
                        step = "卸载更新后的用户注册表文件"
                    # Commit the binding last, after hives are closed. Never skip.
                    step = describe_action(binding, control_set)
                    seq = journal.intent(binding)
                    self.registry.transition(binding)
                    journal.mark(seq, "done")
                    step = "核对用户 SID、目录身份和权限"
                    self.host.require_offline(sid, new)
                    if self.host.identity(new) != identity:
                        raise RenProfileError("改名后目录身份或权限发生变化。")
                    self.host.check_junction(old, new)
                    journal.set("preserved", json.dumps(preserved, ensure_ascii=False))
                    journal.set("status", "completed")
                    self.emit(f"改名和设置更新已完成；{len(preserved)} 处设置保留原值，旧路径兼容入口已保留。")
                    return {"job": job, "old": old, "new": new, "skipped": len(preserved),
                            "manual_source": str(previous_job) if previous_job else ""}
                except BaseException as original:
                    journal.note("failure_context", step)
                    journal.note("last_error", str(original))
                    self.emit(f"失败步骤：{step}\n{original}\n正在自动恢复……")
                    try:
                        self._rollback(plan, journal)
                    except BaseException as recovery:
                        journal.note("status", "recovery_required")
                        journal.note("recovery_error", str(recovery))
                        raise RenProfileError(f"操作未完成，自动恢复未完成：{recovery}\n失败步骤：{step}\n{original}\n恢复资料：{job}") from original
                    if (not manual and isinstance(original, DirectoryRenameError)
                            and original.winerror in (5, 32, 33)):
                        journal.set("manual_rename_pending", "1")
                        raise ManualRenameRequired(sid, old, new, job) from original
                    suffix = "之前手动改好的文件夹保持不变，兼容入口保留。" if manual else "文件夹名称和已修改设置已恢复。"
                    raise RenProfileError(f"操作失败，已回滚。{suffix}\n失败步骤：{step}\n{original}\n恢复资料：{job}") from original

    def _file(self, journal, action, identity):
        seq = journal.intent(action)
        self.host.transition_file(action, identity)
        journal.mark(seq, "done")

    @staticmethod
    def _preserved(action, error):
        return {"root": action.root, "key": action.key, "name": action.name, "error": str(error)}
