"""Recovery only: reads original write-ahead records, including versions 2/3."""

import json
import os
from pathlib import Path
import re
import sqlite3

from .errors import RenProfileError
from .host import is_reparse, plain_path
from .journal import Journal
from .model import Action
from .paths import normalize, validate_pair, within
from .registry import HIVE_FILES


JOB_NAME = re.compile(r"job-\d{8}-\d{6}-[a-f0-9]{12}")


def read_record(job):
    """Keep the account identity even if its journal is locked or corrupt."""
    job = Path(job)
    record = {"job": str(job), "state": "unknown", "old": job.name, "new": "", "sid": None}
    try:
        plain_path(job)
        source = job / ("plan.json" if (job / "plan.json").is_file() else "request.json")
        plain_path(source)
        data = json.loads(source.read_text(encoding="utf-8"))
        record.update(sid=data.get("sid"), old=data["old"], new=data["new"])
        for name in ("journal.sqlite3", "journal.sqlite3-journal"):
            plain_path(job / name)
        report = Journal.read_status(job)
        from .status import failure_details
        record.update(state=report["status"], diagnostic=failure_details(report),
                      manual_rename_pending=report.get("manual_rename_pending", False))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RenProfileError, sqlite3.Error) as error:
        record["error"] = str(error)
    return record


class Recovery:
    def __init__(self, host, registry, emit=print):
        self.host, self.registry, self.emit = host, registry, emit

    def require_no_pending(self, root, sid):
        """Called under the operation lock, before any new migration begins."""
        root = Path(root)
        if not root.exists():
            return
        self.host.prepare_storage(root)
        for job in root.iterdir():
            if not JOB_NAME.fullmatch(job.name):
                continue
            record = read_record(job)
            if record["sid"] not in (None, sid):
                continue
            if record["state"] not in ("planned", "rolled_back", "completed"):
                raise RenProfileError(f"存在尚未恢复或无法读取的操作，请先点击“恢复”处理。\n记录：{job}")

    def recover_status(self, job):
        """An explicit recovery may let SQLite recover its own hot journal."""
        with self.host.lock():
            job, _ = self.load(job)
            with Journal(job) as journal:
                return journal.get("status", "unknown")

    def load(self, job):
        job = Path(job).absolute()
        self.host.prepare_record(job)
        plain_path(job / "plan.json")
        with (job / "plan.json").open(encoding="utf-8") as stream:
            plan = json.load(stream)
        if plan.get("format") not in (2, 4) or plan.get("machine") != self.host.machine():
            raise RenProfileError("计划版本不匹配或不属于此计算机。")
        old, new = validate_pair(plan["old"], plan["new"])
        if within(str(job), old) or within(str(job), new):
            raise RenProfileError("工作目录必须位于目标用户目录之外。")
        if not plan["hive_files"].get("USER") or any(
                HIVE_FILES.get(k) != v for k, v in plan["hive_files"].items()):
            raise RenProfileError("恢复记录中的 hive 文件列表无效。")
        for filename in ("journal.sqlite3", "journal.sqlite3-journal"):
            plain_path(job / filename)
        self.registry.system_path = plan["system_path"]
        return job, plan


    def _profile_location(self, plan):
        matches = []
        for path in (plan["old"], plan["new"]):
            if os.path.lexists(path) and not is_reparse(path) and self.host.identity(path) == plan["identity"]:
                matches.append(path)
        if len(matches) != 1:
            raise RenProfileError("无法唯一识别原用户目录；保留现场，拒绝自动恢复。")
        return matches[0]


    def _offline_for_rollback(self, plan):
        profiles = [p for p in self.registry.profiles() if p["sid"] == plan["sid"]]
        if len(profiles) != 1 or normalize(profiles[0]["path"]).casefold() not in {
                plan["old"].casefold(), plan["new"].casefold()}:
            raise RenProfileError("SID 绑定已发生其他变化，拒绝自动回滚。")
        self.host.require_offline(plan["sid"], normalize(profiles[0]["path"]))


    def _rollback(self, plan, journal):
        self._offline_for_rollback(plan)
        self.registry.release_mounts(journal, plan)
        journal.set("status", "rolling_back")
        entries = journal.reverse()
        if plan.get("manual_rename"):
            if self.host.identity(plan["new"]) != plan["identity"]:
                raise RenProfileError("手动改名的目录身份或 ACL 已变化，恢复资料已保留。")
            # Keep old ProfileImagePath usable after restoring the settings.
            # This alias is retained deliberately; the user's rename is never undone.
            link = Action("junction", name=plan["old"], after=plan["new"])
            link_entries = [(seq, a) for seq, a in entries if a.kind == "junction"]
            seq = link_entries[0][0] if link_entries else journal.intent(link)
            self.host.transition_file(link, plan["identity"])
            journal.mark(seq, "retained")
        registry_entries = [(seq, a) for seq, a in entries if a.kind in ("value", "key")]
        if registry_entries:
            path = self._profile_location(plan)
            with self.registry.mounted(path, plan["hive_files"], journal=journal):
                for seq, action in registry_entries:
                    self.registry.transition(action, undo=True)
                    journal.mark(seq, "undone")
        # Hive files must be completely unloaded before the physical rename.
        for seq, action in entries:
            if action.kind not in ("value", "key"):
                if plan.get("manual_rename"):
                    if action.kind != "junction":
                        raise RenProfileError("手动改名模式的日志包含意外的目录动作，已停止恢复。")
                    continue
                self.host.transition_file(action, plan["identity"], undo=True)
                journal.mark(seq, "undone")
        self.host.require_offline(plan["sid"], plan["old"])
        if self.host.identity(plan["new"] if plan.get("manual_rename") else plan["old"]) != plan["identity"]:
            raise RenProfileError("恢复后目录身份或 ACL 不一致。")
        journal.set("status", "rolled_back")


    def rollback(self, job):
        with self.host.lock(), self.host.native.privileges():
            job, plan = self.load(job)
            with Journal(job) as journal:
                try:
                    if journal.get("status") == "rolled_back":
                        self.registry.release_mounts(journal, plan)
                        self.emit("此操作已回滚。")
                        return
                    self._rollback(plan, journal)
                except BaseException as error:
                    journal.note("status", "recovery_required")
                    journal.note("recovery_error", str(error))
                    raise
            self.emit("已恢复软件修改的设置，手动改名的文件夹和兼容入口保留。" if plan.get("manual_rename")
                      else "已按日志恢复原目录和本工具改过的注册表项。")
