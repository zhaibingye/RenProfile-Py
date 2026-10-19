"""Fresh rename requests and explicit recovery; success removes its own records."""

from dataclasses import dataclass
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import sqlite3
import uuid

from .errors import RenProfileError
from .host import plain_path
from .journal import Journal
from .paths import validate_pair
from .recovery import read_record


@dataclass(frozen=True)
class MigrationResult:
    old: str
    new: str
    skipped: int
    cleaned: bool
    job: str = ""
    cleanup_error: str = ""


def new_folder_path(old, name):
    name = name.strip()
    if not name or any(c in name for c in "\\/:"):
        raise RenProfileError("只输入新的文件夹名称，例如 NewName，不要输入完整路径。")
    return validate_pair(old, ntpath.join(ntpath.dirname(old), name))[1]


class SimpleService:
    def __init__(self, engine, backup_root=None):
        self.engine = engine
        self.host, self.registry = engine.host, engine.registry
        self.root = Path(backup_root or Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RenProfile-Py")

    def profiles(self):
        current = self.host.native.current_sid()
        entries = []
        for profile in self.registry.profiles():
            if profile["sid"] == current or not re.fullmatch(r"S-1-(?:5-21|12-1)(?:-\d+){4}", profile["sid"]):
                continue
            # ProfileList still contains the OLD path after the user's rename.
            if not os.path.lexists(profile["path"]) or (Path(profile["path"]) / "NTUSER.DAT").is_file():
                entries.append(profile)
        return sorted(entries, key=lambda p: p["path"].casefold())

    def _make_root(self):
        self.host.prepare_storage(self.root)

    def _validate_managed_job(self, job):
        """Resolve/check the exact deletion target before any recursive removal."""
        job = Path(job).absolute()
        plain_path(job)
        root = self.root.resolve(strict=True)
        resolved = job.resolve(strict=True)
        if resolved.parent != root or not (re.fullmatch(r"job-\d{8}-\d{6}-[a-f0-9]{12}", resolved.name)
                                          or re.fullmatch(r"cleanup-[a-f0-9]{32}", resolved.name)):
            raise RenProfileError("这不是工具自动生成的恢复目录，未删除任何文件。")
        for folder, directories, files in os.walk(resolved, followlinks=False):
            for name in [*directories, *files]:
                plain_path(Path(folder) / name)
        return resolved

    def _delete_managed_job(self, job):
        target = self._validate_managed_job(job)
        if target.name.startswith("job-"):
            # Rename only after the caller has verified a disposable state.
            # A partial delete must never look like an unfinished migration.
            destination = target.parent / ("cleanup-" + uuid.uuid4().hex)
            if destination.parent != self.root.resolve(strict=True) or os.path.lexists(destination):
                raise RenProfileError("备份清理位置不正确。")
            target.rename(destination)
            target = destination
        try:
            shutil.rmtree(target)
        except OSError as error:
            failure = RenProfileError(f"备份待清理：{target}\n{error}")
            failure.job = str(target)
            raise failure from error
        try:
            self.root.rmdir()  # Empty parent only; other failed jobs remain intact.
        except OSError:
            pass

    def cleanup(self, job, allowed_states=("completed",)):
        job = self._validate_managed_job(job)
        if not job.name.startswith("cleanup-"):
            state = Journal.read_status(job)["status"]
            if state not in allowed_states:
                raise RenProfileError("操作尚未完成，恢复资料会继续保留。")
        self._delete_managed_job(job)

    def migrate(self, profile, name, notify=lambda text: None):
        # A GUI selection is only an SID, never an authoritative saved path.
        matches = [p for p in self.registry.profiles() if p["sid"] == profile["sid"]]
        if len(matches) != 1:
            raise RenProfileError("所选用户已变化，请刷新后重试。")
        new = new_folder_path(matches[0]["path"], name)
        notify("正在检查当前状态……")
        execution = self.engine.migrate(profile["sid"], new, self.root)
        return self._finish(execution, notify)

    def continue_manual(self, job, notify=lambda text: None):
        job, previous = self.engine.load(job)
        notify("正在核对手动改名后的文件夹……")
        execution = self.engine.migrate(previous["sid"], previous["new"], self.root, manual_job=job)
        return self._finish(execution, notify)

    def _finish(self, execution, notify):
        job = execution["job"]
        notify("校验通过，正在删除本次备份……")
        targets = [(job, ("completed",))]
        if execution.get("manual_source"):
            targets.append((execution["manual_source"], ("rolled_back",)))
        errors = []
        for target, states in targets:
            try:
                self.cleanup(target, allowed_states=states)
            except (OSError, RenProfileError, sqlite3.Error) as error:
                errors.append((getattr(error, "job", str(target)), str(error)))
        if errors:
            return MigrationResult(execution["old"], execution["new"], execution["skipped"],
                                   False, errors[0][0], "\n".join(text for _, text in errors))
        return MigrationResult(execution["old"], execution["new"], execution["skipped"], True)

    def pending(self):
        """Only inspect our own directories; never discover unrelated disk paths."""
        if not self.root.exists():
            return []
        self.host.prepare_storage(self.root)
        entries = []
        for job in sorted(self.root.iterdir(), reverse=True):
            if re.fullmatch(r"cleanup-[a-f0-9]{32}", job.name):
                try:
                    self.cleanup(job)
                except (OSError, RenProfileError, sqlite3.Error) as error:
                    entries.append({"job": str(job), "state": "cleanup_pending", "old": job.name,
                                    "new": "", "error": str(error)})
                continue
            if not re.fullmatch(r"job-\d{8}-\d{6}-[a-f0-9]{12}", job.name):
                continue
            try:
                self._validate_managed_job(job)
                record = read_record(job)
                if record["state"] == "completed":
                    try:
                        self.cleanup(job)
                        continue
                    except (OSError, RenProfileError, sqlite3.Error) as error:
                        record.update(job=getattr(error, "job", str(job)), error=str(error))
                        if Path(record["job"]).name.startswith("cleanup-"):
                            record["state"] = "cleanup_pending"
                entries.append(record)
            except (OSError, ValueError, RenProfileError, sqlite3.Error) as error:
                entries.append({"job": str(job), "state": "unknown", "old": job.name, "new": "", "error": str(error)})
        return entries

    def restore(self, job):
        job = Path(job)
        self.host.prepare_record(job)
        if re.fullmatch(r"cleanup-[a-f0-9]{32}", job.name):
            self.cleanup(job)
            return "残留的备份和日志已清理。"
        try:
            state = Journal.read_status(job)["status"]
        except sqlite3.OperationalError:
            # A crash can leave a SQLite rollback journal; opening it read-only
            # cannot repair the database. Only explicit recovery may open rw.
            state = self.engine.recover_status(job)
        if state == "completed":
            # A finished migration must never be reversed by the failure button.
            self.cleanup(job)
            return "迁移已经完成，残留的备份和日志已清理。"
        source = job / ("plan.json" if (job / "plan.json").is_file() else "request.json")
        data = json.loads(source.read_text(encoding="utf-8"))
        manual = data.get("manual_rename", False)
        if state != "planned":
            self.engine.rollback(job)
            if job.parent.resolve() == self.root.resolve():
                self.cleanup(job, allowed_states=("rolled_back",))
            else:
                return ("已恢复软件修改的设置，手动改名的文件夹和兼容入口保留。恢复资料保留在原位置。"
                        if manual else "已恢复原来的名称和设置。旧版恢复文件夹保留在原位置。")
        else:
            if manual:
                identity, _ = self.host.preflight_manual(data["old"], data["new"], data["sid"], job)
                if data.get("identity") and identity != data["identity"]:
                    raise RenProfileError("手动改名的目录已变化，请保留恢复资料并查看详情。")
            else:
                self.host.require_offline(data["sid"], data["old"])
                if not Path(data["old"]).is_dir():
                    raise RenProfileError("原文件夹已不在原位置，请保留恢复资料并查看详情。")
            self._delete_managed_job(job)  # No write-ahead journal: changes never began.
            if manual:
                return "软件尚未修改设置，恢复资料已清理。手动改名的文件夹未变，请完成迁移或手动改回原名后再登录。"
        if manual:
            return "已恢复软件修改的设置，恢复资料已清理。手动改名的文件夹和旧路径兼容入口保留，可重新迁移。"
        return "已恢复原来的名称和设置，恢复资料已清理。"
