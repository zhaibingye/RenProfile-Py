"""Durable write-ahead intents, committed BEFORE each external side effect."""

import hashlib
import json
from pathlib import Path
import sqlite3
import stat

from .errors import RenProfileError
from .model import Action, describe_action


class Journal:
    @staticmethod
    def read_status(job):
        """Read existing metadata without creating/upgrading or writing a journal."""
        path = Path(job) / "journal.sqlite3"
        try:
            info = path.stat()
        except FileNotFoundError:
            return {"status": "planned"}
        if not stat.S_ISREG(info.st_mode):
            raise RenProfileError("执行日志不是普通文件，无法判断操作状态。")
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0)
        try:
            rows = dict(connection.execute("SELECT key, value FROM meta").fetchall())
            plan_bytes = (Path(job) / "plan.json").read_bytes()
            digest = hashlib.sha256(plan_bytes).hexdigest()
            if rows.get("plan_sha256") != digest:
                raise RenProfileError("计划文件发生变化，拒绝使用不匹配的恢复日志。")
            result = {"status": rows.get("status", "unknown"),
                      **{key: rows[key] for key in ("last_error", "recovery_error", "failure_context") if rows.get(key)}}
            result["manual_rename_pending"] = result["status"] == "rolled_back" and (
                rows.get("manual_rename_pending") == "1"
                or rows.get("failure_context", "").startswith("文件夹改名："))
            result["preserved"] = json.loads(rows.get("preserved", "[]"))
            result["written_values"] = sum(
                json.loads(row[0])["kind"] in ("value", "key") for row in connection.execute(
                    "SELECT action FROM actions WHERE state='done'").fetchall())
            if result["status"] != "completed":
                # Legacy logs retain intents even after automatic rollback.
                # This is a clue, not proof: loading/unloading or verification
                # can fail after the last logged registry operation succeeds.
                last = connection.execute("SELECT id, action, state FROM actions ORDER BY id DESC LIMIT 1").fetchone()
                if last:
                    plan = json.loads(plan_bytes)
                    result["last_recorded_action"] = {
                        "sequence": last[0], "state": last[2],
                        "description": describe_action(Action.from_json(json.loads(last[1])),
                                                       plan.get("system_path", r"SYSTEM\CurrentControlSet"))}
            return result
        finally:
            connection.close()

    def __init__(self, job, create=False):
        path = Path(job) / "journal.sqlite3"
        if create and path.exists():
            raise RenProfileError("此记录已经执行过，只能查看或恢复，不能重复执行。")
        if not create and not path.is_file():
            raise RenProfileError("没有执行日志；此计划尚未开始修改系统。")
        uri = path.resolve().as_uri() + ("?mode=rwc" if create else "?mode=rw")
        self.db = sqlite3.connect(uri, uri=True, timeout=0)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA locking_mode=EXCLUSIVE")
            if create:
                self.db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self.db.execute("CREATE TABLE actions (id INTEGER PRIMARY KEY, action TEXT NOT NULL, state TEXT NOT NULL)")
            digest = hashlib.sha256((Path(job) / "plan.json").read_bytes()).hexdigest()
            if create:
                self.set("plan_sha256", digest)
                self.set("status", "applying")
            else:
                if self.get("plan_sha256") != digest:
                    raise RenProfileError("计划文件发生变化，拒绝使用不匹配的恢复日志。")
                self.db.execute("SELECT id, action, state FROM actions LIMIT 0")
        except BaseException:
            self.db.close()
            raise

    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
        self.db.commit()

    def note(self, key, value):
        """Error reporting must not prevent a rollback attempt after a disk error."""
        try:
            self.set(key, value)
        except sqlite3.Error:
            self.db.rollback()

    def intent(self, action):
        row = self.db.execute("INSERT INTO actions(action,state) VALUES (?, 'pending')",
                              (json.dumps(action.json(), ensure_ascii=False),))
        self.db.commit()
        return row.lastrowid

    def mark(self, seq, state):
        self.db.execute("UPDATE actions SET state=? WHERE id=?", (state, seq))
        self.db.commit()

    def reverse(self):
        return [(seq, Action.from_json(json.loads(raw))) for seq, raw in self.db.execute(
            "SELECT id, action FROM actions WHERE state NOT IN ('undone', 'retained') ORDER BY id DESC").fetchall()]

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
