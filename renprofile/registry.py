"""Read raw registry values, retain their types, and journal every mutation."""

from contextlib import contextmanager
import json
import ntpath
import os
import re
import uuid

from .errors import ConflictError, OperationError, RenProfileError
from .model import Action, registry_path, snapshot, unpack

PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
HIVE_FILES = {"USER": "NTUSER.DAT", "CLASSES": r"AppData\Local\Microsoft\Windows\UsrClass.dat"}


def key_path(parent, child):
    # Registry names such as 'C:%5CUsers...' are NOT filesystem drive paths.
    return parent + "\\" + child if parent else child


class Registry:
    def __init__(self, native):
        import winreg
        self.w = winreg
        self.native = native
        self.mounts = {}
        self.system_path = r"SYSTEM\CurrentControlSet"

    def profiles(self):
        result = []
        with self.w.OpenKey(self.w.HKEY_LOCAL_MACHINE, PROFILE_LIST, 0, self.w.KEY_READ | self.w.KEY_WOW64_64KEY) as key:
            count = self.w.QueryInfoKey(key)[0]
            for i in range(count):
                sid = self.w.EnumKey(key, i)
                with self.w.OpenKey(key, sid) as entry:
                    try:
                        raw, _ = self.w.QueryValueEx(entry, "ProfileImagePath")
                    except FileNotFoundError:
                        continue
                    result.append({"sid": sid, "path": self.w.ExpandEnvironmentStrings(raw), "raw_path": raw})
        return result

    def profile_value(self, sid, name):
        with self.w.OpenKey(self.w.HKEY_LOCAL_MACHINE, PROFILE_LIST + "\\" + sid,
                            0, self.w.KEY_READ | self.w.KEY_WOW64_64KEY) as key:
            try:
                return self.w.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return None

    def loaded(self, sid):
        for name in (sid, sid + "_Classes"):
            try:
                with self.w.OpenKey(self.w.HKEY_USERS, name):
                    return True
            except FileNotFoundError:
                pass
        return False

    def location(self, root, key=""):
        if root == "SOFTWARE":
            handle, prefix = self.w.HKEY_LOCAL_MACHINE, "SOFTWARE"
        elif root == "SYSTEM":
            handle, prefix = self.w.HKEY_LOCAL_MACHINE, self.system_path
        else:
            handle, prefix = self.w.HKEY_USERS, self.mounts[root]
        return handle, prefix + ("\\" + key if key else "")

    def open(self, root, key="", write=False, access=None):
        handle, path = self.location(root, key)
        # Enumeration/querying does not need READ_CONTROL or KEY_NOTIFY, which
        # KEY_READ also requests. Extra rights can make an otherwise readable
        # key fail to open. Real access denials still remain visible as gaps.
        if access is None:
            access = self.w.KEY_QUERY_VALUE | (self.w.KEY_WRITE if write else self.w.KEY_ENUMERATE_SUB_KEYS)
        rights = access | self.w.KEY_WOW64_64KEY
        # Open registry links themselves, never follow links into another tree.
        return self.w.OpenKey(handle, path, 0x8, rights)

    @contextmanager
    def mounted(self, base, hive_files, journal=None):
        """Unique mount names; all handles close before checked unloads."""
        if self.mounts or (journal and json.loads(journal.get("hive_mounts", "[]"))):
            raise RenProfileError("上次的用户注册表文件尚未卸载，请先恢复。")
        mounted = []
        try:
            for root, relative in hive_files.items():
                filename = os.path.join(base, relative)
                if not os.path.isfile(filename):
                    raise RenProfileError(f"注册表 hive 不存在：{filename}")
                name = "RenProfile_" + uuid.uuid4().hex + "_" + root
                mounted.append({"root": root, "name": name, "file": filename})
                # Save the intended name before LoadKey. A crash after loading
                # must not leave an unidentifiable hive holding the directory.
                if journal:
                    journal.set("hive_mounts", json.dumps(mounted, ensure_ascii=False))
                try:
                    self.w.LoadKey(self.w.HKEY_USERS, name, filename)
                except OSError as error:
                    raise OperationError("加载用户注册表文件", filename, error) from error
                self.mounts[root] = name
            yield self
        finally:
            self._unload_mounts(mounted, journal)

    def _unload_mounts(self, mounted, journal):
        remaining = list(mounted)
        failures = []
        for entry in reversed(mounted):
            name, root = entry["name"], entry["root"]
            code = self.native.unload(int(self.w.HKEY_USERS), name)
            if code not in (0, 2, 3):  # already absent after reboot/interruption
                failures.append(f"HKU\\{name}: WinError {code}")
                continue
            if self.mounts.get(root) == name:
                self.mounts.pop(root)
            remaining.remove(entry)
            if journal:
                journal.set("hive_mounts", json.dumps(remaining, ensure_ascii=False))
        if failures:
            raise RenProfileError("无法卸载 hive；恢复资料已保留，请重启后点击“恢复”：" + "; ".join(failures))

    def release_mounts(self, journal, plan):
        """Release only this job's saved temporary mounts, including after a crash."""
        mounted = json.loads(journal.get("hive_mounts", "[]"))
        if not isinstance(mounted, list):
            raise RenProfileError("用户注册表挂载记录损坏，无法自动恢复。")
        for entry in mounted:
            root, name = entry.get("root"), entry.get("name", "")
            if root not in plan["hive_files"] or not re.fullmatch(r"RenProfile_[a-f0-9]{32}_" + re.escape(str(root)), name):
                raise RenProfileError("用户注册表挂载名称无效，未卸载任何注册表。")
            expected = {ntpath.normcase(ntpath.join(base, plan["hive_files"][root]))
                        for base in (plan["old"], plan["new"])}
            if ntpath.normcase(entry.get("file", "")) not in expected:
                raise RenProfileError("用户注册表挂载路径不匹配，未卸载任何注册表。")
        self._unload_mounts(mounted, journal)

    def get(self, root, key, name):
        try:
            with self.open(root, key, access=self.w.KEY_QUERY_VALUE) as handle:
                try:
                    data, kind = self.w.QueryValueEx(handle, name)
                    return snapshot((kind, data))
                except FileNotFoundError:
                    return None
        except OSError as error:
            raise OperationError("读取注册表值", self.value_target(root, key, name), error) from error

    def value_target(self, root, key, name):
        return registry_path(root, key, self.system_path) + f" [值：{name or '(默认)'}]"

    def check_writable(self, action):
        """Open/close with exact write rights; no settings or ACL changes."""
        try:
            with self.open(action.root, action.key, access=self.w.KEY_QUERY_VALUE | self.w.KEY_SET_VALUE):
                pass
        except OSError as error:
            raise OperationError("检查注册表写入权限", self.value_target(action.root, action.key, action.name), error) from error

    def exists(self, root, key):
        try:
            with self.open(root, key):
                return True
        except FileNotFoundError:
            return False

    def set(self, root, key, name, value):
        # Set/DeleteValue need SET_VALUE; FlushKey needs QUERY_VALUE. Requesting
        # KEY_WRITE also asks for CREATE_SUB_KEY/READ_CONTROL and can be denied
        # even when the individual value is writable.
        operation = "打开注册表项以写入值"
        try:
            with self.open(root, key, access=self.w.KEY_QUERY_VALUE | self.w.KEY_SET_VALUE) as handle:
                operation = "删除注册表值" if value is None else "写入注册表值"
                if value is None:
                    self.w.DeleteValue(handle, name)
                else:
                    self.w.SetValueEx(handle, name, 0, value["kind"], unpack(value["data"]))
                operation = "将注册表改动写入磁盘"
                self.w.FlushKey(handle)
        except OSError as error:
            raise OperationError(operation, self.value_target(root, key, name), error) from error

    def rename(self, root, parent, old, new):
        operation = "打开注册表父项以改名"
        try:
            with self.open(root, parent, write=True) as handle:
                operation = "修改注册表子项名称"
                code = self.native.rename_key_fn(int(handle), old, new)
                if code:
                    import ctypes
                    raise ctypes.WinError(code)
                operation = "将注册表子项改名写入磁盘"
                self.w.FlushKey(handle)
        except OSError as error:
            target = registry_path(root, key_path(parent, old), self.system_path) + " → " + new
            raise OperationError(operation, target, error) from error

    def transition(self, action, undo=False):
        before, after = (action.after, action.before) if undo else (action.before, action.after)
        if action.kind == "value":
            current = self.get(action.root, action.key, action.name)
            if current == after:
                return  # also handles interrupted writes and repeated rollback
            if current != before:
                raise ConflictError(f"注册表值已被其他程序修改：{action.root}\\{action.key} [{action.name}]")
            self.set(action.root, action.key, action.name, after)
            if self.get(action.root, action.key, action.name) != after:
                raise ConflictError("注册表写入后的校验失败。")
        elif action.kind == "key":
            old = key_path(action.key, before)
            new = key_path(action.key, after)
            old_exists, new_exists = self.exists(action.root, old), self.exists(action.root, new)
            if new_exists and not old_exists:
                return
            if not old_exists or new_exists:
                raise ConflictError(f"注册表子键冲突：{action.root}\\{old} -> {new}")
            self.rename(action.root, action.key, before, after)
        else:
            raise RenProfileError(f"未知注册表动作：{action.kind}")
