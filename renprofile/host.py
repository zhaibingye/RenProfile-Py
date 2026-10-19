"""Windows safety checks and filesystem transitions, separate from orchestration."""

from contextlib import contextmanager
import ctypes
from ctypes import wintypes as w
import hashlib
import ntpath
import os
from pathlib import Path
import re
import stat
import sys

from .errors import ConflictError, DirectoryRenameError, OperationError, RenProfileError
from . import EXECUTABLE_NAME
from .paths import normalize, validate_pair, within


def is_reparse(path):
    return bool(os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def plain_path(path):
    """Reject reparse ancestors as well as a reparse leaf, including job paths."""
    current = Path(path)
    for part in [current, *current.parents]:
        if os.path.lexists(part) and is_reparse(part):
            raise RenProfileError(f"路径包含重解析点，拒绝操作：{part}")


def digest_file(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Host:
    def __init__(self, native, registry):
        self.native, self.registry = native, registry

    def machine(self):
        wreg = self.registry.w
        with wreg.OpenKey(wreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                          wreg.KEY_READ | wreg.KEY_WOW64_64KEY) as key:
            return wreg.QueryValueEx(key, "MachineGuid")[0]

    def identity(self, path):
        info = os.stat(path, follow_symlinks=False)
        if is_reparse(path) or not stat.S_ISDIR(info.st_mode):
            raise RenProfileError(f"必须是普通目录：{path}")
        return {"volume": info.st_dev, "file_id": info.st_ino,
                "security_sha256": hashlib.sha256(self.native.security(path)).hexdigest()}

    def require_offline(self, sid, path):
        if not re.fullmatch(r"S-1-(?:5-21|12-1)(?:-\d+){4}", sid):
            raise RenProfileError("只允许普通本地/域/Entra 用户 SID；拒绝系统、内置账户和备份配置。")
        if not self.native.elevated():
            raise RenProfileError("请从另一个管理员账户，以管理员身份运行终端。")
        if self.native.current_sid() == sid:
            raise RenProfileError("不能修改正在运行本工具的用户。请完全注销目标用户，登录另一个管理员账户。")
        profiles = self.registry.profiles()
        matching = [p for p in profiles if p["sid"] == sid and normalize(p["path"]).casefold() == path.casefold()]
        if len(matching) != 1:
            raise RenProfileError("SID 与 ProfileList 中的目录不一致，拒绝操作。")
        if any(p["sid"] != sid and normalize(p["path"]).casefold() == path.casefold() for p in profiles):
            raise RenProfileError("其他 SID 也引用此目录，拒绝操作。")
        if any(p["sid"] == sid + ".bak" for p in profiles):
            raise RenProfileError("存在此 SID 的 .bak 配置，请先修复用户配置文件状态。")
        if self.registry.loaded(sid):
            raise RenProfileError("目标用户的 hive 仍已加载。锁屏/切换用户不等于注销，请注销或重启后再操作。")
        processes = self.native.processes_for(sid)
        if processes:
            raise RenProfileError(f"目标用户仍有进程运行：{processes[:8]}")
        return matching[0]

    def preflight(self, old, new, sid, job):
        return self._preflight(old, new, sid, job, manual_rename=False)

    def preflight_manual(self, old, new, sid, job):
        """The user already moved the folder; never request a rename handle."""
        return self._preflight(old, new, sid, job, manual_rename=True)

    def _preflight(self, old, new, sid, job, manual_rename):
        old, new = validate_pair(old, new)
        self.require_offline(sid, old)
        plain_path(new)
        plain_path(job)
        if manual_rename:
            plain_path(Path(old).parent)
            if not Path(new).is_dir():
                raise RenProfileError(f"找不到已改名的文件夹：{new}\n请先手动改好文件夹名称，再开始迁移。")
            if os.path.lexists(old):
                try:
                    self.check_junction(old, new)
                except ConflictError as error:
                    raise RenProfileError(f"原文件夹仍在：{old}\n请先手动把它改名为 {ntpath.basename(new)}，再开始迁移。") from error
        else:
            plain_path(old)
            if not Path(old).is_dir() or os.path.lexists(new):
                raise RenProfileError("源目录必须存在，目标路径必须完全不存在。")
        if any(normalize(p["path"]).casefold() == new.casefold() for p in self.registry.profiles()):
            raise RenProfileError("新路径已登记给某个配置文件，即使目录不存在也不能使用。")
        runtime_paths = (job, os.getcwd(), sys.executable, __file__, getattr(sys, "_MEIPASS", __file__))
        for path in ((job,) if manual_rename else runtime_paths):
            if within(str(path), old) or within(str(path), new):
                raise RenProfileError(f"程序仍从目标用户目录运行。请使用 {EXECUTABLE_NAME}；源码方式请把 Python 和源码放到该用户目录之外。")
        self.native.require_ntfs(ntpath.splitdrive(old)[0])
        # The actual rename, after scanning hives have been unloaded, is the
        # useful access check. A preliminary probe could fail before a durable
        # manual-continuation record exists and cannot detect child-file locks.
        wreg = self.registry.w
        with wreg.OpenKey(wreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Select") as key:
            active = wreg.QueryValueEx(key, "Current")[0]
        return self.identity(new if manual_rename else old), rf"SYSTEM\ControlSet{active:03d}"

    @staticmethod
    def check_junction(source, target):
        info = os.lstat(source)
        if getattr(info, "st_reparse_tag", None) != 0xA0000003:
            raise ConflictError("旧路径被其他目录或非 junction 链接占用，拒绝操作。")
        link = os.readlink(source).removeprefix("\\\\?\\").removeprefix("\\??\\")
        if ntpath.normcase(link) != ntpath.normcase(target):
            raise ConflictError("旧路径 junction 指向了其他位置。")

    def directory_error(self, old, new, error):
        code = getattr(error, "winerror", None) or getattr(error, "errno", None)
        try:
            users, diagnostic = self.native.rename_diagnostics(old)
        except Exception as diagnostic_error:
            users, diagnostic = [], f"无法完成占用查询：{diagnostic_error}"
        return DirectoryRenameError(old, new, code, users, diagnostic)

    def check_job(self, job):
        plain_path(job)
        if not Path(job).is_dir():
            raise RenProfileError(f"工具数据位置不是文件夹：{job}")
        # Never accept a job readable/writable by ordinary users. Copies contain
        # private user settings; plan and journal must not be attacker-editable.
        descriptor = self.native.security(job)
        owner = self.native.descriptor_owner(descriptor)
        if (not self.private_dacl(descriptor, self.native.current_sid())
                or owner not in {self.native.current_sid(), "S-1-5-18", "S-1-5-32-544"}):
            raise RenProfileError(f"工具数据目录权限需要整理：{Path(job).absolute()}")

    def prepare_storage(self, root, create=True):
        """Create/repair our data directory; never delete or move its contents."""
        root = Path(root).absolute()
        plain_path(root)
        if not root.exists():
            if not create:
                raise RenProfileError(f"找不到恢复目录：{root}")
            self.native.secure_directory(root)
        try:
            self.check_job(root)
            return
        except (OSError, RenProfileError):
            pass
        try:
            with self.native.privileges():
                self.native.repair_directory_security(root)
            self.check_job(root)
        except (OSError, RenProfileError) as error:
            raise OperationError("整理工具数据目录权限", str(root), error) from error

    def prepare_record(self, job):
        job = Path(job).absolute()
        root = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RenProfile-Py"
        managed = (job.parent == root.absolute() and re.fullmatch(
            r"(?:job-\d{8}-\d{6}-[a-f0-9]{12}|cleanup-[a-f0-9]{32})", job.name))
        if managed:
            self.prepare_storage(job, create=False)
        else:
            self.check_job(job)

    @staticmethod
    def private_dacl(descriptor, current_sid):
        """Compare allow entries by meaning, not byte order or ACL padding."""
        import struct
        if not struct.unpack_from("<H", descriptor, 2)[0] & 0x1000:
            return False
        acl = Host.dacl(descriptor)
        if not acl or len(acl) < 8:
            return False
        allowed = {"S-1-5-18", "S-1-5-32-544", current_sid}
        grants, offset = {}, 8
        for _ in range(struct.unpack_from("<H", acl, 4)[0]):
            if offset + 16 > len(acl):
                return False
            kind, flags, size, mask = struct.unpack_from("<BBHI", acl, offset)
            if kind != 0 or flags & ~0x13 or size < 16 or offset + size > len(acl):
                return False
            sid = acl[offset + 8:offset + size]
            if sid[0] != 1 or 8 + 4 * sid[1] != len(sid):
                return False
            authority = int.from_bytes(sid[2:8], "big")
            sub = struct.unpack_from("<" + "I" * sid[1], sid, 8)
            name = "S-1-" + str(authority) + "".join("-" + str(x) for x in sub)
            if name not in allowed:
                return False
            if mask & 0x10000000:  # GENERIC_ALL
                mask |= 0x1F01FF
            if flags & 3 == 3:
                grants[name] = grants.get(name, 0) | mask
            offset += size
        return all(grants.get(sid, 0) & 0x1F01FF == 0x1F01FF
                   for sid in ("S-1-5-18", "S-1-5-32-544"))

    @staticmethod
    def dacl(descriptor):
        # Self-relative SECURITY_DESCRIPTOR: DACL offset at byte 16; ACL size at +2.
        import struct
        offset = struct.unpack_from("<I", descriptor, 16)[0]
        if not offset:
            return None
        size = struct.unpack_from("<H", descriptor, offset + 2)[0]
        return descriptor[offset:offset + size]

    @contextmanager
    def lock(self):
        create = self.native.kernel.CreateMutexW
        create.argtypes, create.restype = [w.LPVOID, w.BOOL, w.LPCWSTR], w.HANDLE
        ctypes.set_last_error(0)
        handle = create(None, False, "Global\\RenProfile-Py-Operation-v2")
        error = ctypes.get_last_error()
        self.native.check(handle)
        try:
            if error == 183:
                raise RenProfileError("另一个 RenProfile 操作仍在运行。")
            yield
        finally:
            self.native.close(handle)

    def transition_file(self, action, identity, undo=False):
        if action.kind == "directory":
            before, after = (action.after, action.before) if undo else (action.before, action.after)
            if os.path.lexists(after) and not is_reparse(after) and not os.path.lexists(before):
                if self.identity(after) == identity:
                    return
            if not os.path.lexists(before) or os.path.lexists(after) or self.identity(before) != identity:
                raise ConflictError("目录状态、文件标识或 ACL 已变化，拒绝移动。")
            try:
                self.native.rename_directory(before, after)
            except OSError as error:
                raise self.directory_error(before, after, error) from error
            if self.identity(after) != identity:
                raise ConflictError("目录改名后的文件标识或 ACL 校验失败。")
        elif action.kind == "junction":
            source, target = action.name, action.after
            present = os.path.lexists(source)
            if present:
                self.check_junction(source, target)
            if undo:
                if present:
                    os.rmdir(source)  # Remove link only, never recurse into its target.
            elif not present:
                self.native.junction(source, target)
        else:
            raise RenProfileError(f"未知文件动作：{action.kind}")
