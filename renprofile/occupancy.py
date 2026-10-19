"""Find profile-tree users in an isolated reader; terminate verified processes.

The handle table layout is SystemExtendedHandleInformation (phnt/ntexapi.h).
Only duplicated disk handles are queried. No foreign handle is forcibly closed.
"""

import ctypes
from ctypes import wintypes as w
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import uuid

from .errors import RenProfileError
from .paths import within


PROTECTED_NAMES = frozenset((
    "system", "registry", "secure system", "memory compression", "smss.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "winlogon.exe", "logonui.exe", "svchost.exe",
))


class HandleEntry(ctypes.Structure):
    _fields_ = [("object", w.LPVOID), ("pid", ctypes.c_size_t),
                ("handle", ctypes.c_size_t), ("access", w.ULONG),
                ("trace", w.USHORT), ("type", w.USHORT),
                ("attributes", w.ULONG), ("reserved", w.ULONG)]


class ProcessEntry(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                ("heap", ctypes.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                ("name", w.WCHAR * 260)]


class ModuleEntry(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("module", w.DWORD), ("pid", w.DWORD),
                ("global_usage", w.DWORD), ("process_usage", w.DWORD),
                ("base", w.LPVOID), ("length", w.DWORD), ("handle", w.HMODULE),
                ("name", w.WCHAR * 256), ("path", w.WCHAR * 260)]


def path_key(path):
    path = str(path)
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    else:
        path = path.removeprefix("\\\\?\\").removeprefix("\\??\\")
    return ntpath.normcase(ntpath.normpath(path))


def in_tree(path, root):
    path, root = path_key(path), path_key(root)
    # A filename containing the folder name, or a sibling Old2, is not a match.
    return path == root or path.startswith(root.rstrip("\\") + "\\") or path.startswith(root + ":")


class Windows:
    def __init__(self):
        from .native import Native
        self.native = Native()
        self.k = self.native.kernel
        self.nt = ctypes.WinDLL("ntdll")

        def bind(dll, name, result, *args):
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = result, args
            return fn

        self.query = bind(self.nt, "NtQuerySystemInformation", w.LONG,
                          w.ULONG, w.LPVOID, w.ULONG, ctypes.POINTER(w.ULONG))
        self.open = bind(self.k, "OpenProcess", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
        self.duplicate = bind(self.k, "DuplicateHandle", w.BOOL, w.HANDLE, w.HANDLE,
                              w.HANDLE, ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD)
        self.file_type = bind(self.k, "GetFileType", w.DWORD, w.HANDLE)
        self.final_path = bind(self.k, "GetFinalPathNameByHandleW", w.DWORD,
                               w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD)
        self.image = bind(self.k, "QueryFullProcessImageNameW", w.BOOL,
                          w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
        self.times = bind(self.k, "GetProcessTimes", w.BOOL, w.HANDLE,
                          *([ctypes.POINTER(w.FILETIME)] * 4))
        self.critical = bind(self.k, "IsProcessCritical", w.BOOL, w.HANDLE, ctypes.POINTER(w.BOOL))
        self.terminate = bind(self.k, "TerminateProcess", w.BOOL, w.HANDLE, w.UINT)
        self.wait = bind(self.k, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
        self.snapshot = bind(self.k, "CreateToolhelp32Snapshot", w.HANDLE, w.DWORD, w.DWORD)
        self.process_first = bind(self.k, "Process32FirstW", w.BOOL, w.HANDLE, ctypes.POINTER(ProcessEntry))
        self.process_next = bind(self.k, "Process32NextW", w.BOOL, w.HANDLE, ctypes.POINTER(ProcessEntry))
        self.module_first = bind(self.k, "Module32FirstW", w.BOOL, w.HANDLE, ctypes.POINTER(ModuleEntry))
        self.module_next = bind(self.k, "Module32NextW", w.BOOL, w.HANDLE, ctypes.POINTER(ModuleEntry))

    def handle_path(self, handle):
        buf = ctypes.create_unicode_buffer(32768)
        count = self.final_path(handle, buf, len(buf), 0)
        return buf.value if 0 < count < len(buf) else ""

    def metadata(self, handle, pid):
        creation, exit_time, kernel, user = (w.FILETIME() for _ in range(4))
        self.native.check(self.times(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                     ctypes.byref(kernel), ctypes.byref(user)))
        buf, size, critical = ctypes.create_unicode_buffer(32768), w.DWORD(32768), w.BOOL()
        self.native.check(self.image(handle, 0, buf, ctypes.byref(size)))
        self.native.check(self.critical(handle, ctypes.byref(critical)))
        return {"pid": pid, "created": (creation.dwHighDateTime << 32) | creation.dwLowDateTime,
                "image": buf.value, "name": ntpath.basename(buf.value), "critical": bool(critical.value)}

    def processes(self):
        handle = self.snapshot(2, 0)
        if handle == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            result, entry = {}, ProcessEntry()
            entry.size = ctypes.sizeof(entry)
            more = self.process_first(handle, ctypes.byref(entry))
            while more:
                result[entry.pid] = (entry.parent, entry.name)
                more = self.process_next(handle, ctypes.byref(entry))
            if not result:
                raise ctypes.WinError(ctypes.get_last_error())
            return result
        finally:
            self.native.close(handle)

    def excluded(self):
        entries, excluded, pid = self.processes(), {0, 4}, os.getpid()
        while pid and pid not in excluded:
            excluded.add(pid)
            pid = entries.get(pid, (0, ""))[0]
        return excluded

    def modules(self, pid):
        handle = self.snapshot(0x18, pid)
        if handle == w.HANDLE(-1).value:
            return
        try:
            entry = ModuleEntry()
            entry.size = ctypes.sizeof(entry)
            more = self.module_first(handle, ctypes.byref(entry))
            while more:
                yield entry.path
                more = self.module_next(handle, ctypes.byref(entry))
        finally:
            self.native.close(handle)

    def handles(self):
        size = 1024 * 1024
        while size <= 256 * 1024 * 1024:
            buf, needed = ctypes.create_string_buffer(size), w.ULONG()
            status = self.query(64, buf, size, ctypes.byref(needed))
            if status & 0xFFFFFFFF in (0xC0000004, 0xC0000023):
                size = max(size * 2, needed.value + 65536)
                continue
            if status < 0:
                raise RenProfileError(f"系统句柄查询失败：NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
            count = ctypes.c_size_t.from_buffer(buf).value
            offset, width = 2 * ctypes.sizeof(ctypes.c_size_t), ctypes.sizeof(HandleEntry)
            if count > (size - offset) // width:
                raise RenProfileError("系统句柄表长度无效，未结束任何进程。")
            return buf, (HandleEntry * count).from_buffer(buf, offset)
        raise RenProfileError("系统句柄表过大，本次占用检查未完成。")


def scan_worker(root, output):
    """Hidden read-only child. Stream findings so a timeout loses no known users."""
    from .host import plain_path
    plain_path(root)
    plain_path(output)
    root = str(Path(root).resolve(strict=True))
    if within(str(Path(output).absolute()), root):
        raise RenProfileError("占用检查记录不能写入目标用户目录。")
    with Path(output).open("x", encoding="utf-8", buffering=1) as stream:
        def write(record):
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

        write({"kind": "root", "path": root})
        api, opened, found, canonical_paths = Windows(), {}, set(), {}
        denied, checked = 0, 0
        probe = api.native.create_file(root, 0, 7, None, 3, 0x02000000, None)
        if probe == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            with api.native.privileges(("SeDebugPrivilege",), required=False):
                buffer, handles = api.handles()
                file_type = next((h.type for h in handles if h.pid == os.getpid() and h.handle == probe), None)
                if file_type is None:
                    raise RenProfileError("无法识别文件句柄类型，未结束任何进程。")

                def process(pid):
                    nonlocal denied, checked
                    if pid not in opened:
                        handle = api.open(0x1040, False, pid)  # Query + duplicate only.
                        try:
                            info = api.metadata(handle, pid) if handle else None
                        except OSError:
                            info = None
                        if info is None:
                            if handle:
                                api.native.close(handle)
                            opened[pid] = (None, None)
                            denied += 1
                        else:
                            opened[pid] = (handle, info)
                            checked += 1
                    return opened[pid]

                def match(info, path, *, resolved=False):
                    if not path or info["pid"] in found:
                        return
                    if not resolved:
                        key = path_key(path)
                        if key not in canonical_paths:
                            try:
                                canonical_paths[key] = str(Path(path).resolve(strict=True))
                            except OSError:
                                canonical_paths[key] = ""
                        path = canonical_paths[key]
                    if not path or not in_tree(path, root):
                        return
                    found.add(info["pid"])
                    write({"kind": "process", **info, "path": path})

                for entry in handles:
                    if entry.type != file_type or entry.pid in (0, 4, os.getpid()) or entry.pid in found:
                        continue
                    owner, info = process(entry.pid)
                    if not owner:
                        continue
                    duplicate = w.HANDLE()
                    if not api.duplicate(owner, entry.handle, api.native.current_process(),
                                         ctypes.byref(duplicate), 0, False, 2):
                        continue  # A handle may close after the table snapshot.
                    try:
                        if api.file_type(duplicate) == 1:  # Disk files/directories, never pipes.
                            match(info, api.handle_path(duplicate), resolved=True)
                    finally:
                        api.native.close(duplicate)
                # Executables and DLL mappings can outlive their original file handle.
                for pid in api.processes():
                    if pid in (0, 4, os.getpid()) or pid in found:
                        continue
                    owner, info = process(pid)
                    if not owner:
                        continue
                    match(info, info["image"])
                    if pid not in found:
                        for path in api.modules(pid):
                            match(info, path)
                            if pid in found:
                                break
                write({"kind": "summary", "checked": checked, "unreadable": denied})
        finally:
            api.native.close(probe)
            for handle, _ in opened.values():
                if handle:
                    api.native.close(handle)
    return 0


def scan_tree(root, workspace, *, timeout=35):
    """The child can be killed if a filesystem driver blocks a name query."""
    from .host import plain_path
    root = str(Path(root).resolve(strict=True))
    workspace = Path(workspace)
    plain_path(workspace)
    output = workspace / ("locks-" + uuid.uuid4().hex + ".jsonl")
    arguments = ([sys.executable] if getattr(sys, "frozen", False)
                 else [sys.executable, "-B", "-m", "renprofile"])
    arguments += ["--scan-locks", root, str(output)]
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    environment.pop("PYINSTALLER_RESET_ENVIRONMENT", None)  # Reuse our existing extraction.
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=environment,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()  # Only the reader started immediately above.
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            raise RenProfileError("占用查询进程未能及时退出，已停止本次查询。") from error
    result = {"processes": [], "incomplete": True, "checked": 0, "unreadable": 0}
    try:
        plain_path(output)
        if output.stat().st_size > 8 * 1024 * 1024:
            raise RenProfileError("占用检查记录过大，未采用其中的进程信息。")
        records = []
        lines = output.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except ValueError as error:
                if timed_out and index == len(lines) - 1:
                    break  # The reader may have been killed during its last write.
                raise RenProfileError("无法读取占用查询结果。") from error
        if not records or records[0] != {"kind": "root", "path": root}:
            raise RenProfileError("占用检查结果与目标目录不一致。")
        for record in records[1:]:
            if not isinstance(record, dict):
                raise RenProfileError("占用检查记录格式无效。")
            if record.get("kind") == "process":
                if (type(record.get("pid")) is not int or type(record.get("created")) is not int
                        or not 0 < record["pid"] < 0xFFFFFFFF or record["created"] <= 0
                        or not all(isinstance(record.get(key), str) for key in ("path", "image", "name"))
                        or not in_tree(record["path"], root)):
                    raise RenProfileError("占用检查进程记录无效。")
                result["processes"].append(record)
            elif record.get("kind") == "summary":
                if any(type(record.get(key)) is not int or record[key] < 0 for key in ("checked", "unreadable")):
                    raise RenProfileError("占用检查汇总无效。")
                result.update(checked=record["checked"], unreadable=record["unreadable"], incomplete=False)
        result["incomplete"] |= timed_out or process.returncode != 0
        return result
    finally:
        output.unlink(missing_ok=True)


def terminate_users(entries, *, api=None, emit=lambda text: None):
    if not entries:
        return {"terminated": [], "remaining": []}
    api = api or Windows()
    excluded = api.excluded()  # Never terminate the tool, its launcher or parents.
    result = {"terminated": [], "remaining": []}
    with api.native.privileges(("SeDebugPrivilege",), required=False):
        for entry in entries:
            pid = entry["pid"]
            handle = None
            try:
                if pid in excluded:
                    raise RenProfileError("本工具或其启动进程，保留")
                handle = api.open(0x101001, False, pid)  # Terminate + query + synchronize.
                if not handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                current = api.metadata(handle, pid)
                if current["created"] != entry["created"]:
                    continue  # PID was reused; this is a different process.
                if current["critical"] or current["name"].casefold() in PROTECTED_NAMES:
                    raise RenProfileError("关键系统进程或共享服务宿主，保留")
                if api.wait(handle, 0) == 0:
                    continue  # It already exited.
                api.native.check(api.terminate(handle, 1))
                if api.wait(handle, 5000) != 0:
                    raise RenProfileError("已请求强制结束，但进程尚未退出")
                result["terminated"].append(entry)
                emit(f"已强制结束占用程序：{current['name']}（PID {pid}）")
            except (OSError, RenProfileError) as error:
                result["remaining"].append({**entry, "reason": str(error)})
                emit(f"未结束进程 {pid}：{error}")
            finally:
                if handle:
                    api.native.close(handle)
    return result


def force_release(root, workspace, emit=lambda text: None):
    scan = scan_tree(root, workspace)
    result = terminate_users(scan.pop("processes"), emit=emit)
    result.update(scan)
    result["diagnostic"] = (f"已检查整个目录树的可查询文件/目录句柄及程序模块；"
                            f"查询 {scan['checked']} 个进程，{scan['unreadable']} 个进程无法读取；"
                            f"结束 {len(result['terminated'])} 个，保留 {len(result['remaining'])} 个。")
    if scan["incomplete"]:
        result["diagnostic"] += "检查超时或中断，已使用此前查明的占用信息；不能据此排除其他占用。"
    emit(result["diagnostic"])
    return result
