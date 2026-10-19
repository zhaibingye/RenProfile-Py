"""Small, explicitly typed Unicode Win32 API layer. No shell interpolation."""

import ctypes
from ctypes import wintypes as w
from contextlib import contextmanager
import os
from pathlib import Path
import struct
import time

from .errors import RenProfileError

JOB_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", w.DWORD), ("HighPart", w.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", w.DWORD), ("Luid", LUID), ("Attributes", w.DWORD)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", w.DWORD), ("lpSecurityDescriptor", w.LPVOID), ("bInheritHandle", w.BOOL)]


class WTS_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("SessionId", w.DWORD), ("ProcessId", w.DWORD),
                ("pProcessName", w.LPWSTR), ("pUserSid", w.LPVOID)]


class FILE_RENAME_INFO(ctypes.Structure):
    _fields_ = [("Flags", w.DWORD), ("RootDirectory", w.HANDLE),
                ("FileNameLength", w.DWORD), ("FileName", w.WCHAR * 1)]


class Native:
    def __init__(self):
        if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise RenProfileError("需要 64 位 Windows 和 64 位 Python 3.11 或更新版本。")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.wts = ctypes.WinDLL("wtsapi32", use_last_error=True)

        def bind(dll, name, result, *args):
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = result, args
            return fn

        self.current_process = bind(self.kernel, "GetCurrentProcess", w.HANDLE)
        self.close = bind(self.kernel, "CloseHandle", w.BOOL, w.HANDLE)
        self.local_free = bind(self.kernel, "LocalFree", w.HLOCAL, w.HLOCAL)
        self.open_token = bind(self.adv, "OpenProcessToken", w.BOOL, w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
        self.get_token = bind(self.adv, "GetTokenInformation", w.BOOL, w.HANDLE, ctypes.c_int,
                              w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
        self.sid_string = bind(self.adv, "ConvertSidToStringSidW", w.BOOL, w.LPVOID, ctypes.POINTER(w.LPWSTR))
        self.lookup = bind(self.adv, "LookupPrivilegeValueW", w.BOOL, w.LPCWSTR, w.LPCWSTR, ctypes.POINTER(LUID))
        self.adjust = bind(self.adv, "AdjustTokenPrivileges", w.BOOL, w.HANDLE, w.BOOL,
                           ctypes.POINTER(TOKEN_PRIVILEGES), w.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES),
                           ctypes.POINTER(w.DWORD))
        self.enum_processes = bind(self.wts, "WTSEnumerateProcessesW", w.BOOL, w.HANDLE, w.DWORD, w.DWORD,
                                   ctypes.POINTER(ctypes.POINTER(WTS_PROCESS_INFO)), ctypes.POINTER(w.DWORD))
        self.wts_free = bind(self.wts, "WTSFreeMemory", None, w.LPVOID)
        self.short_path_fn = bind(self.kernel, "GetShortPathNameW", w.DWORD, w.LPCWSTR, w.LPWSTR, w.DWORD)
        self.unload = bind(self.adv, "RegUnLoadKeyW", w.LONG, w.HANDLE, w.LPCWSTR)
        self.rename_key_fn = bind(self.adv, "RegRenameKey", w.LONG, w.HANDLE, w.LPCWSTR, w.LPCWSTR)
        self.file_security = bind(self.adv, "GetFileSecurityW", w.BOOL, w.LPCWSTR, w.DWORD,
                                  w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
        self.set_security_info = bind(self.adv, "SetSecurityInfo", w.DWORD, w.HANDLE, ctypes.c_int,
                                      w.DWORD, w.LPVOID, w.LPVOID, w.LPVOID, w.LPVOID)
        self.convert_sd = bind(self.adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
                               w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD))
        self.create_dir = bind(self.kernel, "CreateDirectoryW", w.BOOL, w.LPCWSTR,
                               ctypes.POINTER(SECURITY_ATTRIBUTES))
        self.create_file = bind(self.kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD,
                                w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        self.set_file_info = bind(self.kernel, "SetFileInformationByHandle", w.BOOL,
                                  w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
        self.device_io = bind(self.kernel, "DeviceIoControl", w.BOOL, w.HANDLE, w.DWORD, w.LPVOID,
                              w.DWORD, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID)
        self.volume_info = bind(self.kernel, "GetVolumeInformationW", w.BOOL, w.LPCWSTR, w.LPWSTR,
                                w.DWORD, ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD),
                                ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD)

    @staticmethod
    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def sid_text(self, pointer):
        output = w.LPWSTR()
        self.check(self.sid_string(pointer, ctypes.byref(output)))
        try:
            return output.value
        finally:
            self.local_free(ctypes.cast(output, w.HLOCAL))

    @contextmanager
    def token(self, rights=0x0008):
        token = w.HANDLE()
        self.check(self.open_token(self.current_process(), rights, ctypes.byref(token)))
        try:
            yield token
        finally:
            self.close(token)

    def current_sid(self):
        with self.token() as token:
            size = w.DWORD()
            self.get_token(token, 1, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            self.check(self.get_token(token, 1, buf, size, ctypes.byref(size)))
            return self.sid_text(ctypes.cast(buf, ctypes.POINTER(w.LPVOID))[0])

    def elevated(self):
        with self.token() as token:
            value, size = w.DWORD(), w.DWORD()
            self.check(self.get_token(token, 20, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size)))
            return bool(value.value)

    @contextmanager
    def privileges(self, names=("SeBackupPrivilege", "SeRestorePrivilege"), *, required=True):
        """Restore prior privilege state even on failure; close the token handle."""
        with self.token(0x0020 | 0x0008) as token:
            previous = []
            try:
                for name in names:
                    state, prior, length = TOKEN_PRIVILEGES(), TOKEN_PRIVILEGES(), w.DWORD()
                    state.PrivilegeCount, state.Attributes = 1, 2
                    self.check(self.lookup(None, name, ctypes.byref(state.Luid)))
                    ctypes.set_last_error(0)
                    ok = self.adjust(token, False, ctypes.byref(state), ctypes.sizeof(prior),
                                     ctypes.byref(prior), ctypes.byref(length))
                    error = ctypes.get_last_error()
                    if ok:
                        previous.append(prior)
                    if error == 1300 and not required:
                        continue  # Standard-user tests can still inspect their own children.
                    if not ok or error:
                        raise ctypes.WinError(error)
                yield
            finally:
                for prior in reversed(previous):
                    self.check(self.adjust(token, False, ctypes.byref(prior), 0, None, None))

    def processes_for(self, sid):
        entries, count = ctypes.POINTER(WTS_PROCESS_INFO)(), w.DWORD()
        self.check(self.enum_processes(None, 0, 1, ctypes.byref(entries), ctypes.byref(count)))
        try:
            return [(entries[i].ProcessId, entries[i].pProcessName)
                    for i in range(count.value)
                    if entries[i].pUserSid and self.sid_text(entries[i].pUserSid) == sid]
        finally:
            self.wts_free(entries)

    def short_path(self, path):
        size = self.short_path_fn(path, None, 0)
        if not size:
            return ""  # 8.3 can be disabled; never introduce an empty regex alternative.
        buf = ctypes.create_unicode_buffer(size)
        result = self.short_path_fn(path, buf, size)
        return buf.value if 0 < result < size else ""

    def security(self, path):
        size = w.DWORD()
        self.file_security(str(path), 7, None, 0, ctypes.byref(size))
        if not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buf = ctypes.create_string_buffer(size.value)
        self.check(self.file_security(str(path), 7, buf, size, ctypes.byref(size)))
        return buf.raw[:size.value]

    def security_descriptor(self, sddl):
        descriptor, size = w.LPVOID(), w.DWORD()
        self.check(self.convert_sd(sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)))
        try:
            return ctypes.string_at(descriptor, size.value)
        finally:
            self.local_free(descriptor)

    def job_security(self):
        return self.security_descriptor(JOB_SDDL)

    def set_directory_security(self, path, descriptor):
        """Set one directory's owner/DACL, without propagating to its children."""
        info = os.lstat(path)
        if info.st_file_attributes & 0x400 or not Path(path).is_dir():
            raise RenProfileError(f"工具数据位置必须是普通目录：{path}")
        # MAXIMUM_ALLOWED explicitly suppresses child ACL propagation for
        # SetSecurityInfo. Keep existing backup records and links untouched.
        handle = self.create_file(str(path), 0x02000000, 0x7, None, 3, 0x02200000, None)
        if handle == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            buffer = ctypes.create_string_buffer(descriptor)
            owner_offset = struct.unpack_from("<I", descriptor, 4)[0]
            dacl_offset = struct.unpack_from("<I", descriptor, 16)[0]
            if not dacl_offset:
                raise RenProfileError("工具目录权限模板缺少访问控制列表。")
            owner = ctypes.c_void_p(ctypes.addressof(buffer) + owner_offset) if owner_offset else None
            dacl = ctypes.c_void_p(ctypes.addressof(buffer) + dacl_offset)
            flags = 0x80000004 | (1 if owner_offset else 0)
            code = self.set_security_info(handle, 1, flags, owner, None, dacl, None)
            if code:
                raise ctypes.WinError(code)
        finally:
            self.close(handle)

    def repair_directory_security(self, path):
        """Normalize only a tool-owned directory, including its legacy owner."""
        self.set_directory_security(path, self.security_descriptor("O:BA" + JOB_SDDL))

    def descriptor_owner(self, descriptor):
        offset = struct.unpack_from("<I", descriptor, 4)[0]
        if not offset:
            return None
        buf = ctypes.create_string_buffer(descriptor)
        return self.sid_text(ctypes.c_void_p(ctypes.addressof(buf) + offset))

    def secure_directory(self, path):
        """New job folder accessible only to SYSTEM and elevated Administrators."""
        descriptor = ctypes.create_string_buffer(self.job_security())
        attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), ctypes.cast(descriptor, w.LPVOID), False)
        self.check(self.create_dir(str(path), ctypes.byref(attrs)))

    def require_ntfs(self, drive):
        fs = ctypes.create_unicode_buffer(64)
        self.check(self.volume_info(drive + "\\", None, 0, None, None, None, fs, len(fs)))
        if fs.value.upper() != "NTFS":
            raise RenProfileError("当前版本只支持本地 NTFS 用户目录。")

    @contextmanager
    def rename_handle(self, path):
        # DELETE is needed for rename; this does not delete anything. Backup
        # semantics lets already-enabled SeRestorePrivilege take effect without
        # taking ownership or rewriting a user's permissions.
        handle = self.create_file(str(path), 0x00010000, 0x7, None, 3, 0x02200000, None)
        if handle == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield handle
        finally:
            self.close(handle)

    def probe_directory_rename(self, path):
        """Check/open/close only: fail early on a root lock or denied access."""
        with self.rename_handle(path):
            pass

    def rename_directory(self, old, new):
        """Same-parent rename through a backup-aware handle; never replace."""
        from .paths import validate_pair
        old, new = validate_pair(str(old), str(new))
        encoded = new.encode("utf-16-le")
        offset = FILE_RENAME_INFO.FileName.offset
        buffer = ctypes.create_string_buffer(max(ctypes.sizeof(FILE_RENAME_INFO), offset + len(encoded) + 2))
        info = FILE_RENAME_INFO.from_buffer(buffer)
        info.Flags, info.RootDirectory, info.FileNameLength = 0, None, len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
        for attempt in range(3):
            try:
                with self.rename_handle(old) as handle:
                    self.check(self.set_file_info(handle, 3, buffer, len(buffer)))
                return
            except OSError as error:
                if getattr(error, "winerror", None) not in (5, 32, 33) or attempt == 2:
                    raise
                time.sleep((0.2, 0.5)[attempt])

    def rename_diagnostics(self, old):
        report = getattr(self, "_last_lock_report", None)
        if report and report[0].casefold() == str(old).casefold():
            return report[1]["remaining"], "最近一次完整目录占用检查：" + report[1]["diagnostic"]
        from .locks import file_users
        files = [str(Path(old) / name) for name in
                 ("NTUSER.DAT", r"AppData\Local\Microsoft\Windows\UsrClass.dat")]
        files = [name for name in files if os.path.isfile(name)]
        if not files:
            return [], "没有可查询的用户配置文件；未定位到具体占用者。"
        try:
            return file_users(files), "仅查询 NTUSER.DAT、UsrClass.dat；目录内其他文件的占用也可能导致失败。"
        except OSError as error:
            return [], f"占用查询未完成：{error}；不能据此排除占用。"

    def clear_profile_locks(self, root, workspace, emit=lambda text: None):
        from .occupancy import force_release
        self._last_lock_report = None
        result = force_release(root, workspace, emit)
        self._last_lock_report = (str(root), result)
        return result

    def junction(self, source, target):
        """Create an NTFS mount-point reparse point, avoiding cmd.exe/mklink."""
        source = Path(source)
        source.mkdir()  # must not already exist
        try:
            substitute, printable = ("\\??\\" + str(target)).encode("utf-16-le"), str(target).encode("utf-16-le")
            names = substitute + b"\0\0" + printable + b"\0\0"
            data = struct.pack("<IHHHHHH", 0xA0000003, len(names) + 8, 0, 0, len(substitute),
                               len(substitute) + 2, len(printable)) + names
            handle = self.create_file(str(source), 0x40000000, 0, None, 3, 0x00200000 | 0x02000000, None)
            if handle == w.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                output = w.DWORD()
                self.check(self.device_io(handle, 0x000900A4, data, len(data), None, 0,
                                           ctypes.byref(output), None))
            finally:
                self.close(handle)
        except BaseException:
            # Only an empty directory created by this invocation can be removed here.
            if source.exists() and not (os.lstat(source).st_file_attributes & 0x400):
                source.rmdir()
            raise
