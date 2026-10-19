"""Restart Manager diagnostics only. Never shut down or restart applications."""

import ctypes
from ctypes import wintypes as w


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", w.DWORD), ("ProcessStartTime", w.FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS), ("strAppName", w.WCHAR * 256),
                ("strServiceShortName", w.WCHAR * 64), ("ApplicationType", ctypes.c_int),
                ("AppStatus", w.ULONG), ("TSSessionId", w.DWORD), ("bRestartable", w.BOOL)]


def file_users(files):
    if not files:
        return []
    dll = ctypes.WinDLL("rstrtmgr", use_last_error=True)
    start = dll.RmStartSession
    start.argtypes, start.restype = [ctypes.POINTER(w.DWORD), w.DWORD, w.LPWSTR], w.DWORD
    register = dll.RmRegisterResources
    register.argtypes = [w.DWORD, w.UINT, ctypes.POINTER(w.LPCWSTR), w.UINT,
                        ctypes.POINTER(RM_UNIQUE_PROCESS), w.UINT, ctypes.POINTER(w.LPCWSTR)]
    register.restype = w.DWORD
    get_list = dll.RmGetList
    get_list.argtypes = [w.DWORD, ctypes.POINTER(w.UINT), ctypes.POINTER(w.UINT),
                         ctypes.POINTER(RM_PROCESS_INFO), ctypes.POINTER(w.DWORD)]
    get_list.restype = w.DWORD
    end = dll.RmEndSession
    end.argtypes, end.restype = [w.DWORD], w.DWORD
    session, key = w.DWORD(), ctypes.create_unicode_buffer(33)
    code = start(ctypes.byref(session), 0, key)
    if code:
        raise ctypes.WinError(code)
    try:
        resources = (w.LPCWSTR * len(files))(*files)
        code = register(session, len(files), resources, 0, None, 0, None)
        if code:
            raise ctypes.WinError(code)
        needed, count, reasons = w.UINT(), w.UINT(), w.DWORD()
        code = get_list(session, ctypes.byref(needed), ctypes.byref(count), None, ctypes.byref(reasons))
        for _ in range(3):
            if code == 0 and not needed.value:
                return []
            if code not in (0, 234) or needed.value > 4096:
                raise ctypes.WinError(code or 8)
            count.value = needed.value
            entries = (RM_PROCESS_INFO * count.value)()
            code = get_list(session, ctypes.byref(needed), ctypes.byref(count), entries, ctypes.byref(reasons))
            if code == 0:
                return [{"pid": entries[i].Process.dwProcessId, "name": entries[i].strAppName,
                         "service": entries[i].strServiceShortName} for i in range(count.value)]
        raise ctypes.WinError(code)
    finally:
        end(session)
