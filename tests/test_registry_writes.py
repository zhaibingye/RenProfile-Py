"""Minimal registry access and diagnostics, including an isolated Windows ACL test."""

from contextlib import contextmanager, nullcontext
import ctypes
import os
import unittest
from unittest.mock import Mock
import uuid

from renprofile.errors import OperationError
from renprofile.model import snapshot
from renprofile.registry import Registry


def denied():
    error = PermissionError("[WinError 5] 拒绝访问。")
    error.winerror = 5
    return error


class RegistryWriteTests(unittest.TestCase):
    def registry(self):
        registry = Registry.__new__(Registry)
        registry.system_path = r"SYSTEM\ControlSet001"
        registry.location = Mock(return_value=(123, r"SOFTWARE\Test"))
        registry.w = Mock(KEY_QUERY_VALUE=1, KEY_SET_VALUE=2, KEY_ENUMERATE_SUB_KEYS=8,
                          KEY_WOW64_64KEY=0x100, KEY_WRITE=0x20006)
        registry.w.OpenKey.return_value = nullcontext(456)
        return registry

    def test_set_and_delete_do_not_request_create_subkey_or_enumerate_rights(self):
        for value in (snapshot((2, "new-path")), None):
            with self.subTest(value=value):
                registry = self.registry()
                registry.set("SOFTWARE", "Test", "Path", value)
                self.assertEqual(registry.w.OpenKey.call_args.args[3], 0x103)
                registry.w.FlushKey.assert_called_once_with(456)

    def test_query_does_not_request_enumeration_rights(self):
        registry = self.registry()
        registry.w.QueryValueEx.return_value = ("old-path", 2)
        self.assertEqual(registry.get("SOFTWARE", "Test", "Path"), snapshot((2, "old-path")))
        self.assertEqual(registry.w.OpenKey.call_args.args[3], 0x101)

    def test_denial_distinguishes_open_write_and_flush_without_disclosing_value_data(self):
        for call, phase in (("OpenKey", "打开注册表项以写入值"), ("SetValueEx", "写入注册表值"),
                            ("FlushKey", "将注册表改动写入磁盘")):
            with self.subTest(call=call):
                registry = self.registry()
                getattr(registry.w, call).side_effect = denied()
                with self.assertRaises(OperationError) as caught:
                    registry.set("SOFTWARE", r"Vendor\Protected", "ProfilePath", snapshot((2, "private-data")))
                error = caught.exception
                self.assertEqual(error.operation, phase)
                self.assertEqual(error.winerror, 5)
                self.assertIn(r"HKLM\SOFTWARE\Vendor\Protected", str(error))
                self.assertIn("ProfilePath", str(error))
                self.assertNotIn("private-data", str(error))
                self.assertIsInstance(error.__cause__, PermissionError)


@contextmanager
def volatile_key():
    """Create exactly one fresh HKCU test key; never edit existing keys or ACLs."""
    import winreg
    from ctypes import wintypes as w
    from renprofile.native import Native, SECURITY_ATTRIBUTES
    native = Native()
    leaf = "RenProfile-Test-" + uuid.uuid4().hex
    # Query/set/enumerate/delete/WRITE_DAC, deliberately without CREATE_SUB_KEY.
    # WRITE_DAC belongs only to this disposable key and is not used by Registry.
    descriptor, size = w.LPVOID(), w.DWORD()
    native.check(native.convert_sd(f"D:P(A;;0x0005000B;;;{native.current_sid()})", 1,
                                   ctypes.byref(descriptor), ctypes.byref(size)))
    create = native.adv.RegCreateKeyExW
    create.restype = w.LONG
    create.argtypes = [w.HANDLE, w.LPCWSTR, w.DWORD, w.LPWSTR, w.DWORD, w.DWORD,
                       ctypes.POINTER(SECURITY_ATTRIBUTES), ctypes.POINTER(w.HANDLE), ctypes.POINTER(w.DWORD)]
    created = False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software", 0,
                            winreg.KEY_CREATE_SUB_KEY | winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY) as parent:
            handle, disposition = w.HANDLE(), w.DWORD()
            attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
            code = create(int(parent), leaf, 0, None, 1, 0x5000B | winreg.KEY_WOW64_64KEY,
                          ctypes.byref(attrs), ctypes.byref(handle), ctypes.byref(disposition))
            if code:
                raise ctypes.WinError(code)
            created = disposition.value == 1
            winreg.CloseKey(handle.value)
            try:
                if not created:
                    raise AssertionError("Refusing to use an existing registry key")
                yield native, "Software\\" + leaf
            finally:
                if created:
                    winreg.DeleteKeyEx(parent, leaf, winreg.KEY_WOW64_64KEY)
    finally:
        native.local_free(descriptor)


@unittest.skipUnless(os.name == "nt", "Windows registry ACLs")
class WindowsRegistryAccessTests(unittest.TestCase):
    def test_original_write_mask_denied_but_minimal_value_update_succeeds(self):
        import winreg
        with volatile_key() as (native, path):
            old_rights = winreg.KEY_QUERY_VALUE | winreg.KEY_ENUMERATE_SUB_KEYS | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            with self.assertRaises(PermissionError) as caught:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0x8, old_rights):
                    pass
            self.assertEqual(caught.exception.winerror, 5)
            registry = Registry(native)
            registry.location = lambda root, key="": (winreg.HKEY_CURRENT_USER, path)
            value = snapshot((2, r"C:\Users\YiYang\Desktop"))
            registry.set("USER", "test-only", "ProfilePath", value)
            self.assertEqual(registry.get("USER", "test-only", "ProfilePath"), value)
            registry.set("USER", "test-only", "ProfilePath", None)
            self.assertIsNone(registry.get("USER", "test-only", "ProfilePath"))
        with self.assertRaises(FileNotFoundError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)


if __name__ == "__main__":
    unittest.main()
