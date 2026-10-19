"""Scanning scope and fresh snapshot tests for the v4 workflow."""
import unittest
from renprofile.paths import PathRewriter
from renprofile.scanner import scan, MACHINE_SCOPES, managed_user_key


class Key:
    def __init__(self, root, path):
        self.root, self.path = root, path
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass


class ScanRegistry:
    def __init__(self, values=None, children=None, denied=()):
        self.values, self.children, self.denied = values or {}, children or {}, denied
        self.w, self.opened = self, []
    def open(self, root, path):
        self.opened.append((root, path))
        if (root, path) in self.denied:
            raise PermissionError("denied")
        return Key(root, path)
    def QueryInfoKey(self, h):
        return len(self.children.get((h.root, h.path), [])), len(self.values.get((h.root, h.path), [])), 0
    def EnumValue(self, h, i):
        return self.values[h.root, h.path][i]
    def EnumKey(self, h, i):
        return self.children[h.root, h.path][i]


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.rewrite = PathRewriter(r"C:\Users\Old", r"C:\Users\New")

    def test_types_preserved_and_names_indexes_binary_are_not_rewritten(self):
        registry = ScanRegistry(values={("USER", ""): [
            ("", r"C:\Users\Old\Desktop", 2),
            (r"C:\Users\Old", "index-data", 1),
            ("list", [r"C:\Users\Old", "%USERPROFILE%"], 7),
            ("binary", b"C:\\Users\\Old", 3)]})
        actions, gaps = scan(registry, self.rewrite, {"USER": "NTUSER.DAT"})
        self.assertEqual(gaps, [])
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0].name, "")
        self.assertEqual(actions[0].after, {"kind": 2, "data": r"C:\Users\New\Desktop"})
        self.assertEqual(actions[1].after, {"kind": 7, "data": [r"C:\Users\New", "%USERPROFILE%"]})

    def test_machine_scanning_can_never_visit_state_repository_or_device_tree(self):
        registry = ScanRegistry(children={
            ("SOFTWARE", ""): [r"Microsoft\Windows\CurrentVersion\AppModel\StateRepository"],
            ("SYSTEM", ""): [r"Control\Class"]})
        scan(registry, self.rewrite, {})
        self.assertEqual(registry.opened, [(root, key) for root, key, _ in MACHINE_SCOPES])
        self.assertFalse(any("StateRepository" in key or key == "" for _, key in registry.opened))

    def test_denied_user_settings_do_not_prevent_other_settings_being_scanned(self):
        registry = ScanRegistry(children={("USER", ""): ["locked", "normal"]},
            denied={("USER", "locked")}, values={("USER", "normal"): [("Path", r"C:\Users\Old", 1)]})
        actions, gaps = scan(registry, self.rewrite, {"USER": "NTUSER.DAT"})
        self.assertEqual(len(actions), 1)
        self.assertEqual(gaps, [{"root": "USER", "key": "locked", "error": "denied"}])

    def test_managed_user_appmodel_is_excluded_before_opening(self):
        key = r"Software\Microsoft\Windows\CurrentVersion\AppModel"
        registry = ScanRegistry(children={("USER", ""): [key]})
        actions, gaps = scan(registry, self.rewrite, {"USER": "NTUSER.DAT"})
        self.assertNotIn(("USER", key), registry.opened)
        self.assertEqual(gaps[0]["key"], key)
        self.assertTrue(managed_user_key(key.lower() + r"\x"))
        self.assertFalse(managed_user_key(key + "Backup"))

    def test_scans_read_updated_values_on_each_invocation(self):
        registry = ScanRegistry(values={("USER", ""): [("Path", r"C:\Users\Old\one", 1)]})
        first, _ = scan(registry, self.rewrite, {"USER": "NTUSER.DAT"})
        registry.values["USER", ""] = [("Path", r"C:\Users\Old\two", 1)]
        second, _ = scan(registry, self.rewrite, {"USER": "NTUSER.DAT"})
        self.assertNotEqual(first[0].before, second[0].before)
        self.assertEqual(second[0].after["data"], r"C:\Users\New\two")

    def test_registry_links_are_not_followed(self):
        registry = ScanRegistry(values={("USER", ""): [("SymbolicLinkValue", "link", 6)]},
                                children={("USER", ""): ["outside"]})
        actions, gaps = scan(registry, self.rewrite, {"USER": "NTUSER.DAT"})
        self.assertNotIn(("USER", "outside"), registry.opened)
        self.assertEqual(len(gaps), 1)
