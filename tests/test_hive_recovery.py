"""Simulate hive loading/unloading; never mount a real Windows hive."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from renprofile.errors import RenProfileError
from renprofile.journal import Journal
from renprofile.registry import Registry


class HiveRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="renprofile-hive-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "NTUSER.DAT").write_bytes(b"not a registry hive")
        (self.base / "plan.json").write_text("{}")
        self.journal = Journal(self.base, create=True)
        self.addCleanup(self.journal.close)
        self.registry = Registry.__new__(Registry)
        self.registry.w = Mock(HKEY_USERS=123)
        self.registry.native = Mock()
        self.registry.native.unload.return_value = 5
        self.registry.mounts = {}
        self.plan = {"old": str(self.base), "new": str(self.base.parent / "Renamed"),
                     "hive_files": {"USER": "NTUSER.DAT"}}

    def test_failed_unload_keeps_its_mount_identity_for_recovery(self):
        with self.assertRaises(RenProfileError):
            with self.registry.mounted(self.base, {"USER": "NTUSER.DAT"}):
                pass
        self.assertIn("USER", self.registry.mounts)

    def test_mount_is_journaled_before_loading_and_survives_unload_failure(self):
        def load(root, name, filename):
            saved = json.loads(self.journal.get("hive_mounts"))
            self.assertEqual(saved, [{"root": "USER", "name": name, "file": filename}])
        self.registry.w.LoadKey.side_effect = load
        with self.assertRaises(RenProfileError):
            with self.registry.mounted(self.base, {"USER": "NTUSER.DAT"}, journal=self.journal):
                pass
        self.assertEqual(len(json.loads(self.journal.get("hive_mounts"))), 1)
        # Simulate reopening the app: no in-memory mount identity survives.
        self.registry.mounts.clear()
        self.registry.native.unload.return_value = 0
        self.registry.release_mounts(self.journal, self.plan)
        self.assertEqual(json.loads(self.journal.get("hive_mounts")), [])

    def test_repeated_unload_failure_does_not_forget_the_mount(self):
        with self.assertRaises(RenProfileError):
            with self.registry.mounted(self.base, {"USER": "NTUSER.DAT"}, journal=self.journal):
                pass
        saved = self.journal.get("hive_mounts")
        with self.assertRaises(RenProfileError):
            self.registry.release_mounts(self.journal, self.plan)
        self.assertEqual(self.journal.get("hive_mounts"), saved)

    def test_reboot_or_crash_before_load_can_clear_an_already_absent_mount(self):
        saved = [{"root": "USER", "name": "RenProfile_" + "a" * 32 + "_USER",
                  "file": str(self.base / "NTUSER.DAT")}]
        self.journal.set("hive_mounts", json.dumps(saved))
        self.registry.native.unload.return_value = 2
        self.registry.release_mounts(self.journal, self.plan)
        self.assertEqual(self.journal.get("hive_mounts"), "[]")

    def test_recovery_never_unloads_an_actual_user_sid_or_another_file(self):
        for entry in (
                {"root": "USER", "name": "S-1-5-21-1-2-3-1001", "file": str(self.base / "NTUSER.DAT")},
                {"root": "USER", "name": "RenProfile_" + "a" * 32 + "_USER", "file": r"C:\Other\NTUSER.DAT"}):
            with self.subTest(entry=entry):
                self.journal.set("hive_mounts", json.dumps([entry]))
                with self.assertRaises(RenProfileError):
                    self.registry.release_mounts(self.journal, self.plan)
        self.registry.native.unload.assert_not_called()
