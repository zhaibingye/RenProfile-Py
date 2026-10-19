"""Real reader checks use temporary files; termination targets only our fixtures."""

from contextlib import nullcontext
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from renprofile import EXECUTABLE_NAME
from renprofile.errors import RenProfileError
from renprofile.occupancy import in_tree, scan_tree, terminate_users


class PathMatchingTests(unittest.TestCase):
    def test_entire_tree_and_root_match_but_sibling_names_do_not(self):
        root = r"C:\Users\Old"
        for path in (root, r"c:\USERS\OLD\deep\data.bin", r"\\?\C:\Users\Old\folder", root + ":stream"):
            self.assertTrue(in_tree(path, root), path)
        for path in (r"C:\Users\Old2\file", r"C:\Users\Old.bak", r"C:\Other\Old\file", r"D:\Users\Old\file"):
            self.assertFalse(in_tree(path, root), path)


class TerminationTests(unittest.TestCase):
    def setUp(self):
        self.entry = {"pid": 456, "created": 12345, "name": "example.exe", "path": r"C:\Users\Old\file"}
        self.api = Mock()
        self.api.native.privileges.side_effect = lambda *a, **k: nullcontext()
        self.api.native.check.side_effect = lambda ok: None if ok else (_ for _ in ()).throw(OSError("denied"))
        self.api.excluded.return_value = {0, 4, 111}
        self.api.open.return_value = 999
        self.api.metadata.return_value = {**self.entry, "critical": False}
        self.api.wait.side_effect = [258, 0]
        self.api.terminate.return_value = True

    def test_force_ends_a_matched_process_and_waits_for_exit(self):
        result = terminate_users([self.entry], api=self.api)
        self.assertEqual(result["terminated"], [self.entry])
        self.api.terminate.assert_called_once_with(999, 1)
        self.api.native.close.assert_called_once_with(999)

    def test_pid_reuse_never_terminates_the_replacement(self):
        self.api.metadata.return_value["created"] = 98765
        self.assertEqual(terminate_users([self.entry], api=self.api)["terminated"], [])
        self.api.terminate.assert_not_called()

    def test_actual_critical_flag_and_shared_service_host_are_excluded(self):
        for name, critical in (("unknown.exe", True), ("Svchost.EXE", False), ("lsass.exe", False)):
            with self.subTest(name=name):
                self.api.metadata.return_value.update(name=name, critical=critical)
                result = terminate_users([self.entry], api=self.api)
                self.assertEqual(len(result["remaining"]), 1)
                self.api.terminate.assert_not_called()

    def test_tool_and_launcher_processes_are_never_opened_for_termination(self):
        self.api.excluded.return_value.add(456)
        self.assertEqual(len(terminate_users([self.entry], api=self.api)["remaining"]), 1)
        self.api.open.assert_not_called()

    def test_unknown_critical_state_is_not_treated_as_an_ordinary_process(self):
        self.api.metadata.side_effect = PermissionError("cannot query")
        self.assertEqual(len(terminate_users([self.entry], api=self.api)["remaining"]), 1)
        self.api.terminate.assert_not_called()

    def test_failed_wait_does_not_claim_the_lock_has_been_released(self):
        self.api.wait.side_effect = [258, 258]
        result = terminate_users([self.entry], api=self.api)
        self.assertEqual(result["terminated"], [])
        self.assertEqual(len(result["remaining"]), 1)


FIXTURE = r'''
import ctypes, sys, time
from renprofile.native import Native
native = Native()
if sys.argv[2] == 'module':
    library = ctypes.WinDLL(sys.argv[1])
else:
    flags = 0x02000000 if sys.argv[2] == 'directory' else 0
    handle = native.create_file(sys.argv[1], 0x80000000, 3, None, 3, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
print('ready', flush=True)
while True:
    time.sleep(1)
'''


@unittest.skipUnless(os.name == "nt", "Windows handle table")
class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="renprofile-occupancy-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.workspace = self.base / "profile", self.base / "records"
        self.root.mkdir()
        self.workspace.mkdir()
        self.deep = self.root / "deep" / "nested"
        self.deep.mkdir(parents=True)
        self.file = self.deep / "ordinary-data.bin"
        self.file.write_bytes(b"disposable lock fixture")

    def fixture(self, path, kind="file"):
        process = subprocess.Popen([sys.executable, "-B", "-c", FIXTURE, str(path), kind],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   creationflags=subprocess.CREATE_NO_WINDOW)

        def cleanup():
            if process.poll() is None:
                process.kill()  # Exactly this disposable process, never discovered PIDs.
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()

        self.addCleanup(cleanup)
        self.assertEqual(process.stdout.readline().strip(), "ready")
        return process

    def find(self, pid, report):
        self.assertFalse(report["incomplete"], report)
        entries = [entry for entry in report["processes"] if entry["pid"] == pid]
        self.assertEqual(len(entries), 1, report)
        return entries[0]

    def test_nested_non_hive_file_is_detected_and_only_fixture_is_force_ended(self):
        process = self.fixture(self.file)
        with self.assertRaises(OSError):
            self.root.rename(self.base / "renamed")
        entry = self.find(process.pid, scan_tree(self.root, self.workspace))
        self.assertTrue(in_tree(entry["path"], self.deep.resolve()))
        result = terminate_users([entry])  # No other discovered process is passed to termination.
        self.assertEqual(len(result["terminated"]), 1, result)
        process.wait(timeout=5)
        self.root.rename(self.base / "renamed")

    def test_open_directory_handles_are_detected(self):
        process = self.fixture(self.deep, "directory")
        self.find(process.pid, scan_tree(self.root, self.workspace))

    def test_loaded_dll_is_detected_even_without_an_application_file_handle(self):
        library = self.deep / "winmm.dll"
        shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "winmm.dll", library)
        process = self.fixture(library, "module")
        entry = self.find(process.pid, scan_tree(self.root, self.workspace))
        self.assertTrue(entry["path"].lower().endswith("winmm.dll"))

    def test_unrelated_sibling_folder_is_not_a_match(self):
        sibling = self.base / "profile-other"
        sibling.mkdir()
        file = sibling / "keep.bin"
        file.write_bytes(b"keep")
        process = self.fixture(file)
        report = scan_tree(self.root, self.workspace)
        self.assertNotIn(process.pid, [entry["pid"] for entry in report["processes"]])
        self.assertIsNone(process.poll())

    def test_loaded_dll_alias_is_resolved_to_its_actual_profile_location(self):
        from renprofile.native import Native
        library = self.deep / "winmm.dll"
        shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "winmm.dll", library)
        alias = self.base / "outside-alias"
        Native().junction(alias, self.deep)
        self.addCleanup(os.rmdir, alias)
        process = self.fixture(alias / "winmm.dll", "module")
        self.find(process.pid, scan_tree(self.root, self.workspace))

    def test_profile_junction_to_an_outside_file_does_not_nominate_its_reader(self):
        from renprofile.native import Native
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.bin").write_bytes(b"unrelated data")
        alias = self.root / "external-link"
        Native().junction(alias, outside)
        self.addCleanup(os.rmdir, alias)
        process = self.fixture(alias / "keep.bin")
        report = scan_tree(self.root, self.workspace)
        self.assertNotIn(process.pid, [entry["pid"] for entry in report["processes"]])
        self.assertIsNone(process.poll())

    def test_timeout_retains_complete_findings_and_discards_only_a_partial_last_line(self):
        fake = Mock(returncode=-9)
        fake.wait.side_effect = [subprocess.TimeoutExpired("fixture", 1), 0]

        def start(arguments, **options):
            root, output = arguments[-2:]
            records = [{"kind": "root", "path": root},
                       {"kind": "process", "pid": 456, "created": 12345, "path": str(self.file.resolve()),
                        "name": "fixture.exe", "image": r"C:\fixture.exe"}]
            Path(output).write_text("\n".join(json.dumps(r) for r in records) + '\n{"kind":', encoding="utf-8")
            return fake

        with patch("renprofile.occupancy.subprocess.Popen", side_effect=start):
            report = scan_tree(self.root, self.workspace, timeout=1)
        self.assertTrue(report["incomplete"])
        self.assertEqual(report["processes"][0]["pid"], 456)
        fake.kill.assert_called_once()
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_reader_results_cannot_nominate_a_process_using_an_outside_path(self):
        def start(arguments, **options):
            root, output = arguments[-2:]
            records = [{"kind": "root", "path": root},
                       {"kind": "process", "pid": 456, "created": 12345,
                        "path": str(self.base / "elsewhere.bin"), "name": "fixture.exe", "image": r"C:\fixture.exe"}]
            Path(output).write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
            return Mock(returncode=0)

        with patch("renprofile.occupancy.subprocess.Popen", side_effect=start):
            with self.assertRaisesRegex(RenProfileError, "进程记录无效"):
                scan_tree(self.root, self.workspace)
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_packaged_hidden_reader_finds_locks_without_starting_gui_or_elevation(self):
        exe = Path(__file__).resolve().parents[1] / EXECUTABLE_NAME
        if not exe.exists():
            self.skipTest("Build the current release EXE first")
        process = self.fixture(self.file)
        with patch("renprofile.occupancy.sys.executable", str(exe)), \
                patch("renprofile.occupancy.sys.frozen", True, create=True):
            self.find(process.pid, scan_tree(self.root, self.workspace))
