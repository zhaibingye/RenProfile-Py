"""Launcher tests only use temporary folders and a tiny test executable."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from renprofile.bootstrap import CONTROLLER, launch_external, validate_runtime
from renprofile import EXECUTABLE_NAME
from renprofile.errors import RenProfileError

POWERSHELL = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")


class BootstrapTests(unittest.TestCase):
    def test_launcher_copies_image_and_waits_for_both_original_processes(self):
        with tempfile.TemporaryDirectory(prefix="renprofile-bootstrap-test-") as temp:
            root = Path(temp) / "runtime-root"
            native = Mock()
            native.secure_directory.side_effect = lambda path: Path(path).mkdir()
            with patch("renprofile.bootstrap.Host") as host, patch("renprofile.bootstrap.subprocess.Popen") as popen:
                host.return_value.prepare_storage.side_effect = lambda path: Path(path).mkdir()
                process, runtime = launch_external(native, root=root, origin_pids=(123, 456))
            self.assertEqual((runtime / EXECUTABLE_NAME).read_bytes(), Path(sys.executable).read_bytes())
            self.assertEqual((runtime / ".runtime").read_text(), runtime.name)
            args, options = popen.call_args.args[0], popen.call_args.kwargs
            self.assertEqual(args[args.index("-OriginPid") + 1], "123")
            self.assertEqual(args[args.index("-BootPid") + 1], "456")
            self.assertEqual(args[args.index("-ImageName") + 1], EXECUTABLE_NAME)
            self.assertEqual(options["cwd"], os.environ["SystemRoot"])
            self.assertEqual(options["creationflags"], subprocess.CREATE_NO_WINDOW)
            host.return_value.prepare_storage.assert_called_once_with(root)

    def test_portable_flag_cannot_skip_staging_from_an_unrelated_executable(self):
        with self.assertRaises(RenProfileError):
            validate_runtime(Mock(), sys.executable)

    def test_real_controller_waits_moves_runtime_temp_and_cleans_only_its_runtime(self):
        with tempfile.TemporaryDirectory(prefix="renprofile-controller-test-") as temp:
            root = Path(temp)
            runtime = root / ("runtime-" + uuid.uuid4().hex)
            runtime.mkdir()
            (runtime / "temp").mkdir()
            (runtime / ".runtime").write_text(runtime.name)
            (root / "keep.txt").write_text("unrelated data")
            script = runtime / "launch.ps1"
            script.write_text(CONTROLLER, encoding="utf-8-sig")
            # A harmless .NET fixture writes its TEMP/cwd and exits. It is not
            # a profile worker and performs no registry or account operations.
            compiler = root / "compile.ps1"
            compiler.write_text('''param([string]$Output)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
public class Fixture {
    public static int Main(string[] args) {
        string runtime = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        string root = Path.GetDirectoryName(runtime);
        File.WriteAllText(Path.Combine(root, "observed.txt"), Environment.GetEnvironmentVariable("TEMP") + "\\n" + Environment.CurrentDirectory);
        return 0;
    }
}
'@ -OutputAssembly $Output -OutputType ConsoleApplication
''', encoding="utf-8-sig")
            result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                     "-File", str(compiler), "-Output", str(runtime / "RenProfile.exe")],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            origin = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(1)"],
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            controller = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                         "-File", str(script), "-Runtime", str(runtime), "-Root", str(root),
                                         "-OriginPid", str(origin.pid), "-BootPid", "0", "-Smoke"],
                                        capture_output=True, timeout=35, creationflags=subprocess.CREATE_NO_WINDOW)
            origin.wait(timeout=5)
            self.assertEqual(controller.returncode, 0, controller.stderr.decode(errors="replace"))
            self.assertFalse(runtime.exists(), "runtime must be removed after its worker exits")
            self.assertEqual((root / "keep.txt").read_text(), "unrelated data")
            observed = (root / "observed.txt").read_text().splitlines()
            self.assertEqual(observed, [str(runtime / "temp"), os.environ["SystemRoot"]])

    def test_packaged_exe_can_unpack_in_external_runtime_and_controller_cleans_it(self):
        executable = Path(__file__).resolve().parents[1] / EXECUTABLE_NAME
        if not executable.exists():
            self.skipTest("Build the release EXE first")
        with tempfile.TemporaryDirectory(prefix="renprofile-package-test-") as temp:
            root = Path(temp) / "test-root"
            root.mkdir()
            runtime = root / ("runtime-" + uuid.uuid4().hex)
            runtime.mkdir()
            (runtime / "temp").mkdir()
            (runtime / ".runtime").write_text(runtime.name)
            shutil.copyfile(executable, runtime / "RenProfile.exe")
            # The fixture root is not ProgramData and deliberately has ordinary
            # permissions. Run the read-only packaging check, not production
            # elevation/runtime validation or any real migration.
            script = runtime / "launch.ps1"
            script.write_text(CONTROLLER.replace("--portable-check", "--self-check"), encoding="utf-8-sig")
            result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                     "-File", str(script), "-Runtime", str(runtime), "-Root", str(root),
                                     "-OriginPid", "0", "-BootPid", "0", "-Smoke"],
                                    capture_output=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertFalse(runtime.exists())
