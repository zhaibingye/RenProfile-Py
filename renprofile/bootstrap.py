"""Run the portable EXE outside profile folders and release its original image."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from .errors import RenProfileError
from . import EXECUTABLE_NAME
from .host import Host, plain_path


# Arguments are passed as separate process arguments, never inserted into code.
# This controller outlives both onefile processes, then removes its own runtime.
CONTROLLER = r'''
param([string]$Runtime, [string]$Root, [int]$OriginPid, [int]$BootPid, [string]$ImageName = 'RenProfile.exe', [switch]$Smoke)
$ErrorActionPreference = 'Stop'
$runtimePath = [IO.Path]::GetFullPath($Runtime)
$runtimeItem = Get-Item -LiteralPath $runtimePath -Force
$runtimeRoot = $runtimeItem.Parent.FullName
if (-not [string]::Equals($runtimeRoot, [IO.Path]::GetFullPath($Root).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'Runtime outside requested root' }
if ($runtimeItem.Name -notmatch '^runtime-[a-f0-9]{32}$') { throw 'Invalid runtime' }
if (($runtimeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Runtime is a link' }
if ((Get-Content -LiteralPath (Join-Path $runtimePath '.runtime') -Raw) -ne $runtimeItem.Name) { throw 'Wrong marker' }
if ($ImageName -notmatch '^RenProfile(?:-\d+\.\d+\.\d+)?\.exe$') { throw 'Invalid image name' }
Set-Location -LiteralPath $env:SystemRoot
$workerFinished = $false
try {
    foreach ($origin in @($OriginPid, $BootPid)) {
        if ($origin -gt 0) {
            $process = Get-Process -Id $origin -ErrorAction SilentlyContinue
            if ($process -and -not $process.WaitForExit(30000)) { throw 'Original launcher did not exit' }
        }
    }
    $env:TEMP = Join-Path $runtimePath 'temp'
    $env:TMP = $env:TEMP
    $env:PYINSTALLER_RESET_ENVIRONMENT = '1'
    $arguments = if ($Smoke) { '--portable-check' } else { '--portable' }
    $windowStyle = if ($Smoke) { 'Hidden' } else { 'Normal' }
    $worker = Start-Process -FilePath (Join-Path $runtimePath $ImageName) -ArgumentList $arguments -WorkingDirectory $env:SystemRoot -WindowStyle $windowStyle -PassThru
    $worker.WaitForExit()
    $workerFinished = $true
    if ($worker.ExitCode -ne 0) { throw "Worker exit: $($worker.ExitCode)" }
} catch {
    [IO.File]::WriteAllText((Join-Path $runtimePath 'startup-error.txt'), $_.Exception.ToString())
    if (-not $Smoke) {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show("RenProfile 启动或退出时出错。记录位置：`n$runtimePath", 'RenProfile') | Out-Null
    }
    exit 1
}
if ($workerFinished) {
    # Check every directory without following links before recursive deletion.
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($runtimePath)
    while ($pending.Count -gt 0) {
        foreach ($entry in (Get-ChildItem -LiteralPath ($pending.Dequeue()) -Force)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected runtime link' }
            if ($entry.PSIsContainer) { $pending.Enqueue($entry.FullName) }
        }
    }
    # The exact resolved target above is our new runtime, never a user folder.
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        try { Remove-Item -LiteralPath $runtimePath -Recurse -Force; break }
        catch { if ($attempt -eq 3) { throw }; Start-Sleep -Milliseconds 300 }
    }
    try { [IO.Directory]::Delete($runtimeRoot, $false) } catch { }
}
'''


def runtime_root():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RenProfile-Py"


def validate_runtime(native, executable=None):
    path = Path(executable or sys.executable).resolve()
    root = runtime_root().absolute()
    if path.parent.parent != root or not re.fullmatch(r"runtime-[a-f0-9]{32}", path.parent.name):
        raise RenProfileError(f"临时运行位置不正确，请直接双击 {EXECUTABLE_NAME}。")
    plain_path(path)
    Host(native, None).check_job(root)
    Host(native, None).check_job(path.parent)
    if (path.parent / ".runtime").read_text(encoding="utf-8") != path.parent.name:
        raise RenProfileError("临时程序标记无效，请重新打开原 EXE。")
    return path.parent


def launch_external(native, *, smoke=False, root=None, origin_pids=None):
    """Return immediately so the original EXE AND onefile parent can exit."""
    root = (Path(root) if root else runtime_root()).absolute()
    Host(native, None).prepare_storage(root)
    runtime = root / ("runtime-" + uuid.uuid4().hex)
    native.secure_directory(runtime)
    (runtime / ".runtime").write_text(runtime.name, encoding="utf-8")
    (runtime / "temp").mkdir()
    shutil.copyfile(sys.executable, runtime / EXECUTABLE_NAME)
    (runtime / "launch.ps1").write_text(CONTROLLER, encoding="utf-8-sig")
    origin, boot = origin_pids if origin_pids is not None else (os.getpid(), os.getppid())
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    arguments = [str(powershell), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                 "-ExecutionPolicy", "Bypass", "-File", str(runtime / "launch.ps1"),
                 "-Runtime", str(runtime), "-Root", str(root), "-OriginPid", str(origin), "-BootPid", str(boot),
                 "-ImageName", EXECUTABLE_NAME]
    if smoke:
        arguments.append("-Smoke")
    process = subprocess.Popen(arguments, cwd=os.environ["SystemRoot"], close_fds=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    return process, runtime
