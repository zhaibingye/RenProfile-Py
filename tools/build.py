"""Build the portable Windows tool; keep intermediate files outside the repo."""

import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


def main():
    if os.name != "nt":
        raise SystemExit("请在 Windows 上打包。")
    root = Path(__file__).resolve().parent.parent
    metadata = runpy.run_path(str(root / "renprofile" / "__init__.py"))
    version, filename = metadata["__version__"], metadata["EXECUTABLE_NAME"]
    numbers = tuple(int(part) for part in version.split(".")) + (0,)
    with tempfile.TemporaryDirectory(prefix="renprofile-build-") as build_dir:
        version_file = Path(build_dir) / "version.txt"
        version_file.write_text(
            f"VSVersionInfo(ffi=FixedFileInfo(filevers={numbers!r}, prodvers={numbers!r}, "
            "mask=0x3f, flags=0, OS=0x40004, fileType=1, subtype=0, date=(0,0)), "
            "kids=[StringFileInfo([StringTable('040904B0', ["
            f"StringStruct('FileDescription', 'RenProfile {version}'), "
            f"StringStruct('FileVersion', '{version}'), "
            f"StringStruct('ProductVersion', '{version}'), "
            f"StringStruct('OriginalFilename', '{filename}'), "
            "StringStruct('ProductName', 'RenProfile')])]), "
            "VarFileInfo([VarStruct('Translation', [1033,1200])])])", encoding="utf-8")
        result = subprocess.run([
            sys.executable, "-B", "-m", "PyInstaller", "--onefile", "--windowed", "--noupx",
            "--noconfirm", "--name", Path(filename).stem, "--icon", "NONE", "--optimize", "1",
            "--version-file", str(version_file),
            "--distpath", str(root), "--workpath", str(Path(build_dir) / "work"),
            "--specpath", build_dir, "--paths", str(root), str(root / "run_renprofile.py"),
        ], cwd=root, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
        if result.returncode:
            return result.returncode
    print("已生成：" + str(root / filename))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
