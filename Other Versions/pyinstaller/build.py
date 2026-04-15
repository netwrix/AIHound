#!/usr/bin/env python3
"""
Build helper for AIHound PyInstaller packaging.

Resolves paths relative to this script's location, then invokes
PyInstaller with the spec file.  Run from anywhere:

    python pyinstaller/build.py
"""

import os
import subprocess
import sys


def main() -> int:
    # Directories relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    spec_file = os.path.join(script_dir, "aihound.spec")
    dist_path = os.path.join(script_dir, "dist")
    work_path = os.path.join(script_dir, "build")

    if not os.path.isfile(spec_file):
        print(f"ERROR: spec file not found: {spec_file}", file=sys.stderr)
        return 1

    cmd = [
        sys.executable, "-m", "PyInstaller",
        spec_file,
        "--distpath", dist_path,
        "--workpath", work_path,
        "--noconfirm",
    ]

    print(f"Building AIHound executable...")
    print(f"  spec file : {spec_file}")
    print(f"  dist path : {dist_path}")
    print(f"  work path : {work_path}")
    print(f"  cwd       : {project_root}")
    print()

    result = subprocess.run(cmd, cwd=project_root)

    if result.returncode == 0:
        # Determine expected output name
        exe_name = "aihound.exe" if sys.platform == "win32" else "aihound"
        output = os.path.join(dist_path, exe_name)
        print()
        print(f"SUCCESS: Built executable -> {output}")
        return 0
    else:
        print()
        print("FAILED: PyInstaller exited with errors.", file=sys.stderr)
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
