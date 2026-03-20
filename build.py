"""
build.py — builds jesus.exe using PyInstaller.

Usage:
    conda activate facefusion
    pip install pyinstaller
    python build.py

Output: dist/jesus.exe  (single file, no console window)
"""

import os
import subprocess
import sys
import urllib.request

GITHUB_REPO = "govindmelon/SQL-Jesus-Releases"
BRANCH = "main"


def get_latest_sha():
    url = f"https://api.github.com/repos/{GITHUB_REPO}/commits/{BRANCH}"
    req = urllib.request.Request(url, headers={"User-Agent": "sql-jesus-build"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            import json

            data = json.loads(r.read())
            return data["sha"]
    except Exception as e:
        print(f"Warning: could not fetch latest SHA: {e}")
        return "0000000000000000000000000000000000000000"


def main():
    print("Fetching current commit SHA from GitHub...")
    sha = get_latest_sha()
    print(f"  SHA: {sha}")

    # Write version.txt so it gets baked into the exe
    with open("version.txt", "w") as f:
        f.write(sha)
    print("  Written to version.txt")

    print("\nRunning PyInstaller...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconsole",
        "--name",
        "jesus",
        "--add-data",
        "version.txt;.",  # bundle version.txt
        "jesus.py",
    ]

    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("\nPyInstaller failed. Make sure it is installed:")
        print("  pip install pyinstaller")
        sys.exit(1)

    print("\nBuild complete: dist/jesus.exe")
    print("Upload dist/jesus.exe and jesus.py to your GitHub releases repo.")
    print("Also push version.txt with the current SHA so the updater can compare.")


if __name__ == "__main__":
    main()
