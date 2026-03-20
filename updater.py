"""
updater.py — helper script that replaces jesus.exe with a new download.

This runs as a separate process AFTER jesus.exe exits, because a running
exe cannot replace itself on Windows.

Called automatically by the auto-updater inside jesus.exe. Do not run manually.

Usage (internal):
    python updater.py <new_exe_path> <current_exe_path>
"""

import os
import shutil
import subprocess
import sys
import time


def main():
    if len(sys.argv) < 3:
        print("Usage: updater.py <new_exe> <target_exe>")
        sys.exit(1)

    new_exe = sys.argv[1]
    target_exe = sys.argv[2]

    # Wait for the original process to exit
    print(f"Waiting for {target_exe} to close...")
    for _ in range(30):
        try:
            os.rename(target_exe, target_exe + ".bak")
            os.rename(target_exe + ".bak", target_exe)
            break
        except PermissionError:
            time.sleep(1)
    else:
        print("Timed out waiting for process to exit.")
        sys.exit(1)

    # Replace
    print(f"Installing update: {new_exe} -> {target_exe}")
    try:
        shutil.copy2(new_exe, target_exe)
        os.remove(new_exe)
        print("Update installed. Restarting...")
        subprocess.Popen([target_exe])
    except Exception as e:
        print(f"Update failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
