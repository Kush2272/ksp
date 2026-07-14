#!/usr/bin/env python3
"""Main launcher for ksp-cli Python package wrapper."""

import os
import sys
import shutil
import platform
import subprocess
import urllib.request
import tarfile
import tempfile
from pathlib import Path

VERSION = "0.1.0"
REPO = "kush-secure-protocol/ksp"

def get_install_dir() -> Path:
    home = Path.home()
    ksp_dir = home / ".ksp" / "bin"
    ksp_dir.mkdir(parents=True, exist_ok=True)
    return ksp_dir

def find_binary() -> Path:
    # 1. Check if ksp is already inside our local install dir (~/.ksp/bin/ksp)
    ext = ".exe" if platform.system() == "Windows" else ""
    ksp_bin = get_install_dir() / f"ksp{ext}"
    if ksp_bin.exists():
        return ksp_bin

    # 2. Check system PATH
    system_bin = shutil.which(f"ksp{ext}")
    if system_bin:
        return Path(system_bin)

    return ksp_bin

def download_and_install_binary(dest: Path):
    sys.stdout.write(f"  [+] KSP CLI binary not found on local machine.\n")
    sys.stdout.write(f"  [+] Checking for local Cargo toolchain or downloading pre-built release...\n")
    sys.stdout.flush()

    # If cargo is installed, try cargo install first
    if shutil.which("cargo"):
        sys.stdout.write(f"  [+] Cargo detected. Compiling and installing KSP native binary...\n")
        sys.stdout.flush()
        try:
            cmd = ["cargo", "install", "--git", f"https://github.com/{REPO}.git", "ksp-cli", "--force", "--locked"]
            subprocess.run(cmd, check=True)
            if dest.exists():
                return
            system_bin = shutil.which("ksp.exe" if platform.system() == "Windows" else "ksp")
            if system_bin:
                shutil.copy(system_bin, dest)
                return
        except Exception as e:
            sys.stdout.write(f"  [!] Cargo compile fallback triggered: {e}\n")

    # Otherwise download from GitHub release
    system = platform.system()
    machine = platform.machine()
    
    if system == "Windows":
        url = f"https://github.com/{REPO}/releases/latest/download/ksp.exe"
    elif system == "Darwin":
        url = f"https://github.com/{REPO}/releases/latest/download/ksp-darwin-{machine}.tar.gz"
    else:
        url = f"https://github.com/{REPO}/releases/latest/download/ksp-linux-{machine}.tar.gz"

    try:
        sys.stdout.write(f"  [+] Downloading release binary from {url}...\n")
        sys.stdout.flush()
        if system == "Windows":
            urllib.request.urlretrieve(url, dest)
        else:
            with tempfile.TemporaryDirectory() as tmp:
                archive_path = Path(tmp) / "ksp.tar.gz"
                urllib.request.urlretrieve(url, archive_path)
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=tmp)
                extracted_bin = Path(tmp) / "ksp"
                if extracted_bin.exists():
                    shutil.move(extracted_bin, dest)
                    os.chmod(dest, 0o755)
                else:
                    raise FileNotFoundError("Binary not found inside release archive.")
        sys.stdout.write(f"  ✔ Installed KSP native binary to {dest}\n\n")
    except Exception as e:
        sys.stderr.write(f"\n  ✘ Error installing KSP binary: {e}\n")
        sys.stderr.write(f"  💡 Tip: Ensure Rust is installed (https://rustup.rs) and run:\n")
        sys.stderr.write(f"       cargo install --git https://github.com/{REPO}.git ksp-cli\n\n")
        sys.exit(1)

def main():
    binary_path = find_binary()
    if not binary_path.exists():
        download_and_install_binary(binary_path)

    # Launch the native KSP binary passing all arguments
    try:
        proc = subprocess.run([str(binary_path)] + sys.argv[1:])
        sys.exit(proc.returncode)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        sys.stderr.write(f"Error launching KSP binary ({binary_path}): {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
