#!/usr/bin/env python3
"""Experimental redroid/Ijiami self-destruct shield.

This builds ``src/apk_unpack/scripts/apu_shield.c`` and applies it through
Android's ``wrap.<package>`` LD_PRELOAD mechanism.  The shield forks an
unfiltered supervisor, installs a seccomp user-notification filter, hides
emulator/ABI indicators and blocks self-directed SIGKILL/exit_group.

It is intentionally a standalone tool:

    python backend/tools/redroid_shield.py --package com.example.app --apply
    python backend/tools/redroid_shield.py --package com.example.app --clear

The shield is useful for research and for shells that only use a late
SIGKILL/exit_group self-destruct.  ``--skip-traps`` additionally steps over a
deliberate ``ud2``; some Ijiami VM variants survive longer but still abort
before the DEX window on libndk.  On those targets use a compatible Houdini
translation, an ARM64 host/device, or a different device profile.
Only use it on APKs you are authorized to analyze.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "apk_unpack" / "scripts" / "apu_shield.c"
DEVICE_SO = "/data/local/tmp/libapu_shield.so"
DEVICE_LOG = "/data/local/tmp/apu_shield.log"
DEVICE_MODE = "/data/local/tmp/apu_shield_mode"


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=check)


def adb(serial: str | None, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    argv = ["adb"]
    if serial:
        argv += ["-s", serial]
    argv += list(args)
    return run(argv, check=check)


def build() -> Path:
    if not SOURCE.is_file():
        raise SystemExit(f"shield source not found: {SOURCE}")
    compiler = shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        raise SystemExit("gcc/cc is required to build the shield")
    out = Path(tempfile.mkstemp(prefix="apu-shield-", suffix=".so")[1])
    result = subprocess.run(
        [compiler, "-shared", "-fPIC", "-nostdlib", "-O2", "-fno-builtin", "-o", str(out), str(SOURCE)],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        out.unlink(missing_ok=True)
        raise SystemExit(result.stderr or result.stdout)
    return out


def apply(serial: str | None, package: str, *, skip_traps: bool = False) -> None:
    binary = build()
    try:
        adb(serial, "push", str(binary), DEVICE_SO)
        adb(serial, "shell", f"chmod 644 {DEVICE_SO}")
        adb(serial, "shell", f"rm -f {DEVICE_LOG}; touch {DEVICE_LOG}; chmod 666 {DEVICE_LOG}")
        if skip_traps:
            adb(serial, "shell", f"printf 'skip\\n' > {DEVICE_MODE}; chmod 644 {DEVICE_MODE}")
        else:
            adb(serial, "shell", f"rm -f {DEVICE_MODE}")
        adb(serial, "shell", f"setprop wrap.{package} LD_PRELOAD={DEVICE_SO}")
        adb(serial, "shell", f"am force-stop {package}")
        print(f"shield applied for {package}" + (" (experimental trap skipping)" if skip_traps else ""))
        print(f"launch the app, then inspect: adb shell cat {DEVICE_LOG}")
        print("clear with: python backend/tools/redroid_shield.py --package <pkg> --clear")
    finally:
        binary.unlink(missing_ok=True)


def clear(serial: str | None, package: str) -> None:
    adb(serial, "shell", f"setprop wrap.{package} \"\"", check=False)
    adb(serial, "shell", f"rm -f {DEVICE_SO} {DEVICE_LOG} {DEVICE_MODE}", check=False)
    adb(serial, "shell", f"am force-stop {package}", check=False)
    print(f"shield cleared for {package}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="target application package")
    parser.add_argument("--serial", default=None, help="adb serial (default: adb chooses)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true", help="build and apply the shield (default)")
    group.add_argument("--clear", action="store_true", help="remove the wrap property and shield files")
    parser.add_argument(
        "--skip-traps",
        action="store_true",
        help="experimental: step over SIGILL/SIGSEGV instead of hanging the thread",
    )
    args = parser.parse_args(argv)
    if args.clear:
        clear(args.serial, args.package)
    else:
        apply(args.serial, args.package, skip_traps=args.skip_traps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
