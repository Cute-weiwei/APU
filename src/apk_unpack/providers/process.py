from __future__ import annotations

import re
import posixpath
import shlex
import time
from typing import Any, Callable

from ..domain.errors import fail
from ..domain.models import MapRegion
from .adb import AdbProvider

MAP_RE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s*(.*)$"
)


class ProcessInspector:
    def __init__(self, adb: AdbProvider):
        self.adb = adb

    def find_pid_candidates(self, serial: str, package: str) -> dict[str, Any]:
        """Return the preferred main PID plus every related process for audit.

        A process belongs to the package only when its process name equals the
        package, its cmdline's first token equals the package (the Android main
        process), or either starts with ``package:`` (an Android subprocess).
        Bare substring matches such as ``com.example.other`` against
        ``com.example`` are rejected.  Main is preferred; remote/plugin
        subprocesses are reported but never silently selected as the target.
        """

        pids = self.adb.pidof(serial, package)
        rows = self._ps_rows(serial)
        candidates: list[dict[str, Any]] = []
        seen: set[int] = set()
        for row in rows:
            pid = int(row.get("pid") or 0)
            if not pid or pid in seen:
                continue
            name = str(row.get("name") or "")
            args = str(row.get("args") or "")
            matches, is_main = _match_process(name, args, package)
            if not matches:
                continue
            role, rank = ("main", 0) if is_main else ("subprocess", 2)
            seen.add(pid)
            candidates.append(
                {
                    "pid": pid,
                    "name": name,
                    "args": args,
                    "role": role,
                    "rank": rank,
                    "pidof": pid in pids,
                }
            )
        for pid in pids:
            if pid in seen:
                continue
            # ps may be restricted; validate pidof results through cmdline so a
            # multi-process package still resolves to its main process.  When
            # cmdline is unreadable, trust pidof's exact-name match.
            cmdline = self.cmdline(serial, int(pid))
            if cmdline.strip():
                matches, is_main = _match_process("", cmdline, package)
                if not matches:
                    continue
                role, rank = ("main", 0) if is_main else ("subprocess", 2)
            else:
                role, rank = "pidof", 3
            seen.add(pid)
            candidates.append(
                {
                    "pid": int(pid),
                    "name": None,
                    "args": cmdline,
                    "role": role,
                    "rank": rank,
                    "pidof": True,
                }
            )
        # QEMU user mode retains the host interpreter's argv in /proc/<pid>/
        # cmdline. Android's full process name is held by ActivityManager.
        # Use that name only for a corroborated QEMU process, never as a
        # substring exception to the native PID ownership rules.
        if not any(c["rank"] == 0 for c in candidates) and any(
            _qemu_cmdline(str(row.get("args") or "")) for row in rows
        ):
            by_pid = {int(row["pid"]): row for row in rows}
            for pid, name in self._framework_process_names(serial).items():
                matches, is_main = _match_process(name, "", package)
                if not matches or pid in seen or pid not in by_pid:
                    continue
                args = str(by_pid[pid].get("args") or "")
                if not _qemu_cmdline(args):
                    continue
                try:
                    status = self.status(serial, pid)
                    if not _guest_comm_matches(str(status.get("name") or ""), name):
                        continue
                    if not _qemu_cmdline(self.cmdline(serial, pid)):
                        continue
                except Exception:
                    continue
                seen.add(pid)
                candidates.append({"pid": pid, "name": name, "args": args,
                                   "role": "main" if is_main else "subprocess",
                                   "rank": 0 if is_main else 2, "pidof": pid in pids,
                                   "identity_source": "activity_manager_qemu"})
        candidates.sort(key=lambda item: (item["rank"], item["pid"]))
        main_pid = candidates[0]["pid"] if candidates else None
        return {
            "package": package,
            "main_pid": main_pid,
            "candidates": candidates,
            "pidof": pids,
            "ps_rows": len(rows),
        }

    def find_pid(self, serial: str, package: str) -> int:
        selection = self.find_pid_candidates(serial, package)
        if selection["main_pid"] is None:
            raise fail(
                "process_not_running",
                f"process not running: {package}",
                details={
                    "package": package,
                    "pidof": selection["pidof"],
                    "ps_rows": selection["ps_rows"],
                    "candidates": selection["candidates"],
                },
            )
        return int(selection["main_pid"])

    def validate_pid(self, serial: str, pid: int, package: str) -> dict[str, Any]:
        """Validate an explicitly supplied PID against the same exact rules.

        The cmdline first token must equal the package (main) or start with
        ``package:`` (subprocess); the package appearing anywhere else in the
        cmdline does not make the PID valid.  ``/proc/<pid>/cmdline`` is
        authoritative for native processes. For a QEMU wrapper, an exact
        ActivityManager name plus a matching kernel comm corroborates ownership.
        """

        cmdline = self.cmdline(serial, pid)
        status: dict[str, Any] = {}
        try:
            status = self.status(serial, pid)
        except Exception:
            status = {}
        valid, is_main = _match_process("", cmdline, package)
        identity_source = "cmdline"
        if not valid and status and _qemu_cmdline(cmdline):
            name = self._framework_process_names(serial).get(int(pid), "")
            matches, main = _match_process(name, "", package)
            if matches and _guest_comm_matches(str(status.get("name") or ""), name):
                valid, is_main = True, main
                identity_source = "activity_manager_qemu"
        return {
            "pid": int(pid),
            "package": package,
            "cmdline": cmdline,
            "valid": bool(valid),
            "is_main": bool(is_main),
            "alive": bool(status),
            "name": status.get("name"),
            "identity_source": identity_source,
        }

    def _framework_process_names(self, serial: str) -> dict[int, str]:
        result = self.adb.shell(serial, "dumpsys activity processes", timeout=15)
        if not result.ok:
            return {}
        return {int(pid): name for pid, name in re.findall(
            r"ProcessRecord\{[^{}\s]+\s+([1-9][0-9]*):([^/\s{}]+)/[^\s{}]+\}", result.stdout)}

    def _ps_rows(self, serial: str) -> list[dict[str, Any]]:
        for command in (
            "ps -A -o PID,PPID,NAME,ARGS 2>/dev/null",
            "ps -A 2>/dev/null",
        ):
            result = self.adb.shell(serial, command, timeout=20)
            if not result.ok or not result.stdout.strip():
                continue
            rows = self._parse_ps(result.stdout)
            if rows:
                return rows
        return []

    @staticmethod
    def _parse_ps(text: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 3 or not parts[0].isdigit():
                continue
            rows.append(
                {
                    "pid": int(parts[0]),
                    "ppid": parts[1],
                    "name": parts[2],
                    "args": parts[3] if len(parts) > 3 else "",
                }
            )
        if rows:
            return rows
        # Default `ps -A` format: USER PID PPID ... NAME
        for line in text.splitlines():
            parts = line.split()
            for token in parts:
                if token.isdigit():
                    rows.append(
                        {
                            "pid": int(token),
                            "ppid": "",
                            "name": parts[-1] if parts else "",
                            "args": line,
                        }
                    )
                    break
        return rows

    def status(self, serial: str, pid: int) -> dict[str, Any]:
        result = self.adb.shell(serial, f"cat /proc/{int(pid)}/status 2>/dev/null", timeout=20)
        if not result.ok or not result.stdout.strip():
            raise fail("process_not_running", f"cannot read /proc/{pid}/status")
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, _, value = line.partition(":")
            if key:
                values[key.strip()] = value.strip()
        tracer = 0
        try:
            tracer = int(values.get("TracerPid", "0"))
        except ValueError:
            tracer = 0
        return {
            "pid": int(pid),
            "name": values.get("Name"),
            "state": values.get("State"),
            "tracer_pid": tracer,
            "threads": _to_int(values.get("Threads")),
            "vm_rss_kb": _to_int(values.get("VmRSS")),
            "raw": values,
        }

    def maps(self, serial: str, pid: int) -> list[MapRegion]:
        result = self.adb.shell(serial, f"cat /proc/{int(pid)}/maps 2>/dev/null", timeout=30)
        if not result.ok:
            raise fail("process_not_running", f"cannot read /proc/{pid}/maps")
        regions: list[MapRegion] = []
        for line in result.stdout.splitlines():
            match = MAP_RE.match(line)
            if not match:
                continue
            regions.append(
                MapRegion(
                    start=int(match.group(1), 16),
                    end=int(match.group(2), 16),
                    perms=match.group(3),
                    offset=int(match.group(4), 16),
                    dev=match.group(5),
                    inode=int(match.group(6)),
                    path=(match.group(7) or "").strip(),
                )
            )
        return regions

    def cmdline(self, serial: str, pid: int) -> str:
        result = self.adb.shell(serial, f"cat /proc/{int(pid)}/cmdline 2>/dev/null | tr '\\0' ' '", timeout=15)
        return result.stdout.strip() if result.ok else ""

    def signal(self, serial: str, pid: int, sig: str) -> bool:
        result = self.adb.shell(serial, f"kill -{sig} {int(pid)} 2>/dev/null", timeout=15)
        return result.ok

    def is_alive(self, serial: str, pid: int) -> bool:
        result = self.adb.shell(serial, f"kill -0 {int(pid)} 2>/dev/null", timeout=10)
        return result.ok

    def wait_for_pid(
        self,
        serial: str,
        package: str,
        *,
        timeout_ms: int = 5000,
        interval_ms: int = 80,
    ) -> int:
        deadline = time.monotonic() + timeout_ms / 1000.0
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return self.find_pid(serial, package)
            except Exception as exc:
                last_error = exc
                time.sleep(interval_ms / 1000.0)
        raise fail(
            "process_not_running",
            f"process did not appear within {timeout_ms} ms: {package}",
            details={"package": package, "last_error": str(last_error) if last_error else None},
        )

    def wait_for_map(
        self,
        serial: str,
        pid: int,
        predicate: Callable[[MapRegion], bool],
        *,
        timeout_ms: int = 5000,
        interval_ms: int = 80,
    ) -> tuple[MapRegion | None, list[MapRegion]]:
        deadline = time.monotonic() + timeout_ms / 1000.0
        regions: list[MapRegion] = []
        while time.monotonic() < deadline:
            try:
                regions = self.maps(serial, pid)
            except Exception:
                regions = []
            for region in regions:
                if predicate(region):
                    return region, regions
            time.sleep(interval_ms / 1000.0)
        return None, regions


def _qemu_cmdline(cmdline: str) -> bool:
    tokens = cmdline.split()
    if not tokens:
        return False
    return posixpath.basename(tokens[0]) in {
        "aarch64-binfmt-P", "arm-binfmt-P", "qemu-aarch64",
        "qemu-aarch64-static", "qemu-arm", "qemu-arm-static",
    }


def _guest_comm_matches(comm: str, name: str) -> bool:
    return bool(name and comm and comm in {name, name[:15], name[-15:]})


def _match_process(name: str, cmdline: str, package: str) -> tuple[bool, bool]:
    """Return ``(matches, is_main)`` for an Android process identity.

    Only exact matches count: the process name or the cmdline's first token
    must equal the package (main process), or start with ``package:``
    (Android subprocess).  This deliberately rejects bare substrings so
    ``com.example.other`` is not treated as ``com.example``.
    """

    if not package:
        return False, False
    tokens = cmdline.split()
    first_token = tokens[0] if tokens else ""
    is_main = name == package or first_token == package
    is_subprocess = name.startswith(package + ":") or first_token.startswith(package + ":")
    return is_main or is_subprocess, is_main


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.match(r"\s*(\d+)", value)
    return int(match.group(1)) if match else None
