from __future__ import annotations

import posixpath
import re
import shlex
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..config import Config
from ..domain.errors import fail
from .host import CommandResult, HostRunner, read_elf_arch


@dataclass
class AdbDevice:
    serial: str
    state: str
    attrs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"serial": self.serial, "state": self.state, "attrs": self.attrs}


class AdbProvider:
    def __init__(self, host: HostRunner, config: Config):
        self.host = host
        self.config = config

    # ------------------------------------------------------------------ command plumbing
    def _base(self, serial: str | None = None) -> list[str]:
        command = list(self.config.adb)
        if serial:
            command.extend(["-s", serial])
        return command

    def run(
        self,
        args: list[str],
        *,
        serial: str | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        return self.host.run(
            self._base(serial) + args,
            timeout=timeout or self.config.command_timeout_s,
        )

    def devices(self) -> list[AdbDevice]:
        result = self.run(["devices", "-l"], timeout=20)
        if result.missing:
            raise fail("tool_missing", "adb is not installed or not on PATH", details={"adb": self.config.adb})
        if not result.ok:
            raise fail("device_unavailable", "adb devices failed", captured_output=result.stderr or result.stdout)
        devices: list[AdbDevice] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            attrs: dict[str, str] = {}
            for token in parts[2:]:
                if ":" in token:
                    key, value = token.split(":", 1)
                    attrs[key] = value
            devices.append(AdbDevice(serial=serial, state=state, attrs=attrs))
        return devices

    def resolve_serial(self, serial: str | None = None) -> str:
        serial = serial or self.config.default_serial
        devices = self.devices()
        online = [item for item in devices if item.state == "device"]
        if serial:
            matching = [item for item in devices if item.serial == serial]
            if not matching:
                raise fail(
                    "device_unavailable",
                    f"adb device not found: {serial}",
                    details={"serial": serial, "devices": [item.to_dict() for item in devices]},
                )
            if matching[0].state != "device":
                raise fail(
                    "device_unavailable",
                    f"adb device {serial} is {matching[0].state}, not device",
                    details={"serial": serial, "state": matching[0].state},
                )
            return serial
        if not online:
            raise fail(
                "device_unavailable",
                "no online adb device",
                details={"devices": [item.to_dict() for item in devices]},
            )
        if len(online) > 1:
            raise fail(
                "invalid_input",
                "multiple online adb devices; pass serial explicitly",
                details={"serials": [item.serial for item in online]},
            )
        return online[0].serial

    # ------------------------------------------------------------------ shell / files
    def shell(self, serial: str, command: str, *, timeout: float | None = None) -> CommandResult:
        return self.host.run(
            self._base(serial) + ["shell", command],
            timeout=timeout or self.config.command_timeout_s,
        )

    def shell_text(self, serial: str, command: str, *, timeout: float | None = None) -> str:
        result = self.shell(serial, command, timeout=timeout)
        if not result.ok:
            raise fail(
                "execution_failure",
                f"adb shell failed: {command}",
                captured_output=result.stderr or result.stdout,
                details={"command": command},
            )
        return result.stdout

    def exec_out(self, serial: str, command: str, out_path: str | Path, *, timeout: float | None = None) -> CommandResult:
        return self.host.run_to_file(
            self._base(serial) + ["exec-out", command],
            out_path,
            timeout=timeout or self.config.command_timeout_s,
        )

    def pull(self, serial: str, remote: str, local: str | Path) -> CommandResult:
        return self.run(["pull", remote, str(local)], serial=serial, timeout=180)

    def push(self, serial: str, local: str | Path, remote: str) -> CommandResult:
        return self.run(["push", str(local), remote], serial=serial, timeout=180)

    def forward(self, serial: str, local_port: int, remote_port: int) -> CommandResult:
        return self.run(["forward", f"tcp:{local_port}", f"tcp:{remote_port}"], serial=serial, timeout=30)

    def remove_forward(self, serial: str, local_port: int) -> CommandResult:
        result = self.run(["forward", "--remove", f"tcp:{local_port}"], serial=serial, timeout=30)
        # A device/container restart may already have removed this listener.
        # Confirm absence rather than leaving an unrecoverable mutation behind.
        if not result.ok and "not found" in (result.stderr + result.stdout).lower():
            listing = self.forward_list()
            if listing.ok and not any(
                row["local_port"] == local_port for row in self.parse_forward_list(listing.stdout)
            ):
                return replace(result, returncode=0)
        return result

    def forward_list(self) -> CommandResult:
        return self.run(["forward", "--list"], timeout=30)

    @staticmethod
    def parse_forward_list(text: str) -> list[dict[str, Any]]:
        """Parse ``adb forward --list`` rows into ``{serial, local, remote}``."""

        entries: list[dict[str, Any]] = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            serial, local, remote = parts[0], parts[1], parts[2]
            if not local.startswith("tcp:") or not remote.startswith("tcp:"):
                continue
            try:
                local_port = int(local.split(":", 1)[1])
                remote_port = int(remote.split(":", 1)[1])
            except ValueError:
                continue
            entries.append(
                {"serial": serial, "local_port": local_port, "remote_port": remote_port, "local": local, "remote": remote}
            )
        return entries

    def forwards_for(self, serial: str) -> list[dict[str, Any]]:
        result = self.forward_list()
        if not result.ok:
            return []
        return [entry for entry in self.parse_forward_list(result.stdout) if entry["serial"] == serial]

    def has_forward(self, serial: str, local_port: int, remote_port: int | None = None) -> bool:
        for entry in self.forwards_for(serial):
            if entry["local_port"] != int(local_port):
                continue
            if remote_port is None or entry["remote_port"] == int(remote_port):
                return True
        return False

    def elf_arch(self, serial: str, path: str) -> str | None:
        """Read the ELF machine of a device file without requiring ``file``/``readelf``."""

        result = self.shell(serial, f"od -An -tx1 -N20 {shlex.quote(path)} 2>/dev/null", timeout=20)
        if not result.ok or not result.stdout.strip():
            return None
        try:
            raw = bytes.fromhex("".join(result.stdout.split()))
        except ValueError:
            return None
        if len(raw) < 20 or raw[:4] != b"\x7fELF":
            return None
        machine = int.from_bytes(raw[18:20], "little" if raw[5] == 1 else "big")
        names = {
            0x03: "x86",
            0x28: "arm",
            0x3E: "x86_64",
            0xB7: "arm64",
            0x08: "mips",
            0x2B: "mips64",
        }
        return names.get(machine, f"machine_{machine:#x}")

    # ------------------------------------------------------------------ device facts
    def ensure_root(self, serial: str) -> dict[str, Any]:
        identity = self.shell(serial, "id", timeout=20)
        if identity.ok and "uid=0" in identity.stdout:
            return {"available": True, "uid": 0, "method": "already_root"}
        root = self.run(["root"], serial=serial, timeout=30)
        rejected = "cannot run as root" in (root.stdout + root.stderr).lower()
        tcp = bool(re.fullmatch(r"(?:[A-Za-z0-9_.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}", serial))
        deadline = time.monotonic() + 30
        # adbd restarts after `root`. TCP transports can remain offline until
        # explicitly reconnected; wait-for-device alone does not reconnect them.
        for _ in range(12 if not rejected else 0):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if tcp:
                self.run(["connect", serial], timeout=min(5, remaining))
            else:
                self.run(["wait-for-device"], serial=serial, timeout=min(5, remaining))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            identity = self.shell(serial, "id", timeout=min(5, remaining))
            if identity.ok and "uid=0" in identity.stdout:
                return {"available": True, "uid": 0, "method": "adb_root", "output": root.stdout.strip()}
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        if not rejected and not identity.ok:
            raise fail(
                "device_unavailable",
                "adbd did not reconnect after adb root",
                details={"serial": serial, "adb_root_output": root.stdout.strip(),
                         "adb_root_error": root.stderr.strip(), "id_error": identity.stderr.strip()},
            )
        raise fail(
            "root_required",
            "adb root did not yield uid=0",
            details={"adb_root_output": root.stdout.strip(), "adb_root_error": root.stderr.strip(), "id": identity.stdout.strip()},
        )

    def device_info(self, serial: str, frida_server_path: str | None = None) -> dict[str, Any]:
        script = "; ".join(
            [
                "echo __APU_MODEL=$(getprop ro.product.model)",
                "echo __APU_MANUFACTURER=$(getprop ro.product.manufacturer)",
                "echo __APU_ABI=$(getprop ro.product.cpu.abi)",
                "echo __APU_ABILIST=$(getprop ro.product.cpu.abilist)",
                "echo __APU_SDK=$(getprop ro.build.version.sdk)",
                "echo __APU_RELEASE=$(getprop ro.build.version.release)",
                "echo __APU_SELINUX=$(getenforce 2>/dev/null)",
                "echo __APU_ID=$(id)",
                "echo __APU_SERIAL=$(getprop ro.serialno)",
            ]
        )
        props_result = self.shell(serial, script, timeout=30)
        props: dict[str, str] = {}
        for line in props_result.stdout.splitlines():
            if line.startswith("__APU_"):
                key, _, value = line.partition("=")
                props[key[len("__APU_") :]] = value.strip()
        identity = props.get("ID", "")
        root_available = "uid=0" in identity

        host = self.config.frida_host_for(serial)
        local_port = self.config.frida_port_for(serial)
        remote_port = self.config.frida_remote_port
        frida_cli = self.host.run(list(self.config.frida) + ["--version"], timeout=15)
        frida_cli_version = frida_cli.stdout.strip() if frida_cli.ok else None
        frida_ps_probe = self.host.run(list(self.config.frida_ps) + ["-H", host], timeout=15)
        server_process = self.frida_server_process(serial)
        server_version = None
        server_path = frida_server_path or "/data/local/tmp/frida-server"
        version_result = self.shell(
            serial,
            f"[ -f {shlex.quote(server_path)} ] && {shlex.quote(server_path)} --version || echo __APU_MISSING__",
            timeout=10,
        )
        if version_result.ok:
            text = version_result.stdout.strip()
            if text and "__APU_MISSING__" not in text:
                server_version = text.splitlines()[-1].strip()
        forwarded = self.has_forward(serial, local_port, remote_port)
        abi = props.get("ABI")
        abilist = [item for item in (props.get("ABILIST") or "").split(",") if item]
        server_arch = None
        if frida_server_path and Path(frida_server_path).is_file():
            server_arch = read_elf_arch(frida_server_path)
        version_matches = None
        if frida_cli_version and server_version:
            version_matches = frida_cli_version == server_version
        return {
            "serial": serial,
            "model": props.get("MODEL"),
            "manufacturer": props.get("MANUFACTURER"),
            "abi": abi,
            "abilist": abilist,
            "sdk": _to_int(props.get("SDK")),
            "release": props.get("RELEASE"),
            "selinux": props.get("SELINUX"),
            "root": {
                "available": root_available,
                "identity": identity,
            },
            "frida": {
                "cli_version": frida_cli_version,
                "server_version": server_version,
                "server_path": server_path,
                "server_process": server_process,
                "server_arch": server_arch,
                "forwarded": forwarded,
                "reachable": frida_ps_probe.ok,
                "version_matches": version_matches,
                "host": host,
                "local_port": local_port,
                "remote_port": remote_port,
            },
            "capabilities": {
                "proc_mem": root_available,
                "root": root_available,
                "logcat": True,
                "attach": frida_ps_probe.ok,
                "spawn": frida_ps_probe.ok,
            },
        }

    def _find_frida_server_process(self, serial: str) -> dict[str, Any] | None:
        result = self.shell(serial, "ps -A 2>/dev/null", timeout=20)
        if not result.ok:
            return None
        for line in result.stdout.splitlines():
            if "frida-server" not in line:
                continue
            parts = line.split()
            pid = None
            for token in parts:
                if token.isdigit():
                    pid = int(token)
                    break
            return {"pid": pid, "line": line.strip()}
        return None

    def frida_server_process(self, serial: str) -> dict[str, Any] | None:
        """Public lookup used by the per-device frida-server replacement logic."""

        return self._find_frida_server_process(serial)

    def kill_frida_server(self, serial: str) -> dict[str, Any]:
        process = self._find_frida_server_process(serial)
        pid = (process or {}).get("pid")
        if not pid:
            return {"killed": False, "reason": "not_running"}
        self.shell(serial, f"kill -9 {int(pid)} 2>/dev/null", timeout=15)
        time.sleep(0.5)
        return {"killed": True, "pid": int(pid)}

    # ------------------------------------------------------------------ app lifecycle
    def force_stop(self, serial: str, package: str) -> CommandResult:
        return self.shell(serial, f"am force-stop {shlex.quote(package)}", timeout=30)

    def resolve_activity(self, serial: str, package: str) -> str | None:
        result = self.shell(serial, f"cmd package resolve-activity --brief {shlex.quote(package)}", timeout=20)
        if result.ok and result.stdout:
            for line in reversed(result.stdout.splitlines()):
                line = line.strip()
                if "/" in line and not line.startswith("priority="):
                    return line
        return None

    def am_start(self, serial: str, package: str, activity: str | None = None) -> CommandResult:
        component = self._component(package, activity)
        if component:
            return self.shell(serial, f"am start -W -n {shlex.quote(component)}", timeout=60)
        return self.shell(
            serial,
            "monkey -p {pkg} -c android.intent.category.LAUNCHER 1".format(pkg=shlex.quote(package)),
            timeout=60,
        )

    def install(self, serial: str, apk_path: str | Path) -> CommandResult:
        return self.run(["install", "-r", str(apk_path)], serial=serial, timeout=self.config.install_timeout_s)

    def install_files(self, serial: str, apk_paths: list[str | Path]) -> CommandResult:
        paths = [str(Path(item)) for item in apk_paths]
        if not paths:
            raise fail("invalid_input", "no APK paths to install")
        if len(paths) == 1:
            return self.install(serial, paths[0])
        return self.run(
            ["install-multiple", "-r", *paths],
            serial=serial,
            timeout=self.config.install_timeout_s,
        )

    def package_paths(self, serial: str, package: str) -> list[str]:
        result = self.shell(serial, f"pm path {shlex.quote(package)} 2>/dev/null", timeout=20)
        if not result.ok:
            return []
        paths: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                value = line.split(":", 1)[1].strip()
                if value:
                    paths.append(value)
        return paths

    def package_dirs(self, serial: str, package: str) -> list[str]:
        """Return only directories owned by this package, never all of /data/app."""

        # Android paths are POSIX; Path() on Windows would turn /data/app into
        # \data\app and break the scoped search.
        dirs = {posixpath.dirname(path) for path in self.package_paths(serial, package)}
        dirs.add(f"/data/user/0/{package}")
        return sorted(dirs)

    @staticmethod
    def _component(package: str, activity: str | None) -> str | None:
        if not activity:
            return None
        if "/" in activity:
            return activity
        if activity.startswith("."):
            return package + "/" + activity
        return package + "/" + activity

    def pidof(self, serial: str, package: str) -> list[int]:
        result = self.shell(serial, f"pidof {shlex.quote(package)}", timeout=20)
        if not result.ok or not result.stdout.strip():
            return []
        return [int(token) for token in result.stdout.split() if token.isdigit()]

    def stat_size(self, serial: str, path: str) -> int | None:
        result = self.shell(serial, f"stat -c %s {shlex.quote(path)} 2>/dev/null", timeout=20)
        if result.ok and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
        return None

    def file_exists(self, serial: str, path: str) -> bool:
        result = self.shell(serial, f"[ -e {shlex.quote(path)} ] && echo yes || echo no", timeout=15)
        return result.ok and result.stdout.strip() == "yes"

    def mkdirs(self, serial: str, path: str) -> CommandResult:
        return self.shell(serial, f"mkdir -p {shlex.quote(path)}", timeout=20)

    def chmod(self, serial: str, mode: str, path: str) -> CommandResult:
        return self.shell(serial, f"chmod {mode} {shlex.quote(path)}", timeout=20)

    def remove(self, serial: str, path: str) -> CommandResult:
        return self.shell(serial, f"rm -rf {shlex.quote(path)}", timeout=30)

    def rename(self, serial: str, source: str, destination: str) -> CommandResult:
        return self.shell(serial, f"mv {shlex.quote(source)} {shlex.quote(destination)}", timeout=20)

    def list_dir(self, serial: str, path: str) -> list[str]:
        result = self.shell(serial, f"ls -1 {shlex.quote(path)} 2>/dev/null", timeout=20)
        if not result.ok:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def find(self, serial: str, root: str, name: str) -> list[str]:
        result = self.shell(
            serial,
            f"find {shlex.quote(root)} -name {shlex.quote(name)} 2>/dev/null",
            timeout=60,
        )
        if not result.ok:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def logcat_tail(self, serial: str, lines: int = 200) -> str:
        result = self.shell(serial, f"logcat -d -t {int(lines)} 2>/dev/null", timeout=30)
        return result.stdout if result.ok else ""

    def start_frida_server(self, serial: str, server_path: str, port: int) -> dict[str, Any]:
        existing = self._find_frida_server_process(serial)
        if existing and existing.get("pid"):
            return {"started": False, "pid": existing["pid"], "reason": "already_running"}
        commands = [
            f"setsid {shlex.quote(server_path)} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 < /dev/null &",
            f"nohup {shlex.quote(server_path)} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &",
            f"{shlex.quote(server_path)} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &",
        ]
        for command in commands:
            self.shell(serial, command, timeout=20)
            time.sleep(1.5)
            process = self._find_frida_server_process(serial)
            if process and process.get("pid"):
                return {"started": True, "pid": process["pid"], "reason": "started"}
        raise fail(
            "frida_unavailable",
            "frida-server did not start",
            remediation="Verify the binary matches the device ABI and is executable.",
            details={"server_path": server_path, "port": port},
        )


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None
