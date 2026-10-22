from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..domain.errors import fail


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_s: float = 0.0
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing

    def to_dict(self) -> dict:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "missing": self.missing,
            "duration_s": round(self.duration_s, 3),
            "stdout": self.stdout[-8000:],
            "stderr": self.stderr[-8000:],
        }


@dataclass
class StreamResult:
    argv: list[str]
    returncode: int | None
    lines: list[tuple[str, str]] = field(default_factory=list)  # (stream, line)
    timed_out: bool = False
    cancelled: bool = False
    missing: bool = False
    duration_s: float = 0.0

    def text(self, stream: str | None = None) -> str:
        return "\n".join(line for source, line in self.lines if stream is None or source == stream)

    def to_dict(self) -> dict:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "missing": self.missing,
            "duration_s": round(self.duration_s, 3),
            "stdout": self.text("stdout")[-8000:],
            "stderr": self.text("stderr")[-8000:],
        }


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def _spawn_kwargs() -> dict:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


class HostRunner:
    """Subprocess boundary. Never uses a shell unless the caller explicitly asks."""

    def run(
        self,
        argv: Iterable[str],
        *,
        timeout: float = 120.0,
        cwd: str | Path | None = None,
        input_bytes: bytes | None = None,
        env: dict[str, str] | None = None,
        check: bool = False,
    ) -> CommandResult:
        command = [str(item) for item in argv]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                env=env,
                **_spawn_kwargs(),
            )
        except FileNotFoundError:
            return CommandResult(command, returncode=-1, missing=True, duration_s=time.monotonic() - started)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command,
                returncode=-1,
                stdout=_decode(exc.stdout),
                stderr=_decode(exc.stderr),
                timed_out=True,
                duration_s=time.monotonic() - started,
            )
        result = CommandResult(
            command,
            returncode=completed.returncode,
            stdout=_decode(completed.stdout),
            stderr=_decode(completed.stderr),
            duration_s=time.monotonic() - started,
        )
        if check and not result.ok:
            raise fail(
                "execution_failure",
                f"command failed ({result.returncode}): {' '.join(command)}",
                captured_output=result.stderr or result.stdout,
                details={"argv": command},
            )
        return result

    def run_to_file(
        self,
        argv: Iterable[str],
        out_path: str | Path,
        *,
        timeout: float = 120.0,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        command = [str(item) for item in argv]
        started = time.monotonic()
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(out_path, "wb") as sink:
                completed = subprocess.run(
                    command,
                    stdout=sink,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    cwd=str(cwd) if cwd else None,
                    **_spawn_kwargs(),
                )
        except FileNotFoundError:
            return CommandResult(command, -1, missing=True, duration_s=time.monotonic() - started)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command,
                -1,
                stderr=_decode(exc.stderr),
                timed_out=True,
                duration_s=time.monotonic() - started,
            )
        return CommandResult(
            command,
            completed.returncode,
            stderr=_decode(completed.stderr),
            duration_s=time.monotonic() - started,
        )

    def stream(
        self,
        argv: Iterable[str],
        *,
        timeout: float = 180.0,
        cancel: threading.Event | None = None,
        on_line: Callable[[str, str], None] | None = None,
        stop_when: Callable[[str, str], bool] | None = None,
        cwd: str | Path | None = None,
    ) -> StreamResult:
        command = [str(item) for item in argv]
        started = time.monotonic()
        result = StreamResult(command, returncode=None)
        stop_requested = threading.Event()
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                universal_newlines=True,
                cwd=str(cwd) if cwd else None,
                **_spawn_kwargs(),
            )
        except FileNotFoundError:
            result.missing = True
            result.duration_s = time.monotonic() - started
            return result

        def pump(stream, name: str) -> None:
            try:
                for line in iter(stream.readline, ""):
                    line = line.rstrip("\r\n")
                    result.lines.append((name, line))
                    if on_line:
                        try:
                            on_line(name, line)
                        except Exception:
                            pass
                    if stop_when:
                        try:
                            if stop_when(name, line):
                                stop_requested.set()
                        except Exception:
                            pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        threads = [
            threading.Thread(target=pump, args=(proc.stdout, "stdout"), daemon=True),
            threading.Thread(target=pump, args=(proc.stderr, "stderr"), daemon=True),
        ]
        for thread in threads:
            thread.start()

        deadline = time.monotonic() + max(0.1, timeout)
        while True:
            if cancel is not None and cancel.is_set():
                result.cancelled = True
                self._terminate(proc)
                break
            if stop_requested.is_set():
                self._terminate(proc)
                break
            if time.monotonic() >= deadline:
                result.timed_out = True
                self._terminate(proc)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)

        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._terminate(proc)
        for thread in threads:
            thread.join(timeout=2)
        result.returncode = proc.returncode
        result.duration_s = time.monotonic() - started
        return result

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            proc.kill()
        except OSError:
            pass

    # ------------------------------------------------------------------ resolution
    @staticmethod
    def which(name: str) -> str | None:
        import shutil

        return shutil.which(name)

    @staticmethod
    def first_existing(paths: Iterable[str | Path | None]) -> str | None:
        for item in paths:
            if not item:
                continue
            candidate = Path(str(item)).expanduser()
            try:
                if candidate.is_file():
                    return str(candidate)
            except OSError:
                continue
        return None

    @staticmethod
    def resolve_command(default: list[str], env_name: str) -> list[str]:
        raw = os.environ.get(env_name, "").strip()
        if not raw:
            return default
        candidate = Path(raw)
        if candidate.exists():
            return [raw]
        import shlex

        return shlex.split(raw, posix=(os.name != "nt"))


def read_elf_arch(path: str | Path) -> str | None:
    """Return a human-readable architecture from an ELF header, if possible."""

    try:
        with open(path, "rb") as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    endian = "<" if header[5] == 1 else ">"
    machine = int.from_bytes(header[18:20], "little" if endian == "<" else "big")
    names = {
        0x03: "x86",
        0x28: "arm",
        0x3E: "x86_64",
        0xB7: "arm64",
        0x08: "mips",
        0x2B: "mips64",
    }
    return names.get(machine, f"machine_{machine:#x}")


def python_executable() -> str:
    return sys.executable
