from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

from ..config import Config
from ..domain.errors import fail
from ..domain.jsonutil import canonical_json
from .host import HostRunner, StreamResult

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"


class FridaManager:
    def __init__(self, host: HostRunner, config: Config):
        self.host = host
        self.config = config

    # ------------------------------------------------------------------ probe
    def version(self) -> str | None:
        result = self.host.run(list(self.config.frida) + ["--version"], timeout=15)
        return result.stdout.strip() if result.ok else None

    def probe(self, host: str | None = None) -> dict[str, Any]:
        endpoint = host or self.config.frida_host
        result = self.host.run(list(self.config.frida_ps) + ["-H", endpoint], timeout=20)
        return {
            "reachable": result.ok,
            "host": endpoint,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
            "returncode": result.returncode,
            "missing": result.missing,
        }

    # ------------------------------------------------------------------ script execution
    def run_script(
        self,
        script_name: str,
        config: dict[str, Any],
        *,
        pid: int | None = None,
        package: str | None = None,
        spawn: bool = False,
        timeout_ms: int | None = None,
        cancel: threading.Event | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        if not pid and not (spawn and package):
            raise fail("invalid_input", "Frida run requires pid, or spawn=true with package")
        script_path = SCRIPT_DIR / script_name
        if not script_path.is_file():
            raise fail("tool_missing", f"bundled Frida script not found: {script_path}")
        preamble = (SCRIPT_DIR / "preamble.js").read_text(encoding="utf-8")
        script = script_path.read_text(encoding="utf-8")
        wrapper = "globalThis.APU_CONFIG = " + json.dumps(config, ensure_ascii=False) + ";\n" + preamble + "\n" + script

        temp_dir = _ascii_temp_dir(config.get("run_id") or "frida")
        wrapper_path = temp_dir / f"{Path(script_name).stem}_{os.getpid()}_{_nonce()}.js"
        wrapper_path.write_text(wrapper, encoding="utf-8")

        endpoint = host or self.config.frida_host
        base = list(self.config.frida) + ["-H", endpoint]
        if pid:
            argv = base + ["-p", str(int(pid)), "-l", str(wrapper_path), "-q"]
        else:
            argv = base + ["-f", str(package), "-l", str(wrapper_path), "-q"]
        # Quiet mode otherwise exits immediately after loading the script.
        # Java.perform/waitForApp are asynchronous; the host owns the deadline
        # and stops the CLI on the done marker or cancellation.
        argv += ["-t", "inf"]

        events: list[dict[str, Any]] = []

        def on_line(stream: str, line: str) -> None:
            if stream != "stdout":
                return
            stripped = line.strip()
            if not stripped.startswith("APU::"):
                return
            try:
                payload = json.loads(stripped[len("APU::") :])
            except json.JSONDecodeError:
                return
            if isinstance(payload, dict):
                events.append(payload)

        def stop_when(stream: str, line: str) -> bool:
            stripped = line.strip()
            if stream != "stdout" or not stripped.startswith("APU::"):
                return False
            try:
                payload = json.loads(stripped[len("APU::") :])
            except json.JSONDecodeError:
                return False
            return isinstance(payload, dict) and payload.get("type") == "done"

        timeout = (timeout_ms or self.config.frida_timeout_ms) / 1000.0
        stream_result: StreamResult = self.host.stream(
            argv,
            timeout=timeout,
            cancel=cancel,
            on_line=on_line,
            stop_when=stop_when,
            cwd=temp_dir,
        )
        if stream_result.cancelled:
            raise fail("cancelled", "Frida script cancelled", details={"events": events[-20:]})
        if stream_result.missing:
            raise fail(
                "frida_unavailable",
                "frida CLI is not installed or not on PATH",
                details={"frida": self.config.frida},
            )
        done = next((event for event in events if event.get("type") == "done"), None)
        errors = [event for event in events if event.get("type") == "error"]
        if done is None:
            if stream_result.timed_out:
                raise fail(
                    "timeout",
                    f"Frida script did not finish within {timeout:.0f}s",
                    retryable=True,
                    details={"events": events[-20:], "stderr": stream_result.text("stderr")[-4000:]},
                )
            raise fail(
                "execution_failure",
                "Frida CLI exited before the script reported done",
                captured_output=stream_result.text("stderr") or stream_result.text("stdout"),
                details={"events": events[-20:], "returncode": stream_result.returncode},
            )
        if done.get("ok") is False:
            message = "; ".join(str(item.get("message", item)) for item in errors[-4:]) or "Frida script reported failure"
            raise fail(
                "process_died",
                message,
                retryable=True,
                remediation="Retry with anti-kill hooks, attach mode, or a memory dump.",
                details={"events": events[-20:], "stderr": stream_result.text("stderr")[-4000:]},
            )
        return {
            "script": script_name,
            "wrapper": str(wrapper_path),
            "argv": argv,
            "host": endpoint,
            "events": events,
            "done": done,
            "stdout": stream_result.text("stdout")[-20000:],
            "stderr": stream_result.text("stderr")[-20000:],
            "returncode": stream_result.returncode,
            "timed_out": stream_result.timed_out,
            "duration_s": round(stream_result.duration_s, 3),
        }

    # ------------------------------------------------------------------ helper
    @staticmethod
    def config_digest(config: dict[str, Any]) -> str:
        return canonical_json(config)


def _nonce() -> str:
    import secrets

    return secrets.token_hex(4)


def _ascii_temp_dir(run_id: str) -> Path:
    base = Path(tempfile.gettempdir()) / "apu" / re.sub(r"[^A-Za-z0-9_.-]+", "_", run_id)
    base.mkdir(parents=True, exist_ok=True)
    if os.name == "nt" and not str(base).isascii():
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(2048)
            if ctypes.windll.kernel32.GetShortPathNameW(str(base), buffer, 2048):
                shortened = Path(buffer.value)
                if str(shortened).isascii():
                    return shortened
        except Exception:
            pass
    return base
