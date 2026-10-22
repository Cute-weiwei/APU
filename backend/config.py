from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_SRC = REPO_ROOT / "src"
SKILLS_ROOT = REPO_ROOT / ".agents" / "skills"
SKILL_PATH = SKILLS_ROOT / "unpack-android-apk" / "SKILL.md"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _secret(name: str) -> str | None:
    file_name = name + "_FILE"
    path = _env(file_name)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return None
    return _env(name)


@dataclass
class EngineConfig:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    max_steps: int = 24
    timeout_s: int = 180
    protocol: str = ""
    context_window: int = 65536
    max_tokens: int = 4096
    tool_result_chars: int = 16000
    temperature: float = 0.1

    @property
    def available(self) -> bool:
        return bool(self.api_key) if self.name != "agent" else True

    @property
    def reason(self) -> str:
        if self.name == "agent":
            return "deterministic workflow"
        if not self.api_key:
            return f"missing {self.name.upper()} API key"
        return "configured"

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "max_steps": self.max_steps,
            "available": self.available,
            "reason": self.reason,
        }


@dataclass
class BackendConfig:
    data_dir: Path
    runs_dir: Path
    memory_dir: Path
    uploads_dir: Path
    jobs_dir: Path
    secrets_dir: Path
    skills_root: Path
    db_path: Path
    static_dir: Path
    agent_repo: Path
    agent_src: Path
    agent_python: str
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 1
    admin_user: str = "admin"
    admin_password: str | None = None
    serial: str | None = None
    redroid_addr: str | None = None
    session_days: int = 7
    max_upload_bytes: int = 1024 * 1024 * 1024
    retention_days: int = 14
    tool_result_max_chars: int = 200_000
    device_auto_create: bool = False
    device_image: str = "erstt/redroid:11.0.0_ndk_ChromeOS"
    device_port_start: int = 5557
    device_port_end: int = 5599
    device_max_containers: int = 2
    device_create_timeout_s: int = 120
    # ARM64 redroid runs through QEMU user-mode emulation on this x86_64 host.
    # It is slow, so it is only provisioned as a fallback after the fast x86
    # runtime fails to recover a packed APK.
    device_arm_enabled: bool = True
    # Automatic x86 -> ARM fallback is implemented but stays opt-in until an
    # ARM64 runtime that can finish booting is attached (ARM host or device).
    device_arm_fallback: bool = False
    # Locally built 64-bit-only ARM64 image (see deploy/build-arm-redroid.sh).
    # It is single-architecture, so no --platform flag is needed; the QEMU
    # binfmt handler runs it on this x86_64 host.
    device_arm_image: str = "apu-redroid-arm64:12-64only"
    device_arm_platform: str = ""
    device_arm_max_containers: int = 1
    device_arm_create_timeout_s: int = 1800
    frida_server_arm64: str | None = None
    engines: dict[str, EngineConfig] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        config_path: str | Path | None = None,
        data_dir: str | Path | None = None,
    ) -> "BackendConfig":
        raw: dict[str, Any] = {}
        path = Path(config_path).expanduser() if config_path else None
        if path and path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {}
        server = raw.get("server") or {}
        agent = raw.get("agent") or {}
        engines_raw = raw.get("engines") or {}

        data = Path(
            data_dir
            or _env("APU_WEB_DATA_DIR")
            or server.get("data_dir")
            or (REPO_ROOT / "backend" / "data")
        ).expanduser().resolve()
        runs = Path(_env("APU_WEB_RUNS_DIR") or agent.get("runs_dir") or data / "runs")
        memory = Path(_env("APU_WEB_MEMORY_DIR") or agent.get("memory_dir") or data / "memory")
        uploads = data / "uploads"
        jobs = data / "jobs"
        secrets = data / "secrets"
        repo = Path(_env("APU_WEB_AGENT_REPO") or agent.get("repo") or REPO_ROOT).expanduser().resolve()
        python = _env("APU_WEB_AGENT_PYTHON") or agent.get("python") or sys.executable

        deepseek_raw = engines_raw.get("deepseek") or {}
        claude_raw = engines_raw.get("claude") or {}
        deepseek = EngineConfig(
            name="deepseek",
            base_url=_env("DEEPSEEK_BASE_URL") or deepseek_raw.get("base_url") or "https://api.deepseek.com",
            model=_env("DEEPSEEK_MODEL") or deepseek_raw.get("model") or "deepseek-chat",
            api_key=_secret("DEEPSEEK_API_KEY"),
            max_steps=int(_env("DEEPSEEK_MAX_STEPS") or deepseek_raw.get("max_steps") or 24),
            timeout_s=int(_env("DEEPSEEK_TIMEOUT_S") or deepseek_raw.get("timeout_s") or 180),
        )
        claude = EngineConfig(
            name="claude",
            base_url=_env("ANTHROPIC_BASE_URL") or claude_raw.get("base_url") or "https://api.anthropic.com",
            model=_env("CLAUDE_MODEL") or claude_raw.get("model") or "claude-sonnet-5",
            api_key=_secret("ANTHROPIC_API_KEY"),
            max_steps=int(_env("CLAUDE_MAX_STEPS") or claude_raw.get("max_steps") or 20),
            timeout_s=int(_env("CLAUDE_TIMEOUT_S") or claude_raw.get("timeout_s") or 180),
        )
        agent_engine = EngineConfig(name="agent", base_url="", model="deterministic")
        config = cls(
            data_dir=data,
            runs_dir=runs,
            memory_dir=memory,
            uploads_dir=uploads,
            jobs_dir=jobs,
            secrets_dir=secrets,
            skills_root=SKILLS_ROOT,
            db_path=data / "apu-web.sqlite3",
            static_dir=Path(__file__).resolve().parent / "static",
            agent_repo=repo,
            agent_src=repo / "src",
            agent_python=python,
            host=_env("APU_WEB_HOST") or server.get("host") or "0.0.0.0",
            port=int(_env("APU_WEB_PORT") or server.get("port") or 8080),
            workers=max(1, int(_env("APU_WEB_WORKERS") or server.get("workers") or 1)),
            admin_user=_env("APU_WEB_ADMIN_USER") or "admin",
            admin_password=_env("APU_WEB_ADMIN_PASSWORD"),
            serial=_env("APU_WEB_SERIAL") or _env("APU_SERIAL"),
            redroid_addr=_env("APU_REDROID_ADDR"),
            session_days=int(_env("APU_WEB_SESSION_DAYS") or 7),
            max_upload_bytes=int(_env("APU_WEB_MAX_UPLOAD_MB") or 1024) * 1024 * 1024,
            retention_days=int(_env("APU_WEB_RETENTION_DAYS") or 14),
            tool_result_max_chars=int(_env("APU_WEB_TOOL_RESULT_MAX_CHARS") or 200_000),
            device_auto_create=str(_env("APU_WEB_DEVICE_AUTO_CREATE") or "0").strip().lower()
            in ("1", "true", "yes", "on"),
            device_image=_env("APU_WEB_DEVICE_IMAGE") or "erstt/redroid:11.0.0_ndk_ChromeOS",
            device_port_start=int(_env("APU_WEB_DEVICE_PORT_START") or 5557),
            device_port_end=int(_env("APU_WEB_DEVICE_PORT_END") or 5599),
            device_max_containers=max(0, int(_env("APU_WEB_DEVICE_MAX_CONTAINERS") or 2)),
            device_create_timeout_s=max(30, int(_env("APU_WEB_DEVICE_CREATE_TIMEOUT_S") or 120)),
            device_arm_enabled=str(_env("APU_WEB_DEVICE_ARM_ENABLED") or "1").strip().lower()
            in ("1", "true", "yes", "on"),
            device_arm_fallback=str(_env("APU_WEB_DEVICE_ARM_FALLBACK") or "0").strip().lower()
            in ("1", "true", "yes", "on"),
            device_arm_image=_env("APU_WEB_DEVICE_ARM_IMAGE")
            or "apu-redroid-arm64:12-64only",
            device_arm_platform=str(_env("APU_WEB_DEVICE_ARM_PLATFORM") or "").strip(),
            device_arm_max_containers=max(0, int(_env("APU_WEB_DEVICE_ARM_MAX_CONTAINERS") or 1)),
            device_arm_create_timeout_s=max(
                120, int(_env("APU_WEB_DEVICE_ARM_CREATE_TIMEOUT_S") or 1800)
            ),
            frida_server_arm64=_env("APU_FRIDA_SERVER_ARM64") or None,
            engines={"agent": agent_engine, "deepseek": deepseek, "claude": claude},
        )
        config.ensure_dirs()
        return config

    def ensure_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.runs_dir,
            self.memory_dir,
            self.uploads_dir,
            self.jobs_dir,
            self.secrets_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def public(self) -> dict[str, Any]:
        return {
            "version": "0.1.0",
            "host": self.host,
            "port": self.port,
            "workers": self.workers,
            "data_dir": str(self.data_dir),
            "runs_dir": str(self.runs_dir),
            "memory_dir": str(self.memory_dir),
            "serial": self.serial,
            "redroid_addr": self.redroid_addr,
            "engines": {name: engine.public() for name, engine in self.engines.items()},
        }
