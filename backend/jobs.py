from __future__ import annotations

import json
import os
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import threading
import time
import zipfile
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

from apk_unpack.application.workflow import ToolService
from apk_unpack.config import Config as AgentConfig

from .agents import BUILTIN_AGENT_ID, AgentStore
from .config import BackendConfig
from .db import Database
from .engines import (
    AgentEngine,
    ClaudeEngine,
    DeepSeekEngine,
    EngineResult,
    JobContext,
    ProviderAnthropicEngine,
    ProviderAutoEngine,
    ProviderOpenAIEngine,
    assess_fixed_dex,
    cleanup_summary,
    read_run_state,
    run_expected_package,
)
from .events import EventBus
from .job_options import normalize_job_options
from .lessons import record_job_lesson
from .mcp import McpStore
from .providers import ProviderStore
from .security import redact
from .skills import SkillStore


def new_run_id() -> str:
    return "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_hex(4)


def new_job_id() -> str:
    return "job_" + secrets.token_hex(8)


_DEVICE_CREATE_LOCK = threading.Lock()

ARM_ARCH = "arm64"
X86_ARCH = "x86_64"
ARM_CONTAINER_PREFIX = "apu-redroid-arm-"
X86_CONTAINER_PREFIX = "apu-redroid-"

# Failures that a different runtime cannot fix; never retry them on ARM.
NON_FALLBACK_ERROR_CODES = {
    "configuration_error",
    "unsupported_provider",
    "invalid_input",
    "permission_denied",
    "upload_missing",
    "apk_unreadable",
    "apk_too_large",
}
# Error text used by packers/anti-debug when they abort under x86 translation.
DEVICE_FAILURE_HINTS = (
    "emulator",
    "anti-debug",
    "antidebug",
    "signal 9",
    "sigkill",
    "killed",
    "process died",
    "target not running",
    "not running",
    "crashed",
    "crash",
    "frida",
    "seccomp",
    "native bridge",
    "ndk translation",
    "houdini",
    "exec format",
    "illegal instruction",
    "dump incomplete",
    "no freeze target",
)


class DeviceLockManager:
    def __init__(self) -> None:
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock(self, serial: str | None) -> threading.Lock:
        key = serial or "default"
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    @contextmanager
    def acquire(self, serial: str | None) -> Iterator[None]:
        lock = self._lock(serial)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()


class JobManager:
    def __init__(self, config: BackendConfig, database: Database, bus: EventBus):
        self.config = config
        self.database = database
        self.bus = bus
        self.devices = DeviceLockManager()
        os.environ.setdefault("APU_RUNS_DIR", str(config.runs_dir))
        os.environ.setdefault("APU_MEMORY_DIR", str(config.memory_dir))
        agent_config = AgentConfig.load(runs_dir=config.runs_dir)
        agent_config.memory_dir = config.memory_dir
        if config.serial:
            agent_config.default_serial = config.serial
        self.service = ToolService(agent_config)
        try:
            self.service.lessons.consolidate()
        except Exception:
            pass
        self.providers = ProviderStore(config, database)
        self.skills = SkillStore(config, database)
        self.mcps = McpStore(config, database)
        self.agents = AgentStore(config, database, self.providers, self.skills, self.mcps)
        self.engines: dict[str, Any] = {"agent": AgentEngine(config)}
        self.queue: queue.Queue[str | None] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._contexts: dict[str, JobContext] = {}
        self._context_guard = threading.Lock()
        self._log_lock = threading.Lock()
        self._arch_cache: dict[str, str] = {}
        self._arch_guard = threading.Lock()

    # ------------------------------------------------------------------ catalog / engines
    def seed_catalog(self) -> None:
        self.providers.seed()
        self.skills.seed()
        self.agents.seed()
        self.refresh_engines()

    def refresh_engines(self) -> None:
        self.engines = self._build_engines()

    def _build_engines(self) -> dict[str, Any]:
        engines: dict[str, Any] = {}
        native = self.agents.get(BUILTIN_AGENT_ID)
        native_skills = self.skills.resolve(native.skill_ids) if native else []
        engines[BUILTIN_AGENT_ID] = AgentEngine(self.config, native, native_skills)
        for agent in self.agents.list():
            if agent.kind != "llm" or not agent.provider_id:
                continue
            provider = self.providers.get(agent.provider_id, include_key=True)
            if not provider:
                continue
            skills = self.skills.resolve(agent.skill_ids)
            mcps = self.mcps.resolve(agent.mcp_ids)
            if provider.protocol == "openai":
                engine_type = ProviderOpenAIEngine
            elif provider.protocol == "anthropic":
                engine_type = ProviderAnthropicEngine
            else:
                engine_type = ProviderAutoEngine
            engines[agent.id] = engine_type(self.config, provider, agent, skills, mcps)
        # Legacy env-configured engines remain resolvable for old jobs and retries.
        if self.config.engines.get("deepseek") and self.config.engines["deepseek"].api_key:
            engines.setdefault("deepseek", DeepSeekEngine(self.config))
        if self.config.engines.get("claude") and self.config.engines["claude"].api_key:
            engines.setdefault("claude", ClaudeEngine(self.config))
        return engines

    def _is_legacy(self, name: str, engine: Any) -> bool:
        return name in ("deepseek", "claude") and isinstance(engine, (DeepSeekEngine, ClaudeEngine))

    def engine_public(self, admin: bool = False) -> dict[str, Any]:
        return {
            name: engine.public(admin=admin)
            for name, engine in self.engines.items()
            if not self._is_legacy(name, engine)
        }

    def engine_availability(self) -> dict[str, bool]:
        return {
            name: bool(getattr(engine, "available", True))
            for name, engine in self.engines.items()
            if not self._is_legacy(name, engine)
        }

    def canonical_engine(self, name: str) -> str:
        return self.agents.canonical_engine(name)

    def default_engine(self, visible_to: int | None = None) -> str:
        """Preferred engine for new jobs.

        Model-backed agents are preferred over the deterministic workflow, and
        the DeepSeek OpenAI-protocol agent wins among available model agents.
        The deterministic agent stays as a fallback when no model is usable.
        Private agents owned by another user are never selected.
        """
        candidates: list[tuple[int, str]] = []
        for name, engine in self.engines.items():
            if self._is_legacy(name, engine):
                continue
            agent = getattr(engine, "agent", None)
            if getattr(agent, "kind", "") != "llm":
                continue
            if visible_to is not None:
                owner_id = getattr(agent, "owner_id", None)
                if owner_id is not None and int(owner_id) != int(visible_to):
                    continue
            if not bool(getattr(engine, "available", False)):
                continue
            provider_id = str(getattr(agent, "provider_id", "") or "")
            if name == "agent-deepseek-openai":
                rank = 0
            elif provider_id == "deepseek-openai":
                rank = 1
            elif "deepseek" in provider_id:
                rank = 2
            else:
                rank = 3
            candidates.append((rank, name))
        if candidates:
            return min(candidates)[1]
        if BUILTIN_AGENT_ID in self.engines:
            return BUILTIN_AGENT_ID
        return next(iter(self.engines), BUILTIN_AGENT_ID)

    # ------------------------------------------------------------------ devices
    def _device_arch(self, serial: str | None, refresh: bool = False) -> str:
        """Return ``arm64`` or ``x86_64`` for a device.

        The registry is authoritative for auto-created redroid containers.
        Manually added devices are probed once over adb; ``ro.product.cpu.abi``
        is x86_64 on the libndk runtime even though it translates ARM code.
        Unknown devices are treated as x86 for selection purposes.
        """
        serial = str(serial or "").strip()
        if not serial:
            return ""
        guard = getattr(self, "_arch_guard", None)
        cache = getattr(self, "_arch_cache", None)
        if guard is None or cache is None:
            guard = threading.Lock()
            cache = {}
            self._arch_guard = guard
            self._arch_cache = cache
        with guard:
            cached = cache.get(serial)
        if cached and not refresh:
            return cached
        arch = ""
        try:
            record = self.database.get_device(serial) or {}
            arch = str(record.get("arch") or "").strip()
        except Exception:
            arch = ""
        if not arch:
            try:
                result = self.service.adb.run(
                    ["-s", serial, "shell", "getprop", "ro.product.cpu.abi"], timeout=15
                )
                abi = (result.stdout or "").strip().lower()
                if "arm" in abi:
                    arch = ARM_ARCH
                elif "x86" in abi:
                    arch = X86_ARCH
            except Exception:
                arch = ""
        if arch:
            self._remember_arch(serial, arch)
            try:
                if not (self.database.get_device(serial) or {}).get("arch"):
                    self.database.update_device(serial, arch=arch)
            except Exception:
                pass
        return arch

    def _remember_arch(self, serial: str, arch: str) -> None:
        guard = getattr(self, "_arch_guard", None)
        cache = getattr(self, "_arch_cache", None)
        if guard is None or cache is None:
            guard = threading.Lock()
            cache = {}
            self._arch_guard = guard
            self._arch_cache = cache
        with guard:
            cache[serial] = arch

    def _is_arm_serial(self, serial: str | None) -> bool:
        return self._device_arch(serial) == ARM_ARCH

    def _online_arm_serial(self) -> str | None:
        for serial in self._online_serials():
            if self._is_arm_serial(serial):
                return serial
        return None

    def _arm_runtime_options(self, options: dict[str, Any]) -> dict[str, Any]:
        """Options shared by user-selected and automatic ARM64 runs.

        QEMU user-mode emulation is roughly an order of magnitude slower, so
        the dump methods get a larger budget unless the user pinned one.
        """
        result = {
            **options,
            "_arm_runtime": True,
            "_device_arch": ARM_ARCH,
        }
        result.setdefault("freeze_timeout_ms", 180_000)
        result.setdefault("frida_timeout_ms", 180_000)
        result.setdefault("timeout_s", 7200)
        frida_arm = str(getattr(self.config, "frida_server_arm64", "") or "").strip()
        if frida_arm:
            result.setdefault("_frida_server_path", frida_arm)
        return result

    def _device_identity(self, serial: str) -> str:
        """Return a physical-device identity shared by duplicate adb transports.

        ADB can expose the same redroid instance as both ``emulator-5554`` and
        ``127.0.0.1:5555``. Per-serial locks would then allow two jobs to touch
        one device concurrently. Combine the kernel boot id with the PID
        namespace: containers share a kernel but have different namespaces,
        while separate devices can reuse the same namespace inode number.
        Probes are cached; incomplete identities fall back to the serial.
        """
        serial = str(serial or "").strip()
        if not serial:
            return ""
        guard = getattr(self, "_identity_guard", None)
        cache = getattr(self, "_identity_cache", None)
        if guard is None or cache is None:
            guard = threading.Lock()
            cache = {}
            self._identity_guard = guard
            self._identity_cache = cache
        now = time.monotonic()
        with guard:
            cached = cache.get(serial)
            if cached and now - cached[0] < cached[2]:
                return cached[1]
        identity = serial
        ttl = 10.0
        try:
            result = self.service.adb.run(
                ["-s", serial, "shell", "readlink", "/proc/1/ns/pid"],
                timeout=10,
            )
            value = (result.stdout or "").strip()
            if result.ok and re.fullmatch(r"pid:\[\d+\]", value):
                boot = self.service.adb.run(
                    ["-s", serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"],
                    timeout=10,
                )
                boot_id = (boot.stdout or "").strip().lower()
                if boot.ok and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id):
                    identity = "boot:" + boot_id + ":" + value
                    ttl = 300.0
        except Exception:
            pass
        with guard:
            cache[serial] = (now, identity, ttl)
        return identity

    def device_identity(self, serial: str) -> str:
        """Public wrapper used by device discovery to merge transports."""
        return self._device_identity(serial)

    def _device_preference(self, serial: str) -> tuple[int, int, int, str]:
        """Rank duplicate transports; prefer a manually registered TCP redroid."""
        serial = str(serial or "")
        try:
            record = self.database.get_device(serial) or {}
        except Exception:
            record = {}
        return (
            1 if serial.startswith("emulator-") else 0,
            0 if str(record.get("source") or "") == "manual" else 1,
            0 if ":" in serial else 1,
            serial,
        )

    def dedupe_serials(self, serials: list[str]) -> list[str]:
        """Collapse serials that address the same physical device."""
        groups: dict[str, list[str]] = {}
        order: list[str] = []
        for raw in serials:
            serial = str(raw or "").strip()
            if not serial:
                continue
            identity = self._device_identity(serial) or serial
            if identity not in groups:
                groups[identity] = []
                order.append(identity)
            groups[identity].append(serial)
        return [min(groups[identity], key=self._device_preference) for identity in order]

    def canonical_serial(self, serial: str | None) -> str | None:
        """Map a duplicate transport serial to the preferred online serial."""
        serial = str(serial or "").strip()
        if not serial:
            return None
        try:
            listed = {
                item.serial for item in self.service.adb.devices() if item.state == "device"
            }
        except Exception:
            return serial
        # Do not probe an offline/unknown serial: the adb shell call would
        # block job creation for its full timeout without deduping anything.
        if serial not in listed:
            return serial
        online = self._online_serials()
        if serial in online:
            return serial
        identity = self._device_identity(serial)
        if identity and not identity.startswith("pidns:"):
            return serial
        for candidate in online:
            if self._device_identity(candidate) == identity:
                return candidate
        return serial

    def _online_serials(self) -> list[str]:
        try:
            serials = [item.serial for item in self.service.adb.devices() if item.state == "device"]
        except Exception:
            return []
        # Explicitly hidden/deleted or disabled registry devices must not be
        # picked by the automatic resolver, even while adb still sees them.
        blocked: set[str] = set()
        try:
            for row in self.database.list_devices(include_hidden=True):
                serial = str(row.get("serial") or "")
                if serial and (row.get("hidden") or not row.get("enabled", 1)):
                    blocked.add(serial)
        except Exception:
            pass
        # Hiding one transport must also block its duplicates. Otherwise the
        # same physical device stays selectable as emulator-5554 after the
        # user deleted 127.0.0.1:5555.
        identities = {serial: self._device_identity(serial) for serial in serials}
        blocked_ids = {
            identities[serial]
            for serial in serials
            if serial in blocked and identities.get(serial, "").startswith("pidns:")
        }
        online = [
            serial
            for serial in serials
            if serial not in blocked and identities.get(serial, serial) not in blocked_ids
        ]
        online = self.dedupe_serials(online)
        # x86 first: the deterministic fast route must win whenever it exists.
        # ARM containers are only selected explicitly for fallback.
        return sorted(online, key=lambda item: 1 if self._is_arm_serial(item) else 0)

    def _connect_device(self, serial: str) -> bool:
        if ":" not in serial:
            return False
        try:
            result = self.service.adb.run(["connect", serial], timeout=20)
            connected = bool(result.ok) or "connected" in (result.stdout or "").lower()
            self.database.upsert_device(serial, name=serial, address=serial, source="auto", seen=connected)
            return connected
        except Exception:
            return False

    def _docker(self, args: list[str], timeout: int = 60):
        try:
            return subprocess.run(
                ["docker", *args], timeout=timeout, capture_output=True, text=True
            )
        except Exception:
            return None

    def _auto_container_names(self) -> list[str]:
        result = self._docker(
            ["ps", "-a", "--filter", "name=apu-redroid-", "--format", "{{.Names}}"],
            timeout=20,
        )
        if result is None or result.returncode != 0:
            return []
        return [
            line.strip()
            for line in (result.stdout or "").splitlines()
            if line.strip().startswith("apu-redroid-")
        ]

    def _arm_container_names(self) -> list[str]:
        return [name for name in self._auto_container_names() if name.startswith(ARM_CONTAINER_PREFIX)]

    def _x86_container_names(self) -> list[str]:
        return [
            name
            for name in self._auto_container_names()
            if name.startswith(X86_CONTAINER_PREFIX) and not name.startswith(ARM_CONTAINER_PREFIX)
        ]

    def _next_device_port(self) -> int | None:
        used: set[int] = set()
        try:
            for row in self.database.list_devices(include_hidden=True):
                serial = str(row.get("serial") or "")
                if serial.startswith("127.0.0.1:"):
                    try:
                        used.add(int(serial.rsplit(":", 1)[1]))
                    except ValueError:
                        continue
        except Exception:
            pass
        names = set(self._auto_container_names())
        start = int(getattr(self.config, "device_port_start", 5557))
        end = int(getattr(self.config, "device_port_end", 5599))
        for port in range(start, end + 1):
            if (
                port in used
                or f"{X86_CONTAINER_PREFIX}{port}" in names
                or f"{ARM_CONTAINER_PREFIX}{port}" in names
            ):
                continue
            return port
        return None

    def _wait_for_device(
        self,
        serial: str,
        timeout_s: int,
        cancel: threading.Event | None = None,
        emit: Any = None,
        label: str = "device",
    ) -> bool:
        timeout_s = max(30, int(timeout_s))
        deadline = time.time() + timeout_s
        started = time.time()
        last_report = started
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                return False
            self._connect_device(serial)
            online = self._online_serials()
            if serial in online:
                try:
                    result = self.service.adb.run(
                        ["-s", serial, "shell", "getprop", "sys.boot_completed"],
                        timeout=15,
                    )
                    if "1" in (result.stdout or ""):
                        return True
                except Exception:
                    pass
            now = time.time()
            if emit is not None and now - last_report >= 30:
                last_report = now
                try:
                    emit(
                        "device_boot_wait",
                        f"{label} is still booting ({int(now - started)}s)",
                        {"serial": serial, "elapsed_s": int(now - started), "timeout_s": timeout_s},
                    )
                except Exception:
                    pass
            time.sleep(3)
        return False

    def _create_redroid(
        self,
        arch: str = X86_ARCH,
        cancel: threading.Event | None = None,
        emit: Any = None,
    ) -> str | None:
        """Create a new redroid container when no compatible device is online.

        x86 containers use the libndk runtime and are the fast default. ARM64
        containers run native ARM Android under QEMU user-mode emulation; they
        are slower but avoid ARM-on-x86 translation checks, so they are used
        as an automatic fallback after the x86 route fails.

        Disabled unless ``APU_WEB_DEVICE_AUTO_CREATE=1``. Containers are named
        ``apu-redroid-<port>`` (x86) or ``apu-redroid-arm-<port>`` (ARM64) with
        their own data volume.
        """
        if not bool(getattr(self.config, "device_auto_create", False)):
            return None
        arm = arch == ARM_ARCH
        max_containers = int(
            getattr(
                self.config,
                "device_arm_max_containers" if arm else "device_max_containers",
                0,
            )
        )
        if max_containers <= 0:
            return None
        if arm:
            if not bool(getattr(self.config, "device_arm_enabled", False)):
                return None
            image = str(getattr(self.config, "device_arm_image", "") or "").strip()
            platform = str(getattr(self.config, "device_arm_platform", "") or "").strip()
            create_timeout = int(getattr(self.config, "device_arm_create_timeout_s", 900))
            prefix = ARM_CONTAINER_PREFIX
            label = "ARM64 redroid"
        else:
            image = str(getattr(self.config, "device_image", "") or "").strip()
            platform = ""
            create_timeout = int(getattr(self.config, "device_create_timeout_s", 120))
            prefix = X86_CONTAINER_PREFIX
            label = "x86 redroid"
        if not image:
            return None
        with _DEVICE_CREATE_LOCK:
            if cancel is not None and cancel.is_set():
                return None
            existing = [
                serial
                for serial in self._online_serials()
                if self._is_arm_serial(serial) == arm
            ]
            if existing:
                return existing[0]
            names = self._arm_container_names() if arm else self._x86_container_names()
            if len(names) >= max_containers:
                return None
            port = self._next_device_port()
            if port is None:
                return None
            name = f"{prefix}{port}"
            volume = f"{name}-data"
            args = [
                "run",
                "-d",
                "--name",
                name,
                "--privileged",
            ]
            if platform:
                args.extend(["--platform", platform])
            if arm:
                # Expose init's kernel log; without it ARM boot failures are
                # invisible because redroid logs nothing to docker logs.
                args.extend(["--device", "/dev/kmsg"])
            args.extend(
                [
                    "-p",
                    f"127.0.0.1:{port}:5555",
                    "-v",
                    "/dev/binderfs:/dev/binderfs",
                    "-v",
                    f"{volume}:/data",
                    image,
                    "androidboot.redroid_gpu_mode=guest",
                    "androidboot.use_memfd=1",
                ]
            )
            if emit is not None:
                try:
                    emit(
                        "device_creating",
                        f"creating {label} container {name}",
                        {"container": name, "image": image, "arch": arch, "port": port},
                    )
                except Exception:
                    pass
            result = self._docker(args, timeout=max(300, create_timeout))
            if result is None or result.returncode != 0:
                detail = ""
                if result is not None:
                    detail = (result.stderr or result.stdout or "").strip()[-500:]
                if emit is not None:
                    try:
                        emit(
                            "device_create_failed",
                            f"failed to start {label} container",
                            {"container": name, "arch": arch, "error": redact(detail)},
                        )
                    except Exception:
                        pass
                return None
            serial = f"127.0.0.1:{port}"
            wait_kwargs: dict[str, Any] = {}
            if cancel is not None:
                wait_kwargs["cancel"] = cancel
            if emit is not None:
                wait_kwargs["emit"] = emit
                wait_kwargs["label"] = label
            if not self._wait_for_device(serial, create_timeout, **wait_kwargs):
                self._docker(["rm", "-f", name], timeout=60)
                try:
                    self.database.delete_device(serial)
                except Exception:
                    pass
                if emit is not None:
                    try:
                        emit(
                            "device_create_failed",
                            f"{label} container did not finish booting",
                            {"container": name, "arch": arch, "timeout_s": create_timeout},
                        )
                    except Exception:
                        pass
                return None
            self.database.upsert_device(
                serial,
                name=f"redroid-arm-{port}" if arm else f"redroid-{port}",
                kind="redroid",
                address=serial,
                source="auto",
                seen=True,
                arch=arch,
            )
            self._remember_arch(serial, arch)
            if emit is not None:
                try:
                    emit(
                        "device_created",
                        f"{label} container is ready",
                        {"serial": serial, "container": name, "arch": arch},
                    )
                except Exception:
                    pass
            return serial

    def _ensure_arm_device(
        self,
        cancel: threading.Event | None = None,
        emit: Any = None,
    ) -> str | None:
        """Return an online ARM64 device, reusing containers when possible."""
        if not bool(getattr(self.config, "device_arm_enabled", False)):
            return None
        if cancel is not None and cancel.is_set():
            return None
        online = self._online_serials()
        for serial in online:
            if self._is_arm_serial(serial):
                return serial
        try:
            records = self.database.list_devices(include_hidden=True)
        except Exception:
            records = []
        for record in records:
            serial = str(record.get("serial") or "")
            if not serial or record.get("hidden") or not record.get("enabled", 1):
                continue
            if str(record.get("arch") or "") != ARM_ARCH:
                continue
            if not self._connect_device(serial):
                continue
            if self._wait_for_device(
                serial,
                int(getattr(self.config, "device_arm_create_timeout_s", 900)),
                cancel=cancel,
                emit=emit,
                label="ARM64 redroid",
            ):
                return serial
        # Reuse an existing auto-created ARM container (running or stopped)
        # before pulling/creating another one.
        result = self._docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=apu-redroid-arm-",
                "--format",
                "{{.Names}}|{{.Status}}",
            ],
            timeout=20,
        )
        if result is not None and result.returncode == 0:
            for line in (result.stdout or "").splitlines():
                name, _, status = line.strip().partition("|")
                if not name.startswith(ARM_CONTAINER_PREFIX):
                    continue
                suffix = name[len(ARM_CONTAINER_PREFIX):]
                if not suffix.isdigit():
                    continue
                port = int(suffix)
                serial = f"127.0.0.1:{port}"
                record = self.database.get_device(serial) or {}
                if record.get("hidden"):
                    continue
                if "Up" not in status:
                    start = self._docker(["start", name], timeout=120)
                    if start is None or start.returncode != 0:
                        continue
                if self._wait_for_device(
                    serial,
                    int(getattr(self.config, "device_arm_create_timeout_s", 900)),
                    cancel=cancel,
                    emit=emit,
                    label="ARM64 redroid",
                ):
                    self.database.upsert_device(
                        serial,
                        name=f"redroid-arm-{port}",
                        kind="redroid",
                        address=serial,
                        source="auto",
                        seen=True,
                        arch=ARM_ARCH,
                    )
                    self._remember_arch(serial, ARM_ARCH)
                    return serial
        return self._create_redroid(ARM_ARCH, cancel=cancel, emit=emit)

    def resolve_device(self, serial: str | None = None) -> str | None:
        """Resolve the auto/default device.

        Selection order: an explicitly requested serial, the configured serial
        if already online, any online device, then connect known network
        serials. If nothing is online, the optional ``APU_WEB_DEVICE_START_CMD``
        (for example ``docker start redroid``) is executed once and adb connect
        is retried for a short window. When still unavailable and
        ``APU_WEB_DEVICE_AUTO_CREATE=1``, a new redroid container is created.
        Returns ``None`` when provisioning fails.
        """
        requested = str(serial or "").strip()
        if requested:
            return self.canonical_serial(requested) or requested
        online = self._online_serials()
        preferred = str(self.config.serial or "").strip()
        if preferred and preferred in online:
            return preferred
        if online:
            return online[0]
        candidates: list[str] = []
        if preferred and ":" in preferred:
            candidates.append(preferred)
        try:
            for row in self.database.list_devices():
                item = str(row.get("serial") or "")
                if not item or item in candidates:
                    continue
                if row.get("enabled", 1) and ":" in item:
                    candidates.append(item)
        except Exception:
            pass
        candidates.sort(key=lambda item: 1 if self._is_arm_serial(item) else 0)
        for candidate in candidates:
            if self._connect_device(candidate):
                online = self._online_serials()
                if candidate in online:
                    return candidate
                if online:
                    return online[0]
        command = os.environ.get("APU_WEB_DEVICE_START_CMD", "").strip()
        if command:
            try:
                subprocess.run(shlex.split(command), timeout=90, capture_output=True)
            except Exception:
                pass
            for _ in range(10):
                time.sleep(3)
                for candidate in candidates:
                    if self._connect_device(candidate):
                        online = self._online_serials()
                        if candidate in online:
                            return candidate
                online = self._online_serials()
                if online:
                    return online[0]
        online = self._online_serials()
        if online:
            return online[0]
        return self._create_redroid()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        # Recover after a restart: no in-memory worker survived, so every
        # ``running`` job has a stale lease. Restore device mutations before
        # marking it failed (installed APKs are deliberately never uninstalled).
        self.recover_interrupted_jobs()
        queued, _ = self.database.list_jobs(status="queued", limit=10000)
        for job in queued:
            self.queue.put(job["id"])
        for index in range(self.config.workers):
            thread = threading.Thread(target=self._worker_loop, name=f"apu-worker-{index + 1}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def shutdown(self) -> None:
        self._stop.set()
        for _ in self._threads:
            self.queue.put(None)
        for thread in self._threads:
            thread.join(timeout=5)

    # ------------------------------------------------------------------ cleanup
    def _safety_cleanup(
        self,
        *,
        run_id: str | None,
        serial: str | None,
        options: dict[str, Any] | None = None,
        emit: Any = None,
        force: bool = False,
        lock_held: bool = False,
    ) -> dict[str, Any]:
        """Restore device mutations under the per-device lock.

        Returns a structured status; failures are never swallowed.  Cleanup
        only restores mutations/forwards/temp files -- it never uninstalls the
        target APK.
        """
        options = options or {}
        if not force and not bool(options.get("cleanup", True)):
            return cleanup_summary(
                {
                    "cleanup_status": "skipped",
                    "restored": [],
                    "failed": [],
                    "remaining_mutations": [],
                },
                message="cleanup disabled for this job",
            )
        if not run_id:
            return cleanup_summary(
                {
                    "cleanup_status": "skipped",
                    "restored": [],
                    "failed": [],
                    "remaining_mutations": [],
                },
                message="job has no run to clean",
            )
        run_dir = self.config.runs_dir / run_id
        if not run_dir.is_dir():
            # No run state means the engine never reached inspect_apk, so it
            # could not have applied run-tracked mutations.
            return cleanup_summary(
                {
                    "cleanup_status": "skipped",
                    "restored": [],
                    "failed": [],
                    "remaining_mutations": [],
                },
                message=f"run state is missing for {run_id}; nothing to restore",
            )
        pinned = serial
        if pinned and not lock_held:
            try:
                pinned = self.canonical_serial(pinned) or pinned
            except Exception:
                pinned = serial
        try:
            with (nullcontext() if lock_held else self.devices.acquire(pinned)):
                result = self.service.cleanup_run(
                    run_id,
                    serial=pinned,
                    delete_run=False,
                    prune_raw_dumps=bool(options.get("prune_raw", False)),
                )
            summary = cleanup_summary(result, message="cleanup completed")
        except Exception as exc:
            message = redact(str(exc))
            summary = cleanup_summary(None, message="cleanup failed: " + message)
            summary["cleanup_error"] = message
        if emit is not None:
            try:
                if summary.get("cleanup_incomplete"):
                    emit(
                        "cleanup_failed",
                        "device cleanup incomplete",
                        {
                            "run_id": run_id,
                            "serial": pinned,
                            "cleanup_status": summary.get("cleanup_status"),
                            "cleanup_error": summary.get("cleanup_error"),
                            "failed": summary.get("failed"),
                            "remaining_mutations": summary.get("remaining_mutations"),
                            "restored": summary.get("restored"),
                        },
                    )
                else:
                    emit(
                        "cleanup_completed",
                        "device cleanup completed",
                        {
                            "run_id": run_id,
                            "serial": pinned,
                            "cleanup_status": summary.get("cleanup_status"),
                            "restored": summary.get("restored"),
                        },
                    )
            except Exception:
                pass
        return summary

    @staticmethod
    def _apply_cleanup(result: EngineResult, summary: dict[str, Any]) -> EngineResult:
        """Attach cleanup status to an engine result and degrade on failure."""
        result.cleanup = summary
        result.cleanup_status = str(summary.get("cleanup_status") or "") or None
        result.cleanup_error = summary.get("cleanup_error")
        if not summary.get("cleanup_incomplete"):
            return result
        message = "device cleanup was incomplete: " + str(
            summary.get("cleanup_error") or summary.get("message") or "unknown error"
        )
        result.warnings = list(result.warnings or []) + [message]
        error = dict(result.error or {})
        error.update(
            {
                "cleanup_status": "incomplete",
                "cleanup_error": summary.get("cleanup_error") or summary.get("message"),
            }
        )
        if result.outcome == "success":
            result.outcome = "partial"
            error.setdefault("code", "cleanup_incomplete")
            # Keep an informative message even when the engine had no error.
            if error.get("code") == "cleanup_incomplete":
                error["message"] = "artifacts were recovered but device cleanup did not complete"
        result.error = error
        return result

    def _job_emitter(self, job_id: str, work_dir: Path) -> Any:
        def emit(kind: str, message: str = "", data: dict[str, Any] | None = None) -> None:
            payload = data or {}
            self.bus.publish(job_id, kind, message, payload)
            self._log(work_dir, kind, message, payload)

        return emit

    def cleanup_job(self, job_id: str) -> dict[str, Any]:
        """Manual cleanup endpoint implementation (shared WP-F contract).

        Runs under the device lock, restores reversible mutations, and degrades
        a previously ``succeeded`` job to ``partial`` when the restore fails.
        """
        job = self.database.get_job(job_id)
        if not job:
            raise KeyError(job_id)
        status = str(job.get("status") or "")
        if status in ("queued", "running"):
            raise ValueError("job is still running; cancel it and wait for it to finish before cleanup")
        run_id = job.get("run_id")
        work_dir = self.config.jobs_dir / job_id
        emit = self._job_emitter(job_id, work_dir)
        summary = self._safety_cleanup(
            run_id=run_id,
            serial=job.get("serial"),
            options=job.get("options") or {},
            emit=emit,
            force=True,
        )
        degraded = False
        cleanup_incomplete = bool(summary.get("cleanup_incomplete"))
        if (
            not cleanup_incomplete
            and status in ("succeeded", "partial")
            and run_id
            and not (self.config.runs_dir / run_id).is_dir()
        ):
            # A finished job without run state cannot prove the device was
            # restored; surface that instead of reporting a clean result.
            summary = cleanup_summary(
                None, message=f"run state is missing for {run_id}; cleanup could not be verified"
            )
            summary["cleanup_error"] = f"run directory is missing: {run_id}"
            cleanup_incomplete = True
        if status == "succeeded" and cleanup_incomplete:
            existing = job.get("error") if isinstance(job.get("error"), dict) else {}
            error = dict(existing)
            error.update(
                {
                    "code": "cleanup_incomplete",
                    "message": "artifacts were recovered but device cleanup did not complete",
                    "cleanup_status": "incomplete",
                    "cleanup_error": summary.get("cleanup_error") or summary.get("message"),
                }
            )
            self.database.update_job(
                job_id,
                status="partial",
                error_json=json.dumps(error, ensure_ascii=False),
            )
            degraded = True
            emit(
                "job_cleanup_degraded",
                "cleanup failure degraded the job to partial",
                {"cleanup_error": error.get("cleanup_error")},
            )
        result = {
            "ok": not cleanup_incomplete,
            "cleanup_incomplete": cleanup_incomplete,
            "message": str(summary.get("message") or ("cleanup incomplete" if cleanup_incomplete else "cleanup completed")),
            "restored": summary.get("restored") or [],
            "failed": summary.get("failed") or [],
            "remaining_mutations": summary.get("remaining_mutations") or [],
            "cleanup_status": summary.get("cleanup_status"),
            "cleanup_error": summary.get("cleanup_error"),
            "run_id": run_id,
            "serial": job.get("serial"),
            "degraded": degraded,
        }
        return result

    def recover_interrupted_jobs(self) -> list[dict[str, Any]]:
        """Fail jobs whose worker died with the previous process.

        At startup no in-memory worker/context survives, so every ``running``
        row has a stale lease.  Safety cleanup runs under the device lock;
        installed APKs are intentionally not uninstalled.
        """
        running, _ = self.database.list_jobs(status="running", limit=10000)
        recovered: list[dict[str, Any]] = []
        for job in running:
            job_id = str(job["id"])
            work_dir = self.config.jobs_dir / job_id
            emit = self._job_emitter(job_id, work_dir)
            live = False
            with self._context_guard:
                live = job_id in self._contexts
            if live:
                continue
            summary = self._safety_cleanup(
                run_id=job.get("run_id"),
                serial=job.get("serial"),
                options=job.get("options") or {},
                emit=emit,
            )
            error = {
                "code": "execution_failure",
                "message": "backend restarted while the job was running",
                "cleanup_status": summary.get("cleanup_status"),
            }
            if summary.get("cleanup_error"):
                error["cleanup_error"] = summary.get("cleanup_error")
            self.database.update_job(
                job_id,
                status="failed",
                stage="failed",
                finished_at=_now(),
                error_json=json.dumps(error, ensure_ascii=False),
            )
            self.bus.publish(
                job_id,
                "job_finished",
                "backend restarted while the job was running",
                {
                    "status": "failed",
                    "cleanup_status": summary.get("cleanup_status"),
                    "cleanup_error": summary.get("cleanup_error"),
                },
                "error" if summary.get("cleanup_incomplete") else "warning",
            )
            recovered.append(
                {
                    "job_id": job_id,
                    "run_id": job.get("run_id"),
                    "cleanup_status": summary.get("cleanup_status"),
                    "cleanup_incomplete": bool(summary.get("cleanup_incomplete")),
                }
            )
        return recovered

    def create_job(
        self,
        *,
        user_id: int,
        upload_id: str,
        engine: str,
        serial: str | None,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        engine = self.agents.canonical_engine(engine)
        if engine not in self.engines:
            raise ValueError(f"unknown engine: {engine}")
        # Single option schema (WP-D1).  Internal ``_``-prefixed keys added by
        # retries/ARM provisioning are preserved; every client-visible key is
        # validated strictly so direct callers cannot bypass the API schema.
        raw_options = dict(options or {})
        internal = {
            key: value
            for key, value in raw_options.items()
            if isinstance(key, str) and key.startswith("_")
        }
        public_options = {
            key: value
            for key, value in raw_options.items()
            if not (isinstance(key, str) and key.startswith("_"))
        }
        try:
            options = normalize_job_options(public_options, strict=True)
        except ValueError as exc:
            raise ValueError(f"invalid options: {exc}") from exc
        options.update(internal)
        want_arm = bool(options.get("arm_device"))
        auto_device = not bool(str(serial or "").strip())
        if auto_device:
            if want_arm:
                # Explicit ARM choice: use an already-online ARM device now;
                # otherwise the worker provisions one and reports progress.
                serial = self._online_arm_serial()
            else:
                serial = self.resolve_device()
                if not serial:
                    raise ValueError(
                        "no online device and auto-provisioning failed; start a device "
                        "or set APU_WEB_DEVICE_START_CMD"
                    )
        else:
            # The same redroid can appear as both emulator-5554 and
            # 127.0.0.1:5555; pin the preferred serial so the per-device lock
            # is shared with auto-selected jobs.
            serial = self.canonical_serial(serial) or serial
        if serial and not self.database.get_device(str(serial)):
            self.database.upsert_device(
                str(serial), name=str(serial), address=str(serial), source="auto"
            )
        # Internal marker: only auto-selected devices may be transparently
        # switched to the ARM fallback. A user-pinned serial is never changed.
        options["_auto_device"] = auto_device
        job_id = new_job_id()
        run_id = new_run_id()
        job = self.database.create_job(job_id, user_id, upload_id, engine, serial, options, run_id)
        (self.config.jobs_dir / job_id).mkdir(parents=True, exist_ok=True)
        self.queue.put(job_id)
        self.bus.publish(
            job_id,
            "job_queued",
            "job queued",
            {"engine": engine, "serial": serial, "run_id": run_id},
        )
        self.database.audit(user_id, "job.create", job_id, {"engine": engine, "serial": serial})
        return job

    def cancel_job(self, job_id: str, user_id: int, is_admin: bool = False) -> dict[str, Any]:
        job = self.database.get_job(job_id)
        if not job:
            raise KeyError(job_id)
        if not is_admin and int(job["user_id"]) != user_id:
            raise PermissionError("not allowed")
        self.database.update_job(job_id, cancel_requested=1)
        with self._context_guard:
            context = self._contexts.get(job_id)
        if context:
            context.cancel.set()
        if job["status"] == "queued":
            self.database.update_job(job_id, status="cancelled", stage="cancelled", finished_at=_now())
            self.bus.publish(job_id, "job_finished", "job cancelled before start", {"status": "cancelled"}, "warning")
        self.database.audit(user_id, "job.cancel", job_id)
        return self.database.get_job(job_id) or job

    def retry_job(self, job_id: str, user_id: int, is_admin: bool = False) -> dict[str, Any]:
        job = self.database.get_job(job_id)
        if not job:
            raise KeyError(job_id)
        if not is_admin and int(job["user_id"]) != user_id:
            raise PermissionError("not allowed")
        # Defense in depth: the API/chat already gate this, but a queued or
        # running retry would duplicate device work and a succeeded job already
        # has verified artifacts.
        status = str(job.get("status") or "")
        if status not in ("failed", "partial", "cancelled"):
            raise ValueError(
                f"job status is {status}; only failed, partial or cancelled jobs can be retried"
            )
        options = dict(job.get("options") or {})
        # Retrying an auto-device job should resolve a device again instead of
        # pinning a possibly dead serial. The ARM fallback then still applies.
        auto_device = bool(options.get("_auto_device"))
        return self.create_job(
            user_id=int(job["user_id"]),
            upload_id=job["upload_id"],
            engine=self.agents.canonical_engine(job["engine"]),
            serial=None if auto_device else job.get("serial"),
            options=options,
        )

    def delete_job(self, job_id: str) -> None:
        job = self.database.get_job(job_id)
        if not job:
            return
        self._remove_job_files(job)
        self.database.delete_job(job_id)

    def _remove_job_files(self, job: dict[str, Any]) -> None:
        """Remove the job workspace and its Agent run directory.

        Paths are rebuilt from the job row and checked against the configured
        roots so a malformed database value can never delete outside the data
        directory.
        """
        roots = (
            (self.config.jobs_dir, str(job.get("id") or "")),
            (self.config.runs_dir, str(job.get("run_id") or "")),
        )
        for root, name in roots:
            if not name or "/" in name or "\\" in name or name in (".", ".."):
                continue
            root = root.resolve()
            target = (root / name).resolve()
            if target.parent != root:
                continue
            try:
                shutil.rmtree(target, ignore_errors=True)
            except OSError:
                pass

    # ------------------------------------------------------------------ worker
    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job_id = self.queue.get(timeout=1)
            except queue.Empty:
                continue
            if job_id is None:
                self.queue.task_done()
                break
            try:
                self._process(job_id)
            except Exception as exc:  # pragma: no cover - defensive
                self._fail(job_id, {"code": "execution_failure", "message": redact(str(exc))})
            finally:
                self.queue.task_done()

    def _process(self, job_id: str) -> None:
        job = self.database.get_job(job_id)
        if not job:
            return
        if job.get("cancel_requested"):
            self.database.update_job(job_id, status="cancelled", stage="cancelled", finished_at=_now())
            self.bus.publish(job_id, "job_finished", "job cancelled", {"status": "cancelled"}, "warning")
            return
        upload = self.database.get_upload(job["upload_id"])
        if not upload:
            self._fail(job_id, {"code": "invalid_input", "message": "upload no longer exists"})
            return
        # Cancellation can arrive between the queue pop and this point.
        latest = self.database.get_job(job_id) or job
        if latest.get("cancel_requested"):
            self.database.update_job(job_id, status="cancelled", stage="cancelled", finished_at=_now())
            self.bus.publish(job_id, "job_finished", "job cancelled before start", {"status": "cancelled"}, "warning")
            return
        self.database.update_job(job_id, status="running", stage="starting", started_at=_now())
        work_dir = self.config.jobs_dir / job_id
        work_dir.mkdir(parents=True, exist_ok=True)
        cancel = threading.Event()
        run_id = job.get("run_id") or new_run_id()
        options = dict(job.get("options") or {})
        want_arm = bool(options.get("arm_device"))
        serial = job.get("serial") or (None if want_arm else self.config.serial)

        def emit(kind: str, message: str = "", data: dict[str, Any] | None = None) -> None:
            payload = data or {}
            self.bus.publish(job_id, kind, message, payload)
            if kind == "stage" and payload.get("stage"):
                self.database.update_job(job_id, stage=str(payload["stage"]), status="running")
            self._log(work_dir, kind, message, payload)

        emit("job_started", "job started", {"engine": job["engine"], "run_id": run_id, "serial": serial})
        canonical = self.canonical_serial(serial) if serial else serial
        if canonical and canonical != serial:
            emit(
                "device_selected",
                "merged duplicate adb transport into the primary serial",
                {"serial": canonical, "previous_serial": serial},
            )
            serial = canonical
            self.database.update_job(job_id, serial=serial)
        if want_arm and not self._is_arm_serial(serial):
            # User explicitly selected the ARM runtime. Re-read the cancel
            # flag before the long provisioning wait: cancellation can arrive
            # while canonical_serial()/arch probing holds no context yet.
            latest = self.database.get_job(job_id) or job
            if latest.get("cancel_requested"):
                cancel.set()
            # Register a minimal context so cancel_job can interrupt the slow
            # provisioning wait, then re-check to close the registration race.
            with self._context_guard:
                self._contexts[job_id] = SimpleNamespace(cancel=cancel)
            latest = self.database.get_job(job_id) or job
            if latest.get("cancel_requested"):
                cancel.set()
            emit("stage", "preparing ARM64 redroid runtime", {"stage": "arm_runtime"})
            arm_serial = self._ensure_arm_device(cancel=cancel, emit=emit)
            if not arm_serial:
                with self._context_guard:
                    self._contexts.pop(job_id, None)
                if cancel.is_set() or (self.database.get_job(job_id) or {}).get("cancel_requested"):
                    # Close the provisioning/cancel race: run safety cleanup
                    # even though the engine never started, then mark cancelled.
                    cleanup = self._safety_cleanup(
                        run_id=run_id,
                        serial=serial,
                        options=options,
                        emit=emit,
                    )
                    error = {
                        "code": "cancelled",
                        "message": "job cancelled while provisioning the device",
                        "cleanup_status": cleanup.get("cleanup_status"),
                    }
                    if cleanup.get("cleanup_error"):
                        error["cleanup_error"] = cleanup.get("cleanup_error")
                    self.database.update_job(
                        job_id,
                        status="cancelled",
                        stage="cancelled",
                        finished_at=_now(),
                        error_json=json.dumps(error, ensure_ascii=False),
                    )
                    self.bus.publish(
                        job_id,
                        "job_finished",
                        "job cancelled",
                        {
                            "status": "cancelled",
                            "cleanup_status": cleanup.get("cleanup_status"),
                            "cleanup_error": cleanup.get("cleanup_error"),
                        },
                        "warning" if not cleanup.get("cleanup_incomplete") else "error",
                    )
                else:
                    self._fail(
                        job_id,
                        {
                            "code": "arm_runtime_unavailable",
                            "message": "ARM64 redroid runtime could not be provisioned; "
                            "check APU_WEB_DEVICE_ARM_IMAGE and the QEMU binfmt registration",
                        },
                    )
                return
            serial = arm_serial
            self.database.update_job(job_id, serial=serial)
            emit(
                "device_selected",
                "using ARM64 redroid (slow runtime)",
                {"serial": serial, "arch": ARM_ARCH, "user_selected": True},
            )
        if self._is_arm_serial(serial):
            options = self._arm_runtime_options(options)
        context = JobContext(
            job_id=job_id,
            user_id=int(job["user_id"]),
            engine=job["engine"],
            upload_path=Path(upload["path"]),
            apk_name=upload["filename"],
            serial=serial,
            options=options,
            runs_dir=self.config.runs_dir,
            memory_dir=self.config.memory_dir,
            work_dir=work_dir,
            cancel=cancel,
            emit=emit,
            service=self.service,
            run_id=run_id,
            config=self.config,
        )
        with self._context_guard:
            self._contexts[job_id] = context
        # Re-check after registering the context: cancel_job may have arrived
        # while the worker was between the queued and running states.
        latest = self.database.get_job(job_id) or job
        if latest.get("cancel_requested"):
            cancel.set()
        engine_name = self.agents.canonical_engine(job["engine"])
        engine = self.engines.get(engine_name) or self.engines.get(job["engine"])
        if engine is None:
            with self._context_guard:
                self._contexts.pop(job_id, None)
            self._fail(
                job_id,
                {"code": "unsupported_provider", "message": f"engine is no longer configured: {job['engine']}"},
            )
            return
        auto_device = bool((context.options or {}).get("_auto_device"))
        result: EngineResult
        cleanup_failures: list[str] = []
        previous_attempt: tuple[EngineResult, JobContext] | None = None

        def finish_attempt(current: EngineResult) -> EngineResult:
            """Assess the produced DEX and restore device mutations."""
            self._cleanup_target_app(context, emit)
            guarded = self._guard_outcome(current, context, emit)
            cleanup = self._safety_cleanup(
                run_id=context.run_id,
                serial=context.serial,
                options=context.options,
                emit=emit,
                lock_held=True,
            )
            guarded = self._apply_cleanup(guarded, cleanup)
            if cleanup.get("cleanup_incomplete"):
                cleanup_failures.append(
                    f"{context.run_id} ({context.serial}): "
                    + str(cleanup.get("cleanup_error") or cleanup.get("message") or "cleanup incomplete")
                )
            return guarded

        try:
            result = self._run_engine_attempt(engine, context, job, finish=finish_attempt)
            fallback_reason = self._arm_fallback_reason(result, context, auto_device)
            if fallback_reason and not cancel.is_set():
                emit(
                    "device_fallback_requested",
                    "preparing an ARM64 retry for incomplete x86 recovery",
                    {
                        "reason": fallback_reason,
                        "from_serial": context.serial,
                        "outcome": result.outcome,
                        "error": result.error,
                    },
                )
                # Keep the completed attempt even if provisioning itself raises.
                previous_attempt = (result, context)
                arm_serial = self._ensure_arm_device(cancel=cancel, emit=emit)
                if arm_serial and not cancel.is_set():
                    previous_run_id = context.run_id
                    fallback_run_id = new_run_id()
                    context = replace(
                        context,
                        serial=arm_serial,
                        run_id=fallback_run_id,
                        cleanup_called=False,
                        cleanup_result=None,
                        static_dex_repair=None,
                        last_stage="arm_fallback",
                        options=self._arm_runtime_options(
                            {**(context.options or {}), "_arm_fallback": True}
                        ),
                    )
                    with self._context_guard:
                        self._contexts[job_id] = context
                    self.database.update_job(job_id, serial=arm_serial, run_id=fallback_run_id)
                    emit(
                        "device_fallback",
                        "retrying unpack on ARM64 redroid (slower, native ARM runtime)",
                        {
                            "from_serial": serial,
                            "to_serial": arm_serial,
                            "arch": ARM_ARCH,
                            "previous_run_id": previous_run_id,
                            "run_id": fallback_run_id,
                            "reason": fallback_reason,
                        },
                    )
                    result = self._run_engine_attempt(engine, context, job, finish=finish_attempt)
                    note = (
                        "x86 attempt required a retry "
                        f"({fallback_reason}); retried on ARM64 redroid {arm_serial}"
                    )
                    result.warnings = [note, *(result.warnings or [])]
                else:
                    emit(
                        "device_fallback_failed",
                        "ARM64 fallback runtime is unavailable",
                        {"reason": fallback_reason, "cancelled": cancel.is_set()},
                    )
                    if not cancel.is_set():
                        result.warnings = [
                            *(result.warnings or []),
                            "ARM64 fallback was requested but no ARM64 redroid runtime could be provisioned",
                        ]
        except Exception as exc:
            result = EngineResult(
                "failed",
                run_id=context.run_id,
                error={"code": "execution_failure", "message": redact(str(exc))},
            )
            try:
                cleanup = self._safety_cleanup(
                    run_id=context.run_id,
                    serial=context.serial,
                    options=context.options,
                    emit=emit,
                )
                result = self._apply_cleanup(result, cleanup)
            except Exception as cleanup_exc:  # pragma: no cover - defensive
                result.warnings = [*(result.warnings or []), f"cleanup failed: {redact(str(cleanup_exc))}"]
        finally:
            with self._context_guard:
                self._contexts.pop(job_id, None)
        if result.cleanup_status == "incomplete":
            # Also cover exceptions raised by an attempt's finalizer.
            failure = f"{context.run_id} ({context.serial}): {result.cleanup_error or 'cleanup incomplete'}"
            if failure not in cleanup_failures:
                cleanup_failures.append(failure)
        if previous_attempt is not None and result is not previous_attempt[0]:
            result, context = self._select_fallback_result(previous_attempt, (result, context), emit)
        # A cancel that raced with the last tool call/cleanup must still be
        # observed before the terminal status is written.
        latest = self.database.get_job(job_id) or job
        if latest.get("cancel_requested"):
            cancel.set()
        if cancel.is_set() and result.outcome not in ("success", "partial"):
            result.outcome = "cancelled"
        elif cancel.is_set():
            result.warnings = list(result.warnings or []) + [
                "cancel was requested after the job produced artifacts"
            ]
        if cleanup_failures:
            result.warnings = list(result.warnings or []) + [
                f"cleanup failed on an earlier attempt: {item}" for item in cleanup_failures
            ]
            if result.cleanup_status != "incomplete":
                # Choosing another run's artifacts must not hide a failed restore.
                result = self._apply_cleanup(result, {
                    "cleanup_status": "incomplete",
                    "cleanup_incomplete": True,
                    "cleanup_error": "; ".join(cleanup_failures),
                })
        if result.cleanup_status == "incomplete" and result.outcome == "success":  # pragma: no cover - defensive
            result.outcome = "partial"
        result = self._complete_source_assets(result, context, emit)
        final_run_id = result.run_id or context.run_id
        artifacts = build_artifacts(
            self.config,
            job_id,
            final_run_id,
            Path(upload["path"]),
            work_dir,
        )
        lesson = record_job_lesson(
            self.service.lessons,
            job=self.database.get_job(job_id) or job,
            result=result,
            run_id=final_run_id,
            run_dir=self.config.runs_dir / final_run_id,
            emit=emit,
        )
        lesson_summary = (
            {
                "lesson_id": lesson.get("lesson_id"),
                "title": lesson.get("title"),
                "occurrences": lesson.get("occurrences"),
                "winning_method": lesson.get("winning_method"),
            }
            if lesson
            else None
        )
        status = {
            "success": "succeeded",
            "partial": "partial",
            "cancelled": "cancelled",
            "failed": "failed",
        }.get(result.outcome, "failed")
        error_payload: dict[str, Any] | None = None
        if isinstance(result.error, dict):
            error_payload = dict(result.error)
        elif result.error:
            error_payload = {"code": "execution_failure", "message": str(result.error)}
        # Cleanup status is part of the persisted result.  Server/UI exposure:
        # the DB row currently has no cleanup columns (see WP-F report), so the
        # fields live inside ``error`` for succeeded->partial degradations and
        # every non-success terminal job.
        if result.cleanup_status and (error_payload is not None or result.cleanup_status == "incomplete"):
            if error_payload is None:
                error_payload = {
                    "code": "cleanup_incomplete",
                    "message": "artifacts were recovered but device cleanup did not complete",
                }
            error_payload.setdefault("cleanup_status", result.cleanup_status)
            if result.cleanup_error:
                error_payload.setdefault("cleanup_error", result.cleanup_error)
        self.database.update_job(
            job_id,
            status=status,
            stage="done" if status in ("succeeded", "partial") else status,
            run_id=final_run_id,
            serial=context.serial,
            finished_at=_now(),
            error_json=json.dumps(error_payload, ensure_ascii=False) if error_payload else None,
            dex_zip=artifacts.get("dex_zip"),
            source_zip=artifacts.get("source_zip"),
            evidence_zip=artifacts.get("evidence_zip"),
            logs_zip=artifacts.get("logs_zip"),
            full_zip=artifacts.get("full_zip"),
        )
        emit(
            "job_finished",
            result.summary or status,
            {
                "status": status,
                "outcome": result.outcome,
                "run_id": final_run_id,
                "error": error_payload,
                "warnings": result.warnings,
                "artifacts": artifacts,
                "usage": result.usage,
                "lesson": lesson_summary,
                "cleanup_status": result.cleanup_status,
                "cleanup_error": result.cleanup_error,
            },
        )

    @staticmethod
    def _run_state(run_dir: Path) -> dict[str, Any]:
        return read_run_state(run_dir)

    @staticmethod
    def _run_inspection(state: dict[str, Any]) -> dict[str, Any]:
        for container in (state.get("artifacts") or {}, state):
            if isinstance(container, dict) and isinstance(container.get("inspection"), dict):
                return container["inspection"]
        return {}

    @staticmethod
    def _dynamic_dump_method(state: dict[str, Any]) -> str | None:
        for container in (state.get("artifacts") or {}, state):
            if not isinstance(container, dict):
                continue
            last_dump = container.get("last_dump")
            if isinstance(last_dump, dict):
                method = str(last_dump.get("method") or "")
                if method and not method.startswith("static"):
                    return method
            attempts = container.get("attempts")
            if isinstance(attempts, list):
                for attempt in attempts:
                    if not isinstance(attempt, dict) or attempt.get("status") != "succeeded":
                        continue
                    method = str(attempt.get("method") or "")
                    if method and not method.startswith("static"):
                        return method
        return None

    def _complete_source_assets(self, result: EngineResult, ctx: JobContext, emit: Any) -> EngineResult:
        """Include business assets even when an LLM only requested DEX/JADX tools."""
        run_id = result.run_id or ctx.run_id
        run_dir = ctx.runs_dir / run_id
        if not ctx.options.get("jadx", True) or ctx.cancel.is_set() or not (run_dir / "run.json").is_file():
            return result
        extraction = (self._run_state(run_dir).get("artifacts") or {}).get("asset_extraction") or {}
        assets_dir = (run_dir / "assets").resolve()
        if (extraction.get("all_assets") and extraction.get("coverage") == "complete"
                and Path(str(extraction.get("output_dir") or "")).resolve() == assets_dir
                and assets_dir.is_dir()):
            return result
        try:
            payload = self.service.call_tool("extract_apk_assets", {
                "apk_path": str(ctx.upload_path), "run_id": run_id, "overwrite": True,
            })
            extraction = payload.get("extraction") or {}
            if not extraction or extraction.get("skipped") or extraction.get("coverage") == "partial":
                raise ValueError("asset extraction did not recover every selected file")
            emit("assets_finalized", "business assets included in source output", {"files":len(extraction.get("files") or [])})
        except Exception as exc:
            message = "APK asset extraction incomplete: " + redact(str(exc))
            result.warnings = [*(result.warnings or []), message]
            emit("assets_incomplete", message, {"skipped":extraction.get("skipped") or []})
            if result.outcome == "success":
                result.outcome = "partial"
                result.error = {"code":"assets_incomplete", "message":message}
        return result

    def _guard_outcome(self, result: EngineResult, ctx: JobContext, emit: Any) -> EngineResult:
        """Require a verified target DEX before a job can be ``succeeded``.

        Structural self-consistency alone is not enough: the repaired DEX must
        pass the shared WP-A assessment and (when the package is known) contain
        classes from the target package.  Static extraction of classes*.dex is
        the whole answer only for an unpacked APK; for a packed APK the top-level
        DEX is a loader, so ``packed_static_only`` stays ``partial``.
        """
        if result.outcome != "success":
            return result
        state = self._run_state(ctx.run_dir)
        package = run_expected_package(ctx.run_dir)
        verdict = assess_fixed_dex(
            ctx.run_dir,
            package or None,
            apk_path=getattr(ctx, "upload_path", None),
        )
        inspection = self._run_inspection(state)
        packing = inspection.get("packing") or {}
        packed = packing.get("packed")
        suspicious_application = bool(packing.get("application_class_suspicious"))
        suspicious_dex = any(
            item.get("packed_stub")
            for item in (inspection.get("dex_entries") or [])
            if isinstance(item, dict)
        )
        dynamic = self._dynamic_dump_method(state)
        if not dynamic and (packed is True or suspicious_application or suspicious_dex):
            display = str(packing.get("display") or packing.get("primary") or "unknown")
            message = (
                f"APK is packed ({display}); the static classes*.dex is a shell loader, "
                "not the real application. Runtime dumping or a compatible device is required."
            )
            result.outcome = "partial"
            result.error = {
                "code": "packed_static_only",
                "message": message,
                "reasons": ["packed_static_only", *(verdict.get("reasons") or [])],
                "expected_package": package or None,
            }
            result.warnings = list(result.warnings or []) + [message]
            emit(
                "unpack_outcome_guard",
                message,
                {
                    "code": "packed_static_only",
                    "shell": packing.get("primary"),
                    "packed": packed,
                    "suspicious_application": suspicious_application,
                    "suspicious_dex": suspicious_dex,
                    "dex_reasons": verdict.get("reasons"),
                },
            )
            return result
        if verdict["verified"]:
            return result
        reasons = list(verdict.get("reasons") or ["unverified"])
        code = str(verdict.get("code") or "unverified")
        if verdict["repaired_unverified"]:
            # Structurally complete, but repaired from a checksum/signature-
            # damaged raw dump and not content-matching the APK source (F1).
            code = "repaired_unverified"
            if "repaired_unverified" not in reasons:
                reasons.insert(0, "repaired_unverified")
            message = (
                "recovered DEX was repaired from an integrity-damaged dump and does "
                "not match the APK source; keeping it as partial output "
                f"({', '.join(reasons)})"
            )
        else:
            message = (
                "no complete DEX containing the target package was produced "
                f"({', '.join(reasons)}); recovered files are kept for inspection"
            )
        result.outcome = "partial"
        result.error = {
            "code": code,
            "message": message,
            "reasons": reasons,
            "expected_package": package or None,
        }
        result.warnings = list(result.warnings or []) + [message]
        emit(
            "unpack_outcome_guard",
            message,
            {
                "code": code,
                "reasons": reasons,
                "expected_package": package or None,
                "dynamic_method": dynamic,
                "files": [
                    {
                        "path": item.get("path"),
                        "complete": item.get("complete"),
                        "class_defs": item.get("class_defs"),
                        "classes_with_code": item.get("classes_with_code"),
                        "package_classes": item.get("package_classes"),
                        "truncated": item.get("truncated"),
                        "stub_like": item.get("stub_like"),
                        "holes": item.get("holes"),
                        "source_verified": item.get("source_verified"),
                        "repaired_unverified": item.get("repaired_unverified"),
                        "verified": item.get("verified"),
                    }
                    for item in verdict.get("files") or []
                ],
            },
        )
        return result

    def _run_engine_attempt(self, engine: Any, ctx: JobContext, job: dict[str, Any], *, finish: Any = None) -> EngineResult:
        """Keep the device lease through execution, target stop and restoration."""
        if ctx.cancel.is_set():
            return EngineResult("cancelled", run_id=ctx.run_id, summary="cancelled by user")
        with self.devices.acquire(ctx.serial):
            latest = self.database.get_job(str(job["id"])) or job
            if latest.get("cancel_requested"):
                ctx.cancel.set()
            if ctx.cancel.is_set():
                return EngineResult("cancelled", run_id=ctx.run_id, summary="cancelled by user")
            try:
                result = engine.run(ctx)
            except Exception as exc:
                result = EngineResult(
                    "failed",
                    run_id=ctx.run_id,
                    error={"code": "execution_failure", "message": redact(str(exc))},
                )
            return finish(result) if finish else result

    @staticmethod
    def _run_attempts(state: dict[str, Any]) -> list[dict[str, Any]]:
        for container in (state, state.get("artifacts") or {}):
            if isinstance(container, dict) and isinstance(container.get("attempts"), list):
                return [item for item in container["attempts"] if isinstance(item, dict)]
        return []

    @staticmethod
    def _packed_flags(state: dict[str, Any]) -> tuple[bool, bool]:
        inspection = JobManager._run_inspection(state)
        packing = inspection.get("packing") or {}
        packed = packing.get("packed") is True or bool(packing.get("application_class_suspicious"))
        suspicious_dex = any(
            item.get("packed_stub")
            for item in (inspection.get("dex_entries") or [])
            if isinstance(item, dict)
        )
        return packed, suspicious_dex

    def _fallback_output_quality(self, ctx: JobContext) -> tuple[int, ...]:
        """Compare assessed target bytecode, never shell/static-only output.

        Complete verification takes precedence, then target coverage and coded
        classes. Ties keep the earlier run. Partial output remains partial.
        """
        state = self._run_state(ctx.run_dir)
        if any(self._packed_flags(state)) and not self._dynamic_dump_method(state):
            return (0, 0, 0, 0, 0)
        verdict = assess_fixed_dex(
            ctx.run_dir, run_expected_package(ctx.run_dir) or None,
            apk_path=getattr(ctx, "upload_path", None),
        )
        files = {
            item.get("content_hash") or item["path"]: item
            for item in verdict["files"] if item.get("recoverable") or item.get("complete")
        }.values()
        files = list(files)
        return (
            2 if verdict["verified"] else 1 if files else 0,
            sum(item["package_classes"] for item in files),
            sum(item["classes_with_code"] for item in files),
            -sum(item["holes"] for item in files),
            sum(1 for path in (ctx.run_dir / "dexdump/jadx").glob("**/sources/**/*.java") if path.is_file()),
        )

    def _select_fallback_result(
        self, previous: tuple[EngineResult, JobContext], current: tuple[EngineResult, JobContext], emit: Any,
    ) -> tuple[EngineResult, JobContext]:
        """Keep the better run and expose both attempts, including cleanup."""
        before, before_ctx = previous
        after, after_ctx = current
        before_quality = self._fallback_output_quality(before_ctx)
        after_quality = self._fallback_output_quality(after_ctx)
        retain = (
            before.outcome in ("success", "partial") and before_quality[0] > 0
            and (after.outcome not in ("success", "partial") or before_quality >= after_quality)
        )
        selected = previous if retain else current
        result, ctx = selected
        attempts = [
            {"run_id": item_ctx.run_id, "serial": item_ctx.serial, "outcome": item.outcome,
             "error": item.error, "cleanup_status": item.cleanup_status,
             "cleanup_error": item.cleanup_error, "quality": list(quality)}
            for (item, item_ctx), quality in ((previous, before_quality), (current, after_quality))
        ]
        message = (
            "ARM64 retry did not improve recovered output; retained the earlier run and its downloads"
            if retain else "selected ARM64 retry output; earlier attempt remains available for diagnostics"
        )
        result.warnings = [*(before.warnings or []), *(after.warnings or []), message]
        if result.error is not None:
            result.error = {**result.error, "runtime_attempts": attempts}
        emit("device_fallback_result", message, {"selected_run_id": ctx.run_id, "attempts": attempts})
        return selected

    def _arm_fallback_reason(
        self,
        result: EngineResult,
        ctx: JobContext,
        auto_device: bool,
    ) -> str:
        """Decide whether the failed x86 attempt deserves an ARM64 retry.

        Only automatically selected devices are switched. A user-pinned serial
        is never overridden. The retry is limited to one ARM attempt per job.
        """
        if not auto_device or not ctx.serial or ctx.cancel.is_set():
            return ""
        if not bool(getattr(self.config, "device_arm_enabled", False)):
            return ""
        if not bool(getattr(self.config, "device_arm_fallback", False)):
            return ""
        if (ctx.options or {}).get("_arm_fallback"):
            return ""
        if result.outcome not in ("partial", "failed"):
            return ""
        code = str((result.error or {}).get("code") or "")
        if code in NON_FALLBACK_ERROR_CODES or result.cleanup_status == "incomplete":
            return ""
        if self._is_arm_serial(ctx.serial):
            return ""
        state = self._run_state(ctx.run_dir)
        abis = self._run_inspection(state).get("abis") or []
        # The ARM fallback image is 64-bit only. Pure Java APKs have no ABI list.
        if abis and "arm64-v8a" not in abis:
            return ""
        if code.startswith("jadx_") and assess_fixed_dex(
            ctx.run_dir, run_expected_package(ctx.run_dir) or None,
            apk_path=getattr(ctx, "upload_path", None),
        )["verified"]:
            return ""
        attempts = self._run_attempts(state)
        failed_attempts = [
            item
            for item in attempts
            if item.get("status") not in ("succeeded", "success")
            and not str(item.get("method") or "").startswith("static")
        ]
        packed, suspicious_dex = self._packed_flags(state)
        dynamic_method = self._dynamic_dump_method(state)
        # A packed APK whose static DEX is only the shell loader has no real
        # recovery yet; the native ARM runtime is the most promising retry.
        if (packed or suspicious_dex) and not dynamic_method:
            return code or "packed_static_only"
        if failed_attempts:
            error = failed_attempts[-1].get("error") or {}
            return str(error.get("code") or "dynamic_dump_failed")
        blob = json.dumps(
            {"error": result.error, "attempts": attempts},
            ensure_ascii=False,
            default=str,
        ).lower()
        if any(hint in blob for hint in DEVICE_FAILURE_HINTS):
            return code or "device_runtime_failure"
        # A tool-driven failure with evidence is worth one slower retry; a
        # provider/infrastructure failure without evidence is not.
        if result.outcome == "failed" and attempts:
            return code or "execution_failure"
        return ""

    def _cleanup_target_app(self, ctx: JobContext, emit: Any) -> None:
        """Stop the target app after a job.

        Packer-spawned app_process64 children can survive am force-stop and
        keep several cores busy. Killing matching PIDs after the job keeps the
        shared redroid device usable for the next unpack.
        """
        if not ctx.options.get("cleanup", True) or not ctx.serial:
            return
        state = self._run_state(ctx.run_dir)
        inspection = self._run_inspection(state)
        package = str((inspection.get("package") or {}).get("name") or state.get("package") or "").strip()
        if not re.match(r"^[A-Za-z0-9_.]+$", package):
            return
        try:
            self.service.adb.shell(ctx.serial, f"am force-stop {shlex.quote(package)}", timeout=30)
            result = self.service.adb.shell(
                ctx.serial,
                f"ps -A -o PID,ARGS | grep -F {shlex.quote(package)} | grep -v grep",
                timeout=20,
            )
            pids: list[int] = []
            for line in (result.stdout or "").splitlines():
                token = line.strip().split(None, 1)[0] if line.strip() else ""
                if token.isdigit():
                    pids.append(int(token))
            for pid in pids[:64]:
                self.service.adb.shell(ctx.serial, f"kill -9 {pid}", timeout=10)
            emit(
                "cleanup.target_stopped",
                f"stopped {package} on device",
                {"package": package, "killed": len(pids)},
            )
        except Exception as exc:
            emit(
                "cleanup.target_stop_failed",
                "target process cleanup failed",
                {"package": package, "error": redact(str(exc))[:500]},
            )

    def _fail(self, job_id: str, error: dict[str, Any]) -> None:
        self.database.update_job(
            job_id,
            status="failed",
            stage="failed",
            finished_at=_now(),
            error_json=json.dumps(error, ensure_ascii=False),
        )
        self.bus.publish(job_id, "job_finished", "job failed", {"status": "failed", "error": error}, "error")

    def _log(self, work_dir: Path, kind: str, message: str, data: dict[str, Any]) -> None:
        try:
            line = json.dumps(
                {"ts": _now(), "kind": kind, "message": redact(message), "data": _redact_data(data)},
                ensure_ascii=False,
            )
            with self._log_lock, open(work_dir / "job.log", "a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
        except OSError:
            pass


def _redact_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_data(item) for item in value[:50]]
    if isinstance(value, str):
        return redact(value)[:4000]
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _add(zip_handle: zipfile.ZipFile, path: Path, arcname: str | None = None) -> None:
    if not path.is_file():
        return
    try:
        zip_handle.write(path, arcname or path.name)
    except OSError:
        pass


def _add_tree(zip_handle: zipfile.ZipFile, root: Path, prefix: str = "") -> None:
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if path.is_file():
            try:
                zip_handle.write(path, str(Path(prefix) / path.relative_to(root)))
            except OSError:
                pass


def build_artifacts(
    config: BackendConfig,
    job_id: str,
    run_id: str | None,
    upload_path: Path,
    work_dir: Path,
) -> dict[str, str]:
    job_dir = config.jobs_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, str] = {}
    run_dir = config.runs_dir / run_id if run_id else None
    fixed = list((run_dir / "dexdump" / "fixed").glob("*.dex")) if run_dir else []
    raw = list((run_dir / "dexdump" / "raw").glob("*.dex")) if run_dir else []
    dex_files = fixed or raw
    if dex_files:
        dex_zip = job_dir / "dex.zip"
        with zipfile.ZipFile(dex_zip, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in dex_files:
                _add(archive, path, path.name)
            if run_dir:
                summary = run_dir / "run.json"
                if summary.is_file():
                    _add(archive, summary, "run.json")
                verification = run_dir / "dexdump" / "fixed" / "manifest.json"
                _add(archive, verification, "manifest.json")
            archive.writestr(
                "PROVENANCE.txt",
                f"job_id={job_id}\nrun_id={run_id}\nfile_count={len(dex_files)}\n",
            )
        result["dex_zip"] = str(dex_zip)
    state = JobManager._run_state(run_dir) if run_dir else {}
    decompilation = (state.get("artifacts") or {}).get("decompilation") or {}
    sources = None
    if run_dir:
        declared = decompilation.get("output_dir")
        if declared:
            candidate = (Path(declared) / "sources").resolve()
            if candidate.is_relative_to((run_dir / "dexdump/jadx").resolve()) and candidate.is_dir():
                sources = candidate
        else:
            # Compatibility with runs saved before the output path was recorded.
            candidates = [path for path in run_dir.glob("dexdump/jadx/**/sources") if path.is_dir()]
            if candidates:
                sources = max(candidates, key=lambda path: sum(1 for _ in path.rglob("*.java")))
    assets = run_dir / "assets" if run_dir else None
    has_assets = bool(assets and assets.is_dir() and any(path.is_file() for path in assets.rglob("*")))
    if sources is not None or has_assets:
        source_zip = job_dir / "source.zip"
        with zipfile.ZipFile(source_zip, "w", zipfile.ZIP_DEFLATED) as archive:
            if sources is not None:
                _add_tree(archive, sources)
                _add_tree(archive, sources.parent / "resources", "resources")
            if has_assets:
                _add_tree(archive, assets)
            fallback_path = (decompilation.get("fallback") or {}).get("output_dir")
            if fallback_path and run_dir:
                fallback_root = Path(fallback_path).resolve()
                if fallback_root.is_relative_to((run_dir / "dexdump/jadx").resolve()):
                    _add_tree(archive, fallback_root, "recovery/fallback")
            inspection = JobManager._run_inspection(state)
            archive.writestr("SOURCE_REPORT.json", json.dumps({
                "job_id": job_id, "run_id": run_id,
                "decompilation": decompilation,
                "asset_extraction": (state.get("artifacts") or {}).get("asset_extraction") or {},
                "packed_apk": (inspection.get("packing") or {}).get("packed"),
                "dex_assessment": assess_fixed_dex(run_dir, run_expected_package(run_dir), apk_path=upload_path),
                "assets_included": has_assets,
                "limitations": ["Decompiled files are not the original source project. DEX validation does not prove full application coverage."],
            }, ensure_ascii=False, indent=2))
            archive.writestr("PROVENANCE.txt", f"job_id={job_id}\nrun_id={run_id}\nsource_root={sources}\nassets_root={assets if has_assets else ''}\nSee SOURCE_REPORT.json for recovery and decompilation quality.\n")
        result["source_zip"] = str(source_zip)
    evidence_zip = job_dir / "evidence.zip"
    if run_dir and run_dir.is_dir():
        bundle: list[dict[str, Any]] = []
        evidence_path = run_dir / "evidence.jsonl"
        if evidence_path.is_file():
            for line in evidence_path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    bundle.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        with zipfile.ZipFile(evidence_zip, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in ("run.json", "evidence.jsonl", "events.jsonl", "mutations.json"):
                _add(archive, run_dir / name, name)
            archive.writestr("evidence-bundle.json", json.dumps(bundle, ensure_ascii=False, indent=2))
        result["evidence_zip"] = str(evidence_zip)
    logs_zip = job_dir / "logs.zip"
    with zipfile.ZipFile(logs_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("job.log", "agent.log", "transcript.jsonl"):
            _add(archive, work_dir / name, name)
    result["logs_zip"] = str(logs_zip)
    full_zip = job_dir / "full.zip"
    with zipfile.ZipFile(full_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        _add(archive, upload_path, f"original/{upload_path.name}")
        for key in ("dex_zip", "source_zip", "evidence_zip", "logs_zip"):
            path = result.get(key)
            if path:
                _add(archive, Path(path), Path(path).name)
    result["full_zip"] = str(full_zip)
    return result
