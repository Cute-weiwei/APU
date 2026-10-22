from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = REPO_ROOT.parent
DEFAULT_JADX_TIMEOUT_S = 3600


def default_jadx_timeout_s() -> int:
    """One default for CLI, MCP, and web jobs; zero means use the built-in default."""
    value = int(os.environ.get("APU_JADX_TIMEOUT_S", "0"))
    if value < 0:
        raise ValueError("APU_JADX_TIMEOUT_S must not be negative")
    return value or DEFAULT_JADX_TIMEOUT_S


def default_jadx_threads() -> int:
    """Bound concurrent reconstruction to keep large APKs within the Java heap."""
    value = int(os.environ.get("APU_JADX_THREADS", "1"))
    if not 1 <= value <= 64:
        raise ValueError("APU_JADX_THREADS must be between 1 and 64")
    return value


def default_jadx_heap_mb() -> int:
    """Keep the default bounded regardless of input size; deployments may override."""
    value = int(os.environ.get("APU_JADX_HEAP_MB", "0"))
    if value and not 256 <= value <= 65536:
        raise ValueError("APU_JADX_HEAP_MB must be 0 (default) or between 256 and 65536")
    return value or 4096


def _env_command(name: str) -> list[str] | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    if os.name == "nt":
        # A bare Windows path may contain spaces; only split when it clearly
        # contains additional arguments.
        candidate = Path(raw)
        if candidate.exists():
            return [raw]
    parts = shlex.split(raw, posix=(os.name != "nt"))
    return parts or None


def _first_existing(paths: list[str | Path]) -> str | None:
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


def _which(name: str) -> str | None:
    found = shutil.which(name)
    return found


def default_runs_dir() -> Path:
    explicit = os.environ.get("APU_RUNS_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    home = os.environ.get("APU_HOME", "").strip()
    if home:
        return Path(home).expanduser() / "runs"
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "apk-unpack" / "runs"
    return Path.home() / ".local" / "share" / "apk-unpack" / "runs"


def default_memory_dir() -> Path:
    explicit = os.environ.get("APU_MEMORY_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    home = os.environ.get("APU_HOME", "").strip()
    if home:
        return Path(home).expanduser() / "memory"
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "apk-unpack" / "memory"
    return Path.home() / ".local" / "share" / "apk-unpack" / "memory"


def _nox_aapt_candidates() -> list[str]:
    return [
        r"C:\Program Files (x86)\Nox\bin\aapt.exe",
        r"C:\Program Files\Nox\bin\aapt.exe",
    ]


def _jadx_jar_candidates() -> list[Path]:
    return [
        WORKSPACE_ROOT / "jadx" / "lib" / "jadx-gui-1.5.5-all.jar",
        REPO_ROOT / "vendor" / "jadx" / "jadx-gui-1.5.5-all.jar",
    ]


def _java_candidates() -> list[str | Path]:
    bundle = WORKSPACE_ROOT / "jadx" / "jre" / "bin" / ("java.exe" if os.name == "nt" else "java")
    return [
        os.environ.get("JAVA_HOME", "") and str(Path(os.environ["JAVA_HOME"]) / "bin" / ("java.exe" if os.name == "nt" else "java")),
        str(bundle),
    ]


@dataclass
class Config:
    runs_dir: Path = field(default_factory=default_runs_dir)
    memory_dir: Path = field(default_factory=default_memory_dir)
    adb: list[str] = field(default_factory=lambda: _env_command("APU_ADB") or ["adb"])
    frida: list[str] = field(default_factory=lambda: _env_command("APU_FRIDA") or ["frida"])
    frida_ps: list[str] = field(default_factory=lambda: _env_command("APU_FRIDA_PS") or ["frida-ps"])
    aapt: str | None = None
    java: str | None = None
    jadx_jar: str | None = None
    frida_server: str | None = None
    # Backward-compatible default host. Per-device callers should use
    # ``frida_host_for(serial)`` so devices never share one host port.
    frida_host: str = field(default_factory=lambda: os.environ.get("APU_FRIDA_HOST", "127.0.0.1:27042"))
    frida_port: int = field(default_factory=lambda: int(os.environ.get("APU_FRIDA_PORT", "27042")))
    # Remote port frida-server listens on. The local adb-forward port is
    # allocated per device from [frida_port, frida_port + frida_port_span).
    frida_remote_port: int = field(
        default_factory=lambda: int(os.environ.get("APU_FRIDA_REMOTE_PORT", os.environ.get("APU_FRIDA_PORT", "27042")))
    )
    frida_port_span: int = field(
        default_factory=lambda: int(os.environ.get("APU_FRIDA_PORT_SPAN", "1000"))
    )
    default_serial: str | None = field(default_factory=lambda: os.environ.get("APU_SERIAL") or None)
    dump_top_regions: int = field(
        default_factory=lambda: int(os.environ.get("APU_DUMP_TOP_REGIONS", "16"))
    )
    dump_max_candidates: int = field(
        default_factory=lambda: int(os.environ.get("APU_DUMP_MAX_CANDIDATES", "32"))
    )
    # Only skip the DEX scan when the sampled dump is entirely zero; a real DEX
    # at the start of a large region must not be hidden by a 99.5% threshold.
    dump_zero_ratio: float = field(
        default_factory=lambda: float(os.environ.get("APU_DUMP_ZERO_RATIO", "1.0"))
    )
    mcp_max_response_bytes: int = field(
        default_factory=lambda: int(os.environ.get("APU_MCP_MAX_RESPONSE_BYTES", str(8 * 1024 * 1024)))
    )
    max_region_bytes: int = field(
        default_factory=lambda: int(os.environ.get("APU_MAX_REGION_BYTES", str(256 * 1024 * 1024)))
    )
    max_dump_bytes: int = field(
        default_factory=lambda: int(os.environ.get("APU_MAX_DUMP_BYTES", str(1024 * 1024 * 1024)))
    )
    max_asset_bytes: int = field(
        default_factory=lambda: int(os.environ.get("APU_MAX_ASSET_BYTES", str(512 * 1024 * 1024)))
    )
    frida_timeout_ms: int = field(
        default_factory=lambda: int(os.environ.get("APU_FRIDA_TIMEOUT_MS", "180000"))
    )
    command_timeout_s: int = field(
        default_factory=lambda: int(os.environ.get("APU_COMMAND_TIMEOUT_S", "120"))
    )
    install_timeout_s: int = field(
        default_factory=lambda: int(os.environ.get("APU_INSTALL_TIMEOUT_S", "900"))
    )
    jadx_timeout_s: int = field(default_factory=default_jadx_timeout_s)

    @classmethod
    def load(cls, runs_dir: str | Path | None = None) -> "Config":
        config = cls()
        if runs_dir:
            config.runs_dir = Path(runs_dir).expanduser()
        config.aapt = _env_command("APU_AAPT") and _env_command("APU_AAPT")[0] or _first_existing(
            [_which("aapt") or ""] + _nox_aapt_candidates()
        )
        config.java = _first_existing(
            [(_env_command("APU_JAVA") or [""])[0], str(_which("java") or "")] + _java_candidates()
        )
        config.jadx_jar = _env_command("APU_JADX_JAR") and _env_command("APU_JADX_JAR")[0] or _first_existing(
            [str(item) for item in _jadx_jar_candidates()]
        )
        config.frida_server = _env_command("APU_FRIDA_SERVER") and _env_command("APU_FRIDA_SERVER")[0] or _first_existing(
            [str(WORKSPACE_ROOT / "frida-server"), str(REPO_ROOT / "vendor" / "frida-server")]
        )
        return config

    def ensure_runs_dir(self) -> Path:
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        return self.runs_dir

    def frida_port_for(self, serial: str | None) -> int:
        """Stable per-device host port.

        A device serial always maps to the same port within this configuration,
        while different devices get different ports.  This replaces the old
        global 127.0.0.1:27042 assumption that made concurrent device runs
        collide.
        """

        base = max(1, int(self.frida_port))
        span = max(1, int(self.frida_port_span))
        if not serial:
            return base
        digest = hashlib.sha256(str(serial).encode("utf-8")).digest()
        return base + (int.from_bytes(digest[:4], "big") % span)

    def frida_host_for(self, serial: str | None) -> str:
        return f"127.0.0.1:{self.frida_port_for(serial)}"

    def platform_summary(self) -> dict:
        return {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "runs_dir": str(self.runs_dir),
            "memory_dir": str(self.memory_dir),
            "adb": self.adb,
            "frida": self.frida,
            "aapt": self.aapt,
            "java": self.java,
            "jadx_jar": self.jadx_jar,
            "jadx_timeout_s": self.jadx_timeout_s,
            "frida_server": self.frida_server,
            "frida_host": self.frida_host,
            "frida_port": self.frida_port,
            "frida_remote_port": self.frida_remote_port,
            "frida_port_span": self.frida_port_span,
            "dump_top_regions": self.dump_top_regions,
            "dump_max_candidates": self.dump_max_candidates,
            "dump_zero_ratio": self.dump_zero_ratio,
        }
