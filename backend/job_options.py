"""Canonical job-option schema shared by the HTTP API and the chat toolbox.

The API, chat tools and the job engines used to keep their own allow-lists,
which drifted apart (chat could not pass ``arm_device`` and the HTTP API
silently dropped unknown keys).  This module is the single source of truth:

* :data:`JOB_OPTION_SPECS` describes every option a client may send.
* :func:`normalize_job_options` validates and canonicalises a client payload.
* :func:`option_schema_for_prompt` exposes the same schema to the chat tool
  definitions.

Internal keys (``_auto_device``, ``_arm_runtime``, ``_device_arch``,
``_frida_server_path``) are never accepted from clients; they are added by the
job manager/worker.  ``frida_server_path`` is the public option and is also
mirrored to the internal ``_frida_server_path`` key because that is what the
engine bridge reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Option value kinds.
BOOL = "boolean"
INT = "integer"
STRING = "string"


@dataclass(frozen=True)
class JobOptionSpec:
    """Validation metadata for one client-visible job option."""

    name: str
    kind: str
    description: str
    default: Any = None
    minimum: int | None = None
    maximum: int | None = None
    max_length: int | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def schema(self) -> dict[str, Any]:
        """Return a JSON-schema-like property description."""
        item: dict[str, Any] = {
            "name": self.name,
            "type": self.kind,
            "description": self.description,
        }
        if self.kind == INT:
            if self.minimum is not None:
                item["minimum"] = self.minimum
            if self.maximum is not None:
                item["maximum"] = self.maximum
        elif self.kind == STRING and self.max_length is not None:
            item["maxLength"] = self.max_length
        if self.default is not None:
            item["default"] = self.default
        return item

    def validate(self, value: Any) -> Any:
        if self.kind == BOOL:
            # ``bool`` is a subclass of ``int``; require a real boolean so
            # values such as 1/"true" are rejected instead of coerced.
            if type(value) is not bool:
                raise ValueError(f"option {self.name!r} must be a boolean")
            return value
        if self.kind == INT:
            if type(value) is not int:
                raise ValueError(f"option {self.name!r} must be an integer")
            if value < 0:
                raise ValueError(f"option {self.name!r} must not be negative")
            if self.minimum is not None and value < self.minimum:
                raise ValueError(f"option {self.name!r} must be >= {self.minimum}")
            if self.maximum is not None and value > self.maximum:
                raise ValueError(f"option {self.name!r} must be <= {self.maximum}")
            return value
        if self.kind == STRING:
            if not isinstance(value, str):
                raise ValueError(f"option {self.name!r} must be a string")
            if self.max_length is not None and len(value) > self.max_length:
                raise ValueError(f"option {self.name!r} must be at most {self.max_length} characters")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError(f"option {self.name!r} must not contain control characters")
            return value
        raise ValueError(f"option {self.name!r} has an unsupported type")


JOB_OPTION_SPECS: dict[str, JobOptionSpec] = {
    spec.name: spec
    for spec in (
        JobOptionSpec("install", BOOL, "Install the target APK on the device.", default=True),
        JobOptionSpec("jadx", BOOL, "Decompile recovered DEX with JADX.", default=True),
        JobOptionSpec("cleanup", BOOL, "Restore device mutations after the job.", default=True),
        JobOptionSpec("keep_device_files", BOOL, "Keep temporary files on the device."),
        JobOptionSpec("prune_raw", BOOL, "Delete raw memory/DEX dumps after processing."),
        JobOptionSpec(
            "auto_emulator_bypass",
            BOOL,
            "Automatically rename ijiami emulator-detection libraries.",
            default=True,
        ),
        JobOptionSpec("force_dump", BOOL, "Force a dynamic dump even when static analysis looks sufficient."),
        JobOptionSpec("inner_bypass", BOOL, "Enable the reversible inner-shell library bypass."),
        JobOptionSpec("arm_device", BOOL, "Prefer an ARM64 device/runtime for this job."),
        JobOptionSpec(
            "freeze_timeout_ms",
            INT,
            "Freeze-mode dump timeout in milliseconds.",
            minimum=0,
            maximum=3_600_000,
        ),
        JobOptionSpec(
            "freeze_poll_ms",
            INT,
            "Freeze-mode memory-map polling interval in milliseconds.",
            minimum=0,
            maximum=60_000,
        ),
        JobOptionSpec(
            "frida_timeout_ms",
            INT,
            "Frida dump timeout in milliseconds.",
            minimum=0,
            maximum=3_600_000,
        ),
        JobOptionSpec(
            "max_region_bytes",
            INT,
            "Per-region memory dump cap in bytes (public alias: dump_region_max).",
            minimum=0,
            maximum=16 * 1024 * 1024 * 1024,
            aliases=("dump_region_max",),
        ),
        JobOptionSpec(
            "jadx_timeout_s",
            INT,
            "JADX timeout in seconds; omitted/0 uses APU_JADX_TIMEOUT_S or 3600. Overrides model tool arguments.",
            minimum=0,
            maximum=86_400,
        ),
        JobOptionSpec(
            "timeout_s",
            INT,
            "Whole-job wall-clock timeout in seconds; omitted/0 reserves 3600s plus the JADX timeout when enabled.",
            minimum=0,
            maximum=604_800,
        ),
        JobOptionSpec(
            "llm_max_tokens",
            INT,
            "Maximum output tokens for LLM engines.",
            minimum=0,
            maximum=1_000_000,
        ),
        JobOptionSpec(
            "frida_server_path",
            STRING,
            "Local frida-server binary or existing device path.",
            max_length=1024,
        ),
    )
}

_ALIASES: dict[str, str] = {
    alias: spec.name for spec in JOB_OPTION_SPECS.values() for alias in spec.aliases
}


def normalize_job_options(body: Any, *, strict: bool = True) -> dict[str, Any]:
    """Validate a client ``options`` object and return canonical options.

    Unknown keys are rejected when ``strict`` is true.  Booleans must be real
    booleans, integers must be non-negative and within their documented range,
    and strings are length/control-character bounded.  Defaults for
    ``install``/``jadx``/``cleanup``/``auto_emulator_bypass`` are applied so
    every caller produces the same stored options.
    """
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise ValueError("options must be an object")
    normalized: dict[str, Any] = {}
    seen: dict[str, str] = {}
    for raw_key, value in body.items():
        if not isinstance(raw_key, str):
            raise ValueError("option names must be strings")
        canonical = raw_key if raw_key in JOB_OPTION_SPECS else _ALIASES.get(raw_key)
        spec = JOB_OPTION_SPECS.get(canonical) if canonical else None
        if spec is None or raw_key.startswith("_"):
            if strict:
                raise ValueError(f"unknown option: {raw_key}")
            continue
        if canonical in seen:
            raise ValueError(
                f"option {canonical!r} given more than once ({seen[canonical]!r} and {raw_key!r})"
            )
        normalized[canonical] = spec.validate(value)
        seen[canonical] = raw_key
    for spec in JOB_OPTION_SPECS.values():
        if spec.default is not None and spec.name not in normalized:
            normalized[spec.name] = spec.default
    # The engine bridge reads the resolved frida-server path from the
    # internal key; mirror the public option so callers only ever use one name.
    if "frida_server_path" in normalized:
        normalized["_frida_server_path"] = normalized["frida_server_path"]
    return normalized


def option_schema_for_prompt() -> list[dict[str, Any]]:
    """Return option property descriptors for LLM/chat tool schemas.

    Each item contains ``name`` plus JSON-schema fields (``type``,
    ``description``, numeric bounds, ``maxLength``).  Aliases are included as
    separate entries so the model can use either spelling.
    """
    items: list[dict[str, Any]] = []
    for spec in JOB_OPTION_SPECS.values():
        items.append(spec.schema())
        for alias in spec.aliases:
            alias_item = spec.schema()
            alias_item["name"] = alias
            alias_item["description"] = f"{alias}: {spec.description}"
            items.append(alias_item)
    return items
