from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ERROR_CATEGORIES = {
    "invalid_input": "invalid_input",
    "unsupported_target": "unsupported_target",
    "unsupported_provider": "unsupported_provider",
    "integrity_mismatch": "integrity_mismatch",
    "artifact_changed": "integrity_mismatch",
    "dump_incomplete": "truncated",
    "dex_invalid": "integrity_mismatch",
    "cancelled": "cancelled",
    "timeout": "timeout",
    "resource_constraint": "resource_constraint",
    "device_unavailable": "unavailable",
    "frida_unavailable": "unavailable",
    "frida_version_mismatch": "unavailable",
    "tool_missing": "unavailable",
    "process_not_running": "unavailable",
    "root_required": "access_denied",
    "permission_denied": "access_denied",
    "process_died": "execution_failure",
    "execution_failure": "execution_failure",
    "cleanup_incomplete": "execution_failure",
    "not_found": "invalid_input",
    "conflict": "invalid_input",
}

_DEFAULT_REMEDIATION = {
    "invalid_input": "Check the arguments and retry with an existing absolute path.",
    "unsupported_target": "Inspect the target and choose a supported strategy.",
    "unsupported_provider": "Install or configure the required provider.",
    "integrity_mismatch": "Re-acquire the artifact or rerun the analysis; do not trust the mismatched record.",
    "artifact_changed": "Re-inspect the artifact; it changed since it was recorded.",
    "dump_incomplete": "Retry the dump with a larger window, freeze mode, or a different method.",
    "dex_invalid": "Re-dump the DEX or repair its header before decompiling.",
    "cancelled": "Rerun the operation when ready.",
    "timeout": "Increase the timeout or reduce the target scope.",
    "resource_constraint": "Reduce the requested range or export the evidence to disk.",
    "device_unavailable": "Connect a device/emulator and enable USB debugging.",
    "frida_unavailable": "Install frida CLI and start frida-server on the device.",
    "frida_version_mismatch": "Use matching frida CLI and frida-server versions.",
    "tool_missing": "Install the tool or set its APU_* environment variable.",
    "process_not_running": "Launch the target and retry.",
    "root_required": "Root the device or use a root-capable emulator.",
    "permission_denied": "Check device root access and file ownership.",
    "process_died": "Retry with anti-kill hooks, freeze mode, or a memory dump.",
    "execution_failure": "Read the captured output and adjust the strategy.",
    "cleanup_incomplete": "Inspect the mutation log and restore the reported paths manually.",
    "not_found": "Check the run id, evidence id, or path.",
    "conflict": "Choose a new output path or pass overwrite=true.",
}


@dataclass
class AnalysisError(Exception):
    code: str
    message: str
    retryable: bool = False
    remediation: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    partial: dict[str, Any] | None = None
    captured_output: str | None = None

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)
        if not self.remediation:
            self.remediation = _DEFAULT_REMEDIATION.get(self.code, "Inspect the error details and retry.")

    @property
    def category(self) -> str:
        return ERROR_CATEGORIES.get(self.code, "execution_failure")

    def projection(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "retryable": self.retryable,
            "remediation": {"action": self.remediation},
            "details": _redact(self.details),
        }
        if self.partial is not None:
            data["partial"] = _redact(self.partial)
        if self.captured_output:
            data["captured_output"] = _redact_text(self.captured_output[-4000:])
        return data


def fail(code: str, message: str, **kwargs: Any) -> AnalysisError:
    return AnalysisError(code=code, message=message, **kwargs)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if any(token in key.lower() for token in ("token", "secret", "password")) else _redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _redact_text(text: str) -> str:
    lowered = text.lower()
    if "token" in lowered or "secret" in lowered:
        return "<redacted: possible credential in captured output>"
    return text


def project_error(error: Exception) -> dict[str, Any]:
    if isinstance(error, AnalysisError):
        return error.projection()
    return {
        "code": "execution_failure",
        "category": "execution_failure",
        "message": str(error) or error.__class__.__name__,
        "retryable": False,
        "remediation": {"action": _DEFAULT_REMEDIATION["execution_failure"]},
        "details": {"exception": error.__class__.__name__},
    }
