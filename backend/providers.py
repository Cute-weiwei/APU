from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import BackendConfig
from .security import chmod_private

PROTOCOLS = ("openai", "anthropic", "auto")


def _slug(value: str, fallback: str = "provider") -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return (text or fallback)[:48]


def endpoint_url(base_url: str, protocol: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        return ""
    if protocol == "anthropic":
        if base.endswith("/messages"):
            return base
        if base.endswith("/v1"):
            return base + "/messages"
        return base + "/v1/messages"
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def models_url(base_url: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith("/models"):
        return base
    return base + "/models"


PROTOCOL_DEFAULTS: dict[str, dict[str, Any]] = {
    "openai": {
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "context_window": 65536,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
    },
    "anthropic": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-chat",
        "context_window": 65536,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
    },
    "auto": {
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "context_window": 65536,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
    },
}

MODEL_PRESETS: dict[str, list[str]] = {
    "openai": ["deepseek-chat", "deepseek-reasoner", "gpt-4.1", "gpt-4.1-mini", "qwen-max"],
    "anthropic": ["deepseek-chat", "claude-sonnet-5", "claude-opus-5", "claude-haiku-4-5-20251001"],
    "auto": [
        "deepseek-chat",
        "deepseek-reasoner",
        "claude-sonnet-5",
        "claude-opus-5",
        "gpt-4.1",
        "gpt-4.1-mini",
        "qwen-max",
    ],
}

PROVIDER_PRESETS: list[dict[str, Any]] = [
    {
        "id": "deepseek-openai",
        "name": "DeepSeek · OpenAI 协议",
        "protocol": "openai",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "context_window": 65536,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
        "key_env": "DEEPSEEK_API_KEY",
    },
    {
        "id": "deepseek-anthropic",
        "name": "DeepSeek · Anthropic 协议",
        "protocol": "anthropic",
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-chat",
        "context_window": 65536,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
        "key_env": "DEEPSEEK_API_KEY",
    },
    {
        "id": "anthropic-claude",
        "name": "Anthropic Claude",
        "protocol": "anthropic",
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-5",
        "context_window": 200000,
        "max_tokens": 8192,
        "max_steps": 20,
        "timeout_s": 180,
        "temperature": 0.1,
        "key_env": "ANTHROPIC_API_KEY",
    },
    {
        "id": "openai-generic",
        "name": "OpenAI 兼容",
        "protocol": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1",
        "context_window": 128000,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
        "key_env": "OPENAI_API_KEY",
    },
    {
        "id": "auto-generic",
        "name": "自动兼容（OpenAI / Anthropic）",
        "protocol": "auto",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "context_window": 65536,
        "max_tokens": 8192,
        "max_steps": 24,
        "timeout_s": 180,
        "temperature": 0.1,
        "key_env": "DEEPSEEK_API_KEY",
    },
]


@dataclass
class ProviderConfig:
    id: str
    name: str
    protocol: str
    base_url: str
    model: str
    api_key: str | None = None
    api_key_hint: str | None = None
    context_window: int = 65536
    max_tokens: int = 4096
    max_steps: int = 24
    timeout_s: int = 180
    temperature: float = 0.1
    tool_result_chars: int = 16000
    enabled: bool = True
    updated_at: str | None = None

    @property
    def api_key_set(self) -> bool:
        return bool(self.api_key)

    @property
    def available(self) -> bool:
        return self.enabled and self.api_key_set

    @property
    def reason(self) -> str:
        if not self.enabled:
            return "provider disabled"
        if not self.api_key_set:
            return "missing API key"
        return "configured"

    @property
    def endpoint(self) -> str:
        return endpoint_url(self.base_url, self.protocol)

    def public(self, admin: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol,
            "base_url": self.base_url,
            "model": self.model,
            "context_window": self.context_window,
            "max_tokens": self.max_tokens,
            "max_steps": self.max_steps,
            "timeout_s": self.timeout_s,
            "temperature": self.temperature,
            "tool_result_chars": self.tool_result_chars,
            "enabled": self.enabled,
            "available": self.available,
            "reason": self.reason,
            "endpoint": self.endpoint,
            "api_key_set": self.api_key_set,
            "updated_at": self.updated_at,
        }
        if admin:
            data["api_key_hint"] = self.api_key_hint if self.api_key_set else None
        return data


def _int_value(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _float_value(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bool_value(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("0", "false", "no", "off", "")


def _hint(key: str | None) -> str | None:
    if not key:
        return None
    if len(key) <= 8:
        return "***"
    return key[:3] + "…" + key[-4:]


class ProviderStore:
    """Model provider CRUD. API keys live only in 0600 files, never in the DB."""

    def __init__(self, config: BackendConfig, database: Any):
        self.config = config
        self.database = database

    # ------------------------------------------------------------------ secrets
    def _key_path(self, provider_id: str) -> Path:
        return self.config.secrets_dir / f"provider-{_slug(provider_id)}.key"

    def read_key(self, provider_id: str) -> str | None:
        path = self._key_path(provider_id)
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return value or None

    def write_key(self, provider_id: str, key: str) -> None:
        value = str(key or "").strip()
        if not value:
            raise ValueError("api_key must not be empty")
        path = self._key_path(provider_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".provider-key-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(value + "\n")
            os.replace(temp_name, path)
            chmod_private(path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def delete_key(self, provider_id: str) -> None:
        try:
            self._key_path(provider_id).unlink(missing_ok=True)
        except OSError:
            pass

    # ------------------------------------------------------------------ conversion
    def from_row(self, row: dict[str, Any], include_key: bool = True) -> ProviderConfig:
        key = self.read_key(row["id"]) if include_key else None
        return ProviderConfig(
            id=str(row["id"]),
            name=str(row["name"]),
            protocol=str(row["protocol"]),
            base_url=str(row["base_url"]),
            model=str(row["model"]),
            api_key=key,
            api_key_hint=_hint(key),
            context_window=int(row.get("context_window") or 65536),
            max_tokens=int(row.get("max_tokens") or 4096),
            max_steps=int(row.get("max_steps") or 24),
            timeout_s=int(row.get("timeout_s") or 180),
            temperature=float(row.get("temperature") or 0.1),
            tool_result_chars=int(row.get("tool_result_chars") or 16000),
            enabled=bool(row.get("enabled", 1)),
            updated_at=row.get("updated_at"),
        )

    def list(self, include_keys: bool = True) -> list[ProviderConfig]:
        return [self.from_row(row, include_key=include_keys) for row in self.database.list_providers()]

    def get(self, provider_id: str, include_key: bool = True) -> ProviderConfig | None:
        row = self.database.get_provider(provider_id)
        return self.from_row(row, include_key=include_key) if row else None

    def presets(self) -> dict[str, Any]:
        return {
            "protocols": PROTOCOL_DEFAULTS,
            "providers": PROVIDER_PRESETS,
            "models": MODEL_PRESETS,
        }

    # ------------------------------------------------------------------ validation
    def _validate(self, data: dict[str, Any], *, creating: bool, current: dict[str, Any] | None = None) -> dict[str, Any]:
        merged = dict(current or {})
        merged.update({key: value for key, value in data.items() if value is not None})
        protocol = str(merged.get("protocol") or "").strip().lower()
        if protocol not in PROTOCOLS:
            raise ValueError("protocol must be 'openai', 'anthropic' or 'auto'")
        base_url = str(merged.get("base_url") or "").strip()
        if not re.match(r"^https?://", base_url, flags=re.I):
            raise ValueError("base_url must start with http:// or https://")
        model = str(merged.get("model") or "").strip()
        if not model:
            raise ValueError("model is required")
        name = str(merged.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        context_window = _int_value(merged.get("context_window"), 65536, 1024, 2_000_000)
        max_tokens = _int_value(merged.get("max_tokens"), 4096, 1, context_window)
        result = {
            "name": name[:120],
            "protocol": protocol,
            "base_url": base_url[:500].rstrip("/"),
            "model": model[:200],
            "context_window": context_window,
            "max_tokens": max_tokens,
            "max_steps": _int_value(merged.get("max_steps"), 24, 1, 200),
            "timeout_s": _int_value(merged.get("timeout_s"), 180, 5, 1800),
            "temperature": _float_value(merged.get("temperature"), 0.1, 0.0, 2.0),
            "tool_result_chars": _int_value(merged.get("tool_result_chars"), 16000, 1000, 200000),
            "enabled": 1 if _bool_value(merged.get("enabled"), True) else 0,
        }
        if creating and not result["name"]:
            raise ValueError("name is required")
        return result

    # ------------------------------------------------------------------ CRUD
    def create(self, data: dict[str, Any]) -> ProviderConfig:
        fields = self._validate(data, creating=True)
        provider_id = str(data.get("id") or "").strip().lower()
        if provider_id:
            if not re.match(r"^[a-z0-9][a-z0-9_-]{1,63}$", provider_id):
                raise ValueError("id must match [a-z0-9][a-z0-9_-]{1,63}")
        else:
            provider_id = _slug(fields["name"], "model") + "-" + secrets.token_hex(3)
        if self.database.get_provider(provider_id):
            raise ValueError(f"provider already exists: {provider_id}")
        self.database.create_provider(provider_id, **fields)
        key = data.get("api_key")
        if key:
            self.write_key(provider_id, str(key))
        provider = self.get(provider_id)
        if provider is None:
            raise RuntimeError("provider creation failed")
        return provider

    def update(self, provider_id: str, data: dict[str, Any]) -> ProviderConfig:
        existing = self.database.get_provider(provider_id)
        if not existing:
            raise KeyError(provider_id)
        fields = self._validate(data, creating=False, current=existing)
        self.database.update_provider(provider_id, **fields)
        if data.get("clear_api_key"):
            self.delete_key(provider_id)
        elif data.get("api_key"):
            self.write_key(provider_id, str(data["api_key"]))
        provider = self.get(provider_id)
        if provider is None:  # pragma: no cover - defensive
            raise RuntimeError("provider update failed")
        return provider

    def delete(self, provider_id: str) -> None:
        if not self.database.get_provider(provider_id):
            raise KeyError(provider_id)
        self.database.delete_provider(provider_id)
        self.delete_key(provider_id)

    # ------------------------------------------------------------------ seed
    def seed(self) -> None:
        for preset in PROVIDER_PRESETS:
            provider_id = preset["id"]
            row = self.database.get_provider(provider_id)
            if not row:
                fields = {
                    "name": preset["name"],
                    "protocol": preset["protocol"],
                    "base_url": preset["base_url"],
                    "model": preset["model"],
                    "context_window": preset["context_window"],
                    "max_tokens": preset["max_tokens"],
                    "max_steps": preset["max_steps"],
                    "timeout_s": preset["timeout_s"],
                    "temperature": preset["temperature"],
                    "tool_result_chars": 16000,
                    "enabled": 1,
                }
                if provider_id == "deepseek-openai":
                    fields["base_url"] = os.environ.get("DEEPSEEK_BASE_URL") or fields["base_url"]
                    fields["model"] = os.environ.get("DEEPSEEK_MODEL") or fields["model"]
                elif provider_id == "deepseek-anthropic":
                    fields["base_url"] = (
                        os.environ.get("DEEPSEEK_ANTHROPIC_BASE_URL")
                        or fields["base_url"]
                    )
                    fields["model"] = (
                        os.environ.get("DEEPSEEK_ANTHROPIC_MODEL")
                        or os.environ.get("DEEPSEEK_MODEL")
                        or fields["model"]
                    )
                elif provider_id == "anthropic-claude":
                    fields["model"] = os.environ.get("CLAUDE_MODEL") or fields["model"]
                self.database.create_provider(provider_id, **fields)
            if not self.read_key(provider_id):
                env_name = preset.get("key_env")
                value = os.environ.get(env_name or "") if env_name else ""
                if value:
                    self.write_key(provider_id, value)
