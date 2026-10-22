from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from .config import BackendConfig
from .mcp import McpStore
from .providers import ProviderConfig, ProviderStore
from .skills import BUILTIN_SKILL_ID, SkillStore

BUILTIN_AGENT_ID = "agent-native"
ENGINE_ALIASES = {
    "agent": BUILTIN_AGENT_ID,
    "deepseek": "agent-deepseek-openai",
    "claude": "agent-anthropic-claude",
}


def _slug(value: str, fallback: str = "agent") -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return (text or fallback)[:48]


def _ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text[:80])
    return result[:100]


@dataclass
class AgentSpec:
    id: str
    name: str
    kind: str
    provider_id: str | None = None
    provider_name: str | None = None
    protocol: str | None = None
    model: str | None = None
    base_url: str | None = None
    context_window: int | None = None
    max_tokens: int | None = None
    skill_ids: list[str] = field(default_factory=list)
    mcp_ids: list[str] = field(default_factory=list)
    skills: list[dict[str, Any]] = field(default_factory=list)
    mcps: list[dict[str, Any]] = field(default_factory=list)
    system_prompt: str = ""
    enabled: bool = True
    builtin: bool = False
    owner_id: int | None = None
    provider_available: bool = True
    provider_reason: str = ""
    api_key_set: bool = False
    api_key_hint: str | None = None

    @property
    def available(self) -> bool:
        if not self.enabled:
            return False
        if self.kind == "native":
            return True
        return self.provider_available

    @property
    def reason(self) -> str:
        if not self.enabled:
            return "agent disabled"
        if self.kind == "native":
            return "deterministic workflow"
        return self.provider_reason or ("configured" if self.available else "provider unavailable")

    def public(self, admin: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.id,
            "id": self.id,
            "label": self.name,
            "kind": self.kind,
            "protocol": self.protocol or ("native" if self.kind == "native" else ""),
            "model": self.model or ("deterministic" if self.kind == "native" else ""),
            "base_url": self.base_url or "",
            "context_window": self.context_window,
            "max_tokens": self.max_tokens,
            "available": self.available,
            "reason": self.reason,
            "enabled": self.enabled,
            "builtin": self.builtin,
            "owner_id": self.owner_id,
            "shared": self.owner_id is None,
            "provider_id": self.provider_id,
            "provider": self.provider_name,
            "skills": [{"id": item.get("id"), "name": item.get("name")} for item in self.skills],
            "mcp": [
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "transport": item.get("transport"),
                    "tools": item.get("tools") or [],
                }
                for item in self.mcps
            ],
            "api_key_set": self.api_key_set,
            "system_prompt": self.system_prompt,
            "skill_ids": self.skill_ids,
            "mcp_ids": self.mcp_ids,
        }
        if admin and self.api_key_set:
            data["api_key_hint"] = self.api_key_hint
        return data


class AgentStore:
    def __init__(
        self,
        config: BackendConfig,
        database: Any,
        providers: ProviderStore,
        skills: SkillStore,
        mcp: McpStore,
    ):
        self.config = config
        self.database = database
        self.providers = providers
        self.skills = skills
        self.mcp = mcp

    # ------------------------------------------------------------------ seed
    def seed(self) -> None:
        if not self.database.get_agent(BUILTIN_AGENT_ID):
            self.database.create_agent(
                BUILTIN_AGENT_ID,
                "Agent（确定性）",
                "native",
                None,
                [BUILTIN_SKILL_ID],
                [],
                "Deterministic apk_unpack workflow driven by the backend job options.",
                enabled=1,
                builtin=1,
            )
        for provider in self.providers.list(include_keys=False):
            self.ensure_provider_agent(provider)

    def ensure_provider_agent(self, provider: ProviderConfig) -> dict[str, Any]:
        agent_id = f"agent-{provider.id}"
        row = self.database.get_agent(agent_id)
        if not row:
            return self.database.create_agent(
                agent_id,
                provider.name,
                "llm",
                provider.id,
                [BUILTIN_SKILL_ID],
                [],
                "",
                enabled=1,
                builtin=0,
            )
        return row

    # ------------------------------------------------------------------ resolution
    def _spec(self, row: dict[str, Any]) -> AgentSpec:
        provider: ProviderConfig | None = None
        provider_id = row.get("provider_id")
        if provider_id:
            provider = self.providers.get(str(provider_id), include_key=True)
        skill_docs = []
        for skill_id in row.get("skill_ids") or []:
            skill = self.skills.get(skill_id, include_content=False)
            if skill:
                skill_docs.append({"id": skill["id"], "name": skill["name"]})
        mcp_docs = []
        for server_id in row.get("mcp_ids") or []:
            server = self.mcp.get(server_id, include_secrets=False)
            if server:
                mcp_docs.append(
                    {
                        "id": server.id,
                        "name": server.name,
                        "transport": server.transport,
                        "tools": [tool.get("name") for tool in server.tools if tool.get("name")],
                    }
                )
        return AgentSpec(
            id=str(row["id"]),
            name=str(row["name"]),
            kind=str(row.get("kind") or "llm"),
            provider_id=str(provider_id) if provider_id else None,
            provider_name=provider.name if provider else None,
            protocol=provider.protocol if provider else None,
            model=provider.model if provider else None,
            base_url=provider.base_url if provider else None,
            context_window=provider.context_window if provider else None,
            max_tokens=provider.max_tokens if provider else None,
            skill_ids=list(row.get("skill_ids") or []),
            mcp_ids=list(row.get("mcp_ids") or []),
            skills=skill_docs,
            mcps=mcp_docs,
            system_prompt=str(row.get("system_prompt") or ""),
            enabled=bool(row.get("enabled", 1)),
            builtin=bool(row.get("builtin", 0)),
            owner_id=row.get("owner_id"),
            provider_available=provider.available if provider else (row.get("kind") == "native"),
            provider_reason=provider.reason if provider else ("configured" if row.get("kind") == "native" else "missing provider"),
            api_key_set=provider.api_key_set if provider else False,
            api_key_hint=provider.api_key_hint if provider else None,
        )

    def list(self, visible_to: int | None = None) -> list[AgentSpec]:
        return [self._spec(row) for row in self.database.list_agents(visible_to=visible_to)]

    def get(self, agent_id: str) -> AgentSpec | None:
        row = self.database.get_agent(agent_id)
        return self._spec(row) if row else None

    def resolve_skills(self, agent: AgentSpec) -> list[dict[str, Any]]:
        return self.skills.resolve(agent.skill_ids)

    def resolve_mcps(self, agent: AgentSpec):
        return self.mcp.resolve(agent.mcp_ids)

    def canonical_engine(self, name: str) -> str:
        value = str(name or "").strip()
        if not value:
            return BUILTIN_AGENT_ID
        if value in ENGINE_ALIASES:
            return ENGINE_ALIASES[value]
        if value == BUILTIN_AGENT_ID:
            return value
        if self.database.get_agent(value):
            return value
        if self.database.get_agent(f"agent-{value}"):
            return f"agent-{value}"
        return value

    # ------------------------------------------------------------------ validation
    def _validate_provider(self, provider_id: Any) -> str:
        value = str(provider_id or "").strip()
        if not value:
            raise ValueError("provider_id is required for LLM agents")
        provider = self.providers.get(value, include_key=False)
        if not provider:
            raise ValueError(f"unknown model provider: {value}")
        return value

    @staticmethod
    def _visible(row: dict[str, Any] | Any, owner_id: int | None) -> bool:
        row_owner = row.get("owner_id") if isinstance(row, dict) else getattr(row, "owner_id", None)
        if row_owner is None:
            return True
        return owner_id is not None and int(row_owner) == int(owner_id)

    def _validate_ids(self, skill_ids: Any, mcp_ids: Any, owner_id: int | None = None) -> tuple[list[str], list[str]]:
        skills = _ids(skill_ids)
        for skill_id in skills:
            skill = self.skills.get(skill_id, include_content=False)
            if not skill or not self._visible(skill, owner_id):
                raise ValueError(f"unknown skill: {skill_id}")
        servers = _ids(mcp_ids)
        for server_id in servers:
            server = self.mcp.get(server_id, include_secrets=False)
            if not server or not self._visible(server, owner_id):
                raise ValueError(f"unknown MCP server: {server_id}")
        return skills, servers

    # ------------------------------------------------------------------ CRUD
    def create(self, data: dict[str, Any], owner_id: int | None = None) -> AgentSpec:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        provider_id = self._validate_provider(data.get("provider_id"))
        skill_ids, mcp_ids = self._validate_ids(data.get("skill_ids"), data.get("mcp_ids"), owner_id=owner_id)
        agent_id = str(data.get("id") or "").strip().lower()
        if agent_id:
            if not re.match(r"^[a-z0-9][a-z0-9_-]{1,63}$", agent_id):
                raise ValueError("id must match [a-z0-9][a-z0-9_-]{1,63}")
        else:
            agent_id = _slug(name, "agent") + "-" + secrets.token_hex(3)
        if self.database.get_agent(agent_id):
            raise ValueError(f"agent already exists: {agent_id}")
        self.database.create_agent(
            agent_id,
            name[:120],
            "llm",
            provider_id,
            skill_ids,
            mcp_ids,
            str(data.get("system_prompt") or "")[:20000],
            enabled=1 if data.get("enabled", True) else 0,
            builtin=0,
            owner_id=owner_id,
        )
        agent = self.get(agent_id)
        if agent is None:  # pragma: no cover
            raise RuntimeError("agent creation failed")
        return agent

    def update(self, agent_id: str, data: dict[str, Any]) -> AgentSpec:
        row = self.database.get_agent(agent_id)
        if not row:
            raise KeyError(agent_id)
        kind = str(row.get("kind") or "llm")
        provider_id = row.get("provider_id")
        managed = kind == "native" or (
            bool(provider_id) and agent_id == f"agent-{provider_id}"
        )
        if kind == "native":
            changes = {}
            if "enabled" in data:
                changes["enabled"] = 1 if data["enabled"] else 0
            self.database.update_agent(agent_id, **changes)
            agent = self.get(agent_id)
            if agent is None:  # pragma: no cover
                raise RuntimeError("agent update failed")
            return agent
        changes: dict[str, Any] = {}
        if "name" in data:
            name = str(data.get("name") or "").strip()
            if not name:
                raise ValueError("name must not be empty")
            changes["name"] = name[:120]
        if "system_prompt" in data:
            changes["system_prompt"] = str(data.get("system_prompt") or "")[:20000]
        if "skill_ids" in data or "mcp_ids" in data:
            skill_ids, mcp_ids = self._validate_ids(
                data.get("skill_ids", row.get("skill_ids")),
                data.get("mcp_ids", row.get("mcp_ids")),
                owner_id=row.get("owner_id"),
            )
            changes["skill_ids_json"] = _json_list(skill_ids)
            changes["mcp_ids_json"] = _json_list(mcp_ids)
        if "enabled" in data:
            changes["enabled"] = 1 if data["enabled"] else 0
        if not managed and "provider_id" in data:
            changes["provider_id"] = self._validate_provider(data.get("provider_id"))
        self.database.update_agent(agent_id, **changes)
        agent = self.get(agent_id)
        if agent is None:  # pragma: no cover
            raise RuntimeError("agent update failed")
        return agent

    def delete(self, agent_id: str) -> None:
        row = self.database.get_agent(agent_id)
        if not row:
            raise KeyError(agent_id)
        managed = bool(row.get("builtin")) or (
            bool(row.get("provider_id")) and agent_id == f"agent-{row['provider_id']}"
        )
        if managed:
            raise ValueError("model-bound and built-in agents cannot be deleted; disable them instead")
        self.database.delete_agent(agent_id)


def _json_list(values: list[str]) -> str:
    import json

    return json.dumps(values, ensure_ascii=False)
