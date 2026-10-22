from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any

from .config import BackendConfig
from .skill_content import read_skill_bundle

BUILTIN_SKILL_ID = "unpack-android-apk"


def _slug(value: str, fallback: str = "skill") -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return (text or fallback)[:48]


def _description(text: str) -> str:
    match = re.search(r"(?mi)^description:\s*(.+)$", text[:4000])
    if match:
        return match.group(1).strip().strip("\"'")[:300]
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#") or value in ("---",):
            continue
        return value[:300]
    return ""


class SkillStore:
    """Built-in skill files plus user-editable generic skills stored in SQLite."""

    def __init__(self, config: BackendConfig, database: Any):
        self.config = config
        self.database = database

    def seed(self) -> None:
        if self.database.get_skill(BUILTIN_SKILL_ID):
            return
        path = self.config.skills_root / BUILTIN_SKILL_ID / "SKILL.md"
        text = ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        self.database.create_skill(
            BUILTIN_SKILL_ID,
            "APK 脱壳（内置）",
            _description(text) or "Android APK shell unpacking workflow",
            source="builtin",
            path=str(path),
            content=None,
            enabled=1,
        )

    def _builtin_content(self, row: dict[str, Any]) -> str:
        path_text = row.get("path")
        if path_text:
            return read_skill_bundle(path_text)[0]
        return str(row.get("content") or "")

    def _public(self, row: dict[str, Any], include_content: bool = True) -> dict[str, Any]:
        content = self._builtin_content(row) if row.get("source") == "builtin" else str(row.get("content") or "")
        data: dict[str, Any] = {
            "id": row["id"],
            "name": row["name"],
            "description": row.get("description") or _description(content),
            "source": row.get("source") or "custom",
            "enabled": bool(row.get("enabled", 1)),
            "builtin": row.get("source") == "builtin",
            "path": row.get("path"),
            "chars": len(content),
            "references": read_skill_bundle(row["path"])[1] if row.get("source") == "builtin" and row.get("path") else [],
            "owner_id": row.get("owner_id"),
            "shared": row.get("owner_id") is None,
            "updated_at": row.get("updated_at"),
        }
        if include_content:
            data["content"] = content[:400_000]
        return data

    def list(self, include_content: bool = True, visible_to: int | None = None) -> list[dict[str, Any]]:
        return [
            self._public(row, include_content=include_content)
            for row in self.database.list_skills(visible_to=visible_to)
        ]

    def get(self, skill_id: str, include_content: bool = True) -> dict[str, Any] | None:
        row = self.database.get_skill(skill_id)
        return self._public(row, include_content=include_content) if row else None

    def create(self, data: dict[str, Any], owner_id: int | None = None) -> dict[str, Any]:
        name = str(data.get("name") or "").strip()
        content = str(data.get("content") or "").strip()
        if not name:
            raise ValueError("name is required")
        if not content:
            raise ValueError("content is required")
        skill_id = str(data.get("id") or "").strip().lower()
        if skill_id:
            if not re.match(r"^[a-z0-9][a-z0-9_-]{1,63}$", skill_id):
                raise ValueError("id must match [a-z0-9][a-z0-9_-]{1,63}")
        else:
            skill_id = _slug(name, "skill") + "-" + secrets.token_hex(3)
        if self.database.get_skill(skill_id):
            raise ValueError(f"skill already exists: {skill_id}")
        self.database.create_skill(
            skill_id,
            name[:160],
            str(data.get("description") or _description(content))[:300],
            source="custom",
            path=None,
            content=content[:400_000],
            enabled=1 if data.get("enabled", True) else 0,
            owner_id=owner_id,
        )
        return self.get(skill_id) or {}

    def update(self, skill_id: str, data: dict[str, Any]) -> dict[str, Any]:
        row = self.database.get_skill(skill_id)
        if not row:
            raise KeyError(skill_id)
        if row.get("source") == "builtin":
            changes: dict[str, Any] = {}
            if "enabled" in data:
                changes["enabled"] = 1 if data["enabled"] else 0
            self.database.update_skill(skill_id, **changes)
            return self.get(skill_id) or {}
        changes = {}
        if "name" in data:
            name = str(data.get("name") or "").strip()
            if not name:
                raise ValueError("name must not be empty")
            changes["name"] = name[:160]
        if "description" in data:
            changes["description"] = str(data.get("description") or "")[:300]
        if "content" in data:
            content = str(data.get("content") or "").strip()
            if not content:
                raise ValueError("content must not be empty")
            changes["content"] = content[:400_000]
            if "description" not in data:
                changes["description"] = _description(content)
        if "enabled" in data:
            changes["enabled"] = 1 if data["enabled"] else 0
        self.database.update_skill(skill_id, **changes)
        return self.get(skill_id) or {}

    def delete(self, skill_id: str) -> None:
        row = self.database.get_skill(skill_id)
        if not row:
            raise KeyError(skill_id)
        if row.get("source") == "builtin":
            raise ValueError("the built-in skill cannot be deleted")
        self.database.delete_skill(skill_id)

    def resolve(self, skill_ids: list[str] | None) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        for skill_id in skill_ids or []:
            row = self.database.get_skill(skill_id)
            if not row or not row.get("enabled", 1):
                continue
            content = self._builtin_content(row) if row.get("source") == "builtin" else str(row.get("content") or "")
            if not content.strip():
                continue
            docs.append(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "description": row.get("description") or "",
                    "content": content[:200_000],
                    "source": row.get("source") or "custom",
                    "references": read_skill_bundle(row["path"])[1] if row.get("source") == "builtin" and row.get("path") else [],
                }
            )
        return docs
