from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from .config import REPO_ROOT
from .domain.errors import fail

SKILL_NAME = "unpack-android-apk"


def _claude_skills_dir() -> Path:
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    base = Path(config_dir).expanduser() if config_dir else Path.home() / ".claude"
    return base / "skills"


def _skill_backup_root() -> Path:
    """Keep backups outside ~/.claude/skills so clients do not discover them."""

    return _claude_skills_dir().parent / ".apu-backups"


def _server_entry() -> dict[str, Any]:
    return {
        "command": sys.executable,
        "args": ["-m", "apk_unpack", "mcp"],
        "env": {"PYTHONPATH": str((REPO_ROOT / "src").resolve())},
    }


def build_plan(
    *,
    client: str = "claude_code",
    project_dir: str | Path | None = None,
    uninstall: bool = False,
) -> dict[str, Any]:
    if client not in ("claude_code", "generic"):
        raise fail("invalid_input", f"unsupported client: {client}; use claude_code or generic")
    project = Path(project_dir).expanduser().resolve() if project_dir else Path.cwd().resolve()
    skill_source = REPO_ROOT / ".agents" / "skills" / SKILL_NAME
    if client == "generic":
        return {
            "client": client,
            "uninstall": uninstall,
            "changes": [],
            "instructions": {
                "mcp": {
                    "mcpServers": {"apk-unpack": _server_entry()},
                },
                "skill": str(skill_source),
                "note": "Generic client: paste the MCP snippet into the client configuration and install the skill directory manually.",
            },
        }
    skill_dest = _claude_skills_dir() / SKILL_NAME
    mcp_path = project / ".mcp.json"
    changes: list[dict[str, Any]] = []
    if uninstall:
        changes.append({"action": "remove_skill", "path": str(skill_dest)})
        changes.append({"action": "remove_mcp_entry", "path": str(mcp_path), "key": "apk-unpack"})
    else:
        changes.append({"action": "copy_skill", "source": str(skill_source), "path": str(skill_dest)})
        changes.append({"action": "merge_mcp", "path": str(mcp_path), "key": "apk-unpack", "value": _server_entry()})
    return {
        "client": client,
        "project_dir": str(project),
        "uninstall": uninstall,
        "changes": changes,
        "server_entry": _server_entry(),
    }


def apply_plan(plan: dict[str, Any]) -> dict[str, Any]:
    if plan.get("uninstall"):
        return _uninstall(plan)
    applied: list[dict[str, Any]] = []
    for change in plan.get("changes") or []:
        if change["action"] == "copy_skill":
            source = Path(change["source"])
            destination = Path(change["path"])
            if not source.is_dir():
                raise fail("invalid_input", f"skill source not found: {source}")
            if destination.exists():
                backup_root = _skill_backup_root()
                backup_root.mkdir(parents=True, exist_ok=True)
                backup = backup_root / (destination.name + "-" + time.strftime("%Y%m%d%H%M%S"))
                shutil.move(str(destination), str(backup))
                applied.append({"action": "backup_skill", "path": str(backup)})
            shutil.copytree(source, destination)
            (destination / ".apu-managed.json").write_text(
                json.dumps({"owned_by": "apk-unpack-agents", "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")}, indent=2),
                encoding="utf-8",
            )
            applied.append({"action": "copy_skill", "path": str(destination)})
        elif change["action"] == "merge_mcp":
            path = Path(change["path"])
            data: dict[str, Any] = {}
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise fail("integrity_mismatch", f"existing MCP config is not valid JSON: {exc}", details={"path": str(path)})
                backup = path.with_name(path.name + ".apu.bak-" + time.strftime("%Y%m%d%H%M%S"))
                shutil.copy2(path, backup)
                applied.append({"action": "backup_mcp", "path": str(backup)})
            servers = data.setdefault("mcpServers", {})
            servers[change["key"]] = change["value"]
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_name(path.name + ".tmp")
            temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            os.replace(temp, path)
            applied.append({"action": "merge_mcp", "path": str(path), "key": change["key"]})
    return {"ok": True, "applied": applied}


def _uninstall(plan: dict[str, Any]) -> dict[str, Any]:
    applied: list[dict[str, Any]] = []
    for change in plan.get("changes") or []:
        if change["action"] == "remove_skill":
            destination = Path(change["path"])
            manifest = destination / ".apu-managed.json"
            if destination.exists() and manifest.is_file():
                shutil.rmtree(destination)
                applied.append({"action": "remove_skill", "path": str(destination)})
            elif destination.exists():
                applied.append({"action": "skip_unowned_skill", "path": str(destination)})
        elif change["action"] == "remove_mcp_entry":
            path = Path(change["path"])
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                raise fail("integrity_mismatch", f"existing MCP config is not valid JSON: {path}")
            servers = data.get("mcpServers")
            if isinstance(servers, dict) and change["key"] in servers:
                servers.pop(change["key"])
                temp = path.with_name(path.name + ".tmp")
                temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                os.replace(temp, path)
                applied.append({"action": "remove_mcp_entry", "path": str(path)})
    return {"ok": True, "applied": applied}
