from __future__ import annotations

import io
import json
import re
import secrets
import shlex
import zipfile
from typing import Any

MAX_PACKAGE_BYTES = 25 * 1024 * 1024
MAX_ENTRIES = 500
MAX_UNCOMPRESSED = 50 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SKILL_CHARS = 380_000
MANIFESTS = ("apkunpack-package.json", "manifest.json", "package.json")


class PackageError(ValueError):
    """Invalid or unsafe package."""


def _slug(value: str, fallback: str = "item") -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return (text or fallback)[:60]


def _read_json(data: bytes, path: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"{path}: invalid JSON ({exc})") from exc


def _read_files(payload: bytes) -> dict[str, bytes]:
    if len(payload) > MAX_PACKAGE_BYTES:
        raise PackageError("package is too large")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as exc:
        raise PackageError("file is not a valid ZIP archive") from exc
    infos = archive.infolist()
    if len(infos) > MAX_ENTRIES:
        raise PackageError(f"too many files in package (max {MAX_ENTRIES})")
    files: dict[str, bytes] = {}
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        if info.flag_bits & 0x1:
            raise PackageError(f"encrypted ZIP entries are not supported: {info.filename}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise PackageError(f"symbolic links are not allowed: {info.filename}")
        name = info.filename.replace("\\", "/")
        parts = name.split("/")
        if name.startswith("/") or any(part in ("", ".", "..") for part in parts):
            raise PackageError(f"unsafe ZIP path: {info.filename}")
        if info.file_size > MAX_FILE_BYTES:
            raise PackageError(f"file is too large: {info.filename}")
        total += info.file_size
        if total > MAX_UNCOMPRESSED:
            raise PackageError("package expands to too much data")
        try:
            files[name] = archive.read(info)
        except (RuntimeError, zipfile.BadZipFile) as exc:
            raise PackageError(f"cannot read {info.filename}: {exc}") from exc
    return files


def _front_matter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end = next((index for index in range(1, len(lines)) if lines[index].strip() == "---"), None)
    if end is None:
        return {}, text
    meta: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in ("name", "description", "id"):
            meta[key] = value.strip().strip("\"'")
    return meta, "\n".join(lines[end + 1 :]).lstrip("\n")


def _manifest(files: dict[str, bytes]) -> dict[str, Any]:
    for name in MANIFESTS:
        if name in files:
            value = _read_json(files[name], name)
            if not isinstance(value, dict):
                raise PackageError(f"{name} must contain a JSON object")
            return value
    return {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _load_item(item: Any, files: dict[str, bytes]) -> dict[str, Any] | str:
    if isinstance(item, str):
        path = item.replace("\\", "/").lstrip("./")
        if path not in files:
            raise PackageError(f"manifest references missing file: {item}")
        if path.lower().endswith(".json"):
            value = _read_json(files[path], path)
            if isinstance(value, dict):
                value.setdefault("_file", path)
                return value
            raise PackageError(f"{path} must contain a JSON object")
        return path
    if not isinstance(item, dict):
        raise PackageError("manifest items must be objects or file paths")
    file_path = item.get("file") or item.get("path") or item.get("_file")
    if file_path:
        path = str(file_path).replace("\\", "/").lstrip("./")
        if path not in files:
            raise PackageError(f"manifest references missing file: {file_path}")
        if path.lower().endswith(".json"):
            value = _read_json(files[path], path)
            if not isinstance(value, dict):
                raise PackageError(f"{path} must contain a JSON object")
            merged = dict(value)
            merged.update({key: val for key, val in item.items() if key not in ("file", "path", "_file")})
            merged["_file"] = path
            return merged
        item = dict(item)
        item["_file"] = path
    return item


def _skill_payload(item: Any, files: dict[str, bytes]) -> dict[str, Any]:
    item = _load_item(item, files)
    if isinstance(item, str):
        item = {"_file": item}
    file_path = str(item.get("_file") or "").strip()
    meta: dict[str, str] = {}
    content = str(item.get("content") or "").strip()
    if file_path:
        text = files[file_path].decode("utf-8", errors="replace")
        meta, body = _front_matter(text)
        if body.strip():
            content = body
        base = file_path.rsplit("/", 1)[0] if "/" in file_path else ""
        references: list[str] = []
        for other, data in files.items():
            if other == file_path or not other.lower().endswith(".md"):
                continue
            if other.lower().endswith("/skill.md") or other.lower() == "skill.md":
                continue
            if base:
                if not other.startswith(base + "/"):
                    continue
            elif not other.startswith("references/"):
                continue
            ref_text = data.decode("utf-8", errors="replace").strip()
            if ref_text:
                references.append(f"## Reference: {other}\n\n{ref_text}")
        if references:
            content = (content + "\n\n" + "\n\n".join(references)).strip()
    if not content:
        raise PackageError(f"skill has no content: {file_path or item.get('name') or 'unknown'}")
    name = str(item.get("name") or meta.get("name") or "").strip()
    if not name:
        if file_path:
            parts = file_path.split("/")
            name = parts[-2] if len(parts) > 1 and parts[-1].lower() == "skill.md" else parts[-1].rsplit(".", 1)[0]
        else:
            name = "Imported skill"
    default_id = None
    if file_path:
        parts = file_path.split("/")
        if (
            len(parts) >= 2
            and parts[-1].lower() == "skill.md"
            and parts[-2].lower() not in ("skills", "skill")
        ):
            default_id = _slug(parts[-2], "skill")
    skill_id = str(item.get("id") or meta.get("id") or default_id or "").strip().lower() or None
    description = str(item.get("description") or meta.get("description") or "").strip() or None
    return {
        "id": skill_id,
        "name": name[:160],
        "description": description[:300] if description else None,
        "content": content[:MAX_SKILL_CHARS],
        "enabled": bool(item.get("enabled", True)),
    }


def _mcp_payload(item: Any, files: dict[str, bytes]) -> dict[str, Any]:
    item = _load_item(item, files)
    if isinstance(item, str):
        raise PackageError("MCP entries must be JSON objects")
    if not isinstance(item, dict):
        raise PackageError("MCP entry must be an object")
    command = str(item.get("command") or "").strip()
    args = item.get("args")
    if command and isinstance(args, list):
        command = shlex.join([command] + [str(arg) for arg in args])
    url = str(item.get("url") or "").strip()
    transport = str(item.get("transport") or item.get("type") or "").strip().lower()
    if not transport:
        transport = "http" if url else "stdio"
    headers = item.get("headers") if isinstance(item.get("headers"), dict) else None
    env = item.get("env") if isinstance(item.get("env"), dict) else None
    return {
        "id": str(item.get("id") or "").strip().lower() or None,
        "name": str(item.get("name") or "").strip(),
        "transport": transport,
        "url": url or None,
        "command": command or None,
        "headers": headers,
        "env": env,
        "enabled": bool(item.get("enabled", True)),
    }


def _agent_payload(item: Any, files: dict[str, bytes]) -> dict[str, Any]:
    item = _load_item(item, files)
    if isinstance(item, str):
        raise PackageError("Agent entries must be JSON objects")
    if not isinstance(item, dict):
        raise PackageError("Agent entry must be an object")
    skills = item.get("skill_ids", item.get("skills"))
    mcps = item.get("mcp_ids", item.get("mcps"))
    return {
        "id": str(item.get("id") or "").strip().lower() or None,
        "name": str(item.get("name") or "").strip(),
        "provider_id": str(item.get("provider_id") or "").strip() or None,
        "provider_name": str(item.get("provider_name") or item.get("provider") or "").strip() or None,
        "skill_ids": [str(value) for value in _as_list(skills) if str(value).strip()],
        "mcp_ids": [str(value) for value in _as_list(mcps) if str(value).strip()],
        "system_prompt": str(item.get("system_prompt") or item.get("prompt") or ""),
        "enabled": bool(item.get("enabled", True)),
    }


def _collect(files: dict[str, bytes], manifest: dict[str, Any]) -> tuple[list[Any], list[Any], list[Any]]:
    skills: list[Any] = []
    mcps: list[Any] = []
    agents: list[Any] = []
    referenced: set[str] = set()

    def add_file(path: str, bucket: list[Any]) -> None:
        referenced.add(path)
        bucket.append({"_file": path})

    kind = str(manifest.get("type") or "").strip().lower()
    if kind in ("skill", "skills"):
        for value in _as_list(manifest.get("skill") or manifest):
            skills.append(value)
    elif kind in ("mcp", "mcps"):
        for value in _as_list(manifest.get("mcp") or manifest):
            mcps.append(value)
    elif kind in ("agent", "agents"):
        for value in _as_list(manifest.get("agent") or manifest):
            agents.append(value)

    for key, bucket in (("skills", skills), ("mcps", mcps), ("agents", agents)):
        for value in _as_list(manifest.get(key)):
            bucket.append(value)

    for path, data in files.items():
        lower = path.lower()
        if lower.endswith("/skill.md") or lower == "skill.md":
            if path not in referenced:
                add_file(path, skills)
        elif lower.startswith("mcp/") and lower.endswith(".json"):
            if path not in referenced:
                add_file(path, mcps)
        elif lower.startswith("agents/") and lower.endswith(".json"):
            if path not in referenced:
                add_file(path, agents)
        elif lower in ("mcp.json", "agent.json", "skills.json"):
            if path not in referenced:
                add_file(path, mcps if lower == "mcp.json" else agents)
        elif lower in (".mcp.json", "mcp-servers.json"):
            if path not in referenced:
                value = _read_json(data, path)
                servers = value.get("mcpServers") if isinstance(value, dict) else None
                if isinstance(servers, dict):
                    referenced.add(path)
                    for name, server in servers.items():
                        if isinstance(server, dict):
                            entry = dict(server)
                            entry.setdefault("name", name)
                            entry.setdefault("transport", "http" if entry.get("url") else "stdio")
                            mcps.append(entry)
    return skills, mcps, agents


def import_package(
    payload: bytes,
    *,
    filename: str,
    skills_store: Any,
    mcp_store: Any,
    agent_store: Any,
    providers_store: Any,
    owner_id: int | None = None,
    allow_stdio: bool = True,
) -> dict[str, Any]:
    files = _read_files(payload)
    if not files:
        raise PackageError("package is empty")
    manifest = _manifest(files)
    skill_items, mcp_items, agent_items = _collect(files, manifest)
    if not (skill_items or mcp_items or agent_items):
        raise PackageError("no installable Skill, MCP or Agent found in the ZIP")
    result: dict[str, Any] = {
        "package": filename,
        "detected": {"skills": len(skill_items), "mcps": len(mcp_items), "agents": len(agent_items)},
        "installed": {"skills": [], "mcps": [], "agents": []},
        "skipped": {"skills": [], "mcps": [], "agents": []},
        "errors": [],
    }

    skill_by_id: dict[str, str] = {}
    skill_by_name: dict[str, str] = {}
    for skill in skills_store.list(include_content=False, visible_to=owner_id):
        skill_by_id[str(skill.get("id"))] = str(skill.get("id"))
        skill_by_name[str(skill.get("name") or "").lower()] = str(skill.get("id"))

    mcp_by_id: dict[str, str] = {}
    mcp_by_name: dict[str, str] = {}
    for server in mcp_store.list(include_secrets=False, visible_to=owner_id):
        mcp_by_id[str(server.id)] = str(server.id)
        mcp_by_name[str(server.name or "").lower()] = str(server.id)

    for item in skill_items:
        try:
            data = _skill_payload(item, files)
        except Exception as exc:
            result["errors"].append(f"skill: {exc}")
            continue
        name = str(data["name"])
        existing_id = skill_by_name.get(name.lower())
        if existing_id:
            result["skipped"]["skills"].append({"id": existing_id, "name": name, "reason": "name exists"})
            continue
        desired = data.get("id")
        skill_id = str(desired or _slug(name, "skill"))
        if skill_id in skill_by_id:
            result["skipped"]["skills"].append({"id": skill_id, "name": name, "reason": "id exists"})
            continue
        try:
            created = skills_store.create(
                {
                    "id": skill_id,
                    "name": name,
                    "description": data.get("description") or "",
                    "content": data["content"],
                    "enabled": data.get("enabled", True),
                },
                owner_id=owner_id,
            )
        except Exception as exc:
            result["errors"].append(f"skill {name}: {exc}")
            continue
        actual = str(created.get("id"))
        skill_by_id[actual] = actual
        skill_by_id[skill_id] = actual
        skill_by_name[name.lower()] = actual
        result["installed"]["skills"].append({"id": actual, "name": name})

    for item in mcp_items:
        try:
            data = _mcp_payload(item, files)
        except Exception as exc:
            result["errors"].append(f"mcp: {exc}")
            continue
        name = str(data.get("name") or "").strip()
        if not name:
            result["errors"].append("mcp: name is required")
            continue
        if mcp_by_name.get(name.lower()):
            result["skipped"]["mcps"].append({"id": mcp_by_name[name.lower()], "name": name, "reason": "name exists"})
            continue
        desired = data.get("id")
        server_id = str(desired or _slug(name, "mcp"))
        if server_id in mcp_by_id:
            result["skipped"]["mcps"].append({"id": server_id, "name": name, "reason": "id exists"})
            continue
        if data.get("transport") == "stdio" and not allow_stdio:
            result["errors"].append(
                f"mcp {name}: stdio MCP servers require an administrator; import only http servers"
            )
            continue
        try:
            created = mcp_store.create({**data, "id": server_id}, owner_id=owner_id)
        except Exception as exc:
            result["errors"].append(f"mcp {name}: {exc}")
            continue
        actual = str(created.id)
        mcp_by_id[actual] = actual
        mcp_by_id[server_id] = actual
        mcp_by_name[name.lower()] = actual
        result["installed"]["mcps"].append({"id": actual, "name": name, "transport": created.transport})

    providers = providers_store.list(include_keys=False)
    provider_by_id = {str(provider.id): provider for provider in providers}
    provider_by_name = {str(provider.name or "").lower(): provider for provider in providers}
    agent_by_name = {str(agent.name or "").lower(): agent for agent in agent_store.list(visible_to=owner_id)}
    for item in agent_items:
        try:
            data = _agent_payload(item, files)
        except Exception as exc:
            result["errors"].append(f"agent: {exc}")
            continue
        name = str(data.get("name") or "").strip()
        if not name:
            result["errors"].append("agent: name is required")
            continue
        existing = agent_store.get(data.get("id") or _slug(name, "agent")) or agent_by_name.get(name.lower())
        if existing:
            result["skipped"]["agents"].append({"id": existing.id, "name": name, "reason": "name exists"})
            continue
        provider = provider_by_id.get(str(data.get("provider_id") or ""))
        if provider is None and data.get("provider_name"):
            provider = provider_by_name.get(str(data["provider_name"]).lower())
        if provider is None and len(providers) == 1:
            provider = providers[0]
        if provider is None:
            result["errors"].append(f"agent {name}: provider_id/provider_name is required and must exist")
            continue
        skill_ids: list[str] = []
        missing: list[str] = []
        for reference in data["skill_ids"]:
            actual = skill_by_id.get(reference) or skill_by_name.get(reference.lower())
            if actual:
                skill_ids.append(actual)
            else:
                missing.append(f"skill:{reference}")
        mcp_ids: list[str] = []
        for reference in data["mcp_ids"]:
            actual = mcp_by_id.get(reference) or mcp_by_name.get(reference.lower())
            if actual:
                mcp_ids.append(actual)
            else:
                missing.append(f"mcp:{reference}")
        if missing:
            result["errors"].append(f"agent {name}: missing references: {', '.join(missing)}")
            continue
        try:
            created = agent_store.create(
                {
                    "id": data.get("id") or _slug(name, "agent"),
                    "name": name,
                    "provider_id": provider.id,
                    "skill_ids": skill_ids,
                    "mcp_ids": mcp_ids,
                    "system_prompt": data.get("system_prompt") or "",
                    "enabled": data.get("enabled", True),
                },
                owner_id=owner_id,
            )
        except Exception as exc:
            result["errors"].append(f"agent {name}: {exc}")
            continue
        result["installed"]["agents"].append({"id": created.id, "name": created.name, "provider_id": provider.id})

    result["ok"] = not result["errors"]
    result["summary"] = {
        "installed": sum(len(values) for values in result["installed"].values()),
        "skipped": sum(len(values) for values in result["skipped"].values()),
        "errors": len(result["errors"]),
    }
    return result
