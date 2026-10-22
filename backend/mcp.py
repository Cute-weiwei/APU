from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import secrets
import shlex
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import BackendConfig
from .security import chmod_private, redact

MCP_PROTOCOL_VERSION = "2025-06-18"


def _slug(value: str, fallback: str = "mcp") -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return (text or fallback)[:48]


def tool_alias(server_id: str, tool_name: str) -> str:
    raw = f"mcp__{_slug(server_id, 'server')}__{re.sub(r'[^A-Za-z0-9_]+', '_', tool_name)}"
    if len(raw) <= 64:
        return raw
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
    return raw[:55] + "_" + digest


@dataclass
class McpServerConfig:
    id: str
    name: str
    transport: str
    url: str | None = None
    command: str | None = None
    enabled: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    last_status: str | None = None
    last_checked_at: str | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    owner_id: int | None = None

    @property
    def available(self) -> bool:
        if not self.enabled:
            return False
        return bool(self.url) if self.transport == "http" else bool(self.command)

    @property
    def reason(self) -> str:
        if not self.enabled:
            return "disabled"
        if self.transport == "http" and not self.url:
            return "missing url"
        if self.transport == "stdio" and not self.command:
            return "missing command"
        return "configured"

    def public(self, admin: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "transport": self.transport,
            "url": self.url,
            "command": self.command,
            "enabled": self.enabled,
            "available": self.available,
            "reason": self.reason,
            "last_status": self.last_status,
            "last_checked_at": self.last_checked_at,
            "tools": self.tools,
            "tool_count": len(self.tools),
            "has_secrets": bool(self.headers or self.env),
            "owner_id": self.owner_id,
            "shared": self.owner_id is None,
        }
        if admin:
            data["header_names"] = sorted(self.headers)
            data["env_names"] = sorted(self.env)
        return data


class McpStore:
    def __init__(self, config: BackendConfig, database: Any):
        self.config = config
        self.database = database

    def _secret_path(self, server_id: str) -> Path:
        return self.config.secrets_dir / f"mcp-{_slug(server_id)}.json"

    def _read_secret(self, server_id: str) -> dict[str, dict[str, str]]:
        try:
            value = json.loads(self._secret_path(server_id).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"headers": {}, "env": {}}
        headers = value.get("headers") if isinstance(value.get("headers"), dict) else {}
        env = value.get("env") if isinstance(value.get("env"), dict) else {}
        return {
            "headers": {str(k): str(v) for k, v in headers.items()},
            "env": {str(k): str(v) for k, v in env.items()},
        }

    def _write_secret(self, server_id: str, headers: dict[str, str], env: dict[str, str]) -> None:
        path = self._secret_path(server_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"headers": headers, "env": env}, ensure_ascii=False, indent=2)
        fd, temp_name = tempfile.mkstemp(prefix=".mcp-secret-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload + "\n")
            os.replace(temp_name, path)
            chmod_private(path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _delete_secret(self, server_id: str) -> None:
        try:
            self._secret_path(server_id).unlink(missing_ok=True)
        except OSError:
            pass

    def _from_row(self, row: dict[str, Any], include_secrets: bool = True) -> McpServerConfig:
        secret = self._read_secret(row["id"]) if include_secrets else {"headers": {}, "env": {}}
        return McpServerConfig(
            id=str(row["id"]),
            name=str(row["name"]),
            transport=str(row["transport"]),
            url=row.get("url"),
            command=row.get("command"),
            enabled=bool(row.get("enabled", 1)),
            headers=secret["headers"],
            env=secret["env"],
            last_status=row.get("last_status"),
            last_checked_at=row.get("last_checked_at"),
            tools=row.get("tools") or [],
            owner_id=row.get("owner_id"),
        )

    def list(self, include_secrets: bool = False, visible_to: int | None = None) -> list[McpServerConfig]:
        return [
            self._from_row(row, include_secrets)
            for row in self.database.list_mcp_servers(visible_to=visible_to)
        ]

    def get(self, server_id: str, include_secrets: bool = True) -> McpServerConfig | None:
        row = self.database.get_mcp_server(server_id)
        return self._from_row(row, include_secrets) if row else None

    def resolve(self, server_ids: list[str] | None) -> list[McpServerConfig]:
        result = []
        for server_id in server_ids or []:
            server = self.get(server_id, include_secrets=True)
            if server and server.available:
                result.append(server)
        return result

    def _validate(self, data: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, Any]:
        merged = dict(current or {})
        merged.update({key: value for key, value in data.items() if value is not None})
        name = str(merged.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        transport = str(merged.get("transport") or "").strip().lower()
        if transport not in ("http", "stdio"):
            raise ValueError("transport must be 'http' or 'stdio'")
        url = str(merged.get("url") or "").strip() or None
        command = str(merged.get("command") or "").strip() or None
        if transport == "http":
            if not url or not re.match(r"^https?://", url, flags=re.I):
                raise ValueError("url must start with http:// or https://")
            command = None
        else:
            if not command:
                raise ValueError("command is required for stdio MCP servers")
            url = None
        return {
            "name": name[:120],
            "transport": transport,
            "url": url[:1000] if url else None,
            "command": command[:4000] if command else None,
            "enabled": 1 if data.get("enabled", merged.get("enabled", True)) else 0,
        }

    def create(self, data: dict[str, Any], owner_id: int | None = None) -> McpServerConfig:
        fields = self._validate(data, {"enabled": True})
        server_id = str(data.get("id") or "").strip().lower()
        if server_id:
            if not re.match(r"^[a-z0-9][a-z0-9_-]{1,63}$", server_id):
                raise ValueError("id must match [a-z0-9][a-z0-9_-]{1,63}")
        else:
            server_id = _slug(fields["name"], "mcp") + "-" + secrets.token_hex(3)
        if self.database.get_mcp_server(server_id):
            raise ValueError(f"MCP server already exists: {server_id}")
        self.database.create_mcp_server(server_id, owner_id=owner_id, **fields)
        headers = _string_map(data.get("headers"))
        env = _string_map(data.get("env"))
        if headers or env:
            self._write_secret(server_id, headers, env)
        return self.get(server_id) or self.get(server_id, include_secrets=False)  # type: ignore[return-value]

    def update(self, server_id: str, data: dict[str, Any]) -> McpServerConfig:
        row = self.database.get_mcp_server(server_id)
        if not row:
            raise KeyError(server_id)
        fields = self._validate(data, row)
        self.database.update_mcp_server(server_id, **fields)
        current = self._read_secret(server_id)
        headers = dict(current["headers"])
        env = dict(current["env"])
        if data.get("clear_secrets"):
            headers, env = {}, {}
        if "headers" in data:
            headers = _string_map(data.get("headers"))
        if "env" in data:
            env = _string_map(data.get("env"))
        if headers or env:
            self._write_secret(server_id, headers, env)
        else:
            self._delete_secret(server_id)
        server = self.get(server_id)
        if server is None:  # pragma: no cover
            raise RuntimeError("MCP server update failed")
        return server

    def delete(self, server_id: str) -> None:
        if not self.database.get_mcp_server(server_id):
            raise KeyError(server_id)
        self.database.delete_mcp_server(server_id)
        self._delete_secret(server_id)

    def mark_test(self, server_id: str, status: str, tools: list[dict[str, Any]] | None = None) -> None:
        from datetime import datetime, timezone

        self.database.update_mcp_server(
            server_id,
            last_status=status[:2000],
            last_checked_at=datetime.now(timezone.utc).isoformat(),
            tools_json=json.dumps(tools or [], ensure_ascii=False),
        )


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, item in value.items():
        name = str(key).strip()
        if name:
            result[name[:200]] = str(item)[:8000]
    return result


class McpClient:
    """Minimal MCP client for HTTP JSON-RPC and stdio transports."""

    def __init__(self, server: McpServerConfig, timeout_s: float = 30):
        self.server = server
        self.timeout_s = max(1.0, float(timeout_s))
        self._id = 0
        self._session_id: str | None = None
        self._process: subprocess.Popen | None = None
        self._stdin = None
        self._stdout_queue: queue.Queue[str | None] | None = None
        self._reader: threading.Thread | None = None
        self._stderr: list[str] = []
        self._stderr_thread: threading.Thread | None = None

    # ------------------------------------------------------------------ public
    def connect(self) -> dict[str, Any]:
        if self.server.transport == "stdio":
            self._start_stdio()
        result = self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "apu-web", "version": "0.1.0"},
            },
        )
        self._notify("notifications/initialized", {})
        return result if isinstance(result, dict) else {}

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._request("tools/list", {})
        tools = result.get("tools") if isinstance(result, dict) else []
        if not isinstance(tools, list):
            return []
        cleaned = []
        for tool in tools:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            schema = tool.get("inputSchema") or tool.get("input_schema") or {"type": "object", "properties": {}}
            if not isinstance(schema, dict):
                schema = {"type": "object", "properties": {}}
            cleaned.append(
                {
                    "name": str(tool["name"]),
                    "description": str(tool.get("description") or "")[:2000],
                    "input_schema": schema,
                }
            )
        return cleaned

    def call_tool(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        result = self._request("tools/call", {"name": name, "arguments": arguments or {}})
        return result if isinstance(result, dict) else {"content": []}

    def close(self) -> None:
        process = self._process
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        self._process = None
        self._stdin = None

    # ------------------------------------------------------------------ requests
    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        request_id = self._id
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        if self.server.transport == "http":
            response = self._http_post(payload)
        else:
            response = self._stdio_request(payload, request_id)
        if not isinstance(response, dict):
            raise RuntimeError(f"MCP {method} returned no JSON-RPC response")
        error = response.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise RuntimeError(f"MCP {method} error: {message}")
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        try:
            if self.server.transport == "http":
                self._http_post(payload, notify=True)
            elif self._stdin is not None:
                self._stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
                self._stdin.flush()
        except Exception:
            pass

    # ------------------------------------------------------------------ http
    def _http_post(self, payload: dict[str, Any], notify: bool = False) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "apu-web/0.1.0",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        headers.update(self.server.headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.server.url or "", data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self._session_id = session_id
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:1000]
            except Exception:
                pass
            raise RuntimeError(f"MCP HTTP {exc.code}: {redact(detail)}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"MCP HTTP request failed: {redact(str(exc))}") from exc
        if notify or not raw.strip():
            return {}
        return _parse_http_body(raw)

    # ------------------------------------------------------------------ stdio
    def _start_stdio(self) -> None:
        command = shlex.split(self.server.command or "", posix=(os.name != "nt"))
        if not command:
            raise RuntimeError("empty MCP stdio command")
        env = os.environ.copy()
        env.update(self.server.env)
        env.setdefault("PYTHONUNBUFFERED", "1")
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            start_new_session=(os.name != "nt"),
        )
        self._stdin = self._process.stdin
        self._stdout_queue = queue.Queue()

        def reader() -> None:
            assert self._process is not None and self._process.stdout is not None
            try:
                for line in iter(self._process.stdout.readline, ""):
                    if self._stdout_queue is not None:
                        self._stdout_queue.put(line)
            finally:
                if self._stdout_queue is not None:
                    self._stdout_queue.put(None)

        def stderr_reader() -> None:
            assert self._process is not None and self._process.stderr is not None
            try:
                for line in iter(self._process.stderr.readline, ""):
                    self._stderr.append(redact(line.rstrip()))
                    del self._stderr[:-40]
            except Exception:
                pass

        self._reader = threading.Thread(target=reader, daemon=True)
        self._reader.start()
        self._stderr_thread = threading.Thread(target=stderr_reader, daemon=True)
        self._stderr_thread.start()

    def _stdio_request(self, payload: dict[str, Any], request_id: int) -> dict[str, Any]:
        if self._stdin is None or self._stdout_queue is None:
            raise RuntimeError("MCP stdio session is not started")
        try:
            self._stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._stdin.flush()
        except OSError as exc:
            raise RuntimeError(f"MCP stdio write failed: {exc}") from exc
        deadline = time.monotonic() + self.timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stderr = " | ".join(self._stderr[-5:])
                raise RuntimeError(f"MCP stdio request timed out{(': ' + stderr) if stderr else ''}")
            try:
                line = self._stdout_queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                if self._process is not None and self._process.poll() is not None:
                    stderr = " | ".join(self._stderr[-5:])
                    raise RuntimeError(f"MCP stdio process exited ({self._process.returncode}){(': ' + stderr) if stderr else ''}")
                continue
            if line is None:
                stderr = " | ".join(self._stderr[-5:])
                raise RuntimeError(f"MCP stdio stream closed{(': ' + stderr) if stderr else ''}")
            text = line.strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message


def _parse_http_body(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("{"):
        try:
            value = json.loads(text)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            pass
    messages: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            candidate = line[5:].strip()
            if not candidate or candidate == "[DONE]":
                continue
            try:
                value = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                messages.append(value)
    if not messages:
        return {}
    for message in messages:
        if "result" in message or "error" in message:
            return message
    return messages[-1]


def mcp_result_text(result: dict[str, Any]) -> str:
    content = result.get("content") if isinstance(result, dict) else None
    parts: list[str] = []
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                parts.append(str(block.get("text") or ""))
            elif block.get("type") == "resource":
                resource = block.get("resource") or {}
                parts.append(str(resource.get("text") or resource.get("uri") or ""))
            else:
                parts.append(json.dumps(block, ensure_ascii=False, default=str))
    if not parts and isinstance(result, dict):
        parts.append(json.dumps(result, ensure_ascii=False, default=str))
    return "\n".join(part for part in parts if part)


def test_mcp_server(server: McpServerConfig, timeout_s: float = 30) -> dict[str, Any]:
    started = time.monotonic()
    client = McpClient(server, timeout_s=timeout_s)
    try:
        info = client.connect()
        tools = client.list_tools()
        return {
            "ok": True,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "transport": server.transport,
            "server_info": info.get("serverInfo") if isinstance(info, dict) else None,
            "protocol_version": info.get("protocolVersion") if isinstance(info, dict) else None,
            "tools": tools,
        }
    finally:
        client.close()
