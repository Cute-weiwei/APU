from __future__ import annotations

import email
import email.parser
import email.policy
import json
import mimetypes
import queue
import re
import secrets
import shutil
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

from apk_unpack.contracts.tools import TOOL_SPECS, TOOLS_BY_NAME
from apk_unpack.domain.errors import AnalysisError, project_error

from .chat import ChatError, ChatService
from .config import BackendConfig
from .db import Database
from .engines import DEVICE_TOOLS, RUN_SCOPED, list_provider_models, test_provider
from .events import EventBus
from .job_options import normalize_job_options
from .jobs import JobManager
from .mcp import test_mcp_server
from .packages import PackageError, import_package
from .providers import MODEL_PRESETS, PROTOCOL_DEFAULTS, PROVIDER_PRESETS, ProviderConfig
from .security import (
    chmod_private,
    hash_password,
    is_zip,
    new_token,
    redact,
    safe_filename,
    sha256_file,
    token_hash,
    verify_password,
)


class LoginLimiter:
    def __init__(self, attempts: int = 5, window_s: int = 600):
        self.attempts = attempts
        self.window_s = window_s
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str) -> list[float]:
        now = time.monotonic()
        values = [value for value in self._failures.get(key, []) if now - value < self.window_s]
        if values:
            self._failures[key] = values
        else:
            self._failures.pop(key, None)
        return values

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key)) >= self.attempts

    def failure(self, key: str) -> None:
        with self._lock:
            values = self._prune(key)
            values.append(time.monotonic())
            self._failures[key] = values

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class BackendApp:
    def __init__(self, config: BackendConfig):
        self.config = config
        self.database = Database(config.db_path)
        self.bus = EventBus(self.database)
        self.jobs: JobManager | None = None
        self.chat: ChatService | None = None
        self.limiter = LoginLimiter()
        self.started_at = time.time()
        # Idempotency cache for POST /jobs/{id}/retry (user id + key -> job id).
        self.retry_lock = threading.Lock()
        self.retry_cache: dict[tuple[int, str], str] = {}
        # MCP run ownership for runs created directly through /mcp (runs created
        # by backend jobs are owned via the jobs table) and active per-request
        # cancellation events.
        self.mcp_lock = threading.Lock()
        self.mcp_run_owners: dict[str, int] = {}
        self.mcp_cancels: dict[str, threading.Event] = {}

    # ------------------------------------------------------------------ bootstrap
    def initialize(self) -> None:
        self.config.ensure_dirs()
        self.database.initialize()
        self.database.cleanup_sessions()
        self._bootstrap_admin()
        self.jobs = JobManager(self.config, self.database, self.bus)
        self.jobs.seed_catalog()
        self.chat = ChatService(self.jobs)
        if self.config.redroid_addr:
            for _ in range(60):
                try:
                    self.jobs.service.adb.run(["connect", self.config.redroid_addr], timeout=10)
                    devices = self.jobs.service.adb.devices()
                    if any(
                        item.serial == self.config.redroid_addr and item.state == "device"
                        for item in devices
                    ):
                        break
                except Exception:
                    pass
                time.sleep(2)
        self.jobs.start()

    def _bootstrap_admin(self) -> None:
        if self.database.count_users() > 0:
            return
        username = self.config.admin_user or "admin"
        password = self.config.admin_password
        generated = False
        if not password:
            password = secrets.token_urlsafe(12)
            generated = True
            path = self.config.data_dir / "admin_password.txt"
            path.write_text(password + "\n", encoding="utf-8")
            chmod_private(path)
        salt, digest = hash_password(password)
        self.database.create_user(username, digest, salt, "admin")
        self.database.audit(None, "admin.bootstrap", username)
        if generated:
            print(f"[apu-web] initial admin user: {username}")
            print(f"[apu-web] generated password written to {self.config.data_dir / 'admin_password.txt'}")

    def create_admin(self, username: str, password: str, reset: bool = False) -> dict[str, Any]:
        existing = self.database.get_user_by_name(username)
        salt, digest = hash_password(password)
        if existing:
            if reset:
                self.database.update_user(int(existing["id"]), password_hash=digest, salt=salt, role="admin", disabled=0)
            return self.database.get_user(int(existing["id"])) or {}
        user = self.database.create_user(username, digest, salt, "admin")
        self.database.audit(None, "admin.create", username)
        return user

    # ------------------------------------------------------------------ helpers
    def engine_public(self, admin: bool = False) -> dict[str, Any]:
        if self.jobs is None:
            return {}
        return self.jobs.engine_public(admin=admin)

    @staticmethod
    def _device_kind(serial: str, attrs: dict[str, Any] | None = None) -> str:
        text = str(serial or "").lower()
        blob = f"{text} {attrs or ''}".lower()
        if text.startswith("emulator-") or "emulator" in blob:
            return "emulator"
        if "redroid" in blob:
            return "redroid"
        if ":" in text or "." in text:
            return "network"
        return "usb"

    @staticmethod
    def _normalize_device_serial(serial: str) -> str:
        value = str(serial or "").strip()
        if not value or ":" in value or value.startswith("emulator-"):
            return value
        # adb connect defaults to 5555; make a bare host usable as-is.
        if value == "localhost" or "." in value or value.startswith("127."):
            return value + ":5555"
        return value

    @staticmethod
    def _auto_device_name(serial: str, kind: str) -> str:
        if ":" in serial:
            host, _, port = serial.rpartition(":")
            if port.isdigit():
                return f"{kind}-{port}" if kind not in ("auto", "network") else f"device-{port}"
            return serial
        return serial

    @staticmethod
    def _registry_public(record: dict[str, Any], *, connected: bool) -> dict[str, Any]:
        return {
            "serial": record.get("serial"),
            "name": record.get("name") or record.get("serial"),
            "kind": record.get("kind") or "auto",
            "address": record.get("address") or record.get("serial"),
            "notes": record.get("notes") or "",
            "enabled": bool(record.get("enabled", 1)),
            "source": record.get("source") or "manual",
            "connected": connected,
            "state": "device" if connected else "offline",
            "arch": record.get("arch") or "",
            "last_seen_at": record.get("last_seen_at"),
            "attrs": {},
        }

    def device_list(self, include_hidden: bool = False) -> list[dict[str, Any]]:
        """Merge live adb discovery with the persisted device registry.

        Every connected adb device is auto-registered on each refresh, so jobs
        and chat can refer to devices even after they go offline. Manually
        registered devices stay visible as ``offline`` until they connect.
        Hidden (deleted) devices stay filtered unless ``include_hidden`` is
        requested by an explicit add/scan operation.
        """
        discovered: list[dict[str, Any]] = []
        error: dict[str, Any] | None = None
        hidden = set()
        if not include_hidden:
            hidden = {
                str(item.get("serial"))
                for item in self.database.list_devices(include_hidden=True)
                if item.get("hidden")
            }
        if self.jobs is not None:
            try:
                discovered = [item.to_dict() for item in self.jobs.service.adb.devices()]
            except AnalysisError as exc:
                error = exc.projection()
            except Exception as exc:  # pragma: no cover - defensive
                error = {"code": "device_scan_failed", "message": redact(str(exc))}
        identity_of = (
            getattr(self.jobs, "device_identity", None) if self.jobs is not None else None
        )
        hidden_ids: set[str] = set()
        if hidden and callable(identity_of):
            for item in discovered:
                serial = str(item.get("serial") or "")
                if serial in hidden:
                    identity = identity_of(serial)
                    if str(identity).startswith("pidns:"):
                        hidden_ids.add(identity)
        if hidden_ids:
            discovered = [
                item
                for item in discovered
                if str(item.get("serial") or "") not in hidden
                and identity_of(str(item.get("serial") or "")) not in hidden_ids
            ]
        else:
            discovered = [
                item for item in discovered if str(item.get("serial") or "") not in hidden
            ]
        # One redroid can be listed twice (for example emulator-5554 and
        # 127.0.0.1:5555). Show and schedule only the preferred transport so
        # the UI does not offer two serials for one device.
        dropped: set[str] = set()
        if self.jobs is not None:
            try:
                connected = [
                    str(item.get("serial") or "")
                    for item in discovered
                    if str(item.get("state") or "") == "device"
                ]
                keep = set(self.jobs.dedupe_serials(connected))
                dropped = {serial for serial in connected if serial and serial not in keep}
                if dropped:
                    discovered = [
                        item for item in discovered if str(item.get("serial") or "") not in dropped
                    ]
            except Exception:
                dropped = set()
        online: set[str] = set()
        for item in discovered:
            serial = str(item.get("serial") or "")
            if not serial:
                continue
            attrs = item.get("attrs") if isinstance(item.get("attrs"), dict) else {}
            state = str(item.get("state") or "")
            connected = state == "device"
            name = str(attrs.get("model") or attrs.get("product") or attrs.get("device") or serial)
            kind = self._device_kind(serial, attrs)
            record = self.database.upsert_device(
                serial, name=name, kind=kind, address=serial, source="auto", seen=connected
            )
            item.update(
                {
                    "name": record.get("name") or name,
                    "kind": record.get("kind") or kind,
                    "address": record.get("address") or serial,
                    "notes": record.get("notes") or "",
                    "enabled": bool(record.get("enabled", 1)),
                    "source": record.get("source") or "auto",
                    "connected": connected,
                    "arch": record.get("arch") or "",
                    "last_seen_at": record.get("last_seen_at"),
                }
            )
            if connected:
                online.add(serial)
        for record in self.database.list_devices(include_hidden=include_hidden):
            serial = str(record.get("serial") or "")
            if not serial or serial in online or serial in dropped:
                continue
            if hidden_ids and callable(identity_of) and identity_of(serial) in hidden_ids:
                continue
            # A discovered but offline device is already in `discovered`.
            merged = next((item for item in discovered if item.get("serial") == serial), None)
            if merged is not None:
                merged.update(
                    {
                        "name": record.get("name") or merged.get("name") or serial,
                        "kind": record.get("kind") or merged.get("kind") or "auto",
                        "notes": record.get("notes") or "",
                        "source": record.get("source") or "auto",
                        "connected": False,
                        "arch": record.get("arch") or "",
                        "last_seen_at": record.get("last_seen_at"),
                    }
                )
                continue
            discovered.append(self._registry_public(record, connected=False))
        if not discovered and error is not None:
            return [{"error": error}]
        return discovered

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "version": "0.1.0",
            "uptime_s": round(time.time() - self.started_at, 1),
            "queue": self.jobs.queue.qsize() if self.jobs else 0,
            "jobs": self.database.job_counts(),
            "engines": self.jobs.engine_availability() if self.jobs else {},
        }

    def stop(self) -> None:
        if self.jobs is not None:
            self.jobs.shutdown()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


def make_handler(app: BackendApp):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "apu-web/0.1.0"

        # -------------------------------------------------------------- plumbing
        def log_message(self, fmt: str, *args: Any) -> None:
            try:
                print(redact(fmt % args))
            except Exception:
                pass

        def _json(self, status: int, value: Any, headers: dict[str, str] | None = None) -> None:
            body = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value_ in (headers or {}).items():
                self.send_header(key, value_)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _error(self, status: int, code: str, message: str, details: Any = None) -> None:
            payload = {"error": {"code": code, "message": message}}
            if details is not None:
                payload["error"]["details"] = details
            self._json(status, payload)

        def _read_json(self, limit: int = 2 * 1024 * 1024) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > limit:
                raise ValueError("request body too large")
            body = self.rfile.read(length) if length else b"{}"
            try:
                value = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid JSON: {exc}")
            if not isinstance(value, dict):
                raise ValueError("JSON body must be an object")
            return value

        def _query(self) -> dict[str, list[str]]:
            return parse_qs(urlparse(self.path).query)

        def _cookie_token(self) -> str | None:
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            jar = cookies.SimpleCookie()
            try:
                jar.load(raw)
            except cookies.CookieError:
                return None
            morsel = jar.get("apu_session")
            return morsel.value if morsel else None

        def _auth(self, required: bool = True) -> tuple[dict[str, Any] | None, str | None]:
            token = None
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
                kind = "bearer"
            elif self._cookie_token():
                token = self._cookie_token()
                kind = "cookie"
            else:
                query = self._query()
                token = (query.get("token") or [None])[0]
                kind = "query" if token else None
            if not token:
                if required:
                    self._error(401, "unauthorized", "authentication required")
                return None, None
            session = app.database.get_session(token_hash(token))
            if not session:
                if required:
                    self._error(401, "unauthorized", "invalid or expired session")
                return None, None
            if kind == "cookie" and self.command not in ("GET", "HEAD", "OPTIONS"):
                if (self.headers.get("X-Requested-With") or "").lower() != "xmlhttprequest":
                    if required:
                        self._error(403, "csrf_rejected", "missing X-Requested-With header")
                    return None, None
            user = {
                "id": int(session["user_id"]),
                "username": session["username"],
                "role": session["role"],
            }
            return user, kind

        def _require_admin(self) -> dict[str, Any] | None:
            user, _ = self._auth()
            if user is None:
                return None
            if user.get("role") != "admin":
                self._error(403, "forbidden", "administrator required")
                return None
            return user

        def _set_cookie(self, token: str) -> None:
            secure = ""
            if self.headers.get("X-Forwarded-Proto", "").lower() == "https" or (
                (self.headers.get("Host") or "").startswith("https")
            ):
                secure = "; Secure"
            self.send_header(
                "Set-Cookie",
                f"apu_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={app.config.session_days * 86400}{secure}",
            )

        def _clear_cookie(self) -> None:
            self.send_header("Set-Cookie", "apu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

        def _client_ip(self) -> str:
            forwarded = self.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
            return self.client_address[0] if self.client_address else "unknown"

        # -------------------------------------------------------------- routing
        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PATCH(self) -> None:
            self._handle("PATCH")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Allow", "GET, POST, PATCH, DELETE, OPTIONS")
            self.end_headers()

        def _handle(self, method: str) -> None:
            path = urlparse(self.path).path
            try:
                if method == "GET" and path == "/api/v1/health":
                    self._json(200, app.health())
                    return
                if method == "POST" and path == "/mcp":
                    self._mcp()
                    return
                if path.startswith("/api/v1/"):
                    self._api(method, path)
                    return
                if method == "GET":
                    self._static(path)
                    return
                self._error(404, "not_found", "not found")
            except PermissionError:
                self._error(403, "forbidden", "forbidden")
            except KeyError as exc:
                self._error(404, "not_found", f"not found: {exc}")
            except ValueError as exc:
                self._error(400, "invalid_input", str(exc))
            except AnalysisError as exc:
                self._json(400, {"error": exc.projection()})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:  # pragma: no cover - defensive
                traceback.print_exc()
                self._error(500, "internal_error", redact(str(exc)))

        # -------------------------------------------------------------- API
        def _api(self, method: str, path: str) -> None:
            if method == "POST" and path == "/api/v1/auth/login":
                self._login()
                return
            if method == "POST" and path == "/api/v1/auth/logout":
                self._logout()
                return
            user, kind = self._auth()
            if user is None:
                return
            if method == "GET" and path == "/api/v1/auth/me":
                self._json(200, {"user": user})
                return
            if method == "POST" and path == "/api/v1/auth/password":
                self._change_password(user)
                return
            if path.startswith("/api/v1/packages"):
                self._packages(method, path, user)
                return
            if path.startswith("/api/v1/providers"):
                self._providers(method, path, user)
                return
            if path.startswith("/api/v1/agents"):
                self._agents(method, path, user)
                return
            if path.startswith("/api/v1/skills"):
                self._skills(method, path, user)
                return
            if path.startswith("/api/v1/mcp-servers"):
                self._mcp_servers(method, path, user)
                return
            if path.startswith("/api/v1/chat"):
                self._chats(method, path, user)
                return
            if path.startswith("/api/v1/storage"):
                self._storage(method, path, user)
                return
            if path.startswith("/api/v1/uploads"):
                self._uploads(method, path, user)
                return
            if path.startswith("/api/v1/jobs"):
                self._jobs(method, path, user)
                return
            if path.startswith("/api/v1/users"):
                self._users(method, path, user)
                return
            if path.startswith("/api/v1/lessons"):
                self._lessons(method, path, user)
                return
            if path.startswith("/api/v1/devices"):
                self._devices(method, path, user)
                return
            if method == "GET" and path == "/api/v1/engines":
                admin = user.get("role") == "admin"
                engines = app.engine_public(admin=admin)
                if not admin:
                    for name in list(engines):
                        agent = app.jobs.agents.get(name)
                        if agent is not None and agent.owner_id is not None and int(agent.owner_id) != int(user["id"]):
                            engines.pop(name, None)
                self._json(200, {"engines": engines})
                return
            if method == "GET" and path == "/api/v1/doctor":
                self._json(200, app.jobs.service.doctor())
                return
            if method == "GET" and path == "/api/v1/audit":
                if user.get("role") != "admin":
                    self._error(403, "forbidden", "administrator required")
                    return
                query = self._query()
                limit = min(200, int((query.get("limit") or ["100"])[0]))
                offset = max(0, int((query.get("offset") or ["0"])[0]))
                items, total = app.database.list_audit(limit, offset)
                self._json(200, {"items": items, "total": total})
                return
            if method == "GET" and path == "/api/v1/stats":
                if user.get("role") != "admin":
                    self._error(403, "forbidden", "administrator required")
                    return
                jobs = app.database.job_counts()
                uploads = app.database.list_uploads(None, limit=100000)
                disk = shutil.disk_usage(app.config.data_dir)
                try:
                    lesson_stats = app.jobs.service.lessons.stats()
                except Exception:
                    lesson_stats = {"total": 0}
                engines = app.jobs.engine_availability()
                self._json(
                    200,
                    {
                        "users": app.database.count_users(),
                        "admins": app.database.count_admins(active_only=False),
                        "active_admins": app.database.count_admins(active_only=True),
                        "jobs": jobs,
                        "uploads": {
                            "count": len(uploads),
                            "bytes": sum(int(item.get("size") or 0) for item in uploads),
                        },
                        "lessons": lesson_stats,
                        "engines": {
                            "total": len(engines),
                            "available": sum(1 for value in engines.values() if value),
                        },
                        "disk": {
                            "total": disk.total,
                            "used": disk.used,
                            "free": disk.free,
                        },
                    },
                )
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- auth
        def _login(self) -> None:
            body = self._read_json(64 * 1024)
            username = str(body.get("username") or "").strip()
            password = str(body.get("password") or "")
            key = f"{self._client_ip()}:{username}"
            if app.limiter.blocked(key):
                self._error(429, "rate_limited", "too many failed logins; try again later")
                return
            user = app.database.get_user_by_name(username)
            if not user or user.get("disabled") or not verify_password(password, user["salt"], user["password_hash"]):
                app.limiter.failure(key)
                app.database.audit(None, "auth.login_failed", username, {"ip": self._client_ip()})
                self._error(401, "invalid_credentials", "invalid username or password")
                return
            app.limiter.reset(key)
            token = new_token()
            app.database.create_session(
                token_hash(token),
                int(user["id"]),
                app.config.session_days,
                self._client_ip(),
                self.headers.get("User-Agent"),
            )
            app.database.audit(int(user["id"]), "auth.login", username, {"ip": self._client_ip()})
            public = {"id": int(user["id"]), "username": user["username"], "role": user["role"]}
            body = json.dumps({"token": token, "user": public}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._set_cookie(token)
            self.end_headers()
            self.wfile.write(body)

        def _logout(self) -> None:
            token = None
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
            elif self._cookie_token():
                token = self._cookie_token()
            if token:
                app.database.delete_session(token_hash(token))
            self.send_response(204)
            self._clear_cookie()
            self.end_headers()

        def _change_password(self, user: dict[str, Any]) -> None:
            body = self._read_json()
            current = str(body.get("current_password") or "")
            new = str(body.get("new_password") or "")
            if len(new) < 4:
                self._error(400, "invalid_input", "new password is too short")
                return
            record = app.database.get_user(int(user["id"]))
            if not record or not verify_password(current, record["salt"], record["password_hash"]):
                self._error(401, "invalid_credentials", "current password is incorrect")
                return
            salt, digest = hash_password(new)
            app.database.update_user(int(user["id"]), password_hash=digest, salt=salt)
            app.database.audit(int(user["id"]), "auth.password_change", user["username"])
            self._json(200, {"ok": True})

        # -------------------------------------------------------------- providers
        def _providers(self, method: str, path: str, user: dict[str, Any]) -> None:
            if method == "GET" and path == "/api/v1/providers":
                # Any signed-in user may see model metadata (keys stay masked); management is admin-only.
                admin = user.get("role") == "admin"
                items = [provider.public(admin=admin) for provider in app.jobs.providers.list(include_keys=admin)]
                self._json(200, {"items": items})
                return
            if method == "GET" and path == "/api/v1/providers/presets":
                self._json(
                    200,
                    {
                        "protocols": PROTOCOL_DEFAULTS,
                        "providers": PROVIDER_PRESETS,
                        "models": MODEL_PRESETS,
                    },
                )
                return
            if user.get("role") != "admin":
                self._error(403, "forbidden", "administrator required")
                return
            if method == "POST" and path == "/api/v1/providers":
                body = self._read_json()
                provider = app.jobs.providers.create(body)
                app.jobs.agents.ensure_provider_agent(provider)
                app.jobs.refresh_engines()
                app.database.audit(
                    int(user["id"]),
                    "provider.create",
                    provider.id,
                    {"protocol": provider.protocol, "base_url": provider.base_url, "model": provider.model},
                )
                self._json(201, {"provider": provider.public(admin=True)})
                return
            if method == "POST" and path in ("/api/v1/providers/test", "/api/v1/providers/models"):
                body = self._read_json()
                provider = self._provider_for_test(body)
                if provider is None:
                    return
                override_key = str(body.get("api_key") or "") or None
                if path.endswith("/test"):
                    result = test_provider(provider, override_key=override_key)
                    app.database.audit(
                        int(user["id"]),
                        "provider.test",
                        provider.id,
                        {"protocol": provider.protocol, "ok": result.get("ok")},
                    )
                else:
                    result = list_provider_models(provider, override_key=override_key)
                self._json(200, result)
                return
            match = re.match(r"^/api/v1/providers/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "PATCH":
                provider_id = match.group(1)
                body = self._read_json()
                previous = app.jobs.providers.get(provider_id, include_key=False)
                provider = app.jobs.providers.update(provider_id, body)
                if previous and previous.name != provider.name:
                    agent_id = f"agent-{provider_id}"
                    row = app.database.get_agent(agent_id)
                    if row and row.get("name") == previous.name:
                        app.database.update_agent(agent_id, name=provider.name)
                app.jobs.agents.ensure_provider_agent(provider)
                app.jobs.refresh_engines()
                app.database.audit(
                    int(user["id"]),
                    "provider.update",
                    provider_id,
                    {
                        "protocol": provider.protocol,
                        "base_url": provider.base_url,
                        "model": provider.model,
                        "api_key_set": provider.api_key_set,
                    },
                )
                self._json(200, {"provider": provider.public(admin=True)})
                return
            match = re.match(r"^/api/v1/providers/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "DELETE":
                provider_id = match.group(1)
                app.jobs.providers.delete(provider_id)
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "provider.delete", provider_id)
                self._json(200, {"ok": True})
                return
            match = re.match(r"^/api/v1/providers/([a-z0-9][a-z0-9_-]{1,63})/test$", path)
            if match and method == "POST":
                provider = app.jobs.providers.get(match.group(1))
                if not provider:
                    self._error(404, "not_found", "provider not found")
                    return
                body = self._read_json()
                result = test_provider(provider, override_key=str(body.get("api_key") or "") or None)
                app.database.audit(
                    int(user["id"]),
                    "provider.test",
                    provider.id,
                    {"protocol": provider.protocol, "ok": result.get("ok")},
                )
                self._json(200, result)
                return
            match = re.match(r"^/api/v1/providers/([a-z0-9][a-z0-9_-]{1,63})/models$", path)
            if match and method == "GET":
                provider = app.jobs.providers.get(match.group(1))
                if not provider:
                    self._error(404, "not_found", "provider not found")
                    return
                self._json(200, list_provider_models(provider))
                return
            self._error(404, "not_found", "not found")

        def _provider_for_test(self, body: dict[str, Any]) -> ProviderConfig | None:
            provider_id = str(body.get("provider_id") or "").strip()
            stored = app.jobs.providers.get(provider_id) if provider_id else None
            if provider_id and stored is None:
                self._error(404, "not_found", "provider not found")
                return None
            protocol = str(body.get("protocol") or (stored.protocol if stored else "") or "").strip().lower()
            base_url = str(body.get("base_url") or (stored.base_url if stored else "") or "").strip()
            model = str(body.get("model") or (stored.model if stored else "") or "").strip()
            if protocol not in ("openai", "anthropic"):
                self._error(400, "invalid_input", "protocol must be 'openai' or 'anthropic'")
                return None
            if not base_url.startswith(("http://", "https://")):
                self._error(400, "invalid_input", "base_url must start with http:// or https://")
                return None
            if not model:
                self._error(400, "invalid_input", "model is required")
                return None

            def number(key: str, default: int) -> int:
                try:
                    return int(body.get(key, stored.__dict__.get(key, default) if stored else default))
                except (TypeError, ValueError):
                    return default

            try:
                temperature = float(
                    body.get("temperature", stored.temperature if stored else 0.1)
                )
            except (TypeError, ValueError):
                temperature = 0.1

            return ProviderConfig(
                id=provider_id or "test",
                name=str(body.get("name") or (stored.name if stored else "test")),
                protocol=protocol,
                base_url=base_url,
                model=model,
                api_key=str(body.get("api_key") or "") or (stored.api_key if stored else None),
                context_window=number("context_window", 65536),
                max_tokens=number("max_tokens", 4096),
                max_steps=number("max_steps", 24),
                timeout_s=number("timeout_s", 180),
                temperature=temperature,
                tool_result_chars=number("tool_result_chars", 16000),
                enabled=True,
            )

        # -------------------------------------------------------------- catalogs
        @staticmethod
        def _visible_to(user: dict[str, Any]) -> int | None:
            return None if user.get("role") == "admin" else int(user["id"])

        @staticmethod
        def _can_manage(row: dict[str, Any] | None, user: dict[str, Any]) -> bool:
            if not row:
                return False
            if user.get("role") == "admin":
                return True
            owner = row.get("owner_id")
            return owner is not None and int(owner) == int(user["id"])

        def _manage_or_error(self, row: dict[str, Any] | None, user: dict[str, Any], kind: str) -> bool:
            if not row:
                self._error(404, "not_found", f"{kind} not found")
                return False
            if not self._can_manage(row, user):
                self._error(403, "forbidden", "shared resources can only be changed by an administrator")
                return False
            return True

        # -------------------------------------------------------------- agents
        def _agents(self, method: str, path: str, user: dict[str, Any]) -> None:
            admin = user.get("role") == "admin"
            visible = self._visible_to(user)
            if method == "GET" and path == "/api/v1/agents":
                items = [agent.public(admin=admin) for agent in app.jobs.agents.list(visible_to=visible)]
                self._json(200, {"items": items})
                return
            if method == "POST" and path == "/api/v1/agents":
                body = self._read_json()
                agent = app.jobs.agents.create(body, owner_id=None if admin else int(user["id"]))
                app.jobs.refresh_engines()
                app.database.audit(
                    int(user["id"]), "agent.create", agent.id,
                    {"provider_id": agent.provider_id, "owner_id": agent.owner_id},
                )
                self._json(201, {"agent": agent.public(admin=admin)})
                return
            match = re.match(r"^/api/v1/agents/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "PATCH":
                row = app.database.get_agent(match.group(1))
                if not self._manage_or_error(row, user, "agent"):
                    return
                body = self._read_json()
                agent = app.jobs.agents.update(match.group(1), body)
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "agent.update", agent.id, {"provider_id": agent.provider_id})
                self._json(200, {"agent": agent.public(admin=admin)})
                return
            match = re.match(r"^/api/v1/agents/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "DELETE":
                row = app.database.get_agent(match.group(1))
                if not self._manage_or_error(row, user, "agent"):
                    return
                app.jobs.agents.delete(match.group(1))
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "agent.delete", match.group(1))
                self._json(200, {"ok": True})
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- skills
        def _skills(self, method: str, path: str, user: dict[str, Any]) -> None:
            admin = user.get("role") == "admin"
            visible = self._visible_to(user)
            if method == "GET" and path == "/api/v1/skills":
                self._json(200, {"items": app.jobs.skills.list(include_content=True, visible_to=visible)})
                return
            if method == "POST" and path == "/api/v1/skills":
                body = self._read_json()
                skill = app.jobs.skills.create(body, owner_id=None if admin else int(user["id"]))
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "skill.create", skill["id"], {"owner_id": skill.get("owner_id")})
                self._json(201, {"skill": skill})
                return
            match = re.match(r"^/api/v1/skills/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "PATCH":
                row = app.database.get_skill(match.group(1))
                if not self._manage_or_error(row, user, "skill"):
                    return
                body = self._read_json()
                skill = app.jobs.skills.update(match.group(1), body)
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "skill.update", match.group(1))
                self._json(200, {"skill": skill})
                return
            match = re.match(r"^/api/v1/skills/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "DELETE":
                row = app.database.get_skill(match.group(1))
                if not self._manage_or_error(row, user, "skill"):
                    return
                app.jobs.skills.delete(match.group(1))
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "skill.delete", match.group(1))
                self._json(200, {"ok": True})
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- MCP servers
        def _mcp_servers(self, method: str, path: str, user: dict[str, Any]) -> None:
            admin = user.get("role") == "admin"
            visible = self._visible_to(user)
            if method == "GET" and path == "/api/v1/mcp-servers":
                items = [
                    server.public(admin=admin)
                    for server in app.jobs.mcps.list(include_secrets=True, visible_to=visible)
                ]
                self._json(200, {"items": items})
                return
            if method == "POST" and path == "/api/v1/mcp-servers":
                body = self._read_json()
                if not admin and str(body.get("transport") or "").strip().lower() == "stdio":
                    self._error(403, "forbidden", "stdio MCP servers require an administrator; use http")
                    return
                server = app.jobs.mcps.create(body, owner_id=None if admin else int(user["id"]))
                app.jobs.refresh_engines()
                app.database.audit(
                    int(user["id"]),
                    "mcp.create",
                    server.id,
                    {
                        "transport": server.transport,
                        "url": redact(server.url or ""),
                        "command": redact(server.command or ""),
                        "owner_id": server.owner_id,
                    },
                )
                self._json(201, {"server": server.public(admin=admin)})
                return
            match = re.match(r"^/api/v1/mcp-servers/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "PATCH":
                row = app.database.get_mcp_server(match.group(1))
                if not self._manage_or_error(row, user, "MCP server"):
                    return
                body = self._read_json()
                if not admin and str(body.get("transport") or "").strip().lower() == "stdio":
                    self._error(403, "forbidden", "stdio MCP servers require an administrator; use http")
                    return
                server = app.jobs.mcps.update(match.group(1), body)
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "mcp.update", server.id)
                self._json(200, {"server": server.public(admin=admin)})
                return
            match = re.match(r"^/api/v1/mcp-servers/([a-z0-9][a-z0-9_-]{1,63})$", path)
            if match and method == "DELETE":
                row = app.database.get_mcp_server(match.group(1))
                if not self._manage_or_error(row, user, "MCP server"):
                    return
                app.jobs.mcps.delete(match.group(1))
                app.jobs.refresh_engines()
                app.database.audit(int(user["id"]), "mcp.delete", match.group(1))
                self._json(200, {"ok": True})
                return
            match = re.match(r"^/api/v1/mcp-servers/([a-z0-9][a-z0-9_-]{1,63})/test$", path)
            if match and method == "POST":
                row = app.database.get_mcp_server(match.group(1))
                if not self._manage_or_error(row, user, "MCP server"):
                    return
                server = app.jobs.mcps.get(match.group(1), include_secrets=True)
                if not server:
                    self._error(404, "not_found", "MCP server not found")
                    return
                try:
                    result = test_mcp_server(server, timeout_s=30)
                    app.jobs.mcps.mark_test(server.id, "ok", result.get("tools"))
                except Exception as exc:
                    result = {"ok": False, "error": redact(str(exc)), "tools": []}
                    app.jobs.mcps.mark_test(server.id, f"error: {redact(str(exc))}", [])
                app.jobs.refresh_engines()
                app.database.audit(
                    int(user["id"]),
                    "mcp.test",
                    server.id,
                    {"ok": result.get("ok")},
                )
                self._json(200, result)
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- uploads
        def _uploads(self, method: str, path: str, user: dict[str, Any]) -> None:
            if path == "/api/v1/uploads" and method == "POST":
                self._upload(user)
                return
            if path == "/api/v1/uploads" and method == "GET":
                query = self._query()
                limit = min(1000, max(1, int((query.get("limit") or ["200"])[0])))
                offset = max(0, int((query.get("offset") or ["0"])[0]))
                items = app.database.list_uploads(
                    None if user.get("role") == "admin" else int(user["id"]),
                    limit=limit,
                    offset=offset,
                )
                self._json(200, {"items": items, "limit": limit, "offset": offset})
                return
            match = re.match(r"^/api/v1/uploads/([a-f0-9]+)$", path)
            if match and method == "DELETE":
                upload = app.database.get_upload(match.group(1))
                if not upload:
                    self._error(404, "not_found", "upload not found")
                    return
                if user.get("role") != "admin" and int(upload["user_id"]) != int(user["id"]):
                    self._error(403, "forbidden", "not allowed")
                    return
                jobs, _ = app.database.list_jobs(upload_id=upload["id"], limit=100000)
                active = [job for job in jobs if job.get("status") in ACTIVE_JOB_STATES]
                if active:
                    self._error(
                        409,
                        "upload_in_use",
                        f"upload has {len(active)} active job(s); cancel and finish them first",
                    )
                    return
                for job in jobs:
                    app.jobs.delete_job(job["id"])
                self._remove_upload_files(upload)
                app.database.delete_upload(upload["id"])
                app.database.audit(
                    int(user["id"]),
                    "upload.delete",
                    upload["id"],
                    {"deleted_jobs": len(jobs), "filename": upload.get("filename")},
                )
                self._json(200, {"ok": True, "deleted_jobs": len(jobs)})
                return
            self._error(404, "not_found", "not found")

        def _upload(self, user: dict[str, Any]) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                self._error(400, "invalid_input", "empty upload")
                return
            if length > app.config.max_upload_bytes:
                self._error(413, "resource_constraint", "upload exceeds the configured size limit")
                return
            content_type = self.headers.get("Content-Type") or ""
            body = self.rfile.read(length)
            filename, payload = _parse_multipart_file(body, content_type)
            if not filename or payload is None:
                self._error(400, "invalid_input", "multipart field 'file' is required")
                return
            filename = safe_filename(filename)
            suffix = Path(filename).suffix.lower()
            if suffix in (".apks", ".xapk"):
                # APK bundles need split-install support in the job model.  Fail
                # at upload time instead of accepting them and failing later.
                self._error(
                    400,
                    "bundle_not_supported",
                    "APK bundles (.apks/.xapk) are not supported; upload a single .apk",
                )
                return
            if suffix != ".apk":
                self._error(400, "unsupported_target", "only .apk uploads are supported")
                return
            upload_id = uuid.uuid4().hex
            destination_dir = app.config.uploads_dir / upload_id
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = destination_dir / filename
            destination.write_bytes(payload)
            if not is_zip(destination):
                destination.unlink(missing_ok=True)
                self._error(400, "unsupported_target", "uploaded file is not a valid ZIP/APK")
                return
            digest = sha256_file(destination)
            record = app.database.create_upload(
                upload_id,
                int(user["id"]),
                filename,
                str(destination),
                len(payload),
                digest,
            )
            app.database.audit(int(user["id"]), "upload.create", upload_id, {"filename": filename, "size": len(payload)})
            self._json(201, {"upload": record})

        def _remove_upload_files(self, upload: dict[str, Any]) -> None:
            root = app.config.uploads_dir.resolve()
            targets: list[Path] = [root / str(upload.get("id") or "")]
            raw = str(upload.get("path") or "")
            if raw:
                try:
                    path = Path(raw).resolve()
                    if path.is_relative_to(root):
                        targets.append(path if path.is_dir() else path.parent)
                except OSError:
                    pass
            for target in targets:
                try:
                    target = target.resolve()
                except OSError:
                    continue
                if target == root or not target.is_relative_to(root):
                    continue
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        pass

        # -------------------------------------------------------------- packages
        def _packages(self, method: str, path: str, user: dict[str, Any]) -> None:
            if method == "POST" and path == "/api/v1/packages/import":
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    self._error(400, "invalid_input", "empty package upload")
                    return
                if length > 30 * 1024 * 1024:
                    self._error(413, "resource_constraint", "package upload exceeds 30 MB")
                    return
                body = self.rfile.read(length)
                content_type = self.headers.get("Content-Type") or ""
                filename, payload = _parse_multipart_file(body, content_type)
                if not filename or payload is None:
                    self._error(400, "invalid_input", "multipart field 'file' is required")
                    return
                filename = safe_filename(filename)
                if Path(filename).suffix.lower() != ".zip":
                    self._error(400, "unsupported_target", "only .zip packages are supported")
                    return
                try:
                    admin = user.get("role") == "admin"
                    result = import_package(
                        payload,
                        filename=filename,
                        skills_store=app.jobs.skills,
                        mcp_store=app.jobs.mcps,
                        agent_store=app.jobs.agents,
                        providers_store=app.jobs.providers,
                        owner_id=None if admin else int(user["id"]),
                        allow_stdio=admin,
                    )
                except PackageError as exc:
                    self._error(400, "invalid_package", str(exc))
                    return
                except Exception as exc:  # pragma: no cover - defensive
                    self._error(400, "invalid_package", redact(str(exc)))
                    return
                app.jobs.refresh_engines()
                app.database.audit(
                    int(user["id"]),
                    "package.import",
                    filename,
                    {
                        "summary": result.get("summary"),
                        "installed": {
                            key: [item.get("id") for item in values]
                            for key, values in (result.get("installed") or {}).items()
                        },
                    },
                )
                self._json(201, result)
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- chat
        @staticmethod
        def _agent_visible(agent: Any, user: dict[str, Any]) -> bool:
            if agent is None:
                return False
            if user.get("role") == "admin":
                return True
            return agent.owner_id is None or int(agent.owner_id) == int(user["id"])

        def _chats(self, method: str, path: str, user: dict[str, Any]) -> None:
            if method == "GET" and path == "/api/v1/chat/agents":
                items = []
                visible = None if user.get("role") == "admin" else int(user["id"])
                for agent in app.jobs.agents.list(visible_to=visible):
                    if agent.kind == "native":
                        continue
                    items.append(agent.public(admin=user.get("role") == "admin"))
                items.sort(key=lambda item: (not bool(item.get("available")), str(item.get("label") or "")))
                self._json(200, {"items": items})
                return
            if path == "/api/v1/chats":
                if method == "GET":
                    items = app.database.list_chats(int(user["id"]))
                    for item in items:
                        agent = app.jobs.agents.get(str(item.get("agent_id") or ""))
                        item["agent_name"] = agent.name if agent else (item.get("agent_id") or "")
                        item["agent_available"] = bool(agent and agent.available) if agent else False
                    self._json(200, {"items": items})
                    return
                if method == "POST":
                    try:
                        body = self._read_json()
                    except ValueError as exc:
                        self._error(400, "invalid_input", str(exc))
                        return
                    agent_id = str(body.get("agent_id") or "").strip()
                    agent = app.jobs.agents.get(agent_id) if agent_id else None
                    if not self._agent_visible(agent, user) or agent.kind == "native":
                        self._error(400, "invalid_agent", "choose a chat-capable LLM Agent")
                        return
                    if not agent.available:
                        self._error(409, "agent_unavailable", agent.reason or "agent unavailable")
                        return
                    title = str(body.get("title") or "新聊天").strip()[:120] or "新聊天"
                    chat_id = "chat_" + uuid.uuid4().hex[:16]
                    chat = app.database.create_chat(chat_id, int(user["id"]), title, agent.id)
                    app.database.audit(int(user["id"]), "chat.create", chat_id, {"agent_id": agent.id})
                    self._json(201, {"chat": chat, "agent": agent.public(admin=False)})
                    return
            match = re.match(r"^/api/v1/chats/([a-zA-Z0-9_]+)$", path)
            if match:
                chat = self._chat_or_403(match.group(1), user)
                if chat is None:
                    return
                if method == "GET":
                    agent = app.jobs.agents.get(str(chat.get("agent_id") or ""))
                    self._json(
                        200,
                        {
                            "chat": chat,
                            "agent": agent.public(admin=False) if agent else None,
                            "messages": app.database.list_chat_messages(chat["id"], limit=500),
                        },
                    )
                    return
                if method == "PATCH":
                    try:
                        body = self._read_json()
                    except ValueError as exc:
                        self._error(400, "invalid_input", str(exc))
                        return
                    title = None
                    if "title" in body:
                        title = str(body.get("title") or "").strip()[:120] or "新聊天"
                    agent_id = None
                    if "agent_id" in body:
                        candidate = str(body.get("agent_id") or "").strip()
                        agent = app.jobs.agents.get(candidate) if candidate else None
                        if not self._agent_visible(agent, user) or agent.kind == "native":
                            self._error(400, "invalid_agent", "choose a chat-capable LLM Agent")
                            return
                        if not agent.available:
                            self._error(409, "agent_unavailable", agent.reason or "agent unavailable")
                            return
                        agent_id = agent.id
                    app.database.update_chat(chat["id"], title=title, agent_id=agent_id)
                    updated = app.database.get_chat(chat["id"])
                    self._json(200, {"chat": updated})
                    return
                if method == "DELETE":
                    self._remove_chat_files(chat["id"])
                    app.database.delete_chat(chat["id"])
                    app.database.audit(int(user["id"]), "chat.delete", chat["id"])
                    self._json(200, {"ok": True})
                    return
            match = re.match(r"^/api/v1/chats/([a-zA-Z0-9_]+)/files$", path)
            if match and method == "POST":
                chat = self._chat_or_403(match.group(1), user)
                if chat is None:
                    return
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    self._error(400, "invalid_input", "empty file upload")
                    return
                if length > 25 * 1024 * 1024:
                    self._error(413, "resource_constraint", "chat file exceeds 20 MB")
                    return
                body = self.rfile.read(length)
                filename, payload = _parse_multipart_file(body, self.headers.get("Content-Type") or "")
                if not filename or payload is None:
                    self._error(400, "invalid_input", "multipart field 'file' is required")
                    return
                if len(payload) > 20 * 1024 * 1024:
                    self._error(413, "resource_constraint", "chat file exceeds 20 MB")
                    return
                filename = safe_filename(filename) or "file"
                file_id = "cf_" + uuid.uuid4().hex[:16]
                folder = (app.config.data_dir / "chat-files" / chat["id"]).resolve()
                root = (app.config.data_dir / "chat-files").resolve()
                if not folder.is_relative_to(root):
                    self._error(400, "invalid_input", "invalid chat id")
                    return
                folder.mkdir(parents=True, exist_ok=True)
                destination = folder / f"{file_id}_{filename}"
                destination.write_bytes(payload)
                digest = sha256_file(destination)
                mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                record = app.database.create_chat_file(
                    file_id,
                    chat["id"],
                    int(user["id"]),
                    filename,
                    str(destination),
                    len(payload),
                    mime,
                    digest,
                )
                self._json(201, {"file": _chat_file_public(record)})
                return
            match = re.match(r"^/api/v1/chats/([a-zA-Z0-9_]+)/files/([a-zA-Z0-9_]+)$", path)
            if match and method == "GET":
                chat = self._chat_or_403(match.group(1), user)
                if chat is None:
                    return
                record = app.database.get_chat_file(match.group(2))
                if not record or str(record.get("chat_id")) != str(chat["id"]):
                    self._error(404, "not_found", "chat file not found")
                    return
                path = Path(str(record.get("path") or "")).resolve()
                root = (app.config.data_dir / "chat-files" / chat["id"]).resolve()
                if not path.is_relative_to(root) or not path.is_file():
                    self._error(404, "not_found", "chat file not found")
                    return
                data = path.read_bytes()
                name = str(record.get("filename") or "file")
                ascii_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "file"
                self.send_response(200)
                self.send_header("Content-Type", str(record.get("mime") or "application/octet-stream"))
                self.send_header("Content-Length", str(len(data)))
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Cache-Control", "private, no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            match = re.match(r"^/api/v1/chats/([a-zA-Z0-9_]+)/clear$", path)
            if match and method == "POST":
                chat = self._chat_or_403(match.group(1), user)
                if chat is None:
                    return
                self._remove_chat_files(chat["id"])
                app.database.clear_chat_messages(chat["id"])
                app.database.audit(int(user["id"]), "chat.clear", chat["id"])
                self._json(200, {"ok": True})
                return
            match = re.match(r"^/api/v1/chats/([a-zA-Z0-9_]+)/messages$", path)
            if match and method == "POST":
                chat = self._chat_or_403(match.group(1), user)
                if chat is None:
                    return
                try:
                    body = self._read_json()
                except ValueError as exc:
                    self._error(400, "invalid_input", str(exc))
                    return
                content = str(body.get("content") or "").strip()
                if len(content) > 20000:
                    self._error(400, "invalid_input", "message exceeds 20000 characters")
                    return
                raw_file_ids = body.get("file_ids") or []
                if not isinstance(raw_file_ids, list) or len(raw_file_ids) > 8:
                    self._error(400, "invalid_input", "file_ids must be an array with at most 8 entries")
                    return
                attachments: list[dict[str, Any]] = []
                for file_id in raw_file_ids:
                    file_id = str(file_id or "")
                    record = app.database.get_chat_file(file_id)
                    if not record or str(record.get("chat_id")) != str(chat["id"]):
                        self._error(400, "invalid_input", "invalid chat attachment")
                        return
                    attachments.append(record)
                if not content and not attachments:
                    self._error(400, "invalid_input", "message content or attachments are required")
                    return
                if not content:
                    content = "请分析附件。"
                agent = app.jobs.agents.get(str(chat.get("agent_id") or ""))
                if not self._agent_visible(agent, user) or agent.kind == "native":
                    self._error(409, "agent_unavailable", "chat agent no longer exists")
                    return
                if not agent.available:
                    self._error(409, "agent_unavailable", agent.reason or "agent unavailable")
                    return
                if app.chat is None:
                    self._error(503, "unavailable", "chat service is not ready")
                    return
                prior = app.database.list_chat_messages(chat["id"], limit=1)
                public_attachments = [_chat_file_public(record) for record in attachments]
                user_message = app.database.append_chat_message(
                    chat["id"],
                    "user",
                    content,
                    {"attachments": public_attachments} if public_attachments else None,
                )
                if not prior and str(chat.get("title") or "") in ("", "新聊天"):
                    title = content.replace("\n", " ")[:40]
                    app.database.update_chat(chat["id"], title=title or "新聊天")
                history = app.database.list_chat_messages(chat["id"], limit=200)
                try:
                    result = app.chat.reply(chat, agent, history, attachments=attachments)
                except ChatError as exc:
                    self._error(502, "chat_failed", str(exc))
                    return
                except Exception as exc:
                    self._error(502, "chat_failed", redact(str(exc)))
                    return
                meta = {
                    "agent_id": agent.id,
                    "protocol": result.protocol,
                    "model": result.model,
                    "usage": result.usage,
                    "warnings": result.warnings,
                    "events": result.events[-60:],
                }
                assistant_message = app.database.append_chat_message(
                    chat["id"], "assistant", result.text, meta
                )
                self._json(
                    201,
                    {
                        "chat": app.database.get_chat(chat["id"]),
                        "user": user_message,
                        "assistant": assistant_message,
                        "events": result.events,
                        "usage": result.usage,
                        "warnings": result.warnings,
                    },
                )
                return
            match = re.match(r"^/api/v1/chats/([a-zA-Z0-9_]+)/stop$", path)
            if match and method == "POST":
                chat = self._chat_or_403(match.group(1), user)
                if chat is None:
                    return
                if app.chat is None:
                    self._error(503, "unavailable", "chat service is not ready")
                    return
                request_cancel = getattr(app.chat, "request_cancel", None)
                if not callable(request_cancel):
                    self._error(
                        501,
                        "chat_stop_not_supported",
                        "this chat backend cannot cancel an in-flight reply",
                    )
                    return
                cancelled = bool(request_cancel(chat["id"]))
                app.database.audit(
                    int(user["id"]),
                    "chat.stop",
                    chat["id"],
                    {"cancelled": cancelled},
                )
                self._json(200, {"ok": True, "cancelled": cancelled})
                return
            self._error(404, "not_found", "not found")

        def _remove_chat_files(self, chat_id: str) -> None:
            root = (app.config.data_dir / "chat-files" / chat_id).resolve()
            for record in app.database.list_chat_files(chat_id):
                try:
                    path = Path(str(record.get("path") or "")).resolve()
                    if path.is_relative_to(root):
                        path.unlink(missing_ok=True)
                except OSError:
                    pass
            app.database.delete_chat_files(chat_id)
            shutil.rmtree(root, ignore_errors=True)

        def _chat_or_403(self, chat_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
            chat = app.database.get_chat(chat_id)
            if not chat:
                self._error(404, "not_found", "chat not found")
                return None
            if int(chat.get("user_id") or 0) != int(user["id"]):
                self._error(403, "forbidden", "not allowed")
                return None
            return chat

        # -------------------------------------------------------------- devices
        def _devices(self, method: str, path: str, user: dict[str, Any]) -> None:
            path = unquote(path)
            if method == "GET" and path == "/api/v1/devices":
                self._json(200, {"devices": app.device_list()})
                return
            if user.get("role") != "admin":
                self._error(403, "forbidden", "administrator required")
                return
            if method == "POST" and path == "/api/v1/devices":
                body = self._read_json()
                raw_serial = str(body.get("serial") or "").strip()
                if not raw_serial:
                    # No input needed: auto-register every currently connected adb
                    # device. An explicit add also restores devices hidden earlier.
                    visible = {str(item.get("serial")) for item in app.device_list()}
                    hidden_now = {
                        str(item.get("serial"))
                        for item in app.database.list_devices(include_hidden=True)
                        if item.get("hidden")
                    }
                    devices = app.device_list(include_hidden=True)
                    registered = [
                        item
                        for item in devices
                        if item.get("serial")
                        and not item.get("error")
                        and item.get("connected")
                    ]
                    added: list[str] = []
                    restored: list[str] = []
                    for item in registered:
                        serial = str(item["serial"])
                        app.database.update_device(serial, hidden=0)
                        if serial in hidden_now:
                            restored.append(serial)
                        elif serial not in visible:
                            added.append(serial)
                    app.database.audit(
                        int(user["id"]),
                        "device.auto_register",
                        None,
                        {
                            "count": len(registered),
                            "added": added,
                            "restored": restored,
                        },
                    )
                    self._json(
                        200,
                        {
                            "ok": True,
                            "auto": True,
                            "count": len(registered),
                            "new_count": len(added),
                            "restored_count": len(restored),
                            "devices": registered,
                        },
                    )
                    return
                serial = app._normalize_device_serial(raw_serial)
                if not re.match(r"^[A-Za-z0-9._:@-]{1,160}$", serial):
                    self._error(400, "invalid_input", "serial must match [A-Za-z0-9._:@-]{1,160}")
                    return
                kind = str(body.get("kind") or "auto").strip().lower()
                if kind not in ("auto", "usb", "emulator", "redroid", "network"):
                    self._error(400, "invalid_input", "kind must be auto/usb/emulator/redroid/network")
                    return
                if kind == "auto":
                    if serial.startswith("emulator-"):
                        kind = "emulator"
                    elif ":" in serial:
                        kind = "redroid" if serial.startswith(("127.0.0.1", "localhost")) else "network"
                    else:
                        kind = "usb"
                name = str(body.get("name") or "").strip() or app._auto_device_name(serial, kind)
                notes = str(body.get("notes") or "").strip()
                record = app.database.upsert_device(
                    serial,
                    name=name,
                    kind=kind,
                    address=str(body.get("address") or serial).strip() or serial,
                    notes=notes,
                    source="manual",
                )
                app.database.update_device(serial, source="manual", hidden=0)
                connected = False
                if body.get("connect"):
                    connected = self._adb_connect(serial)
                app.database.audit(
                    int(user["id"]), "device.create", serial, {"kind": kind, "connect": bool(body.get("connect"))}
                )
                self._json(
                    201,
                    {"device": {**app._registry_public({**record, "hidden": 0}, connected=connected), "registry": True}},
                )
                return
            match = re.match(r"^/api/v1/devices/([A-Za-z0-9._:@-]{1,160})/connect$", path)
            if match and method == "POST":
                serial = match.group(1)
                if not app.database.get_device(serial):
                    app.database.upsert_device(serial, name=serial, kind="network", address=serial, source="manual")
                connected = self._adb_connect(serial)
                app.database.audit(int(user["id"]), "device.connect", serial, {"connected": connected})
                self._json(200, {"ok": connected, "serial": serial, "connected": connected})
                return
            match = re.match(r"^/api/v1/devices/([A-Za-z0-9._:@-]{1,160})$", path)
            if match and method == "PATCH":
                serial = match.group(1)
                record = app.database.get_device(serial)
                if not record:
                    self._error(404, "not_found", "device not found")
                    return
                body = self._read_json()
                changes: dict[str, Any] = {}
                if "name" in body:
                    changes["name"] = str(body.get("name") or "").strip()[:200] or serial
                if "notes" in body:
                    changes["notes"] = str(body.get("notes") or "").strip()[:2000]
                if "kind" in body and str(body.get("kind") or "").strip().lower() in (
                    "auto", "usb", "emulator", "redroid", "network"
                ):
                    changes["kind"] = str(body["kind"]).strip().lower()
                if "address" in body:
                    changes["address"] = str(body.get("address") or "").strip()[:400] or serial
                if "enabled" in body:
                    changes["enabled"] = 1 if body.get("enabled") else 0
                changes["hidden"] = 0
                app.database.update_device(serial, **changes)
                app.database.audit(int(user["id"]), "device.update", serial)
                updated = app.database.get_device(serial) or record
                self._json(200, {"device": app._registry_public(updated, connected=False)})
                return
            match = re.match(r"^/api/v1/devices/([A-Za-z0-9._:@-]{1,160})$", path)
            if match and method == "DELETE":
                serial = match.group(1)
                if not app.database.get_device(serial):
                    # Connected devices are auto-registered on refresh; hide the
                    # serial so discovery does not immediately bring it back.
                    app.database.hide_device(serial)
                else:
                    app.database.hide_device(serial)
                app.database.audit(int(user["id"]), "device.hide", serial)
                self._json(200, {"ok": True, "hidden": True})
                return
            self._error(404, "not_found", "not found")

        def _adb_connect(self, serial: str) -> bool:
            if ":" not in serial:
                return False
            try:
                result = app.jobs.service.adb.run(["connect", serial], timeout=20)
                app.database.upsert_device(serial, name=serial, kind="network", address=serial, source="auto", seen=result.ok)
                return bool(result.ok)
            except Exception:
                return False

        # -------------------------------------------------------------- storage
        def _storage(self, method: str, path: str, user: dict[str, Any]) -> None:
            if user.get("role") != "admin":
                self._error(403, "forbidden", "administrator required")
                return
            if method == "GET" and path == "/api/v1/storage":
                self._json(200, self._storage_inventory())
                return
            if method == "POST" and path == "/api/v1/storage/cleanup":
                self._storage_cleanup(user)
                return
            self._error(404, "not_found", "not found")

        def _storage_inventory(self) -> dict[str, Any]:
            jobs, _ = app.database.list_jobs(limit=100000)
            uploads = app.database.list_uploads(None, limit=100000)
            jobs_dir = app.config.jobs_dir
            runs_dir = app.config.runs_dir
            job_ids = {str(job.get("id") or "") for job in jobs}
            run_ids = {str(job.get("run_id") or "") for job in jobs if job.get("run_id")}
            job_dirs = _subdirs(jobs_dir)
            run_dirs = _subdirs(runs_dir)
            orphan_job_dirs = [path for path in job_dirs if path.name not in job_ids]
            orphan_runs = [path for path in run_dirs if path.name not in run_ids]
            orphan_uploads = [upload for upload in uploads if not int(upload.get("job_count") or 0)]
            statuses: dict[str, int] = {}
            for job in jobs:
                status = str(job.get("status") or "unknown")
                statuses[status] = statuses.get(status, 0) + 1
            disk = shutil.disk_usage(app.config.data_dir)
            return {
                "uploads": {
                    "count": len(uploads),
                    "bytes": _path_bytes(app.config.uploads_dir),
                },
                "jobs": {
                    "count": len(jobs),
                    "bytes": _path_bytes(jobs_dir),
                    "statuses": statuses,
                },
                "runs": {
                    "count": len(run_dirs),
                    "bytes": _path_bytes(runs_dir),
                },
                "orphans": {
                    "uploads": len(orphan_uploads),
                    "uploads_bytes": sum(_upload_bytes(upload) for upload in orphan_uploads),
                    "runs": len(orphan_runs),
                    "runs_bytes": sum(_path_bytes(path) for path in orphan_runs),
                    "job_dirs": len(orphan_job_dirs),
                    "job_dirs_bytes": sum(_path_bytes(path) for path in orphan_job_dirs),
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                },
                "items": uploads,
            }

        def _storage_cleanup(self, user: dict[str, Any]) -> None:
            try:
                body = self._read_json()
            except ValueError as exc:
                self._error(400, "invalid_input", str(exc))
                return
            target = str(body.get("target") or "completed_jobs")
            if target not in ("completed_jobs", "orphan_uploads", "orphan_runs", "orphan_job_dirs", "all"):
                self._error(400, "invalid_input", "unknown cleanup target")
                return
            try:
                days = max(0, min(3650, int(body.get("older_than_days") or 0)))
            except (TypeError, ValueError):
                self._error(400, "invalid_input", "older_than_days must be an integer")
                return
            cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days else None
            result: dict[str, Any] = {
                "target": target,
                "older_than_days": days,
                "deleted_jobs": 0,
                "deleted_uploads": 0,
                "deleted_runs": 0,
                "deleted_job_dirs": 0,
                "freed_bytes": 0,
                "skipped_active": 0,
            }
            jobs_dir = app.config.jobs_dir
            runs_dir = app.config.runs_dir
            if target in ("completed_jobs", "all"):
                jobs, _ = app.database.list_jobs(limit=100000)
                for job in jobs:
                    if job.get("status") not in TERMINAL_JOB_STATES:
                        result["skipped_active"] += 1
                        continue
                    if not _older_than(job.get("finished_at") or job.get("created_at"), cutoff):
                        continue
                    result["freed_bytes"] += _path_bytes(jobs_dir / str(job["id"]))
                    if job.get("run_id"):
                        result["freed_bytes"] += _path_bytes(runs_dir / str(job["run_id"]))
                    app.jobs.delete_job(job["id"])
                    result["deleted_jobs"] += 1
            if target in ("orphan_uploads", "all"):
                jobs, _ = app.database.list_jobs(limit=100000)
                referenced = {str(job.get("upload_id") or "") for job in jobs}
                uploads = app.database.list_uploads(None, limit=100000)
                for upload in uploads:
                    if upload["id"] in referenced:
                        continue
                    if not _older_than(upload.get("created_at"), cutoff):
                        continue
                    result["freed_bytes"] += _upload_bytes(upload)
                    self._remove_upload_files(upload)
                    app.database.delete_upload(upload["id"])
                    result["deleted_uploads"] += 1
            if target in ("orphan_runs", "all"):
                jobs, _ = app.database.list_jobs(limit=100000)
                run_ids = {str(job.get("run_id") or "") for job in jobs if job.get("run_id")}
                for path in _subdirs(runs_dir):
                    if path.name in run_ids:
                        continue
                    if not _older_than(_mtime_iso(path), cutoff):
                        continue
                    result["freed_bytes"] += _path_bytes(path)
                    shutil.rmtree(path, ignore_errors=True)
                    result["deleted_runs"] += 1
            if target in ("orphan_job_dirs", "all"):
                jobs, _ = app.database.list_jobs(limit=100000)
                job_ids = {str(job.get("id") or "") for job in jobs}
                for path in _subdirs(jobs_dir):
                    if path.name in job_ids:
                        continue
                    if not _older_than(_mtime_iso(path), cutoff):
                        continue
                    result["freed_bytes"] += _path_bytes(path)
                    shutil.rmtree(path, ignore_errors=True)
                    result["deleted_job_dirs"] += 1
            app.database.audit(int(user["id"]), "storage.cleanup", target, result)
            self._json(200, result)

        # -------------------------------------------------------------- jobs
        def _jobs(self, method: str, path: str, user: dict[str, Any]) -> None:
            if path == "/api/v1/jobs" and method == "POST":
                self._create_job(user)
                return
            if path == "/api/v1/jobs" and method == "GET":
                query = self._query()
                limit = min(200, max(1, int((query.get("limit") or ["50"])[0])))
                offset = max(0, int((query.get("offset") or ["0"])[0]))
                jobs, total = app.database.list_jobs(
                    user_id=None if user.get("role") == "admin" else int(user["id"]),
                    status=(query.get("status") or [None])[0],
                    engine=(query.get("engine") or [None])[0],
                    limit=limit,
                    offset=offset,
                )
                self._json(200, {"items": _job_public_many(jobs), "total": total, "limit": limit, "offset": offset})
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)$", path)
            if match and method == "GET":
                job = self._job_or_403(match.group(1), user)
                if job is None:
                    return
                events = app.database.list_events(job["id"], 0, 1000)
                upload = app.database.get_upload(job["upload_id"]) or {}
                self._json(200, {"job": _job_public(job), "upload": upload, "events": events})
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)/cancel$", path)
            if match and method == "POST":
                job = self._job_or_403(match.group(1), user)
                if job is None:
                    return
                updated = app.jobs.cancel_job(job["id"], int(user["id"]), user.get("role") == "admin")
                self._json(200, {"job": _job_public(updated)})
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)/retry$", path)
            if match and method == "POST":
                self._retry_job(match.group(1), user)
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)/cleanup$", path)
            if match and method == "POST":
                self._cleanup_job(match.group(1), user)
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)/events$", path)
            if match and method == "GET":
                job = self._job_or_403(match.group(1), user)
                if job is None:
                    return
                query = self._query()
                last_event = self.headers.get("Last-Event-ID")
                after = int(last_event or (query.get("after_seq") or ["0"])[0])
                limit = min(1000, max(1, int((query.get("limit") or ["500"])[0])))
                events = app.database.list_events(job["id"], after, limit)
                self._json(200, {"events": events, "after_seq": after})
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)/stream$", path)
            if match and method == "GET":
                job = self._job_or_403(match.group(1), user)
                if job is None:
                    return
                self._stream(job)
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)/download/([a-z]+)$", path)
            if match and method == "GET":
                job = self._job_or_403(match.group(1), user)
                if job is None:
                    return
                self._download(job, match.group(2), user)
                return
            match = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_]+)$", path)
            if match and method == "DELETE":
                job = self._job_or_403(match.group(1), user)
                if job is None:
                    return
                if job.get("status") in ACTIVE_JOB_STATES:
                    self._error(409, "job_active", "cancel the job and wait for it to finish before deleting")
                    return
                app.jobs.delete_job(job["id"])
                app.database.audit(int(user["id"]), "job.delete", job["id"])
                self._json(200, {"ok": True})
                return
            self._error(404, "not_found", "not found")

        def _job_or_403(self, job_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
            job = app.database.get_job(job_id)
            if not job:
                self._error(404, "not_found", "job not found")
                return None
            if user.get("role") != "admin" and int(job["user_id"]) != int(user["id"]):
                self._error(403, "forbidden", "not allowed")
                return None
            return job

        def _retry_job(self, job_id: str, user: dict[str, Any]) -> None:
            job = self._job_or_403(job_id, user)
            if job is None:
                return
            status = str(job.get("status") or "")
            if status not in RETRYABLE_JOB_STATES:
                app.database.audit(
                    int(user["id"]),
                    "job.retry_rejected",
                    job["id"],
                    {"status": status, "reason": "not_retryable"},
                )
                self._error(
                    409,
                    "job_not_retryable",
                    f"job status is {status}; only failed, partial or cancelled jobs can be retried",
                )
                return
            idempotency_key = (self.headers.get("Idempotency-Key") or "").strip()[:200]
            cache = getattr(app, "retry_cache", None)
            cache_lock = getattr(app, "retry_lock", None)
            if idempotency_key and isinstance(cache, dict):
                with (cache_lock or threading.Lock()):
                    cached_id = cache.get((int(user["id"]), idempotency_key))
                if cached_id:
                    cached = app.database.get_job(cached_id)
                    if cached:
                        self._json(200, {"job": _job_public(cached), "idempotent": True})
                        return
            try:
                created = app.jobs.retry_job(job["id"], int(user["id"]), user.get("role") == "admin")
            except KeyError:
                self._error(404, "not_found", "job not found")
                return
            except PermissionError:
                self._error(403, "forbidden", "not allowed")
                return
            except ValueError as exc:
                self._error(400, "invalid_input", str(exc))
                return
            if idempotency_key and isinstance(cache, dict):
                with (cache_lock or threading.Lock()):
                    cache[(int(user["id"]), idempotency_key)] = str(created.get("id") or "")
            app.database.audit(
                int(user["id"]),
                "job.retry",
                job["id"],
                {"created": created.get("id"), "status": status, "idempotency_key": idempotency_key or None},
            )
            self._json(201, {"job": _job_public(created)})

        def _cleanup_job(self, job_id: str, user: dict[str, Any]) -> None:
            job = self._job_or_403(job_id, user)
            if job is None:
                return
            cleanup = getattr(app.jobs, "cleanup_job", None)
            if not callable(cleanup):
                self._error(
                    501,
                    "cleanup_not_supported",
                    "this build does not support job cleanup; update the backend",
                )
                return
            try:
                result = cleanup(job["id"])
            except KeyError:
                self._error(404, "not_found", "job not found")
                return
            except PermissionError:
                self._error(403, "forbidden", "not allowed")
                return
            except AnalysisError as exc:
                status = 409 if exc.code == "conflict" else (404 if exc.code == "not_found" else 500)
                self._json(status, {"error": exc.projection()})
                return
            except ValueError as exc:
                message = str(exc)
                if any(token in message.lower() for token in ("conflict", "running", "in progress", "active")):
                    self._error(409, "job_conflict", message)
                else:
                    self._error(400, "invalid_input", message)
                return
            except Exception as exc:  # pragma: no cover - defensive
                self._error(500, "cleanup_failed", redact(str(exc)))
                return
            if not isinstance(result, dict):
                self._error(500, "cleanup_failed", "cleanup returned an invalid result")
                return
            current = app.database.get_job(job["id"]) or job
            app.database.audit(
                int(user["id"]),
                "job.cleanup",
                job["id"],
                {
                    "ok": bool(result.get("ok")),
                    "cleanup_incomplete": bool(result.get("cleanup_incomplete")),
                },
            )
            body = dict(result)
            body["job"] = _job_public(current)
            self._json(200, body)

        def _create_job(self, user: dict[str, Any]) -> None:
            body = self._read_json()
            upload_id = str(body.get("upload_id") or "")
            upload = app.database.get_upload(upload_id)
            if not upload:
                self._error(404, "not_found", "upload not found")
                return
            if user.get("role") != "admin" and int(upload["user_id"]) != int(user["id"]):
                self._error(403, "forbidden", "not allowed")
                return
            requested_engine = str(body.get("engine") or "").strip()
            engine = (
                app.jobs.canonical_engine(requested_engine)
                if requested_engine
                else app.jobs.default_engine(visible_to=self._visible_to(user))
            )
            selected = app.jobs.engines.get(engine)
            if selected is None:
                self._error(400, "invalid_input", f"unknown engine: {engine}")
                return
            selected_agent = getattr(selected, "agent", None)
            if (
                selected_agent is not None
                and selected_agent.owner_id is not None
                and user.get("role") != "admin"
                and int(selected_agent.owner_id) != int(user["id"])
            ):
                self._error(403, "forbidden", "this agent belongs to another user")
                return
            if not getattr(selected, "available", True):
                self._error(400, "unsupported_provider", getattr(selected, "reason", "engine unavailable"))
                return
            try:
                options = normalize_job_options(body.get("options"), strict=True)
            except ValueError as exc:
                self._error(400, "invalid_input", f"invalid options: {exc}")
                return
            # An empty serial means automatic selection. Leave it to the
            # worker so the job is marked as auto and an x86 failure can be
            # retried on ARM64; only a user-supplied serial pins the device.
            serial = str(body.get("serial") or "").strip() or None
            try:
                job = app.jobs.create_job(
                    user_id=int(user["id"]),
                    upload_id=upload_id,
                    engine=engine,
                    serial=serial,
                    options=options,
                )
            except ValueError as exc:
                message = str(exc)
                if "no online device" in message:
                    self._error(503, "device_unavailable", message)
                else:
                    self._error(400, "invalid_input", message)
                return
            self._json(201, {"job": _job_public(job)})

        def _download(self, job: dict[str, Any], kind: str, user: dict[str, Any]) -> None:
            mapping = {
                "dex": "dex_zip",
                "source": "source_zip",
                "evidence": "evidence_zip",
                "logs": "logs_zip",
                "full": "full_zip",
            }
            column = mapping.get(kind)
            if not column:
                self._error(404, "not_found", "unknown artifact")
                return
            path_text = job.get(column)
            if not path_text:
                status = 409 if job.get("status") in ("queued", "running") else 404
                self._error(status, "not_found", "artifact is not available yet")
                return
            path = Path(path_text)
            if not path.is_file():
                self._error(404, "not_found", "artifact file is missing")
                return
            app.database.audit(int(user["id"]), "artifact.download", job["id"], {"kind": kind})
            filename = f"{job['id']}_{kind}.zip"
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(path.stat().st_size))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with open(path, "rb") as handle:
                shutil.copyfileobj(handle, self.wfile)

        def _stream(self, job: dict[str, Any]) -> None:
            query = self._query()
            last_event = self.headers.get("Last-Event-ID")
            after = int(last_event or (query.get("after_seq") or ["0"])[0])
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.close_connection = True
            subscriber = app.bus.subscribe(job["id"])
            overflow_flag = getattr(subscriber, "overflowed", None)
            cursor = after

            def send_event(event: dict[str, Any]) -> bool:
                nonlocal cursor
                try:
                    data = json.dumps(event, ensure_ascii=False, default=str)
                    self.wfile.write(f"id: {event['seq']}\ndata: {data}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    cursor = int(event["seq"])
                    return True
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return False

            def stream_overflow() -> None:
                # Tell the client explicitly instead of silently losing events.
                # Closing the response makes EventSource reconnect with the
                # Last-Event-ID of the last event we actually sent, replaying
                # the gap from the database.
                payload = json.dumps(
                    {
                        "code": "sse_overflow",
                        "message": "subscriber fell behind; reconnect to replay missed events",
                        "last_seq": cursor,
                    },
                    ensure_ascii=False,
                )
                try:
                    self.wfile.write(f"retry: 1000\nevent: overflow\ndata: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

            try:
                # Replay retained events first.
                while True:
                    batch = app.database.list_events(job["id"], cursor, 500)
                    if not batch:
                        break
                    for event in batch:
                        if not send_event(event):
                            return
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    if overflow_flag is not None and overflow_flag.is_set():
                        stream_overflow()
                        return
                    try:
                        event = subscriber.get(timeout=15)
                    except queue.Empty:
                        try:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            return
                        current = app.database.get_job(job["id"]) or {}
                        if current.get("status") in ("succeeded", "partial", "failed", "cancelled"):
                            try:
                                self.wfile.write(b"event: stream_end\ndata: {}\n\n")
                                self.wfile.flush()
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                pass
                            return
                        continue
                    if overflow_flag is not None and overflow_flag.is_set():
                        stream_overflow()
                        return
                    if not send_event(event):
                        return
                    current = app.database.get_job(job["id"]) or {}
                    if event.get("kind") == "job_finished" or current.get("status") in (
                        "succeeded",
                        "partial",
                        "failed",
                        "cancelled",
                    ):
                        try:
                            self.wfile.write(b"event: stream_end\ndata: {}\n\n")
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            pass
                        return
            finally:
                app.bus.unsubscribe(job["id"], subscriber)

        # -------------------------------------------------------------- users
        def _users(self, method: str, path: str, user: dict[str, Any]) -> None:
            if user.get("role") != "admin":
                self._error(403, "forbidden", "administrator required")
                return
            if path == "/api/v1/users" and method == "GET":
                self._json(
                    200,
                    {
                        "items": app.database.list_users(),
                        "admins": app.database.count_admins(active_only=False),
                        "active_admins": app.database.count_admins(active_only=True),
                    },
                )
                return
            if path == "/api/v1/users" and method == "POST":
                body = self._read_json()
                username = str(body.get("username") or "").strip()
                password = str(body.get("password") or "")
                role = str(body.get("role") or "user")
                if not username or len(password) < 4:
                    self._error(400, "invalid_input", "username and password (>=4 chars) are required")
                    return
                if app.database.get_user_by_name(username):
                    self._error(409, "conflict", "username already exists")
                    return
                salt, digest = hash_password(password)
                created = app.database.create_user(username, digest, salt, role if role in ("user", "admin") else "user")
                app.database.audit(int(user["id"]), "user.create", username)
                self._json(201, {"user": {"id": created["id"], "username": created["username"], "role": created["role"]}})
                return
            match = re.match(r"^/api/v1/users/(\d+)$", path)
            if match and method == "PATCH":
                target = int(match.group(1))
                target_user = app.database.get_user(target)
                if not target_user:
                    self._error(404, "not_found", "user not found")
                    return
                body = self._read_json()
                changes: dict[str, Any] = {}
                demote = False
                disable = False
                if "disabled" in body:
                    changes["disabled"] = 1 if body["disabled"] else 0
                    disable = bool(changes["disabled"])
                if body.get("role") in ("user", "admin"):
                    changes["role"] = body["role"]
                    demote = target_user.get("role") == "admin" and changes["role"] != "admin"
                if target_user.get("role") == "admin" and not target_user.get("disabled") and (demote or disable):
                    if app.database.count_admins(active_only=True) <= 1:
                        self._error(409, "last_admin", "至少需要保留一个可用的管理员账号")
                        return
                if body.get("password"):
                    salt, digest = hash_password(str(body["password"]))
                    changes["password_hash"] = digest
                    changes["salt"] = salt
                app.database.update_user(target, **changes)
                if disable or body.get("password"):
                    app.database.delete_sessions_for_user(target)
                app.database.audit(int(user["id"]), "user.update", str(target))
                self._json(200, {"ok": True})
                return
            if match and method == "DELETE":
                target = int(match.group(1))
                target_user = app.database.get_user(target)
                if not target_user:
                    self._error(404, "not_found", "user not found")
                    return
                if target == int(user["id"]):
                    self._error(400, "invalid_input", "不能删除当前登录的账号，请使用其他管理员账号操作")
                    return
                if target_user.get("role") == "admin" and not target_user.get("disabled"):
                    if app.database.count_admins(active_only=True) <= 1:
                        self._error(409, "last_admin", "至少需要保留一个可用的管理员账号")
                        return
                app.database.delete_user(target)
                app.database.audit(int(user["id"]), "user.delete", str(target_user.get("username") or target))
                self._json(200, {"ok": True})
                return
            match = re.match(r"^/api/v1/users/(\d+)/reset$", path)
            if match and method == "POST":
                target = int(match.group(1))
                if not app.database.get_user(target):
                    self._error(404, "not_found", "user not found")
                    return
                body = self._read_json()
                password = str(body.get("password") or "")
                if len(password) < 4:
                    self._error(400, "invalid_input", "password (>=4 chars) is required")
                    return
                salt, digest = hash_password(password)
                app.database.update_user(target, password_hash=digest, salt=salt)
                app.database.delete_sessions_for_user(target)
                app.database.audit(int(user["id"]), "user.reset_password", str(target))
                self._json(200, {"ok": True})
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- lessons
        def _lessons(self, method: str, path: str, user: dict[str, Any]) -> None:
            if path == "/api/v1/lessons/export" and method == "GET":
                document = app.jobs.service.export_unpack_lessons()
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                self._json(
                    200,
                    document,
                    {
                        "Content-Disposition": f'attachment; filename="apu-lessons-{stamp}.json"',
                    },
                )
                return
            if path == "/api/v1/lessons/import" and method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    self._error(400, "invalid_input", "empty import body")
                    return
                if length > 8 * 1024 * 1024:
                    self._error(413, "resource_constraint", "lesson import exceeds 8 MB")
                    return
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self._error(400, "invalid_input", f"invalid JSON: {exc}")
                    return
                if not isinstance(body, (dict, list)):
                    self._error(400, "invalid_input", "lesson import must be an object or an array")
                    return
                # Only administrators may publish trusted global lessons.
                # Non-admin imports are still stored, but marked untrusted and
                # excluded from recall/learned route ranking until reviewed.
                is_admin = user.get("role") == "admin"
                store = getattr(app.jobs.service, "lessons", None)
                try:
                    if store is not None and hasattr(store, "import_document"):
                        result = store.import_document(
                            body, source="web-import", trusted=is_admin
                        )
                    else:  # pragma: no cover - legacy service without .lessons
                        result = app.jobs.service.import_unpack_lessons(body)
                except AnalysisError as exc:
                    self._json(400, {"error": exc.projection()})
                    return
                except (TypeError, ValueError) as exc:
                    self._error(400, "invalid_input", str(exc))
                    return
                app.database.audit(
                    int(user["id"]),
                    "lesson.import",
                    None,
                    {
                        "imported": result.get("imported"),
                        "skipped": result.get("skipped"),
                        "invalid": result.get("invalid"),
                        "trusted": is_admin,
                    },
                )
                self._json(200, {"ok": True, **result})
                return
            if path == "/api/v1/lessons/batch-delete" and method == "POST":
                # Consume the body before a 403 so rejected keep-alive requests
                # cannot leave JSON bytes on the socket and desync the next request.
                body = self._read_json()
                if user.get("role") != "admin":
                    self._error(403, "forbidden", "administrator required")
                    return
                lesson_ids = body.get("lesson_ids")
                if not isinstance(lesson_ids, list):
                    self._error(400, "invalid_input", "lesson_ids must be an array")
                    return
                result = app.jobs.service.lessons.delete(lesson_ids)
                app.database.audit(
                    int(user["id"]),
                    "lesson.batch_delete",
                    None,
                    {
                        "requested": len(lesson_ids),
                        "deleted": result["deleted"],
                        "missing": len(result["missing"]),
                    },
                )
                self._json(200, {"ok": True, **result})
                return
            if path == "/api/v1/lessons" and method == "GET":
                query = self._query()
                result = app.jobs.service.recall_unpack_lessons(
                    query=(query.get("query") or [None])[0],
                    shell=(query.get("shell") or [None])[0],
                    device_abi=(query.get("device_abi") or [None])[0],
                    framework=(query.get("framework") or [None])[0],
                    package_name=(query.get("package") or [None])[0],
                    limit=int((query.get("limit") or ["20"])[0]),
                )
                self._json(200, result)
                return
            if path == "/api/v1/lessons" and method == "POST":
                body = self._read_json()
                is_admin = user.get("role") == "admin"
                scope = str(body.get("scope") or "global").strip().lower()
                if scope not in ("global", "package"):
                    self._error(400, "invalid_input", "scope must be global or package")
                    return
                package_name = body.get("package_name") or body.get("package")
                if scope == "package" and not str(package_name or "").strip():
                    self._error(400, "invalid_input", "package_name is required when scope=package")
                    return
                # Global lessons influence every user, so only an administrator
                # may publish one. Package-scoped lessons from regular users are
                # accepted but stored untrusted and excluded from ranking.
                if scope == "global" and not is_admin:
                    self._error(403, "forbidden", "administrator required for global lessons")
                    return
                required = ["title", "scenario", "solution"]
                missing = [key for key in required if not str(body.get(key) or "").strip()]
                if missing:
                    self._error(400, "invalid_input", "missing: " + ", ".join(missing))
                    return
                source = "manual" if is_admin else "web-import"
                payload = {
                    "title": str(body["title"]),
                    "scenario": str(body["scenario"]),
                    "solution": str(body["solution"]),
                    "root_cause": body.get("root_cause"),
                    "shell": body.get("shell"),
                    "device_abi": body.get("device_abi"),
                    "apk_abis": body.get("apk_abis"),
                    "framework": body.get("framework"),
                    "package_scope": str(package_name) if scope == "package" else "global",
                    "winning_method": body.get("winning_method"),
                    "failed_methods": body.get("failed_methods"),
                    "symptoms": body.get("symptoms"),
                    "tags": body.get("tags"),
                    "evidence_links": body.get("evidence_links"),
                    "confidence": body.get("confidence") or "analyst",
                    "trusted": is_admin,
                    "source": source,
                }
                store = getattr(app.jobs.service, "lessons", None)
                try:
                    if store is not None and hasattr(store, "record"):
                        lesson, status = store.record(
                            payload, kind="manual", success=True, trusted=is_admin, source=source
                        )
                        result = {
                            "memory_dir": str(store.root),
                            "status": status,
                            "lesson": lesson,
                            "stats": store.stats(),
                        }
                    else:  # pragma: no cover - legacy service without .lessons
                        result = app.jobs.service.remember_unpack_lesson(
                            title=payload["title"],
                            scenario=payload["scenario"],
                            solution=payload["solution"],
                            root_cause=payload["root_cause"],
                            shell=payload["shell"],
                            device_abi=payload["device_abi"],
                            apk_abis=payload["apk_abis"],
                            framework=payload["framework"],
                            package_name=package_name,
                            winning_method=payload["winning_method"],
                            failed_methods=payload["failed_methods"],
                            symptoms=payload["symptoms"],
                            tags=payload["tags"],
                            evidence_links=payload["evidence_links"],
                            confidence=payload["confidence"],
                            scope=scope,
                        )
                except AnalysisError as exc:
                    self._json(400, {"error": exc.projection()})
                    return
                except (TypeError, ValueError) as exc:
                    self._error(400, "invalid_input", str(exc))
                    return
                app.database.audit(
                    int(user["id"]),
                    "lesson.remember",
                    result.get("lesson", {}).get("lesson_id"),
                    {"scope": scope, "trusted": is_admin},
                )
                self._json(201, result)
                return
            match = re.match(r"^/api/v1/lessons/([A-Za-z0-9_-]{1,120})$", path)
            if match and method == "PATCH":
                # Consume the body before a 403 so rejected keep-alive requests
                # cannot leave JSON bytes on the socket and desync the next request.
                body = self._read_json()
                if user.get("role") != "admin":
                    self._error(403, "forbidden", "administrator required")
                    return
                lesson_id = match.group(1)
                updated = app.jobs.service.lessons.update(lesson_id, body)
                if updated is None:
                    self._error(404, "not_found", "lesson not found")
                    return
                app.database.audit(
                    int(user["id"]),
                    "lesson.update",
                    lesson_id,
                    {"fields": sorted(body)},
                )
                self._json(
                    200,
                    {
                        "ok": True,
                        "lesson": updated,
                        "stats": app.jobs.service.lessons.stats(),
                    },
                )
                return
            match = re.match(r"^/api/v1/lessons/([A-Za-z0-9_-]{1,120})$", path)
            if match and method == "DELETE":
                if user.get("role") != "admin":
                    self._error(403, "forbidden", "administrator required")
                    return
                lesson_id = match.group(1)
                result = app.jobs.service.lessons.delete([lesson_id])
                if not result["deleted"]:
                    self._error(404, "not_found", "lesson not found")
                    return
                app.database.audit(int(user["id"]), "lesson.delete", lesson_id)
                self._json(
                    200,
                    {
                        "ok": True,
                        "deleted": result["deleted"],
                        "lesson_id": lesson_id,
                        "total": result["total"],
                    },
                )
                return
            self._error(404, "not_found", "not found")

        # -------------------------------------------------------------- MCP HTTP
        @staticmethod
        def _mcp_state(name: str, factory: Any) -> Any:
            holder = getattr(app, name, None)
            if holder is None:
                holder = factory()
                try:
                    setattr(app, name, holder)
                except Exception:  # pragma: no cover - defensive
                    pass
            return holder

        def _mcp_run_owner(self, run_id: str) -> int | None:
            try:
                jobs, _ = app.database.list_jobs(limit=100000)
            except Exception:
                jobs = []
            for job in jobs:
                if str(job.get("run_id") or "") == run_id:
                    try:
                        return int(job.get("user_id") or 0)
                    except (TypeError, ValueError):
                        return 0
            owners = self._mcp_state("mcp_run_owners", dict)
            return owners.get(run_id)

        def _mcp_check_run(self, tool: str, run_id: str, user: dict[str, Any]) -> None:
            run_id = str(run_id or "").strip()
            if not run_id:
                return
            if not re.match(r"^run_[A-Za-z0-9_]+$", run_id):
                raise AnalysisError("invalid_input", f"invalid run id: {run_id!r}")
            if user.get("role") == "admin":
                return
            owner = self._mcp_run_owner(run_id)
            if owner is None:
                # A new run may be created by a tool that accepts a caller
                # supplied run id; only allow that when it does not exist yet.
                run_dir = Path(app.config.runs_dir) / run_id
                if tool in ("inspect_apk", "inspect_android_device") and not run_dir.exists():
                    return
                raise AnalysisError(
                    "permission_denied",
                    "run is not owned by this account; inspect the APK first to create your own run",
                    details={"run_id": run_id},
                )
            if owner != int(user["id"]):
                raise AnalysisError(
                    "permission_denied",
                    "run belongs to another user",
                    details={"run_id": run_id},
                )

        def _mcp_owned_upload(self, resolved: Path, user: dict[str, Any]) -> bool:
            try:
                uploads = app.database.list_uploads(user_id=int(user["id"]), limit=100000)
            except Exception:  # pragma: no cover - defensive
                uploads = []
            for upload in uploads:
                try:
                    upload_path = Path(str(upload.get("path") or "")).resolve()
                except OSError:
                    continue
                base = upload_path if upload_path.is_dir() else upload_path.parent
                if resolved == upload_path or _is_relative(resolved, base):
                    return True
            return False

        def _mcp_check_path(
            self,
            field: str,
            raw_path: Any,
            user: dict[str, Any],
            *,
            run_id: str = "",
        ) -> str:
            """Confine an MCP file path to the upload/run roots and its owner.

            Administrative accounts may address any path below those roots;
            regular users are limited to their own uploads and their own run
            directories. When the tool names a run, paths under the runs root
            must stay inside that run. Traversal and absolute paths elsewhere
            are rejected after resolution (which also follows symlinks).
            """
            try:
                resolved = Path(str(raw_path)).expanduser().resolve()
            except (OSError, ValueError) as exc:
                raise AnalysisError("invalid_input", f"invalid {field}: {exc}") from exc
            uploads_root = Path(app.config.uploads_dir).resolve()
            runs_root = Path(app.config.runs_dir).resolve()
            inside_upload = _is_relative(resolved, uploads_root)
            inside_run = _is_relative(resolved, runs_root)
            if resolved == uploads_root or resolved == runs_root or not (inside_upload or inside_run):
                raise AnalysisError(
                    "permission_denied",
                    f"{field} must point inside the upload or run directory",
                )
            if user.get("role") == "admin":
                return str(resolved)
            if inside_upload:
                if self._mcp_owned_upload(resolved, user):
                    return str(resolved)
                raise AnalysisError("permission_denied", f"{field} belongs to another user's upload")
            # Inside the shared runs root: the first path component is the run id.
            try:
                parts = resolved.relative_to(runs_root).parts
            except ValueError:  # pragma: no cover - guarded above
                parts = ()
            path_run_id = parts[0] if parts else ""
            if run_id and path_run_id and path_run_id != run_id:
                raise AnalysisError(
                    "permission_denied",
                    f"{field} must stay inside run {run_id}",
                    details={"run_id": run_id},
                )
            if path_run_id:
                owner = self._mcp_run_owner(path_run_id)
                if owner is not None and owner == int(user["id"]):
                    return str(resolved)
            raise AnalysisError("permission_denied", f"{field} belongs to another user's run")

        def _mcp_check_apk_path(self, raw_path: Any, user: dict[str, Any], *, run_id: str = "") -> str:
            return self._mcp_check_path("apk_path", raw_path, user, run_id=run_id)

        def _mcp(self) -> None:
            user, kind = self._auth()
            if user is None:
                return
            if kind != "bearer":
                self._error(401, "unauthorized", "MCP requires a Bearer token")
                return
            try:
                message = self._read_json(4 * 1024 * 1024)
            except ValueError as exc:
                self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
                return
            method = message.get("method")
            request_id = message.get("id")
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            if method == "notifications/initialized":
                self.send_response(204)
                self.end_headers()
                return
            if method == "notifications/cancelled":
                # Apply cancellation to the matching in-flight tools/call.
                # Only acknowledged when a real request was cancelled; a fake
                # 202 would let clients believe an operation stopped.
                request_to_cancel = params.get("requestId")
                event = None
                if request_to_cancel is not None:
                    cancels = self._mcp_state("mcp_cancels", dict)
                    lock = self._mcp_state("mcp_lock", threading.Lock)
                    with lock:
                        event = cancels.get(_mcp_request_key(request_to_cancel))
                if event is None:
                    self._json(
                        501,
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": "cancel_not_supported",
                                "message": "no active tools/call matches params.requestId; pass the request id of an in-flight call",
                            },
                        },
                    )
                    return
                event.set()
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if method == "initialize":
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": "apk-unpack-backend", "version": "0.1.0"},
                            "instructions": "Authenticated MCP bridge over the APK unpack agent tools.",
                        },
                    },
                )
                return
            if method == "ping":
                self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": {}})
                return
            if method == "tools/list":
                self._json(
                    200,
                    {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [spec.to_mcp() for spec in TOOL_SPECS]}},
                )
                return
            if method != "tools/call":
                self._json(
                    200,
                    {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"unknown method: {method}"}},
                )
                return
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str) or name not in TOOLS_BY_NAME:
                self._json(
                    200,
                    {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": f"unknown tool: {name}"}},
                )
                return
            spec = TOOLS_BY_NAME[name]
            if not isinstance(arguments, dict):
                self._json(
                    200,
                    {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "arguments must be an object"}},
                )
                return
            unexpected = [key for key in arguments if key not in (spec.input_schema.get("properties") or {})]
            if unexpected:
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32602, "message": f"unexpected argument(s): {', '.join(sorted(unexpected))}"},
                    },
                )
                return
            missing = [key for key in spec.input_schema.get("required", []) if arguments.get(key) in (None, "")]
            if missing:
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32602, "message": f"missing required argument(s): {', '.join(missing)}"},
                    },
                )
                return
            # Lesson recording publishes knowledge that other users recall.
            # Only administrators may create trusted lessons, so reject
            # non-admin MCP callers instead of letting the workflow persist a
            # default-trusted entry. Admin behavior is unchanged.
            if name == "remember_unpack_lesson" and user.get("role") != "admin":
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(
                                        {
                                            "error": {
                                                "code": "forbidden",
                                                "category": "access_denied",
                                                "message": "administrator required to record unpack lessons",
                                                "details": {"admin_required": True},
                                            }
                                        },
                                        ensure_ascii=False,
                                    ),
                                }
                            ],
                            "isError": True,
                        },
                    },
                )
                return
            # Restrict run and file-path access to the caller's own uploads/runs.
            try:
                if name in RUN_SCOPED and arguments.get("run_id"):
                    self._mcp_check_run(name, str(arguments["run_id"]), user)
                run_id = str(arguments.get("run_id") or "").strip()
                if arguments.get("apk_path"):
                    arguments["apk_path"] = self._mcp_check_apk_path(
                        arguments["apk_path"], user, run_id=run_id
                    )
                # Every host path argument must stay inside the allowed roots.
                for field in ("input_dir", "output_dir", "dex_dir", "output_path"):
                    if arguments.get(field):
                        arguments[field] = self._mcp_check_path(
                            field, arguments[field], user, run_id=run_id
                        )
                for field in ("input_paths", "dex_paths"):
                    if arguments.get(field) is None:
                        continue
                    values = arguments[field]
                    if not isinstance(values, list) or not all(
                        isinstance(item, str) and item for item in values
                    ):
                        raise AnalysisError("invalid_input", f"{field} must be an array of paths")
                    arguments[field] = [
                        self._mcp_check_path(field, item, user, run_id=run_id)
                        for item in values
                    ]
                # frida_server_path may be a device path; only confine it when
                # it is an existing local file (a binary the server would push).
                frida_path = arguments.get("frida_server_path")
                if frida_path:
                    candidate = Path(str(frida_path)).expanduser()
                    if candidate.exists():
                        arguments["frida_server_path"] = self._mcp_check_path(
                            "frida_server_path", candidate, user, run_id=run_id
                        )
            except AnalysisError as exc:
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps({"error": exc.projection()}, ensure_ascii=False)}],
                            "isError": True,
                        },
                    },
                )
                return
            cancel = threading.Event()
            # Canonicalise duplicate adb transports before taking the per-device
            # lock or calling a device tool.
            serial = arguments.get("serial") or app.config.serial
            canonical = getattr(app.jobs, "canonical_serial", None)
            if serial and "serial" in (spec.input_schema.get("properties") or {}) and callable(canonical):
                try:
                    serial = canonical(str(serial)) or str(serial)
                except Exception:  # pragma: no cover - defensive
                    serial = str(serial)
                arguments["serial"] = serial
            cancel_key = _mcp_request_key(request_id) if request_id is not None else None
            if cancel_key:
                cancels = self._mcp_state("mcp_cancels", dict)
                lock = self._mcp_state("mcp_lock", threading.Lock)
                with lock:
                    cancels[cancel_key] = cancel
            try:
                if name in DEVICE_TOOLS:
                    with app.jobs.devices.acquire(serial):
                        result = app.jobs.service.call_tool(name, arguments, cancel)
                else:
                    result = app.jobs.service.call_tool(name, arguments, cancel)
                # Remember ownership of runs created directly through MCP.
                if isinstance(result, dict):
                    created_run = str(result.get("run_id") or arguments.get("run_id") or "").strip()
                    if created_run and re.match(r"^run_[A-Za-z0-9_]+$", created_run):
                        owners = self._mcp_state("mcp_run_owners", dict)
                        owners[created_run] = int(user["id"])
                text = json.dumps(result, ensure_ascii=False, default=str)
                if len(text.encode("utf-8")) > 8 * 1024 * 1024:
                    error = {
                        "code": "resource_constraint",
                        "message": "MCP response exceeds 8 MiB",
                        "remediation": "Use get_evidence/export_evidence_bundle and page the result.",
                    }
                    self._json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "result": {
                                "content": [{"type": "text", "text": json.dumps({"error": error}, ensure_ascii=False)}],
                                "isError": True,
                            },
                        },
                    )
                    return
                app.database.audit(int(user["id"]), "mcp.tools_call", name)
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [{"type": "text", "text": text}],
                            "structuredContent": result,
                            "isError": False,
                        },
                    },
                )
            except AnalysisError as exc:
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps({"error": exc.projection()}, ensure_ascii=False)}],
                            "isError": True,
                        },
                    },
                )
            except Exception as exc:  # pragma: no cover - defensive
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps({"error": project_error(exc)}, ensure_ascii=False)}],
                            "isError": True,
                        },
                    },
                )
            finally:
                if cancel_key:
                    cancels = self._mcp_state("mcp_cancels", dict)
                    lock = self._mcp_state("mcp_lock", threading.Lock)
                    with lock:
                        cancels.pop(cancel_key, None)

        # -------------------------------------------------------------- static
        def _static(self, path: str) -> None:
            if path.startswith("/static/"):
                name = path[len("/static/") :]
                candidate = (app.config.static_dir / name).resolve()
                if app.config.static_dir.resolve() not in candidate.parents:
                    self._error(404, "not_found", "not found")
                    return
                if not candidate.is_file():
                    self._error(404, "not_found", "not found")
                    return
                self._serve_file(candidate)
                return
            if path == "/" or path == "/login" or path.startswith("/jobs/") or path in ("/lessons", "/admin"):
                index = app.config.static_dir / "index.html"
                if index.is_file():
                    self._serve_file(index)
                    return
            self._error(404, "not_found", "not found")

        def _serve_file(self, path: Path) -> None:
            content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") or content_type == "application/javascript" else ""))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _parse_multipart_file(body: bytes, content_type: str) -> tuple[str | None, bytes | None]:
    if "multipart/form-data" not in content_type.lower():
        return None, None
    if "boundary=" not in content_type:
        return None, None
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    message = email.parser.BytesParser(policy=email.policy.default).parsebytes(header + body)
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
        return filename, payload
    return None, None


ACTIVE_JOB_STATES = {"queued", "running"}
TERMINAL_JOB_STATES = {"succeeded", "partial", "failed", "cancelled"}
# Only a finished job that did not fully succeed can be retried.  Retrying a
# queued/running job would duplicate device work, and a succeeded job already
# produced verified artifacts.
RETRYABLE_JOB_STATES = {"failed", "partial", "cancelled"}


def _mcp_request_key(request_id: Any) -> str:
    """Stable key for matching a JSON-RPC request id with a cancel notification."""
    return json.dumps(request_id, sort_keys=True, default=str)


def _is_relative(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _subdirs(path: Path) -> list[Path]:
    try:
        return [child for child in path.iterdir() if child.is_dir()]
    except OSError:
        return []


def _path_bytes(path: Path) -> int:
    try:
        if path.is_file():
            return path.stat().st_size
        if not path.is_dir():
            return 0
        total = 0
        for child in path.rglob("*"):
            try:
                if child.is_file():
                    total += child.stat().st_size
            except OSError:
                continue
        return total
    except OSError:
        return 0


def _upload_bytes(upload: dict[str, Any]) -> int:
    raw = str(upload.get("path") or "")
    if not raw:
        return 0
    try:
        path = Path(raw)
        return _path_bytes(path)
    except OSError:
        return 0


def _mtime_iso(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    except OSError:
        return ""


def _older_than(value: Any, cutoff: datetime | None) -> bool:
    if cutoff is None:
        return True
    if not value:
        return True
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return True
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp < cutoff


def _chat_file_public(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "chat_id": record.get("chat_id"),
        "filename": record.get("filename"),
        "size": int(record.get("size") or 0),
        "mime": record.get("mime"),
        "sha256": record.get("sha256"),
        "created_at": record.get("created_at"),
    }


def _job_public(job: dict[str, Any]) -> dict[str, Any]:
    result = dict(job)
    result.pop("options_json", None)
    result.pop("error_json", None)
    # Cleanup outcome is persisted inside error_json; expose the common fields
    # at the top level so the UI does not have to dig into the error object.
    error = result.get("error")
    if isinstance(error, dict):
        for key in ("cleanup_status", "cleanup_error"):
            if result.get(key) is None and error.get(key) is not None:
                result[key] = error[key]
        if error.get("cleanup_status") == "incomplete":
            result.setdefault("cleanup_incomplete", True)
    result["artifacts"] = {
        key: bool(result.get(key))
        for key in ("dex_zip", "source_zip", "evidence_zip", "logs_zip", "full_zip")
    }
    return result


def _job_public_many(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_job_public(job) for job in jobs]


class ApuHTTPServer(ThreadingHTTPServer):
    """Threading server that treats client disconnects as normal disconnects."""

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


def serve(app: BackendApp) -> None:
    handler = make_handler(app)
    server = ApuHTTPServer((app.config.host, app.config.port), handler)
    print(f"[apu-web] listening on http://{app.config.host}:{app.config.port}")
    try:
        server.serve_forever()
    finally:
        app.stop()
        server.server_close()
