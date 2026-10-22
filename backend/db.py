from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS model_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    base_url TEXT NOT NULL,
    model TEXT NOT NULL,
    context_window INTEGER NOT NULL DEFAULT 65536,
    max_tokens INTEGER NOT NULL DEFAULT 4096,
    max_steps INTEGER NOT NULL DEFAULT 24,
    timeout_s INTEGER NOT NULL DEFAULT 180,
    temperature REAL NOT NULL DEFAULT 0.1,
    tool_result_chars INTEGER NOT NULL DEFAULT 16000,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS skills (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'custom',
    path TEXT,
    content TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    transport TEXT NOT NULL,
    url TEXT,
    command TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_status TEXT,
    last_checked_at TEXT,
    tools_json TEXT,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'llm',
    provider_id TEXT,
    skill_ids_json TEXT NOT NULL DEFAULT '[]',
    mcp_ids_json TEXT NOT NULL DEFAULT '[]',
    system_prompt TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES model_providers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS devices (
    serial TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'auto',
    address TEXT,
    notes TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'manual',
    hidden INTEGER NOT NULL DEFAULT 0,
    arch TEXT NOT NULL DEFAULT '',
    last_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS uploads (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    serial TEXT,
    options_json TEXT NOT NULL,
    run_id TEXT,
    error_json TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    dex_zip TEXT,
    source_zip TEXT,
    evidence_zip TEXT,
    logs_zip TEXT,
    full_zip TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    ts TEXT NOT NULL,
    data_json TEXT
);

CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    agent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    meta_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_user_created ON jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS chat_files (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chats_user_updated ON chats(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_messages_chat ON chat_messages(chat_id, id);
CREATE INDEX IF NOT EXISTS idx_chat_files_chat ON chat_files(chat_id, created_at);
CREATE INDEX IF NOT EXISTS idx_events_job_seq ON events(job_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_agents_provider ON agents(provider_id);
CREATE INDEX IF NOT EXISTS idx_mcp_enabled ON mcp_servers(enabled);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _conn(self):
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._conn() as connection:
            connection.executescript(SCHEMA)
            # Existing databases do not get new columns from CREATE TABLE IF NOT EXISTS.
            for table in ("skills", "mcp_servers", "agents"):
                columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                if "owner_id" not in columns:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
                connection.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_owner ON {table}(owner_id)")
            device_columns = {row["name"] for row in connection.execute("PRAGMA table_info(devices)")}
            if "hidden" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")
            if "arch" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN arch TEXT NOT NULL DEFAULT ''")

    # ------------------------------------------------------------------ users
    def create_user(self, username: str, password_hash: str, salt: str, role: str = "user") -> dict[str, Any]:
        with self._write_lock, self._conn() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username,password_hash,salt,role,disabled,created_at) VALUES(?,?,?,?,0,?)",
                (username, password_hash, salt, role, _now()),
            )
            user_id = int(cursor.lastrowid)
        return self.get_user(user_id) or {}

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def get_user_by_name(self, username: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())

    def list_users(self) -> list[dict[str, Any]]:
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT id,username,role,disabled,created_at FROM users ORDER BY id"
            ).fetchall()
            return [dict(row) for row in rows]

    def count_users(self) -> int:
        with self._conn() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM users").fetchone()
            return int(row["n"]) if row else 0

    def count_admins(self, *, active_only: bool = True) -> int:
        with self._conn() as connection:
            sql = "SELECT COUNT(*) AS n FROM users WHERE role='admin'"
            if active_only:
                sql += " AND disabled=0"
            row = connection.execute(sql).fetchone()
            return int(row["n"]) if row else 0

    def delete_user(self, user_id: int) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            connection.execute("DELETE FROM users WHERE id=?", (user_id,))

    def delete_sessions_for_user(self, user_id: int) -> int:
        with self._write_lock, self._conn() as connection:
            cursor = connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            return int(cursor.rowcount or 0)

    def update_user(self, user_id: int, **changes: Any) -> None:
        allowed = {"role", "disabled", "password_hash", "salt"}
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE users SET {assignments} WHERE id=?", (*fields.values(), user_id))

    # ------------------------------------------------------------------ sessions
    def create_session(
        self,
        token_hash: str,
        user_id: int,
        days: int,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,ip,user_agent) VALUES(?,?,?,?,?,?)",
                (token_hash, user_id, _now(), expires, ip, user_agent),
            )

    def get_session(self, token_hash: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            row = connection.execute(
                "SELECT s.*, u.username, u.role, u.disabled FROM sessions s "
                "JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            session = dict(row)
            if session["disabled"]:
                return None
            if session["expires_at"] < _now():
                self.delete_session(token_hash)
                return None
            return session

    def delete_session(self, token_hash: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def cleanup_sessions(self) -> int:
        with self._write_lock, self._conn() as connection:
            cursor = connection.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
            return cursor.rowcount

    # ------------------------------------------------------------------ devices
    def upsert_device(
        self,
        serial: str,
        *,
        name: str | None = None,
        kind: str | None = None,
        address: str | None = None,
        notes: str | None = None,
        source: str = "auto",
        seen: bool = False,
        arch: str | None = None,
    ) -> dict[str, Any]:
        now = _now()
        arch = (arch or "").strip()[:40]
        with self._write_lock, self._conn() as connection:
            existing = connection.execute("SELECT * FROM devices WHERE serial=?", (serial,)).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO devices(serial,name,kind,address,notes,enabled,source,hidden,arch,last_seen_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,1,?,0,?,?,?,?)",
                    (
                        serial,
                        (name or serial)[:200],
                        (kind or "auto")[:40],
                        (address or serial)[:400],
                        (notes or "")[:2000],
                        source if source in ("auto", "manual") else "auto",
                        arch,
                        now if seen else None,
                        now,
                        now,
                    ),
                )
            else:
                fields: dict[str, Any] = {"updated_at": now}
                if seen:
                    fields["last_seen_at"] = now
                row = dict(existing)
                # Auto-discovery never overwrites a manually assigned name/notes.
                if name and (not row.get("name") or row.get("name") == row.get("serial") or row.get("source") != "manual"):
                    fields["name"] = name[:200]
                if kind and row.get("kind") in (None, "", "auto"):
                    fields["kind"] = kind[:40]
                if address and not row.get("address"):
                    fields["address"] = address[:400]
                if arch and row.get("arch") != arch:
                    fields["arch"] = arch
                assignments = ", ".join(f"{key}=?" for key in fields)
                connection.execute(
                    f"UPDATE devices SET {assignments} WHERE serial=?",
                    (*fields.values(), serial),
                )
        return self.get_device(serial) or {}

    def list_devices(self, include_hidden: bool = False) -> list[dict[str, Any]]:
        with self._conn() as connection:
            sql = "SELECT * FROM devices"
            if not include_hidden:
                sql += " WHERE hidden=0"
            sql += " ORDER BY serial"
            rows = connection.execute(sql).fetchall()
            return [dict(row) for row in rows]

    def get_device(self, serial: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM devices WHERE serial=?", (serial,)).fetchone())

    def update_device(self, serial: str, **changes: Any) -> None:
        allowed = {"name", "kind", "address", "notes", "enabled", "source", "hidden", "arch"}
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        fields["updated_at"] = _now()
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE devices SET {assignments} WHERE serial=?", (*fields.values(), serial))

    def delete_device(self, serial: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM devices WHERE serial=?", (serial,))

    def hide_device(self, serial: str) -> None:
        """Hide a device from discovery without disconnecting adb."""
        now = _now()
        with self._write_lock, self._conn() as connection:
            row = connection.execute("SELECT serial FROM devices WHERE serial=?", (serial,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO devices(serial,name,kind,address,notes,enabled,source,hidden,last_seen_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,1,'manual',1,NULL,?,?)",
                    (serial, serial, "auto", serial, "", now, now),
                )
            else:
                connection.execute(
                    "UPDATE devices SET hidden=1, updated_at=? WHERE serial=?", (now, serial)
                )

    # ------------------------------------------------------------------ uploads
    def create_upload(
        self,
        upload_id: str,
        user_id: int,
        filename: str,
        path: str,
        size: int,
        sha256: str,
    ) -> dict[str, Any]:
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO uploads(id,user_id,filename,path,size,sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                (upload_id, user_id, filename, path, size, sha256, _now()),
            )
        return self.get_upload(upload_id) or {}

    def get_upload(self, upload_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone())

    def list_uploads(
        self,
        user_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(100000, int(limit)))
        offset = max(0, int(offset))
        where = " WHERE u.user_id=?" if user_id is not None else ""
        values: list[Any] = [user_id] if user_id is not None else []
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT u.*, (SELECT COUNT(*) FROM jobs j WHERE j.upload_id=u.id) AS job_count "
                f"FROM uploads u{where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_upload(self, upload_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM uploads WHERE id=?", (upload_id,))

    # ------------------------------------------------------------------ jobs
    def create_job(
        self,
        job_id: str,
        user_id: int,
        upload_id: str,
        engine: str,
        serial: str | None,
        options: dict[str, Any],
        run_id: str,
    ) -> dict[str, Any]:
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO jobs(id,user_id,upload_id,engine,status,stage,serial,options_json,run_id,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    job_id,
                    user_id,
                    upload_id,
                    engine,
                    "queued",
                    "queued",
                    serial,
                    json.dumps(options, ensure_ascii=False),
                    run_id,
                    _now(),
                ),
            )
        return self.get_job(job_id) or {}

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            return self._job(row)

    def list_jobs(
        self,
        *,
        user_id: int | None = None,
        status: str | None = None,
        engine: str | None = None,
        upload_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if user_id is not None:
            clauses.append("user_id=?")
            values.append(user_id)
        if status:
            clauses.append("status=?")
            values.append(status)
        if engine:
            clauses.append("engine=?")
            values.append(engine)
        if upload_id:
            clauses.append("upload_id=?")
            values.append(upload_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn() as connection:
            total_row = connection.execute(f"SELECT COUNT(*) AS n FROM jobs{where}", values).fetchone()
            rows = connection.execute(
                f"SELECT * FROM jobs{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
            return [self._job(row) or {} for row in rows], int(total_row["n"]) if total_row else 0

    def _job(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        job = dict(row)
        for key in ("options_json", "error_json"):
            if job.get(key):
                try:
                    job[key.replace("_json", "")] = json.loads(job.pop(key))
                except json.JSONDecodeError:
                    job[key.replace("_json", "")] = None
            else:
                job.pop(key, None)
                job[key.replace("_json", "")] = None
        return job

    def update_job(self, job_id: str, **changes: Any) -> None:
        allowed = {
            "status",
            "stage",
            "serial",
            "run_id",
            "error_json",
            "started_at",
            "finished_at",
            "dex_zip",
            "source_zip",
            "evidence_zip",
            "logs_zip",
            "full_zip",
            "cancel_requested",
        }
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE jobs SET {assignments} WHERE id=?", (*fields.values(), job_id))

    def delete_job(self, job_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def job_counts(self) -> dict[str, int]:
        with self._conn() as connection:
            rows = connection.execute("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status").fetchall()
            return {row["status"]: int(row["n"]) for row in rows}

    # ------------------------------------------------------------------ chats
    def create_chat(self, chat_id: str, user_id: int, title: str, agent_id: str | None) -> dict[str, Any]:
        now = _now()
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO chats(id,user_id,title,agent_id,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (chat_id, user_id, title, agent_id, now, now),
            )
        return self.get_chat(chat_id) or {}

    def get_chat(self, chat_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone())

    def list_chats(self, user_id: int) -> list[dict[str, Any]]:
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT c.*, (SELECT COUNT(*) FROM chat_messages m WHERE m.chat_id=c.id) AS message_count "
                "FROM chats c WHERE c.user_id=? ORDER BY c.updated_at DESC, c.id DESC",
                (user_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def update_chat(self, chat_id: str, *, title: str | None = None, agent_id: str | None = None) -> None:
        fields: dict[str, Any] = {"updated_at": _now()}
        if title is not None:
            fields["title"] = title
        if agent_id is not None:
            fields["agent_id"] = agent_id
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE chats SET {assignments} WHERE id=?", (*fields.values(), chat_id))

    def touch_chat(self, chat_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("UPDATE chats SET updated_at=? WHERE id=?", (_now(), chat_id))

    def delete_chat(self, chat_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM chats WHERE id=?", (chat_id,))

    def clear_chat_messages(self, chat_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM chat_messages WHERE chat_id=?", (chat_id,))
            connection.execute("UPDATE chats SET updated_at=? WHERE id=?", (_now(), chat_id))

    def append_chat_message(
        self,
        chat_id: str,
        role: str,
        content: str,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._write_lock, self._conn() as connection:
            cursor = connection.execute(
                "INSERT INTO chat_messages(chat_id,role,content,meta_json,created_at) VALUES(?,?,?,?,?)",
                (chat_id, role, content, json.dumps(meta, ensure_ascii=False) if meta else None, _now()),
            )
            message_id = int(cursor.lastrowid)
            connection.execute("UPDATE chats SET updated_at=? WHERE id=?", (_now(), chat_id))
        return self.get_chat_message(int(message_id)) or {}

    def get_chat_message(self, message_id: int) -> dict[str, Any] | None:
        with self._conn() as connection:
            row = connection.execute("SELECT * FROM chat_messages WHERE id=?", (message_id,)).fetchone()
            return self._chat_message(row)

    def list_chat_messages(self, chat_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT * FROM (SELECT * FROM chat_messages WHERE chat_id=? ORDER BY id DESC LIMIT ?) "
                "ORDER BY id ASC",
                (chat_id, max(1, min(2000, int(limit)))),
            ).fetchall()
            return [self._chat_message(row) for row in rows]

    def create_chat_file(
        self,
        file_id: str,
        chat_id: str,
        user_id: int,
        filename: str,
        path: str,
        size: int,
        mime: str | None,
        digest: str,
    ) -> dict[str, Any]:
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO chat_files(id,chat_id,user_id,filename,path,size,mime,sha256,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (file_id, chat_id, user_id, filename, path, size, mime, digest, _now()),
            )
        return self.get_chat_file(file_id) or {}

    def get_chat_file(self, file_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM chat_files WHERE id=?", (file_id,)).fetchone())

    def list_chat_files(self, chat_id: str, limit: int = 500) -> list[dict[str, Any]]:
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT * FROM chat_files WHERE chat_id=? ORDER BY created_at ASC LIMIT ?",
                (chat_id, max(1, min(2000, int(limit)))),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_chat_file(self, file_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM chat_files WHERE id=?", (file_id,))

    def delete_chat_files(self, chat_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM chat_files WHERE chat_id=?", (chat_id,))

    def _chat_message(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        message = dict(row)
        raw = message.pop("meta_json", None)
        try:
            message["meta"] = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            message["meta"] = {}
        return message

    # ------------------------------------------------------------------ events
    def append_event(
        self,
        job_id: str,
        kind: str,
        message: str = "",
        data: dict[str, Any] | None = None,
        level: str = "info",
    ) -> dict[str, Any]:
        with self._write_lock, self._conn() as connection:
            cursor = connection.execute(
                "INSERT INTO events(job_id,ts,kind,level,message,data_json) VALUES(?,?,?,?,?,?)",
                (job_id, _now(), kind, level, message, json.dumps(data, ensure_ascii=False) if data else None),
            )
            seq = int(cursor.lastrowid)
        return {
            "seq": seq,
            "job_id": job_id,
            "ts": _now(),
            "kind": kind,
            "level": level,
            "message": message,
            "data": data or {},
        }

    def list_events(self, job_id: str, after_seq: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        with self._conn() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                (job_id, after_seq, limit),
            ).fetchall()
            events: list[dict[str, Any]] = []
            for row in rows:
                event = dict(row)
                try:
                    event["data"] = json.loads(event.pop("data_json")) if event.get("data_json") else {}
                except json.JSONDecodeError:
                    event.pop("data_json", None)
                    event["data"] = {}
                events.append(event)
            return events

    # ------------------------------------------------------------------ model providers
    def create_provider(
        self,
        provider_id: str,
        name: str,
        protocol: str,
        base_url: str,
        model: str,
        context_window: int = 65536,
        max_tokens: int = 4096,
        max_steps: int = 24,
        timeout_s: int = 180,
        temperature: float = 0.1,
        tool_result_chars: int = 16000,
        enabled: int = 1,
    ) -> dict[str, Any]:
        now = _now()
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO model_providers(id,name,protocol,base_url,model,context_window,max_tokens,max_steps,"
                "timeout_s,temperature,tool_result_chars,enabled,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    provider_id,
                    name,
                    protocol,
                    base_url,
                    model,
                    int(context_window),
                    int(max_tokens),
                    int(max_steps),
                    int(timeout_s),
                    float(temperature),
                    int(tool_result_chars),
                    int(enabled),
                    now,
                    now,
                ),
            )
        return self.get_provider(provider_id) or {}

    def list_providers(self) -> list[dict[str, Any]]:
        with self._conn() as connection:
            rows = connection.execute("SELECT * FROM model_providers ORDER BY created_at, id").fetchall()
            return [dict(row) for row in rows]

    def get_provider(self, provider_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM model_providers WHERE id=?", (provider_id,)).fetchone())

    def update_provider(self, provider_id: str, **changes: Any) -> None:
        allowed = {
            "name",
            "protocol",
            "base_url",
            "model",
            "context_window",
            "max_tokens",
            "max_steps",
            "timeout_s",
            "temperature",
            "tool_result_chars",
            "enabled",
        }
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        fields["updated_at"] = _now()
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(
                f"UPDATE model_providers SET {assignments} WHERE id=?",
                (*fields.values(), provider_id),
            )

    def delete_provider(self, provider_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM model_providers WHERE id=?", (provider_id,))

    # ------------------------------------------------------------------ skills
    def create_skill(
        self,
        skill_id: str,
        name: str,
        description: str = "",
        source: str = "custom",
        path: str | None = None,
        content: str | None = None,
        enabled: int = 1,
        owner_id: int | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO skills(id,name,description,source,path,content,enabled,owner_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (skill_id, name, description, source, path, content, int(enabled), owner_id, now, now),
            )
        return self.get_skill(skill_id) or {}

    def list_skills(self, visible_to: int | None = None) -> list[dict[str, Any]]:
        with self._conn() as connection:
            if visible_to is None:
                rows = connection.execute("SELECT * FROM skills ORDER BY source, name").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM skills WHERE owner_id IS NULL OR owner_id=? ORDER BY source, name",
                    (visible_to,),
                ).fetchall()
            return [dict(row) for row in rows]

    def get_skill(self, skill_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return _row(connection.execute("SELECT * FROM skills WHERE id=?", (skill_id,)).fetchone())

    def update_skill(self, skill_id: str, **changes: Any) -> None:
        allowed = {"name", "description", "path", "content", "enabled"}
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        fields["updated_at"] = _now()
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE skills SET {assignments} WHERE id=?", (*fields.values(), skill_id))

    def delete_skill(self, skill_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM skills WHERE id=?", (skill_id,))

    # ------------------------------------------------------------------ mcp servers
    def create_mcp_server(
        self,
        server_id: str,
        name: str,
        transport: str,
        url: str | None = None,
        command: str | None = None,
        enabled: int = 1,
        owner_id: int | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO mcp_servers(id,name,transport,url,command,enabled,owner_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (server_id, name, transport, url, command, int(enabled), owner_id, now, now),
            )
        return self.get_mcp_server(server_id) or {}

    def list_mcp_servers(self, visible_to: int | None = None) -> list[dict[str, Any]]:
        with self._conn() as connection:
            if visible_to is None:
                rows = connection.execute("SELECT * FROM mcp_servers ORDER BY created_at, id").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM mcp_servers WHERE owner_id IS NULL OR owner_id=? ORDER BY created_at, id",
                    (visible_to,),
                ).fetchall()
            return [self._mcp(row) or {} for row in rows]

    def get_mcp_server(self, server_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return self._mcp(connection.execute("SELECT * FROM mcp_servers WHERE id=?", (server_id,)).fetchone())

    def _mcp(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        raw = item.pop("tools_json", None)
        try:
            item["tools"] = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            item["tools"] = []
        return item

    def update_mcp_server(self, server_id: str, **changes: Any) -> None:
        allowed = {
            "name",
            "transport",
            "url",
            "command",
            "enabled",
            "last_status",
            "last_checked_at",
            "tools_json",
        }
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        fields["updated_at"] = _now()
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE mcp_servers SET {assignments} WHERE id=?", (*fields.values(), server_id))

    def delete_mcp_server(self, server_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM mcp_servers WHERE id=?", (server_id,))

    # ------------------------------------------------------------------ agents
    def create_agent(
        self,
        agent_id: str,
        name: str,
        kind: str,
        provider_id: str | None,
        skill_ids: list[str] | None = None,
        mcp_ids: list[str] | None = None,
        system_prompt: str = "",
        enabled: int = 1,
        builtin: int = 0,
        owner_id: int | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO agents(id,name,kind,provider_id,skill_ids_json,mcp_ids_json,system_prompt,"
                "enabled,builtin,owner_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    agent_id,
                    name,
                    kind,
                    provider_id,
                    json.dumps(skill_ids or [], ensure_ascii=False),
                    json.dumps(mcp_ids or [], ensure_ascii=False),
                    system_prompt,
                    int(enabled),
                    int(builtin),
                    owner_id,
                    now,
                    now,
                ),
            )
        return self.get_agent(agent_id) or {}

    def list_agents(self, visible_to: int | None = None) -> list[dict[str, Any]]:
        with self._conn() as connection:
            if visible_to is None:
                rows = connection.execute("SELECT * FROM agents ORDER BY builtin DESC, created_at, id").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM agents WHERE owner_id IS NULL OR owner_id=? "
                    "ORDER BY builtin DESC, created_at, id",
                    (visible_to,),
                ).fetchall()
            return [self._agent(row) or {} for row in rows]

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        with self._conn() as connection:
            return self._agent(connection.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone())

    def _agent(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        for key, target in (("skill_ids_json", "skill_ids"), ("mcp_ids_json", "mcp_ids")):
            raw = item.pop(key, None)
            try:
                item[target] = json.loads(raw) if raw else []
            except json.JSONDecodeError:
                item[target] = []
        return item

    def update_agent(self, agent_id: str, **changes: Any) -> None:
        allowed = {
            "name",
            "kind",
            "provider_id",
            "skill_ids_json",
            "mcp_ids_json",
            "system_prompt",
            "enabled",
        }
        fields = {key: value for key, value in changes.items() if key in allowed}
        if not fields:
            return
        fields["updated_at"] = _now()
        assignments = ", ".join(f"{key}=?" for key in fields)
        with self._write_lock, self._conn() as connection:
            connection.execute(f"UPDATE agents SET {assignments} WHERE id=?", (*fields.values(), agent_id))

    def delete_agent(self, agent_id: str) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    # ------------------------------------------------------------------ audit
    def audit(self, user_id: int | None, action: str, target: str | None = None, data: dict[str, Any] | None = None) -> None:
        with self._write_lock, self._conn() as connection:
            connection.execute(
                "INSERT INTO audit(user_id,action,target,ts,data_json) VALUES(?,?,?,?,?)",
                (user_id, action, target, _now(), json.dumps(data, ensure_ascii=False) if data else None),
            )

    def list_audit(self, limit: int = 100, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        with self._conn() as connection:
            total = connection.execute("SELECT COUNT(*) AS n FROM audit").fetchone()
            rows = connection.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                try:
                    item["data"] = json.loads(item.pop("data_json")) if item.get("data_json") else {}
                except json.JSONDecodeError:
                    item.pop("data_json", None)
                    item["data"] = {}
                items.append(item)
            return items, int(total["n"]) if total else 0
