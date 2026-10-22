from __future__ import annotations

import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..domain.errors import fail
from ..domain.jsonutil import canonical_json
from ..domain.workspace import utc_now

LESSON_SCHEMA_VERSION = 1
MAX_LESSONS = 5000
MAX_TEXT = 4000
MAX_SHORT = 500
MAX_TAGS = 32
MAX_TAG_LENGTH = 64
MAX_EVIDENCE_LINKS = 50
MAX_EXAMPLES = 10
MAX_DELETE_BATCH = 500
MAX_LESSON_ID = 120
LESSON_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,%d}$" % MAX_LESSON_ID)

# Only these fields may be changed through the lesson-management API. Identity,
# counters, evidence and schema fields stay owned by the recorder/importer.
EDITABLE_LESSON_FIELDS = (
    "title",
    "scenario",
    "root_cause",
    "solution",
    "shell",
    "device_abi",
    "framework",
    "tags",
)

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(token|secret|password|passwd|authorization|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
]

DUMP_METHODS = {
    "frida_inmemory",
    "frida_inmemory_spawn",
    "frida_mcookie",
    "frida_mcookie_spawn",
    "memory_dd_retry",
    "disk_pull",
    "memory_dd",
    "freeze_dd",
}


def apk_abi_class(abis: list[str] | set[str] | tuple[str, ...] | None) -> str:
    values = [str(item).lower() for item in (abis or []) if item]
    if not values:
        return "unknown"
    has_arm = any(value.startswith("arm") for value in values)
    has_x86 = any(value.startswith("x86") for value in values)
    if has_arm and has_x86:
        return "mixed"
    if has_arm:
        return "arm-only"
    if has_x86:
        return "x86_64" if any(value == "x86_64" for value in values) else "x86"
    return "unknown"


def _redact(text: str) -> str:
    value = text
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda match: match.group(1) + "=<redacted>" if match.lastindex else "<redacted>", value)
    return value


def _clean(value: Any, limit: int = MAX_TEXT) -> str:
    text = "" if value is None else str(value)
    text = _redact(text).strip()
    return text[:limit]


def _clean_list(values: Any, *, limit: int, item_limit: int = MAX_SHORT) -> list[str]:
    if not values:
        return []
    cleaned: list[str] = []
    for item in values:
        text = _clean(item, item_limit)
        if text and text not in cleaned:
            cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _clean_tags(values: Any) -> list[str]:
    tags = _clean_list(values, limit=MAX_TAGS, item_limit=MAX_TAG_LENGTH)
    return [re.sub(r"\s+", "-", tag.lower()) for tag in tags]


def _clean_lesson_id(value: Any) -> str:
    if not isinstance(value, str):
        raise fail("invalid_input", "lesson_id must be a string")
    text = value.strip()
    if not text or not LESSON_ID_PATTERN.fullmatch(text):
        raise fail(
            "invalid_input",
            "invalid lesson_id (letters, digits, '_' and '-' only)",
            details={"max_length": MAX_LESSON_ID},
        )
    return text


def _normalise_lesson_changes(changes: dict[str, Any]) -> dict[str, Any]:
    """Validate and sanitize writable lesson fields.

    Unknown keys are rejected by the caller. Text is redacted and clamped to
    the same limits the recorder uses, and tags are normalized exactly like a
    recorded lesson so edits cannot corrupt the library schema.
    """
    cleaned: dict[str, Any] = {}
    if "title" in changes:
        title = _clean(changes.get("title"), 240)
        if not title:
            raise fail("invalid_input", "lesson title must not be empty")
        cleaned["title"] = title
    for key in ("scenario", "root_cause", "solution"):
        if key in changes:
            cleaned[key] = _clean(changes.get(key), MAX_TEXT)
    for key in ("shell", "device_abi", "framework"):
        if key in changes:
            cleaned[key] = _clean(changes.get(key), 80) or None
    if "tags" in changes:
        raw = changes.get("tags")
        if raw is None:
            raw = []
        if not isinstance(raw, (list, tuple)):
            raise fail("invalid_input", "tags must be an array of strings")
        for item in raw:
            if not isinstance(item, str):
                raise fail("invalid_input", "tags must be an array of strings")
        # Normalize first, then drop duplicates created by case/whitespace
        # variants ("Flutter" vs "flutter").
        cleaned["tags"] = list(dict.fromkeys(_clean_tags(list(raw))))
    return cleaned


def _normalize_failed_methods(values: Any) -> list[dict[str, Any]]:
    if not values:
        return []
    normalized: list[dict[str, Any]] = []
    for item in values[:10]:
        if isinstance(item, str):
            normalized.append({"method": _clean(item, 120), "code": None, "message": None})
        elif isinstance(item, dict):
            normalized.append(
                {
                    "method": _clean(item.get("method"), 120),
                    "code": _clean(item.get("code"), 120) or None,
                    "message": _clean(item.get("message") or item.get("captured_output"), 500) or None,
                }
            )
    return normalized


def _normalize_examples(values: Any) -> list[dict[str, Any]]:
    if not values:
        return []
    normalized: list[dict[str, Any]] = []
    for item in values[:MAX_EXAMPLES]:
        if isinstance(item, dict):
            normalized.append(
                {
                    "run_id": _clean(item.get("run_id"), 120) or None,
                    "package": _clean(item.get("package"), 200) or None,
                    "evidence_id": _clean(item.get("evidence_id"), 80) or None,
                    "timestamp": _clean(item.get("timestamp"), 40) or None,
                }
            )
    return normalized


NOT_PACKED_ROOT = "APK is not packed; runtime dumping is unnecessary."
PACKED_STATIC_ROOT = (
    "APK is packed; the top-level classes*.dex is a shell loader, not the real application code."
)


def _root_category(lesson: dict[str, Any]) -> str:
    """Return a cross-profile category for root causes that are universal.

    The same "not packed" (or "packed but only the shell DEX was extracted")
    conclusion must not be duplicated once per shell/ABI/framework. Everything
    concrete stays in examples/evidence on the merged lesson.
    """
    root = str(lesson.get("root_cause") or "").strip()
    if root.startswith("APK is not packed"):
        return "not_packed"
    if root.startswith("APK is packed; the top-level classes*.dex is a shell loader"):
        return "packed_static_only"
    return ""


def _canonicalize_root_category(lesson: dict[str, Any], category: str) -> None:
    if category == "not_packed":
        lesson["title"] = "APK is not packed: static route"
        lesson["scenario"] = "APK has no shell indicators or is already unpacked"
        lesson["root_cause"] = NOT_PACKED_ROOT
        lesson["solution"] = (
            "APK is not packed: skip runtime dumping and decompile the APK or extract "
            "classes*.dex directly. This is the fast route for unpacked/system APKs."
        )
        lesson["winning_method"] = "static_route"
        lesson["shell"] = None
        lesson["framework"] = None
        lesson["device_abi"] = None
        lesson["apk_abi_class"] = "unknown"
    elif category == "packed_static_only":
        lesson["title"] = "Packed APK: static route only returned shell classes"
        lesson["scenario"] = "Static classes*.dex extraction on a packed APK"
        lesson["root_cause"] = PACKED_STATIC_ROOT
        lesson["solution"] = (
            "Do not trust static classes*.dex on a packed APK: it contains only the "
            "shell loader. Use a runtime dump (or a compatible ARM/native-bridge "
            "device) and verify class count and completeness."
        )
        lesson["winning_method"] = "static_shell_only"
        lesson["shell"] = None
        lesson["framework"] = None
        lesson["device_abi"] = None
        lesson["apk_abi_class"] = "unknown"


def _auto_route_key(lesson: dict[str, Any]) -> str:
    """Stable identity for an observed route, ignoring volatile error text.

    Two runs that reach the same shell/device/ABI profile through the same
    strategy and the same failed method names are the same lesson even when
    the underlying error codes or messages differ. This is the primary
    content-level dedupe; the fingerprint remains the exact-profile key.
    """
    category = _root_category(lesson)
    if category:
        return canonical_json({"root_cause_category": category})
    failed = sorted(
        {
            str(item.get("method") or "")
            for item in (lesson.get("failed_methods") or [])
            if isinstance(item, dict) and item.get("method")
        }
    )
    return canonical_json(
        {
            "shell": lesson.get("shell") or "unknown",
            "device_abi": lesson.get("device_abi") or "unknown",
            "apk_abi_class": lesson.get("apk_abi_class") or "unknown",
            "framework": lesson.get("framework") or "",
            "winning_method": lesson.get("winning_method") or "none",
            "failed_methods": failed,
        }
    )


def _lesson_fingerprint(kind: str, payload: dict[str, Any]) -> str:
    if kind == "manual":
        identity = {
            "kind": "manual",
            "package_scope": payload.get("package_scope"),
            "shell": payload.get("shell"),
            "title": payload.get("title"),
        }
    else:
        identity = {
            "kind": "auto",
            "shell": payload.get("shell"),
            "device_abi": payload.get("device_abi"),
            "apk_abi_class": payload.get("apk_abi_class"),
            "framework": payload.get("framework"),
            "winning_method": payload.get("winning_method"),
            "failed_signature": [
                f"{item.get('method')}:{item.get('code')}" for item in payload.get("failed_methods") or []
            ],
        }
    # Untrusted lessons get a distinct identity so a web import can never
    # collide with (and later be merged into) a verified local lesson.
    if payload.get("trusted") is False:
        identity["untrusted"] = True
    return canonical_json(identity)


def _is_trusted(lesson: dict[str, Any]) -> bool:
    """Legacy lessons without a ``trusted`` field are trusted."""
    return lesson.get("trusted") is not False


class MemoryStore:
    """Persistent lessons learned across APK unpacking runs."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "lessons.json"
        self.lock_path = self.root / "LOCK"

    def ensure(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        return self.root

    # ------------------------------------------------------------------ persistence
    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"schema_version": LESSON_SCHEMA_VERSION, "updated_at": None, "lessons": []}
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise fail(
                "integrity_mismatch",
                f"memory store is not valid JSON: {exc}",
                details={"path": str(self.path)},
            )
        if not isinstance(data, dict):
            raise fail("integrity_mismatch", f"memory store has an unexpected shape: {self.path}")
        data.setdefault("schema_version", LESSON_SCHEMA_VERSION)
        data.setdefault("lessons", [])
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.ensure()
        data["updated_at"] = utc_now()
        temp = self.path.with_name(self.path.name + ".tmp")
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)

    @contextmanager
    def _lock(self, timeout: float = 10.0) -> Iterator[None]:
        self.ensure()
        deadline = time.monotonic() + max(0.0, timeout)
        acquired = False
        while True:
            try:
                fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, f"{os.getpid()} {time.time()}\n".encode("ascii"))
                os.close(fd)
                acquired = True
                break
            except FileExistsError:
                try:
                    if time.time() - self.lock_path.stat().st_mtime > 60:
                        self.lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise fail("conflict", f"memory store is locked: {self.lock_path}")
                time.sleep(0.05)
        try:
            yield
        finally:
            if acquired:
                try:
                    self.lock_path.unlink(missing_ok=True)
                except OSError:
                    pass

    # ------------------------------------------------------------------ record
    def record(
        self,
        payload: dict[str, Any],
        *,
        kind: str = "auto",
        success: bool = True,
        trusted: bool = True,
        source: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        if kind not in ("auto", "manual"):
            raise fail("invalid_input", f"unknown lesson kind: {kind}")
        now = utc_now()
        trusted = bool(payload.get("trusted", trusted))
        source = _clean(payload.get("source") or source or ("manual" if kind == "manual" else "auto"), 120) or "unknown"
        if str(payload.get("winning_method") or "").strip().lower() in ("none", "failed", "no_method"):
            success = False
        package_scope = payload.get("package_scope")
        if not package_scope:
            if kind == "manual" and payload.get("package_name"):
                package_scope = _clean(payload.get("package_name"), 200)
            else:
                package_scope = "global"
        lesson: dict[str, Any] = {
            "schema_version": LESSON_SCHEMA_VERSION,
            "lesson_id": None,
            "fingerprint": None,
            "kind": kind,
            "title": _clean(payload.get("title"), 240),
            "scenario": _clean(payload.get("scenario")),
            "shell": _clean(payload.get("shell"), 80) or None,
            "device_abi": _clean(payload.get("device_abi"), 80) or None,
            "apk_abi_class": payload.get("apk_abi_class") or apk_abi_class(payload.get("apk_abis")),
            "framework": _clean(payload.get("framework"), 80) or None,
            "package_scope": package_scope,
            "symptoms": _clean_list(payload.get("symptoms"), limit=20),
            "root_cause": _clean(payload.get("root_cause")),
            "solution": _clean(payload.get("solution")),
            "winning_method": _clean(payload.get("winning_method"), 80) or None,
            "failed_methods": _normalize_failed_methods(payload.get("failed_methods")),
            "tags": _clean_tags(payload.get("tags")),
            "evidence_links": _clean_list(payload.get("evidence_links"), limit=MAX_EVIDENCE_LINKS, item_limit=240),
            "examples": _normalize_examples(payload.get("examples")),
            "confidence": payload.get("confidence") or ("observed" if kind == "auto" else "analyst"),
            "trusted": trusted,
            "source": source,
            "occurrences": 1,
            "success_count": 1 if success else 0,
            "created_at": now,
            "updated_at": now,
            "last_seen": now,
            "limitations": _clean_list(payload.get("limitations"), limit=20),
        }
        if lesson["confidence"] not in ("observed", "analyst"):
            raise fail("invalid_input", "confidence must be observed or analyst")
        if kind == "manual":
            missing = [key for key in ("title", "scenario", "solution") if not lesson.get(key)]
            if missing:
                raise fail(
                    "invalid_input",
                    f"manual lesson is missing required field(s): {', '.join(missing)}",
                    details={"missing": missing},
                )
        else:
            if not lesson["winning_method"] and not lesson["failed_methods"]:
                raise fail("invalid_input", "auto lesson requires a winning method or failed methods")
        fingerprint = _lesson_fingerprint(kind, lesson)
        lesson["fingerprint"] = fingerprint
        lesson["lesson_id"] = "ls_" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

        with self._lock():
            data = self._load()
            lessons: list[dict[str, Any]] = data.get("lessons") or []
            existing = None
            if kind == "auto":
                # Content-level dedupe first: never create a second lesson for
                # the same route just because error codes/messages differ.
                route = _auto_route_key(lesson)
                existing = next(
                    (
                        item
                        for item in lessons
                        if item.get("kind") == "auto"
                        and _is_trusted(item) == trusted
                        and _auto_route_key(item) == route
                    ),
                    None,
                )
            if existing is None:
                existing = next(
                    (item for item in lessons if item.get("lesson_id") == lesson["lesson_id"]),
                    None,
                )
            if existing is not None and _is_trusted(existing) != trusted:
                # Never merge an untrusted record into a verified lesson (or
                # vice versa): untrusted imports must stay isolated.
                existing = None
            if existing is None:
                lessons.append(lesson)
                status = "added"
                saved = lesson
            else:
                status = "merged"
                existing["occurrences"] = int(existing.get("occurrences", 1)) + 1
                existing["success_count"] = int(existing.get("success_count", 0)) + (1 if success else 0)
                existing["updated_at"] = now
                existing["last_seen"] = now
                existing["tags"] = _merge_unique(existing.get("tags"), lesson["tags"], MAX_TAGS)
                existing["evidence_links"] = _merge_unique(
                    existing.get("evidence_links"), lesson["evidence_links"], MAX_EVIDENCE_LINKS
                )
                existing["limitations"] = _merge_unique(existing.get("limitations"), lesson["limitations"], 20)
                existing["examples"] = _merge_examples(existing.get("examples"), lesson["examples"])
                category = _root_category(lesson)
                if category == "not_packed":
                    existing["title"] = "APK is not packed: static route"
                    existing["scenario"] = "APK has no shell indicators or is already unpacked"
                    existing["root_cause"] = NOT_PACKED_ROOT
                    existing["solution"] = (
                        "APK is not packed: skip runtime dumping and decompile the APK or "
                        "extract classes*.dex directly. This is the fast route for "
                        "unpacked/system APKs."
                    )
                    existing["winning_method"] = "static_route"
                    existing["shell"] = None
                    existing["framework"] = None
                    existing["device_abi"] = None
                    existing["apk_abi_class"] = "unknown"
                elif category == "packed_static_only":
                    existing["title"] = "Packed APK: static route only returned shell classes"
                    existing["scenario"] = "Static classes*.dex extraction on a packed APK"
                    existing["root_cause"] = PACKED_STATIC_ROOT
                    existing["solution"] = (
                        "Do not trust static classes*.dex on a packed APK: it contains only "
                        "the shell loader. Use a runtime dump (or a compatible ARM/native-"
                        "bridge device) and verify class count and completeness."
                    )
                    existing["winning_method"] = "static_shell_only"
                    existing["shell"] = None
                    existing["framework"] = None
                    existing["device_abi"] = None
                    existing["apk_abi_class"] = "unknown"
                if lesson["confidence"] == "analyst":
                    for key in ("title", "scenario", "root_cause", "solution", "winning_method", "symptoms"):
                        if lesson.get(key):
                            existing[key] = lesson[key]
                    if lesson.get("failed_methods"):
                        existing["failed_methods"] = lesson["failed_methods"]
                    existing["confidence"] = "analyst"
                saved = existing
            data["lessons"] = lessons[-MAX_LESSONS:]
            self._save(data)
        return json.loads(json.dumps(saved)), status

    def consolidate(self) -> dict[str, int]:
        """Merge universal-root-cause lessons that predate the category key.

        Existing libraries may already contain the same "APK is not packed" or
        "packed but only the shell DEX was extracted" conclusion once per
        shell/ABI/framework. This normalizes them into one generic lesson and
        keeps every example/evidence link.
        """
        merged = 0
        with self._lock():
            data = self._load()
            lessons: list[dict[str, Any]] = data.get("lessons") or []
            grouped: dict[str, dict[str, Any]] = {}
            output: list[dict[str, Any]] = []
            for lesson in lessons:
                if not isinstance(lesson, dict) or lesson.get("kind") != "auto":
                    output.append(lesson)
                    continue
                category = _root_category(lesson)
                if not category:
                    output.append(lesson)
                    continue
                # Keep untrusted imports in their own bucket so consolidation
                # cannot launder them into a verified lesson.
                group_key = category if _is_trusted(lesson) else category + ":untrusted"
                base = grouped.get(group_key)
                if base is None:
                    base = json.loads(json.dumps(lesson))
                    grouped[group_key] = base
                    output.append(base)
                else:
                    merged += 1
                    base["occurrences"] = int(base.get("occurrences", 1)) + int(
                        lesson.get("occurrences", 1)
                    )
                    base["success_count"] = int(base.get("success_count", 0)) + int(
                        lesson.get("success_count", 0)
                    )
                    base["tags"] = _merge_unique(base.get("tags"), lesson.get("tags"), MAX_TAGS)
                    base["symptoms"] = _merge_unique(base.get("symptoms"), lesson.get("symptoms"), 20)
                    base["evidence_links"] = _merge_unique(
                        base.get("evidence_links"), lesson.get("evidence_links"), MAX_EVIDENCE_LINKS
                    )
                    base["limitations"] = _merge_unique(
                        base.get("limitations"), lesson.get("limitations"), 20
                    )
                    base["examples"] = _merge_examples(base.get("examples"), lesson.get("examples"))
                    base["updated_at"] = base.get("updated_at") or lesson.get("updated_at")
                    base["last_seen"] = max(
                        str(base.get("last_seen") or ""), str(lesson.get("last_seen") or "")
                    ) or base.get("last_seen")
                _canonicalize_root_category(base, category)
            if merged:
                data["lessons"] = output[-MAX_LESSONS:]
                data["updated_at"] = utc_now()
                self._save(data)
            return {"merged": merged, "total": len(output)}

    def get(self, lesson_id: str) -> dict[str, Any] | None:
        if not lesson_id:
            return None
        for lesson in self._load().get("lessons") or []:
            if lesson.get("lesson_id") == lesson_id:
                return json.loads(json.dumps(lesson))
        return None

    # ------------------------------------------------------------------ management
    def update(self, lesson_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
        """Edit an existing lesson without changing its identity.

        ``lesson_id`` and ``fingerprint`` stay stable so imports, evidence and
        future merges keep pointing at the same record. Only the whitelisted
        content fields are writable; confidence is forced to ``analyst`` and
        ``edited_at``/``updated_at`` record the edit. Returns ``None`` when the
        id is well formed but unknown.
        """
        lesson_id = _clean_lesson_id(lesson_id)
        if not isinstance(changes, dict):
            raise fail("invalid_input", "lesson changes must be an object")
        if not all(isinstance(key, str) for key in changes):
            raise fail("invalid_input", "lesson field names must be strings")
        unknown = sorted(set(changes) - set(EDITABLE_LESSON_FIELDS))
        if unknown:
            raise fail(
                "invalid_input",
                "unsupported lesson field(s): " + ", ".join(unknown),
                details={"fields": unknown},
            )
        cleaned = _normalise_lesson_changes(changes)
        if not cleaned:
            raise fail("invalid_input", "no editable lesson fields were provided")
        now = utc_now()
        with self._lock():
            data = self._load()
            lessons: list[dict[str, Any]] = data.get("lessons") or []
            target = next(
                (
                    item
                    for item in lessons
                    if isinstance(item, dict) and item.get("lesson_id") == lesson_id
                ),
                None,
            )
            if target is None:
                return None
            target.update(cleaned)
            target["confidence"] = "analyst"
            target["edited_at"] = now
            target["updated_at"] = now
            self._save(data)
            return json.loads(json.dumps(target))

    def delete(self, lesson_ids: list[str] | tuple[str, ...]) -> dict[str, Any]:
        """Delete a bounded batch of lessons atomically.

        Unknown but well-formed ids are skipped and reported in ``missing`` so
        a batch delete is idempotent. Malformed ids, non-string entries, empty
        batches and batches above ``MAX_DELETE_BATCH`` are rejected before the
        lock is taken.
        """
        if isinstance(lesson_ids, (str, bytes)) or not isinstance(lesson_ids, (list, tuple)):
            raise fail("invalid_input", "lesson_ids must be an array")
        if not lesson_ids:
            raise fail("invalid_input", "lesson_ids must not be empty")
        if len(lesson_ids) > MAX_DELETE_BATCH:
            raise fail(
                "invalid_input",
                f"too many lesson ids (max {MAX_DELETE_BATCH})",
                details={"max": MAX_DELETE_BATCH, "received": len(lesson_ids)},
            )
        wanted: list[str] = []
        for raw in lesson_ids:
            if not isinstance(raw, str):
                raise fail("invalid_input", "every lesson id must be a string")
            cleaned = _clean_lesson_id(raw)
            if cleaned not in wanted:
                wanted.append(cleaned)
        wanted_set = set(wanted)
        with self._lock():
            data = self._load()
            lessons: list[dict[str, Any]] = data.get("lessons") or []
            present = {
                str(item.get("lesson_id"))
                for item in lessons
                if isinstance(item, dict) and item.get("lesson_id")
            }
            deleted_ids = [lesson_id for lesson_id in wanted if lesson_id in present]
            missing = [lesson_id for lesson_id in wanted if lesson_id not in present]
            if deleted_ids:
                remaining = [
                    item
                    for item in lessons
                    if not (isinstance(item, dict) and item.get("lesson_id") in wanted_set)
                ]
                data["lessons"] = remaining[-MAX_LESSONS:]
                self._save(data)
            else:
                remaining = lessons
            return {
                "deleted": len(deleted_ids),
                "deleted_ids": deleted_ids,
                "missing": missing,
                "total": len(remaining),
            }

    # ------------------------------------------------------------------ sharing
    def export_document(self) -> dict[str, Any]:
        data = self._load()
        lessons = data.get("lessons") or []
        return {
            "kind": "apu-lessons",
            "schema_version": LESSON_SCHEMA_VERSION,
            "exported_at": utc_now(),
            "count": len(lessons),
            "stats": self.stats(lessons=lessons),
            "lessons": json.loads(json.dumps(lessons)),
        }

    def import_document(
        self,
        document: Any,
        *,
        source: str = "import",
        trusted: bool = True,
    ) -> dict[str, Any]:
        """Import shared lessons without overwriting existing fingerprints.

        Lessons are identified by their computed fingerprint, not by any
        lesson_id supplied by the file.  Existing lessons are never modified,
        so importing the same file repeatedly is safe.
        """
        if isinstance(document, list):
            incoming = document
        elif isinstance(document, dict):
            incoming = document.get("lessons")
        else:
            raise fail("invalid_input", "lesson import must be an object or an array")
        if not isinstance(incoming, list):
            raise fail("invalid_input", "lesson import requires a lessons array")
        if len(incoming) > MAX_LESSONS:
            raise fail("invalid_input", f"too many lessons (max {MAX_LESSONS})")
        now = utc_now()
        errors: list[str] = []
        imported = 0
        skipped = 0
        invalid = 0
        with self._lock():
            data = self._load()
            lessons: list[dict[str, Any]] = data.get("lessons") or []
            known = {str(item.get("lesson_id")) for item in lessons if item.get("lesson_id")}
            added: list[dict[str, Any]] = []
            for index, raw in enumerate(incoming):
                if len(lessons) + len(added) >= MAX_LESSONS:
                    skipped += 1
                    continue
                if not isinstance(raw, dict):
                    invalid += 1
                    if len(errors) < 10:
                        errors.append(f"item {index}: not an object")
                    continue
                try:
                    lesson = self._normalise_imported(
                        raw, now, trusted=bool(trusted), source=source
                    )
                except (ValueError, TypeError) as exc:
                    invalid += 1
                    if len(errors) < 10:
                        errors.append(f"item {index}: {exc}")
                    continue
                if lesson["lesson_id"] in known:
                    skipped += 1
                    continue
                known.add(lesson["lesson_id"])
                added.append(lesson)
                imported += 1
            if added:
                lessons.extend(added)
                data["lessons"] = lessons[-MAX_LESSONS:]
                self._save(data)
        return {
            "status": "imported" if imported else "no_change",
            "source": source[:120],
            "trusted": bool(trusted),
            "imported": imported,
            "skipped": skipped,
            "invalid": invalid,
            "errors": errors,
            "total": len(data.get("lessons") or []),
            "stats": self.stats(),
        }

    def _normalise_imported(
        self,
        raw: dict[str, Any],
        now: str,
        *,
        trusted: bool = True,
        source: str = "import",
    ) -> dict[str, Any]:
        kind = str(raw.get("kind") or "").strip()
        if kind not in ("auto", "manual"):
            kind = "manual" if any(
                str(raw.get(key) or "").strip() for key in ("title", "scenario", "solution")
            ) else "auto"
        title = _clean(raw.get("title"), 240)
        scenario = _clean(raw.get("scenario"))
        solution = _clean(raw.get("solution"))
        winning_method = _clean(raw.get("winning_method"), 80) or None
        failed_methods = _normalize_failed_methods(raw.get("failed_methods"))
        if kind == "manual":
            missing = [key for key, value in (("title", title), ("scenario", scenario), ("solution", solution)) if not value]
            if missing:
                raise ValueError("missing " + ", ".join(missing))
        elif not winning_method and not failed_methods:
            raise ValueError("auto lesson needs winning_method or failed_methods")
        confidence = str(raw.get("confidence") or "")
        if confidence not in ("observed", "analyst"):
            confidence = "analyst" if kind == "manual" else "observed"
        try:
            occurrences = max(1, min(int(raw.get("occurrences") or 1), 1_000_000))
        except (TypeError, ValueError):
            occurrences = 1
        try:
            success_count = max(0, min(int(raw.get("success_count") or 0), occurrences))
        except (TypeError, ValueError):
            success_count = 0
        if winning_method in ("none", "failed", "no_method"):
            success_count = 0
        lesson: dict[str, Any] = {
            "schema_version": LESSON_SCHEMA_VERSION,
            "lesson_id": None,
            "fingerprint": None,
            "kind": kind,
            "title": title,
            "scenario": scenario,
            "shell": _clean(raw.get("shell"), 80) or None,
            "device_abi": _clean(raw.get("device_abi"), 80) or None,
            "apk_abi_class": raw.get("apk_abi_class") or apk_abi_class(raw.get("apk_abis")),
            "framework": _clean(raw.get("framework"), 80) or None,
            "package_scope": _clean(raw.get("package_scope"), 200) or "global",
            "symptoms": _clean_list(raw.get("symptoms"), limit=20),
            "root_cause": _clean(raw.get("root_cause")),
            "solution": solution,
            "winning_method": winning_method,
            "failed_methods": failed_methods,
            "tags": _clean_tags(raw.get("tags")),
            "evidence_links": _clean_list(raw.get("evidence_links"), limit=MAX_EVIDENCE_LINKS, item_limit=240),
            "examples": _normalize_examples(raw.get("examples")),
            "confidence": confidence,
            "trusted": bool(trusted),
            "source": _clean(source, 120) or "import",
            "occurrences": occurrences,
            "success_count": success_count,
            "created_at": _clean(raw.get("created_at"), 64) or now,
            "updated_at": _clean(raw.get("updated_at"), 64) or now,
            "last_seen": _clean(raw.get("last_seen"), 64) or now,
            "limitations": _clean_list(raw.get("limitations"), limit=20),
        }
        fingerprint = _lesson_fingerprint(kind, lesson)
        lesson["fingerprint"] = fingerprint
        lesson["lesson_id"] = "ls_" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        return lesson

    # ------------------------------------------------------------------ recall
    def recall(
        self,
        *,
        query: str | None = None,
        shell: str | None = None,
        device_abi: str | None = None,
        apk_abis: list[str] | None = None,
        framework: str | None = None,
        package_name: str | None = None,
        tags: list[str] | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        data = self._load()
        lessons: list[dict[str, Any]] = data.get("lessons") or []
        abi_class = apk_abi_class(apk_abis) if apk_abis else None
        query_tokens = [token.lower() for token in re.split(r"\s+", (query or "").strip()) if token]
        wanted_tags = {tag.lower() for tag in (tags or [])}
        has_filter = any((query_tokens, shell, device_abi, abi_class, framework, package_name, wanted_tags))
        matched: list[dict[str, Any]] = []
        for lesson in lessons:
            # Untrusted (web-imported) lessons are stored for review but never
            # participate in recall ranking or learned route selection.
            if not _is_trusted(lesson):
                continue
            candidate_shell = lesson.get("shell")
            candidate_abi = lesson.get("device_abi")
            candidate_apk_abi = lesson.get("apk_abi_class")
            candidate_framework = lesson.get("framework")
            candidate_scope = lesson.get("package_scope") or "global"
            if shell and candidate_shell and candidate_shell != shell:
                continue
            if device_abi and candidate_abi and candidate_abi != device_abi:
                continue
            if abi_class and candidate_apk_abi and candidate_apk_abi not in (abi_class, "unknown"):
                continue
            if framework and candidate_framework and candidate_framework != framework:
                continue
            if package_name and candidate_scope not in ("global", package_name):
                continue
            score = 0
            reasons: list[str] = []
            if shell and candidate_shell == shell:
                score += 10
                reasons.append(f"shell={shell}")
            if device_abi and candidate_abi == device_abi:
                score += 6
                reasons.append(f"device_abi={device_abi}")
            if abi_class and candidate_apk_abi == abi_class:
                score += 5
                reasons.append(f"apk_abi={abi_class}")
            if framework and candidate_framework == framework:
                score += 4
                reasons.append(f"framework={framework}")
            if package_name and candidate_scope == package_name:
                score += 8
                reasons.append("package-specific")
            elif candidate_scope == "global":
                score += 1
            haystack = " ".join(
                str(lesson.get(key) or "")
                for key in ("title", "scenario", "root_cause", "solution", "tags", "symptoms")
            ).lower()
            query_hit = False
            for token in query_tokens:
                if token in haystack:
                    score += 2
                    query_hit = True
                    reasons.append(f"query={token}")
            if query_tokens and not query_hit:
                continue
            overlap = wanted_tags & {str(tag).lower() for tag in lesson.get("tags") or []}
            if overlap:
                score += 2 * len(overlap)
                reasons.append("tags=" + ",".join(sorted(overlap)))
            if score == 0 and has_filter:
                continue
            occurrences = int(lesson.get("occurrences", 1))
            success_count = int(lesson.get("success_count", 0))
            score += min(occurrences, 10) * 0.5
            if occurrences:
                score += 2.0 * (success_count / occurrences)
            if _recent(lesson.get("last_seen")):
                score += 2
                reasons.append("recent")
            entry = dict(lesson)
            entry["score"] = round(score, 2)
            entry["relevance_reasons"] = reasons
            matched.append(entry)
        matched.sort(
            key=lambda item: (item.get("score", 0), item.get("occurrences", 1), item.get("last_seen", "")),
            reverse=True,
        )
        page = matched[: max(1, min(int(limit or 10), 100))]
        return {
            "memory_dir": str(self.root),
            "lessons": page,
            "total": len(matched),
            "stats": self.stats(lessons=lessons),
            "filters": {
                "query": query,
                "shell": shell,
                "device_abi": device_abi,
                "apk_abi_class": abi_class,
                "framework": framework,
                "package_name": package_name,
                "tags": sorted(wanted_tags),
            },
        }

    def list(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        data = self._load()
        lessons = sorted(
            data.get("lessons") or [],
            key=lambda item: (item.get("last_seen") or "", item.get("occurrences", 1)),
            reverse=True,
        )
        page = lessons[offset : offset + max(1, min(int(limit or 50), 500))]
        return {
            "memory_dir": str(self.root),
            "lessons": page,
            "total": len(lessons),
            "offset": offset,
            "limit": limit,
            "stats": self.stats(lessons=lessons),
        }

    def stats(self, *, lessons: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if lessons is None:
            lessons = self._load().get("lessons") or []
        by_shell: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for lesson in lessons:
            shell = lesson.get("shell") or "unknown"
            by_shell[shell] = by_shell.get(shell, 0) + 1
            method = lesson.get("winning_method")
            if method:
                by_method[method] = by_method.get(method, 0) + 1
        return {
            "total": len(lessons),
            "analyst": sum(1 for item in lessons if item.get("confidence") == "analyst"),
            "observed": sum(1 for item in lessons if item.get("confidence") == "observed"),
            "untrusted": sum(1 for item in lessons if item.get("trusted") is False),
            "by_shell": by_shell,
            "by_winning_method": by_method,
            "path": str(self.path),
        }


def _merge_unique(existing: Any, incoming: list[Any], limit: int) -> list[Any]:
    values: list[Any] = list(existing or [])
    for item in incoming:
        if item not in values:
            values.append(item)
        if len(values) >= limit:
            break
    return values[:limit]


def _merge_examples(existing: Any, incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values = list(existing or [])
    for item in incoming:
        if item not in values:
            values.append(item)
    return values[-MAX_EXAMPLES:]


def _recent(timestamp: str | None, days: int = 30) -> bool:
    if not timestamp:
        return False
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - parsed).days <= days
