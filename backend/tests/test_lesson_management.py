from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from apk_unpack.application.memory import MemoryStore
from apk_unpack.domain.errors import AnalysisError
from backend.config import BackendConfig
from backend.db import Database
from backend.security import token_hash
from backend.server import make_handler


def manual_payload(title: str = "manual lesson", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": title,
        "scenario": "sandbox refused the injection",
        "solution": "use freeze mode",
        "root_cause": "anti-debug killed the injected process",
        "shell": "ijiami",
        "device_abi": "x86_64",
        "framework": "flutter",
        "tags": ["Auto", "Dump"],
        "confidence": "analyst",
        "package_scope": "global",
    }
    payload.update(overrides)
    return payload


class MemoryStoreManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = MemoryStore(Path(self.temp.name) / "memory")

    def _record(self, title: str = "manual lesson") -> dict[str, Any]:
        lesson, status = self.store.record(manual_payload(title), kind="manual")
        self.assertEqual(status, "added")
        return lesson

    def test_update_keeps_identity_and_forces_analyst(self) -> None:
        lesson = self._record()
        updated = self.store.update(
            lesson["lesson_id"],
            {
                "title": "edited title",
                "scenario": "edited scenario",
                "root_cause": "edited root",
                "solution": "edited solution",
                "shell": "  ",
                "device_abi": "arm64-v8a",
                "framework": "",
                "tags": ["Flutter", "frida dump", "flutter"],
            },
        )
        self.assertIsNotNone(updated)
        assert updated is not None
        self.assertEqual(updated["lesson_id"], lesson["lesson_id"])
        self.assertEqual(updated["fingerprint"], lesson["fingerprint"])
        self.assertEqual(updated["kind"], "manual")
        self.assertEqual(updated["title"], "edited title")
        self.assertEqual(updated["scenario"], "edited scenario")
        self.assertEqual(updated["root_cause"], "edited root")
        self.assertEqual(updated["solution"], "edited solution")
        self.assertIsNone(updated["shell"])
        self.assertEqual(updated["device_abi"], "arm64-v8a")
        self.assertIsNone(updated["framework"])
        self.assertEqual(updated["tags"], ["flutter", "frida-dump"])
        self.assertEqual(updated["confidence"], "analyst")
        self.assertEqual(updated["created_at"], lesson["created_at"])
        self.assertEqual(updated["occurrences"], lesson["occurrences"])
        self.assertTrue(updated["edited_at"])
        self.assertEqual(updated["edited_at"], updated["updated_at"])

        reloaded = MemoryStore(Path(self.temp.name) / "memory")
        stored = reloaded.get(lesson["lesson_id"])
        self.assertEqual(stored["title"], "edited title")

    def test_update_redacts_secrets_and_rejects_unknown_fields(self) -> None:
        lesson = self._record()
        updated = self.store.update(
            lesson["lesson_id"],
            {"scenario": "request failed with token=abcd1234"},
        )
        self.assertIn("<redacted>", updated["scenario"])

        with self.assertRaises(AnalysisError) as caught:
            self.store.update(lesson["lesson_id"], {"lesson_id": "ls_other"})
        self.assertEqual(caught.exception.code, "invalid_input")
        with self.assertRaises(AnalysisError):
            self.store.update(lesson["lesson_id"], {"fingerprint": "forged"})
        with self.assertRaises(AnalysisError):
            self.store.update(lesson["lesson_id"], {"occurrences": 99})
        with self.assertRaises(AnalysisError):
            self.store.update(lesson["lesson_id"], {})
        with self.assertRaises(AnalysisError):
            self.store.update(lesson["lesson_id"], {"title": "   "})
        with self.assertRaises(AnalysisError):
            self.store.update(lesson["lesson_id"], {"tags": "a,b"})
        with self.assertRaises(AnalysisError):
            self.store.update(lesson["lesson_id"], {"tags": [1, 2]})

        self.assertIsNone(self.store.update("ls_missing", {"title": "nope"}))
        with self.assertRaises(AnalysisError):
            self.store.update("../../etc/passwd", {"title": "nope"})

    def test_batch_delete_skips_missing_and_persists(self) -> None:
        first = self._record("first")
        second = self._record("second")
        third = self._record("third")
        result = self.store.delete([first["lesson_id"], "ls_missing", first["lesson_id"]])
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["deleted_ids"], [first["lesson_id"]])
        self.assertEqual(result["missing"], ["ls_missing"])
        self.assertEqual(result["total"], 2)
        self.assertIsNone(self.store.get(first["lesson_id"]))
        self.assertIsNotNone(self.store.get(second["lesson_id"]))
        self.assertIsNotNone(self.store.get(third["lesson_id"]))

        reloaded = MemoryStore(Path(self.temp.name) / "memory")
        ids = {lesson["lesson_id"] for lesson in reloaded.list(limit=10)["lessons"]}
        self.assertNotIn(first["lesson_id"], ids)
        self.assertEqual(len(ids), 2)

        again = self.store.delete(["ls_missing"])
        self.assertEqual(again["deleted"], 0)
        self.assertEqual(again["missing"], ["ls_missing"])

    def test_delete_limits_and_validation(self) -> None:
        ids = [f"ls_{index:064d}" for index in range(501)]
        with self.assertRaises(AnalysisError) as caught:
            self.store.delete(ids)
        self.assertEqual(caught.exception.code, "invalid_input")
        with self.assertRaises(AnalysisError):
            self.store.delete([])
        with self.assertRaises(AnalysisError):
            self.store.delete("ls_one")  # type: ignore[arg-type]
        with self.assertRaises(AnalysisError):
            self.store.delete([1])  # type: ignore[list-item]
        with self.assertRaises(AnalysisError):
            self.store.delete(["../../etc/passwd"])
        self.assertEqual(self.store.list(limit=10)["total"], 0)


class _FakeService:
    def __init__(self, lessons: MemoryStore) -> None:
        self.lessons = lessons

    def recall_unpack_lessons(self, **kwargs: Any) -> dict[str, Any]:
        return self.lessons.recall(**kwargs)

    def export_unpack_lessons(self) -> dict[str, Any]:
        return self.lessons.export_document()

    def import_unpack_lessons(self, document: Any) -> dict[str, Any]:
        return self.lessons.import_document(document, source="web-import")

    def remember_unpack_lesson(
        self,
        *,
        title: str,
        scenario: str,
        solution: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        payload = {
            "title": title,
            "scenario": scenario,
            "solution": solution,
            "root_cause": kwargs.get("root_cause"),
            "shell": kwargs.get("shell"),
            "device_abi": kwargs.get("device_abi"),
            "apk_abis": kwargs.get("apk_abis") or [],
            "framework": kwargs.get("framework"),
            "package_scope": kwargs.get("package_name") or "global",
            "winning_method": kwargs.get("winning_method"),
            "failed_methods": kwargs.get("failed_methods") or [],
            "symptoms": kwargs.get("symptoms") or [],
            "tags": kwargs.get("tags") or [],
            "evidence_links": kwargs.get("evidence_links") or [],
            "confidence": kwargs.get("confidence") or "analyst",
        }
        lesson, status = self.lessons.record(payload, kind="manual")
        return {
            "memory_dir": str(self.lessons.root),
            "status": status,
            "lesson": lesson,
            "stats": self.lessons.stats(),
        }


class _FakeJobs:
    def __init__(self, lessons: MemoryStore) -> None:
        self.service = _FakeService(lessons)


class LessonApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=root / "data")
        self.config.ensure_dirs()
        self.db = Database(self.config.data_dir / "backend.sqlite3")
        self.db.initialize()
        self.admin = self.db.create_user("admin", "hash", "salt", "admin")
        self.user = self.db.create_user("viewer", "hash", "salt", "user")
        self.admin_token = "admin-token"
        self.user_token = "user-token"
        self.db.create_session(token_hash(self.admin_token), int(self.admin["id"]), 1)
        self.db.create_session(token_hash(self.user_token), int(self.user["id"]), 1)

        self.lessons = MemoryStore(root / "memory")
        self.app = SimpleNamespace(
            config=self.config,
            database=self.db,
            jobs=_FakeJobs(self.lessons),
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = int(self.httpd.server_address[1])
        self.addCleanup(self._stop_server)

    def _stop_server(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: Any = None,
    ) -> tuple[int, dict[str, Any] | None]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Connection": "close", "X-Requested-With": "XMLHttpRequest"}
        payload = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else None
        finally:
            connection.close()

    def _record(self, title: str = "api lesson") -> dict[str, Any]:
        lesson, _ = self.lessons.record(manual_payload(title), kind="manual")
        return lesson

    def _audit_actions(self) -> list[str]:
        items, _ = self.db.list_audit(200, 0)
        return [str(item.get("action")) for item in items]

    def test_admin_patch_updates_and_audits(self) -> None:
        lesson = self._record()
        status, data = self._request(
            "PATCH",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            token=self.admin_token,
            body={
                "title": "api edited",
                "scenario": "edited through the API",
                "root_cause": "root edited",
                "solution": "solution edited",
                "shell": "bangcle",
                "device_abi": "arm64-v8a",
                "framework": "react-native",
                "tags": ["Web", "edited"],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["lesson"]["lesson_id"], lesson["lesson_id"])
        self.assertEqual(data["lesson"]["fingerprint"], lesson["fingerprint"])
        self.assertEqual(data["lesson"]["title"], "api edited")
        self.assertEqual(data["lesson"]["confidence"], "analyst")
        self.assertEqual(data["lesson"]["tags"], ["web", "edited"])

        status, listing = self._request(
            "GET",
            "/api/v1/lessons?limit=20&query=api%20edited",
            token=self.user_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(listing["lessons"][0]["lesson_id"], lesson["lesson_id"])
        self.assertIn("lesson.update", self._audit_actions())

    def test_patch_permissions_validation_and_missing(self) -> None:
        lesson = self._record()
        status, _ = self._request(
            "PATCH",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            token=self.user_token,
            body={"title": "forbidden"},
        )
        self.assertEqual(status, 403)

        status, data = self._request(
            "PATCH",
            "/api/v1/lessons/ls_" + "a" * 64,
            token=self.admin_token,
            body={"title": "missing"},
        )
        self.assertEqual(status, 404)
        self.assertEqual(data["error"]["code"], "not_found")

        status, data = self._request(
            "PATCH",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            token=self.admin_token,
            body={"lesson_id": "ls_forged"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "invalid_input")

        status, data = self._request(
            "PATCH",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            token=self.admin_token,
            body={"title": "  "},
        )
        self.assertEqual(status, 400)

        status, _ = self._request(
            "PATCH",
            "/api/v1/lessons/../../etc/passwd",
            token=self.admin_token,
            body={"title": "traversal"},
        )
        self.assertEqual(status, 404)

    def test_delete_single_permissions_missing_and_audit(self) -> None:
        lesson = self._record()
        status, _ = self._request(
            "DELETE",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            token=self.user_token,
        )
        self.assertEqual(status, 403)
        self.assertIsNotNone(self.lessons.get(lesson["lesson_id"]))

        status, data = self._request(
            "DELETE",
            "/api/v1/lessons/ls_" + "b" * 64,
            token=self.admin_token,
        )
        self.assertEqual(status, 404)
        self.assertEqual(data["error"]["code"], "not_found")

        status, data = self._request(
            "DELETE",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            token=self.admin_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["deleted"], 1)
        self.assertIsNone(self.lessons.get(lesson["lesson_id"]))
        self.assertIn("lesson.delete", self._audit_actions())

    def test_batch_delete_permissions_limits_and_missing(self) -> None:
        first = self._record("batch first")
        second = self._record("batch second")
        status, data = self._request(
            "POST",
            "/api/v1/lessons/batch-delete",
            token=self.user_token,
            body={"lesson_ids": [first["lesson_id"]]},
        )
        self.assertEqual(status, 403)
        self.assertIsNotNone(self.lessons.get(first["lesson_id"]))

        status, data = self._request(
            "POST",
            "/api/v1/lessons/batch-delete",
            token=self.admin_token,
            body={"lesson_ids": [first["lesson_id"], "ls_missing"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["deleted"], 1)
        self.assertEqual(data["missing"], ["ls_missing"])
        self.assertEqual(data["total"], 1)
        self.assertIsNone(self.lessons.get(first["lesson_id"]))
        self.assertIsNotNone(self.lessons.get(second["lesson_id"]))
        self.assertIn("lesson.batch_delete", self._audit_actions())

        status, data = self._request(
            "POST",
            "/api/v1/lessons/batch-delete",
            token=self.admin_token,
            body={"lesson_ids": [f"ls_{index:064d}" for index in range(501)]},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "invalid_input")

        status, data = self._request(
            "POST",
            "/api/v1/lessons/batch-delete",
            token=self.admin_token,
            body={"lesson_ids": "../../etc/passwd"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "invalid_input")

        status, data = self._request(
            "POST",
            "/api/v1/lessons/batch-delete",
            token=self.admin_token,
            body={},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "invalid_input")

    def test_rejected_mutations_keep_keepalive_connection_in_sync(self) -> None:
        """Rejected mutation bodies must be consumed before the 403 response.

        Otherwise the leftover JSON is parsed as the next request line on a
        keep-alive connection and the following request fails with HTTP 501.
        """
        lesson = self._record()
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Authorization": f"Bearer {self.user_token}",
            "Content-Type": "application/json",
        }
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(connection.close)

        def request(method: str, path: str, body: Any = None) -> tuple[int, dict[str, Any] | None]:
            payload = json.dumps(body).encode("utf-8") if body is not None else None
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else None

        status, _ = request(
            "PATCH",
            f"/api/v1/lessons/{lesson['lesson_id']}",
            {"title": "forbidden"},
        )
        self.assertEqual(status, 403)
        status, data = request("GET", "/api/v1/lessons?limit=20")
        self.assertEqual(status, 200)
        self.assertIn("lessons", data)

        status, _ = request(
            "POST",
            "/api/v1/lessons/batch-delete",
            {"lesson_ids": [lesson["lesson_id"]]},
        )
        self.assertEqual(status, 403)
        status, data = request("GET", "/api/v1/lessons?limit=20")
        self.assertEqual(status, 200)
        self.assertIn("lessons", data)
        self.assertIsNotNone(self.lessons.get(lesson["lesson_id"]))

    def test_non_admin_global_add_is_forbidden_and_import_is_untrusted(self) -> None:
        status, data = self._request("GET", "/api/v1/lessons?limit=20", token=self.user_token)
        self.assertEqual(status, 200)
        self.assertIn("lessons", data)

        # Global manual lessons require an administrator.
        status, data = self._request(
            "POST",
            "/api/v1/lessons",
            token=self.user_token,
            body={
                "title": "viewer global lesson",
                "scenario": "viewer scenario",
                "solution": "viewer solution",
                "confidence": "analyst",
            },
        )
        self.assertEqual(status, 403, data)
        assert data is not None
        self.assertEqual(data["error"]["code"], "forbidden")

        # Non-admin imports are stored, but explicitly untrusted.
        status, data = self._request(
            "POST",
            "/api/v1/lessons/import",
            token=self.user_token,
            body={"lessons": [manual_payload("viewer imported lesson")]},
        )
        self.assertEqual(status, 200, data)
        assert data is not None
        self.assertTrue(data["ok"])
        self.assertEqual(data["imported"], 1)
        self.assertFalse(data["trusted"])
        stored = self.lessons.list(limit=10)["lessons"]
        imported = next(item for item in stored if item["title"] == "viewer imported lesson")
        self.assertIs(imported["trusted"], False)
        self.assertEqual(imported["source"], "web-import")

        # Untrusted lessons never participate in recall ranking.
        status, data = self._request(
            "GET", "/api/v1/lessons?limit=20&query=viewer%20imported", token=self.user_token
        )
        self.assertEqual(status, 200)
        assert data is not None
        self.assertEqual(data["lessons"], [])

        # Package-scoped manual lessons from a regular user are accepted, but
        # remain untrusted and are excluded from recall.
        status, data = self._request(
            "POST",
            "/api/v1/lessons",
            token=self.user_token,
            body={
                "title": "viewer package lesson",
                "scenario": "viewer package scenario",
                "solution": "viewer package solution",
                "scope": "package",
                "package_name": "com.example.viewer",
                "confidence": "analyst",
            },
        )
        self.assertEqual(status, 201, data)
        assert data is not None
        self.assertEqual(data["lesson"]["title"], "viewer package lesson")
        self.assertIs(data["lesson"]["trusted"], False)
        self.assertEqual(data["lesson"]["source"], "web-import")

    def test_admin_import_and_global_add_are_trusted(self) -> None:
        status, data = self._request(
            "POST",
            "/api/v1/lessons/import",
            token=self.admin_token,
            body={"lessons": [manual_payload("admin imported lesson")]},
        )
        self.assertEqual(status, 200, data)
        assert data is not None
        self.assertEqual(data["imported"], 1)
        self.assertTrue(data["trusted"])
        stored = next(
            item
            for item in self.lessons.list(limit=10)["lessons"]
            if item["title"] == "admin imported lesson"
        )
        self.assertIs(stored["trusted"], True)
        self.assertEqual(stored["source"], "web-import")

        status, data = self._request(
            "GET",
            "/api/v1/lessons?limit=20&query=admin%20imported",
            token=self.user_token,
        )
        self.assertEqual(status, 200)
        assert data is not None
        self.assertEqual(len(data["lessons"]), 1)

        status, data = self._request(
            "POST",
            "/api/v1/lessons",
            token=self.admin_token,
            body={
                "title": "admin global lesson",
                "scenario": "admin scenario",
                "solution": "admin solution",
                "confidence": "analyst",
            },
        )
        self.assertEqual(status, 201, data)
        assert data is not None
        self.assertEqual(data["lesson"]["title"], "admin global lesson")
        self.assertIs(data["lesson"]["trusted"], True)
        self.assertEqual(data["lesson"]["source"], "manual")

    def test_import_then_manual_add_never_merges_trust_levels(self) -> None:
        payload = manual_payload("trust boundary lesson")
        status, data = self._request(
            "POST", "/api/v1/lessons/import", token=self.user_token, body={"lessons": [payload]}
        )
        self.assertEqual(status, 200, data)
        status, data = self._request("POST", "/api/v1/lessons", token=self.user_token, body=payload)
        self.assertEqual(status, 403, data)
        status, data = self._request("POST", "/api/v1/lessons", token=self.admin_token, body=payload)
        self.assertEqual(status, 201, data)
        assert data is not None
        self.assertIs(data["lesson"]["trusted"], True)
        # Both records exist independently: the import did not merge into the
        # trusted record and did not acquire its success history.
        all_lessons = self.lessons.list(limit=10)["lessons"]
        matching = [item for item in all_lessons if item["title"] == "trust boundary lesson"]
        self.assertEqual(len(matching), 2)
        self.assertEqual({bool(item["trusted"]) for item in matching}, {True, False})


if __name__ == "__main__":
    unittest.main()
