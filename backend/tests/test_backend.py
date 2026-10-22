from __future__ import annotations

import contextlib
import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from apk_unpack.application.memory import MemoryStore
from backend.config import BackendConfig
from backend.db import Database
from backend.engines import ClaudeEngine, DeepSeekEngine, EngineResult, JobContext, ToolBridge
from backend.events import EventBus
from backend.job_options import (
    JOB_OPTION_SPECS,
    normalize_job_options,
    option_schema_for_prompt,
)
from backend.jobs import JobManager
from backend.security import hash_password, token_hash, verify_password
from backend.server import _job_public, _mcp_request_key, _parse_multipart_file, make_handler
from tests.fixtures import build_valid_dex


class FakeService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call_tool(self, name: str, arguments: dict[str, Any], cancel=None) -> dict[str, Any]:
        self.calls.append((name, dict(arguments)))
        if name == "inspect_apk":
            return {
                "run_id": arguments.get("run_id") or "run_fake",
                "inspection": {"package": {"name": "com.example"}, "packing": {"primary": "ijiami"}, "abis": []},
            }
        return {"run_id": arguments.get("run_id") or "run_fake", "ok": True}


class LessonAwareFakeService(FakeService):
    """FakeService that records remember_unpack_lesson into a real store."""

    def __init__(self, lessons: MemoryStore) -> None:
        super().__init__()
        self.lessons = lessons

    def call_tool(self, name: str, arguments: dict[str, Any], cancel=None) -> dict[str, Any]:
        if name != "remember_unpack_lesson":
            return super().call_tool(name, arguments, cancel)
        self.calls.append((name, dict(arguments)))
        payload = dict(arguments)
        package_name = payload.pop("package_name", None)
        payload["package_scope"] = package_name or "global"
        lesson, status = self.lessons.record(payload, kind="manual")
        return {
            "memory_dir": str(self.lessons.root),
            "status": status,
            "lesson": lesson,
            "stats": self.lessons.stats(),
        }


class FakeEngine:
    name = "fake"

    def __init__(self, write_dex: bool = True) -> None:
        self.write_dex = write_dex

    def run(self, ctx: JobContext) -> EngineResult:
        if self.write_dex:
            # The finalizer requires a content-verified target DEX; a fake
            # "success" without artifacts must be reported as partial.
            fixed = Path(ctx.run_dir) / "dexdump" / "fixed"
            fixed.mkdir(parents=True, exist_ok=True)
            (fixed / "classes.dex").write_bytes(build_valid_dex("com.example"))
            (Path(ctx.run_dir) / "run.json").write_text(
                json.dumps({"package": "com.example", "status": "succeeded"}),
                encoding="utf-8",
            )
        ctx.emit("stage", "faked", {"stage": "faked"})
        return EngineResult("success", run_id=ctx.run_id, summary="fake success")


class DatabaseAuthTests(unittest.TestCase):
    def test_password_and_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "db.sqlite")
            db.initialize()
            salt, digest = hash_password("test-password")
            user = db.create_user("test-user", digest, salt, "admin")
            self.assertEqual(user["username"], "test-user")
            stored = db.get_user_by_name("test-user")
            self.assertTrue(verify_password("test-password", stored["salt"], stored["password_hash"]))
            self.assertFalse(verify_password("wrong", stored["salt"], stored["password_hash"]))
            db.create_session(token_hash("token"), int(user["id"]), 1)
            session = db.get_session(token_hash("token"))
            self.assertEqual(session["username"], "test-user")
            db.delete_session(token_hash("token"))
            self.assertIsNone(db.get_session(token_hash("token")))


class MultipartTests(unittest.TestCase):
    def test_parse_file_part(self) -> None:
        boundary = "xyz123"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="a.apk"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + b"PK\x03\x04payload" + f"\r\n--{boundary}--\r\n".encode()
        filename, payload = _parse_multipart_file(body, f"multipart/form-data; boundary={boundary}")
        self.assertEqual(filename, "a.apk")
        self.assertTrue(payload and payload.startswith(b"PK\x03\x04"))


class ToolBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.upload = self.root / "target.apk"
        self.upload.write_bytes(b"PK\x03\x04")
        self.service = FakeService()
        self.ctx = JobContext(
            job_id="job_test",
            user_id=1,
            engine="agent",
            upload_path=self.upload,
            apk_name="target.apk",
            serial="serial-1",
            options={"install": True, "jadx": True, "cleanup": True},
            runs_dir=self.root / "runs",
            memory_dir=self.root / "memory",
            work_dir=self.root / "work",
            cancel=None,  # type: ignore[arg-type]
            emit=lambda *args, **kwargs: None,
            service=self.service,
            run_id="run_test",
            config=self.config,
        )
        self.bridge = ToolBridge(self.ctx)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_schema_mapping(self) -> None:
        self.assertTrue(self.bridge.tools_openai())
        self.assertTrue(self.bridge.tools_anthropic())
        self.assertEqual(self.bridge.tools_openai()[0]["type"], "function")

    def test_injection_and_policy(self) -> None:
        result, is_error, _ = self.bridge.execute("inspect_apk", {"apk_path": str(self.upload)})
        self.assertFalse(is_error)
        self.assertTrue(self.service.calls[-1][1]["run_id"] == "run_test")
        self.bridge.execute("prepare_android_environment", {})
        prepared = self.service.calls[-1][1]
        self.assertEqual(prepared["run_id"], "run_test")
        self.assertEqual(prepared["serial"], "serial-1")
        self.assertEqual(prepared["apk_path"], str(self.upload))
        self.assertTrue(prepared["allow_install"])
        self.bridge.execute("cleanup_run", {})
        cleanup = self.service.calls[-1][1]
        self.assertFalse(cleanup["delete_run"])

    def test_foreign_run_is_rejected(self) -> None:
        result, is_error, _ = self.bridge.execute("prepare_android_environment", {"run_id": "run_other"})
        self.assertTrue(is_error)
        self.assertEqual(result.get("code"), "permission_denied")


class LLMEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.config.engines["deepseek"].api_key = "fake-key"
        self.config.engines["claude"].api_key = "fake-key"
        self.upload = self.root / "target.apk"
        self.upload.write_bytes(b"PK\x03\x04")
        self.service = FakeService()
        self.ctx = JobContext(
            job_id="job_llm",
            user_id=1,
            engine="deepseek",
            upload_path=self.upload,
            apk_name="target.apk",
            serial="serial-1",
            options={"install": False, "jadx": False, "cleanup": False},
            runs_dir=self.root / "runs",
            memory_dir=self.root / "memory",
            work_dir=self.root / "work",
            cancel=threading.Event(),
            emit=lambda *args, **kwargs: None,
            service=self.service,
            run_id="run_test",
            config=self.config,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _tool_names(self) -> list[str]:
        return [name for name, _ in self.service.calls]

    def test_deepseek_tool_loop(self) -> None:
        replies = [
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "function": {"name": "recommend_unpack_strategy", "arguments": "{}"},
                                }
                            ],
                        }
                    }
                ],
                "usage": {"total_tokens": 10},
            },
            {"choices": [{"message": {"content": "done"}}], "usage": {"total_tokens": 5}},
        ]
        with mock.patch("backend.engines._post_json", side_effect=replies):
            result = DeepSeekEngine(self.config).run(self.ctx)
        names = self._tool_names()
        self.assertIn("inspect_apk", names)
        self.assertIn("recommend_unpack_strategy", names)
        self.assertEqual(result.run_id, "run_test")

    def test_claude_tool_loop(self) -> None:
        replies = [
            {
                "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "recommend_unpack_strategy", "input": {}}
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            {"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"},
        ]
        self.ctx.engine = "claude"
        with mock.patch("backend.engines._post_json", side_effect=replies):
            result = ClaudeEngine(self.config).run(self.ctx)
        names = self._tool_names()
        self.assertIn("inspect_apk", names)
        self.assertIn("recommend_unpack_strategy", names)
        self.assertEqual(result.run_id, "run_test")


class JobQueueTests(unittest.TestCase):
    def test_fake_engine_job_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = BackendConfig.load(data_dir=root / "data")
            db = Database(config.db_path)
            db.initialize()
            salt, digest = hash_password("test-password")
            user = db.create_user("test-user", digest, salt, "admin")
            upload_path = root / "target.apk"
            upload_path.write_bytes(b"PK\x03\x04")
            db.create_upload("u1", int(user["id"]), "target.apk", str(upload_path), 4, "0" * 64)
            bus = EventBus(db)
            manager = JobManager(config, db, bus)
            manager.engines["fake"] = FakeEngine()
            job = manager.create_job(
                user_id=int(user["id"]),
                upload_id="u1",
                engine="fake",
                serial="serial-1",
                options={"install": False, "jadx": False, "cleanup": False},
            )
            manager._process(job["id"])
            updated = db.get_job(job["id"])
            self.assertEqual(updated["status"], "succeeded")
            self.assertEqual(updated["stage"], "done")
            self.assertTrue(updated["logs_zip"])
            events = db.list_events(job["id"])
            self.assertTrue(any(event["kind"] == "job_finished" for event in events))

    def test_fake_engine_without_dex_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = BackendConfig.load(data_dir=root / "data")
            db = Database(config.db_path)
            db.initialize()
            salt, digest = hash_password("test-password")
            user = db.create_user("test-user", digest, salt, "admin")
            upload_path = root / "target.apk"
            upload_path.write_bytes(b"PK\x03\x04")
            db.create_upload("u1", int(user["id"]), "target.apk", str(upload_path), 4, "0" * 64)
            manager = JobManager(config, db, EventBus(db))
            manager.engines["fake"] = FakeEngine(write_dex=False)
            job = manager.create_job(
                user_id=int(user["id"]),
                upload_id="u1",
                engine="fake",
                serial="serial-1",
                options={"install": False, "jadx": False, "cleanup": False},
            )
            manager._process(job["id"])
            updated = db.get_job(job["id"])
            self.assertEqual(updated["status"], "partial")
            error = updated.get("error") or {}
            self.assertEqual(error.get("code"), "no_target_dex")

    def test_job_public_exposes_cleanup_fields(self) -> None:
        public = _job_public(
            {
                "id": "job_test",
                "error": {
                    "code": "cleanup_incomplete",
                    "cleanup_status": "incomplete",
                    "cleanup_error": "forward restore failed",
                },
            }
        )
        self.assertEqual(public["cleanup_status"], "incomplete")
        self.assertEqual(public["cleanup_error"], "forward restore failed")
        self.assertTrue(public["cleanup_incomplete"])

    def test_create_job_marks_automatic_device_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = BackendConfig.load(data_dir=Path(tmp) / "data")
            db = Database(config.db_path)
            db.initialize()
            user = db.create_user("auto-user", "hash", "salt", "admin")
            db.create_upload(
                "u1", int(user["id"]), "target.apk", "/tmp/target.apk", 4, "0" * 64
            )
            manager = JobManager(config, db, EventBus(db))
            manager.engines["agent-native"] = SimpleNamespace(available=True)
            with mock.patch.object(manager, "resolve_device", return_value="serial-auto"):
                job = manager.create_job(
                    user_id=int(user["id"]),
                    upload_id="u1",
                    engine="agent-native",
                    serial=None,
                    options={},
                )
            row = db.get_job(job["id"])
            assert row is not None
            self.assertEqual(row["serial"], "serial-auto")
            self.assertTrue(row["options"]["_auto_device"])
            with mock.patch.object(manager, "canonical_serial", side_effect=lambda value: value):
                pinned = manager.create_job(
                    user_id=int(user["id"]),
                    upload_id="u1",
                    engine="agent-native",
                    serial="serial-pinned",
                    options={},
                )
            pinned_row = db.get_job(pinned["id"])
            assert pinned_row is not None
            self.assertFalse(pinned_row["options"]["_auto_device"])


class _JobApiJobs:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.created: dict[str, Any] | None = None
        self.error = ""
        self.retried: dict[str, Any] | None = None
        self.retry_error: Exception | None = None
        # WP-F adds JobQueue.cleanup_job; the API must return 501 until then.
        self.cleanup_job: Any = None
        self.engines = {
            "agent-native": SimpleNamespace(agent=None, available=True, reason="ok"),
        }

    def retry_job(self, job_id: str, user_id: int, is_admin: bool = False) -> dict[str, Any]:
        if self.retry_error is not None:
            raise self.retry_error
        self.retried = {"job_id": job_id, "user_id": user_id}
        return {
            "id": "job_retry_1",
            "status": "queued",
            "stage": "queued",
            "engine": "agent-native",
            "upload_id": "upload_api",
            "options": {},
            "serial": None,
            "user_id": user_id,
        }

    def canonical_engine(self, engine: str) -> str:
        return engine or "agent-native"

    def default_engine(self, visible_to: Any = None) -> str:
        return "agent-native"

    def create_job(self, **kwargs: Any) -> dict[str, Any]:
        if self.error:
            raise ValueError(self.error)
        self.created = kwargs
        return {
            "id": "job_api_1",
            "status": "queued",
            "stage": "queued",
            "engine": kwargs["engine"],
            "upload_id": kwargs["upload_id"],
            "options": kwargs["options"],
            "serial": kwargs["serial"],
            "user_id": kwargs["user_id"],
        }


class JobApiOptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=root / "data")
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)
        self.db.initialize()
        user = self.db.create_user("api-user", "hash", "salt", "admin")
        self.user_id = int(user["id"])
        self.token = "job-api-token"
        self.db.create_session(token_hash(self.token), self.user_id, 1)
        self.db.create_upload(
            "upload_api", self.user_id, "target.apk", str(root / "target.apk"), 4, "0" * 64
        )
        self.jobs = _JobApiJobs(self.db)
        self.app = SimpleNamespace(
            config=self.config,
            database=self.db,
            jobs=self.jobs,
            retry_cache={},
            retry_lock=threading.Lock(),
        )
        app = self.app
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
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
        body: Any = None,
        *,
        raw_body: bytes | None = None,
        content_type: str = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {
            "Connection": "close",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.token}",
        }
        headers.update(extra_headers or {})
        if raw_body is None and body is not None:
            raw_body = json.dumps(body).encode("utf-8")
        try:
            connection.request(method, path, body=raw_body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else None
        finally:
            connection.close()

    def _post(self, body: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
        return self._request("POST", "/api/v1/jobs", body)

    def _make_job(self, job_id: str, status: str, run_id: str | None = None) -> dict[str, Any]:
        job = self.db.create_job(
            job_id,
            self.user_id,
            "upload_api",
            "agent-native",
            None,
            {},
            run_id or f"run_{job_id}",
        )
        self.db.update_job(job_id, status=status)
        return self.db.get_job(job_id) or job

    def _multipart(self, filename: str, payload: bytes = b"PK\x03\x04") -> tuple[bytes, str]:
        boundary = "boundary123"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
        return body, f"multipart/form-data; boundary={boundary}"

    def test_arm_option_is_forwarded_and_auto_device_preserved(self) -> None:
        status, data = self._post(
            {
                "upload_id": "upload_api",
                "engine": "agent-native",
                "options": {"arm_device": True},
            }
        )
        self.assertEqual(status, 201, data)
        assert self.jobs.created is not None
        self.assertTrue(self.jobs.created["options"]["arm_device"])
        # None lets the worker resolve the device and mark the job as auto,
        # which is what enables the x86 -> ARM fallback.
        self.assertIsNone(self.jobs.created["serial"])

    def test_explicit_serial_is_forwarded(self) -> None:
        status, data = self._post(
            {
                "upload_id": "upload_api",
                "engine": "agent-native",
                "serial": "127.0.0.1:5555",
                "options": {},
            }
        )
        self.assertEqual(status, 201, data)
        assert self.jobs.created is not None
        self.assertEqual(self.jobs.created["serial"], "127.0.0.1:5555")

    def test_no_online_device_maps_to_503(self) -> None:
        self.jobs.error = (
            "no online device and auto-provisioning failed; start a device "
            "or set APU_WEB_DEVICE_START_CMD"
        )
        status, data = self._post({"upload_id": "upload_api", "engine": "agent-native"})
        self.assertEqual(status, 503, data)

    def test_invalid_and_unknown_options_are_rejected(self) -> None:
        for options in (
            {"bogus": True},
            {"_auto_device": True},
            {"install": 1},
            {"timeout_s": -1},
            {"freeze_timeout_ms": "100"},
            {"frida_server_path": 42},
        ):
            with self.subTest(options=options):
                status, data = self._post(
                    {"upload_id": "upload_api", "engine": "agent-native", "options": options}
                )
                self.assertEqual(status, 400, data)
                assert data is not None
                self.assertEqual(data["error"]["code"], "invalid_input")
                self.assertIsNone(self.jobs.created)

    def test_all_shared_options_are_forwarded(self) -> None:
        options = {
            "install": False,
            "jadx": False,
            "cleanup": False,
            "keep_device_files": True,
            "prune_raw": True,
            "auto_emulator_bypass": False,
            "force_dump": True,
            "inner_bypass": True,
            "arm_device": True,
            "freeze_timeout_ms": 120000,
            "freeze_poll_ms": 50,
            "frida_timeout_ms": 90000,
            "dump_region_max": 4096,
            "jadx_timeout_s": 600,
            "timeout_s": 3600,
            "llm_max_tokens": 2048,
            "frida_server_path": "/opt/frida-server",
        }
        status, data = self._post(
            {"upload_id": "upload_api", "engine": "agent-native", "options": options}
        )
        self.assertEqual(status, 201, data)
        assert self.jobs.created is not None
        forwarded = self.jobs.created["options"]
        self.assertFalse(forwarded["install"])
        self.assertFalse(forwarded["jadx"])
        self.assertFalse(forwarded["cleanup"])
        self.assertTrue(forwarded["arm_device"])
        # The public dump_region_max alias is normalised to the engine key.
        self.assertEqual(forwarded["max_region_bytes"], 4096)
        self.assertEqual(forwarded["_frida_server_path"], "/opt/frida-server")
        self.assertEqual(forwarded["frida_server_path"], "/opt/frida-server")

    def test_retry_accepts_only_failed_partial_cancelled(self) -> None:
        for status in ("failed", "partial", "cancelled"):
            with self.subTest(status=status):
                job_id = f"job_retry_{status}"
                self._make_job(job_id, status)
                code, data = self._request("POST", f"/api/v1/jobs/{job_id}/retry")
                self.assertEqual(code, 201, data)
                assert self.jobs.retried is not None
                self.assertEqual(self.jobs.retried["job_id"], job_id)
        for status in ("queued", "running", "succeeded"):
            with self.subTest(status=status):
                job_id = f"job_retry_{status}"
                self._make_job(job_id, status)
                self.jobs.retried = None
                code, data = self._request("POST", f"/api/v1/jobs/{job_id}/retry")
                self.assertEqual(code, 409, data)
                assert data is not None
                self.assertEqual(data["error"]["code"], "job_not_retryable")
                self.assertIsNone(self.jobs.retried)
        actions = [row["action"] for row in self.db.list_audit(limit=100)[0]]
        self.assertIn("job.retry", actions)
        self.assertIn("job.retry_rejected", actions)

    def test_retry_idempotency_key_returns_same_job(self) -> None:
        self._make_job("job_retry_idem", "failed")
        self._make_job("job_retry_1", "queued")
        headers = {"Idempotency-Key": "retry-key-1"}
        code, data = self._request(
            "POST", "/api/v1/jobs/job_retry_idem/retry", extra_headers=headers
        )
        self.assertEqual(code, 201, data)
        retried = dict(self.jobs.retried or {})
        code, data = self._request(
            "POST", "/api/v1/jobs/job_retry_idem/retry", extra_headers=headers
        )
        self.assertEqual(code, 200, data)
        assert data is not None
        self.assertTrue(data["idempotent"])
        self.assertEqual(data["job"]["id"], "job_retry_1")
        self.assertEqual(self.jobs.retried, retried)

    def test_cleanup_endpoint_contract(self) -> None:
        self._make_job("job_cleanup", "failed")
        path = "/api/v1/jobs/job_cleanup/cleanup"

        # No JobQueue.cleanup_job yet in this tree (WP-F adds it).
        code, data = self._request("POST", path)
        self.assertEqual(code, 501, data)
        assert data is not None
        self.assertEqual(data["error"]["code"], "cleanup_not_supported")

        self.jobs.cleanup_job = lambda job_id: {
            "ok": True,
            "cleanup_incomplete": False,
            "message": "restored",
            "restored": ["libfoo.so"],
        }
        code, data = self._request("POST", path)
        self.assertEqual(code, 200, data)
        assert data is not None
        self.assertTrue(data["ok"])
        self.assertEqual(data["restored"], ["libfoo.so"])
        self.assertEqual(data["job"]["id"], "job_cleanup")

        def raise_missing(job_id: str) -> dict[str, Any]:
            raise KeyError(job_id)

        self.jobs.cleanup_job = raise_missing
        code, _ = self._request("POST", path)
        self.assertEqual(code, 404)

        def raise_conflict(job_id: str) -> dict[str, Any]:
            raise ValueError("job is still running")

        self.jobs.cleanup_job = raise_conflict
        code, data = self._request("POST", path)
        self.assertEqual(code, 409, data)

    def test_bundle_uploads_are_rejected_early(self) -> None:
        for filename in ("app.apks", "app.xapk"):
            with self.subTest(filename=filename):
                body, content_type = self._multipart(filename)
                code, data = self._request(
                    "POST",
                    "/api/v1/uploads",
                    raw_body=body,
                    content_type=content_type,
                )
                self.assertEqual(code, 400, data)
                assert data is not None
                self.assertEqual(data["error"]["code"], "bundle_not_supported")
        self.assertEqual(len(self.db.list_uploads(self.user_id)), 1)

    def test_chat_stop_requests_backend_cancellation(self) -> None:
        self.db.create_chat("chat_stop", self.user_id, "Stop me", "agent-native")
        seen: list[str] = []

        def request_cancel(chat_id: str) -> bool:
            seen.append(chat_id)
            return True

        self.app.chat = SimpleNamespace(request_cancel=request_cancel)
        code, data = self._request("POST", "/api/v1/chats/chat_stop/stop")
        self.assertEqual(code, 200, data)
        assert data is not None
        self.assertTrue(data["cancelled"])
        self.assertEqual(seen, ["chat_stop"])

        self.app.chat = SimpleNamespace()
        code, data = self._request("POST", "/api/v1/chats/chat_stop/stop")
        self.assertEqual(code, 501, data)
        assert data is not None
        self.assertEqual(data["error"]["code"], "chat_stop_not_supported")


class JobOptionSchemaTests(unittest.TestCase):
    def test_defaults_and_alias(self) -> None:
        options = normalize_job_options({"dump_region_max": 1024})
        self.assertTrue(options["install"])
        self.assertTrue(options["jadx"])
        self.assertTrue(options["cleanup"])
        self.assertTrue(options["auto_emulator_bypass"])
        self.assertEqual(options["max_region_bytes"], 1024)

    def test_rejects_unknown_internal_and_wrong_types(self) -> None:
        for body in (
            {"_auto_device": True},
            {"_arm_runtime": True},
            {"unknown": 1},
            {"install": 0},
            {"freeze_timeout_ms": True},
            {"freeze_timeout_ms": -1},
            {"timeout_s": 604_801},
            {"frida_server_path": "x" * 1025},
            ["not", "an", "object"],
        ):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    normalize_job_options(body)

    def test_schema_exposes_every_accepted_option(self) -> None:
        names = {item["name"] for item in option_schema_for_prompt()}
        self.assertIn("arm_device", names)
        for name in JOB_OPTION_SPECS:
            self.assertIn(name, names)
        self.assertIn("dump_region_max", names)
        self.assertNotIn("_auto_device", names)
        self.assertNotIn("_arm_runtime", names)


class EventBusOverflowTests(unittest.TestCase):
    def test_full_subscriber_is_marked_and_events_stay_in_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = Database(root / "db.sqlite3")
            db.initialize()
            user = db.create_user("bus-user", "hash", "salt")
            db.create_upload("u1", int(user["id"]), "a.apk", str(root / "a.apk"), 1, "0" * 64)
            db.create_job("job_bus", int(user["id"]), "u1", "agent-native", None, {}, "run_bus")
            bus = EventBus(db)
            subscriber = bus.subscribe("job_bus", maxsize=1)
            bus.publish("job_bus", "first")
            bus.publish("job_bus", "second")
            self.assertTrue(subscriber.overflowed.is_set())
            self.assertEqual(subscriber.qsize(), 1)
            events = db.list_events("job_bus", 0, 10)
            self.assertEqual([event["kind"] for event in events], ["first", "second"])
            # The queued event is still retrievable; the stream ends so the
            # client reconnects with Last-Event-ID instead of losing events.
            self.assertEqual(subscriber.get_nowait()["kind"], "first")
            bus.unsubscribe("job_bus", subscriber)


class _FakeDevices:
    def __init__(self) -> None:
        self.acquired: list[Any] = []

    def acquire(self, serial: Any):
        self.acquired.append(serial)
        return contextlib.nullcontext()


class McpIsolationTests(unittest.TestCase):
    def test_default_device_is_not_injected_into_non_device_tool(self) -> None:
        self.config.serial = "emulator-5554"
        self._call("inspect_run", {"run_id": "run_own", "limit": 1})
        self.assertEqual(self.service.calls[-1][0], "inspect_run")
        self.assertNotIn("serial", self.service.calls[-1][1])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=root / "data")
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.user = self.db.create_user("mcp-user", "hash", "salt")
        self.user_id = int(self.user["id"])
        self.other = self.db.create_user("mcp-other", "hash", "salt")
        self.other_id = int(self.other["id"])
        self.token = "mcp-token"
        self.db.create_session(token_hash(self.token), self.user_id, 1)
        self.admin = self.db.create_user("mcp-admin", "hash", "salt", "admin")
        self.admin_token = "mcp-admin-token"
        self.db.create_session(token_hash(self.admin_token), int(self.admin["id"]), 1)
        self.lessons = MemoryStore(root / "memory")

        own_dir = self.config.uploads_dir / "upload_own"
        own_dir.mkdir(parents=True)
        self.own_apk = own_dir / "target.apk"
        self.own_apk.write_bytes(b"PK\x03\x04")
        self.db.create_upload(
            "upload_own", self.user_id, "target.apk", str(self.own_apk), 4, "0" * 64
        )
        self.db.create_job(
            "job_own", self.user_id, "upload_own", "agent-native", None, {}, "run_own"
        )

        foreign_dir = self.config.uploads_dir / "upload_foreign"
        foreign_dir.mkdir(parents=True)
        self.foreign_apk = foreign_dir / "secret.apk"
        self.foreign_apk.write_bytes(b"PK\x03\x04")
        self.db.create_upload(
            "upload_foreign", self.other_id, "secret.apk", str(self.foreign_apk), 4, "1" * 64
        )
        self.db.create_job(
            "job_foreign", self.other_id, "upload_foreign", "agent-native", None, {}, "run_foreign"
        )

        self.service = LessonAwareFakeService(self.lessons)
        self.devices = _FakeDevices()
        self.jobs = SimpleNamespace(
            service=self.service,
            devices=self.devices,
            canonical_serial=lambda serial: f"canon-{serial}",
        )
        self.app = SimpleNamespace(
            config=self.config,
            database=self.db,
            jobs=self.jobs,
            mcp_run_owners={},
            mcp_cancels={},
            mcp_lock=threading.Lock(),
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

    def _mcp(
        self, payload: dict[str, Any], token: str | None = None
    ) -> tuple[int, dict[str, Any]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {
            "Connection": "close",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token or self.token}",
        }
        try:
            connection.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else {}
        finally:
            connection.close()

    def _call(
        self,
        name: str,
        arguments: dict[str, Any],
        request_id: Any = 1,
        token: str | None = None,
    ) -> dict[str, Any]:
        _, data = self._mcp(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            token=token,
        )
        return data.get("result") or {}

    def _assert_error(self, result: dict[str, Any], code: str) -> None:
        self.assertTrue(result.get("isError"), result)
        payload = json.loads(result["content"][0]["text"])
        if isinstance(payload.get("error"), dict):
            payload = payload["error"]
        self.assertEqual(payload["code"], code)

    def test_device_serial_is_canonicalized_before_lock(self) -> None:
        result = self._call("inspect_android_device", {"serial": "emulator-5554"})
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(self.devices.acquired, ["canon-emulator-5554"])
        self.assertEqual(self.service.calls[-1][1]["serial"], "canon-emulator-5554")

    def test_foreign_run_is_rejected(self) -> None:
        result = self._call("inspect_process_state", {"run_id": "run_foreign", "pid": 1})
        self._assert_error(result, "permission_denied")
        self.assertFalse(any(name == "inspect_process_state" for name, _ in self.service.calls))

    def test_own_run_is_allowed(self) -> None:
        result = self._call("inspect_process_state", {"run_id": "run_own", "pid": 1})
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(self.service.calls[-1][1]["run_id"], "run_own")

    def test_non_admin_remember_lesson_is_forbidden_and_not_recorded(self) -> None:
        result = self._call(
            "remember_unpack_lesson",
            {
                "title": "non-admin lesson",
                "scenario": "a regular user calls the MCP tool",
                "solution": "should be rejected instead of trusted",
            },
        )
        self._assert_error(result, "forbidden")
        payload = json.loads(result["content"][0]["text"])["error"]
        self.assertTrue(payload.get("details", {}).get("admin_required"))
        # The workflow must never run, so no default-trusted lesson exists.
        self.assertFalse(
            any(name == "remember_unpack_lesson" for name, _ in self.service.calls)
        )
        self.assertEqual(self.lessons.list(limit=10)["total"], 0)
        self.assertEqual(self.service.lessons.stats()["untrusted"], 0)

    def test_admin_remember_lesson_is_allowed_and_trusted(self) -> None:
        result = self._call(
            "remember_unpack_lesson",
            {
                "title": "admin lesson",
                "scenario": "an administrator calls the MCP tool",
                "solution": "the lesson is recorded as trusted",
            },
            token=self.admin_token,
        )
        self.assertFalse(result.get("isError"), result)
        payload = json.loads(result["content"][0]["text"])
        self.assertIs(payload["lesson"]["trusted"], True)
        self.assertEqual(payload["lesson"]["source"], "manual")
        stored = self.lessons.list(limit=10)
        self.assertEqual(stored["total"], 1)
        self.assertIs(stored["lessons"][0]["trusted"], True)
        self.assertEqual(stored["stats"]["untrusted"], 0)

    def test_apk_path_outside_roots_and_traversal_are_rejected(self) -> None:
        outside = Path(self.temp.name) / "outside.apk"
        outside.write_bytes(b"PK\x03\x04")
        for path in (
            str(outside),
            str(self.config.uploads_dir / "upload_own" / ".." / ".." / "outside.apk"),
        ):
            with self.subTest(path=path):
                self.service.calls.clear()
                result = self._call("inspect_apk", {"apk_path": path})
                self._assert_error(result, "permission_denied")
                self.assertFalse(any(name == "inspect_apk" for name, _ in self.service.calls))

    def test_foreign_upload_is_rejected_and_own_upload_allowed(self) -> None:
        result = self._call("inspect_apk", {"apk_path": str(self.foreign_apk)})
        self._assert_error(result, "permission_denied")
        self.assertFalse(any(name == "inspect_apk" for name, _ in self.service.calls))

        result = self._call("inspect_apk", {"apk_path": str(self.own_apk)})
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(self.service.calls[-1][1]["apk_path"], str(self.own_apk.resolve()))
        # The run created by inspect_apk is now owned by this caller.
        self.assertEqual(self.app.mcp_run_owners.get("run_fake"), self.user_id)

    def test_output_path_outside_roots_and_foreign_runs_are_rejected(self) -> None:
        outside = Path(self.temp.name) / "bundle.json"
        foreign = self.config.runs_dir / "run_foreign" / "bundle.json"
        traversal = self.config.runs_dir / "run_own" / ".." / "run_foreign" / "bundle.json"
        for path in (str(outside), str(foreign), str(traversal)):
            with self.subTest(path=path):
                self.service.calls.clear()
                result = self._call(
                    "export_evidence_bundle",
                    {"run_id": "run_own", "output_path": path},
                )
                self._assert_error(result, "permission_denied")
                self.assertFalse(any(name == "export_evidence_bundle" for name, _ in self.service.calls))

        own_output = self.config.runs_dir / "run_own" / "bundle.json"
        result = self._call(
            "export_evidence_bundle",
            {"run_id": "run_own", "output_path": str(own_output)},
        )
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(
            self.service.calls[-1][1]["output_path"], str(own_output.resolve())
        )

    def test_input_paths_and_dirs_are_confined(self) -> None:
        foreign_dex = self.config.runs_dir / "run_foreign" / "raw" / "classes.dex"
        traversal = self.config.runs_dir / "run_own" / ".." / "run_foreign" / "raw" / "classes.dex"
        outside = Path(self.temp.name) / "classes.dex"
        for value in (
            [str(foreign_dex)],
            [str(traversal)],
            [str(outside)],
            [str(self.config.runs_dir / "run_own" / "raw" / "classes.dex"), str(outside)],
        ):
            with self.subTest(value=value):
                self.service.calls.clear()
                result = self._call(
                    "repair_android_dex", {"run_id": "run_own", "input_paths": value}
                )
                self._assert_error(result, "permission_denied")
                self.assertFalse(any(name == "repair_android_dex" for name, _ in self.service.calls))

        for field, value in (
            ("input_dir", str(foreign_dex.parent)),
            ("output_dir", str(Path(self.temp.name) / "fixed")),
        ):
            with self.subTest(field=field):
                self.service.calls.clear()
                result = self._call(
                    "repair_android_dex", {"run_id": "run_own", field: value}
                )
                self._assert_error(result, "permission_denied")
                self.assertFalse(any(name == "repair_android_dex" for name, _ in self.service.calls))

        own_dex = self.config.runs_dir / "run_own" / "raw" / "classes.dex"
        result = self._call(
            "repair_android_dex", {"run_id": "run_own", "input_paths": [str(own_dex)]}
        )
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(self.service.calls[-1][1]["input_paths"], [str(own_dex.resolve())])

    def test_cancel_notification_sets_active_request_and_rejects_unknown(self) -> None:
        event = threading.Event()
        self.app.mcp_cancels[_mcp_request_key(7)] = event
        status, _ = self._mcp(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 7},
            }
        )
        self.assertEqual(status, 202)
        self.assertTrue(event.is_set())

        status, data = self._mcp(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 999},
            }
        )
        self.assertEqual(status, 501, data)
        self.assertEqual(data["error"]["code"], "cancel_not_supported")


class StaticAssetTests(unittest.TestCase):
    """Lightweight guards for static UI wiring that has no JS test harness."""

    def setUp(self) -> None:
        self.static = Path(__file__).resolve().parents[1] / "static"

    def test_i18n_covers_advanced_options_cleanup_and_arm_notes(self) -> None:
        source = (self.static / "i18n.js").read_text(encoding="utf-8")
        # The stale .apks/.xapk support claim must be gone.
        self.assertNotIn("支持 .apk / .apks / .xapk", source)
        self.assertNotIn("Supports .apk / .apks / .xapk", source)
        for key in (
            "仅支持单个 .apk 文件",
            "不支持的分卷包",
            "高级任务选项",
            "冻结超时 ms",
            "内存区域上限",
            "JADX 超时 s",
            "总超时 s",
            "Frida Server 路径",
            "强制 DEX dump",
            "内层 SO 绕过",
            "清理原始 dump",
            "清理设备",
            "设备清理",
            "清理错误",
            "ARM 可用性：加载中…",
        ):
            with self.subTest(key=key):
                self.assertIn(f'"{key}"', source)

    def test_chat_stop_calls_backend_endpoint_and_aborts_locally(self) -> None:
        source = (self.static / "app.js").read_text(encoding="utf-8")
        self.assertIn("/api/v1/chats/${encodeURIComponent(chatId)}/stop", source)
        self.assertIn("state.chatAbort.abort()", source)
        # 404/501 are tolerated so older backends keep the local abort behavior.
        self.assertIn("[404, 501, 503]", source)


if __name__ == "__main__":
    unittest.main()
