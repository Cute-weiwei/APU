from __future__ import annotations

import io
import json
import struct
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from apk_unpack.providers.dex import repair_dex
from backend.config import BackendConfig
from backend.db import Database
from backend.engines import (
    AgentEngine,
    EngineResult,
    JobContext,
    ProviderOpenAIEngine,
    _looks_like_jadx_error,
    apk_source_dex_hashes,
    assess_fixed_dex,
    dex_content_hash,
    run_target_apk_path,
)
from backend.events import EventBus
from backend.jobs import DeviceLockManager, JobManager
from backend.providers import ProviderConfig
from tests.fixtures import build_apk, build_dex, build_valid_dex


def write_run(
    run_dir: Path,
    dex_bytes: bytes | None = None,
    package: str = "com.example",
    packed: bool = False,
    attempts: list[dict[str, Any]] | None = None,
    target_apk: Path | None = None,
    raw: dict[str, bytes] | None = None,
) -> Path:
    fixed = run_dir / "dexdump" / "fixed"
    fixed.mkdir(parents=True, exist_ok=True)
    if dex_bytes is not None:
        (fixed / "classes.dex").write_bytes(dex_bytes)
    if raw:
        raw_dir = run_dir / "dexdump" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        for name, data in raw.items():
            (raw_dir / name).write_bytes(data)
    state: dict[str, Any] = {
        "package": package,
        "artifacts": {
            "inspection": {
                "package": {"name": package},
                "packing": {"packed": packed, "primary": "test"},
                "dex_entries": [],
            },
            "attempts": attempts or [],
        },
    }
    if target_apk is not None:
        state["target"] = {"path": str(target_apk), "format": "apk"}
    (run_dir / "run.json").write_text(json.dumps(state), encoding="utf-8")
    return run_dir


def stale_signature_dex(dex_bytes: bytes) -> bytes:
    """Keep Adler32 valid but corrupt the SHA-1 signature (re-signed app)."""
    mutated = bytearray(dex_bytes)
    mutated[0x0C] ^= 0xFF
    checksum = zlib.adler32(bytes(mutated[0x0C:])) & 0xFFFFFFFF
    struct.pack_into("<I", mutated, 0x08, checksum)
    return bytes(mutated)


class FakeCleanupService:
    def __init__(
        self,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        inspection_package: str = "com.example",
    ) -> None:
        self.result = result
        self.error = error
        self.inspection_package = inspection_package
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.tool_calls: list[tuple[str, dict[str, Any]]] = []

    def cleanup_run(self, run_id: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((run_id, dict(kwargs)))
        if self.error:
            raise RuntimeError(self.error)
        return self.result or {
            "cleanup_status": "complete",
            "restored": [],
            "failed": [],
            "remaining_mutations": [],
            "run_id": run_id,
        }

    def call_tool(self, name: str, arguments: dict[str, Any], cancel: Any = None) -> dict[str, Any]:
        self.tool_calls.append((name, dict(arguments)))
        if name == "inspect_apk":
            return {
                "run_id": arguments.get("run_id") or "run_test",
                "inspection": {
                    "package": {"name": self.inspection_package},
                    "packing": {},
                    "abis": [],
                },
            }
        return {"run_id": arguments.get("run_id") or "run_test", "ok": True}


def minimal_manager(config: BackendConfig, db: Database, service: Any) -> JobManager:
    manager = object.__new__(JobManager)
    manager.config = config
    manager.database = db
    manager.bus = EventBus(db)
    manager.devices = DeviceLockManager()
    manager.service = service
    manager._contexts = {}
    manager._context_guard = threading.Lock()
    manager._log_lock = threading.Lock()
    manager.canonical_serial = lambda serial: serial  # type: ignore[method-assign]
    return manager


def create_job_row(
    db: Database,
    config: BackendConfig,
    *,
    status: str = "succeeded",
    run_id: str = "run_cleanup",
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    user = db.create_user("cleanup-user", "hash", "salt")
    upload = config.uploads_dir / "target.apk"
    upload.parent.mkdir(parents=True, exist_ok=True)
    upload.write_bytes(b"PK\x03\x04")
    db.create_upload("upload-cleanup", int(user["id"]), "target.apk", str(upload), 4, "0" * 64)
    job = db.create_job(
        "job_cleanup",
        int(user["id"]),
        "upload-cleanup",
        "agent-native",
        "serial-1",
        options or {"install": False, "jadx": False, "cleanup": True},
        run_id,
    )
    db.update_job(job["id"], status=status, stage="done" if status in ("succeeded", "partial") else status)
    return db.get_job(job["id"]) or job


def llm_context(
    root: Path,
    config: BackendConfig,
    service: Any,
    *,
    options: dict[str, Any] | None = None,
    run_id: str = "run_llm",
) -> JobContext:
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)
    return JobContext(
        job_id="job_llm",
        user_id=1,
        engine="agent-openai",
        upload_path=root / "target.apk",
        apk_name="target.apk",
        serial="serial-1",
        options=options or {"install": False, "jadx": False, "cleanup": True},
        runs_dir=config.runs_dir,
        memory_dir=config.memory_dir,
        work_dir=work,
        cancel=threading.Event(),
        emit=lambda *args, **kwargs: None,
        service=service,
        run_id=run_id,
        config=config,
    )


def provider_config() -> ProviderConfig:
    return ProviderConfig(
        id="p",
        name="p",
        protocol="openai",
        base_url="https://example.test",
        model="m",
        api_key="sk-test",
        context_window=65536,
        max_tokens=100,
    )


class DexGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = object.__new__(JobManager)

    def _guard(self, run_dir: Path) -> EngineResult:
        return self.manager._guard_outcome(
            EngineResult("success", run_id=run_dir.name),
            SimpleNamespace(run_dir=run_dir),
            lambda *args, **kwargs: None,
        )

    def test_valid_target_dex_succeeds(self) -> None:
        run_dir = write_run(self.root / "run_ok", build_valid_dex("com.example"))
        self.assertEqual(self._guard(run_dir).outcome, "success")

    def test_wrong_package_dex_is_partial(self) -> None:
        run_dir = write_run(
            self.root / "run_wrong",
            build_valid_dex("com.other"),
            attempts=[{"method": "memory_dd", "status": "succeeded"}],
        )
        result = self._guard(run_dir)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "no_target_dex")
        self.assertIn("no_target_dex", result.error["reasons"])

    def test_stub_dex_is_partial(self) -> None:
        run_dir = write_run(
            self.root / "run_stub",
            build_dex(class_defs_size=1),
            attempts=[{"method": "memory_dd", "status": "succeeded"}],
        )
        result = self._guard(run_dir)
        self.assertEqual(result.outcome, "partial")
        self.assertIn(result.error["code"], ("stub_only", "unverified"))
        self.assertIn("stub_only", result.error["reasons"])

    def test_truncated_dex_is_partial(self) -> None:
        run_dir = write_run(
            self.root / "run_truncated",
            build_valid_dex("com.example")[:-10],
            attempts=[{"method": "memory_dd", "status": "succeeded"}],
        )
        result = self._guard(run_dir)
        self.assertEqual(result.outcome, "partial")
        self.assertIn("truncated", result.error["reasons"])
        self.assertEqual(result.error["code"], "truncated")

    def test_no_fixed_dex_is_partial(self) -> None:
        run_dir = write_run(self.root / "run_none", None)
        result = self._guard(run_dir)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "no_target_dex")

    def test_packed_static_only_is_never_succeeded(self) -> None:
        run_dir = write_run(
            self.root / "run_packed",
            build_valid_dex("com.example"),
            packed=True,
            attempts=[],
        )
        result = self._guard(run_dir)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "packed_static_only")


class DexSourceIntegrityTests(unittest.TestCase):
    """F1: repaired header alone is not proof of source integrity."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = object.__new__(JobManager)

    def _guard(self, run_dir: Path) -> EngineResult:
        return self.manager._guard_outcome(
            EngineResult("success", run_id=run_dir.name),
            SimpleNamespace(run_dir=run_dir),
            lambda *args, **kwargs: None,
        )

    def test_fixed_dex_copied_from_source_is_source_verified(self) -> None:
        source = build_valid_dex("com.example")
        apk = build_apk(self.root / "plain.apk", {"classes.dex": source})
        run_dir = write_run(self.root / "run_source", source, target_apk=apk)
        self.assertEqual(run_target_apk_path(run_dir), apk)
        source_hashes, info = apk_source_dex_hashes(apk)
        self.assertTrue(info["available"])
        self.assertIn(dex_content_hash(source), source_hashes)

        verdict = assess_fixed_dex(run_dir, "com.example")
        self.assertTrue(verdict["usable"])
        self.assertTrue(verdict["verified"])
        self.assertFalse(verdict["repaired_unverified"])
        item = verdict["files"][0]
        self.assertTrue(item["source_verified"])
        self.assertTrue(item["verified"])
        self.assertEqual(item["source_entry"], "classes.dex")
        self.assertEqual(verdict["source"]["apk_path"], str(apk))
        self.assertEqual(self._guard(run_dir).outcome, "success")

    def test_dynamic_dump_matching_source_succeeds(self) -> None:
        source = build_valid_dex("com.example")
        apk = build_apk(self.root / "unprotected.apk", {"classes.dex": source})
        run_dir = write_run(
            self.root / "run_dynamic",
            source,
            target_apk=apk,
            attempts=[{"method": "memory_dd", "status": "succeeded"}],
        )
        verdict = assess_fixed_dex(run_dir, "com.example")
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["files"][0]["source_verified"])
        self.assertEqual(self._guard(run_dir).outcome, "success")

    def test_static_route_repaired_dex_remains_source_verified(self) -> None:
        # Static routes copy the APK DEX to raw and repair it.  A stale SHA-1
        # header must not break the content match against the shipped source.
        source = build_valid_dex("com.example")
        stale = stale_signature_dex(source)
        apk = build_apk(self.root / "stale.apk", {"classes.dex": stale})
        run_dir = write_run(
            self.root / "run_static",
            None,
            target_apk=apk,
            raw={"classes.dex": stale},
        )
        report = repair_dex(
            run_dir / "dexdump" / "raw" / "classes.dex",
            run_dir / "dexdump" / "fixed" / "classes.dex",
            expected_package="com.example",
        )
        self.assertEqual(report["status"], "complete")
        self.assertEqual(
            dex_content_hash(run_dir / "dexdump" / "fixed" / "classes.dex"),
            dex_content_hash(stale),
        )

        verdict = assess_fixed_dex(run_dir, "com.example")
        self.assertTrue(verdict["verified"])
        self.assertFalse(verdict["repaired_unverified"])
        item = verdict["files"][0]
        self.assertTrue(item["source_verified"])
        self.assertTrue(item["verified"])
        self.assertEqual(self._guard(run_dir).outcome, "success")

    def test_repaired_dex_without_source_match_is_repaired_unverified(self) -> None:
        source = build_valid_dex("com.example")
        damaged = build_valid_dex("com.example", classes=13, corrupt=True)
        apk = build_apk(self.root / "source.apk", {"classes.dex": source})
        run_dir = write_run(
            self.root / "run_repaired",
            None,
            target_apk=apk,
            raw={"raw.dex": damaged},
        )
        report = repair_dex(
            run_dir / "dexdump" / "raw" / "raw.dex",
            run_dir / "dexdump" / "fixed" / "classes.dex",
            expected_package="com.example",
        )
        self.assertEqual(report["status"], "complete")
        # Repair only rewrites the header: the damaged content is preserved.
        self.assertEqual(
            dex_content_hash(run_dir / "dexdump" / "raw" / "raw.dex"),
            dex_content_hash(run_dir / "dexdump" / "fixed" / "classes.dex"),
        )

        verdict = assess_fixed_dex(run_dir, "com.example")
        self.assertTrue(verdict["usable"])
        self.assertFalse(verdict["verified"])
        self.assertTrue(verdict["repaired_unverified"])
        self.assertEqual(verdict["code"], "repaired_unverified")
        self.assertIn("repaired_unverified", verdict["reasons"])
        item = verdict["files"][0]
        self.assertFalse(item["source_verified"])
        self.assertTrue(item["repaired_unverified"])
        self.assertFalse(item["verified"])
        self.assertTrue(item["raw_matches"])

        result = self._guard(run_dir)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "repaired_unverified")
        self.assertIn("repaired_unverified", result.error["reasons"])

    def test_valid_header_raw_is_verified_without_source(self) -> None:
        raw = build_valid_dex("com.example")
        run_dir = write_run(
            self.root / "run_valid_raw",
            raw,
            target_apk=None,
            raw={"raw.dex": raw},
        )
        verdict = assess_fixed_dex(run_dir, "com.example")
        self.assertTrue(verdict["usable"])
        self.assertTrue(verdict["verified"])
        self.assertFalse(verdict["repaired_unverified"])
        self.assertFalse(verdict["files"][0]["source_verified"])
        self.assertTrue(verdict["files"][0]["verified"])
        self.assertEqual(self._guard(run_dir).outcome, "success")


class StaticDexExtractionTests(unittest.TestCase):
    """LLM static extraction repairs stale APK headers and keeps raw copies."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.config.runs_dir.mkdir(parents=True, exist_ok=True)
        self.service = FakeCleanupService()
        self.engine = ProviderOpenAIEngine(self.config, provider_config())

    def test_extract_repairs_stale_header_and_keeps_raw(self) -> None:
        source = stale_signature_dex(build_valid_dex("com.example"))
        apk = build_apk(self.root / "plain.apk", {"classes.dex": source})
        ctx = llm_context(self.root, self.config, self.service)
        ctx.upload_path = apk
        events: list[tuple[str, str, dict[str, Any] | None]] = []
        ctx.emit = lambda kind, message, data=None: events.append((kind, message, data))
        write_run(ctx.run_dir, None, target_apk=apk)

        count = self.engine._extract_static_dex(ctx)
        self.assertEqual(count, 1)
        raw = ctx.run_dir / "dexdump" / "raw" / "classes.dex"
        fixed = ctx.run_dir / "dexdump" / "fixed" / "classes.dex"
        self.assertEqual(raw.read_bytes(), source)
        self.assertTrue(fixed.is_file())
        # The repaired header differs, but the content identity does not.
        self.assertNotEqual(fixed.read_bytes(), source)
        self.assertEqual(dex_content_hash(fixed), dex_content_hash(source))
        self.assertEqual(ctx.static_dex_repair["status"], "complete")

        verdict = assess_fixed_dex(ctx.run_dir, "com.example")
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["files"][0]["source_verified"])

        extracted_events = [item for item in events if item[0] == "static_dex_extracted"]
        self.assertEqual(len(extracted_events), 1)
        payload = extracted_events[0][2] or {}
        self.assertEqual(payload["repair_status"], "complete")
        self.assertEqual(payload["expected_package"], "com.example")
        self.assertEqual(payload["repaired"], 1)
        self.assertIn(str(raw), payload["raw_paths"])

    def test_result_reports_repaired_unverified_as_partial(self) -> None:
        source = build_valid_dex("com.example")
        damaged = build_valid_dex("com.example", classes=13, corrupt=True)
        apk = build_apk(self.root / "source.apk", {"classes.dex": source})
        ctx = llm_context(self.root, self.config, self.service)
        ctx.upload_path = apk
        run_dir = write_run(ctx.run_dir, None, target_apk=apk, raw={"raw.dex": damaged})
        repair_dex(
            run_dir / "dexdump" / "raw" / "raw.dex",
            run_dir / "dexdump" / "fixed" / "classes.dex",
            expected_package="com.example",
        )
        result = self.engine._result(ctx, "ok", None, [], {"cleanup": None})
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "repaired_unverified")
        self.assertIn("repaired_unverified", result.error["reasons"])


class LLMEngineResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.config.runs_dir.mkdir(parents=True, exist_ok=True)
        self.service = FakeCleanupService()
        self.engine = ProviderOpenAIEngine(self.config, provider_config())

    def test_sources_only_is_partial(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        sources = ctx.run_dir / "dexdump" / "jadx" / "x" / "sources"
        sources.mkdir(parents=True)
        (sources / "Main.java").write_text("class Main {}", encoding="utf-8")
        result = self.engine._result(ctx, "sources", None, [], {"cleanup": None})
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "sources_only")

    def test_sources_with_usable_dex_succeeds(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, build_valid_dex("com.example"))
        sources = ctx.run_dir / "dexdump" / "jadx" / "x" / "sources"
        sources.mkdir(parents=True)
        (sources / "Main.java").write_text("class Main {}", encoding="utf-8")
        result = self.engine._result(ctx, "ok", None, [], {"cleanup": None})
        self.assertEqual(result.outcome, "success")

    def test_packed_sources_preserve_runtime_failure_cause(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, None)
        state_path = ctx.run_dir / "run.json"
        state = json.loads(state_path.read_text())
        state.setdefault("artifacts", {})["inspection"] = {"packing": {"packed": True, "primary": "ijiami"}}
        state["device"] = {"abi": "x86_64"}
        state["attempts"] = [{"method": "frida_inmemory", "status": "failed",
                              "error": {"code": "execution_failure", "message": "Process terminated"}}]
        state_path.write_text(json.dumps(state))
        sources = ctx.run_dir / "dexdump" / "jadx" / "sources"
        sources.mkdir(parents=True)
        (sources / "Shell.java").write_text("class Shell {}")
        result = self.engine._result(ctx, "ok", None, [], {"cleanup": None})
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "runtime_dump_failed")
        self.assertEqual(result.error["details"]["failed_attempts"][0]["message"], "Process terminated")
        self.assertEqual(result.error["details"]["shell"], "ijiami")
        self.assertTrue(result.error["details"]["static_sources_only"])

        state["attempts"] = []
        state_path.write_text(json.dumps(state))
        result = self.engine._result(ctx, "ok", None, [], {"cleanup": None})
        self.assertEqual(result.error["code"], "packed_static_only")

    def test_failed_verify_tool_is_not_success(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, build_valid_dex("com.example"))
        findings = {
            "tool_errors": ["verify_android_dex"],
            "cleanup": {"cleanup_status": "complete", "cleanup_incomplete": False},
        }
        result = self.engine._result(ctx, "ok", None, [], findings)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "tool_failed")

    def test_jadx_failure_alone_keeps_good_dex(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, build_valid_dex("com.example"))
        findings = {
            "tool_errors": ["decompile_android_apk"],
            "cleanup": {"cleanup_status": "complete", "cleanup_incomplete": False},
        }
        result = self.engine._result(ctx, "ok", None, [], findings)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "jadx_incomplete")
        self.assertTrue(assess_fixed_dex(ctx.run_dir, "com.example")["verified"])

    def test_cleanup_failure_degrades_success(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, build_valid_dex("com.example"))
        findings = {
            "cleanup": {
                "cleanup_status": "incomplete",
                "cleanup_incomplete": True,
                "cleanup_error": "failed to restore libfoo.so",
                "restored": [],
            }
        }
        result = self.engine._result(ctx, "ok", None, [], findings)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "cleanup_incomplete")
        self.assertEqual(result.cleanup_status, "incomplete")
        self.assertIn("libfoo.so", result.cleanup_error)

    def test_apply_cleanup_degrades_success(self) -> None:
        summary = {
            "cleanup_status": "incomplete",
            "cleanup_incomplete": True,
            "cleanup_error": "boom",
            "restored": [],
        }
        result = JobManager._apply_cleanup(EngineResult("success"), summary)
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "cleanup_incomplete")
        self.assertEqual(result.cleanup_status, "incomplete")

    def test_cancel_stops_loop_and_runs_cleanup(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        ctx.cancel.set()
        with mock.patch("backend.engines._post_json") as post:
            result = self.engine._run_openai(ctx, provider_config())
        post.assert_not_called()
        self.assertEqual(result.outcome, "cancelled")
        self.assertEqual(len(self.service.calls), 1)
        self.assertEqual(result.cleanup_status, "complete")

    def test_whole_task_timeout(self) -> None:
        ctx = llm_context(
            self.root,
            self.config,
            self.service,
            options={"timeout_s": 1, "install": False, "jadx": False, "cleanup": True},
        )
        ctx.cancel = threading.Event()

        def slow_post(*args: Any, **kwargs: Any) -> dict[str, Any]:
            time.sleep(1.05)
            return {"choices": [{"message": {"content": "done"}}], "usage": {}}

        with mock.patch("backend.engines._post_json", side_effect=slow_post):
            result = self.engine._run_openai(ctx, provider_config())
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.error["code"], "timeout")
        self.assertEqual(len(self.service.calls), 1)

    def test_finalize_records_tool_errors(self) -> None:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, build_valid_dex("com.example"))

        class FailingBridge:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def execute(self, name: str, arguments: dict[str, Any] | None) -> tuple[dict[str, Any], bool, str]:
                self.calls.append(name)
                if name in ("verify_android_dex", "cleanup_run"):
                    return {"code": "execution_failure"}, True, "{}"
                return {"ok": True}, False, "{}"

        warnings: list[str] = []
        findings = self.engine._finalize(ctx, FailingBridge(), warnings)  # type: ignore[arg-type]
        self.assertIn("verify_android_dex", findings["tool_errors"])
        self.assertIn("cleanup_run", findings["tool_errors"])
        self.assertTrue(findings["cleanup"]["cleanup_incomplete"])
        self.assertTrue(any("verify failed" in item for item in warnings))
        self.assertTrue(any("cleanup" in item for item in warnings))


class AgentEngineJadxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.config.runs_dir.mkdir(parents=True, exist_ok=True)
        self.service = FakeCleanupService()

    def _run_agent(self, payload: dict[str, Any]) -> EngineResult:
        ctx = llm_context(self.root, self.config, self.service)
        write_run(ctx.run_dir, build_valid_dex("com.example"))
        engine = AgentEngine(self.config)
        proc = SimpleNamespace(
            pid=1234,
            poll=lambda: 0,
            stdout=io.StringIO(json.dumps(payload)),
            stderr=io.StringIO(""),
            returncode=0,
        )
        engine._tail_events = lambda *args, **kwargs: None  # type: ignore[method-assign]
        engine._safety_cleanup = lambda *args, **kwargs: {  # type: ignore[method-assign]
            "cleanup_status": "complete",
            "cleanup_incomplete": False,
            "cleanup_error": None,
            "message": "ok",
            "restored": [],
            "failed": [],
            "remaining_mutations": [],
        }
        with mock.patch("backend.engines.subprocess.Popen", return_value=proc):
            return engine.run(ctx)

    def test_jadx_failure_does_not_fail_good_dex(self) -> None:
        result = self._run_agent(
            {
                "status": "success",
                "run_id": "run_llm",
                "error": {"code": "tool_missing", "message": "JADX CLI is not configured"},
            }
        )
        self.assertEqual(result.outcome, "partial")
        self.assertEqual(result.error["code"], "jadx_failed")
        self.assertTrue(result.warnings)

    def test_jadx_helper_detection(self) -> None:
        self.assertTrue(_looks_like_jadx_error({"message": "JADX decompile failed"}))
        self.assertFalse(_looks_like_jadx_error({"message": "adb device offline"}))

    def test_non_jadx_error_still_fails(self) -> None:
        result = self._run_agent(
            {
                "status": "success",
                "run_id": "run_llm",
                "error": {"code": "execution_failure", "message": "adb offline"},
            }
        )
        self.assertEqual(result.outcome, "failed")


class CleanupJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.config.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.config.runs_dir.mkdir(parents=True, exist_ok=True)

    def test_cleanup_job_structured_complete(self) -> None:
        job = create_job_row(self.db, self.config)
        write_run(self.config.runs_dir / job["run_id"], build_valid_dex("com.example"))
        service = FakeCleanupService()
        manager = minimal_manager(self.config, self.db, service)
        result = manager.cleanup_job(job["id"])
        self.assertTrue(result["ok"])
        self.assertFalse(result["cleanup_incomplete"])
        self.assertEqual(result["restored"], [])
        self.assertEqual(result["cleanup_status"], "complete")
        self.assertIn("message", result)
        self.assertEqual(service.calls[0][0], job["run_id"])
        self.assertEqual(self.db.get_job(job["id"])["status"], "succeeded")

    def test_cleanup_failure_degrades_succeeded_job(self) -> None:
        job = create_job_row(self.db, self.config)
        write_run(self.config.runs_dir / job["run_id"], build_valid_dex("com.example"))
        service = FakeCleanupService(
            result={
                "cleanup_status": "incomplete",
                "restored": [],
                "failed": [{"kind": "rename_device_lib", "error": {"code": "cleanup_incomplete"}}],
                "remaining_mutations": ["m1"],
                "run_id": job["run_id"],
            }
        )
        manager = minimal_manager(self.config, self.db, service)
        result = manager.cleanup_job(job["id"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["cleanup_incomplete"])
        self.assertTrue(result["degraded"])
        updated = self.db.get_job(job["id"])
        self.assertEqual(updated["status"], "partial")
        self.assertEqual(updated["error"]["code"], "cleanup_incomplete")
        self.assertEqual(updated["error"]["cleanup_status"], "incomplete")
        self.assertTrue(updated["error"]["cleanup_error"])

    def test_cleanup_with_missing_run_state_is_incomplete(self) -> None:
        job = create_job_row(self.db, self.config)
        manager = minimal_manager(self.config, self.db, FakeCleanupService())
        result = manager.cleanup_job(job["id"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["cleanup_incomplete"])
        self.assertIn("missing", result["cleanup_error"])
        self.assertEqual(self.db.get_job(job["id"])["status"], "partial")

    def test_cleanup_job_exception_is_incomplete(self) -> None:
        job = create_job_row(self.db, self.config)
        write_run(self.config.runs_dir / job["run_id"], build_valid_dex("com.example"))
        service = FakeCleanupService(error="adb: device offline")
        manager = minimal_manager(self.config, self.db, service)
        result = manager.cleanup_job(job["id"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["cleanup_incomplete"])
        self.assertIn("device offline", result["cleanup_error"])

    def test_cleanup_rejects_active_jobs(self) -> None:
        job = create_job_row(self.db, self.config, status="running")
        manager = minimal_manager(self.config, self.db, FakeCleanupService())
        with self.assertRaises(ValueError):
            manager.cleanup_job(job["id"])
        with self.assertRaises(KeyError):
            manager.cleanup_job("job_missing")

    def test_cleanup_runs_under_device_lock(self) -> None:
        job = create_job_row(self.db, self.config)
        write_run(self.config.runs_dir / job["run_id"], build_valid_dex("com.example"))
        seen: list[str] = []

        class LockAwareService(FakeCleanupService):
            def cleanup_run(inner_self, run_id: str, **kwargs: Any) -> dict[str, Any]:
                held = manager.devices._lock(kwargs.get("serial")).locked()
                seen.append("locked" if held else "unlocked")
                return super().cleanup_run(run_id, **kwargs)

        manager = minimal_manager(self.config, self.db, LockAwareService())
        manager.cleanup_job(job["id"])
        self.assertEqual(seen, ["locked"])


class StartupAndRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.config.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.config.runs_dir.mkdir(parents=True, exist_ok=True)

    def test_startup_recovery_cleans_and_fails_running_jobs(self) -> None:
        job = create_job_row(self.db, self.config, status="running", run_id="run_interrupted")
        write_run(self.config.runs_dir / job["run_id"], build_valid_dex("com.example"))
        service = FakeCleanupService()
        manager = minimal_manager(self.config, self.db, service)
        recovered = manager.recover_interrupted_jobs()
        self.assertEqual(len(recovered), 1)
        updated = self.db.get_job(job["id"])
        self.assertEqual(updated["status"], "failed")
        self.assertEqual(updated["error"]["code"], "execution_failure")
        self.assertEqual(updated["error"]["cleanup_status"], "complete")
        self.assertEqual(service.calls[0][0], "run_interrupted")

    def test_start_invokes_recovery(self) -> None:
        manager = minimal_manager(self.config, self.db, FakeCleanupService())
        manager._stop = threading.Event()
        manager._threads = []
        manager.queue = mock.Mock()
        with mock.patch.object(manager, "recover_interrupted_jobs") as recover, mock.patch(
            "backend.jobs.threading.Thread"
        ):
            manager.start()
        recover.assert_called_once()

    def test_retry_gate_rejects_non_terminal_failures(self) -> None:
        manager = minimal_manager(self.config, self.db, FakeCleanupService())
        manager.agents = SimpleNamespace(canonical_engine=lambda name: name)
        manager.create_job = mock.Mock(return_value={"id": "job_new"})
        user = self.db.create_user("retry-user", "hash", "salt")
        upload = self.root / "target.apk"
        upload.write_bytes(b"PK\x03\x04")
        self.db.create_upload("upload-retry", int(user["id"]), "target.apk", str(upload), 4, "0" * 64)
        for index, status in enumerate(("queued", "running", "succeeded", "failed", "partial", "cancelled")):
            job_id = f"job_retry_{index}"
            self.db.create_job(
                job_id,
                int(user["id"]),
                "upload-retry",
                "agent-native",
                "serial-1",
                {},
                f"run_retry_{index}",
            )
            self.db.update_job(job_id, status=status)
            if status in ("queued", "running", "succeeded"):
                with self.assertRaises(ValueError):
                    manager.retry_job(job_id, int(user["id"]))
            else:
                manager.retry_job(job_id, int(user["id"]))
        self.assertEqual(manager.create_job.call_count, 3)


class ProcessFinalizationTests(unittest.TestCase):
    """End-to-end ``_process`` status using a DEX-producing fake engine."""

    class DexEngine:
        name = "dex-engine"

        def __init__(self, dex_bytes: bytes, package: str = "com.example") -> None:
            self.dex_bytes = dex_bytes
            self.package = package

        def run(self, ctx: JobContext) -> EngineResult:
            fixed = ctx.run_dir / "dexdump" / "fixed"
            fixed.mkdir(parents=True, exist_ok=True)
            (fixed / "classes.dex").write_bytes(self.dex_bytes)
            (ctx.run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "package": self.package,
                        "artifacts": {
                            "inspection": {
                                "package": {"name": self.package},
                                "packing": {"packed": False},
                                "dex_entries": [],
                            },
                            "attempts": [{"method": "memory_dd", "status": "succeeded"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            return EngineResult("success", run_id=ctx.run_id, summary="fake")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.user = self.db.create_user("process-user", "hash", "salt")
        self.upload = self.root / "target.apk"
        self.upload.write_bytes(b"PK\x03\x04")
        self.db.create_upload("upload-process", int(self.user["id"]), "target.apk", str(self.upload), 4, "0" * 64)

    def _run_job(self, dex_bytes: bytes) -> dict[str, Any]:
        manager = JobManager(self.config, self.db, EventBus(self.db))
        manager.canonical_serial = lambda value: value  # type: ignore[method-assign]
        manager._is_arm_serial = lambda value: False  # type: ignore[method-assign]
        manager.engines["dex-engine"] = self.DexEngine(dex_bytes)
        job = manager.create_job(
            user_id=int(self.user["id"]),
            upload_id="upload-process",
            engine="dex-engine",
            serial="serial-1",
            options={"install": False, "jadx": False, "cleanup": False},
        )
        manager._process(job["id"])
        return self.db.get_job(job["id"]) or {}

    def test_valid_dex_is_succeeded(self) -> None:
        job = self._run_job(build_valid_dex("com.example"))
        self.assertEqual(job["status"], "succeeded", job.get("error"))

    def test_stub_dex_job_is_partial(self) -> None:
        job = self._run_job(build_dex(class_defs_size=1))
        self.assertEqual(job["status"], "partial")
        self.assertIn(job["error"]["code"], ("stub_only", "unverified"))

    def test_create_job_validates_options(self) -> None:
        manager = JobManager(self.config, self.db, EventBus(self.db))
        manager.canonical_serial = lambda value: value  # type: ignore[method-assign]
        with self.assertRaises(ValueError):
            manager.create_job(
                user_id=int(self.user["id"]),
                upload_id="upload-process",
                engine="agent",
                serial="serial-1",
                options={"timeout_s": "not-an-int"},
            )
        with self.assertRaises(ValueError):
            manager.create_job(
                user_id=int(self.user["id"]),
                upload_id="upload-process",
                engine="agent",
                serial="serial-1",
                options={"unknown_option": True},
            )

    def test_wrong_package_job_is_partial(self) -> None:
        job = self._run_job(build_valid_dex("com.other"))
        self.assertEqual(job["status"], "partial")
        self.assertEqual(job["error"]["code"], "no_target_dex")


if __name__ == "__main__":
    unittest.main()
