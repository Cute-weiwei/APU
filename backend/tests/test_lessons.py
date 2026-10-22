from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from apk_unpack.application.memory import MemoryStore

from backend.engines import EngineResult
from backend.lessons import record_job_lesson


class AutoLessonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run_dir = self.root / "runs" / "run_test"
        self.run_dir.mkdir(parents=True)
        self.lessons = MemoryStore(self.root / "memory")
        self.events: list[tuple[str, str, dict[str, Any]]] = []
        self.job = {"id": "job_test", "engine": "agent-deepseek-openai"}

    def emit(self, kind: str, message: str = "", data: dict[str, Any] | None = None) -> None:
        self.events.append((kind, message, data or {}))

    def write_state(self, artifacts: dict[str, Any]) -> None:
        (self.run_dir / "run.json").write_text(
            json.dumps({"run_id": "run_test", "artifacts": artifacts}, ensure_ascii=False),
            encoding="utf-8",
        )

    def test_dynamic_success_auto_saved(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                    "frameworks": [],
                },
                "device": {"abi": "x86_64"},
                "attempts": [
                    {
                        "method": "frida_inmemory",
                        "status": "failed",
                        "error": {"code": "frida_attach_failed", "message": "attach refused"},
                        "evidence_id": "ev_1",
                    },
                    {"method": "memory_dd_retry", "status": "succeeded", "evidence_id": "ev_2"},
                ],
                "last_dump": {"method": "memory_dd_retry"},
            }
        )
        fixed = self.run_dir / "dexdump" / "fixed"
        fixed.mkdir(parents=True)
        (fixed / "classes.dex").write_bytes(b"dex\n035\x00")
        result = EngineResult("success", run_id="run_test")
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        self.assertEqual(lesson["kind"], "auto")
        self.assertEqual(lesson["winning_method"], "memory_dd_retry")
        self.assertEqual(lesson["shell"], "ijiami")
        self.assertEqual(lesson["device_abi"], "x86_64")
        self.assertEqual(lesson["apk_abi_class"], "arm-only")
        self.assertEqual(lesson["occurrences"], 1)
        self.assertEqual(lesson["success_count"], 1)
        self.assertTrue(any(item[0] == "lesson_recorded" for item in self.events))
        stored = self.lessons.list(limit=10)["lessons"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["lesson_id"], lesson["lesson_id"])

    def test_static_success_auto_saved(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.android.settings"},
                    "packing": {"primary": None, "packed": False},
                    "abis": [],
                    "frameworks": [],
                },
                "device": {"abi": "x86_64"},
                "attempts": [],
            }
        )
        sources = self.run_dir / "dexdump" / "jadx" / "settings" / "sources"
        sources.mkdir(parents=True)
        (sources / "Example.java").write_text("class Example {}", encoding="utf-8")
        result = EngineResult("success", run_id="run_test")
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        self.assertEqual(lesson["winning_method"], "static_route")
        self.assertIn("static", lesson["tags"])
        self.assertIn("not packed", lesson["root_cause"])

    def test_packed_static_route_is_a_pitfall(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example.geiri"},
                    "packing": {"primary": "360", "display": "360 Jiagu (360加固)", "packed": True},
                    "abis": ["arm64-v8a"],
                    "frameworks": [],
                },
                "device": {"abi": "x86_64"},
                "attempts": [],
            }
        )
        sources = self.run_dir / "dexdump" / "jadx" / "loader" / "sources"
        sources.mkdir(parents=True)
        (sources / "Loader.java").write_text("class Loader {}", encoding="utf-8")
        result = EngineResult(
            "partial",
            run_id="run_test",
            error={"code": "packed_static_only", "message": "shell loader only"},
        )
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        self.assertEqual(lesson["winning_method"], "static_shell_only")
        self.assertIn("shell loader", lesson["root_cause"])
        self.assertEqual(lesson["success_count"], 0)

    def test_failed_job_auto_saved(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example.bad"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [
                    {
                        "method": "frida_inmemory",
                        "status": "failed",
                        "error": {"code": "process_died", "message": "SIGKILL after libexec.so"},
                    }
                ],
            }
        )
        result = EngineResult("failed", run_id="run_test")
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        self.assertEqual(lesson["success_count"], 0)
        self.assertEqual(len(lesson["failed_methods"]), 1)
        self.assertIn("process terminated", lesson["root_cause"].lower())

    def test_cancelled_and_infra_failures_are_skipped(self) -> None:
        self.write_state({"inspection": {}, "attempts": []})
        result = EngineResult("cancelled", run_id="run_test")
        self.assertIsNone(
            record_job_lesson(
                self.lessons,
                job=self.job,
                result=result,
                run_id="run_test",
                run_dir=self.run_dir,
                emit=self.emit,
            )
        )
        result = EngineResult(
            "failed",
            run_id="run_test",
            error={"code": "unsupported_provider", "message": "missing API key"},
        )
        self.assertIsNone(
            record_job_lesson(
                self.lessons,
                job=self.job,
                result=result,
                run_id="run_test",
                run_dir=self.run_dir,
                emit=self.emit,
            )
        )
        self.assertEqual(self.lessons.list(limit=10)["total"], 0)

    def test_agent_lesson_is_not_double_counted(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [
                    {
                        "method": "frida_inmemory",
                        "status": "failed",
                        "error": {"code": "attach_failed", "message": "attach refused"},
                    },
                    {"method": "memory_dd_retry", "status": "succeeded"},
                ],
                "last_dump": {"method": "memory_dd_retry"},
            }
        )
        fixed = self.run_dir / "dexdump" / "fixed"
        fixed.mkdir(parents=True)
        (fixed / "classes.dex").write_bytes(b"dex\n035\x00")
        result = EngineResult("success", run_id="run_test")
        first = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(first)
        (self.run_dir / "events.jsonl").write_text(
            json.dumps({"event": "memory_recorded", "detail": {"lesson_id": first["lesson_id"]}}) + "\n",
            encoding="utf-8",
        )
        second = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertEqual(second["lesson_id"], first["lesson_id"])
        self.assertEqual(self.lessons.get(first["lesson_id"])["occurrences"], 1)
        self.assertTrue(any((data or {}).get("deduped") for _, _, data in self.events))

    def test_same_route_with_different_error_code_is_deduped(self) -> None:
        def write(code: str) -> None:
            self.write_state(
                {
                    "inspection": {
                        "package": {"name": "com.example"},
                        "packing": {"primary": "ijiami", "packed": True},
                        "abis": ["arm64-v8a"],
                        "frameworks": [],
                    },
                    "device": {"abi": "x86_64"},
                    "attempts": [
                        {
                            "method": "frida_inmemory",
                            "status": "failed",
                            "error": {"code": code, "message": f"attach refused ({code})"},
                        },
                        {"method": "memory_dd_retry", "status": "succeeded"},
                    ],
                    "last_dump": {"method": "memory_dd_retry"},
                }
            )
            fixed = self.run_dir / "dexdump" / "fixed"
            fixed.mkdir(parents=True, exist_ok=True)
            (fixed / "classes.dex").write_bytes(b"dex\n035\x00")

        write("frida_attach_failed")
        first = record_job_lesson(
            self.lessons, job=self.job, result=EngineResult("success", run_id="run_test"),
            run_id="run_test", run_dir=self.run_dir, emit=self.emit,
        )
        write("frida_server_missing")
        second = record_job_lesson(
            self.lessons, job=self.job, result=EngineResult("success", run_id="run_test"),
            run_id="run_test", run_dir=self.run_dir, emit=self.emit,
        )
        self.assertEqual(second["lesson_id"], first["lesson_id"])
        stored = self.lessons.list(limit=10)["lessons"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["occurrences"], 2)
        self.assertTrue(any((data or {}).get("deduped") for _, _, data in self.events))

    def test_success_without_artifacts_is_skipped(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [{"method": "memory_dd_retry", "status": "succeeded"}],
                "last_dump": {"method": "memory_dd_retry"},
            }
        )
        lesson = record_job_lesson(
            self.lessons, job=self.job, result=EngineResult("success", run_id="run_test"),
            run_id="run_test", run_dir=self.run_dir, emit=self.emit,
        )
        self.assertIsNone(lesson)
        self.assertEqual(self.lessons.list(limit=10)["total"], 0)

    def test_job_level_process_died_is_recorded_as_pitfall(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [],
            }
        )
        result = EngineResult(
            "failed",
            run_id="run_test",
            error={
                "code": "process_died",
                "message": "am start: process not found after 5s; SIGKILL before dump",
            },
        )
        lesson = record_job_lesson(
            self.lessons, job=self.job, result=result,
            run_id="run_test", run_dir=self.run_dir, emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        self.assertEqual(lesson["success_count"], 0)
        self.assertEqual(lesson["failed_methods"][0]["method"], "process_died")
        self.assertIn("startup", lesson["title"])
        self.assertIn("terminated", lesson["root_cause"].lower())

    def test_dump_failure_with_attempts_is_recorded_as_pitfall(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "bangcle", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [
                    {
                        "method": "memory_dd",
                        "status": "failed",
                        "error": {"code": "dump_incomplete", "message": "no freeze target region appeared"},
                    }
                ],
            }
        )
        lesson = record_job_lesson(
            self.lessons, job=self.job, result=EngineResult("failed", run_id="run_test"),
            run_id="run_test", run_dir=self.run_dir, emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        self.assertEqual(lesson["success_count"], 0)
        self.assertEqual(lesson["failed_methods"][0]["method"], "memory_dd")
        self.assertIn("no winning", lesson["title"])

    def test_job_level_error_without_attempts_is_skipped(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "bangcle", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [],
            }
        )
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=EngineResult(
                "failed", run_id="run_test",
                error={"code": "configuration_error", "message": "missing tool"},
            ),
            run_id="run_test", run_dir=self.run_dir, emit=self.emit,
        )
        self.assertIsNone(lesson)
        self.assertEqual(self.lessons.list(limit=10)["total"], 0)


    def _write_partial_dynamic_state(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                    "frameworks": [],
                },
                "device": {"abi": "x86_64"},
                "attempts": [
                    {
                        "method": "frida_inmemory",
                        "status": "failed",
                        "error": {"code": "frida_attach_failed", "message": "attach refused"},
                    },
                    {"method": "memory_dd_retry", "status": "succeeded", "evidence_id": "ev_partial"},
                ],
                "last_dump": {"method": "memory_dd_retry"},
            }
        )
        fixed = self.run_dir / "dexdump" / "fixed"
        fixed.mkdir(parents=True, exist_ok=True)
        (fixed / "classes.dex").write_bytes(b"dex\n035\x00")

    def test_partial_dynamic_route_is_a_warning_not_a_success(self) -> None:
        self._write_partial_dynamic_state()
        result = EngineResult(
            "partial",
            run_id="run_test",
            error={
                "code": "no_target_dex",
                "message": "fixed dex has no target package classes",
            },
            warnings=["target DEX failed verification"],
        )
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=result,
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        assert lesson is not None
        # A partial job must never count as a success or be promoted as a route.
        self.assertEqual(lesson["success_count"], 0)
        self.assertEqual(lesson["occurrences"], 1)
        self.assertIsNone(lesson["winning_method"])
        self.assertIn("partial", lesson["title"].lower())
        self.assertIn("unverified", lesson["title"].lower())
        self.assertIn("pitfall", lesson["tags"])
        self.assertIn("warning", lesson["tags"])
        self.assertIn("partial", lesson["tags"])
        self.assertIn("not a success", lesson["solution"].lower())
        failed = {(item.get("method"), item.get("code")) for item in lesson["failed_methods"]}
        self.assertIn(("memory_dd_retry", "no_target_dex"), failed)
        stored = self.lessons.get(lesson["lesson_id"])
        assert stored is not None
        self.assertEqual(stored["success_count"], 0)
        self.assertEqual(stored["winning_method"], None)

        recalled = self.lessons.recall(
            shell="ijiami",
            device_abi="x86_64",
            apk_abis=["arm64-v8a"],
            limit=10,
        )
        entry = next(
            (item for item in recalled["lessons"] if item["lesson_id"] == lesson["lesson_id"]),
            None,
        )
        self.assertIsNotNone(entry)
        assert entry is not None
        # The learned route order derives from winning_method + success ratio;
        # a warning lesson contributes neither.
        self.assertIsNone(entry["winning_method"])
        self.assertEqual(entry["success_count"], 0)

    def test_partial_and_verified_success_stay_separate(self) -> None:
        self._write_partial_dynamic_state()
        partial = record_job_lesson(
            self.lessons,
            job=self.job,
            result=EngineResult(
                "partial",
                run_id="run_test",
                error={"code": "no_target_dex", "message": "no target classes"},
            ),
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        success = record_job_lesson(
            self.lessons,
            job=self.job,
            result=EngineResult("success", run_id="run_test"),
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(partial)
        self.assertIsNotNone(success)
        assert partial is not None and success is not None
        self.assertNotEqual(partial["lesson_id"], success["lesson_id"])
        self.assertEqual(success["success_count"], 1)
        self.assertEqual(success["winning_method"], "memory_dd_retry")
        self.assertEqual(self.lessons.get(partial["lesson_id"])["success_count"], 0)
        self.assertEqual(self.lessons.get(success["lesson_id"])["success_count"], 1)
        self.assertEqual(self.lessons.list(limit=10)["total"], 2)

    def test_partial_without_artifacts_is_recorded_as_warning(self) -> None:
        self.write_state(
            {
                "inspection": {
                    "package": {"name": "com.example"},
                    "packing": {"primary": "ijiami", "packed": True},
                    "abis": ["arm64-v8a"],
                },
                "device": {"abi": "x86_64"},
                "attempts": [{"method": "memory_dd", "status": "succeeded"}],
                "last_dump": {"method": "memory_dd"},
            }
        )
        lesson = record_job_lesson(
            self.lessons,
            job=self.job,
            result=EngineResult(
                "partial",
                run_id="run_test",
                warnings=["no usable DEX was produced"],
            ),
            run_id="run_test",
            run_dir=self.run_dir,
            emit=self.emit,
        )
        self.assertIsNotNone(lesson)
        assert lesson is not None
        self.assertEqual(lesson["success_count"], 0)
        self.assertIsNone(lesson["winning_method"])
        self.assertIn("pitfall", lesson["tags"])
        self.assertTrue(lesson["failed_methods"])


class UntrustedLessonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = MemoryStore(Path(self.temp.name) / "memory")

    def _manual(self, title: str = "shared lesson") -> dict[str, Any]:
        return {
            "title": title,
            "scenario": "a shell symptom",
            "solution": "use the documented fallback",
            "shell": "ijiami",
            "package_scope": "global",
            "confidence": "analyst",
        }

    def test_untrusted_import_is_stored_but_not_recalled(self) -> None:
        result = self.store.import_document(
            {"lessons": [self._manual("untrusted import")]},
            source="web-import",
            trusted=False,
        )
        self.assertEqual(result["imported"], 1)
        self.assertFalse(result["trusted"])
        stored = self.store.list(limit=10)["lessons"][0]
        self.assertIs(stored["trusted"], False)
        self.assertEqual(stored["source"], "web-import")
        self.assertEqual(self.store.recall(limit=10)["total"], 0)
        self.assertEqual(self.store.recall(query="untrusted", limit=10)["total"], 0)
        self.assertEqual(self.store.stats()["untrusted"], 1)

    def test_trusted_import_is_recalled(self) -> None:
        result = self.store.import_document(
            {"lessons": [self._manual("trusted import")]},
            source="web-import",
            trusted=True,
        )
        self.assertEqual(result["imported"], 1)
        recalled = self.store.recall(query="trusted", limit=10)
        self.assertEqual(recalled["total"], 1)
        self.assertIs(recalled["lessons"][0]["trusted"], True)
        self.assertEqual(recalled["lessons"][0]["source"], "web-import")

    def test_untrusted_auto_lesson_never_merges_into_verified_success(self) -> None:
        payload = {
            "title": "ijiami: dump route",
            "scenario": "DEX dump automatic route",
            "shell": "ijiami",
            "device_abi": "x86_64",
            "apk_abis": ["arm64-v8a"],
            "winning_method": "memory_dd",
            "failed_methods": [{"method": "frida_inmemory", "code": "execution_failure"}],
            "confidence": "observed",
        }
        trusted, status = self.store.record(payload, kind="auto", trusted=True)
        self.assertEqual(status, "added")
        self.assertIs(trusted["trusted"], True)
        self.assertEqual(trusted["success_count"], 1)

        untrusted, status = self.store.record(
            payload, kind="auto", success=False, trusted=False, source="web-import"
        )
        self.assertEqual(status, "added")
        self.assertIs(untrusted["trusted"], False)
        self.assertNotEqual(untrusted["lesson_id"], trusted["lesson_id"])

        # A later verified success merges into the trusted record only.
        merged, status = self.store.record(payload, kind="auto", trusted=True)
        self.assertEqual(status, "merged")
        self.assertEqual(merged["lesson_id"], trusted["lesson_id"])
        self.assertEqual(merged["success_count"], 2)
        self.assertEqual(merged["occurrences"], 2)
        self.assertEqual(self.store.get(untrusted["lesson_id"])["success_count"], 0)
        self.assertEqual(self.store.get(untrusted["lesson_id"])["occurrences"], 1)

    def test_recall_ignores_legacy_untrusted_and_keeps_legacy_trusted(self) -> None:
        self.store.ensure()
        legacy = self._manual("legacy trusted")
        legacy.update(
            {
                "schema_version": 1,
                "lesson_id": "ls_legacytrusted",
                "fingerprint": "fp-legacy",
                "kind": "manual",
                "success_count": 1,
                "occurrences": 1,
            }
        )
        blocked = self._manual("legacy blocked")
        blocked.update(
            {
                "schema_version": 1,
                "lesson_id": "ls_legacyblocked",
                "fingerprint": "fp-blocked",
                "kind": "manual",
                "trusted": False,
                "source": "web-import",
                "success_count": 1,
                "occurrences": 1,
            }
        )
        (self.store.root / "lessons.json").write_text(
            json.dumps({"schema_version": 1, "lessons": [legacy, blocked]}),
            encoding="utf-8",
        )
        recalled = self.store.recall(limit=10)
        ids = {item["lesson_id"] for item in recalled["lessons"]}
        self.assertEqual(ids, {"ls_legacytrusted"})


if __name__ == "__main__":
    unittest.main()
