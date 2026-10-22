from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from apk_unpack.application.memory import MemoryStore
from apk_unpack.application.workflow import ToolService
from apk_unpack.config import Config
from apk_unpack.domain.workspace import RunWorkspace


def inspection() -> dict:
    return {
        "identity": {"path": "x.apk", "sha256": "a" * 64, "size": 1},
        "package": {"name": "com.example", "launchable_activity": None},
        "abis": ["arm64-v8a"],
        "frameworks": [],
        "packing": {"primary": "ijiami", "layers": [{"shell": "ijiami"}], "packed": True},
        "limitations": [],
    }


class LearningIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config.load(runs_dir=self.root / "runs")
        self.config.memory_dir = self.root / "memory"
        self.service = ToolService(self.config)
        self.run = RunWorkspace.create(self.root / "runs")
        self.run.update_run(
            package="com.example",
            artifacts={
                "inspection": inspection(),
                "device": {"serial": "fake", "abi": "x86_64", "root": {"available": True}},
                "process": {"tracer_pid": 0},
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_repeated_lesson_promotes_learned_primary(self) -> None:
        payload = {
            "title": "ijiami: frida_inmemory → freeze_dd",
            "scenario": "DEX dump automatic fallback",
            "shell": "ijiami",
            "device_abi": "x86_64",
            "apk_abis": ["arm64-v8a"],
            "winning_method": "freeze_dd",
            "failed_methods": [{"method": "frida_inmemory", "code": "execution_failure", "message": "signal 9"}],
            "solution": "Use freeze_dd.",
            "confidence": "observed",
        }
        for _ in range(3):
            self.service.lessons.record(payload, kind="auto")
        result = self.service.recommend_unpack_strategy(self.run.run_id)
        strategy = result["strategy"]
        self.assertEqual(strategy["learned_primary"], "freeze_dd")
        self.assertTrue(any(item["kind"] == "primary" for item in strategy["learned_adjustments"]))
        self.assertTrue(strategy["lessons"])
        self.assertTrue(any("ijiami" in (lesson.get("title") or "") for lesson in strategy["lessons"]))

    def test_manual_lesson_and_recall_tools(self) -> None:
        remembered = self.service.remember_unpack_lesson(
            title="new anti-debug check",
            scenario="attach was killed with SIGKILL",
            solution="use freeze_dd",
            shell="ijiami",
            device_abi="x86_64",
            apk_abis=["arm64-v8a"],
            confidence="analyst",
        )
        self.assertEqual(remembered["status"], "added")
        recalled = self.service.recall_unpack_lessons(shell="ijiami", device_abi="x86_64")
        self.assertGreaterEqual(recalled["total"], 1)
        self.assertEqual(recalled["lessons"][0]["winning_method"], None)
        self.assertIn("freeze_dd", recalled["lessons"][0]["solution"])


if __name__ == "__main__":
    unittest.main()
