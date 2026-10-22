from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from apk_unpack.application.memory import MemoryStore, apk_abi_class


def auto_payload(
    *,
    shell: str = "ijiami",
    winning_method: str = "freeze_dd",
    failed_method: str = "frida_inmemory",
) -> dict:
    return {
        "title": f"{shell}: {failed_method} → {winning_method}",
        "scenario": "DEX dump automatic fallback",
        "shell": shell,
        "device_abi": "x86_64",
        "apk_abis": ["arm64-v8a"],
        "framework": None,
        "winning_method": winning_method,
        "failed_methods": [{"method": failed_method, "code": "execution_failure", "message": "signal 9"}],
        "symptoms": ["frida attach terminated with signal 9"],
        "root_cause": "anti-debug killed the injected process",
        "solution": f"Use {winning_method}.",
        "tags": ["auto", "dump"],
        "evidence_links": ["run:run_test", "ev:ev_test"],
        "confidence": "observed",
    }


class MemoryStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = MemoryStore(self.root / "memory")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_auto_lesson_merges_and_persists(self) -> None:
        first, status = self.store.record(auto_payload(), kind="auto")
        self.assertEqual(status, "added")
        self.assertEqual(first["occurrences"], 1)
        second, status = self.store.record(auto_payload(), kind="auto")
        self.assertEqual(status, "merged")
        self.assertEqual(second["occurrences"], 2)
        self.assertEqual(second["success_count"], 2)
        reloaded = MemoryStore(self.root / "memory")
        result = reloaded.recall(shell="ijiami", device_abi="x86_64", apk_abis=["arm64-v8a"])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["lessons"][0]["winning_method"], "freeze_dd")
        self.assertTrue(any("shell=ijiami" in reason for reason in result["lessons"][0]["relevance_reasons"]))

    def test_no_winning_method_does_not_count_as_a_success(self) -> None:
        payload = auto_payload(winning_method="none")
        payload.update(title="All routes failed", scenario="Process exited", solution="Investigate startup")
        lesson, _ = self.store.record(payload, kind="manual", success=True)
        self.assertEqual(lesson["success_count"], 0)
        lesson, _ = self.store.record(payload, kind="manual", success=True)
        self.assertEqual(lesson["success_count"], 0)

    def test_imported_failure_cannot_restore_a_success_counter(self) -> None:
        self.store.import_document([{
            **auto_payload(winning_method="none"), "kind": "auto",
            "occurrences": 3, "success_count": 3,
        }])
        self.assertEqual(self.store.list()["lessons"][0]["success_count"], 0)

    def test_not_packed_lessons_merge_across_shells_and_frameworks(self) -> None:
        def payload(shell: str, framework: str, method: str) -> dict:
            return {
                "title": f"{shell}: static route",
                "scenario": "APK has no shell indicators or is already unpacked",
                "shell": shell,
                "device_abi": "x86_64",
                "apk_abis": ["arm64-v8a"],
                "framework": framework,
                "winning_method": method,
                "failed_methods": [],
                "symptoms": [],
                "root_cause": "APK is not packed; runtime dumping is unnecessary.",
                "solution": "Use the static route.",
                "tags": ["auto", "static", shell, framework],
                "evidence_links": ["run:run_test"],
                "confidence": "observed",
            }

        first, status = self.store.record(payload("bangcle", "react-native", "static_jadx"), kind="auto")
        self.assertEqual(status, "added")
        second, status = self.store.record(payload("unknown", "flutter", "static_dex_extract"), kind="auto")
        self.assertEqual(status, "merged")
        self.assertEqual(second["occurrences"], 2)
        self.assertEqual(second["title"], "APK is not packed: static route")
        self.assertIsNone(second["shell"])
        self.assertIsNone(second["framework"])
        self.assertEqual(second["winning_method"], "static_route")
        self.assertEqual(len(self.store.list()["lessons"]), 1)

    def test_consolidate_migrates_existing_not_packed_duplicates(self) -> None:
        import json

        root = "APK is not packed; runtime dumping is unnecessary."
        rows = []
        for index, shell in enumerate(("bangcle", "unknown", "unknown")):
            rows.append(
                {
                    "schema_version": 1,
                    "lesson_id": f"ls_old{index}",
                    "fingerprint": f"fp{index}",
                    "kind": "auto",
                    "title": f"{shell}: static route",
                    "scenario": "unpacked",
                    "shell": shell,
                    "device_abi": "x86_64",
                    "apk_abi_class": "arm-only",
                    "framework": None,
                    "package_scope": "global",
                    "symptoms": [],
                    "root_cause": root,
                    "solution": "Use static.",
                    "winning_method": "static_jadx",
                    "failed_methods": [],
                    "tags": ["auto", "static"],
                    "evidence_links": [f"run:run_{index}"],
                    "examples": [{"run_id": f"run_{index}"}],
                    "occurrences": 2,
                    "success_count": 2,
                    "confidence": "observed",
                    "limitations": [],
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-01T00:00:00Z",
                }
            )
        self.store.ensure()
        (self.store.root / "lessons.json").write_text(
            json.dumps({"schema_version": 1, "lessons": rows}), encoding="utf-8"
        )
        result = self.store.consolidate()
        self.assertEqual(result["merged"], 2)
        stored = self.store.list()["lessons"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["occurrences"], 6)
        self.assertIsNone(stored[0]["shell"])
        self.assertEqual(stored[0]["title"], "APK is not packed: static route")

    def test_recall_query_filters_non_matching_lessons(self) -> None:
        self.store.record(
            {
                **auto_payload(),
                "title": "unique marker lesson",
                "scenario": "only this row has zzz_unique_marker",
            },
            kind="auto",
        )
        self.store.record(auto_payload(winning_method="memory_dd", failed_method="disk_pull"), kind="auto")
        result = self.store.recall(query="zzz_unique_marker", limit=20)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["lessons"][0]["title"], "unique marker lesson")
        self.assertEqual(self.store.recall(query="no_such_marker", limit=20)["total"], 0)

    def test_recall_ranks_matching_shell_and_abi(self) -> None:
        for _ in range(3):
            self.store.record(auto_payload(), kind="auto")
        self.store.record(
            auto_payload(winning_method="memory_dd", failed_method="disk_pull"),
            kind="auto",
        )
        result = self.store.recall(shell="ijiami", device_abi="x86_64", apk_abis=["arm64-v8a"])
        self.assertEqual(result["lessons"][0]["winning_method"], "freeze_dd")
        self.assertGreater(result["lessons"][0]["score"], result["lessons"][1]["score"])

    def test_manual_lesson_redacts_secrets_and_merges(self) -> None:
        payload = {
            "title": "new emulator check",
            "scenario": "app called the API with token=abcd1234 and died",
            "solution": "rename the detection library",
            "shell": "ijiami",
            "confidence": "analyst",
            "package_scope": "global",
        }
        first, status = self.store.record(payload, kind="manual")
        self.assertEqual(status, "added")
        self.assertIn("<redacted>", first["scenario"])
        second, status = self.store.record(payload, kind="manual")
        self.assertEqual(status, "merged")
        self.assertEqual(second["occurrences"], 2)
        self.assertEqual(second["confidence"], "analyst")

    def test_package_scoped_lessons_do_not_leak(self) -> None:
        self.store.record(
            {
                "title": "package-specific fix",
                "scenario": "only this app",
                "solution": "rename a lib",
                "package_scope": "com.example",
                "confidence": "analyst",
            },
            kind="manual",
        )
        other = self.store.recall(package_name="com.other")
        self.assertEqual(other["total"], 0)
        exact = self.store.recall(package_name="com.example")
        self.assertEqual(exact["total"], 1)

    def test_abi_class(self) -> None:
        self.assertEqual(apk_abi_class(["arm64-v8a", "armeabi-v7a"]), "arm-only")
        self.assertEqual(apk_abi_class(["x86_64"]), "x86_64")
        self.assertEqual(apk_abi_class(["x86_64", "arm64-v8a"]), "mixed")
        self.assertEqual(apk_abi_class([]), "unknown")


if __name__ == "__main__":
    unittest.main()
