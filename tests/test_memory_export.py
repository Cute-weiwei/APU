from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from apk_unpack.application.memory import MemoryStore


class LessonExportImportTests(unittest.TestCase):
    def test_export_import_is_non_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = MemoryStore(Path(temp) / "source")
            source.record(
                {
                    "title": "Shared lesson",
                    "scenario": "A shell symptom",
                    "solution": "Use the documented fallback",
                    "shell": "ijiami",
                    "tags": ["shared"],
                },
                kind="manual",
                success=True,
            )
            document = source.export_document()
            self.assertEqual(document["count"], 1)
            self.assertEqual(document["kind"], "apu-lessons")
            self.assertEqual(len(document["lessons"]), 1)

            target = MemoryStore(Path(temp) / "target")
            first = target.import_document(document)
            self.assertEqual(first["imported"], 1)
            self.assertEqual(first["skipped"], 0)
            second = target.import_document(document)
            self.assertEqual(second["imported"], 0)
            self.assertEqual(second["skipped"], 1)
            self.assertEqual(second["total"], 1)

            # A same-fingerprint lesson must not overwrite the local copy.
            changed = source.export_document()
            changed["lessons"][0]["solution"] = "overwritten?"
            result = target.import_document(changed)
            self.assertEqual(result["imported"], 0)
            local = target.list()["lessons"][0]
            self.assertEqual(local["solution"], "Use the documented fallback")

    def test_import_rejects_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = MemoryStore(Path(temp))
            result = store.import_document(
                {
                    "lessons": [
                        {"kind": "manual", "title": "missing scenario and solution"},
                        {"kind": "auto"},
                        "not an object",
                    ]
                }
            )
            self.assertEqual(result["imported"], 0)
            self.assertEqual(result["invalid"], 3)
            self.assertEqual(result["total"], 0)


if __name__ == "__main__":
    unittest.main()
