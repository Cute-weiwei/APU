from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from apk_unpack.providers.dex import (
    assess_dex,
    parse_dex_header,
    repair_dex,
    repair_dex_set,
    scan_file_for_dex,
    verify_dex,
)

from tests.fixtures import _build_dex_blob, build_dex, build_valid_dex, memory_dump_with_dex


def loader_dex(classes: int = 12) -> bytes:
    descriptors = [f"Lcom/Proxy/Loader{index:02d};".encode() for index in range(classes)]
    return _build_dex_blob(descriptors, set(range(classes)))


class DexTests(unittest.TestCase):
    def test_valid_dex_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classes.dex"
            path.write_bytes(build_valid_dex())
            report = verify_dex(path, "com.example")
            self.assertEqual(report["status"], "complete")
            self.assertTrue(report["complete"])
            self.assertEqual(report["total_classes"], 12)
            self.assertEqual(report["package_classes"], 12)
            self.assertEqual(report["classes_with_code"], 12)
            self.assertTrue(all(report["checks"].values()))
            self.assertTrue(report["assessment"]["complete"])

    def test_stub_dex_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stub.dex"
            path.write_bytes(build_dex(class_defs_size=2))
            report = verify_dex(path)
            self.assertNotEqual(report["status"], "complete")
            self.assertFalse(report["complete"])
            self.assertIn("stub_like", report["reasons"])
            self.assertTrue(report["assessment"]["stub_like"])

    def test_shell_dex_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "loader.dex"
            path.write_bytes(loader_dex())
            report = verify_dex(path, "com.example")
            self.assertNotEqual(report["status"], "complete")
            self.assertFalse(report["complete"])
            self.assertFalse(report["content_complete"])
            self.assertTrue(report["shell_like"])
            self.assertIn("shell_loader", report["reasons"])
            self.assertTrue(report["assessment"]["shell_like"])

    def test_corrupt_checksum_is_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bad.dex"
            source.write_bytes(build_valid_dex(corrupt=True))
            bad = verify_dex(source)
            self.assertFalse(bad["checks"]["checksum"])
            self.assertFalse(bad["checks"]["signature"])
            self.assertFalse(bad["complete"])
            fixed = Path(tmp) / "fixed.dex"
            report = repair_dex(source, fixed)
            self.assertEqual(report["status"], "complete")
            self.assertTrue(report["complete"])
            self.assertTrue(report["checksum_valid"])
            self.assertTrue(report["signature_valid"])
            self.assertEqual(parse_dex_header(fixed.read_bytes()).class_defs_size, 12)
            self.assertEqual(verify_dex(fixed, "com.example")["package_classes"], 12)
            self.assertTrue(verify_dex(fixed, "com.example")["complete"])

    def test_scan_finds_and_extracts_dex_at_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "region.bin"
            dump.write_bytes(memory_dump_with_dex(prefix_size=0x123))
            candidates = scan_file_for_dex(dump, Path(tmp) / "raw", label="region0", base_vaddr=0x1000)
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertTrue(candidate["complete"])
            self.assertEqual(candidate["vaddr"], 0x1123)
            self.assertEqual(candidate["holes"], 0)
            self.assertTrue(Path(candidate["local_path"]).is_file())
            self.assertEqual(verify_dex(candidate["local_path"])["status"], "complete")

    def test_scan_marks_stub_candidate_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "region.bin"
            dump.write_bytes(memory_dump_with_dex(dex_bytes=build_dex(class_defs_size=2)))
            candidates = scan_file_for_dex(dump, Path(tmp) / "raw", label="stub")
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertFalse(candidate["complete"])
            self.assertFalse(candidate["truncated"])
            self.assertTrue(candidate["assessment"]["stub_like"])
            self.assertIn("stub_like", candidate["reasons"])

    def test_truncated_dex_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = build_valid_dex()
            dump = Path(tmp) / "region.bin"
            dump.write_bytes(original[:-20])
            candidates = scan_file_for_dex(dump, Path(tmp) / "raw", label="truncated")
            self.assertEqual(len(candidates), 1)
            self.assertFalse(candidates[0]["complete"])
            self.assertTrue(candidates[0]["truncated"])
            self.assertIn("truncated", candidates[0]["reasons"])

    def test_cdex_is_rejected(self) -> None:
        self.assertIsNone(parse_dex_header(b"cdex001\x00" + b"\x00" * 200))

    def test_repair_set_dedupes_and_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw"
            raw.mkdir()
            good = build_valid_dex()
            (raw / "a.dex").write_bytes(good)
            (raw / "b.dex").write_bytes(good)
            (raw / "c.dex").write_bytes(build_valid_dex(corrupt=True))
            (raw / "junk.dex").write_bytes(b"not a dex")
            result = repair_dex_set(sorted(raw.glob("*.dex")), Path(tmp) / "fixed", package="com.example")
            self.assertTrue(result["files"])
            self.assertEqual(result["files"][0]["name"], "classes.dex")
            self.assertTrue(all(item["complete"] for item in result["files"]))
            self.assertEqual(result["status"], "complete")
            self.assertTrue((Path(tmp) / "fixed" / "classes.dex").is_file())
            self.assertTrue((Path(tmp) / "fixed" / "manifest.json").is_file())
            self.assertTrue(result["duplicates"])
            self.assertTrue(result["skipped"])
            manifest = json.loads((Path(tmp) / "fixed" / "manifest.json").read_text(encoding="utf-8"))
            self.assertIn("files", manifest)
            self.assertIn("assessment", manifest["files"][0])

    def test_repair_set_allow_truncated_keeps_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw"
            raw.mkdir()
            (raw / "short.dex").write_bytes(build_valid_dex()[:-5])
            result = repair_dex_set(
                sorted(raw.glob("*.dex")),
                Path(tmp) / "fixed",
                allow_truncated=True,
                package="com.example",
            )
            self.assertTrue(result["files"])
            self.assertEqual(result["files"][0]["status"], "truncated")
            self.assertFalse(result["files"][0]["complete"])
            self.assertTrue(result["files"][0]["truncated"])
            self.assertEqual(result["status"], "partial")

    def test_repair_set_wrong_package_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw"
            raw.mkdir()
            (raw / "classes.dex").write_bytes(build_valid_dex("com.example"))
            result = repair_dex_set(
                sorted(raw.glob("*.dex")),
                Path(tmp) / "fixed",
                package="org.different",
            )
            self.assertTrue(result["files"])
            self.assertFalse(result["files"][0]["complete"])
            self.assertEqual(result["status"], "partial")
            self.assertIn("package_not_found", result["files"][0]["reasons"])

    def test_repair_set_drops_stub_and_shell_unless_included(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw"
            raw.mkdir()
            (raw / "classes.dex").write_bytes(build_valid_dex("com.example"))
            (raw / "loader.dex").write_bytes(loader_dex())
            (raw / "stub.dex").write_bytes(build_dex(class_defs_size=1))

            dropped = repair_dex_set(
                sorted(raw.glob("*.dex")),
                root / "without_stubs",
                include_stub=False,
                package="com.example",
            )
            self.assertEqual(len(dropped["files"]), 1)
            self.assertTrue(dropped["files"][0]["complete"])
            self.assertEqual(dropped["status"], "complete")
            self.assertTrue(dropped["complete"])
            self.assertTrue((root / "without_stubs" / "classes.dex").is_file())
            skip_reasons = {item.get("reason") for item in dropped["skipped"]}
            self.assertIn("stub_like", skip_reasons)
            self.assertIn("shell_loader", skip_reasons)

            kept = repair_dex_set(
                sorted(raw.glob("*.dex")),
                root / "with_stubs",
                include_stub=True,
                package="com.example",
            )
            self.assertEqual(len(kept["files"]), 3)
            self.assertTrue(any(item["stub"] for item in kept["files"]))
            self.assertTrue(any(item["shell_like"] for item in kept["files"]))
            # The recovered target still wins: retained stubs are inspection
            # artifacts, not failures.
            self.assertEqual(kept["status"], "complete")
            self.assertTrue(kept["complete"])
            for item in kept["files"]:
                self.assertTrue(Path(item["path"]).is_file())

    def test_repair_set_shell_only_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw"
            raw.mkdir()
            (raw / "loader.dex").write_bytes(loader_dex())

            dropped = repair_dex_set(sorted(raw.glob("*.dex")), root / "no_stubs", package="com.example")
            self.assertEqual(dropped["files"], [])
            self.assertFalse(dropped["complete"])
            self.assertEqual(dropped["status"], "partial")
            self.assertTrue(any(item.get("reason") == "shell_loader" for item in dropped["skipped"]))

            kept = repair_dex_set(
                sorted(raw.glob("*.dex")),
                root / "with_stubs",
                include_stub=True,
                package="com.example",
            )
            self.assertEqual(len(kept["files"]), 1)
            self.assertTrue(kept["files"][0]["shell_like"])
            self.assertFalse(kept["files"][0]["complete"])
            self.assertFalse(kept["complete"])
            self.assertEqual(kept["status"], "partial")

    def test_repair_set_runtime_dex_without_target_is_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw"
            raw.mkdir()
            (raw / "classes.dex").write_bytes(build_valid_dex("com.example"))
            (raw / "runtime.dex").write_bytes(build_valid_dex("org.runtime", classes=11))

            result = repair_dex_set(sorted(raw.glob("*.dex")), root / "fixed", package="com.example")
            self.assertEqual(len(result["files"]), 2)
            target = [item for item in result["files"] if item["complete"]]
            runtime = [item for item in result["files"] if not item["complete"]]
            self.assertEqual(len(target), 1)
            self.assertEqual(len(runtime), 1)
            self.assertTrue(runtime[0]["content_complete"])
            self.assertIn("package_not_found", runtime[0]["reasons"])
            self.assertTrue(result["files_complete"])
            self.assertTrue(result["target_complete"])
            self.assertTrue(result["complete"])
            self.assertEqual(result["status"], "complete")

    def test_small_target_app_repairs_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw"
            raw.mkdir()
            (raw / "classes.dex").write_bytes(build_valid_dex("com.example", classes=5))
            result = repair_dex_set(sorted(raw.glob("*.dex")), root / "fixed", package="com.example")
            self.assertEqual(len(result["files"]), 1)
            self.assertFalse(result["files"][0]["stub"])
            self.assertTrue(result["files"][0]["complete"])
            self.assertEqual(result["status"], "complete")

    def test_assessment_exported_from_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classes.dex"
            path.write_bytes(build_valid_dex())
            assessment = assess_dex(path, "com.example")
            self.assertTrue(assessment.complete)
            self.assertEqual(assessment.package_classes, 12)


if __name__ == "__main__":
    unittest.main()
