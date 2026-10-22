from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from apk_unpack.application.dex_validation import (
    SHELL_CLASS_PREFIXES,
    assess_dex,
    is_usable_dex,
    parse_dex_header,
)
from apk_unpack.providers.dex import repair_dex, repair_dex_set, verify_dex

from tests.fixtures import _build_dex_blob, build_dex, build_valid_dex, resign_dex


def descriptor_dex(descriptors: list[bytes]) -> bytes:
    """Build a valid DEX with exactly the supplied class descriptors."""

    return _build_dex_blob(descriptors, set(range(len(descriptors))))


def shell_dex(prefix: str = "Lcom/Proxy/", classes: int = 12) -> bytes:
    descriptors = [f"{prefix}Class{index:02d};".encode() for index in range(classes)]
    return descriptor_dex(descriptors)


class DexAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_valid_dex_is_complete(self) -> None:
        path = self.write("classes.dex", build_valid_dex())
        assessment = assess_dex(path)
        self.assertTrue(assessment.complete)
        self.assertFalse(assessment.truncated)
        self.assertTrue(assessment.size_ok)
        self.assertTrue(assessment.checksum_ok)
        self.assertTrue(assessment.signature_ok)
        self.assertTrue(assessment.adler_ok)
        self.assertEqual(assessment.class_defs, 12)
        self.assertEqual(assessment.classes_with_code, 12)
        self.assertEqual(assessment.code_items, 12)
        self.assertEqual(assessment.type_ids, 12)
        self.assertEqual(assessment.string_ids, 12)
        self.assertEqual(assessment.holes, 0)
        self.assertFalse(assessment.stub_like)
        self.assertEqual(assessment.reasons, [])
        self.assertTrue(is_usable_dex(path))

    def test_valid_dex_with_matching_package(self) -> None:
        path = self.write("classes.dex", build_valid_dex("com.example.demo"))
        assessment = assess_dex(path, "com.example.demo")
        self.assertTrue(assessment.complete)
        self.assertEqual(assessment.package_classes, 12)
        self.assertTrue(is_usable_dex(path, "com.example.demo"))

    def test_stub_only_dex_is_not_complete(self) -> None:
        path = self.write("stub.dex", build_dex(class_defs_size=4))
        assessment = assess_dex(path)
        self.assertFalse(assessment.complete)
        self.assertTrue(assessment.stub_like)
        self.assertLess(assessment.class_defs, 10)
        self.assertIn("stub_like", assessment.reasons)
        # Header/digests are valid, so this is a content verdict, not corruption.
        self.assertTrue(assessment.checksum_ok)
        self.assertTrue(assessment.signature_ok)

    def test_no_code_dex_is_not_complete(self) -> None:
        path = self.write("nocode.dex", build_valid_dex(classes_with_code=0))
        assessment = assess_dex(path)
        self.assertFalse(assessment.complete)
        self.assertTrue(assessment.stub_like)
        self.assertEqual(assessment.classes_with_code, 0)
        self.assertIn("no_classes_with_code", assessment.reasons)

    def test_wrong_package_is_not_complete(self) -> None:
        path = self.write("classes.dex", build_valid_dex("com.example"))
        assessment = assess_dex(path, "com.other.app")
        self.assertFalse(assessment.complete)
        self.assertEqual(assessment.package_classes, 0)
        self.assertIn("package_not_found", assessment.reasons)
        self.assertFalse(is_usable_dex(path, "com.other.app"))
        # Without a package requirement the same content is complete.
        self.assertTrue(assess_dex(path).complete)

    def test_package_specified_with_zero_package_classes(self) -> None:
        path = self.write("classes.dex", build_valid_dex("com.example"))
        report = verify_dex(path, "com.example.missing")
        self.assertEqual(report["package_classes"], 0)
        self.assertFalse(report["complete"])
        self.assertNotEqual(report["status"], "complete")
        self.assertIn("package_not_found", report["reasons"])

    def test_truncation_2_5_10_bytes_with_allow_truncated(self) -> None:
        original = build_valid_dex()
        for drop in (2, 5, 10):
            with self.subTest(drop=drop):
                source = self.write(f"short{drop}.dex", original[:-drop])
                assessment = assess_dex(source, "com.example")
                self.assertFalse(assessment.complete)
                self.assertTrue(assessment.truncated)
                self.assertEqual(assessment.declared_size, len(original))
                self.assertEqual(assessment.actual_size, len(original) - drop)
                self.assertIn("truncated", assessment.reasons)
                self.assertFalse(is_usable_dex(source, "com.example"))

                output = self.root / f"fixed{drop}.dex"
                report = repair_dex(
                    source,
                    output,
                    allow_truncated=True,
                    expected_package="com.example",
                )
                self.assertTrue(output.is_file())
                self.assertFalse(report["complete"])
                self.assertTrue(report["truncated"])
                self.assertEqual(report["status"], "truncated")
                self.assertIn("truncated", report["reasons"])
                self.assertFalse(report["assessment"]["complete"])
                self.assertTrue(report["assessment"]["truncated"])
                # The repaired file is still refused on a subsequent verify.
                self.assertFalse(verify_dex(output, "com.example")["complete"])

    def test_truncation_without_allow_writes_nothing(self) -> None:
        source = self.write("short.dex", build_valid_dex()[:-4])
        output = self.root / "fixed.dex"
        report = repair_dex(source, output)
        self.assertEqual(report["status"], "truncated")
        self.assertFalse(report["complete"])
        self.assertIsNone(report["output_path"])
        self.assertFalse(output.exists())

    def test_extreme_truncation_before_header_is_clean(self) -> None:
        original = build_valid_dex()
        source = self.write("tiny.dex", original[:50])
        assessment = assess_dex(source)
        self.assertFalse(assessment.complete)
        self.assertFalse(assessment.header_ok)
        self.assertEqual(assessment.actual_size, 50)
        self.assertIn("invalid_header", assessment.reasons)

        output = self.root / "tiny_fixed.dex"
        report = repair_dex(source, output, allow_truncated=True)
        self.assertFalse(report["complete"])
        self.assertTrue(report["truncated"])
        self.assertEqual(report["status"], "truncated")
        self.assertIsNone(report["output_path"])
        self.assertFalse(output.exists())

    def test_truncation_before_data_off_is_clean(self) -> None:
        original = build_valid_dex(padding=4096)
        header = parse_dex_header(original)
        assert header is not None
        source = self.write("predata.dex", original[: header.data_off - 10])
        assessment = assess_dex(source, "com.example")
        self.assertTrue(assessment.header_ok)
        self.assertTrue(assessment.truncated)
        self.assertFalse(assessment.complete)

        output = self.root / "predata_fixed.dex"
        report = repair_dex(source, output, allow_truncated=True, expected_package="com.example")
        # Must not raise KeyError/IndexError; the result stays incomplete.
        self.assertFalse(report["complete"])
        self.assertTrue(report["truncated"])
        self.assertIn("truncated", report["reasons"])
        if report["output_path"]:
            self.assertFalse(verify_dex(output, "com.example")["complete"])

    def test_repair_set_survives_extreme_truncation(self) -> None:
        raw = self.root / "raw"
        raw.mkdir()
        (raw / "tiny.dex").write_bytes(b"dex\n035\x00")
        (raw / "valid.dex").write_bytes(build_valid_dex())
        result = repair_dex_set(sorted(raw.glob("*.dex")), self.root / "fixed", allow_truncated=True)
        self.assertTrue(result["files"])
        self.assertTrue(result["skipped"])
        self.assertEqual(result["status"], "complete")
        self.assertTrue(all(item["complete"] for item in result["files"]))

    def test_middle_zero_hole_is_not_complete(self) -> None:
        original = build_valid_dex(padding=16384)
        header = parse_dex_header(original)
        assert header is not None
        mutated = bytearray(original)
        hole_start = header.data_off + 6000
        mutated[hole_start : hole_start + 4096] = b"\x00" * 4096
        path = self.write("hole.dex", resign_dex(bytes(mutated)))

        assessment = assess_dex(path, "com.example")
        self.assertFalse(assessment.complete)
        self.assertGreaterEqual(assessment.holes, 1)
        self.assertTrue(any(reason.startswith("zero_holes=") for reason in assessment.reasons))
        self.assertEqual(assessment.classes_with_code, 12)
        report = verify_dex(path, "com.example")
        self.assertFalse(report["complete"])
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["checks"]["holes"])

    def test_trailing_junk_is_detected(self) -> None:
        path = self.write("trailing.dex", build_valid_dex() + b"JUNK")
        assessment = assess_dex(path)
        self.assertFalse(assessment.complete)
        self.assertFalse(assessment.truncated)
        self.assertEqual(assessment.trailing_bytes, 4)
        self.assertTrue(any(reason.startswith("trailing_bytes=") for reason in assessment.reasons))

    def test_repaired_valid_dex_stays_complete(self) -> None:
        source = self.write("corrupt.dex", build_valid_dex(corrupt=True))
        self.assertFalse(assess_dex(source, "com.example").complete)
        output = self.root / "fixed.dex"
        report = repair_dex(source, output, expected_package="com.example")
        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["complete"])
        self.assertEqual(report["reasons"], [])
        self.assertTrue(report["checksum_valid"])
        self.assertTrue(report["signature_valid"])
        assessment = assess_dex(output, "com.example")
        self.assertTrue(assessment.complete)
        self.assertTrue(verify_dex(output, "com.example")["complete"])

    def test_repaired_stub_never_complete(self) -> None:
        source = self.write("stub.dex", build_dex(class_defs_size=3, corrupt=True))
        output = self.root / "stub_fixed.dex"
        # The package does not match, so this is not a small targeted app and
        # keeps the stub signal.
        report = repair_dex(source, output, expected_package="com.other")
        self.assertTrue(output.is_file())
        self.assertFalse(report["complete"])
        self.assertNotEqual(report["status"], "complete")
        self.assertTrue(report["assessment"]["stub_like"])
        self.assertFalse(verify_dex(output, "com.other")["complete"])

    def test_wrong_package_repair_never_complete(self) -> None:
        source = self.write("classes.dex", build_valid_dex("com.example"))
        output = self.root / "wrong_pkg_fixed.dex"
        report = repair_dex(source, output, expected_package="org.other")
        self.assertFalse(report["complete"])
        self.assertNotEqual(report["status"], "complete")
        self.assertEqual(report["assessment"]["package_classes"], 0)
        self.assertIn("package_not_found", report["reasons"])

    def test_malformed_headers_do_not_raise(self) -> None:
        samples = {
            "empty.dex": b"",
            "garbage.dex": b"not a dex" * 40,
            "cdex.dex": b"cdex001\x00" + b"\x00" * 200,
            "short_header.dex": build_valid_dex()[:0x6F],
        }
        for name, payload in samples.items():
            with self.subTest(name=name):
                path = self.write(name, payload)
                assessment = assess_dex(path, "com.example")
                self.assertFalse(assessment.complete)
                self.assertFalse(is_usable_dex(path, "com.example"))
                report = verify_dex(path, "com.example")
                self.assertEqual(report["status"], "invalid")
                self.assertFalse(report["complete"])

    def test_impossible_table_ranges_rejected(self) -> None:
        blob = bytearray(build_valid_dex())
        struct.pack_into("<I", blob, 0x60, 1_000_000)  # class_defs_size
        self.assertIsNone(parse_dex_header(bytes(blob)))
        path = self.write("huge.dex", bytes(blob))
        self.assertFalse(assess_dex(path).complete)

    # ---------------------------------------------------------------- shell veto
    def test_shell_only_dex_is_not_complete(self) -> None:
        path = self.write("shell.dex", shell_dex())
        assessment = assess_dex(path)
        self.assertTrue(assessment.shell_like)
        self.assertEqual(assessment.shell_classes, 12)
        self.assertEqual(assessment.named_classes, 12)
        self.assertFalse(assessment.complete)
        self.assertFalse(assessment.content_complete)
        self.assertFalse(assessment.repairable_complete)
        self.assertIn("shell_loader", assessment.reasons)
        self.assertFalse(is_usable_dex(path))

        report = verify_dex(path)
        self.assertFalse(report["complete"])
        self.assertNotEqual(report["status"], "complete")
        self.assertTrue(report["shell_like"])
        self.assertFalse(report["checks"]["not_shell_loader"])
        self.assertIn("shell_loader", report["reasons"])

        output = self.root / "shell_fixed.dex"
        repaired = repair_dex(path, output)
        self.assertTrue(output.is_file())
        self.assertFalse(repaired["complete"])
        self.assertNotEqual(repaired["status"], "complete")
        self.assertTrue(repaired["assessment"]["shell_like"])
        self.assertIn("shell_loader", repaired["reasons"])
        self.assertFalse(verify_dex(output)["complete"])

    def test_known_loader_prefixes_are_detected(self) -> None:
        for prefix in SHELL_CLASS_PREFIXES:
            with self.subTest(prefix=prefix):
                path = self.write("loader.dex", shell_dex(prefix=prefix, classes=12))
                assessment = assess_dex(path)
                self.assertEqual(assessment.shell_classes, 12)
                self.assertTrue(assessment.shell_like)
                self.assertIn("shell_loader", assessment.reasons)

    def test_loader_dominant_dex_with_target_classes_is_vetoed(self) -> None:
        descriptors = [b"Lcom/Proxy/Loader%02d;" % index for index in range(10)]
        descriptors += [b"Lcom/example/Real%02d;" % index for index in range(2)]
        path = self.write("proxy.dex", descriptor_dex(descriptors))
        assessment = assess_dex(path, "com.example")
        self.assertEqual(assessment.package_classes, 2)
        self.assertEqual(assessment.shell_classes, 10)
        self.assertTrue(assessment.shell_like)
        self.assertFalse(assessment.complete)
        self.assertFalse(assessment.content_complete)
        self.assertFalse(assessment.repairable_complete)
        self.assertIn("shell_loader", assessment.reasons)
        self.assertFalse(verify_dex(path, "com.example")["complete"])

    def test_few_sdk_classes_do_not_flag_normal_app(self) -> None:
        descriptors = [b"Lcom/example/App%02d;" % index for index in range(10)]
        descriptors += [b"Lcom/Proxy/Sdk%02d;" % index for index in range(2)]
        path = self.write("app.dex", descriptor_dex(descriptors))
        assessment = assess_dex(path, "com.example")
        self.assertEqual(assessment.shell_classes, 2)
        self.assertEqual(assessment.named_classes, 12)
        self.assertFalse(assessment.shell_like)
        self.assertNotIn("shell_loader", assessment.reasons)
        self.assertTrue(assessment.complete)

    # ------------------------------------------------------------- small target apps
    def test_small_target_app_is_not_stub(self) -> None:
        path = self.write("small.dex", build_valid_dex("com.example", classes=5))
        assessment = assess_dex(path, "com.example")
        self.assertEqual(assessment.class_defs, 5)
        self.assertEqual(assessment.package_classes, 5)
        self.assertLess(assessment.class_defs, 10)
        self.assertFalse(assessment.stub_like)
        self.assertNotIn("stub_like", assessment.reasons)
        self.assertTrue(assessment.repairable_complete)
        self.assertTrue(assessment.content_complete)
        self.assertTrue(assessment.complete)
        self.assertTrue(is_usable_dex(path, "com.example"))

        report = verify_dex(path, "com.example")
        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["complete"])

        output = self.root / "small_fixed.dex"
        repaired = repair_dex(path, output, expected_package="com.example")
        self.assertEqual(repaired["status"], "complete")
        self.assertTrue(repaired["complete"])

    def test_small_target_app_without_package_is_still_stub(self) -> None:
        path = self.write("small_no_pkg.dex", build_valid_dex("com.example", classes=5))
        assessment = assess_dex(path)
        self.assertTrue(assessment.stub_like)
        self.assertFalse(assessment.complete)

    def test_single_class_target_dex_remains_stub(self) -> None:
        # One class is the classic loader shape; keep the stub signal even when
        # it happens to carry the target package name.
        path = self.write("one.dex", build_dex(class_defs_size=1))
        assessment = assess_dex(path, "com.example")
        self.assertEqual(assessment.package_classes, 1)
        self.assertTrue(assessment.stub_like)
        self.assertFalse(assessment.complete)
        self.assertFalse(is_usable_dex(path, "com.example"))


if __name__ == "__main__":
    unittest.main()
