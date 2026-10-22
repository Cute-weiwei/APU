from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from apk_unpack.providers.apk import ApkInspector
from apk_unpack.providers.axml import extract_manifest
from apk_unpack.providers.host import HostRunner

from tests.fixtures import build_apk, build_dex, build_manifest, shell_apk


class ApkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inspector = ApkInspector(HostRunner(), aapt=None)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_shell_matrix(self) -> None:
        cases = {
            "ijiami": "ijiami",
            "bangcle": "bangcle",
            "360": "360",
            "tencent": "tencent",
            "unknown": "unknown",
        }
        for index, (shell, expected) in enumerate(cases.items()):
            apk = shell_apk(self.root / f"{index}_{shell}.apk", shell)
            inspection = self.inspector.inspect(apk)
            self.assertEqual(inspection["packing"]["primary"], expected, shell)

    def test_bangcle_precedence_over_ijiami(self) -> None:
        apk = shell_apk(self.root / "mixed.apk", "bangcle_ijiami")
        inspection = self.inspector.inspect(apk)
        packing = inspection["packing"]
        self.assertEqual(packing["primary"], "bangcle")
        self.assertTrue(packing["mixed"])
        self.assertTrue(any("libDexHelper" in note for note in packing["precedence_notes"]))

    def test_360_secneo_layers(self) -> None:
        apk = shell_apk(self.root / "double.apk", "360_secneo")
        inspection = self.inspector.inspect(apk)
        self.assertEqual(inspection["packing"]["primary"], "360")
        layers = {item["shell"] for item in inspection["packing"]["layers"]}
        self.assertEqual(layers, {"360", "secneo"})
        self.assertTrue(inspection["packing"]["mixed"])

    def test_manifest_axml_extraction(self) -> None:
        manifest = build_manifest(
            "com.example",
            activity="com.example.Main",
            app_class="com.example.App",
            component_factory="s.h.e.l.l.A",
        )
        parsed = extract_manifest(manifest)
        self.assertEqual(parsed["package"], "com.example")
        self.assertEqual(parsed["launchable_activity"], "com.example.Main")
        self.assertEqual(parsed["application_class"], "com.example.App")
        self.assertEqual(parsed["app_component_factory"], "s.h.e.l.l.A")
        self.assertEqual(parsed["min_sdk"], 21)

    def test_inspect_uses_manifest_shell_signal(self) -> None:
        manifest = build_manifest("com.example", component_factory="s.h.e.l.l.A")
        apk = build_apk(self.root / "manifest.apk", {"classes.dex": build_dex()}, manifest=manifest)
        inspection = self.inspector.inspect(apk)
        self.assertEqual(inspection["package"]["name"], "com.example")
        self.assertEqual(inspection["package"]["launchable_activity"], "com.example.Main")
        self.assertEqual(inspection["packing"]["primary"], "ijiami")
        self.assertTrue(any(match["kind"] == "manifest" for match in inspection["shells"]))

    def test_dex_string_shell_signal(self) -> None:
        dex_with_marker = build_dex(descriptor=b"s.h.e.l.l.S")
        apk = build_apk(self.root / "string.apk", {"classes.dex": dex_with_marker})
        inspection = self.inspector.inspect(apk)
        self.assertEqual(inspection["packing"]["primary"], "ijiami")
        self.assertTrue(any(match["kind"] == "dex-string" for match in inspection["shells"]))

    def test_packed_detection(self) -> None:
        apk = shell_apk(self.root / "packed.apk", "ijiami")
        inspection = self.inspector.inspect(apk)
        self.assertTrue(inspection["packing"]["packed"])
        self.assertTrue(inspection["dex_entries"][0]["packed_stub"])

    def test_uni_app_framework_and_wgt_extraction(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as nested:
            nested.writestr("app-service.js", "console.log('hello')")
        apk = build_apk(
            self.root / "uni.apk",
            {
                "classes.dex": build_dex(),
                "assets/__UNI__ABC.wgt": buffer.getvalue(),
            },
        )
        inspection = self.inspector.inspect(apk)
        self.assertIn("uni-app", {item["name"] for item in inspection["frameworks"]})
        self.assertEqual(inspection["wgt_entries"], ["assets/__UNI__ABC.wgt"])
        extraction = self.inspector.extract_assets(apk, self.root / "assets_out")
        self.assertEqual(len(extraction["files"]), 1)
        self.assertTrue(Path(extraction["files"][0]["extracted_dir"]).is_dir())
        self.assertTrue((Path(extraction["files"][0]["extracted_dir"]) / "app-service.js").is_file())

    def test_path_traversal_is_rejected(self) -> None:
        apk = build_apk(
            self.root / "traversal.apk",
            {
                "classes.dex": build_dex(),
                "../evil.txt": b"evil",
            },
        )
        extraction = self.inspector.extract_assets(
            apk, self.root / "safe_out", patterns=["*"], include_wgt=False
        )
        self.assertFalse((self.root / "evil.txt").exists())
        self.assertTrue(any("traversal" in item["reason"] for item in extraction["skipped"]))


if __name__ == "__main__":
    unittest.main()
