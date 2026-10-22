from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from apk_unpack.application.workflow import ToolService, _abis_compatible
from apk_unpack.config import Config
from apk_unpack.domain.workspace import RunWorkspace

from tests.fixtures import build_apk, build_dex, build_manifest


class InstallSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config.load(runs_dir=self.root / "runs")
        self.config.memory_dir = self.root / "memory"
        self.service = ToolService(self.config)
        self.run = RunWorkspace.create(self.root / "runs")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_base_plus_same_package_splits(self) -> None:
        base = build_apk(
            self.root / "base.apk",
            {"classes.dex": build_dex()},
            manifest=build_manifest("com.example"),
        )
        split = build_apk(
            self.root / "split_config.arm64_v8a.apk",
            {},
            manifest=build_manifest("com.example"),
        )
        build_apk(
            self.root / "split_config.x86.apk",
            {},
            manifest=build_manifest("com.other"),
        )
        build_apk(
            self.root / "unrelated.apk",
            {},
            manifest=build_manifest("com.other"),
        )
        paths = self.service._install_set(base, self.run)
        names = {path.name for path in paths}
        self.assertEqual(names, {"base.apk", "split_config.arm64_v8a.apk"})

    def test_apks_bundle_extracts_apk_members(self) -> None:
        base_bytes = build_apk(
            self.root / "bundle_base.apk",
            {"classes.dex": build_dex()},
            manifest=build_manifest("com.example"),
        ).read_bytes()
        split_bytes = build_apk(
            self.root / "bundle_split.apk",
            {},
            manifest=build_manifest("com.example"),
        ).read_bytes()
        bundle = self.root / "app.apks"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("splits/base-master.apk", base_bytes)
            archive.writestr("splits/base-arm64_v8a.apk", split_bytes)
        paths = self.service._install_set(bundle, self.run)
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(path.is_file() for path in paths))

    def test_abi_compatibility(self) -> None:
        self.assertTrue(_abis_compatible(["arm64-v8a"], ["x86_64", "arm64-v8a"]))
        self.assertTrue(_abis_compatible(["armeabi-v7a"], ["arm"]))
        self.assertFalse(_abis_compatible(["arm64-v8a"], ["x86_64"]))
        self.assertTrue(_abis_compatible([], ["x86_64"]))


if __name__ == "__main__":
    unittest.main()
