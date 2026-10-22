from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from apk_unpack.providers.adb import AdbProvider
from apk_unpack.providers.host import CommandResult
from apk_unpack.domain.errors import AnalysisError


class FakeAdb(AdbProvider):
    def __init__(self, output: str):
        self.output = output

    def shell(self, serial: str, command: str, timeout=None):  # type: ignore[override]
        return SimpleNamespace(ok=True, stdout=self.output, stderr="", returncode=0)


class ForwardListAdb(AdbProvider):
    def __init__(self, output: str):
        self.output = output

    def forward_list(self):
        return SimpleNamespace(ok=True, stdout=self.output, stderr="", returncode=0)


class ComponentTests(unittest.TestCase):
    def test_root_reconnects_only_selected_tcp_transport(self) -> None:
        provider = AdbProvider(None, None)
        identities = iter([CommandResult([], 0, stdout="uid=2000(shell)"),
                           CommandResult([], 1, stderr="device offline"),
                           CommandResult([], 0, stdout="uid=0(root)")])
        provider.shell = lambda *a, **kw: next(identities)
        calls = []
        provider.run = lambda args, **kw: calls.append((args, kw)) or CommandResult(
            [], 0, stdout="restarting adbd as root")
        with patch("apk_unpack.providers.adb.time.sleep"):
            self.assertEqual(provider.ensure_root("127.0.0.1:5599")["uid"], 0)
        self.assertEqual([a for a, _ in calls].count(["root"]), 1)
        self.assertEqual([a for a, _ in calls].count(["connect", "127.0.0.1:5599"]), 2)
        self.assertFalse(any(a[0] in {"disconnect", "kill-server"} for a, _ in calls))

    def test_root_restart_offline_is_not_reported_as_missing_root(self) -> None:
        provider = AdbProvider(None, None)
        identities = iter([CommandResult([], 0, stdout="uid=2000(shell)")])
        provider.shell = lambda *a, **kw: next(identities, CommandResult([], 1, stderr="offline"))
        provider.run = lambda *a, **kw: CommandResult([], 0, stdout="restarting adbd as root")
        with patch("apk_unpack.providers.adb.time.sleep"), self.assertRaises(AnalysisError) as caught:
            provider.ensure_root("127.0.0.1:5599")
        self.assertEqual(caught.exception.code, "device_unavailable")

    def test_root_rejection_does_not_retry_production_build(self) -> None:
        provider = AdbProvider(None, None)
        provider.shell = lambda *a, **kw: CommandResult([], 0, stdout="uid=2000(shell)")
        calls = []
        provider.run = lambda args, **kw: calls.append(args) or CommandResult(
            [], 0, stdout="adbd cannot run as root in production builds")
        with self.assertRaises(AnalysisError) as caught:
            provider.ensure_root("usb-serial")
        self.assertEqual(caught.exception.code, "root_required")
        self.assertEqual(calls, [["root"]])

    def test_restart_removed_forward_cleanup_is_idempotent(self) -> None:
        provider = AdbProvider(None, None)
        provider.run = lambda *args, **kwargs: CommandResult([], 1, stderr="listener 'tcp:27042' not found")
        provider.forward_list = lambda: CommandResult([], 0, stdout="serial-b tcp:27043 tcp:27042\n")
        self.assertTrue(provider.remove_forward("serial-a", 27042).ok)
        provider.forward_list = lambda: CommandResult([], 0, stdout="serial-b tcp:27042 tcp:27042\n")
        self.assertFalse(provider.remove_forward("serial-a", 27042).ok)
        provider.forward_list = lambda: CommandResult([], 1)
        self.assertFalse(provider.remove_forward("serial-a", 27042).ok)

    def test_component_forms(self) -> None:
        self.assertEqual(
            AdbProvider._component("com.cube.messager", "com.cube.messager.launch.LaunchDistributeActivity"),
            "com.cube.messager/com.cube.messager.launch.LaunchDistributeActivity",
        )
        self.assertEqual(
            AdbProvider._component("com.example", ".MainActivity"),
            "com.example/.MainActivity",
        )
        self.assertEqual(
            AdbProvider._component("com.example", "com.example/.MainActivity"),
            "com.example/.MainActivity",
        )
        self.assertIsNone(AdbProvider._component("com.example", None))

    def test_package_dirs_are_scoped_to_the_package(self) -> None:
        fake = FakeAdb(
            "package:/data/app/com.cube.messager-Yx7OHsNp9FyDUNjDSUbCmQ==/base.apk\n"
        )
        dirs = fake.package_dirs("serial", "com.cube.messager")
        self.assertIn("/data/app/com.cube.messager-Yx7OHsNp9FyDUNjDSUbCmQ==", dirs)
        self.assertIn("/data/user/0/com.cube.messager", dirs)
        self.assertFalse(any(dir == "/data/app" for dir in dirs))

    def test_forward_list_is_scoped_to_device_and_port(self) -> None:
        ads = ForwardListAdb(
            "serial-a tcp:27042 tcp:27042\n"
            "serial-b tcp:27043 tcp:27042\n"
            "serial-a tcp:27044 tcp:27042\n"
        )
        entries = ads.parse_forward_list(ads.output)
        self.assertEqual(len(entries), 3)
        self.assertTrue(ads.has_forward("serial-a", 27042, 27042))
        self.assertFalse(ads.has_forward("serial-a", 27043, 27042))  # other device's port
        self.assertFalse(ads.has_forward("serial-b", 27042, 27042))
        self.assertTrue(ads.has_forward("serial-a", 27044))

    def test_parse_forward_list_ignores_malformed_rows(self) -> None:
        entries = AdbProvider.parse_forward_list(
            "not-a-list-header\nserial tcp:abc tcp:27042\nserial tcp:27042 tcp:27042\n"
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["local_port"], 27042)


if __name__ == "__main__":
    unittest.main()
