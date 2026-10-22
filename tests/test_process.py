from __future__ import annotations

import re
import unittest
from types import SimpleNamespace

from apk_unpack.domain.errors import AnalysisError
from apk_unpack.providers.process import ProcessInspector


def result(stdout: str = "") -> SimpleNamespace:
    return SimpleNamespace(ok=True, stdout=stdout, stderr="", returncode=0, missing=False, timed_out=False)


def _pid_from_command(command: str) -> int | None:
    match = re.search(r"/proc/(\d+)/", command)
    return int(match.group(1)) if match else None


class FakeAdb:
    """A fake adb whose ``ps``/``pidof``/``cmdline`` output is scripted."""

    def __init__(
        self,
        *,
        ps: str = "",
        pidof: list[int] | None = None,
        cmdlines: dict[int, str] | None = None,
    ) -> None:
        self.ps_output = ps
        self.pidof_value = list(pidof or [])
        self.cmdlines = dict(cmdlines or {})

    def pidof(self, serial: str, package: str) -> list[int]:
        return list(self.pidof_value)

    def shell(self, serial: str, command: str, timeout=None) -> SimpleNamespace:
        if "ps -A" in command:
            return result(self.ps_output)
        if "cmdline" in command:
            pid = _pid_from_command(command)
            return result(self.cmdlines.get(pid, "") if pid is not None else "")
        if "/status" in command:
            return result("")
        return result()


def ps_line(pid: int, name: str, args: str | None = None) -> str:
    return f"{pid}  1  {name}  {args if args is not None else name}\n"


class ExactPackageMatchTests(unittest.TestCase):
    def test_qemu_guest_uses_exact_framework_name_and_kernel_comm(self) -> None:
        wrapper = "/usr/libexec/qemu-binfmt/aarch64-binfmt-P /system/bin/app_process64 -Xzygote"
        adb = FakeAdb(ps=ps_line(42, "aarch64-binfmt", wrapper), cmdlines={42: wrapper})
        original_shell = adb.shell
        def shell(serial, command, timeout=None):
            if command == "dumpsys activity processes":
                return result("*APP* UID 10070 ProcessRecord{ab12 42:com.example.longpackage/u0a70}")
            return original_shell(serial, command, timeout)
        adb.shell = shell
        inspector = ProcessInspector(adb)
        inspector.status = lambda *a: {"name": "com.example.longpackage"[-15:]}
        selection = inspector.find_pid_candidates("serial", "com.example.longpackage")
        self.assertEqual(selection["main_pid"], 42)
        self.assertEqual(selection["candidates"][0]["identity_source"], "activity_manager_qemu")
        identity = inspector.validate_pid("serial", 42, "com.example.longpackage")
        self.assertTrue(identity["valid"])
        self.assertEqual(identity["identity_source"], "activity_manager_qemu")

    def test_qemu_framework_prefix_or_stale_kernel_name_is_rejected(self) -> None:
        wrapper = "/usr/libexec/qemu-binfmt/aarch64-binfmt-P /system/bin/app_process64"
        adb = FakeAdb(ps=ps_line(42, "aarch64-binfmt", wrapper), cmdlines={42: wrapper})
        original_shell = adb.shell
        def shell(serial, command, timeout=None):
            if command == "dumpsys activity processes":
                return result("ProcessRecord{ab12 42:com.example.other/u0a70}")
            return original_shell(serial, command, timeout)
        adb.shell = shell
        inspector = ProcessInspector(adb)
        inspector.status = lambda *a: {"name": "com.example.other"[-15:]}
        self.assertFalse(inspector.validate_pid("serial", 42, "com.example")["valid"])
        self.assertIsNone(inspector.find_pid_candidates("serial", "com.example")["main_pid"])
        inspector.status = lambda *a: {"name": "another-process"}
        self.assertFalse(inspector.validate_pid("serial", 42, "com.example.other")["valid"])
        self.assertIsNone(inspector.find_pid_candidates("serial", "com.example.other")["main_pid"])

    def test_framework_identity_does_not_override_a_native_process(self) -> None:
        adb = FakeAdb(ps=ps_line(42, "other", "other --target com.example"),
                      cmdlines={42: "other --target com.example"})
        inspector = ProcessInspector(adb)
        inspector.status = lambda *a: {"name": "com.example"}
        inspector._framework_process_names = lambda *a: {42: "com.example"}
        self.assertFalse(inspector.validate_pid("serial", 42, "com.example")["valid"])
        self.assertIsNone(inspector.find_pid_candidates("serial", "com.example")["main_pid"])

    def test_exact_name_matches_only_the_main_process(self) -> None:
        ps = (
            ps_line(1234, "com.example")
            + ps_line(2000, "com.example.other")
            + ps_line(3000, "com.example.extra")
        )
        inspector = ProcessInspector(FakeAdb(ps=ps))  # type: ignore[arg-type]

        selection = inspector.find_pid_candidates("serial", "com.example")

        self.assertEqual(selection["main_pid"], 1234)
        self.assertEqual([item["pid"] for item in selection["candidates"]], [1234])
        self.assertEqual(inspector.find_pid("serial", "com.example"), 1234)

    def test_prefix_collision_is_not_matched(self) -> None:
        # A different package that merely contains the target as a prefix.
        ps = ps_line(2000, "com.example.other") + ps_line(3000, "com.examplex")
        inspector = ProcessInspector(FakeAdb(ps=ps))  # type: ignore[arg-type]

        selection = inspector.find_pid_candidates("serial", "com.example")

        self.assertIsNone(selection["main_pid"])
        self.assertEqual(selection["candidates"], [])
        with self.assertRaises(AnalysisError) as raised:
            inspector.find_pid("serial", "com.example")
        self.assertEqual(raised.exception.code, "process_not_running")

    def test_package_elsewhere_in_args_is_not_matched(self) -> None:
        # The old bare-substring check accepted any occurrence in args; only
        # the cmdline's first token identifies an Android app process.
        ps = ps_line(2000, "some.wrapper", "some.wrapper --target com.example")
        inspector = ProcessInspector(FakeAdb(ps=ps))  # type: ignore[arg-type]

        self.assertIsNone(inspector.find_pid_candidates("serial", "com.example")["main_pid"])

    def test_truncated_name_uses_cmdline_first_token(self) -> None:
        ps = ps_line(1234, "com.example.hid", "com.example.hidden")
        inspector = ProcessInspector(FakeAdb(ps=ps))  # type: ignore[arg-type]

        selection = inspector.find_pid_candidates("serial", "com.example.hidden")

        self.assertEqual(selection["main_pid"], 1234)
        self.assertEqual(selection["candidates"][0]["role"], "main")


class SubprocessMatchTests(unittest.TestCase):
    def test_remote_subprocess_is_matched_and_main_is_preferred(self) -> None:
        ps = ps_line(2000, "com.example:remote") + ps_line(1234, "com.example")
        inspector = ProcessInspector(FakeAdb(ps=ps))  # type: ignore[arg-type]

        selection = inspector.find_pid_candidates("serial", "com.example")

        self.assertEqual(selection["main_pid"], 1234)
        roles = {item["pid"]: item["role"] for item in selection["candidates"]}
        self.assertEqual(roles, {1234: "main", 2000: "subprocess"})
        self.assertEqual(inspector.find_pid("serial", "com.example"), 1234)

    def test_remote_subprocess_matched_via_truncated_name(self) -> None:
        # Android comm truncates at 15 chars, so the name may only retain
        # ``com.example:r``; the ``package:`` prefix still identifies it.
        ps = ps_line(2000, "com.example:r", "com.example:remote")
        inspector = ProcessInspector(FakeAdb(ps=ps))  # type: ignore[arg-type]

        selection = inspector.find_pid_candidates("serial", "com.example")

        self.assertEqual(selection["main_pid"], 2000)
        self.assertEqual(selection["candidates"][0]["role"], "subprocess")

    def test_pidof_entry_with_mismatched_cmdline_is_rejected(self) -> None:
        adb = FakeAdb(pidof=[5555], cmdlines={5555: "com.example.other"})
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]

        selection = inspector.find_pid_candidates("serial", "com.example")

        self.assertIsNone(selection["main_pid"])
        self.assertEqual(selection["candidates"], [])


class ValidateExplicitPidTests(unittest.TestCase):
    def setUp(self) -> None:
        adb = FakeAdb(
            cmdlines={
                1111: "com.example",
                2222: "com.example:remote",
                3333: "com.example.other",
                4444: "sh -c com.example",
            }
        )
        self.inspector = ProcessInspector(adb)  # type: ignore[arg-type]

    def test_main_pid_is_valid(self) -> None:
        validation = self.inspector.validate_pid("serial", 1111, "com.example")
        self.assertTrue(validation["valid"])
        self.assertTrue(validation["is_main"])

    def test_subprocess_pid_is_valid(self) -> None:
        validation = self.inspector.validate_pid("serial", 2222, "com.example")
        self.assertTrue(validation["valid"])
        self.assertFalse(validation["is_main"])

    def test_prefix_collision_pid_is_rejected(self) -> None:
        validation = self.inspector.validate_pid("serial", 3333, "com.example")
        self.assertFalse(validation["valid"])

    def test_package_elsewhere_in_cmdline_is_rejected(self) -> None:
        validation = self.inspector.validate_pid("serial", 4444, "com.example")
        self.assertFalse(validation["valid"])


if __name__ == "__main__":
    unittest.main()
