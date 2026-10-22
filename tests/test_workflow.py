from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from apk_unpack.application.workflow import ToolService
from apk_unpack.config import Config
from apk_unpack.domain.errors import AnalysisError
from apk_unpack.domain.workspace import RunWorkspace

from tests.fixtures import build_apk, build_dex, build_valid_dex


def result(stdout: str = "", ok: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        ok=ok, stdout=stdout, stderr="", returncode=0 if ok else 1, missing=False, timed_out=False
    )


def inspection(packed: bool = True) -> dict:
    return {
        "identity": {"path": "x.apk", "sha256": "a" * 64, "size": 1},
        "package": {"name": "com.example", "launchable_activity": None},
        "abis": ["x86_64"],
        "frameworks": [],
        "packing": {
            "primary": "unknown",
            "layers": [],
            "packed": packed,
        },
        "limitations": [],
    }


class SerialAdb:
    def resolve_serial(self, serial):
        return serial or "fake"


def elf_bytes(machine: int) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little endian
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


class WorkflowBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config.load(runs_dir=self.root / "runs")
        self.config.memory_dir = self.root / "memory"
        self.config.frida_server = None
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

    def candidate(self, path: Path, source: str = "frida-cookie", **extra) -> dict:
        candidate = {
            "label": path.stem,
            "source": source,
            "local_path": str(path),
            "device_path": f"/data/local/tmp/{path.name}",
            "notes": [],
        }
        candidate.update(extra)
        return candidate


class StaticJadxRouteTests(WorkflowBase):
    def test_unpack_passes_explicit_jadx_timeout_to_static_route(self):
        apk = build_apk(self.root / 'unpacked.apk', {'classes.dex':build_valid_dex('com.example')})
        _, decompile = self._unpack_static(apk, run_jadx=True, jadx_timeout_s=5400)
        self.assertEqual(decompile.call_args.kwargs['timeout_s'], 5400)

    def _unpack_static(self, apk, **kwargs):
        with mock.patch.object(
            self.service,
            "inspect_apk",
            return_value={"run_id": self.run.run_id, "inspection": inspection(packed=False)},
        ), mock.patch.object(
            self.service,
            "recommend_unpack_strategy",
            return_value={"strategy": {"primary": "static_jadx", "fallbacks": []}},
        ), mock.patch.object(
            self.service,
            "decompile_android_apk",
            return_value={"decompilation": {"ok": True, "output_dir": str(self.run.jadx_dir)}},
        ) as decompile:
            result = self.service.unpack(str(apk), run_id=self.run.run_id, **kwargs)
        return result, decompile

    def test_static_route_extracts_repairs_and_verifies_top_level_dex(self) -> None:
        apk = build_apk(
            self.root / "unpacked.apk",
            {"classes.dex": build_valid_dex("com.example")},
        )
        result, decompile = self._unpack_static(apk, run_jadx=True)
        self.assertTrue((self.run.raw_dir / "classes.dex").is_file())
        self.assertTrue((self.run.fixed_dir / "classes.dex").is_file())
        self.assertTrue(result["dex_extraction"]["files"])
        self.assertEqual(result["dex_extraction"]["files"][0]["name"], "classes.dex")
        self.assertTrue(result["verification"]["complete"])
        self.assertTrue(result["decompilation"]["ok"])
        decompile.assert_called_once()

    def test_static_route_keeps_verified_dex_when_jadx_fails(self) -> None:
        apk = build_apk(
            self.root / "unpacked.apk",
            {"classes.dex": build_valid_dex("com.example")},
        )
        with mock.patch.object(
            self.service,
            "inspect_apk",
            return_value={"run_id": self.run.run_id, "inspection": inspection(packed=False)},
        ), mock.patch.object(
            self.service,
            "recommend_unpack_strategy",
            return_value={"strategy": {"primary": "static_jadx", "fallbacks": []}},
        ), mock.patch.object(
            self.service,
            "decompile_android_apk",
            side_effect=AnalysisError("jadx_failed", "jadx failed"),
        ) as decompile:
            result = self.service.unpack(str(apk), run_id=self.run.run_id, run_jadx=True)
        self.assertTrue((self.run.fixed_dir / "classes.dex").is_file())
        self.assertTrue(result["verification"]["complete"])
        self.assertFalse(result["decompilation"]["ok"])
        decompile.assert_called_once()

    def test_static_route_extracts_dex_when_jadx_disabled(self) -> None:
        apk = build_apk(
            self.root / "unpacked.apk",
            {"classes.dex": build_valid_dex("com.example")},
        )
        result, decompile = self._unpack_static(apk, run_jadx=False)
        self.assertTrue((self.run.fixed_dir / "classes.dex").is_file())
        self.assertTrue(result["verification"]["complete"])
        self.assertTrue(result["decompilation"]["skipped"])
        decompile.assert_not_called()

    def test_static_wgt_route_also_extracts_and_verifies_dex(self) -> None:
        apk = build_apk(
            self.root / "uni-app.apk",
            {"classes.dex": build_valid_dex("com.example")},
        )
        with mock.patch.object(
            self.service,
            "inspect_apk",
            return_value={"run_id": self.run.run_id, "inspection": inspection(packed=False)},
        ), mock.patch.object(
            self.service,
            "recommend_unpack_strategy",
            return_value={"strategy": {"primary": "static_wgt", "fallbacks": []}},
        ), mock.patch.object(
            self.service,
            "extract_apk_assets",
            return_value={"extraction": {"files": [{"name": "app.wgt"}]}},
        ), mock.patch.object(
            self.service,
            "decompile_android_apk",
            return_value={"decompilation": {"ok": True}},
        ) as decompile:
            result = self.service.unpack(str(apk), run_id=self.run.run_id, run_jadx=True)
        self.assertEqual(result["static_route"], "uni-app wgt")
        self.assertTrue(result["extraction"]["files"])
        self.assertTrue((self.run.fixed_dir / "classes.dex").is_file())
        self.assertTrue(result["dex_extraction"]["files"])
        self.assertTrue(result["verification"]["complete"])
        self.assertTrue(result["decompilation"]["ok"])
        decompile.assert_called_once()


class MultiDexVerificationTests(WorkflowBase):
    def test_runtime_dex_without_target_package_does_not_break_verification(self) -> None:
        (self.run.fixed_dir / "classes.dex").write_bytes(build_valid_dex("com.example"))
        (self.run.fixed_dir / "classes2.dex").write_bytes(build_valid_dex("com.vendor.runtime"))
        result = self.service.verify_android_dex(
            self.run.run_id, package_name="com.example"
        )
        verification = result["verification"]
        self.assertTrue(verification["complete"])
        self.assertTrue(verification["files_complete"])
        self.assertTrue(verification["target_complete"])
        by_name = {Path(item["path"]).name: item for item in verification["files"]}
        self.assertTrue(by_name["classes.dex"]["complete"])
        self.assertTrue(by_name["classes.dex"]["content_complete"])
        self.assertTrue(by_name["classes2.dex"]["content_complete"])
        self.assertFalse(by_name["classes2.dex"]["complete"])

    def test_verification_rejects_only_wrong_package_dex(self) -> None:
        (self.run.fixed_dir / "classes.dex").write_bytes(build_valid_dex("com.vendor.runtime"))
        result = self.service.verify_android_dex(
            self.run.run_id, package_name="com.example"
        )
        verification = result["verification"]
        self.assertTrue(verification["files_complete"])
        self.assertFalse(verification["target_complete"])
        self.assertFalse(verification["complete"])


class CandidateAcceptanceTests(WorkflowBase):
    def test_repairable_checksum_mismatch_is_accepted_and_repaired(self) -> None:
        raw = self.run.raw_dir / "candidate.dex"
        data = bytearray(build_valid_dex("com.example"))
        # Live memory dumps often have a stale/zeroed checksum and signature;
        # the class table and code are intact and repair can recompute them.
        data[0x08:0x20] = b"\x00" * 24
        raw.write_bytes(data)
        candidate = self.candidate(raw)
        self.service._assess_candidate(candidate, "com.example")
        self.assertTrue(candidate["accepted"])
        self.assertTrue(candidate["target"])
        self.assertTrue(candidate["repairable_complete"])
        self.assertFalse(candidate["content_complete"])
        self.assertFalse(candidate["checksum_ok"])
        self.assertIn("checksum_mismatch", candidate["reasons"])
        self.service.repair_android_dex(self.run.run_id)
        verified = self.service.verify_android_dex(self.run.run_id)
        self.assertTrue((self.run.fixed_dir / "classes.dex").is_file())
        self.assertTrue(verified["verification"]["complete"])
        self.assertTrue(verified["verification"]["target_complete"])

    def test_incomplete_candidate_continues_fallback(self) -> None:
        inbound = self.run.raw_dir
        inbound.mkdir(parents=True, exist_ok=True)
        stub = inbound / "stub.dex"
        stub.write_bytes(build_dex())  # 1 class: stub-like, not complete
        good = inbound / "good.dex"
        good.write_bytes(build_valid_dex("com.example"))

        def outcome(path: Path) -> dict:
            return {
                "pid": 42,
                "method": "frida-cookie",
                "frida": {"events": [], "returncode": 0},
                "candidates": [self.candidate(path)],
                "limitations": [],
            }

        self.service.adb = SerialAdb()  # type: ignore[assignment]
        with mock.patch.object(
            self.service,
            "_attempt_frida_cookie",
            side_effect=[outcome(stub), outcome(good)],
        ), mock.patch.object(self.service, "_frida_reachable", return_value=True):
            dumped = self.service.dump_android_dex(self.run.run_id, serial="fake", method="auto")

        self.assertEqual(dumped["method"], "frida_inmemory_spawn")
        self.assertEqual(dumped["attempts"][0]["status"], "incomplete")
        self.assertEqual(dumped["attempts"][1]["status"], "succeeded")
        accepted = dumped["accepted_candidates"]
        self.assertEqual(len(accepted), 1)
        self.assertTrue(accepted[0]["target"])
        self.assertGreater(accepted[0]["package_classes"], 0)
        self.assertEqual(dumped["skipped_candidates"], [])
        self.assertEqual(dumped["attempts"][0]["rejected_count"], 1)
        self.assertIn("stub_like", dumped["attempts"][0]["reasons"])

    def test_all_incomplete_candidates_fail_the_chain(self) -> None:
        raw = self.run.raw_dir
        raw.mkdir(parents=True, exist_ok=True)
        stub = raw / "stub.dex"
        stub.write_bytes(build_dex())
        truncated = raw / "truncated.dex"
        truncated.write_bytes(build_valid_dex("com.example")[:-16])

        def outcome(path: Path) -> dict:
            return {
                "pid": 42,
                "method": "frida-cookie",
                "frida": {"events": [], "returncode": 0},
                "candidates": [self.candidate(path)],
                "limitations": [],
            }

        self.service.adb = SerialAdb()  # type: ignore[assignment]
        with mock.patch.object(
            self.service,
            "_attempt_frida_cookie",
            side_effect=lambda *a, **kw: outcome(stub),
        ), mock.patch.object(
            self.service,
            "_attempt_memory",
            side_effect=lambda *a, **kw: outcome(truncated),
        ), mock.patch.object(self.service, "_frida_reachable", return_value=True):
            with self.assertRaises(AnalysisError) as context:
                self.service.dump_android_dex(self.run.run_id, serial="fake", method="auto")

        self.assertEqual(context.exception.code, "dump_incomplete")
        attempts = context.exception.partial["attempts"]
        self.assertTrue(attempts)
        self.assertTrue(all(item["status"] == "incomplete" for item in attempts))

    def test_acceptance_rejects_wrong_package_and_dump_holes(self) -> None:
        wrong = self.run.raw_dir / "wrong.dex"
        wrong.parent.mkdir(parents=True, exist_ok=True)
        wrong.write_bytes(build_valid_dex("com.other"))
        holed = self.run.raw_dir / "holed.dex"
        holed.write_bytes(build_valid_dex("com.example"))

        accepted, rejected = self.service._accept_candidates(
            {
                "candidates": [
                    self.candidate(wrong),
                    self.candidate(holed, dump_holes=16),
                ]
            },
            "com.example",
        )
        self.assertFalse(accepted)
        self.assertEqual(len(rejected), 2)
        self.assertTrue(any("package_not_found" in item["reasons"] for item in rejected))
        self.assertTrue(any(any("dump_zero_fill" in r for r in item["reasons"]) for item in rejected))
        # A wrong-package DEX can be structurally repairable but is still not a
        # target; a zero-filled dump is not repairable.
        self.assertTrue(any(item["repairable_complete"] and not item["target"] for item in rejected))
        self.assertTrue(any(not item["complete"] for item in rejected))

    def test_explicit_pid_must_match_package(self) -> None:
        class FakeProcess:
            def validate_pid(self, serial, pid, package):
                return {
                    "pid": pid,
                    "package": package,
                    "cmdline": "com.other",
                    "valid": False,
                    "is_main": False,
                }

        class FakeAdb:
            def resolve_serial(self, serial):
                return "fake"

        service = ToolService(self.config, adb=FakeAdb(), process=FakeProcess())
        with self.assertRaises(AnalysisError) as context:
            service.dump_android_dex(self.run.run_id, serial="fake", pid=1234, method="freeze_dd")
        self.assertEqual(context.exception.code, "process_mismatch")

    def test_exited_pid_is_process_died_rather_than_package_mismatch(self) -> None:
        process = SimpleNamespace(validate_pid=lambda serial, pid, package: {
            "pid": pid, "valid": False, "alive": False, "cmdline": "",
        })
        service = ToolService(self.config, adb=SerialAdb(), process=process)
        with self.assertRaises(AnalysisError) as context:
            service.inspect_process_state(self.run.run_id, serial="fake", pid=1234)
        self.assertEqual(context.exception.code, "process_died")
        self.assertTrue(context.exception.retryable)

    def test_pid_exiting_after_cmdline_read_is_not_accepted(self) -> None:
        process = SimpleNamespace(validate_pid=lambda serial, pid, package: {
            "pid": pid, "valid": True, "alive": False, "cmdline": package,
        })
        service = ToolService(self.config, adb=SerialAdb(), process=process)
        with self.assertRaises(AnalysisError) as context:
            service._validated_pid("fake", 1234, "com.example")
        self.assertEqual(context.exception.code, "process_died")


class DiskPullTests(WorkflowBase):
    def test_disk_short_read_is_rejected(self) -> None:
        full = build_valid_dex("com.example")
        truncated = full[:-10]

        class FakeAdb:
            def __init__(self):
                self.removed = []

            def pull(self, serial, remote, local):
                Path(local).write_bytes(truncated)
                return result()

            def stat_size(self, serial, path):
                return len(full)

            def list_dir(self, serial, path):
                return []

            def remove(self, serial, path):
                self.removed.append(path)
                return result()

        class FakeFrida:
            def run_script(self, *args, **kwargs):
                return {
                    "events": [
                        {"type": "path", "path": "/data/user/0/com.example/files/prodexdir/x.dex"}
                    ],
                    "returncode": 0,
                }

            def probe(self, host=None):
                return {"reachable": True}

        class FakeProcess:
            def find_pid(self, serial, package):
                return 42

        service = ToolService(
            self.config,
            adb=FakeAdb(),
            frida=FakeFrida(),
            process=FakeProcess(),
        )
        outcome = service._attempt_frida_disk(
            self.run, "fake", "com.example", timeout_ms=10000, cancel=None
        )
        candidate = outcome["candidates"][0]
        self.assertFalse(candidate["complete"])
        self.assertTrue(candidate["truncated"])
        self.assertTrue(any("short read" in note for note in candidate["notes"]))
        accepted, rejected = service._accept_candidates(outcome, "com.example")
        self.assertFalse(accepted)
        self.assertEqual(len(rejected), 1)


class JadxIsolationTests(WorkflowBase):
    def test_jadx_failure_does_not_invalidate_valid_dex(self) -> None:
        self.run.fixed_dir.mkdir(parents=True, exist_ok=True)
        (self.run.fixed_dir / "classes.dex").write_bytes(build_valid_dex("com.example"))

        class FakeJadx:
            def decompile(self, *args, **kwargs):
                from apk_unpack.domain.errors import fail

                raise fail("execution_failure", "jadx exploded", captured_output="boom")

        self.service.jadx = FakeJadx()
        verified = self.service.verify_android_dex(self.run.run_id, run_jadx=True)
        verification = verified["verification"]
        self.assertTrue(verification["complete"])
        self.assertFalse(verification["jadx"]["ok"])
        self.assertEqual(verification["jadx"]["error"]["code"], "execution_failure")


class LessonTrustTests(WorkflowBase):
    def test_untrusted_lessons_are_skipped(self) -> None:
        untrusted = {
            "lesson_id": "ls_untrusted",
            "title": "imported",
            "winning_method": "freeze_dd",
            "occurrences": 5,
            "success_count": 5,
            "failed_methods": [{"method": "frida_inmemory"}],
            "trusted": False,
        }
        trusted = {
            "lesson_id": "ls_trusted",
            "title": "observed",
            "winning_method": "memory_dd",
            "occurrences": 2,
            "success_count": 2,
            "failed_methods": [],
            "trusted": True,
        }

        class FakeLessons:
            def recall(self, **kwargs):
                return {"lessons": [untrusted, trusted], "stats": {"total": 2}}

        self.service.lessons = FakeLessons()
        strategy = self.service._augment_strategy_with_lessons(
            {"primary": "frida_inmemory", "fallbacks": ["memory_dd", "freeze_dd"], "do_not_attempt": []},
            inspection(),
            {"abi": "x86_64"},
            {},
        )
        self.assertIsNone(strategy["learned_primary"])
        self.assertEqual([item["lesson_id"] for item in strategy["lessons"]], ["ls_trusted"])
        self.assertEqual(strategy["fallbacks"][0], "memory_dd")


class CleanupMutationRetryTests(WorkflowBase):
    def _forward_mutation(self, state: str = "applied") -> dict:
        return self.run.add_mutation(
            {
                "kind": "adb_forward",
                "target": "tcp:27042",
                "detail": {"local_port": 27042, "remote_port": 27042, "created": True},
                "reversible": True,
                "state": state,
            }
        )

    def test_restore_failed_mutation_is_retried_and_reported(self) -> None:
        class FailingAdb(SerialAdb):
            def remove_forward(self, serial, local_port):
                return result(ok=False)

            def remove(self, serial, path):
                return result()

        mutation = self._forward_mutation(state="restore_failed")
        service = ToolService(self.config, adb=FailingAdb())
        summary = service.cleanup_run(self.run.run_id, serial="fake")

        # The retry ran (state started as restore_failed) and failed again.
        self.assertFalse(summary["ok"])
        self.assertTrue(summary["cleanup_incomplete"])
        self.assertEqual(summary["cleanup_status"], "incomplete")
        self.assertEqual([item["mutation_id"] for item in summary["failed"]], [mutation["mutation_id"]])
        self.assertEqual(summary["failed"][0]["kind"], "adb_forward")
        self.assertIn(mutation["mutation_id"], summary["remaining_mutations"])
        self.assertEqual(self.run.load_mutations()[0]["state"], "restore_failed")

    def test_second_cleanup_restores_restore_failed_mutation(self) -> None:
        class FailingAdb(SerialAdb):
            def remove_forward(self, serial, local_port):
                return result(ok=False)

            def remove(self, serial, path):
                return result()

        class WorkingAdb(SerialAdb):
            def remove_forward(self, serial, local_port):
                return result()

            def remove(self, serial, path):
                return result()

        mutation = self._forward_mutation()
        first = ToolService(self.config, adb=FailingAdb()).cleanup_run(self.run.run_id, serial="fake")
        self.assertTrue(first["cleanup_incomplete"])
        self.assertEqual(self.run.load_mutations()[0]["state"], "restore_failed")

        second = ToolService(self.config, adb=WorkingAdb()).cleanup_run(self.run.run_id, serial="fake")
        self.assertTrue(second["ok"])
        self.assertFalse(second["cleanup_incomplete"])
        self.assertEqual(second["cleanup_status"], "complete")
        self.assertEqual([item["mutation_id"] for item in second["restored"]], [mutation["mutation_id"]])
        self.assertEqual(second["failed"], [])
        self.assertEqual(second["remaining_mutations"], [])
        self.assertEqual(self.run.load_mutations()[0]["state"], "restored")

    def test_cont_failure_leaves_mutation_restore_failed(self) -> None:
        class FakeProcess:
            def __init__(self, signal_ok: bool) -> None:
                self.signal_ok = signal_ok
                self.signals: list[tuple[str, int]] = []

            def is_alive(self, serial, pid):
                return True

            def signal(self, serial, pid, sig):
                self.signals.append((sig, pid))
                return self.signal_ok

        class WorkingAdb(SerialAdb):
            def remove(self, serial, path):
                return result()

        mutation = self.run.add_mutation(
            {
                "kind": "kill_stop",
                "target": "pid:4242",
                "detail": {"reason": "freeze_dd"},
                "reversible": True,
            }
        )
        failing_process = FakeProcess(signal_ok=False)
        summary = ToolService(self.config, adb=WorkingAdb(), process=failing_process).cleanup_run(
            self.run.run_id, serial="fake"
        )
        self.assertEqual(failing_process.signals, [("CONT", 4242)])
        self.assertFalse(summary["ok"])
        self.assertTrue(summary["cleanup_incomplete"])
        self.assertEqual(summary["cleanup_status"], "incomplete")
        self.assertEqual(summary["failed"][0]["kind"], "kill_stop")
        self.assertIn(mutation["mutation_id"], summary["remaining_mutations"])
        self.assertEqual(self.run.load_mutations()[0]["state"], "restore_failed")

        # A later cleanup retries the CONT and can finish.
        working_process = FakeProcess(signal_ok=True)
        retried = ToolService(self.config, adb=WorkingAdb(), process=working_process).cleanup_run(
            self.run.run_id, serial="fake"
        )
        self.assertEqual(working_process.signals, [("CONT", 4242)])
        self.assertTrue(retried["ok"])
        self.assertEqual(retried["cleanup_status"], "complete")
        self.assertEqual(self.run.load_mutations()[0]["state"], "restored")

    def test_apply_failed_and_unknown_states_keep_cleanup_incomplete(self) -> None:
        class WorkingAdb(SerialAdb):
            def remove(self, serial, path):
                return result()

        mutation = self.run.add_mutation(
            {
                "kind": "push_file",
                "target": "/data/local/tmp/apu/file",
                "detail": {"created": True},
                "reversible": True,
                "state": "apply_failed",
            }
        )
        summary = ToolService(self.config, adb=WorkingAdb()).cleanup_run(self.run.run_id, serial="fake")
        self.assertFalse(summary["ok"])
        self.assertTrue(summary["cleanup_incomplete"])
        self.assertIn(mutation["mutation_id"], summary["remaining_mutations"])
        self.assertEqual(summary["failed"][0]["state"], "apply_failed")

    def test_not_applied_mutation_does_not_make_cleanup_incomplete(self) -> None:
        class WorkingAdb(SerialAdb):
            def remove(self, serial, path):
                return result()

        self.run.add_mutation(
            {
                "kind": "push_file",
                "target": "/data/local/tmp/apu/file",
                "detail": {"created": False},
                "reversible": False,
                "state": "not_applied",
            }
        )
        summary = ToolService(self.config, adb=WorkingAdb()).cleanup_run(self.run.run_id, serial="fake")
        self.assertTrue(summary["ok"])
        self.assertFalse(summary["cleanup_incomplete"])
        self.assertEqual(summary["cleanup_status"], "complete")


class CleanupStructureTests(WorkflowBase):
    def test_forward_removal_failure_is_structured(self) -> None:
        self.config.default_serial = None

        class FakeAdb:
            def remove_forward(self, serial, local_port):
                return result(ok=False)

            def remove(self, serial, path):
                return result()

            def resolve_serial(self, serial):
                return "fake"

        service = ToolService(self.config, adb=FakeAdb())
        self.run.add_mutation(
            {
                "kind": "adb_forward",
                "target": "tcp:27042",
                "detail": {"local_port": 27042, "remote_port": 27042, "created": True},
                "reversible": True,
            }
        )
        summary = service.cleanup_run(self.run.run_id, serial="fake")
        self.assertFalse(summary["ok"])
        self.assertTrue(summary["cleanup_incomplete"])
        self.assertEqual(summary["cleanup_status"], "incomplete")
        self.assertTrue(summary["failed"])
        self.assertEqual(summary["failed"][0]["kind"], "adb_forward")
        self.assertFalse(summary["run_deleted"])


class FakeDeviceAdb:
    def __init__(self, *, server_exists: bool, server_arch: str, server_version: str, cli_version: str):
        self.server_exists = server_exists
        self.server_arch = server_arch
        self.server_version = server_version
        self.cli_version = cli_version
        self.pushed: list[tuple[str, str, str]] = []
        self.killed = False
        self.forwards: list[dict] = []

    def resolve_serial(self, serial):
        return serial or "fake"

    def ensure_root(self, serial):
        return {"available": True, "uid": 0, "method": "already_root"}

    def shell(self, serial, command, timeout=None):
        if "getprop ro.product.cpu.abi" in command:
            return result("x86_64\n")
        if "--version" in command:
            return result(f"{self.server_version}\n")
        if "ps -A" in command:
            return result("u0_a50 100 1 S /data/local/tmp/frida-server -l 0.0.0.0:27042\n")
        return result()

    def file_exists(self, serial, path):
        return self.server_exists

    def elf_arch(self, serial, path):
        return self.server_arch if self.server_exists else None

    def kill_frida_server(self, serial):
        self.killed = True
        return {"killed": True, "pid": 100}

    def push(self, serial, local, remote):
        self.pushed.append((serial, str(local), remote))
        self.server_exists = True
        self.server_arch = "x86_64"
        self.server_version = self.cli_version
        return result()

    def chmod(self, serial, mode, path):
        return result()

    def start_frida_server(self, serial, path, port):
        return {"started": True, "pid": 100, "reason": "started"}

    def has_forward(self, serial, local_port, remote_port=None):
        return any(
            item["serial"] == serial
            and item["local_port"] == local_port
            and (remote_port is None or item["remote_port"] == remote_port)
            for item in self.forwards
        )

    def forward(self, serial, local_port, remote_port):
        self.forwards.append(
            {"serial": serial, "local_port": local_port, "remote_port": remote_port}
        )
        return result()

    def forward_list(self):
        rows = ["%s tcp:%d tcp:%d" % (f["serial"], f["local_port"], f["remote_port"]) for f in self.forwards]
        return result("\n".join(rows))

    def device_info(self, serial, frida_server_path=None):
        return {
            "serial": serial,
            "abi": "x86_64",
            "root": {"available": True},
            "frida": {"reachable": True},
        }


class FakeFrida:
    def __init__(self, version: str):
        self._version = version

    def version(self):
        return self._version

    def probe(self, host=None):
        return {"reachable": True, "host": host}


class FridaIsolationTests(WorkflowBase):
    def make_service(self, adb: FakeDeviceAdb) -> ToolService:
        self.config.frida = ["frida"]
        return ToolService(
            self.config,
            adb=adb,
            frida=FakeFrida("16.1.0"),
            process=SimpleNamespace(),
        )

    def test_stale_or_wrong_arch_server_is_replaced(self) -> None:
        adb = FakeDeviceAdb(
            server_exists=True,
            server_arch="x86",  # wrong for x86_64 device
            server_version="15.0.0",
            cli_version="16.1.0",
        )
        local = self.root / "frida-server-x86_64"
        local.write_bytes(elf_bytes(0x3E))
        self.config.frida_server = str(local)
        self.config.frida_port_span = 1
        service = self.make_service(adb)

        prepared = service.prepare_android_environment(
            self.run.run_id, serial="fake", start_frida_server=True
        )
        self.assertTrue(adb.killed)
        self.assertEqual(len(adb.pushed), 1)
        actions = prepared["actions"]
        push_actions = [item for item in actions if item["action"] == "frida_server_push"]
        self.assertEqual(push_actions[0]["reason"], "stale_or_wrong_arch")
        expected_port = self.config.frida_port_for("fake")
        self.assertTrue(adb.has_forward("fake", expected_port, self.config.frida_remote_port))
        self.assertTrue(
            any(action.get("action") == "adb_forward" and action.get("port") == expected_port for action in actions)
        )

    def test_wrong_arch_server_without_local_binary_fails_clearly(self) -> None:
        adb = FakeDeviceAdb(
            server_exists=True,
            server_arch="arm64",
            server_version="16.1.0",
            cli_version="16.1.0",
        )
        service = self.make_service(adb)
        with self.assertRaises(AnalysisError) as context:
            service.prepare_android_environment(
                self.run.run_id, serial="fake", start_frida_server=True
            )
        self.assertEqual(context.exception.code, "frida_version_mismatch")
        self.assertIn("refusing to reuse", context.exception.message)
        self.assertFalse(adb.killed)

    def test_local_binary_arch_mismatch_is_rejected_before_push(self) -> None:
        adb = FakeDeviceAdb(
            server_exists=False,
            server_arch="",
            server_version="16.1.0",
            cli_version="16.1.0",
        )
        local = self.root / "frida-server-x86_64"
        local.write_bytes(elf_bytes(0x3E))
        self.config.frida_server = str(local)
        service = ToolService(
            self.config,
            adb=adb,
            frida=FakeFrida("16.1.0"),
            process=SimpleNamespace(),
        )
        # Pretend the device is ARM while the only local server is x86_64.
        adb.shell = lambda serial, command, timeout=None: (
            result("arm64-v8a\n") if "getprop ro.product.cpu.abi" in command else result()
        )
        with self.assertRaises(AnalysisError) as context:
            service.prepare_android_environment(
                self.run.run_id, serial="fake", start_frida_server=True
            )
        self.assertEqual(context.exception.code, "frida_arch_mismatch")
        self.assertFalse(adb.pushed)


if __name__ == "__main__":
    unittest.main()
