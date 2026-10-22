"""Exercise result selection through real job finalization, without devices."""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from backend.config import BackendConfig
from backend.db import Database
from backend.engines import EngineResult
from backend.tests.test_finalization import minimal_manager, write_run
from tests.fixtures import build_apk, build_dex, build_valid_dex


class RuntimeFallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.config.serial = None
        self.config.device_arm_enabled = True
        self.config.device_arm_fallback = True
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)
        self.db.initialize()
        user = self.db.create_user("fallback-user", "hash", "salt")
        apk = build_apk(self.root / "input.apk", {"classes.dex": build_dex()})
        self.db.create_upload("upload", user["id"], apk.name, str(apk), apk.stat().st_size,
                              hashlib.sha256(apk.read_bytes()).hexdigest())
        self.job = self.db.create_job("job_fallback", user["id"], "upload", "fake", "x86",
                                      {"_auto_device": True, "jadx": False, "install": False}, "run_x86")
        self.manager = minimal_manager(self.config, self.db, SimpleNamespace(lessons=None))
        self.manager.agents = SimpleNamespace(canonical_engine=lambda name: name)
        self.manager._is_arm_serial = lambda serial: serial == "arm"
        self.manager._ensure_arm_device = mock.Mock(return_value="arm")
        self.manager._cleanup_target_app = mock.Mock()
        self.manager._safety_cleanup = mock.Mock(side_effect=self.cleanup)
        self.manager._arm_runtime_options = lambda options: dict(options)
        self.calls = []
        self.arm_output = "failed"
        self.first_output = "partial"
        self.first_abis = ["arm64-v8a"]
        self.arm_classes = 12
        self.arm_cleanup_fails = False
        self.first_cleanup_fails = False
        self.manager.engines = {"fake": SimpleNamespace(run=self.run_engine)}

    def cleanup(self, **kwargs):
        failed = self.arm_cleanup_fails if kwargs["serial"] == "arm" else self.first_cleanup_fails
        return {"cleanup_status": "incomplete" if failed else "complete", "cleanup_incomplete": failed,
                "cleanup_error": "simulated restore failure" if failed else None,
                "remaining_mutations": ["audit-mutation"] if failed else []}

    def run_engine(self, ctx):
        self.calls.append((ctx.run_id, ctx.serial))
        mode = self.arm_output if ctx.serial == "arm" else self.first_output
        if mode == "raises":
            raise RuntimeError("simulated ARM engine failure")
        if mode == "cancelled":
            ctx.cancel.set()
            return EngineResult("cancelled", run_id=ctx.run_id)
        if mode == "failed":
            write_run(ctx.run_dir, packed=True)
            return EngineResult("failed", run_id=ctx.run_id,
                                error={"code": "unsupported_target", "message": "simulated incompatible runtime"})
        classes = self.arm_classes if ctx.serial == "arm" else 12
        blob = build_valid_dex("com.example", classes=classes, padding=8192)
        if mode == "partial":
            blob = blob.replace(b"\xa5" * 4096, b"\0" * 4096, 1)
        if mode == "shell":
            blob = build_dex()
        write_run(ctx.run_dir, blob, packed=True, attempts=[
            {"method": "frida_inmemory", "status": "failed", "error": {"code": "frida_unavailable"}},
            {"method": "memory_dd", "status": "succeeded" if mode == "verified" else "incomplete"},
        ])
        state = json.loads((ctx.run_dir / "run.json").read_text())
        state["artifacts"]["inspection"]["abis"] = self.first_abis
        state["artifacts"]["last_dump"] = {"method": "memory_dd", "status": "succeeded" if mode == "verified" else "partial"}
        sources = ctx.run_dir / "dexdump/jadx/dex/sources/com/example"
        sources.mkdir(parents=True)
        (sources / "Main.java").write_text("package com.example; class Main {}")
        state["artifacts"]["decompilation"] = {"output_dir": str(sources.parents[2]), "java_file_count": 1}
        (ctx.run_dir / "run.json").write_text(json.dumps(state))
        return EngineResult("success" if mode == "verified" else "partial", run_id=ctx.run_id,
                            error=None if mode == "verified" else {"code": "partial_bytecode"})

    def process(self):
        with mock.patch("backend.jobs.record_job_lesson", return_value=None):
            self.manager._process(self.job["id"])
        return self.db.get_job(self.job["id"])

    def assert_original_downloads(self, final):
        self.assertEqual((final["run_id"], final["serial"], final["status"]), ("run_x86", "x86", "partial"))
        self.assertEqual(final["error"]["code"], "partial_bytecode")
        with zipfile.ZipFile(final["dex_zip"]) as archive:
            self.assertTrue(any(name.endswith("classes.dex") for name in archive.namelist()))
        with zipfile.ZipFile(final["source_zip"]) as archive:
            self.assertIn("com/example/Main.java", archive.namelist())
            self.assertIn("run_id=run_x86", archive.read("PROVENANCE.txt").decode())

    def test_failed_fallback_keeps_original_downloads_and_both_attempt_records(self):
        final = self.process()
        self.assert_original_downloads(final)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.manager._safety_cleanup.call_count, 2)
        attempts = final["error"]["runtime_attempts"]
        self.assertEqual([a["outcome"] for a in attempts], ["partial", "failed"])
        self.assertEqual(attempts[1]["error"]["code"], "unsupported_target")
        self.assertTrue((self.config.runs_dir / attempts[1]["run_id"] / "run.json").is_file())

    def test_smaller_partial_fallback_keeps_more_target_code(self):
        self.arm_output = "partial"
        self.arm_classes = 4
        self.assert_original_downloads(self.process())

    def test_more_complete_partial_fallback_is_selected(self):
        self.arm_output = "partial"
        self.arm_classes = 24
        final = self.process()
        self.assertEqual((final["serial"], final["status"]), ("arm", "partial"))
        self.assertNotEqual(final["run_id"], "run_x86")
        self.assertTrue((self.config.runs_dir / "run_x86/dexdump/fixed/classes.dex").is_file())

    def test_equal_partial_fallback_keeps_earlier_download_source(self):
        self.arm_output = "partial"
        self.assert_original_downloads(self.process())

    def test_pure_java_apk_can_still_use_arm_fallback(self):
        self.first_abis = []
        self.arm_output = "verified"
        final = self.process()
        self.assertEqual((final["serial"], final["status"]), ("arm", "succeeded"))

    def test_x86_only_apk_is_not_retried_on_arm64(self):
        self.first_abis = ["x86", "x86_64"]
        self.assert_original_downloads(self.process())
        self.manager._ensure_arm_device.assert_not_called()

    def test_verified_fallback_is_selected(self):
        self.arm_output = "verified"
        final = self.process()
        self.assertEqual((final["serial"], final["status"]), ("arm", "succeeded"))
        self.assertTrue(final["dex_zip"])

    def test_engine_exception_keeps_original_output(self):
        self.arm_output = "raises"
        self.assert_original_downloads(self.process())

    def test_provision_exception_keeps_original_output(self):
        self.manager._ensure_arm_device.side_effect = RuntimeError("simulated provisioning failure")
        self.assert_original_downloads(self.process())

    def test_cancel_during_fallback_keeps_already_recovered_output(self):
        self.arm_output = "cancelled"
        self.assert_original_downloads(self.process())

    def test_fallback_cleanup_failure_remains_visible_when_original_selected(self):
        self.arm_cleanup_fails = True
        final = self.process()
        self.assert_original_downloads(final)
        self.assertEqual(final["error"]["cleanup_status"], "incomplete")
        self.assertIn("simulated restore failure", final["error"]["cleanup_error"])

    def test_incomplete_original_cleanup_does_not_start_another_runtime(self):
        self.first_cleanup_fails = True
        final = self.process()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(final["error"]["cleanup_status"], "incomplete")
        self.manager._ensure_arm_device.assert_not_called()

    def test_finalizer_exception_does_not_hide_fallback_cleanup_failure(self):
        self.arm_cleanup_fails = True
        def stop(ctx, emit):
            if ctx.serial == "arm":
                raise RuntimeError("simulated finalizer failure")
        self.manager._cleanup_target_app.side_effect = stop
        final = self.process()
        self.assert_original_downloads(final)
        self.assertEqual(final["error"]["cleanup_status"], "incomplete")

    def test_shell_output_cannot_override_failed_runtime_status(self):
        self.first_output = "shell"
        final = self.process()
        self.assertEqual((final["serial"], final["status"]), ("arm", "failed"))

    def test_arm32_only_apk_is_not_retried_on_arm64_only_runtime(self):
        self.first_abis = ["armeabi-v7a"]
        self.assert_original_downloads(self.process())
        self.manager._ensure_arm_device.assert_not_called()

    def test_jadx_warning_after_verified_dump_does_not_retry_old_frida_error(self):
        self.first_output = "verified"
        self.run_engine(SimpleNamespace(run_id="run_x86", serial="x86", run_dir=self.config.runs_dir / "run_x86"))
        ctx = SimpleNamespace(run_dir=self.config.runs_dir / "run_x86", serial="x86", options={},
                              cancel=threading.Event(), upload_path=self.root / "input.apk")
        result = EngineResult("partial", error={"code": "jadx_incomplete"})
        self.assertEqual(self.manager._arm_fallback_reason(result, ctx, True), "")


if __name__ == "__main__":
    unittest.main()
