from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

from apk_unpack.config import Config
from apk_unpack.domain.errors import AnalysisError
from apk_unpack.providers.frida import FridaManager
from apk_unpack.providers.host import HostRunner


FAKE_FRIDA = r'''
import json
import os
import sys
import time

mode = os.environ.get("FAKE_FRIDA_MODE", "done")
print("APU::" + json.dumps({"type": "hello", "pid": 42, "frida": "fake", "argv": sys.argv[1:]}))
if mode == "done":
    print("APU::" + json.dumps({"type": "done", "ok": True, "saved": 0}))
elif mode == "fail":
    print("APU::" + json.dumps({"type": "error", "where": "cookie", "message": "boom"}))
    print("APU::" + json.dumps({"type": "done", "ok": False}))
elif mode == "nodone":
    sys.exit(1)
elif mode in ("delayed", "waiting"):
    # Match the real CLI's quiet-mode lifetime, not just its output format.
    if "-q" in sys.argv and "-t" not in sys.argv:
        sys.exit(0)
    if mode == "delayed":
        time.sleep(0.1)
        print('APU::{"type":"done","ok":true,"saved":1}', flush=True)
    time.sleep(10)
'''


class FridaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fake = self.root / "fake_frida.py"
        self.fake.write_text(FAKE_FRIDA, encoding="utf-8")
        self.config = Config.load(runs_dir=self.root / "runs")
        self.config.frida = [sys.executable, str(self.fake)]
        self.manager = FridaManager(HostRunner(), self.config)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_done_marker_is_parsed(self) -> None:
        os.environ["FAKE_FRIDA_MODE"] = "done"
        try:
            result = self.manager.run_script("dump_cookie.js", {"run_id": "run_test"}, pid=42)
        finally:
            os.environ.pop("FAKE_FRIDA_MODE", None)
        self.assertTrue(result["done"]["ok"])
        self.assertEqual(result["events"][0]["type"], "hello")

    def test_explicit_host_is_passed_to_frida_client(self) -> None:
        os.environ["FAKE_FRIDA_MODE"] = "done"
        try:
            result = self.manager.run_script(
                "dump_cookie.js", {"run_id": "run_test"}, pid=42, host="127.0.0.1:27555"
            )
        finally:
            os.environ.pop("FAKE_FRIDA_MODE", None)
        argv = result["events"][0]["argv"]
        self.assertIn("-H", argv)
        self.assertEqual(argv[argv.index("-H") + 1], "127.0.0.1:27555")
        self.assertEqual(result["host"], "127.0.0.1:27555")

    def test_per_device_ports_are_stable_and_distinct(self) -> None:
        first = self.config.frida_port_for("emulator-5554")
        second = self.config.frida_port_for("emulator-5556")
        self.assertEqual(first, self.config.frida_port_for("emulator-5554"))
        self.assertNotEqual(first, second)
        self.assertTrue(first >= self.config.frida_port)
        self.assertLess(first, self.config.frida_port + self.config.frida_port_span)
        self.assertEqual(self.config.frida_host_for("emulator-5554"), f"127.0.0.1:{first}")

    def test_probe_uses_explicit_host(self) -> None:
        probe = self.manager.probe(host="127.0.0.1:27555")
        self.assertEqual(probe["host"], "127.0.0.1:27555")

    def test_failed_done_raises_process_died(self) -> None:
        os.environ["FAKE_FRIDA_MODE"] = "fail"
        try:
            with self.assertRaises(AnalysisError) as context:
                self.manager.run_script("dump_cookie.js", {"run_id": "run_test"}, pid=42)
        finally:
            os.environ.pop("FAKE_FRIDA_MODE", None)
        self.assertEqual(context.exception.code, "process_died")

    def test_early_exit_raises_execution_failure(self) -> None:
        os.environ["FAKE_FRIDA_MODE"] = "nodone"
        try:
            with self.assertRaises(AnalysisError) as context:
                self.manager.run_script("dump_cookie.js", {"run_id": "run_test"}, pid=42)
        finally:
            os.environ.pop("FAKE_FRIDA_MODE", None)
        self.assertEqual(context.exception.code, "execution_failure")

    def test_async_completion_survives_quiet_mode_for_attach_and_spawn(self) -> None:
        for target in ({"pid": 42}, {"spawn": True, "package": "com.example"}):
            with self.subTest(target=target), mock.patch.dict(os.environ, {"FAKE_FRIDA_MODE": "delayed"}):
                result = self.manager.run_script("dump_cookie.js", {"run_id": "async_test"}, timeout_ms=2000, **target)
            self.assertEqual(result["done"]["saved"], 1)
            self.assertLess(result["duration_s"], 2)

    def test_host_deadline_still_stops_waiting_cli(self) -> None:
        with mock.patch.dict(os.environ, {"FAKE_FRIDA_MODE": "waiting"}):
            with self.assertRaises(AnalysisError) as caught:
                self.manager.run_script("dump_cookie.js", {}, pid=42, timeout_ms=250)
        self.assertEqual(caught.exception.code, "timeout")

    def test_host_cancellation_still_stops_waiting_cli(self) -> None:
        cancelled = threading.Event()
        timer = threading.Timer(0.2, cancelled.set)
        timer.start()
        try:
            with mock.patch.dict(os.environ, {"FAKE_FRIDA_MODE": "waiting"}):
                with self.assertRaises(AnalysisError) as caught:
                    self.manager.run_script("dump_cookie.js", {}, pid=42, cancel=cancelled, timeout_ms=2000)
            self.assertEqual(caught.exception.code, "cancelled")
        finally:
            timer.cancel()


if __name__ == "__main__":
    unittest.main()
