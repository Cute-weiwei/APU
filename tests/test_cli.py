from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.fixtures import build_apk, build_dex, build_manifest, shell_apk

REPO = Path(__file__).resolve().parents[1]


def run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "apk_unpack", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(REPO),
        env=env,
        timeout=120,
    )


class CliTests(unittest.TestCase):
    def test_inspect_strategy_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = shell_apk(root / "target.apk", "bangcle")
            runs = root / "runs"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO / "src")
            env["APU_RUNS_DIR"] = str(runs)
            env["APU_AAPT"] = "missing-aapt-for-tests"

            result = run_cli(["inspect-apk", str(apk), "--json"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            inspection = json.loads(result.stdout)
            run_id = inspection["run_id"]
            self.assertEqual(inspection["inspection"]["packing"]["primary"], "bangcle")

            result = run_cli(["strategy", run_id, "--json"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            strategy = json.loads(result.stdout)
            self.assertEqual(strategy["strategy"]["primary"], "memory_dd")

            result = run_cli(["evidence", run_id, "--json"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertGreaterEqual(evidence["total"], 2)

            result = run_cli(["run-state", run_id, "--json"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            state = json.loads(result.stdout)
            self.assertEqual(state["run_id"], run_id)

    def test_json_output_is_utf8_when_redirected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = build_manifest("com.example", version_name="1.0测试")
            apk = build_apk(root / "unicode.apk", {"classes.dex": build_dex()}, manifest=manifest)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO / "src")
            env["APU_RUNS_DIR"] = str(root / "runs")
            env["APU_AAPT"] = "missing-aapt-for-tests"
            result = subprocess.run(
                [sys.executable, "-m", "apk_unpack", "inspect-apk", str(apk), "--json"],
                capture_output=True,
                cwd=str(REPO),
                env=env,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            decoded = result.stdout.decode("utf-8")
            payload = json.loads(decoded)
            self.assertEqual(payload["inspection"]["package"]["version_name"], "1.0测试")

    def test_lesson_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO / "src")
            env["APU_RUNS_DIR"] = str(Path(tmp) / "runs")
            env["APU_MEMORY_DIR"] = str(Path(tmp) / "memory")
            env["APU_AAPT"] = "missing-aapt-for-tests"

            result = run_cli(
                [
                    "lesson-add",
                    "--title",
                    "cli lesson",
                    "--scenario",
                    "cli scenario",
                    "--solution",
                    "cli solution",
                    "--shell",
                    "ijiami",
                    "--json",
                ],
                env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            remembered = json.loads(result.stdout)
            self.assertEqual(remembered["status"], "added")

            result = run_cli(["recall-lessons", "--shell", "ijiami", "--json"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            recalled = json.loads(result.stdout)
            self.assertGreaterEqual(recalled["total"], 1)
            self.assertEqual(recalled["lessons"][0]["title"], "cli lesson")

    def test_doctor_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO / "src")
            env["APU_RUNS_DIR"] = str(Path(tmp) / "runs")
            env["APU_AAPT"] = "missing-aapt-for-tests"
            result = run_cli(["doctor", "--json"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertIn("checks", report)
            self.assertTrue(any(item["name"] == "python" for item in report["checks"]))


if __name__ == "__main__":
    unittest.main()
