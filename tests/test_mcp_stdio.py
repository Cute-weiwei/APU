from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests.fixtures import shell_apk

REPO = Path(__file__).resolve().parents[1]


class McpProcess:
    def __init__(self, env: dict[str, str]):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "apk_unpack", "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=str(REPO),
            env=env,
        )
        self.queue: "queue.Queue[str]" = queue.Queue()
        self.lines: list[str] = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.queue.put(line)

    def send(self, payload: object) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def send_raw(self, text: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float = 25.0) -> dict:
        line = self.queue.get(timeout=timeout)
        self.lines.append(line)
        return json.loads(line)

    def recv_id(self, request_id: object) -> dict:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            message = self.recv(timeout=max(0.1, deadline - time.monotonic()))
            if message.get("id") == request_id:
                return message
        raise AssertionError(f"no response for id {request_id}")

    def close(self) -> None:
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass


class McpStdioTests(unittest.TestCase):
    def test_initialize_list_and_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = shell_apk(root / "target.apk", "ijiami")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO / "src")
            env["APU_RUNS_DIR"] = str(root / "runs")
            env["APU_MEMORY_DIR"] = str(root / "memory")
            env["APU_AAPT"] = "missing-aapt-for-tests"
            client = McpProcess(env)
            try:
                client.send(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test"}},
                    }
                )
                init = client.recv_id(1)
                self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
                self.assertEqual(init["result"]["serverInfo"]["name"], "apk-unpack-agents")

                client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                tools = client.recv_id(2)
                names = {item["name"] for item in tools["result"]["tools"]}
                self.assertIn("inspect_apk", names)
                self.assertIn("dump_android_dex", names)
                self.assertIn("cleanup_run", names)
                self.assertIn("recall_unpack_lessons", names)
                self.assertIn("remember_unpack_lesson", names)
                self.assertGreaterEqual(len(names), 17)

                client.send(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "inspect_apk", "arguments": {"apk_path": str(apk)}},
                    }
                )
                call = client.recv_id(3)
                self.assertFalse(call["result"]["isError"])
                structured = call["result"]["structuredContent"]
                self.assertTrue(structured["run_id"].startswith("run_"))
                self.assertTrue(structured["evidence_id"].startswith("ev_"))
                self.assertEqual(structured["inspection"]["packing"]["primary"], "ijiami")

                client.send({"jsonrpc": "2.0", "id": 4, "method": "ping"})
                self.assertEqual(client.recv_id(4)["result"], {})

                client.send(
                    {
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {
                            "name": "remember_unpack_lesson",
                            "arguments": {
                                "title": "test lesson",
                                "scenario": "unit test scenario",
                                "solution": "unit test solution",
                                "shell": "ijiami",
                                "confidence": "analyst",
                            },
                        },
                    }
                )
                remembered = client.recv_id(5)
                self.assertFalse(remembered["result"]["isError"])
                self.assertEqual(remembered["result"]["structuredContent"]["lesson"]["shell"], "ijiami")

                client.send(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "recall_unpack_lessons",
                            "arguments": {"shell": "ijiami", "limit": 5},
                        },
                    }
                )
                recalled = client.recv_id(6)
                self.assertFalse(recalled["result"]["isError"])
                self.assertGreaterEqual(recalled["result"]["structuredContent"]["total"], 1)

                client.send_raw("{not json")
                parse_error = client.recv()
                self.assertEqual(parse_error["error"]["code"], -32700)
                for line in client.lines:
                    json.loads(line)
            finally:
                client.close()


if __name__ == "__main__":
    unittest.main()
