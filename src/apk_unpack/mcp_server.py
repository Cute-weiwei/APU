from __future__ import annotations

import json
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import __version__
from .application.workflow import ToolService
from .contracts.tools import TOOLS_BY_NAME, TOOL_SPECS, server_info
from .domain.errors import AnalysisError, fail, project_error
from .domain.jsonutil import canonical_json

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

INSTRUCTIONS = (
    "APK shell-unpacking agent. Inspect the APK first, then recommend_unpack_strategy, prepare the environment, "
    "launch, inspect process state, dump DEX, repair, verify, and finally cleanup_run. Every evidence-producing call "
    "returns inline Evidence with an ev_ id. Use summary-first reasoning and do not repeat an identical failed attempt. "
    "Only use this on APKs you are authorized to analyze."
)


class McpServer:
    def __init__(self, service: ToolService):
        self.service = service
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="apu-tool")
        self.write_lock = threading.Lock()
        self.cancellations: dict[str, threading.Event] = {}
        self.cancellation_lock = threading.Lock()
        self.initialized = False
        self.protocol_version: str | None = None

    # ------------------------------------------------------------------ transport
    def serve(self) -> int:
        for raw in sys.stdin.buffer:
            try:
                line = raw.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                self._send_error(None, -32700, f"parse error: {exc}")
                continue
            try:
                self._handle(message)
            except Exception as exc:  # pragma: no cover - defensive
                self._log(traceback.format_exc())
                self._send_error(self._message_id(message), -32603, f"internal error: {exc}")
        self.executor.shutdown(wait=False, cancel_futures=True)
        return 0

    def _send(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self.write_lock:
            try:
                sys.stdout.buffer.write(data.encode("utf-8"))
                sys.stdout.buffer.flush()
            except (BrokenPipeError, OSError):
                pass

    def _send_result(self, request_id: Any, result: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _send_error(self, request_id: Any, code: int, message: str, data: Any = None) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        self._send({"jsonrpc": "2.0", "id": request_id, "error": error})

    def _log(self, message: str) -> None:
        try:
            sys.stderr.write(message.rstrip() + "\n")
            sys.stderr.flush()
        except Exception:
            pass

    @staticmethod
    def _message_id(message: Any) -> Any:
        if isinstance(message, dict):
            return message.get("id")
        return None

    # ------------------------------------------------------------------ dispatch
    def _handle(self, message: Any) -> None:
        if not isinstance(message, dict):
            self._send_error(None, -32600, "invalid request")
            return
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}
        is_notification = "id" not in message
        if not isinstance(method, str):
            self._send_error(request_id, -32600, "missing method")
            return
        if method == "initialize":
            self._handle_initialize(request_id, params)
            return
        if method == "notifications/initialized":
            self.initialized = True
            return
        if method == "notifications/cancelled":
            self._handle_cancelled(params)
            return
        if method.startswith("notifications/"):
            return
        if method == "ping":
            self._send_result(request_id, {})
            return
        if method == "tools/list":
            self._send_result(request_id, {"tools": [spec.to_mcp() for spec in TOOL_SPECS]})
            return
        if method == "tools/call":
            self._handle_tool_call(request_id, params)
            return
        if is_notification:
            return
        self._send_error(request_id, -32601, f"unknown method: {method}")

    def _handle_initialize(self, request_id: Any, params: dict[str, Any]) -> None:
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        self.protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        self.initialized = True
        self._send_result(
            request_id,
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": server_info(),
                "instructions": INSTRUCTIONS,
            },
        )

    def _handle_cancelled(self, params: dict[str, Any]) -> None:
        request_id = params.get("requestId") if isinstance(params, dict) else None
        key = str(request_id)
        with self.cancellation_lock:
            event = self.cancellations.get(key)
        if event:
            event.set()

    def _handle_tool_call(self, request_id: Any, params: dict[str, Any]) -> None:
        if not isinstance(params, dict):
            self._send_error(request_id, -32602, "invalid params")
            return
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not name:
            self._send_error(request_id, -32602, "missing tool name")
            return
        if not isinstance(arguments, dict):
            self._send_error(request_id, -32602, "arguments must be an object")
            return
        spec = TOOLS_BY_NAME.get(name)
        if spec is None:
            self._send_error(request_id, -32602, f"unknown tool: {name}")
            return
        unexpected = [key for key in arguments if key not in spec.input_schema.get("properties", {})]
        if unexpected:
            self._send_error(
                request_id,
                -32602,
                f"unexpected argument(s): {', '.join(sorted(unexpected))}",
                data={"tool": name, "unexpected": sorted(unexpected)},
            )
            return
        missing = [key for key in spec.input_schema.get("required", []) if arguments.get(key) in (None, "")]
        if missing:
            self._send_error(
                request_id,
                -32602,
                f"missing required argument(s): {', '.join(missing)}",
                data={"tool": name, "missing": missing},
            )
            return

        cancel = threading.Event()
        key = str(request_id)
        with self.cancellation_lock:
            self.cancellations[key] = cancel

        def run() -> None:
            try:
                result = self.service.call_tool(name, arguments, cancel)
                payload = canonical_json(result)
                if len(payload.encode("utf-8")) > self.service.config.mcp_max_response_bytes:
                    error = fail(
                        "resource_constraint",
                        "tool response exceeds the MCP response budget",
                        remediation="Use get_evidence/export_evidence_bundle and page the retained evidence.",
                        details={"run_id": result.get("run_id"), "evidence_id": result.get("evidence_id")},
                    )
                    self._send_tool_error(request_id, error)
                    return
                self._send_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                        "structuredContent": result,
                        "isError": False,
                    },
                )
            except AnalysisError as exc:
                self._send_tool_error(request_id, exc)
            except Exception as exc:  # pragma: no cover - defensive
                self._log(traceback.format_exc())
                self._send_tool_error(request_id, fail("execution_failure", str(exc)))
            finally:
                with self.cancellation_lock:
                    self.cancellations.pop(key, None)

        self.executor.submit(run)

    def _send_tool_error(self, request_id: Any, error: Exception) -> None:
        projection = project_error(error)
        text = json.dumps({"error": projection}, ensure_ascii=False)
        self._send_result(
            request_id,
            {
                "content": [{"type": "text", "text": text}],
                "isError": True,
            },
        )


def run_server(service: ToolService) -> int:
    return McpServer(service).serve()
