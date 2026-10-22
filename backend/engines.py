from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import zipfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from apk_unpack.application.dex_validation import assess_dex
from apk_unpack.application.targets import target_namespaces
from apk_unpack.config import default_jadx_timeout_s
from apk_unpack.contracts.tools import TOOL_SPECS, TOOLS_BY_NAME
from apk_unpack.domain.errors import AnalysisError, project_error

from .agents import AgentSpec
from .config import BackendConfig, SKILL_PATH
from .mcp import McpClient, McpServerConfig, mcp_result_text, tool_alias
from .prompts import skill_text, system_prompt, user_prompt
from .providers import MODEL_PRESETS, ProviderConfig, endpoint_url, models_url
from .security import redact
from .skill_content import read_skill_bundle


@dataclass
class JobContext:
    job_id: str
    user_id: int
    engine: str
    upload_path: Path
    apk_name: str
    serial: str | None
    options: dict[str, Any]
    runs_dir: Path
    memory_dir: Path
    work_dir: Path
    cancel: threading.Event
    emit: Callable[[str, str, dict[str, Any] | None], Any]
    service: Any
    run_id: str
    config: BackendConfig
    last_stage: str = "queued"
    cleanup_called: bool = False
    # Structured result of the last safety-net cleanup (never a bare bool:
    # callers must be able to see ``cleanup_status``/``cleanup_error``).
    cleanup_result: dict[str, Any] | None = None
    # Repair report for the most recent static classes*.dex extraction.
    static_dex_repair: dict[str, Any] | None = None

    @property
    def transcript_path(self) -> Path:
        return self.work_dir / "transcript.jsonl"

    @property
    def run_dir(self) -> Path:
        return self.runs_dir / self.run_id


@dataclass
class EngineResult:
    outcome: str
    run_id: str | None = None
    summary: str = ""
    error: dict[str, Any] | None = None
    usage: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    transcript_path: str | None = None
    # Cleanup outcome is part of the job result: an incomplete cleanup after a
    # successful unpack must be visible (and degrades the job to ``partial``).
    cleanup_status: str | None = None
    cleanup_error: str | None = None
    cleanup: dict[str, Any] | None = None


DEFAULT_TASK_TIMEOUT_S = 3600


def read_run_state(run_dir: Path) -> dict[str, Any]:
    try:
        value = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def run_expected_package(run_dir: Path) -> str:
    """Target package recorded by the run, with the inspection as fallback."""
    state = read_run_state(run_dir)
    package = str(state.get("package") or "").strip()
    if package:
        return package
    for container in (state.get("artifacts") or {}, state):
        if isinstance(container, dict) and isinstance(container.get("inspection"), dict):
            package = str((container["inspection"].get("package") or {}).get("name") or "").strip()
            if package:
                return package
    return ""


def fixed_dex_paths(run_dir: Path) -> list[Path]:
    return sorted((run_dir / "dexdump" / "fixed").glob("*.dex"))


_CLASSES_DEX_RE = re.compile(r"classes\d*\.dex")
# The first 0x20 bytes hold the magic, Adler32 checksum and SHA-1 signature.
# Repair rewrites checksum/signature (and, for truncated dumps, file_size), so
# everything from 0x20 onward is the content identity used to compare a fixed
# DEX with the APK source DEX or with its raw dump.
_DEX_CONTENT_HASH_OFFSET = 0x20


def dex_content_hash(source: str | Path | bytes | bytearray | memoryview) -> str:
    """SHA-256 of the DEX bytes after the checksum/signature header.

    The hash is stable across ``repair_dex`` re-signing, which is what makes it
    usable as source-integrity evidence (F1): a repaired DEX that does not
    content-match the APK source cannot be proven to be the shipped code.
    """
    digest = hashlib.sha256()
    if isinstance(source, (bytes, bytearray, memoryview)):
        digest.update(bytes(source)[_DEX_CONTENT_HASH_OFFSET:])
        return digest.hexdigest()
    try:
        with open(Path(source), "rb") as handle:
            handle.seek(_DEX_CONTENT_HASH_OFFSET)
            while True:
                chunk = handle.read(4 * 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def run_target_apk_path(run_dir: Path) -> Path | None:
    """Return the target APK recorded by the run, when it still exists."""
    state = read_run_state(run_dir)
    candidates: list[Any] = []
    target = state.get("target")
    if isinstance(target, dict):
        candidates.extend((target.get("path"), target.get("local_path")))
    for container in (state.get("artifacts") or {}, state):
        if not isinstance(container, dict):
            continue
        inspection = container.get("inspection")
        if not isinstance(inspection, dict):
            continue
        identity = inspection.get("identity")
        if isinstance(identity, dict):
            candidates.extend((identity.get("path"), identity.get("local_path")))
    for value in candidates:
        if not value:
            continue
        path = Path(str(value)).expanduser()
        if path.is_file():
            return path
    return None


def apk_source_dex_hashes(apk_path: Path | None) -> tuple[dict[str, str], dict[str, Any]]:
    """Map content hashes to names of the APK's top-level ``classes*.dex``."""
    info: dict[str, Any] = {
        "apk_path": str(apk_path) if apk_path else None,
        "available": False,
        "dex_entries": [],
        "error": None,
    }
    hashes: dict[str, str] = {}
    if apk_path is None:
        return hashes, info
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = sorted(
                name for name in archive.namelist() if _CLASSES_DEX_RE.fullmatch(name)
            )
            for name in names:
                data = archive.read(name)
                digest = dex_content_hash(data)
                if not digest:
                    continue
                hashes.setdefault(digest, name)
                info["dex_entries"].append(
                    {"name": name, "size": len(data), "content_hash": digest}
                )
    except (OSError, zipfile.BadZipFile, ValueError, KeyError) as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        return hashes, info
    info["available"] = True
    return hashes, info


def _raw_dex_content_index(run_dir: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    for path in sorted((run_dir / "dexdump" / "raw").glob("*.dex")):
        digest = dex_content_hash(path)
        if digest:
            index.setdefault(digest, []).append(path)
    return index


def assess_fixed_dex(
    run_dir: Path,
    expected_package: str | None = None,
    apk_path: Path | None = None,
) -> dict[str, Any]:
    """Assess every repaired DEX of a run using the shared WP-A rules.

    ``usable`` is true only when at least one file is ``complete`` and, when
    the target package is known, contains classes from that package.

    ``verified`` adds source-integrity evidence (F1): a structurally complete
    DEX is only trusted when it content-matches a top-level ``classes*.dex`` of
    the run's target APK, or when it comes from a raw dump whose header was
    already valid.  A repaired DEX that matches a checksum/signature-damaged
    raw dump but not the APK source is reported as ``repaired_unverified`` and
    must not be presented as success.

    The returned ``reasons`` are stable tokens for job/error reporting.
    """
    paths = fixed_dex_paths(run_dir)
    namespaces = target_namespaces((read_run_state(run_dir).get("artifacts") or {}).get("inspection") or {})
    assessments = [assess_dex(path, expected_package or None, target_packages=namespaces) for path in paths]
    target_apk = run_target_apk_path(run_dir)
    if target_apk is None and apk_path is not None:
        candidate = Path(apk_path).expanduser()
        if candidate.is_file():
            target_apk = candidate
    source_hashes, source_info = apk_source_dex_hashes(target_apk)
    reasons: list[str] = []

    def add(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    raw_index: dict[str, list[Path]] | None = None
    files: list[dict[str, Any]] = []
    for path, assessment in zip(paths, assessments):
        digest = dex_content_hash(path)
        source_entry = source_hashes.get(digest) if digest else None
        source_verified = bool(source_entry)
        repaired_unverified = False
        raw_matches: list[str] = []
        if not source_verified and digest:
            if raw_index is None:
                raw_index = _raw_dex_content_index(run_dir)
            for raw_path in raw_index.get(digest, []):
                raw_matches.append(str(raw_path))
                raw_assessment = assess_dex(raw_path, expected_package or None, target_packages=namespaces)
                if raw_assessment.repairable_complete and not raw_assessment.content_complete:
                    repaired_unverified = True
        payload = assessment.to_dict()
        payload["content_hash"] = digest
        payload["source_verified"] = source_verified
        payload["source_entry"] = source_entry
        payload["repaired_unverified"] = repaired_unverified
        payload["raw_matches"] = raw_matches
        payload["verified"] = bool(assessment.complete and not repaired_unverified)
        if repaired_unverified and "repaired_unverified" not in payload["reasons"]:
            payload["reasons"] = [*payload["reasons"], "repaired_unverified"]
        files.append(payload)

    usable = any(item["complete"] for item in files)
    # A package need not occur in every multidex member. Require structural
    # integrity for every non-loader file, and target coverage in at least one.
    business_files = [item for item in files if not item["stub_like"] and not item["shell_like"]]
    files_complete = bool(business_files) and all(item["content_complete"] for item in business_files)
    repaired_unverified = any(item["repaired_unverified"] for item in files)
    dump_partial = ((read_run_state(run_dir).get("artifacts") or {}).get("last_dump") or {}).get("status") == "partial"
    verified = usable and files_complete and not repaired_unverified and not dump_partial
    if dump_partial:
        add("partial_bytecode")
    if not assessments:
        add("no_target_dex")
    else:
        if any(item.truncated for item in assessments):
            add("truncated")
        if any(item.holes for item in assessments):
            add("zero_holes")
        if all(item.stub_like for item in assessments):
            add("stub_only")
        if expected_package and not any(item.package_classes > 0 for item in assessments):
            add("no_target_dex")
        if repaired_unverified:
            add("repaired_unverified")
        if usable and not files_complete:
            add("incomplete_dex_set")
        if not usable and not reasons:
            add("unverified")
    if verified:
        code = None
    elif "partial_bytecode" in reasons:
        code = "partial_bytecode"
    elif "no_target_dex" in reasons:
        code = "no_target_dex"
    elif "stub_only" in reasons:
        code = "stub_only"
    elif "truncated" in reasons:
        code = "truncated"
    elif "repaired_unverified" in reasons:
        code = "repaired_unverified"
    elif "incomplete_dex_set" in reasons:
        code = "incomplete_dex_set"
    else:
        code = "unverified"
    return {
        "usable": usable,
        "recoverable": any(item["recoverable"] for item in files),
        "verified": verified,
        "files_complete": files_complete,
        "repaired_unverified": repaired_unverified,
        "code": code,
        "reasons": reasons,
        "expected_package": expected_package or None,
        "target_packages": namespaces,
        "source": source_info,
        "files": files,
    }


def decompilation_incomplete(result: Any) -> bool:
    """Distinguish recovered bytecode from the quality of reconstructed source."""
    return bool(isinstance(result, dict) and not result.get("skipped") and (
        result.get("error") or result.get("status") == "partial" or result.get("timed_out") or result.get("memory_exhausted") or result.get("process_failed")
        or result.get("error_count") or result.get("incomplete_file_count")
        or result.get("returncode") not in (None, 0)
    ))


def decompilation_error(result: Any) -> dict[str, Any]:
    result = result if isinstance(result, dict) else {}
    error = result.get("error") if isinstance(result.get("error"), dict) else {}
    timed_out = bool(result.get("timed_out") or error.get("code") == "timeout")
    source = {**(error.get("details") or {}), **result}
    memory_exhausted = bool(source.get("memory_exhausted"))
    process_failed = bool(source.get("process_failed") or source.get("returncode") not in (None, 0, 3)
                          or error.get("code") == "execution_failure")
    details = {key: source[key] for key in (
        "timeout_s", "duration_s", "total_duration_s", "timed_out", "memory_exhausted", "process_failed", "returncode", "java_file_count", "incomplete_file_count", "error_count",
    ) if key in source}
    fallback = result.get("fallback") or {}
    if fallback.get("output_dir"):
        details["fallback_covered_file_count"] = fallback.get("covered_file_count", 0)
        details["fallback_file_count"] = fallback.get("java_file_count", 0)
    return {
        "code": "jadx_timeout" if timed_out else "jadx_memory" if memory_exhausted else "jadx_process_error" if process_failed else "jadx_incomplete",
        "message": "DEX verified; JADX timed out; partial source output is retained" if timed_out
        else "DEX verified; JADX exhausted Java heap memory; primary source coverage is incomplete" if memory_exhausted
        else "DEX verified; JADX exited abnormally; primary source coverage is unknown" if process_failed
        else "DEX verified; JADX source reconstruction has errors or warnings (not an unpacking failure)",
        "details": details,
    }


def jadx_timeout_s(ctx: JobContext) -> int:
    return int(ctx.options.get("jadx_timeout_s") or default_jadx_timeout_s())


def cleanup_summary(result: Any, *, message: str = "") -> dict[str, Any]:
    """Normalise a ``cleanup_run`` payload into a structured status."""
    if not isinstance(result, dict):
        return {
            "cleanup_status": "incomplete",
            "cleanup_incomplete": True,
            "cleanup_error": "cleanup returned an invalid result",
            "message": message or "cleanup returned an invalid result",
            "restored": [],
            "failed": [],
            "remaining_mutations": [],
        }
    status = str(result.get("cleanup_status") or "")
    failed = list(result.get("failed") or [])
    remaining = list(result.get("remaining_mutations") or [])
    if not status:
        status = "incomplete" if failed or remaining else "complete"
    # ``skipped`` (cleanup disabled / nothing to clean) is not a failure.
    incomplete = status not in ("complete", "skipped") or bool(failed) or bool(remaining)
    error = result.get("error") or result.get("cleanup_error")
    if not error and failed:
        first = failed[0] if isinstance(failed[0], dict) else {}
        error = first.get("error") or json.dumps(failed, ensure_ascii=False, default=str)[:500]
    if not error and remaining:
        error = "device mutations remain applied: " + ", ".join(str(item) for item in remaining)
    return {
        "cleanup_status": "incomplete" if incomplete else "complete",
        "cleanup_incomplete": incomplete,
        "cleanup_error": str(error)[:2000] if error else None,
        "message": message
        or (
            "cleanup incomplete"
            if incomplete
            else str(result.get("message") or "cleanup completed")
        ),
        "restored": list(result.get("restored") or []),
        "failed": failed,
        "remaining_mutations": remaining,
        "run_id": result.get("run_id"),
    }


def _looks_like_jadx_error(error: dict[str, Any] | None) -> bool:
    if not isinstance(error, dict):
        return False
    blob = json.dumps(error, ensure_ascii=False, default=str).lower()
    return "jadx" in blob or "decompil" in blob


def task_timeout_s(ctx: JobContext) -> int:
    """Whole-task wall-clock timeout for the tool loop (not per API call)."""
    # Reserve the normal unpacking budget plus one full decompilation window.
    # An explicit whole-job limit remains authoritative.
    default = DEFAULT_TASK_TIMEOUT_S + (jadx_timeout_s(ctx) if ctx.options.get("jadx", True) else 0)
    try:
        value = int(ctx.options.get("timeout_s") or default)
    except (TypeError, ValueError):
        value = default
    return value if value > 0 else default


def _request_budget(provider: ProviderConfig, deadline: float) -> int:
    """Never let one HTTP request outlive the whole-task deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 1
    return max(1, min(int(provider.timeout_s or 1), int(remaining)))


RUN_SCOPED = {
    "inspect_apk",
    "extract_apk_assets",
    "prepare_android_environment",
    "launch_android_target",
    "inspect_process_state",
    "recommend_unpack_strategy",
    "dump_android_dex",
    "repair_android_dex",
    "verify_android_dex",
    "decompile_android_apk",
    "get_evidence",
    "export_evidence_bundle",
    "inspect_run",
    "cleanup_run",
}
APK_TOOLS = {"inspect_apk", "extract_apk_assets"}
DEVICE_TOOLS = {
    "inspect_android_device",
    "prepare_android_environment",
    "launch_android_target",
    "inspect_process_state",
    "dump_android_dex",
    "cleanup_run",
}


def _compact_tool_result(result: dict[str, Any], run_id: str = "") -> dict[str, Any]:
    """Keep outcome facts when large evidence/file lists exceed the model budget."""
    compact = {"truncated": True, "run_id": result.get("run_id") or run_id,
               "evidence_id": result.get("evidence_id"),
               "next": "Use the summary for the outcome; page evidence for details. Do not rerun JADX just to obtain counts."}
    state = result.get("run_state") or {}
    artifacts = (state.get("artifacts") or {}) if isinstance(state, dict) else {}
    verification = result.get("verification") or artifacts.get("verification")
    quality = result.get("decompilation") or artifacts.get("decompilation")
    if isinstance(verification, dict):
        compact["verification"] = {k: verification[k] for k in
            ("complete", "file_count", "total_classes", "scope") if k in verification}
        quality = quality or verification.get("jadx")
    if isinstance(quality, dict):
        compact["decompilation"] = {k: quality[k] for k in
            ("status", "java_file_count", "incomplete_file_count", "error_count", "timed_out",
             "memory_exhausted", "process_failed", "returncode", "timeout_s", "completion_reason") if k in quality}
        fallback = quality.get("fallback")
        if isinstance(fallback, dict):
            compact["fallback"] = {k: fallback[k] for k in
                ("status", "requested_file_count", "covered_file_count", "incomplete_file_count") if k in fallback}
    if "next_offset" in result:
        compact["next_offset"] = result["next_offset"]
    if not quality and not verification:
        compact["keys"] = sorted(result.keys())
    return compact


class ToolBridge:
    """Map the agent's ToolSpecs to LLM tools and execute them safely."""

    def __init__(self, ctx: JobContext):
        self.ctx = ctx
        self.max_chars = ctx.config.tool_result_max_chars

    def tools_openai(self) -> list[dict[str, Any]]:
        tools = []
        for spec in TOOL_SPECS:
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.input_schema,
                    },
                }
            )
        return tools

    def tools_anthropic(self) -> list[dict[str, Any]]:
        return [
            {"name": spec.name, "description": spec.description, "input_schema": spec.input_schema}
            for spec in TOOL_SPECS
        ]

    def execute(self, name: str, arguments: dict[str, Any] | None) -> tuple[dict[str, Any], bool, str]:
        if name not in TOOLS_BY_NAME:
            error = {"code": "invalid_input", "message": f"unknown tool: {name}"}
            return error, True, json.dumps(error, ensure_ascii=False)
        arguments = dict(arguments or {})
        spec = TOOLS_BY_NAME[name]
        allowed = set((spec.input_schema.get("properties") or {}).keys())
        unknown = [key for key in arguments if key not in allowed]
        if unknown:
            error = {"code": "invalid_input", "message": f"unexpected argument(s): {', '.join(sorted(unknown))}"}
            return error, True, json.dumps(error, ensure_ascii=False)
        missing = [key for key in spec.input_schema.get("required", []) if arguments.get(key) in (None, "") and key not in ("run_id", "apk_path")]
        if missing:
            error = {"code": "invalid_input", "message": "missing required argument(s): " + ", ".join(missing)}
            return error, True, json.dumps(error, ensure_ascii=False)
        try:
            self._inject(name, arguments)
            result = self.ctx.service.call_tool(name, arguments, self.ctx.cancel)
            if name == "cleanup_run":
                summary = cleanup_summary(result)
                self.ctx.cleanup_result = summary
                # A failed/incomplete cleanup must be retried by the safety net;
                # only a complete restore marks cleanup as done.
                self.ctx.cleanup_called = not summary["cleanup_incomplete"]
            if isinstance(result, dict) and result.get("run_id"):
                self.ctx.run_id = result["run_id"]
            text = json.dumps(result, ensure_ascii=False, default=str)
            if len(text) > self.max_chars:
                compact = _compact_tool_result(result, self.ctx.run_id) if isinstance(result, dict) else {"truncated": True}
                return compact, False, json.dumps(compact, ensure_ascii=False)
            value = json.loads(text)
            return value, False, text
        except AnalysisError as exc:
            projection = exc.projection()
            return projection, True, json.dumps({"error": projection}, ensure_ascii=False)
        except Exception as exc:  # pragma: no cover - defensive
            projection = project_error(exc)
            return projection, True, json.dumps({"error": projection}, ensure_ascii=False)

    def _inject(self, name: str, args: dict[str, Any]) -> None:
        ctx = self.ctx
        if name in RUN_SCOPED:
            supplied = args.get("run_id")
            if supplied and supplied != ctx.run_id:
                raise AnalysisError("permission_denied", "a different run_id is not allowed")
            args["run_id"] = ctx.run_id
        if name in APK_TOOLS:
            supplied = args.get("apk_path")
            if supplied and Path(supplied).resolve() != ctx.upload_path.resolve():
                raise AnalysisError("permission_denied", "apk_path must be the uploaded APK")
            args["apk_path"] = str(ctx.upload_path)
        if name in DEVICE_TOOLS:
            supplied = args.get("serial")
            if supplied and ctx.serial and supplied != ctx.serial:
                raise AnalysisError("permission_denied", "a different serial is not allowed")
            if ctx.serial:
                args["serial"] = ctx.serial
        options = ctx.options
        install = bool(options.get("install", True))
        jadx = bool(options.get("jadx", True))
        cleanup = bool(options.get("cleanup", True))
        keep = bool(options.get("keep_device_files", False))
        prune = bool(options.get("prune_raw", False))
        auto_bypass = bool(options.get("auto_emulator_bypass", True))
        if name == "recommend_unpack_strategy":
            args["force_dump"] = bool(options.get("force_dump", False))
        elif name == "prepare_android_environment":
            args["apk_path"] = str(ctx.upload_path)
            args["allow_install"] = install
            args["keep_device_files"] = keep
            args.setdefault("start_frida_server", True)
            if options.get("inner_bypass"):
                args["inner_bypass"] = True
            frida_path = str(options.get("_frida_server_path") or "").strip()
            if frida_path:
                args.setdefault("frida_server_path", frida_path)
        elif name == "launch_android_target":
            args["apk_path"] = str(ctx.upload_path)
            args["install"] = False
            args["auto_emulator_bypass"] = auto_bypass
        elif name == "dump_android_dex":
            args.setdefault("method", "auto")
            args["keep_device_files"] = keep
            if options.get("inner_bypass"):
                args["inner_bypass"] = True
            for source, target in (
                ("freeze_timeout_ms", "freeze_timeout_ms"),
                ("freeze_poll_ms", "freeze_poll_ms"),
                ("frida_timeout_ms", "frida_timeout_ms"),
                ("max_region_bytes", "max_region_bytes"),
            ):
                if options.get(source) is not None:
                    args[target] = options[source]
        elif name == "verify_android_dex":
            # DEX validation is cheap; decompilation is an explicit separate step.
            # Enabling JADX for a job must not implicitly run it twice.
            args.setdefault("run_jadx", False)
            if not jadx:
                args["run_jadx"] = False
            args["timeout_s"] = jadx_timeout_s(ctx)
        elif name == "decompile_android_apk":
            args.setdefault("source", "dex")
            if args.get("source") == "apk":
                args["apk_path"] = str(ctx.upload_path)
            # Job settings take precedence over an LLM's suggested timeout.
            args["timeout_s"] = jadx_timeout_s(ctx)
            if args.get("output_dir") and not _inside(Path(args["output_dir"]), ctx.run_dir):
                raise AnalysisError("permission_denied", "decompile output must stay inside the run directory")
        elif name == "cleanup_run":
            args["delete_run"] = False
            args["prune_raw_dumps"] = prune
        elif name == "extract_apk_assets":
            args["apk_path"] = str(ctx.upload_path)
            args.setdefault("output_dir", str(ctx.run_dir / "assets"))
        elif name == "export_evidence_bundle":
            output = Path(args.get("output_path") or (ctx.work_dir / "evidence-bundle.json"))
            if not _inside(output, ctx.work_dir) and not _inside(output, ctx.run_dir):
                raise AnalysisError("permission_denied", "evidence export must stay inside the job/run directory")
            args["output_path"] = str(output)
        elif name == "repair_android_dex":
            if args.get("output_dir") and not _inside(Path(args["output_dir"]), ctx.run_dir):
                raise AnalysisError("permission_denied", "repair output must stay inside the run directory")


def _inside(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# deterministic agent engine
# ---------------------------------------------------------------------------


class AgentEngine:
    name = "agent"

    @property
    def available(self) -> bool:
        return self.agent.available if self.agent else True

    @property
    def reason(self) -> str:
        return self.agent.reason if self.agent else "deterministic workflow"

    def __init__(
        self,
        config: BackendConfig,
        agent: AgentSpec | None = None,
        skills: list[dict[str, Any]] | None = None,
    ):
        self.config = config
        self.agent = agent
        self.skills = skills or []

    def public(self, admin: bool = False) -> dict[str, Any]:
        if self.agent:
            data = self.agent.public(admin=admin)
            data["kind"] = "native"
            data["protocol"] = "native"
            data["model"] = "deterministic"
            return data
        return {
            "name": "agent",
            "id": "agent",
            "label": "Agent（确定性）",
            "kind": "native",
            "protocol": "native",
            "model": "deterministic",
            "base_url": "",
            "available": True,
            "reason": "deterministic workflow",
            "enabled": True,
            "builtin": True,
            "skills": [],
            "mcp": [],
        }

    def _emit_config(self, ctx: JobContext) -> None:
        if self.agent:
            ctx.emit(
                "engine_config",
                f"{self.agent.name} · 确定性工作流",
                {
                    "agent_id": self.agent.id,
                    "agent": self.agent.name,
                    "kind": "native",
                    "provider": None,
                    "protocol": "native",
                    "model": "deterministic",
                    "skills": [{"id": item.get("id"), "name": item.get("name")} for item in self.skills],
                    "mcp": [],
                },
            )
        for skill in self.skills:
            ctx.emit(
                "skill_loaded",
                f"skill: {skill.get('name') or skill.get('id')}",
                {
                    "id": skill.get("id"),
                    "name": skill.get("name"),
                    "source": skill.get("source"),
                    "chars": len(str(skill.get("content") or "")),
                },
            )

    def run(self, ctx: JobContext) -> EngineResult:
        self._emit_config(ctx)
        options = ctx.options
        cmd = [
            self.config.agent_python,
            "-m",
            "apk_unpack",
            "unpack",
            str(ctx.upload_path),
            "--json",
            "--runs-dir",
            str(ctx.runs_dir),
            "--run-id",
            ctx.run_id,
        ]
        if ctx.serial:
            cmd.extend(["--serial", ctx.serial])
        frida_path = str(options.get("_frida_server_path") or "").strip()
        if options.get("install", True):
            cmd.append("--install")
        if not options.get("jadx", True):
            cmd.append("--no-jadx")
        cmd.extend(["--jadx-timeout-s", str(jadx_timeout_s(ctx))])
        if not options.get("cleanup", True):
            cmd.append("--no-cleanup")
        if options.get("keep_device_files"):
            cmd.append("--keep-device-files")
        if not options.get("auto_emulator_bypass", True):
            cmd.append("--no-auto-bypass")
        if options.get("force_dump"):
            cmd.append("--force-dump")
        if options.get("inner_bypass"):
            cmd.append("--inner-bypass")
        for key, flag in (
            ("freeze_timeout_ms", "--freeze-timeout-ms"),
            ("freeze_poll_ms", "--freeze-poll-ms"),
            ("frida_timeout_ms", "--frida-timeout-ms"),
            ("max_region_bytes", "--max-region-bytes"),
        ):
            if options.get(key) is not None:
                cmd.extend([flag, str(options[key])])
        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(self.config.agent_src) + (os.pathsep + existing if existing else "")
        env["APU_RUNS_DIR"] = str(ctx.runs_dir)
        env["APU_MEMORY_DIR"] = str(ctx.memory_dir)
        if frida_path:
            # unpack consumes this through Config.load; --frida-server is
            # only a CLI option for device/prepare/doctor subcommands.
            env["APU_FRIDA_SERVER"] = frida_path
        if ctx.serial:
            env["APU_SERIAL"] = ctx.serial
        log_path = ctx.work_dir / "agent.log"
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        lock = threading.Lock()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(self.config.agent_repo),
                env=env,
                start_new_session=(os.name != "nt"),
            )
        except OSError as exc:
            return EngineResult("failed", run_id=ctx.run_id, error={"code": "execution_failure", "message": str(exc)})
        ctx.emit("agent.started", "agent subprocess started", {"pid": proc.pid, "cmd": cmd})
        log_handle = open(log_path, "a", encoding="utf-8", errors="replace")

        def reader(pipe, prefix: str, sink: list[str]) -> None:
            try:
                for line in iter(pipe.readline, ""):
                    text = redact(line.rstrip("\r\n"))
                    with lock:
                        sink.append(line)
                    log_handle.write(f"[{prefix}] {text}\n")
                    log_handle.flush()
                    if text.strip():
                        ctx.emit(f"agent.{prefix}", text[:2000])
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass

        readers = [
            threading.Thread(target=reader, args=(proc.stdout, "stdout", stdout_chunks), daemon=True),
            threading.Thread(target=reader, args=(proc.stderr, "stderr", stderr_chunks), daemon=True),
        ]
        for thread in readers:
            thread.start()

        tail_stop = threading.Event()
        tail_thread = threading.Thread(target=self._tail_events, args=(ctx, tail_stop), daemon=True)
        tail_thread.start()

        deadline = time.monotonic() + task_timeout_s(ctx)
        cancelled = False
        timed_out = False
        while proc.poll() is None:
            if ctx.cancel.is_set():
                cancelled = True
                self._terminate(proc)
                break
            if time.monotonic() > deadline:
                timed_out = True
                self._terminate(proc)
                break
            time.sleep(0.2)
        for thread in readers:
            thread.join(timeout=5)
        tail_stop.set()
        tail_thread.join(timeout=5)
        log_handle.close()
        ctx.emit("agent.finished", "agent subprocess finished", {"returncode": proc.returncode, "cancelled": cancelled})
        stdout = "".join(stdout_chunks)
        stderr = "".join(stderr_chunks)
        if cancelled:
            cleanup = self._safety_cleanup(ctx)
            return EngineResult(
                "cancelled",
                run_id=ctx.run_id,
                summary="cancelled by user",
                error={"code": "cancelled", "message": "cancelled by user"},
                cleanup_status=cleanup["cleanup_status"],
                cleanup_error=cleanup.get("cleanup_error"),
                cleanup=cleanup,
            )
        payload = _extract_last_json(stdout)
        if payload is None:
            if timed_out:
                error = {"code": "timeout", "message": "agent subprocess timed out"}
            else:
                error = {
                    "code": "execution_failure",
                    "message": "agent did not return JSON",
                    "captured_output": redact(stderr[-4000:]) or redact(stdout[-4000:]),
                }
            cleanup = self._safety_cleanup(ctx)
            return EngineResult(
                "failed",
                run_id=ctx.run_id,
                error=error,
                summary="agent failed",
                cleanup_status=cleanup["cleanup_status"],
                cleanup_error=cleanup.get("cleanup_error"),
                cleanup=cleanup,
            )
        run_id = payload.get("run_id") or ctx.run_id
        ctx.run_id = run_id
        cleanup = self._safety_cleanup(ctx, require_incomplete=True)
        verdict = assess_fixed_dex(
            ctx.run_dir, run_expected_package(ctx.run_dir), apk_path=ctx.upload_path
        )
        warnings: list[str] = []
        error: dict[str, Any] | None = None
        outcome = "failed"
        if payload.get("error"):
            error = payload["error"] if isinstance(payload["error"], dict) else {"code": "execution_failure", "message": str(payload["error"])}
            if verdict["usable"] and _looks_like_jadx_error(error):
                # A decompilation (JADX) failure must not invalidate a DEX that
                # the deterministic workflow already recovered and verified.
                warnings.append("JADX/decompilation failed after a usable DEX was recovered: " + json.dumps(error, ensure_ascii=False)[:500])
                error = {"code": "jadx_failed", "message": "DEX recovered but JADX decompilation failed", "reasons": verdict["reasons"]}
                outcome = "partial"
            else:
                return EngineResult(
                    "failed",
                    run_id=run_id,
                    error=error,
                    summary="agent failed",
                    warnings=warnings,
                    cleanup_status=cleanup["cleanup_status"],
                    cleanup_error=cleanup.get("cleanup_error"),
                    cleanup=cleanup,
                )
        else:
            status = str(payload.get("status") or "success")
            verification = payload.get("verification") or {}
            if status == "failed":
                outcome = "failed"
            elif verdict["verified"] and status != "partial" and (
                not isinstance(verification, dict) or verification.get("complete") is not False
            ):
                outcome = "success"
            else:
                outcome = "partial"
                error = {
                    "code": "workflow_partial",
                    "message": "DEX files passed validation but the workflow reported incomplete recovery",
                    "reasons": [],
                } if verdict["verified"] else {
                    "code": verdict["code"] or "unverified",
                    "message": "no verified target DEX was produced: " + ", ".join(verdict["reasons"] or ["unverified"]),
                    "reasons": verdict["reasons"],
                }
                if verdict.get("recoverable") and not verdict["usable"]:
                    error = {"code": "partial_bytecode", "message": "Target bytecode retained for best-effort JADX; consult the quality report for missing methods and bytes.", "reasons": verdict["reasons"]}
            if not verdict["verified"]:
                warnings.append("DEX assessment: " + ", ".join(verdict["reasons"] or ["unverified"]))
            if not isinstance(verification, dict):
                verification = {}
            jadx = payload.get("decompilation") or verification.get("jadx") or (
                read_run_state(ctx.run_dir).get("artifacts") or {}
            ).get("decompilation") or {}
            if decompilation_incomplete(jadx):
                warnings.append("JADX produced partial source output; recovered DEX files are retained")
                if outcome == "success":
                    outcome = "partial"
                    error = decompilation_error(jadx)
            if payload.get("extraction_error") or (payload.get("extraction") or {}).get("skipped"):
                warnings.append("Some APK assets could not be extracted")
                if outcome == "success":
                    outcome = "partial"
                    error = {"code": "assets_incomplete", "message": "Some APK assets were not recovered"}
            if cleanup["cleanup_incomplete"] and outcome == "success":
                outcome = "partial"
            if cleanup["cleanup_incomplete"]:
                warnings.append("cleanup incomplete: " + str(cleanup.get("cleanup_error") or cleanup.get("message")))
                if outcome not in ("failed", "cancelled"):
                    error = {
                        "code": "cleanup_incomplete",
                        "message": "device cleanup did not complete; review restored mutations",
                        "cleanup_status": "incomplete",
                        "cleanup_error": cleanup.get("cleanup_error"),
                    }
        summary = {
            "status": str(payload.get("status") or ""),
            "method": payload.get("method"),
            "files": len((payload.get("repair") or {}).get("files") or []),
            "classes": (payload.get("verification") or {}).get("total_classes"),
            "complete": (payload.get("verification") or {}).get("complete"),
            "cleanup": cleanup["cleanup_status"],
            "verified_dex": verdict["verified"],
            "dex_reasons": verdict["reasons"],
        }
        return EngineResult(
            outcome,
            run_id=run_id,
            summary=json.dumps(summary, ensure_ascii=False),
            error=error,
            warnings=warnings,
            transcript_path=str(log_path),
            cleanup_status=cleanup["cleanup_status"],
            cleanup_error=cleanup.get("cleanup_error"),
            cleanup=cleanup,
        )

    def _tail_events(self, ctx: JobContext, stop: threading.Event) -> None:
        path = ctx.run_dir / "events.jsonl"
        deadline = time.monotonic() + 15
        while not path.exists() and time.monotonic() < deadline and not stop.is_set():
            time.sleep(0.2)
        offset = 0
        carry = ""
        last_stage = None
        while True:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        chunk = handle.read()
                        offset = handle.tell()
                except OSError:
                    chunk = ""
                data = carry + chunk
                lines = data.split("\n")
                carry = lines.pop() if lines else ""
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    name = event.get("event")
                    detail = event.get("detail") or {}
                    if name == "stage":
                        stage = detail.get("stage")
                        if stage and stage != last_stage:
                            last_stage = stage
                            ctx.last_stage = stage
                            ctx.emit("stage", str(stage), detail)
                    else:
                        ctx.emit(f"agent.{name}", "", detail)
            if stop.is_set():
                break
            time.sleep(0.2)

    def _safety_cleanup(self, ctx: JobContext, require_incomplete: bool = False) -> dict[str, Any]:
        """Run the safety-net cleanup and return its structured status.

        Cleanup errors are never swallowed: they are emitted and returned so the
        job result can be degraded to ``partial``.
        """
        if not ctx.options.get("cleanup", True) or not ctx.run_id:
            return {
                "cleanup_status": "skipped",
                "cleanup_incomplete": False,
                "cleanup_error": None,
                "message": "cleanup disabled or no run",
                "restored": [],
                "failed": [],
                "remaining_mutations": [],
            }
        if require_incomplete:
            state = read_run_state(ctx.run_dir)
            if state.get("cleanup_status") == "complete":
                summary = cleanup_summary(
                    {
                        "cleanup_status": "complete",
                        "restored": [],
                        "failed": [],
                        "remaining_mutations": [],
                        "run_id": ctx.run_id,
                    },
                    message="workflow already cleaned the device",
                )
                ctx.cleanup_result = summary
                ctx.cleanup_called = True
                return summary
        try:
            result = ctx.service.cleanup_run(
                ctx.run_id,
                serial=ctx.serial,
                delete_run=False,
                prune_raw_dumps=bool(ctx.options.get("prune_raw", False)),
            )
            summary = cleanup_summary(result, message="safety-net cleanup completed")
            ctx.cleanup_result = summary
            ctx.cleanup_called = not summary["cleanup_incomplete"]
            if summary["cleanup_incomplete"]:
                ctx.emit(
                    "cleanup.safety_net_failed",
                    "safety-net cleanup incomplete",
                    {
                        "cleanup_status": summary["cleanup_status"],
                        "cleanup_error": summary.get("cleanup_error"),
                        "failed": summary.get("failed"),
                        "remaining_mutations": summary.get("remaining_mutations"),
                    },
                )
            else:
                ctx.emit(
                    "cleanup.safety_net",
                    "safety-net cleanup completed",
                    {"status": summary["cleanup_status"]},
                )
            return summary
        except Exception as exc:
            message = redact(str(exc))
            summary = cleanup_summary(None, message="safety-net cleanup failed: " + message)
            summary["cleanup_error"] = message
            ctx.cleanup_result = summary
            ctx.emit("cleanup.safety_net_failed", "safety-net cleanup failed", {"error": message[:1000]})
            return summary

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# LLM engines
# ---------------------------------------------------------------------------


@dataclass
class McpRuntime:
    clients: dict[str, McpClient] = field(default_factory=dict)
    mapping: dict[str, tuple[McpServerConfig, str]] = field(default_factory=dict)
    openai_tools: list[dict[str, Any]] = field(default_factory=list)
    anthropic_tools: list[dict[str, Any]] = field(default_factory=list)
    info: list[dict[str, Any]] = field(default_factory=list)

    def close(self) -> None:
        for client in self.clients.values():
            try:
                client.close()
            except Exception:
                pass
        self.clients.clear()


def _headers_for(protocol: str, api_key: str | None) -> dict[str, str]:
    key = api_key or ""
    if protocol == "anthropic":
        return {
            "x-api-key": key,
            "Authorization": f"Bearer {key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def _estimate_tokens(value: Any) -> int:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
    return max(1, len(text) // 3)


def _context_budget(provider: ProviderConfig) -> int:
    return max(2048, int(provider.context_window) - int(provider.max_tokens) - 1024)


def _fit_openai_context(
    ctx: JobContext,
    messages: list[dict[str, Any]],
    system_text: str,
    tools: list[dict[str, Any]],
    provider: ProviderConfig,
) -> int:
    budget = _context_budget(provider)
    overhead = _estimate_tokens(system_text) + _estimate_tokens(tools) + 512
    if overhead >= budget:
        if not getattr(ctx, "_context_pressure_emitted", False):
            setattr(ctx, "_context_pressure_emitted", True)
            ctx.emit(
                "engine_context_pressure",
                "tool schema and system prompt nearly fill the context window",
                {"estimated_tokens": overhead, "context_window": provider.context_window},
            )
        return 0
    removed = 0
    while len(messages) > 2:
        conversation = [message for message in messages if message.get("role") != "system"]
        if _estimate_tokens(conversation) + overhead <= budget:
            break
        start = 2
        if start >= len(messages):
            break
        end = start + 1
        if messages[start].get("role") == "assistant":
            while end < len(messages) and messages[end].get("role") == "tool":
                end += 1
        del messages[start:end]
        removed += 1
    if removed:
        ctx.emit(
            "engine_context_trimmed",
            f"trimmed {removed} older message group(s) to fit the context window",
            {"removed_messages": removed, "context_window": provider.context_window},
        )
    return removed


def _fit_anthropic_context(
    ctx: JobContext,
    messages: list[dict[str, Any]],
    system_text: str,
    tools: list[dict[str, Any]],
    provider: ProviderConfig,
) -> int:
    budget = _context_budget(provider)
    overhead = _estimate_tokens(system_text) + _estimate_tokens(tools) + 512
    if overhead >= budget:
        if not getattr(ctx, "_context_pressure_emitted", False):
            setattr(ctx, "_context_pressure_emitted", True)
            ctx.emit(
                "engine_context_pressure",
                "tool schema and system prompt nearly fill the context window",
                {"estimated_tokens": overhead, "context_window": provider.context_window},
            )
        return 0
    removed = 0
    while len(messages) > 3:
        if _estimate_tokens(messages) + overhead <= budget:
            break
        if messages[1].get("role") == "assistant" and messages[2].get("role") == "user":
            del messages[1:3]
            removed += 1
        else:
            break
    if removed:
        ctx.emit(
            "engine_context_trimmed",
            f"trimmed {removed} older message group(s) to fit the context window",
            {"removed_messages": removed, "context_window": provider.context_window},
        )
    return removed


def _truncate_for_model(text: str, provider: ProviderConfig) -> str:
    limit = max(1000, int(provider.tool_result_chars))
    if len(text) <= limit:
        return text
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        value = None
    if isinstance(value, dict):
        compact = _compact_tool_result(value)
        if "decompilation" in compact or "verification" in compact:
            return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(
        {
            "truncated": True,
            "original_chars": len(text),
            "preview": text[:limit],
            "next": "Use get_evidence with the run_id/evidence_id to page the full record.",
        },
        ensure_ascii=False,
    )


class LLMEngineBase:
    name = "llm"
    protocol = ""

    def __init__(
        self,
        config: BackendConfig,
        provider: ProviderConfig | None = None,
        agent: AgentSpec | None = None,
        skills: list[dict[str, Any]] | None = None,
        mcps: list[McpServerConfig] | None = None,
    ):
        self.config = config
        self.provider = provider
        self.agent = agent
        self.skills = skills or []
        self.mcps = mcps or []

    @property
    def available(self) -> bool:
        if self.agent is not None:
            return self.agent.available
        return self.provider.available if self.provider else False

    @property
    def reason(self) -> str:
        if self.agent is not None:
            return self.agent.reason
        return self.provider.reason if self.provider else "no provider configured"

    def public(self, admin: bool = False) -> dict[str, Any]:
        if not self.provider:
            return {
                "name": self.name,
                "id": self.name,
                "label": self.name,
                "kind": "llm",
                "available": False,
                "reason": "no provider configured",
            }
        data = self.provider.public(admin=admin)
        data.update(
            {
                "name": self.name,
                "id": self.name,
                "label": self.agent.name if self.agent else self.provider.name,
                "kind": "llm",
                "provider_id": self.provider.id,
                "available": self.available,
                "reason": self.reason,
                "skills": [{"id": item.get("id"), "name": item.get("name")} for item in self.skills],
                "mcp": [
                    {
                        "id": item.id,
                        "name": item.name,
                        "transport": item.transport,
                        "tools": [tool.get("name") for tool in item.tools if tool.get("name")],
                    }
                    for item in self.mcps
                ],
                "api_key_set": self.provider.api_key_set,
            }
        )
        if self.agent is not None:
            data["agent_id"] = self.agent.id
            data["agent"] = self.agent.name
            data["system_prompt"] = self.agent.system_prompt if admin else None
        if admin and self.provider.api_key_set:
            data["api_key_hint"] = self.provider.api_key_hint
        return data

    # ------------------------------------------------------------------ setup
    def _system_text(self, provider: ProviderConfig) -> str:
        max_chars = min(80_000, max(8_000, int(provider.context_window) * 2))
        docs = self.skills or [
            {"id": "unpack-android-apk", "name": "APK unpack skill (built-in default)", "content": skill_text()}
        ]
        return system_prompt(
            docs,
            self.agent.system_prompt if self.agent else "",
            max_chars=max_chars,
        )

    def _emit_config(self, ctx: JobContext, provider: ProviderConfig, runtime: McpRuntime) -> None:
        skills = [
            {"id": item.get("id"), "name": item.get("name"), "source": item.get("source"), "references": item.get("references", [])}
            for item in self.skills
        ]
        if not skills:
            skills = [{"id": "unpack-android-apk", "name": "APK unpack skill (built-in default)", "source": "builtin", "references": read_skill_bundle(SKILL_PATH)[1]}]
        ctx.emit(
            "engine_config",
            f"{self.agent.name if self.agent else provider.name} · {provider.protocol}/{provider.model}",
            {
                "agent_id": self.agent.id if self.agent else provider.id,
                "agent": self.agent.name if self.agent else provider.name,
                "kind": "llm",
                "provider_id": provider.id,
                "provider": provider.name,
                "protocol": provider.protocol,
                "model": provider.model,
                "base_url": provider.base_url,
                "context_window": provider.context_window,
                "max_tokens": provider.max_tokens,
                "max_steps": provider.max_steps,
                "skills": skills,
                "mcp": runtime.info,
            },
        )
        for skill in skills:
            ctx.emit(
                "skill_loaded",
                f"skill: {skill.get('name') or skill.get('id')}",
                {"id": skill.get("id"), "name": skill.get("name"), "source": skill.get("source"), "references": skill.get("references", [])},
            )

    def _open_mcp(self, ctx: JobContext, provider: ProviderConfig) -> McpRuntime:
        runtime = McpRuntime()
        for server in self.mcps:
            try:
                client = McpClient(server, timeout_s=min(30, provider.timeout_s))
                client.connect()
                tools = client.list_tools()
                runtime.clients[server.id] = client
                aliases: list[str] = []
                for tool in tools:
                    original = str(tool.get("name") or "")
                    if not original:
                        continue
                    alias = tool_alias(server.id, original)
                    suffix = 2
                    while alias in runtime.mapping:
                        alias = (tool_alias(server.id, original)[:60] + f"_{suffix}")[:64]
                        suffix += 1
                    schema = tool.get("input_schema") or {"type": "object", "properties": {}}
                    description = f"[MCP {server.name}] {tool.get('description') or ''}"[:2000]
                    runtime.mapping[alias] = (server, original)
                    runtime.openai_tools.append(
                        {
                            "type": "function",
                            "function": {"name": alias, "description": description, "parameters": schema},
                        }
                    )
                    runtime.anthropic_tools.append(
                        {"name": alias, "description": description, "input_schema": schema}
                    )
                    aliases.append(original)
                runtime.info.append(
                    {
                        "id": server.id,
                        "name": server.name,
                        "transport": server.transport,
                        "tools": aliases,
                    }
                )
                ctx.emit(
                    "mcp_connected",
                    f"MCP {server.name} connected",
                    {"server": server.id, "transport": server.transport, "tools": aliases},
                )
            except Exception as exc:
                message = redact(str(exc))
                runtime.info.append(
                    {
                        "id": server.id,
                        "name": server.name,
                        "transport": server.transport,
                        "tools": [],
                        "error": message,
                    }
                )
                ctx.emit(
                    "mcp_error",
                    f"MCP {server.name} unavailable",
                    {"server": server.id, "error": message},
                )
        return runtime

    def _call_mcp(
        self,
        ctx: JobContext,
        runtime: McpRuntime,
        alias: str,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], bool, str]:
        server, tool_name = runtime.mapping[alias]
        ctx.emit(
            "mcp_tool_call",
            f"{server.name}/{tool_name}",
            {"server": server.id, "server_name": server.name, "tool": tool_name, "arguments": arguments},
        )
        try:
            result = runtime.clients[server.id].call_tool(tool_name, arguments)
            text = mcp_result_text(result)
            is_error = bool(result.get("isError"))
            ctx.emit(
                "mcp_tool_result",
                f"{server.name}/{tool_name}",
                {"server": server.id, "tool": tool_name, "is_error": is_error, "result": result},
            )
            return result, is_error, text
        except Exception as exc:
            error = {"code": "execution_failure", "message": redact(str(exc))}
            ctx.emit(
                "mcp_tool_result",
                f"{server.name}/{tool_name}",
                {"server": server.id, "tool": tool_name, "is_error": True, "error": error},
            )
            return error, True, json.dumps({"error": error}, ensure_ascii=False)

    # ------------------------------------------------------------------ prompts / inspect
    def _pre_inspect(self, ctx: JobContext, bridge: ToolBridge) -> tuple[dict[str, Any] | None, EngineResult | None]:
        result, is_error, _ = bridge.execute(
            "inspect_apk",
            {"apk_path": str(ctx.upload_path), "run_id": ctx.run_id, "deep_dex_scan": True},
        )
        if is_error:
            return None, EngineResult("failed", run_id=ctx.run_id, error=result, summary="APK inspection failed")
        inspection = result.get("inspection") or {}
        compact = {
            "package": (inspection.get("package") or {}).get("name"),
            "version": (inspection.get("package") or {}).get("version_name"),
            "shell": (inspection.get("packing") or {}).get("primary"),
            "mixed": (inspection.get("packing") or {}).get("mixed"),
            "packed": (inspection.get("packing") or {}).get("packed"),
            "abis": inspection.get("abis"),
            "frameworks": inspection.get("frameworks"),
            "dex_entries": [
                {"name": item.get("name"), "class_defs": (item.get("header") or {}).get("class_defs_size")}
                for item in inspection.get("dex_entries") or []
            ],
            "limitations": inspection.get("limitations") or [],
        }
        return compact, None

    # ------------------------------------------------------------------ openai loop
    def _run_openai(
        self,
        ctx: JobContext,
        provider: ProviderConfig,
        *,
        deadline: float | None = None,
        timeout_s: int | None = None,
    ) -> EngineResult:
        if not provider.available:
            return EngineResult(
                "failed",
                run_id=ctx.run_id,
                error={"code": "unsupported_provider", "message": provider.reason},
            )
        timeout_s = timeout_s or task_timeout_s(ctx)
        if deadline is None:
            deadline = time.monotonic() + timeout_s
        bridge = ToolBridge(ctx)
        if ctx.cancel.is_set():
            return self._cancelled_result(ctx, {}, [])
        compact, error = self._pre_inspect(ctx, bridge)
        if error:
            return error
        if ctx.cancel.is_set():
            return self._cancelled_result(ctx, {}, [])
        if time.monotonic() >= deadline:
            return self._timeout_result(ctx, {}, [], timeout_s)
        runtime = McpRuntime()
        warnings: list[str] = []
        usage_total: dict[str, Any] = {}
        try:
            runtime = self._open_mcp(ctx, provider)
            for item in runtime.info:
                if item.get("error"):
                    warnings.append(f"MCP {item.get('name')} unavailable: {item['error']}")
            self._emit_config(ctx, provider, runtime)
            system_text = self._system_text(provider)
            tools = bridge.tools_openai() + runtime.openai_tools
            messages: list[dict[str, Any]] = [
                {"role": "system", "content": system_text},
                {"role": "user", "content": user_prompt(ctx, compact)},
            ]
            url = endpoint_url(provider.base_url, "openai")
            headers = _headers_for("openai", provider.api_key)
            for step in range(provider.max_steps):
                if ctx.cancel.is_set():
                    return self._cancelled_result(ctx, usage_total, warnings)
                if time.monotonic() >= deadline:
                    return self._timeout_result(ctx, usage_total, warnings, timeout_s)
                _fit_openai_context(ctx, messages, system_text, tools, provider)
                payload: dict[str, Any] = {
                    "model": provider.model,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "auto",
                    "max_tokens": _max_tokens(ctx, provider),
                    "temperature": provider.temperature,
                    "stream": False,
                }
                data = _post_json(
                    url,
                    headers,
                    payload,
                    _request_budget(provider, deadline),
                    deadline=deadline,
                )
                _merge_usage(usage_total, data.get("usage"))
                message = ((data.get("choices") or [{}])[0] or {}).get("message") or {}
                content = message.get("content") or ""
                if content:
                    ctx.emit("engine_message", content[:4000], {"engine": provider.id, "step": step})
                    _append_transcript(ctx, {"step": step, "role": "assistant", "content": content})
                calls = message.get("tool_calls") or []
                ctx.emit(
                    "engine_usage",
                    f"step {step + 1}",
                    {
                        "step": step,
                        "usage": dict(usage_total),
                        "estimated_prompt_tokens": _estimate_tokens(messages) + _estimate_tokens(tools),
                        "context_window": provider.context_window,
                    },
                )
                if not calls:
                    break
                messages.append({"role": "assistant", "content": content, "tool_calls": calls})
                for index, call in enumerate(calls):
                    if ctx.cancel.is_set():
                        return self._cancelled_result(ctx, usage_total, warnings)
                    if time.monotonic() >= deadline:
                        return self._timeout_result(ctx, usage_total, warnings, timeout_s)
                    function = call.get("function") or {}
                    name = str(function.get("name") or "")
                    raw_arguments = function.get("arguments")
                    if isinstance(raw_arguments, dict):
                        arguments = raw_arguments
                    else:
                        try:
                            arguments = json.loads(raw_arguments or "{}")
                        except (json.JSONDecodeError, TypeError):
                            arguments = {}
                            ctx.emit("tool_error", name, {"error": "invalid JSON arguments"})
                    if not isinstance(arguments, dict):
                        arguments = {}
                    ctx.emit("tool_call", name, {"arguments": arguments, "step": step, "source": "mcp" if name in runtime.mapping else "tool"})
                    if name in runtime.mapping:
                        result, is_error, result_text = self._call_mcp(ctx, runtime, name, arguments)
                    else:
                        result, is_error, result_text = bridge.execute(name, arguments)
                        ctx.emit("tool_result", name, {"is_error": is_error, "result": result})
                    result_text = _truncate_for_model(result_text, provider)
                    _append_transcript(ctx, {"step": step, "role": "tool", "name": name, "result": result})
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.get("id") or f"call_{step}_{index}",
                            "content": result_text,
                        }
                    )
            else:
                warnings.append(f"{provider.name} reached max_steps={provider.max_steps}")
        except Exception as exc:
            message = redact(str(exc))
            if time.monotonic() >= deadline:
                ctx.emit("engine_timeout", f"{provider.name} exceeded the {timeout_s}s task timeout", {"error": message})
                return self._timeout_result(ctx, usage_total, warnings, timeout_s)
            ctx.emit("engine_error", f"{provider.name} request failed", {"error": message})
            cleanup = self._safety_cleanup(ctx)
            return EngineResult(
                "failed",
                run_id=ctx.run_id,
                error={"code": "execution_failure", "message": message},
                usage=usage_total,
                warnings=warnings,
                cleanup_status=cleanup["cleanup_status"],
                cleanup_error=cleanup.get("cleanup_error"),
                cleanup=cleanup,
            )
        finally:
            runtime.close()
        if ctx.cancel.is_set():
            return self._cancelled_result(ctx, usage_total, warnings)
        if time.monotonic() >= deadline:
            return self._timeout_result(ctx, usage_total, warnings, timeout_s)
        findings = self._finalize(ctx, bridge, warnings)
        summary = _summary_from_run(ctx)
        result = self._result(ctx, summary, usage_total, warnings, findings)
        result.usage = usage_total
        return result

    # ------------------------------------------------------------------ anthropic loop
    def _run_anthropic(
        self,
        ctx: JobContext,
        provider: ProviderConfig,
        *,
        deadline: float | None = None,
        timeout_s: int | None = None,
    ) -> EngineResult:
        if not provider.available:
            return EngineResult(
                "failed",
                run_id=ctx.run_id,
                error={"code": "unsupported_provider", "message": provider.reason},
            )
        timeout_s = timeout_s or task_timeout_s(ctx)
        if deadline is None:
            deadline = time.monotonic() + timeout_s
        bridge = ToolBridge(ctx)
        if ctx.cancel.is_set():
            return self._cancelled_result(ctx, {}, [])
        compact, error = self._pre_inspect(ctx, bridge)
        if error:
            return error
        if ctx.cancel.is_set():
            return self._cancelled_result(ctx, {}, [])
        if time.monotonic() >= deadline:
            return self._timeout_result(ctx, {}, [], timeout_s)
        runtime = McpRuntime()
        warnings: list[str] = []
        usage_total: dict[str, Any] = {}
        try:
            runtime = self._open_mcp(ctx, provider)
            for item in runtime.info:
                if item.get("error"):
                    warnings.append(f"MCP {item.get('name')} unavailable: {item['error']}")
            self._emit_config(ctx, provider, runtime)
            system_text = self._system_text(provider)
            tools = bridge.tools_anthropic() + runtime.anthropic_tools
            messages: list[dict[str, Any]] = [
                {"role": "user", "content": user_prompt(ctx, compact)},
            ]
            url = endpoint_url(provider.base_url, "anthropic")
            headers = _headers_for("anthropic", provider.api_key)
            for step in range(provider.max_steps):
                if ctx.cancel.is_set():
                    return self._cancelled_result(ctx, usage_total, warnings)
                if time.monotonic() >= deadline:
                    return self._timeout_result(ctx, usage_total, warnings, timeout_s)
                _fit_anthropic_context(ctx, messages, system_text, tools, provider)
                payload: dict[str, Any] = {
                    "model": provider.model,
                    "system": system_text,
                    "messages": messages,
                    "tools": tools,
                    "max_tokens": _max_tokens(ctx, provider),
                }
                data = _post_json(
                    url,
                    headers,
                    payload,
                    _request_budget(provider, deadline),
                    deadline=deadline,
                )
                _merge_usage(usage_total, data.get("usage"))
                content = data.get("content") or []
                tool_uses = [block for block in content if isinstance(block, dict) and block.get("type") == "tool_use"]
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = str(block.get("text") or "")
                        if text:
                            ctx.emit("engine_message", text[:4000], {"engine": provider.id, "step": step})
                            _append_transcript(ctx, {"step": step, "role": "assistant", "content": text})
                ctx.emit(
                    "engine_usage",
                    f"step {step + 1}",
                    {
                        "step": step,
                        "usage": dict(usage_total),
                        "estimated_prompt_tokens": _estimate_tokens(messages) + _estimate_tokens(tools) + _estimate_tokens(system_text),
                        "context_window": provider.context_window,
                    },
                )
                if not tool_uses:
                    break
                messages.append({"role": "assistant", "content": content})
                results: list[dict[str, Any]] = []
                for block in tool_uses:
                    if ctx.cancel.is_set():
                        return self._cancelled_result(ctx, usage_total, warnings)
                    if time.monotonic() >= deadline:
                        return self._timeout_result(ctx, usage_total, warnings, timeout_s)
                    name = str(block.get("name") or "")
                    arguments = block.get("input") or {}
                    if not isinstance(arguments, dict):
                        arguments = {}
                    ctx.emit("tool_call", name, {"arguments": arguments, "step": step, "source": "mcp" if name in runtime.mapping else "tool"})
                    if name in runtime.mapping:
                        result, is_error, result_text = self._call_mcp(ctx, runtime, name, arguments)
                    else:
                        result, is_error, result_text = bridge.execute(name, arguments)
                        ctx.emit("tool_result", name, {"is_error": is_error, "result": result})
                    result_text = _truncate_for_model(result_text, provider)
                    _append_transcript(ctx, {"step": step, "role": "tool", "name": name, "result": result})
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.get("id"),
                            "content": result_text,
                            "is_error": is_error,
                        }
                    )
                messages.append({"role": "user", "content": results})
            else:
                warnings.append(f"{provider.name} reached max_steps={provider.max_steps}")
        except Exception as exc:
            message = redact(str(exc))
            if time.monotonic() >= deadline:
                ctx.emit("engine_timeout", f"{provider.name} exceeded the {timeout_s}s task timeout", {"error": message})
                return self._timeout_result(ctx, usage_total, warnings, timeout_s)
            ctx.emit("engine_error", f"{provider.name} request failed", {"error": message})
            cleanup = self._safety_cleanup(ctx)
            return EngineResult(
                "failed",
                run_id=ctx.run_id,
                error={"code": "execution_failure", "message": message},
                usage=usage_total,
                warnings=warnings,
                cleanup_status=cleanup["cleanup_status"],
                cleanup_error=cleanup.get("cleanup_error"),
                cleanup=cleanup,
            )
        finally:
            runtime.close()
        if ctx.cancel.is_set():
            return self._cancelled_result(ctx, usage_total, warnings)
        if time.monotonic() >= deadline:
            return self._timeout_result(ctx, usage_total, warnings, timeout_s)
        findings = self._finalize(ctx, bridge, warnings)
        summary = _summary_from_run(ctx)
        result = self._result(ctx, summary, usage_total, warnings, findings)
        result.usage = usage_total
        return result

    # ------------------------------------------------------------------ finalize
    def _extract_static_dex(self, ctx: JobContext) -> int:
        """Extract, repair and verify top-level classes*.dex of a plain APK.

        The ZIP entries are kept under ``dexdump/raw`` and repaired into
        ``dexdump/fixed`` with the run's expected package before verification.
        Without the repair step a repackaged APK whose checksum/SHA-1 header is
        stale would be reported as partial even though its content is intact.
        """
        run_dir = ctx.run_dir
        raw_dir = run_dir / "dexdump" / "raw"
        fixed_dir = run_dir / "dexdump" / "fixed"
        extracted: list[Path] = []
        try:
            with zipfile.ZipFile(ctx.upload_path) as archive:
                names = [
                    name
                    for name in archive.namelist()
                    if re.fullmatch(r"classes\d*\.dex", name)
                ]
                if not names:
                    return 0
                names.sort(
                    key=lambda value: int(
                        re.match(r"classes(\d*)\.dex", value).group(1) or "1"
                    )
                )
                raw_dir.mkdir(parents=True, exist_ok=True)
                fixed_dir.mkdir(parents=True, exist_ok=True)
                for name in names:
                    destination = raw_dir / name
                    with archive.open(name) as source, open(destination, "wb") as output:
                        shutil.copyfileobj(source, output)
                    extracted.append(destination)
        except (OSError, zipfile.BadZipFile, ValueError):
            return 0
        package = str(
            run_expected_package(run_dir)
            or ((_inspection_from_run(ctx).get("package") or {}).get("name"))
            or ""
        )
        repair: dict[str, Any] | None = None
        repair_error: str | None = None
        try:
            from apk_unpack.providers.dex import repair_dex_set

            repair = repair_dex_set(
                extracted,
                fixed_dir,
                include_stub=True,
                package=package or None,
            )
        except Exception as exc:  # pragma: no cover - defensive against IO errors
            repair_error = redact(str(exc))
        skipped = {
            str(Path(str(item.get("path") or ""))): item
            for item in (repair or {}).get("skipped") or []
            if isinstance(item, dict)
        }
        # Keep unrepairable sources visible for verification/inspection, exactly
        # as the previous copy-only path did.  Do not overwrite a repaired file.
        for source in extracted:
            if str(source) not in skipped:
                continue
            destination = fixed_dir / source.name
            if destination.exists():
                continue
            try:
                shutil.copyfile(source, destination)
            except OSError:
                continue
        ctx.static_dex_repair = repair
        if repair_error and repair is None:
            ctx.static_dex_repair = {
                "status": "error",
                "files": [],
                "skipped": [{"path": str(path)} for path in extracted],
                "error": repair_error,
            }
        if extracted:
            report = ctx.static_dex_repair or {}
            ctx.emit(
                "static_dex_extracted",
                f"extracted {len(extracted)} DEX file(s) from the APK",
                {
                    "files": [path.name for path in extracted],
                    "raw_paths": [str(path) for path in extracted],
                    "run_id": ctx.run_id,
                    "expected_package": package or None,
                    "repair_status": report.get("status"),
                    "repair_error": report.get("error"),
                    "repaired": len(report.get("files") or []),
                    "skipped": len(report.get("skipped") or []),
                },
            )
        return len(extracted)

    def _safety_cleanup(self, ctx: JobContext) -> dict[str, Any]:
        """Run cleanup once and return a structured status; errors are kept."""
        if not ctx.options.get("cleanup", True):
            return cleanup_summary(
                {
                    "cleanup_status": "skipped",
                    "restored": [],
                    "failed": [],
                    "remaining_mutations": [],
                },
                message="cleanup disabled",
            )
        if ctx.cleanup_called and isinstance(ctx.cleanup_result, dict):
            return ctx.cleanup_result
        try:
            result = ctx.service.cleanup_run(
                ctx.run_id,
                serial=ctx.serial,
                delete_run=False,
                prune_raw_dumps=bool(ctx.options.get("prune_raw", False)),
            )
            summary = cleanup_summary(result, message="safety-net cleanup completed")
            ctx.cleanup_result = summary
            ctx.cleanup_called = not summary["cleanup_incomplete"]
            if summary["cleanup_incomplete"]:
                ctx.emit(
                    "cleanup.safety_net_failed",
                    "safety-net cleanup incomplete",
                    {
                        "cleanup_status": summary["cleanup_status"],
                        "cleanup_error": summary.get("cleanup_error"),
                        "remaining_mutations": summary.get("remaining_mutations"),
                    },
                )
            else:
                ctx.emit("cleanup.safety_net", "safety-net cleanup completed")
            return summary
        except Exception as exc:
            message = redact(str(exc))
            summary = cleanup_summary(None, message="safety-net cleanup failed: " + message)
            summary["cleanup_error"] = message
            ctx.cleanup_result = summary
            ctx.emit("cleanup.safety_net_failed", "safety-net cleanup failed", {"error": message[:1000]})
            return summary

    def _cancelled_result(
        self,
        ctx: JobContext,
        usage: dict[str, Any] | None,
        warnings: list[str],
    ) -> EngineResult:
        cleanup = self._safety_cleanup(ctx)
        error: dict[str, Any] = {"code": "cancelled", "message": "cancelled by user"}
        combined = list(warnings or [])
        if cleanup["cleanup_incomplete"]:
            error["cleanup_status"] = "incomplete"
            error["cleanup_error"] = cleanup.get("cleanup_error")
            combined.append("cleanup incomplete after cancel: " + str(cleanup.get("cleanup_error") or cleanup.get("message")))
        return EngineResult(
            "cancelled",
            run_id=ctx.run_id,
            summary="cancelled",
            error=error,
            usage=usage or None,
            warnings=combined,
            transcript_path=str(ctx.transcript_path) if ctx.transcript_path.exists() else None,
            cleanup_status=cleanup["cleanup_status"],
            cleanup_error=cleanup.get("cleanup_error"),
            cleanup=cleanup,
        )

    def _timeout_result(
        self,
        ctx: JobContext,
        usage: dict[str, Any] | None,
        warnings: list[str],
        timeout_s: int,
    ) -> EngineResult:
        """Stop the loop on the whole-task deadline and record cleanup."""
        cleanup = self._safety_cleanup(ctx)
        package = run_expected_package(ctx.run_dir)
        verdict = assess_fixed_dex(ctx.run_dir, package, apk_path=ctx.upload_path)
        outcome = "partial" if verdict["verified"] else "failed"
        error: dict[str, Any] = {
            "code": "timeout",
            "message": f"job exceeded the whole-task timeout of {timeout_s}s",
            "reasons": verdict["reasons"],
        }
        combined = list(warnings or []) + [f"task timeout after {timeout_s}s"]
        if cleanup["cleanup_incomplete"]:
            error["cleanup_status"] = "incomplete"
            error["cleanup_error"] = cleanup.get("cleanup_error")
            combined.append("cleanup incomplete after timeout: " + str(cleanup.get("cleanup_error") or cleanup.get("message")))
        return EngineResult(
            outcome,
            run_id=ctx.run_id,
            summary="timed out",
            error=error,
            usage=usage or None,
            warnings=combined,
            transcript_path=str(ctx.transcript_path) if ctx.transcript_path.exists() else None,
            cleanup_status=cleanup["cleanup_status"],
            cleanup_error=cleanup.get("cleanup_error"),
            cleanup=cleanup,
        )

    def _finalize(self, ctx: JobContext, bridge: ToolBridge, warnings: list[str]) -> dict[str, Any]:
        findings: dict[str, Any] = {"tool_errors": [], "cleanup": None}
        run_dir = ctx.run_dir
        if not run_dir.is_dir():
            warnings.append("no run directory was produced")
            findings["cleanup"] = cleanup_summary(
                {"cleanup_status": "skipped", "restored": [], "failed": [], "remaining_mutations": []},
                message="no run directory to clean",
            )
            return findings
        fixed = list(run_dir.glob("dexdump/fixed/*.dex"))
        raw = list(run_dir.glob("dexdump/raw/*.dex"))
        if not fixed and raw:
            result, is_error, _ = bridge.execute("repair_android_dex", {"run_id": ctx.run_id})
            if is_error:
                findings["tool_errors"].append("repair_android_dex")
                warnings.append("repair failed: " + json.dumps(result, ensure_ascii=False)[:500])
        fixed = list(run_dir.glob("dexdump/fixed/*.dex"))
        if not fixed:
            # Unpacked/plain APKs do not need a runtime dump: the DEX files are
            # already in the ZIP. Packed APKs are the opposite: their top-level
            # classes*.dex is only a loader, so never present it as unpacked.
            inspection = _inspection_from_run(ctx)
            packing = inspection.get("packing") or {}
            suspicious_dex = any(
                item.get("packed_stub")
                for item in (inspection.get("dex_entries") or [])
                if isinstance(item, dict)
            )
            if packing.get("packed") is True or packing.get("application_class_suspicious") or suspicious_dex:
                warnings.append("packed APK: skipped static DEX extraction (shell loader only)")
            else:
                extracted = self._extract_static_dex(ctx)
                if extracted:
                    warnings.append(f"statically extracted {extracted} DEX file(s) from the APK")
                    repair = ctx.static_dex_repair or {}
                    if repair.get("status"):
                        warnings.append(f"static DEX repair: {repair.get('status')}")
                    fixed = list(run_dir.glob("dexdump/fixed/*.dex"))
        if fixed:
            result, is_error, _ = bridge.execute(
                "verify_android_dex",
                {"run_id": ctx.run_id, "run_jadx": False},
            )
            if is_error:
                findings["tool_errors"].append("verify_android_dex")
                warnings.append("verify failed: " + json.dumps(result, ensure_ascii=False)[:500])
        if ctx.options.get("jadx", True):
            sources = list(run_dir.glob("dexdump/jadx/**/sources"))
            if not sources and fixed:
                result, is_error, _ = bridge.execute(
                    "decompile_android_apk",
                    {"run_id": ctx.run_id, "source": "dex"},
                )
                if is_error:
                    findings["tool_errors"].append("decompile_android_apk")
                    warnings.append("decompile failed (DEX validation still applies): " + json.dumps(result, ensure_ascii=False)[:500])
            elif not sources and not fixed:
                result, is_error, _ = bridge.execute(
                    "decompile_android_apk",
                    {
                        "run_id": ctx.run_id,
                        "source": "apk",
                        "apk_path": str(ctx.upload_path),
                    },
                )
                if is_error:
                    findings["tool_errors"].append("decompile_android_apk")
                    warnings.append("static APK decompile failed: " + json.dumps(result, ensure_ascii=False)[:500])
        if ctx.options.get("cleanup", True) and not ctx.cleanup_called:
            result, is_error, _ = bridge.execute(
                "cleanup_run",
                {"run_id": ctx.run_id, "serial": ctx.serial, "prune_raw_dumps": bool(ctx.options.get("prune_raw", False))},
            )
            if is_error:
                findings["tool_errors"].append("cleanup_run")
                summary = cleanup_summary(None, message="cleanup tool failed")
                summary["cleanup_error"] = json.dumps(result, ensure_ascii=False, default=str)[:1000]
                findings["cleanup"] = summary
                warnings.append("cleanup failed: " + summary["cleanup_error"][:500])
            else:
                findings["cleanup"] = cleanup_summary(result)
        if findings["cleanup"] is None:
            findings["cleanup"] = ctx.cleanup_result or cleanup_summary(
                {"cleanup_status": "skipped", "restored": [], "failed": [], "remaining_mutations": []},
                message="cleanup disabled",
            )
        if findings["cleanup"].get("cleanup_incomplete"):
            warnings.append(
                "cleanup incomplete: "
                + str(findings["cleanup"].get("cleanup_error") or findings["cleanup"].get("message"))
            )
        return findings

    def _result(
        self,
        ctx: JobContext,
        summary: str,
        usage: dict[str, Any] | None,
        warnings: list[str],
        findings: dict[str, Any] | None = None,
    ) -> EngineResult:
        findings = findings or {}
        package = run_expected_package(ctx.run_dir)
        fixed = list(ctx.run_dir.glob("dexdump/fixed/*.dex"))
        raw = list(ctx.run_dir.glob("dexdump/raw/*.dex"))
        sources = [path for path in ctx.run_dir.glob("dexdump/jadx/**/sources") if path.is_dir()]
        verdict = assess_fixed_dex(ctx.run_dir, package, apk_path=ctx.upload_path)
        error: dict[str, Any] | None = None
        if verdict["verified"]:
            outcome = "success"
        elif verdict.get("recoverable") and not verdict["usable"]:
            outcome = "partial"
            error = {"code": "partial_bytecode", "message": "Recovered target bytecode is available for best-effort JADX; incomplete methods and missing bytes are retained in the quality report.", "reasons": verdict["reasons"]}
        elif verdict["repaired_unverified"]:
            # A repaired DEX exists but does not match the APK source and came
            # from an integrity-damaged raw dump: keep it, but never call it
            # verified output.
            outcome = "partial"
            reasons = list(verdict.get("reasons") or ["repaired_unverified"])
            error = {
                "code": "repaired_unverified",
                "message": "recovered DEX was repaired from an integrity-damaged dump "
                "and does not match the APK source: "
                + ", ".join(reasons),
                "reasons": reasons,
                "expected_package": package or None,
            }
        elif fixed or raw or sources:
            outcome = "partial"
            if not fixed and not raw and sources:
                code = "sources_only"
                reasons = ["sources_only"]
            else:
                code = verdict["code"] or "unverified"
                reasons = verdict["reasons"] or ["unverified"]
            error = {
                "code": code,
                "message": "no verified target DEX was produced: " + ", ".join(reasons),
                "reasons": reasons,
                "expected_package": package or None,
            }
        else:
            outcome = "failed"
            error = {
                "code": verdict["code"] or "no_target_dex",
                "message": "no DEX artifacts were recovered: " + ", ".join(verdict["reasons"] or ["no_target_dex"]),
                "reasons": verdict["reasons"] or ["no_target_dex"],
                "expected_package": package or None,
            }
        state = read_run_state(ctx.run_dir)
        inspection = (state.get("artifacts") or {}).get("inspection") or {}
        packing = inspection.get("packing") or {}
        if not fixed and not raw and (packing.get("packed") or packing.get("application_class_suspicious")):
            # Static source/resources can be useful, but they must not hide the
            # actual failure to recover business DEX from a protected process.
            failed_attempts = [
                {"method": item.get("method"),
                 "code": (item.get("error") or {}).get("code"),
                 "message": str((item.get("error") or {}).get("message") or "")[:1000]}
                for item in state.get("attempts") or []
                if isinstance(item, dict) and item.get("status") == "failed"
            ]
            code = "runtime_dump_failed" if failed_attempts else "packed_static_only"
            error = {
                "code": code,
                "message": "Packed APK has no recovered business DEX. "
                           + ("Runtime extraction attempts failed. " if failed_attempts else "")
                           + "Static shell code and resources do not establish successful unpacking.",
                "reasons": [code, *((error or {}).get("reasons") or [])],
                "expected_package": package or None,
                "details": {"shell": packing.get("primary"),
                            "device_abi": (state.get("device") or {}).get("abi"),
                            "static_sources_only": bool(sources),
                            "failed_attempts": failed_attempts},
            }
        # Keep good DEX artifacts, but do not call a requested source export
        # complete when JADX failed or left unreconstructed methods.
        decompilation = (state.get("artifacts") or {}).get("decompilation")
        if outcome == "success" and (
            decompilation_incomplete(decompilation)
            or "decompile_android_apk" in (findings.get("tool_errors") or [])
        ):
            outcome = "partial"
            error = decompilation_error(decompilation)
            warnings = [*warnings, error["message"]]
        if ctx.options.get("force_dump") and not (
            (read_run_state(ctx.run_dir).get("artifacts") or {}).get("last_dump") or {}
        ).get("candidates"):
            # Static recovery remains useful but cannot satisfy an explicitly
            # requested runtime dump that the model omitted or failed.
            if outcome == "success":
                outcome = "partial"
            if verdict["verified"]:
                error = {"code": "runtime_dump_incomplete", "message": "Static DEX verified, but the requested runtime dump produced no accepted DEX"}
                warnings = [*warnings, error["message"]]
        # A failed critical tool must never be presented as a clean success.
        critical = [
            item
            for item in (findings.get("tool_errors") or [])
            if item in ("repair_android_dex", "verify_android_dex", "cleanup_run")
        ]
        if critical and outcome == "success":
            outcome = "partial"
            error = {
                "code": "tool_failed",
                "message": "critical unpack tool(s) failed: " + ", ".join(critical),
                "tools": critical,
            }
        elif critical and isinstance(error, dict):
            error.setdefault("tools", critical)
        cleanup = findings.get("cleanup") or ctx.cleanup_result
        cleanup_status = cleanup.get("cleanup_status") if isinstance(cleanup, dict) else None
        cleanup_error = cleanup.get("cleanup_error") if isinstance(cleanup, dict) else None
        if isinstance(cleanup, dict) and cleanup.get("cleanup_incomplete"):
            if outcome == "success":
                outcome = "partial"
            if error is None:
                error = {
                    "code": "cleanup_incomplete",
                    "message": "artifacts were recovered but device cleanup did not complete",
                }
            error["cleanup_status"] = "incomplete"
            error["cleanup_error"] = cleanup_error or cleanup.get("message")
        return EngineResult(
            outcome,
            run_id=ctx.run_id,
            summary=summary,
            error=error,
            usage=usage,
            warnings=list(warnings or []),
            transcript_path=str(ctx.transcript_path) if ctx.transcript_path.exists() else None,
            cleanup_status=cleanup_status,
            cleanup_error=cleanup_error,
            cleanup=cleanup if isinstance(cleanup, dict) else None,
        )


    def _run_auto(
        self,
        ctx: JobContext,
        provider: ProviderConfig,
        primary: str | None = None,
    ) -> EngineResult:
        """Run one API protocol and fall back to the other on endpoint/protocol errors.

        This is what makes a URL/key usable by either agent base: an OpenAI-style
        endpoint can serve a Claude-named agent and an Anthropic-style endpoint can
        serve a DeepSeek-named agent, as long as the key is valid.
        """
        base = str(provider.base_url or "").lower()
        model = str(provider.model or "").lower()
        if primary in ("openai", "anthropic"):
            first = primary
        elif "/anthropic" in base or "/messages" in base or model.startswith("claude"):
            first = "anthropic"
        else:
            first = "openai"
        second = "anthropic" if first == "openai" else "openai"
        order = [first, second]
        # One wall-clock budget covers both protocol attempts: an auto engine
        # must not double the configured timeout by falling back.
        timeout_s = task_timeout_s(ctx)
        deadline = time.monotonic() + timeout_s
        attempts: list[str] = []
        first_failure: EngineResult | None = None
        for protocol in order:
            attempts.append(protocol)
            if protocol == "openai":
                result = self._run_openai(
                    ctx, provider, deadline=deadline, timeout_s=timeout_s
                )
            else:
                result = self._run_anthropic(
                    ctx, provider, deadline=deadline, timeout_s=timeout_s
                )
            if result.outcome in ("success", "partial", "cancelled"):
                if attempts and attempts[0] != protocol:
                    result.warnings = list(result.warnings) + [
                        f"auto protocol: {attempts[0]} endpoint failed, {protocol} succeeded"
                    ]
                return result
            if first_failure is None:
                first_failure = result
            code = str((result.error or {}).get("code") or "")
            if code in ("cancelled",):
                return result
        assert first_failure is not None
        first_failure.warnings = list(first_failure.warnings) + [
            f"auto protocol: both OpenAI and Anthropic requests failed ({', '.join(attempts)})"
        ]
        return first_failure


class ProviderOpenAIEngine(LLMEngineBase):
    protocol = "openai"

    def __init__(
        self,
        config: BackendConfig,
        provider: ProviderConfig,
        agent: AgentSpec | None = None,
        skills: list[dict[str, Any]] | None = None,
        mcps: list[McpServerConfig] | None = None,
    ):
        super().__init__(config, provider=provider, agent=agent, skills=skills, mcps=mcps)

    @property
    def name(self) -> str:  # type: ignore[override]
        return self.agent.id if self.agent else self.provider.id if self.provider else "openai"

    def run(self, ctx: JobContext) -> EngineResult:
        assert self.provider is not None
        return self._run_openai(ctx, self.provider)


class ProviderAnthropicEngine(LLMEngineBase):
    protocol = "anthropic"

    def __init__(
        self,
        config: BackendConfig,
        provider: ProviderConfig,
        agent: AgentSpec | None = None,
        skills: list[dict[str, Any]] | None = None,
        mcps: list[McpServerConfig] | None = None,
    ):
        super().__init__(config, provider=provider, agent=agent, skills=skills, mcps=mcps)

    @property
    def name(self) -> str:  # type: ignore[override]
        return self.agent.id if self.agent else self.provider.id if self.provider else "anthropic"

    def run(self, ctx: JobContext) -> EngineResult:
        assert self.provider is not None
        return self._run_anthropic(ctx, self.provider)


class ProviderAutoEngine(LLMEngineBase):
    protocol = "auto"

    def __init__(
        self,
        config: BackendConfig,
        provider: ProviderConfig,
        agent: AgentSpec | None = None,
        skills: list[dict[str, Any]] | None = None,
        mcps: list[McpServerConfig] | None = None,
    ):
        super().__init__(config, provider=provider, agent=agent, skills=skills, mcps=mcps)

    @property
    def name(self) -> str:  # type: ignore[override]
        return self.agent.id if self.agent else self.provider.id if self.provider else "auto"

    def run(self, ctx: JobContext) -> EngineResult:
        assert self.provider is not None
        return self._run_auto(ctx, self.provider)


def _legacy_provider(cfg: Any, protocol: str, provider_id: str) -> ProviderConfig:
    return ProviderConfig(
        id=provider_id,
        name=cfg.name,
        protocol=protocol,
        base_url=cfg.base_url,
        model=cfg.model,
        api_key=cfg.api_key,
        context_window=getattr(cfg, "context_window", 65536),
        max_tokens=getattr(cfg, "max_tokens", 4096),
        max_steps=cfg.max_steps,
        timeout_s=cfg.timeout_s,
        temperature=getattr(cfg, "temperature", 0.1),
        tool_result_chars=getattr(cfg, "tool_result_chars", 16000),
        enabled=True,
    )


class DeepSeekEngine(LLMEngineBase):
    name = "deepseek"
    protocol = "openai"

    def __init__(self, config: BackendConfig):
        super().__init__(config, provider=_legacy_provider(config.engines["deepseek"], "openai", "deepseek"))

    def run(self, ctx: JobContext) -> EngineResult:
        assert self.provider is not None
        return self._run_auto(ctx, self.provider, primary="openai")


class ClaudeEngine(LLMEngineBase):
    name = "claude"
    protocol = "anthropic"

    def __init__(self, config: BackendConfig):
        super().__init__(config, provider=_legacy_provider(config.engines["claude"], "anthropic", "claude"))

    def run(self, ctx: JobContext) -> EngineResult:
        assert self.provider is not None
        return self._run_auto(ctx, self.provider, primary="anthropic")


# ---------------------------------------------------------------------------
# provider helpers
# ---------------------------------------------------------------------------


def _max_tokens(ctx: JobContext, provider: ProviderConfig) -> int:
    value = provider.max_tokens
    override = ctx.options.get("llm_max_tokens")
    if override is not None:
        try:
            value = int(override)
        except (TypeError, ValueError):
            value = provider.max_tokens
    return max(1, min(int(value), int(provider.max_tokens)))


def test_provider(provider: ProviderConfig, override_key: str | None = None) -> dict[str, Any]:
    if provider.protocol == "auto":
        attempts: list[dict[str, Any]] = []
        base = str(provider.base_url or "").lower()
        model = str(provider.model or "").lower()
        order = ("anthropic", "openai") if ("/anthropic" in base or "/messages" in base or model.startswith("claude")) else ("openai", "anthropic")
        for protocol in order:
            attempt = test_provider(replace(provider, protocol=protocol), override_key)
            attempts.append(
                {
                    "protocol": protocol,
                    "ok": bool(attempt.get("ok")),
                    "endpoint": attempt.get("endpoint"),
                    "error": attempt.get("error"),
                    "reply": attempt.get("reply"),
                    "latency_ms": attempt.get("latency_ms"),
                }
            )
            if attempt.get("ok"):
                attempt["protocol"] = "auto"
                attempt["attempts"] = attempts
                return attempt
        return {
            "ok": False,
            "protocol": "auto",
            "model": provider.model,
            "base_url": provider.base_url,
            "attempts": attempts,
            "error": "OpenAI 和 Anthropic 两种协议的测试请求都失败",
        }
    key = (override_key or provider.api_key or "").strip()
    started = time.monotonic()
    result: dict[str, Any] = {
        "ok": False,
        "protocol": provider.protocol,
        "model": provider.model,
        "base_url": provider.base_url,
        "endpoint": endpoint_url(provider.base_url, provider.protocol),
    }
    if not key:
        result["error"] = "missing API key"
        return result
    headers = _headers_for(provider.protocol, key)
    try:
        if provider.protocol == "anthropic":
            payload = {
                "model": provider.model,
                "max_tokens": 32,
                "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
            }
        else:
            payload = {
                "model": provider.model,
                "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
                "max_tokens": 32,
                "temperature": 0,
            }
        data = _post_json(result["endpoint"], headers, payload, min(60, provider.timeout_s), attempts=1)
        if provider.protocol == "anthropic":
            reply = "".join(
                str(block.get("text") or "")
                for block in data.get("content") or []
                if isinstance(block, dict) and block.get("type") == "text"
            )
        else:
            reply = str(((data.get("choices") or [{}])[0] or {}).get("message", {}).get("content") or "")
        result.update(
            {
                "ok": True,
                "reply": reply[:1000],
                "usage": data.get("usage") or {},
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
            }
        )
    except Exception as exc:
        result.update(
            {
                "error": redact(str(exc)),
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
            }
        )
    return result


def list_provider_models(provider: ProviderConfig, override_key: str | None = None) -> dict[str, Any]:
    fallback = list(MODEL_PRESETS.get(provider.protocol, []))
    if provider.protocol == "anthropic":
        return {
            "models": fallback,
            "source": "preset",
            "note": "Anthropic 协议没有公开的 /models 端点，以下为常用模型名。",
        }
    key = (override_key or provider.api_key or "").strip()
    if not key:
        return {"models": fallback, "source": "preset", "error": "missing API key"}
    try:
        data = _get_json(
            models_url(provider.base_url),
            _headers_for("openai", key),
            min(30, provider.timeout_s),
        )
        models = sorted(
            {
                str(item.get("id"))
                for item in data.get("data") or []
                if isinstance(item, dict) and item.get("id")
            }
        )
        return {
            "models": models or fallback,
            "source": "api" if models else "preset",
            "endpoint": models_url(provider.base_url),
        }
    except Exception as exc:
        return {
            "models": fallback,
            "source": "preset",
            "endpoint": models_url(provider.base_url),
            "error": redact(str(exc)),
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _post_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_s: int,
    attempts: int = 3,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    last_error: Exception | None = None
    attempts = max(1, attempts)
    for attempt in range(attempts):
        if deadline is not None and time.monotonic() >= deadline:
            raise RuntimeError("request failed: whole-task deadline exceeded")
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            detail = _safe_body(exc)
            if exc.code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
                last_error = RuntimeError(f"HTTP {exc.code}: {detail}")
                continue
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise RuntimeError(f"request failed: {exc}") from exc
    raise RuntimeError(f"request failed: {last_error}")


def _get_json(url: str, headers: dict[str, str], timeout_s: int, attempts: int = 1) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    last_error: Exception | None = None
    attempts = max(1, attempts)
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            detail = _safe_body(exc)
            if exc.code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
                last_error = RuntimeError(f"HTTP {exc.code}: {detail}")
                continue
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise RuntimeError(f"request failed: {exc}") from exc
    raise RuntimeError(f"request failed: {last_error}")


def _safe_body(exc: Any) -> str:
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except Exception:
        body = ""
    return redact(body[:2000])


def _merge_usage(total: dict[str, Any], usage: Any) -> None:
    if not isinstance(usage, dict):
        return
    for key, value in usage.items():
        if isinstance(value, (int, float)):
            total[key] = total.get(key, 0) + value


def _append_transcript(ctx: JobContext, record: dict[str, Any]) -> None:
    try:
        with open(ctx.transcript_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def _extract_last_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for index in range(len(text) - 1, -1, -1):
        if text[index] != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    return None


def _inspection_from_run(ctx: JobContext) -> dict:
    try:
        state = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(state, dict):
        return {}
    for container in (state.get("artifacts") or {}, state):
        if isinstance(container, dict) and isinstance(container.get("inspection"), dict):
            return container["inspection"]
    return {}


def _summary_from_run(ctx: JobContext) -> str:
    try:
        state = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "run state unavailable"
    artifacts = state.get("artifacts") or {}
    verification = artifacts.get("verification") or {}
    fixed = list(ctx.run_dir.glob("dexdump/fixed/*.dex"))
    summary = {
        "stage": state.get("stage"),
        "cleanup": state.get("cleanup_status"),
        "dex_files": len(fixed),
        "classes": verification.get("total_classes"),
        "complete": verification.get("complete"),
        "artifacts": state.get("artifacts", {}).get("last_dump", {}).get("method")
        if isinstance(state.get("artifacts"), dict)
        else None,
    }
    return json.dumps(summary, ensure_ascii=False)


def build_engines(config: BackendConfig) -> dict[str, Any]:
    """Legacy env-only engine registry (kept for direct API compatibility)."""
    return {
        "agent": AgentEngine(config),
        "deepseek": DeepSeekEngine(config),
        "claude": ClaudeEngine(config),
    }
