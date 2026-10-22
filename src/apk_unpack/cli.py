from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path
from typing import Any

from .application.workflow import ToolService
from .composition import build_service
from .domain.errors import AnalysisError, project_error
from .mcp_server import run_server
from .setup import apply_plan, build_plan

METHODS = ["auto", "frida_inmemory", "frida_inmemory_spawn", "frida_mcookie", "disk_pull", "memory_dd", "freeze_dd"]


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="Emit pretty JSON.")
    common.add_argument("--runs-dir", help="Override the run directory root.")
    common.add_argument("--serial", help="adb device serial.")

    parser = argparse.ArgumentParser(
        prog="apk-unpack",
        description="REA-style APK shell-unpacking agent: CLI, MCP server, evidence ledger.",
    )
    parser.add_argument("--version", action="version", version="apk-unpack-agents 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inspect-apk", parents=[common], help="Static APK inspection and shell detection.")
    p.add_argument("apk")
    p.add_argument("--run-id")
    p.add_argument("--no-deep-scan", action="store_true")

    p = sub.add_parser("extract-assets", parents=[common], help="Extract APK assets (default: uni-app wgt).")
    p.add_argument("apk")
    p.add_argument("--out")
    p.add_argument("--run-id")
    p.add_argument("--patterns", nargs="*")
    p.add_argument("--no-wgt", action="store_true")
    p.add_argument("--overwrite", action="store_true")

    p = sub.add_parser("device", parents=[common], help="Inspect the connected Android device.")
    p.add_argument("--run-id")
    p.add_argument("--frida-server", help="Local frida-server path or existing device path.")

    p = sub.add_parser("prepare", parents=[common], help="Prepare root/Frida/bypasses for a run.")
    p.add_argument("run")
    p.add_argument("--package")
    p.add_argument("--frida-server")
    p.add_argument("--no-start-frida", action="store_true")
    p.add_argument("--port", type=int)
    p.add_argument("--apk")
    p.add_argument("--allow-install", action="store_true")
    p.add_argument("--inner-bypass", action="store_true")
    p.add_argument("--rename-lib", action="append", default=[])
    p.add_argument("--keep-device-files", action="store_true")

    p = sub.add_parser("launch", parents=[common], help="Force-stop and start the target.")
    p.add_argument("run")
    p.add_argument("--package")
    p.add_argument("--activity")
    p.add_argument("--apk")
    p.add_argument("--no-force-stop", action="store_true")
    p.add_argument("--install", action="store_true")
    p.add_argument("--poll-timeout-ms", type=int, default=5000)
    p.add_argument("--no-auto-bypass", action="store_true", help="Disable the automatic ijiami emulator-library rename.")

    p = sub.add_parser("process-state", parents=[common], help="Inspect /proc status and maps.")
    p.add_argument("run")
    p.add_argument("--pid", type=int)
    p.add_argument("--package")

    p = sub.add_parser("strategy", parents=[common], help="Recommend an unpacking strategy.")
    p.add_argument("run")
    p.add_argument("--force-dump", action="store_true")

    p = sub.add_parser("recall-lessons", parents=[common], help="Search persistent unpacking lessons.")
    p.add_argument("--query")
    p.add_argument("--shell")
    p.add_argument("--device-abi")
    p.add_argument("--framework")
    p.add_argument("--package")
    p.add_argument("--tag", action="append", default=[])
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--stats", action="store_true")

    p = sub.add_parser("lesson-add", parents=[common], help="Record a new unpacking lesson.")
    p.add_argument("--title", required=True)
    p.add_argument("--scenario", required=True)
    p.add_argument("--solution", required=True)
    p.add_argument("--root-cause")
    p.add_argument("--shell")
    p.add_argument("--device-abi")
    p.add_argument("--framework")
    p.add_argument("--package")
    p.add_argument("--winning-method")
    p.add_argument("--tag", action="append", default=[])
    p.add_argument("--evidence-link", action="append", default=[])
    p.add_argument("--confidence", choices=["observed", "analyst"], default="analyst")
    p.add_argument("--scope", choices=["global", "package"], default="global")

    p = sub.add_parser("dump-dex", parents=[common], help="Dump DEX with Frida/disk/memory methods.")
    p.add_argument("run")
    p.add_argument("--package")
    p.add_argument("--pid", type=int)
    p.add_argument("--method", choices=METHODS, default="auto")
    p.add_argument("--mode", choices=["auto", "attach", "spawn"], default="auto")
    p.add_argument("--inner-bypass", action="store_true")
    p.add_argument("--timeout-ms", type=int)
    p.add_argument("--freeze-timeout-ms", type=int, default=15000)
    p.add_argument("--freeze-poll-ms", type=int, default=80)
    p.add_argument("--max-region-bytes", type=int)
    p.add_argument("--keep-device-files", action="store_true")

    p = sub.add_parser("repair-dex", parents=[common], help="Repair/dedupe/rename DEX in a run.")
    p.add_argument("run")
    p.add_argument("--input-dir")
    p.add_argument("--input", action="append", default=[])
    p.add_argument("--out")
    p.add_argument("--allow-truncated", action="store_true")
    p.add_argument("--include-stub", action="store_true")

    p = sub.add_parser("verify-dex", parents=[common], help="Verify DEX integrity and class counts.")
    p.add_argument("run")
    p.add_argument("--dex-dir")
    p.add_argument("--dex", action="append", default=[])
    p.add_argument("--package")
    p.add_argument("--jadx", action="store_true")
    p.add_argument("--timeout", type=int, help="JADX timeout in seconds; default APU_JADX_TIMEOUT_S or 3600.")

    p = sub.add_parser("decompile", parents=[common], help="Run JADX against the APK or DEX set.")
    p.add_argument("run")
    p.add_argument("--source", choices=["apk", "dex"], default="apk")
    p.add_argument("--apk")
    p.add_argument("--dex-dir")
    p.add_argument("--out")
    p.add_argument("--timeout", type=int, help="JADX timeout in seconds; default APU_JADX_TIMEOUT_S or 3600.")

    p = sub.add_parser("evidence", parents=[common], help="Read evidence from a run.")
    p.add_argument("run")
    p.add_argument("--id")
    p.add_argument("--operation")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("export-evidence", parents=[common], help="Export the evidence bundle.")
    p.add_argument("run")
    p.add_argument("--out", required=True)
    p.add_argument("--overwrite", action="store_true")

    p = sub.add_parser("run-state", parents=[common], help="Read run state and mutations.")
    p.add_argument("run")
    p.add_argument("--events", action="store_true")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("cleanup", parents=[common], help="Restore device mutations and thaw processes.")
    p.add_argument("run")
    p.add_argument("--keep-device-files", action="store_true")
    p.add_argument("--delete-run", action="store_true")
    p.add_argument("--no-restore", action="store_true")
    p.add_argument("--no-cont", action="store_true")
    p.add_argument("--prune-raw", action="store_true", help="Remove large raw region_*.bin dumps.")

    p = sub.add_parser("doctor", parents=[common], help="Diagnose prerequisites and device state.")
    p.add_argument("--frida-server")

    p = sub.add_parser("setup", parents=[common], help="Install the agent skill and register MCP.")
    p.add_argument("--client", choices=["claude_code", "generic"], default="claude_code")
    p.add_argument("--project-dir")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--uninstall", action="store_true")

    sub.add_parser("mcp", parents=[common], help="Run the MCP stdio server.")

    p = sub.add_parser("unpack", parents=[common], help="Full automated unpack workflow.")
    p.add_argument("apk")
    p.add_argument("--run-id")
    p.add_argument("--package")
    p.add_argument("--inner-bypass", action="store_true")
    p.add_argument("--install", action="store_true", help="Install the APK (base + sibling splits) before unpacking.")
    p.add_argument("--no-jadx", action="store_true")
    p.add_argument("--jadx-timeout-s", type=int, help="JADX timeout in seconds; default APU_JADX_TIMEOUT_S or 3600.")
    p.add_argument("--no-cleanup", action="store_true", help="Do not restore device mutations when done.")
    p.add_argument("--freeze-timeout-ms", type=int, default=15000)
    p.add_argument("--freeze-poll-ms", type=int, default=80)
    p.add_argument("--frida-timeout-ms", type=int)
    p.add_argument("--max-region-bytes", type=int)
    p.add_argument("--keep-device-files", action="store_true")
    p.add_argument("--no-auto-bypass", action="store_true")
    p.add_argument("--force-dump", action="store_true", help="Skip the static route and force a runtime DEX dump.")

    return parser


def _configure_stdio() -> None:
    """Make CLI JSON UTF-8 on Windows even when redirected to a file."""

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def _handle_sigterm(signum: int, frame: object) -> None:
    raise KeyboardInterrupt()


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except (AttributeError, ValueError, OSError):
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "mcp":
            service = build_service(args.runs_dir)
            return run_server(service)
        if args.command == "setup":
            plan = build_plan(
                client=args.client,
                project_dir=args.project_dir,
                uninstall=args.uninstall,
            )
            if args.yes:
                result = apply_plan(plan)
                _emit(result, args.json)
                return 0
            _emit({"requires_approval": True, "hint": "Re-run with --yes to apply exactly this plan.", **plan}, args.json)
            return 0
        service = build_service(args.runs_dir)
        result = _dispatch(service, args)
        _emit(result, args.json)
        return 0
    except AnalysisError as exc:
        projection = {"error": exc.projection()}
        if getattr(args, "json", False):
            _emit(projection, True)
        else:
            sys.stderr.write(json.dumps(projection, ensure_ascii=False, indent=2) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("cancelled\n")
        return 130


def _dispatch(service: ToolService, args: argparse.Namespace) -> dict[str, Any]:
    command = args.command
    serial = getattr(args, "serial", None)
    if command == "inspect-apk":
        return service.inspect_apk(args.apk, run_id=args.run_id, deep_dex_scan=not args.no_deep_scan)
    if command == "extract-assets":
        return service.extract_apk_assets(
            args.apk,
            output_dir=args.out,
            run_id=args.run_id,
            patterns=args.patterns,
            include_wgt=not args.no_wgt,
            overwrite=args.overwrite,
        )
    if command == "device":
        return service.inspect_android_device(serial=serial, run_id=args.run_id, frida_server_path=args.frida_server)
    if command == "prepare":
        return service.prepare_android_environment(
            args.run,
            serial=serial,
            package_name=args.package,
            frida_server_path=args.frida_server,
            start_frida_server=not args.no_start_frida,
            forward_port=args.port,
            apk_path=args.apk,
            allow_install=args.allow_install,
            inner_bypass=args.inner_bypass,
            rename_libs=args.rename_lib or None,
            keep_device_files=args.keep_device_files,
        )
    if command == "launch":
        return service.launch_android_target(
            args.run,
            serial=serial,
            package_name=args.package,
            apk_path=args.apk,
            activity=args.activity,
            force_stop=not args.no_force_stop,
            install=args.install,
            poll_timeout_ms=args.poll_timeout_ms,
            auto_emulator_bypass=not args.no_auto_bypass,
        )
    if command == "process-state":
        return service.inspect_process_state(
            args.run, serial=serial, pid=args.pid, package_name=args.package
        )
    if command == "strategy":
        return service.recommend_unpack_strategy(args.run, force_dump=args.force_dump)
    if command == "recall-lessons":
        result = service.recall_unpack_lessons(
            query=args.query,
            shell=args.shell,
            device_abi=args.device_abi,
            framework=args.framework,
            package_name=args.package,
            tags=args.tag or None,
            limit=args.limit,
        )
        if args.stats:
            result = {
                "memory_dir": result.get("memory_dir"),
                "stats": result.get("stats"),
                "total": result.get("total"),
                "lessons": [],
            }
        return result
    if command == "lesson-add":
        return service.remember_unpack_lesson(
            title=args.title,
            scenario=args.scenario,
            solution=args.solution,
            root_cause=args.root_cause,
            shell=args.shell,
            device_abi=args.device_abi,
            framework=args.framework,
            package_name=args.package,
            winning_method=args.winning_method,
            tags=args.tag or None,
            evidence_links=args.evidence_link or None,
            confidence=args.confidence,
            scope=args.scope,
        )
    if command == "dump-dex":
        return service.dump_android_dex(
            args.run,
            serial=serial,
            package_name=args.package,
            pid=args.pid,
            method=args.method,
            mode=args.mode,
            inner_bypass=args.inner_bypass,
            freeze_timeout_ms=args.freeze_timeout_ms,
            freeze_poll_ms=args.freeze_poll_ms,
            frida_timeout_ms=args.timeout_ms,
            max_region_bytes=args.max_region_bytes,
            keep_device_files=args.keep_device_files,
        )
    if command == "repair-dex":
        return service.repair_android_dex(
            args.run,
            input_paths=args.input or None,
            input_dir=args.input_dir,
            output_dir=args.out,
            allow_truncated=args.allow_truncated,
            include_stub=args.include_stub,
        )
    if command == "verify-dex":
        return service.verify_android_dex(
            args.run,
            dex_paths=args.dex or None,
            dex_dir=args.dex_dir,
            package_name=args.package,
            run_jadx=args.jadx,
            timeout_s=args.timeout,
        )
    if command == "decompile":
        return service.decompile_android_apk(
            args.run,
            source=args.source,
            apk_path=args.apk,
            dex_dir=args.dex_dir,
            output_dir=args.out,
            timeout_s=args.timeout,
        )
    if command == "evidence":
        return service.get_evidence(
            args.run,
            evidence_id=args.id,
            operation=args.operation,
            offset=args.offset,
            limit=args.limit,
        )
    if command == "export-evidence":
        return service.export_evidence_bundle(args.run, args.out, overwrite=args.overwrite)
    if command == "run-state":
        return service.inspect_run(args.run, include_events=args.events, limit=args.limit)
    if command == "cleanup":
        return service.cleanup_run(
            args.run,
            serial=serial,
            restore_mutations=not args.no_restore,
            cont_process=not args.no_cont,
            keep_device_files=args.keep_device_files,
            delete_run=args.delete_run,
            prune_raw_dumps=args.prune_raw,
        )
    if command == "doctor":
        return service.doctor(frida_server_path=args.frida_server)
    if command == "unpack":
        return service.unpack(
            args.apk,
            serial=serial,
            run_id=args.run_id,
            package_name=args.package,
            inner_bypass=args.inner_bypass,
            run_jadx=not args.no_jadx,
            jadx_timeout_s=args.jadx_timeout_s,
            cleanup=not args.no_cleanup,
            install=args.install,
            freeze_timeout_ms=args.freeze_timeout_ms,
            freeze_poll_ms=args.freeze_poll_ms,
            frida_timeout_ms=args.frida_timeout_ms,
            max_region_bytes=args.max_region_bytes,
            keep_device_files=args.keep_device_files,
            auto_emulator_bypass=not args.no_auto_bypass,
            force_dump=args.force_dump,
        )
    raise AnalysisError("invalid_input", f"unknown command: {command}")


def _emit(value: Any, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n")
        return
    sys.stdout.write(_summary(value) + "\n")


def _summary(value: dict[str, Any]) -> str:
    if "error" in value:
        return json.dumps(value, ensure_ascii=False, indent=2)
    if "run_state" in value and "records" in value:
        return f"run {value['run_id']}: {value['total']} evidence record(s); showing {len(value['records'])}."
    if "state" in value and "evidence_summary" in value:
        return (
            f"run {value['run_id']} stage={value['state'].get('stage')} "
            f"evidence={value['evidence_count']} mutations={len(value.get('mutations') or [])}"
        )
    if "inspection" in value:
        inspection = value["inspection"]
        packing = inspection.get("packing") or {}
        package = inspection.get("package") or {}
        return (
            f"run={value['run_id']} package={package.get('name')} shell={packing.get('primary')} "
            f"mixed={packing.get('mixed')} packed={packing.get('packed')} abis={','.join(inspection.get('abis') or []) or '-'}\n"
            f"evidence={value['evidence_id']}"
        )
    if "device" in value and "checks" not in value:
        device = value["device"]
        frida = device.get("frida") or {}
        root = device.get("root") or {}
        return (
            f"device={device.get('serial')} model={device.get('model')} abi={device.get('abi')} "
            f"sdk={device.get('sdk')} root={root.get('available')} frida_reachable={frida.get('reachable')}"
        )
    if "lessons" in value and "memory_dir" in value:
        stats = value.get("stats") or {}
        lines = [
            f"memory={value.get('memory_dir')} lessons={stats.get('total')} "
            f"(analyst={stats.get('analyst')}, observed={stats.get('observed')})"
        ]
        for lesson in value.get("lessons") or []:
            lines.append(
                f"  {lesson.get('lesson_id')}  [{lesson.get('confidence')}] "
                f"score={lesson.get('score')} occ={lesson.get('occurrences')} "
                f"method={lesson.get('winning_method') or '-'}"
            )
            lines.append(f"    {lesson.get('title')}")
            if lesson.get("solution"):
                lines.append(f"    solution: {lesson.get('solution')[:300]}")
        return "\n".join(lines)
    if "lesson" in value and "status" in value:
        lesson = value["lesson"]
        return (
            f"{value.get('status')} {lesson.get('lesson_id')} "
            f"[{lesson.get('confidence')}] {lesson.get('title')}\n"
            f"memory={value.get('memory_dir')} occurrences={lesson.get('occurrences')}"
        )
    if "strategy" in value:
        strategy = value["strategy"]
        steps = " -> ".join(
            f"{step.get('tool')}({step.get('method') or '-'})" for step in strategy.get("steps") or []
        )
        return (
            f"primary={strategy.get('primary')} shell={strategy.get('shell')} "
            f"fallbacks={', '.join(strategy.get('fallbacks') or []) or '-'}\nsteps: {steps}"
        )
    if "candidates" in value:
        candidates = value["candidates"]
        lines = [f"run={value['run_id']} method={value.get('method')} candidates={len(candidates)}"]
        for item in candidates:
            lines.append(
                f"  {Path(item['local_path']).name} size={item.get('size')} classes={item.get('class_defs_size')} "
                f"complete={item.get('complete')}"
            )
        return "\n".join(lines)
    if "repair" in value:
        repair = value["repair"]
        return (
            f"run={value['run_id']} repaired={len(repair.get('files') or [])} "
            f"duplicates={len(repair.get('duplicates') or [])} status={repair.get('status')} "
            f"dir={repair.get('output_dir')}"
        )
    if "verification" in value:
        verification = value["verification"]
        return (
            f"run={value['run_id']} files={verification.get('file_count')} classes={verification.get('total_classes')} "
            f"complete={verification.get('complete')} size={verification.get('total_size')}"
        )
    if "decompilation" in value:
        decomp = value["decompilation"]
        return (
            f"run={value['run_id']} java_files={decomp.get('java_file_count')} "
            f"package_files={decomp.get('package_java_file_count')} errors={decomp.get('error_count')} "
            f"dir={decomp.get('output_dir')}"
        )
    if "export" in value:
        export = value["export"]
        return f"exported {export.get('output_path')} sha256={export.get('sha256')} size={export.get('size')}"
    if "cleanup_status" in value:
        return (
            f"run={value['run_id']} cleanup={value.get('cleanup_status')} "
            f"restored={len(value.get('restored') or [])} failed={len(value.get('failed') or [])}"
        )
    if "checks" in value and "config" in value:
        lines = [f"doctor ok={value.get('ok')}"]
        for check in value["checks"]:
            marker = "OK " if check["ok"] else "FAIL"
            lines.append(f"  [{marker}] {check['name']}: {check.get('detail')}")
            if not check["ok"] and check.get("remediation"):
                lines.append(f"        -> {check['remediation']}")
        return "\n".join(lines)
    if "changes" in value and "client" in value:
        lines = [
            f"client={value.get('client')} uninstall={value.get('uninstall')}",
            "changes:",
        ]
        for change in value.get("changes") or []:
            lines.append(f"  {change}")
        if value.get("instructions"):
            lines.append("instructions: " + json.dumps(value["instructions"], ensure_ascii=False, indent=2))
        return "\n".join(lines)
    if "status" in value and "run_id" in value:
        return json.dumps(value, ensure_ascii=False, indent=2)
    return json.dumps(value, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
