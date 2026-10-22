from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import __version__


def _obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


def _string(description: str, **extra: Any) -> dict[str, Any]:
    return {"type": "string", "description": description, **extra}


def _bool(description: str) -> dict[str, Any]:
    return {"type": "boolean", "description": description}


def _int(description: str, **extra: Any) -> dict[str, Any]:
    return {"type": "integer", "description": description, **extra}


def _array(description: str, items: str = "string") -> dict[str, Any]:
    return {"type": "array", "description": description, "items": {"type": items}}


@dataclass(frozen=True)
class ToolEffects:
    mutates_target: bool = False
    mutates_session: bool = False
    writes_filesystem: bool = False
    launches_process: bool = False
    accesses_network: bool = False
    changes_ui_state: bool = False
    may_discard_data: bool = False
    executes_foreign_code: bool = False
    mutates_device: bool = False
    idempotent: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "mutates_target": self.mutates_target,
            "mutates_session": self.mutates_session,
            "writes_filesystem": self.writes_filesystem,
            "launches_process": self.launches_process,
            "accesses_network": self.accesses_network,
            "changes_ui_state": self.changes_ui_state,
            "may_discard_data": self.may_discard_data,
            "executes_foreign_code": self.executes_foreign_code,
            "mutates_device": self.mutates_device,
            "idempotent": self.idempotent,
        }


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    effects: ToolEffects
    annotations: dict[str, bool] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    returns_untrusted_content: bool = True
    examples: list[dict[str, Any]] = field(default_factory=list)

    def to_mcp(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }
        if self.output_schema:
            data["outputSchema"] = self.output_schema
        if self.returns_untrusted_content:
            data["_meta"] = {"provenance": {"untrusted_content": True}}
        return data


def _annotations(effects: ToolEffects, *, destructive: bool = False) -> dict[str, bool]:
    return {
        "readOnlyHint": not any(
            (
                effects.mutates_target,
                effects.mutates_session,
                effects.writes_filesystem,
                effects.launches_process,
                effects.changes_ui_state,
                effects.may_discard_data,
                effects.executes_foreign_code,
                effects.mutates_device,
            )
        ),
        "destructiveHint": destructive,
        "idempotentHint": effects.idempotent,
        "openWorldHint": effects.accesses_network or effects.mutates_device,
    }


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="inspect_apk",
        title="Inspect APK",
        description=(
            "Inspect one local APK's identity, manifest, ABIs, frameworks, top-level DEX headers, and shell signatures "
            "(ijiami, Bangcle, 360 Jiagu, Tencent MTP, SecNeo). Returns inline Evidence and creates a run for follow-up tools. "
            "This is static analysis only: it does not launch the APK or prove runtime behavior."
        ),
        input_schema=_obj(
            {
                "apk_path": _string("Absolute or relative path to the APK."),
                "run_id": _string("Optional existing run id to reuse."),
                "deep_dex_scan": _bool("Scan classes*.dex strings for shell markers (default true)."),
            },
            ["apk_path"],
        ),
        effects=ToolEffects(mutates_session=True, writes_filesystem=True),
        annotations=_annotations(ToolEffects(mutates_session=True, writes_filesystem=True)),
        examples=[{"title": "Inspect an APK", "input": {"apk_path": "/targets/Example.apk"}}],
    ),
    ToolSpec(
        name="extract_apk_assets",
        title="Extract APK assets",
        description=(
            "Extract selected APK members (default: uni-app __UNI__*.wgt) into a caller-selected directory and unpack wgt ZIPs. "
            "Use this before dynamic unpacking when a framework ships recoverable assets; it does not recover shell-encrypted DEX."
        ),
        input_schema=_obj(
            {
                "apk_path": _string("Path to the APK."),
                "output_dir": _string("Destination directory. Defaults to the run assets directory."),
                "run_id": _string("Optional existing run id."),
                "patterns": _array("fnmatch patterns; empty extracts all assets, including expanded uni-app and hybrid business code."),
                "include_wgt": _bool("Include and expand .wgt assets with default selection (default true)."),
                "overwrite": _bool("Allow writing into a non-empty output directory."),
                "max_total_bytes": _int("Byte budget for extracted assets."),
            },
            ["apk_path"],
        ),
        effects=ToolEffects(mutates_session=True, writes_filesystem=True),
        annotations=_annotations(ToolEffects(mutates_session=True, writes_filesystem=True)),
    ),
    ToolSpec(
        name="inspect_android_device",
        title="Inspect Android device",
        description=(
            "Inspect connected adb device(s), root, ABI/SDK, SELinux, frida-server process/version/forward state, and capabilities. "
            "Read-only on the device; Evidence is recorded in a run."
        ),
        input_schema=_obj(
            {
                "serial": _string("adb serial; required when multiple devices are online."),
                "run_id": _string("Optional existing run id."),
                "frida_server_path": _string("Device path or local path used to inspect frida-server architecture."),
            }
        ),
        effects=ToolEffects(mutates_session=True),
        annotations=_annotations(ToolEffects(mutates_session=True)),
    ),
    ToolSpec(
        name="prepare_android_environment",
        title="Prepare Android environment",
        description=(
            "Ensure root, push/start a matching frida-server, forward the Frida port, and apply reversible inner-shell bypasses "
            "(for example renaming libSdkHelper_sdk.so for 360+SecNeo). Every device mutation is recorded and can be undone by cleanup_run. "
            "It does not install external tools or modify the source APK."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id created by inspect_apk/inspect_android_device."),
                "serial": _string("adb serial."),
                "package_name": _string("Target package name."),
                "frida_server_path": _string("Local frida-server binary to push, or existing device path."),
                "start_frida_server": _bool("Start frida-server when not already running (default true)."),
                "forward_port": _int("adb forward port (default 27042)."),
                "apk_path": _string("APK to install when allow_install is true."),
                "allow_install": _bool("Permit adb install -r; install is not automatically reversed."),
                "inner_bypass": _bool("Rename the SecNeo inner SDK library reversibly."),
                "rename_libs": _array("Additional device library names to rename reversibly."),
                "keep_device_files": _bool("Keep device temp files."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(
            mutates_session=True,
            writes_filesystem=True,
            launches_process=True,
            mutates_device=True,
        ),
        annotations=_annotations(
            ToolEffects(mutates_session=True, writes_filesystem=True, launches_process=True, mutates_device=True),
            destructive=True,
        ),
    ),
    ToolSpec(
        name="launch_android_target",
        title="Launch Android target",
        description=(
            "Force-stop and start the target activity, then return the PID and /proc status. Launch is a device/UI mutation; "
            "anti-debug may kill the process immediately, which is reported explicitly."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id with an inspected APK."),
                "serial": _string("adb serial."),
                "package_name": _string("Package name; defaults to the inspected APK."),
                "apk_path": _string("APK path when install=true."),
                "activity": _string("Activity/component; defaults to manifest launchable-activity."),
                "force_stop": _bool("Force-stop before launching (default true)."),
                "install": _bool("Install the APK first."),
                "poll_timeout_ms": _int("PID polling timeout in milliseconds."),
                "auto_emulator_bypass": _bool(
                    "For ijiami crash-loops, automatically apply the reversible "
                    "libijm-emulator.so/libijmdetect-drisk.so rename and retry launch (default true)."
                ),
            },
            ["run_id"],
        ),
        effects=ToolEffects(
            mutates_session=True,
            launches_process=True,
            mutates_device=True,
            changes_ui_state=True,
        ),
        annotations=_annotations(
            ToolEffects(mutates_session=True, launches_process=True, mutates_device=True, changes_ui_state=True),
            destructive=True,
        ),
    ),
    ToolSpec(
        name="inspect_process_state",
        title="Inspect process state",
        description=(
            "Read /proc/<pid>/status and /proc/<pid>/maps, report TracerPid, and rank candidate DEX memory regions "
            "(dalvik-DEX, libc_malloc, heap). Region scores are heuristics, not proof that a DEX is present."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "serial": _string("adb serial."),
                "pid": _int("Process id; derived from package when omitted."),
                "package_name": _string("Package name; defaults to the inspected APK."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(mutates_session=True),
        annotations=_annotations(ToolEffects(mutates_session=True)),
    ),
    ToolSpec(
        name="recommend_unpack_strategy",
        title="Recommend unpack strategy",
        description=(
            "Derive a deterministic primary route, ordered fallback chain, prerequisites, risks, and do-not-attempt list from the "
            "APK shell/ABI/framework facts and current device/process facts. This is an inference; runtime behavior remains unverified."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id with inspect_apk evidence."),
                "force_dump": _bool("Require a runtime DEX dump even for a plain APK; shell-specific exclusions still apply."),
                "inspection_evidence_id": _string("Optional Evidence id to link."),
                "device_evidence_id": _string("Optional Evidence id to link."),
                "process_evidence_id": _string("Optional Evidence id to link."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(mutates_session=True),
        annotations=_annotations(ToolEffects(mutates_session=True)),
    ),
    ToolSpec(
        name="recall_unpack_lessons",
        title="Recall unpacking lessons",
        description=(
            "Search persistent lessons learned from previous authorized APK unpacking runs: new shell behaviors, "
            "anti-debug/anti-emulator symptoms, fallback chains that worked, and device-specific pitfalls. "
            "Lessons are historical evidence, not proof; check their scope, occurrences, and limitations before relying on them."
        ),
        input_schema=_obj(
            {
                "query": _string("Free-text symptom or topic search."),
                "shell": _string("Shell family, for example ijiami or bangcle."),
                "device_abi": _string("Device ABI, for example x86_64 or arm64-v8a."),
                "apk_abis": _array("APK ABIs; the store derives arm-only/x86/mixed."),
                "framework": _string("Framework, for example uni-app or flutter."),
                "package_name": _string("Package name for package-scoped lessons."),
                "tags": _array("Tag filters."),
                "limit": _int("Maximum lessons to return (default 10)."),
            }
        ),
        effects=ToolEffects(),
        annotations=_annotations(ToolEffects()),
        examples=[{"title": "Recall ijiami lessons for this device", "input": {"shell": "ijiami", "device_abi": "x86_64", "apk_abis": ["arm64-v8a"]}}],
    ),
    ToolSpec(
        name="remember_unpack_lesson",
        title="Remember unpacking lesson",
        description=(
            "Record a verified new scenario, pitfall, or solution so future runs become more accurate. "
            "Use this for genuinely new observations not already captured automatically by dump_android_dex or "
            "launch_android_target. Provide concrete symptoms, root cause, solution, scope, and evidence. "
            "Never store credentials, tokens, APK bytes, or unrelated user data."
        ),
        input_schema=_obj(
            {
                "title": _string("Short, specific lesson title."),
                "scenario": _string("When this lesson applies and what was observed."),
                "solution": _string("What actually fixed it."),
                "root_cause": _string("Root cause, if established."),
                "shell": _string("Shell family."),
                "device_abi": _string("Device ABI."),
                "apk_abis": _array("APK ABIs."),
                "framework": _string("Framework."),
                "package_name": _string("Package name when scope=package."),
                "winning_method": _string("Method that succeeded, if applicable."),
                "failed_methods": {
                    "type": "array",
                    "description": "Methods that failed and their error codes/messages.",
                    "items": _obj(
                        {
                            "method": _string("Method name."),
                            "code": _string("Error code."),
                            "message": _string("Short error message."),
                        },
                        ["method"],
                    ),
                },
                "symptoms": _array("Observed symptoms."),
                "tags": _array("Search tags."),
                "evidence_links": _array("Run/evidence references, for example run:run_... or ev:ev_..."),
                "confidence": _string("observed | analyst.", enum=["observed", "analyst"]),
                "scope": _string("global | package.", enum=["global", "package"]),
            },
            ["title", "scenario", "solution"],
        ),
        effects=ToolEffects(writes_filesystem=True),
        annotations=_annotations(ToolEffects(writes_filesystem=True)),
        examples=[
            {
                "title": "Record a new anti-debug workaround",
                "input": {
                    "title": "ijiami: signal 9 on attach → freeze_dd",
                    "scenario": "ARM-only ijiami app on x86_64 Houdini killed Frida attach with SIGKILL.",
                    "root_cause": "Inline-syscall anti-debug terminated the injected process.",
                    "solution": "Freeze the process after dalvik-DEX appears and dump with /proc/pid/mem.",
                    "shell": "ijiami",
                    "device_abi": "x86_64",
                    "apk_abis": ["arm64-v8a"],
                    "winning_method": "freeze_dd",
                    "tags": ["anti-frida", "houdini"],
                    "confidence": "analyst",
                    "scope": "global",
                },
            }
        ],
    ),
    ToolSpec(
        name="dump_android_dex",
        title="Dump Android DEX",
        description=(
            "Recover DEX from a running target with one of: Frida cookie/in-memory dump, on-disk MTP pull, root /proc/pid/mem dd, "
            "or SIGSTOP freeze + dd. method=auto follows the strategy recommendation. Raw DEX is saved in the run; call "
            "repair_android_dex and verify_android_dex afterwards. Device mutations and spawned-process termination are reported."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "serial": _string("adb serial."),
                "package_name": _string("Package name; defaults to the inspected APK."),
                "pid": _int("Explicit target PID."),
                "method": _string(
                    "auto | frida_inmemory | frida_inmemory_spawn | frida_mcookie | disk_pull | memory_dd | freeze_dd.",
                    enum=[
                        "auto",
                        "frida_inmemory",
                        "frida_inmemory_spawn",
                        "frida_mcookie",
                        "disk_pull",
                        "memory_dd",
                        "freeze_dd",
                    ],
                ),
                "mode": _string("auto | attach | spawn.", enum=["auto", "attach", "spawn"]),
                "apk_path": _string("APK path when the run has no target."),
                "inner_bypass": _bool("Prepare the reversible SecNeo inner-library bypass."),
                "freeze_poll_ms": _int("Freeze-mode map polling interval."),
                "freeze_timeout_ms": _int("Freeze-mode timeout."),
                "frida_timeout_ms": _int("Frida script timeout."),
                "max_region_bytes": _int("Per-region memory dump cap."),
                "keep_device_files": _bool("Keep device-side dump files."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(
            mutates_session=True,
            writes_filesystem=True,
            launches_process=True,
            executes_foreign_code=True,
            mutates_device=True,
            may_discard_data=True,
        ),
        annotations=_annotations(
            ToolEffects(
                mutates_session=True,
                writes_filesystem=True,
                launches_process=True,
                executes_foreign_code=True,
                mutates_device=True,
                may_discard_data=True,
            ),
            destructive=True,
        ),
    ),
    ToolSpec(
        name="repair_android_dex",
        title="Repair Android DEX",
        description=(
            "Validate and repair DEX headers in a run: authoritative file_size, zeroed checksum/signature, SHA-1 over [0x20:], "
            "Adler32 over [0x0C:], dedupe, and deterministic classes.dex naming. The source APK and raw dumps are never modified."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "input_paths": _array("Explicit DEX paths; defaults to the run raw directory."),
                "input_dir": _string("Directory containing raw DEX files."),
                "output_dir": _string("Output directory; defaults to the run fixed directory."),
                "allow_truncated": _bool("Repair a truncated DEX by lowering file_size."),
                "include_stub": _bool("Include shell stub DEX files."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(mutates_session=True, writes_filesystem=True),
        annotations=_annotations(ToolEffects(mutates_session=True, writes_filesystem=True)),
    ),
    ToolSpec(
        name="verify_android_dex",
        title="Verify Android DEX",
        description=(
            "Verify magic/header/endian/file_size, Adler32, SHA-1, class_defs/type_ids/string_ids, and package class counts. "
            "Optionally run JADX to count decompiled Java files. A valid checksum proves consistency, not complete recovery."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "dex_paths": _array("Explicit DEX paths."),
                "dex_dir": _string("DEX directory; defaults to the fixed directory, then raw."),
                "package_name": _string("Package used for class counting."),
                "run_jadx": _bool("Run JADX and count Java files."),
                "timeout_s": _int("JADX timeout in seconds; omitted/0 uses APU_JADX_TIMEOUT_S or 3600."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(
            mutates_session=True,
            writes_filesystem=True,
            launches_process=True,
        ),
        annotations=_annotations(ToolEffects(mutates_session=True, writes_filesystem=True, launches_process=True)),
    ),
    ToolSpec(
        name="decompile_android_apk",
        title="Decompile Android APK",
        description=(
            "Run the configured JADX CLI against the original APK or a run's DEX directory. Output is reconstructed source, not original source; "
            "this tool does not recover shell-encrypted code by itself."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "source": _string("apk | dex.", enum=["apk", "dex"]),
                "apk_path": _string("APK path when source=apk."),
                "dex_dir": _string("DEX directory when source=dex."),
                "output_dir": _string("JADX output directory; defaults to the run jadx directory."),
                "extra_args": _array("Extra JADX CLI arguments."),
                "timeout_s": _int("JADX timeout in seconds; omitted/0 uses APU_JADX_TIMEOUT_S or 3600."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(
            mutates_session=True,
            writes_filesystem=True,
            launches_process=True,
        ),
        annotations=_annotations(ToolEffects(mutates_session=True, writes_filesystem=True, launches_process=True)),
    ),
    ToolSpec(
        name="get_evidence",
        title="Get evidence",
        description="Read evidence records from a run, optionally filtered by evidence id or operation.",
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "evidence_id": _string("Exact ev_... id."),
                "operation": _string("Operation name filter."),
                "offset": _int("Pagination offset."),
                "limit": _int("Page size."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(),
        annotations=_annotations(ToolEffects()),
    ),
    ToolSpec(
        name="export_evidence_bundle",
        title="Export evidence bundle",
        description="Atomically export the run state, evidence ledger, events, and mutations to one JSON bundle.",
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "output_path": _string("Destination JSON path."),
                "overwrite": _bool("Replace an existing file."),
            },
            ["run_id", "output_path"],
        ),
        effects=ToolEffects(mutates_session=True, writes_filesystem=True),
        annotations=_annotations(ToolEffects(mutates_session=True, writes_filesystem=True)),
    ),
    ToolSpec(
        name="inspect_run",
        title="Inspect run",
        description="Read run state, mutations, evidence summaries, and optionally recent events.",
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "include_events": _bool("Include recent events."),
                "limit": _int("Maximum evidence/event rows."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(),
        annotations=_annotations(ToolEffects()),
    ),
    ToolSpec(
        name="cleanup_run",
        title="Cleanup run",
        description=(
            "Send SIGCONT to frozen processes, restore device mutations in reverse order (renamed libraries, forwards, started frida-server, pushed files), "
            "and remove device temp files. Failed restores retain the run and report cleanup_incomplete. Installing an APK is never auto-reversed."
        ),
        input_schema=_obj(
            {
                "run_id": _string("Run id."),
                "serial": _string("adb serial; resolved automatically when possible."),
                "restore_mutations": _bool("Restore reversible device mutations (default true)."),
                "cont_process": _bool("SIGCONT frozen processes (default true)."),
                "keep_device_files": _bool("Keep device temp files."),
                "delete_run": _bool("Delete the run directory after a fully successful cleanup."),
                "prune_raw_dumps": _bool("Remove large raw region_*.bin dumps after cleanup."),
            },
            ["run_id"],
        ),
        effects=ToolEffects(
            mutates_session=True,
            writes_filesystem=True,
            launches_process=True,
            mutates_device=True,
            may_discard_data=True,
            idempotent=True,
        ),
        annotations=_annotations(
            ToolEffects(
                mutates_session=True,
                writes_filesystem=True,
                launches_process=True,
                mutates_device=True,
                may_discard_data=True,
                idempotent=True,
            ),
            destructive=True,
        ),
    ),
]

TOOLS_BY_NAME = {tool.name: tool for tool in TOOL_SPECS}


def tool_names() -> list[str]:
    return [tool.name for tool in TOOL_SPECS]


def server_info() -> dict[str, Any]:
    return {"name": "apk-unpack-agents", "version": __version__}
