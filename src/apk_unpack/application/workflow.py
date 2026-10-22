from __future__ import annotations

import json
import hashlib
import os
import platform
import re
import shlex
import shutil
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from typing import Any, Iterable

from ..config import Config
from ..domain.errors import AnalysisError, fail, project_error
from ..domain.evidence import create_evidence
from ..domain.jsonutil import canonical_json, sha256_file
from ..domain.models import MutationRecord, to_jsonable
from ..domain.workspace import RunWorkspace, utc_now
from ..providers.adb import AdbProvider
from ..providers.apk import ApkInspector
from ..providers.axml import extract_manifest
from ..providers.dex import read_header, repair_dex_set, scan_file_for_dex, verify_dex
from ..providers.frida import FridaManager
from ..providers.host import HostRunner, read_elf_arch
from ..providers.jadx import JadxProvider
from ..providers.memory import MemoryReader
from ..providers.process import ProcessInspector
from .dex_validation import assess_dex
from .targets import target_namespaces
from .memory import DUMP_METHODS, MemoryStore, apk_abi_class
from .strategy import recommend_strategy

PROVIDERS = {
    "apk": {"id": "apk-static", "name": "APK static inspector", "version": "0.1.0"},
    "adb": {"id": "adb", "name": "Android Debug Bridge", "version": None},
    "frida": {"id": "frida", "name": "Frida CLI", "version": None},
    "memory": {"id": "proc-mem", "name": "/proc/pid/mem reader", "version": "0.1.0"},
    "dex": {"id": "dex-forensics", "name": "DEX forensic toolkit", "version": "0.1.0"},
    "jadx": {"id": "jadx", "name": "JADX CLI", "version": None},
}

# Mutation states cleanup attempts to reverse. ``restore_failed`` is included so
# a later cleanup call can retry a restore that previously failed.
_RETRYABLE_MUTATION_STATES = frozenset({"applied", "restore_failed"})
# Mutation states that do not make cleanup incomplete. Anything else (applied,
# restore_failed, apply_failed, unknown) means a mutation was not finalized.
_TERMINAL_MUTATION_STATES = frozenset({"restored", "kept", "not_applied"})


def _static_dex_entry_key(name: str) -> tuple[int, int, str]:
    """Order classes.dex, classes2.dex, ... like the Android runtime."""
    match = re.fullmatch(r"classes(\d*)\.dex", name)
    if not match:
        return (1, 0, name)
    return (0, int(match.group(1) or 1), name)


class ToolService:
    def __init__(
        self,
        config: Config,
        *,
        host: HostRunner | None = None,
        adb: AdbProvider | None = None,
        apk: ApkInspector | None = None,
        frida: FridaManager | None = None,
        process: ProcessInspector | None = None,
        memory: MemoryReader | None = None,
        jadx: JadxProvider | None = None,
        lessons: MemoryStore | None = None,
    ):
        self.config = config
        self.host = host or HostRunner()
        self.adb = adb or AdbProvider(self.host, config)
        self.apk = apk or ApkInspector(self.host, config.aapt)
        self.frida = frida or FridaManager(self.host, config)
        self.process = process or ProcessInspector(self.adb)
        self.memory = memory or MemoryReader(self.adb, self.process, config)
        self.jadx = jadx or JadxProvider(self.host, config.java, config.jadx_jar)
        self.lessons = lessons or MemoryStore(config.memory_dir)

    # ------------------------------------------------------------------ helpers
    def _stage(self, run_id: str, stage: str, **detail: Any) -> None:
        try:
            run = self._load_run(run_id)
            run.append_event("stage", {"stage": stage, **detail})
        except Exception:
            pass

    def _runs_dir(self) -> Path:
        return self.config.ensure_runs_dir()

    def _load_run(self, run_id: str) -> RunWorkspace:
        return RunWorkspace.load(self._runs_dir(), run_id)

    def _create_run(self, *, target: dict[str, Any] | None = None, device: dict[str, Any] | None = None) -> RunWorkspace:
        return RunWorkspace.create(self._runs_dir(), target=target, device=device)

    def _result(self, run: RunWorkspace, evidence: dict[str, Any], **extra: Any) -> dict[str, Any]:
        data = {
            "run_id": run.run_id,
            "evidence_id": evidence["evidence_id"],
            "evidence": evidence,
        }
        data.update(extra)
        return data

    def _record(
        self,
        run: RunWorkspace,
        *,
        operation: str,
        normalized_result: dict[str, Any],
        subject: dict[str, Any] | None = None,
        provider: str = "apk",
        predicate_type: str | None = None,
        parameters: dict[str, Any] | None = None,
        raw_result: dict[str, Any] | None = None,
        confidence: str = "observed",
        authority: str = "shipped-artifact",
        limitations: list[str] | None = None,
        locations: list[dict[str, Any]] | None = None,
        evidence_links: list[str] | None = None,
    ) -> dict[str, Any]:
        evidence = create_evidence(
            operation=operation,
            subject=subject,
            provider=PROVIDERS.get(provider, PROVIDERS["apk"]),
            predicate_type=predicate_type,
            parameters=parameters or {},
            normalized_result=normalized_result,
            raw_result=raw_result,
            confidence=confidence,
            authority=authority,
            environment=self._environment(),
            limitations=limitations,
            locations=locations,
            evidence_links=evidence_links,
        )
        run.append_evidence(evidence)
        run.update_run(evidence_ids=[evidence["evidence_id"]])
        return evidence

    @staticmethod
    def _environment(device: dict[str, Any] | None = None) -> dict[str, Any]:
        environment: dict[str, Any] = {
            "id": "local",
            "platform": sys.platform,
            "architecture": platform.machine(),
            "isolation": "owned-run-directory",
        }
        if device:
            environment["device_serial"] = device.get("serial")
            environment["device_abi"] = device.get("abi")
        return environment

    @staticmethod
    def _apk_subject(inspection: dict[str, Any]) -> dict[str, Any]:
        identity = inspection.get("identity") or {}
        return {
            "format": "apk",
            "name": Path(identity.get("path", "")).name,
            "local_path": identity.get("path"),
            "sha256": identity.get("sha256"),
            "size": identity.get("size"),
            "architecture": ",".join(inspection.get("abis") or []),
        }

    @staticmethod
    def _run_artifacts(run: RunWorkspace) -> dict[str, Any]:
        return dict(run.load_run().get("artifacts") or {})

    def _inspection_for(self, run: RunWorkspace) -> dict[str, Any]:
        inspection = self._run_artifacts(run).get("inspection")
        if not inspection:
            target = run.load_run().get("target") or {}
            path = target.get("path")
            if not path:
                raise fail("invalid_input", "run has no inspected APK; call inspect_apk first", details={"run_id": run.run_id})
            inspection = self.apk.inspect(path)
            run.update_run(artifacts={"inspection": inspection})
        return inspection

    @staticmethod
    def _require(arguments: dict[str, Any], *keys: str) -> None:
        missing = [key for key in keys if arguments.get(key) in (None, "")]
        if missing:
            raise fail("invalid_input", f"missing required argument(s): {', '.join(missing)}", details={"missing": missing})

    def _serial(self, serial: str | None) -> str:
        return self.adb.resolve_serial(serial)

    def _device_artifact(self, run: RunWorkspace) -> dict[str, Any] | None:
        return self._run_artifacts(run).get("device")

    def _package_for(self, run: RunWorkspace, package_name: str | None) -> str:
        if package_name:
            return package_name
        state = run.load_run()
        if state.get("package"):
            return state["package"]
        inspection = self._inspection_for(run)
        package = (inspection.get("package") or {}).get("name")
        if not package:
            raise fail("invalid_input", "package name is unknown; pass package_name explicitly")
        return package

    def _install_set(self, apk_path: str | Path, run: RunWorkspace) -> list[Path]:
        """Resolve a base APK plus same-package split APKs, or extract a bundle."""

        path = Path(apk_path).expanduser().resolve()
        suffix = path.suffix.lower()
        if suffix in (".apks", ".xapk"):
            target_dir = run.tmp_dir / "install_set"
            target_dir.mkdir(parents=True, exist_ok=True)
            extracted: list[Path] = []
            try:
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if info.is_dir() or not info.filename.lower().endswith(".apk"):
                            continue
                        name = Path(info.filename).name
                        destination = target_dir / name
                        if destination.exists():
                            destination = target_dir / f"{len(extracted)}_{name}"
                        with archive.open(info) as source, open(destination, "wb") as sink:
                            shutil.copyfileobj(source, sink)
                        extracted.append(destination)
            except (zipfile.BadZipFile, OSError) as exc:
                raise fail("unsupported_target", f"cannot extract {suffix} bundle: {exc}")
            if not extracted:
                raise fail("unsupported_target", f"no APK members found in {path}")
            return extracted
        if suffix != ".apk":
            raise fail("invalid_input", f"unsupported install file: {path}")
        base_package = _read_apk_package(path)
        paths = [path]
        for sibling in sorted(path.parent.glob("*.apk")):
            if sibling.resolve() == path:
                continue
            name = sibling.name.lower()
            if not (name.startswith(("split_", "config.", "base-", "split.")) or "_split_" in name):
                continue
            sibling_package = _read_apk_package(sibling)
            if base_package and sibling_package not in (None, base_package):
                continue
            paths.append(sibling.resolve())
        return paths

    def _install_failure(self, result: Any, install_paths: list[Path]) -> AnalysisError:
        output = f"{result.stdout or ''}\n{result.stderr or ''}"
        details = {
            "timed_out": result.timed_out,
            "returncode": result.returncode,
            "timeout_s": self.config.install_timeout_s,
            "apk_paths": [str(path) for path in install_paths],
        }
        if "INSTALL_FAILED_NO_MATCHING_ABIS" in output:
            return fail(
                "unsupported_target",
                "install failed: no matching ABI",
                remediation="Use a device/emulator with a matching ABI or ARM translation.",
                details=details,
                captured_output=output,
            )
        if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in output or "INSTALL_FAILED_VERSION_DOWNGRADE" in output:
            return fail(
                "conflict",
                "install failed: incompatible existing package",
                remediation="Uninstall the existing package or use a matching signature/version.",
                details=details,
                captured_output=output,
            )
        if "INSTALL_FAILED_INSUFFICIENT_STORAGE" in output:
            return fail(
                "resource_constraint",
                "install failed: insufficient device storage",
                remediation="Free space on the device and retry.",
                details=details,
                captured_output=output,
            )
        return fail(
            "execution_failure",
            "adb install failed or timed out",
            retryable=result.timed_out,
            captured_output=output,
            details=details,
        )

    def _check_install_compatibility(self, serial: str, inspection: dict[str, Any]) -> None:
        apk_abis = inspection.get("abis") or []
        if not apk_abis:
            return
        device = self.adb.device_info(serial)
        device_abis = list(
            dict.fromkeys(
                [device.get("abi") or ""] + list(device.get("abilist") or [])
            )
        )
        if not _abis_compatible(apk_abis, device_abis):
            raise fail(
                "unsupported_target",
                f"APK ABIs {sorted(apk_abis)} are not supported by device ABIs {sorted({a for a in device_abis if a})}",
                remediation="Use a device/emulator with a matching ABI or ARM translation.",
                details={"apk_abis": apk_abis, "device_abis": device_abis},
            )

    # ------------------------------------------------------------------ inspect_apk
    def inspect_apk(
        self,
        apk_path: str | Path,
        *,
        run_id: str | None = None,
        deep_dex_scan: bool = True,
    ) -> dict[str, Any]:
        inspection = self.apk.inspect(apk_path, deep_dex_scan=deep_dex_scan)
        if run_id:
            try:
                run = self._load_run(run_id)
            except AnalysisError:
                run = RunWorkspace.create(self._runs_dir(), run_id=run_id, target=inspection["identity"])
        else:
            run = self._create_run(target=inspection["identity"])
        run.update_run(
            stage="inspected",
            target=inspection["identity"],
            package=(inspection.get("package") or {}).get("name"),
            artifacts={"inspection": inspection},
        )
        evidence = self._record(
            run,
            operation="inspect_apk",
            subject=self._apk_subject(inspection),
            provider="apk",
            predicate_type="apk.static",
            parameters={"apk_path": str(apk_path), "deep_dex_scan": deep_dex_scan},
            normalized_result=inspection,
            confidence=inspection.get("packing", {}).get("confidence", "observed"),
            authority="shipped-artifact",
            limitations=inspection.get("limitations") or [],
            locations=[{"kind": "artifact-path", "path": str(Path(apk_path).resolve())}],
        )
        return self._result(run, evidence, inspection=inspection)

    # ------------------------------------------------------------------ extract_apk_assets
    def extract_apk_assets(
        self,
        apk_path: str | Path,
        *,
        output_dir: str | Path | None = None,
        run_id: str | None = None,
        patterns: list[str] | None = None,
        include_wgt: bool = True,
        overwrite: bool = False,
        max_total_bytes: int | None = None,
    ) -> dict[str, Any]:
        run = self._load_run(run_id) if run_id else self._create_run()
        inspection = self.apk.inspect(apk_path, deep_dex_scan=False) if not run_id else None
        if inspection:
            run.update_run(
                stage="inspected",
                target=inspection["identity"],
                package=(inspection.get("package") or {}).get("name"),
                artifacts={"inspection": inspection},
            )
        target_dir = Path(output_dir) if output_dir else run.assets_dir
        result = self.apk.extract_assets(
            apk_path,
            target_dir,
            patterns=patterns,
            include_wgt=include_wgt,
            overwrite=overwrite,
            max_total_bytes=max_total_bytes or self.config.max_asset_bytes,
        )
        evidence = self._record(
            run,
            operation="extract_apk_assets",
            subject={"format": "apk", "sha256": inspection["identity"]["sha256"] if inspection else None, "local_path": str(apk_path)},
            provider="apk",
            parameters={"patterns": patterns or [], "include_wgt": include_wgt},
            normalized_result=result,
            confidence="observed",
            authority="shipped-artifact",
            locations=[{"kind": "artifact-path", "path": result["output_dir"]}],
        )
        run.update_run(stage="assets_extracted", artifacts={
            "assets_dir": result["output_dir"],
            "asset_extraction": {**result, "all_assets": not patterns and include_wgt},
        })
        return self._result(run, evidence, extraction=result)

    # ------------------------------------------------------------------ device
    def inspect_android_device(
        self,
        *,
        serial: str | None = None,
        run_id: str | None = None,
        frida_server_path: str | None = None,
    ) -> dict[str, Any]:
        serial = self._serial(serial)
        info = self.adb.device_info(serial, frida_server_path=frida_server_path)
        run = self._load_run(run_id) if run_id else self._create_run(device=info)
        run.update_run(stage="device_inspected", device=info, artifacts={"device": info})
        evidence = self._record(
            run,
            operation="inspect_android_device",
            subject={"format": "device", "digest": {"serial": serial}},
            provider="adb",
            predicate_type="device.inspect",
            parameters={"serial": serial},
            normalized_result=info,
            confidence="observed",
            authority="live-device",
            limitations=[
                "Live-device facts describe this device at observation time; they do not prove the app's behavior.",
            ],
            locations=[{"kind": "device-path", "path": f"serial:{serial}"}],
        )
        return self._result(run, evidence, device=info)

    def prepare_android_environment(
        self,
        run_id: str,
        *,
        serial: str | None = None,
        package_name: str | None = None,
        frida_server_path: str | None = None,
        start_frida_server: bool = True,
        forward_port: int | None = None,
        apk_path: str | None = None,
        allow_install: bool = False,
        inner_bypass: bool = False,
        rename_libs: list[str] | None = None,
        keep_device_files: bool = False,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        serial = self._serial(serial)
        package = package_name or run.load_run().get("package")
        actions: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        root = self.adb.ensure_root(serial)
        actions.append({"action": "ensure_root", "result": root})

        server_path = "/data/local/tmp/frida-server"
        local_server: str | None = None
        for candidate in (frida_server_path, self.config.frida_server):
            if not candidate:
                continue
            # On POSIX a local binary also starts with "/", so check the host
            # filesystem before treating the value as a device path.
            if Path(candidate).is_file():
                local_server = candidate
                break
            if candidate.startswith("/"):
                server_path = candidate
                break
        local_port = int(forward_port or self.config.frida_port_for(serial))
        remote_port = int(forward_port or self.config.frida_remote_port)
        device_abi = (
            self.adb.shell(serial, "getprop ro.product.cpu.abi 2>/dev/null", timeout=15).stdout or ""
        ).strip()
        cli_version = self.frida.version() if start_frida_server else None
        if start_frida_server:
            existing = self.adb.file_exists(serial, server_path)
            device_arch = self.adb.elf_arch(serial, server_path) if existing else None
            device_version = self._device_frida_server_version(serial, server_path) if existing else None
            local_arch = read_elf_arch(local_server) if local_server else None
            local_version = self._local_frida_server_version(local_server) if local_server else None
            expected_version = local_version or cli_version
            if local_version and cli_version and local_version != cli_version:
                raise fail(
                    "frida_version_mismatch",
                    "configured frida-server does not match the host frida client",
                    remediation="Use the frida-server build that matches the installed frida CLI.",
                    details={
                        "server_path": local_server,
                        "server_version": local_version,
                        "cli_version": cli_version,
                    },
                )

            if local_server and device_abi:
                if not local_arch:
                    raise fail(
                        "frida_arch_mismatch",
                        "cannot read the ELF architecture of the configured frida-server",
                        remediation="Point frida_server_path/APU_FRIDA_SERVER at an ELF binary matching the device ABI.",
                        details={"server_path": local_server, "device_abi": device_abi},
                    )
                if not _arch_matches(local_arch, device_abi):
                    raise fail(
                        "frida_arch_mismatch",
                        f"frida-server architecture {local_arch} does not match device ABI {device_abi}",
                        remediation="Use frida-server built for the device ABI.",
                        details={"server_arch": local_arch, "device_abi": device_abi, "server_path": local_server},
                    )

            arch_ok = bool(not device_abi or (device_arch and _arch_matches(device_arch, device_abi)))
            version_ok = bool(not expected_version or (device_version and device_version == expected_version))
            if not existing:
                if not local_server:
                    raise fail(
                        "frida_unavailable",
                        "frida-server is not on the device and no local binary was supplied",
                        remediation="Set APU_FRIDA_SERVER, pass frida_server_path, or push frida-server manually.",
                        details={"device_path": server_path},
                    )
                actions.append({"action": "frida_server_push", "reason": "missing_on_device"})
                push_created = True
            elif not (arch_ok and version_ok):
                problems = []
                if not arch_ok:
                    problems.append(f"arch {device_arch or 'unknown'} != device ABI {device_abi or 'unknown'}")
                if not version_ok:
                    problems.append(
                        f"version {device_version or 'unknown'} != expected {expected_version or 'unknown'}"
                    )
                if not local_server:
                    raise fail(
                        "frida_version_mismatch",
                        "on-device frida-server does not match this host/device; refusing to reuse it",
                        remediation="Set APU_FRIDA_SERVER/pass frida_server_path so the matching server can be pushed.",
                        details={
                            "device_path": server_path,
                            "device_arch": device_arch,
                            "device_version": device_version,
                            "expected_version": expected_version,
                            "device_abi": device_abi,
                            "problems": problems,
                        },
                    )
                self.adb.kill_frida_server(serial)
                actions.append(
                    {
                        "action": "frida_server_push",
                        "reason": "stale_or_wrong_arch",
                        "problems": problems,
                        "replaced": {
                            "arch": device_arch,
                            "version": device_version,
                        },
                    }
                )
                push_created = False
            else:
                actions.append(
                    {
                        "action": "frida_server_check",
                        "result": "reused",
                        "arch": device_arch,
                        "version": device_version,
                    }
                )
                push_created = None

            if push_created is not None:
                push = self.adb.push(serial, local_server, server_path)
                if not push.ok:
                    raise fail("execution_failure", "failed to push frida-server", captured_output=push.stderr or push.stdout)
                mutation = run.add_mutation(
                    {
                        "kind": "push_file",
                        "target": server_path,
                        "detail": {"local": str(local_server), "created": push_created},
                        "apply_command": ["adb", "push", str(local_server), server_path],
                        "restore_command": ["adb", "shell", f"rm -f {server_path}"] if push_created else None,
                        "reversible": push_created,
                    }
                )
                actions.append(
                    {
                        "action": "push_frida_server",
                        "mutation_id": mutation["mutation_id"],
                        "replaced_existing": not push_created,
                    }
                )
            chmod = self.adb.chmod(serial, "755", server_path)
            if not chmod.ok:
                raise fail("execution_failure", "failed to chmod frida-server", captured_output=chmod.stderr)
            started = self.adb.start_frida_server(serial, server_path, remote_port)
            actions.append({"action": "start_frida_server", "result": started})
            server_version = self._device_frida_server_version(serial, server_path)
            if expected_version and server_version and expected_version != server_version:
                raise fail(
                    "frida_version_mismatch",
                    "device frida-server version changed or does not match the host client",
                    remediation="Install the frida-server build that matches the host frida CLI.",
                    details={
                        "expected_version": expected_version,
                        "server_version": server_version,
                        "server_path": server_path,
                    },
                )
            if started.get("started"):
                run.add_mutation(
                    {
                        "kind": "frida_server_start",
                        "target": f"pid:{started['pid']}",
                        "detail": started,
                        "apply_command": ["adb", "shell", f"kill {started['pid']}"],
                        "restore_command": ["adb", "shell", f"kill {started['pid']}"],
                        "reversible": True,
                    }
                )
            # Verify our own forward exists, not just any forward globally.
            already = self.adb.has_forward(serial, local_port, remote_port)
            if not already:
                result = self.adb.forward(serial, local_port, remote_port)
                if not result.ok:
                    raise fail("execution_failure", "adb forward failed", captured_output=result.stderr or result.stdout)
                run.add_mutation(
                    {
                        "kind": "adb_forward",
                        "target": f"tcp:{local_port}",
                        "detail": {"local_port": local_port, "remote_port": remote_port, "created": True},
                        "apply_command": [
                            "adb",
                            "-s",
                            serial,
                            "forward",
                            f"tcp:{local_port}",
                            f"tcp:{remote_port}",
                        ],
                        "restore_command": ["adb", "-s", serial, "forward", "--remove", f"tcp:{local_port}"],
                        "reversible": True,
                    }
                )
                actions.append({"action": "adb_forward", "port": local_port, "remote_port": remote_port})
            else:
                actions.append(
                    {
                        "action": "adb_forward",
                        "port": local_port,
                        "remote_port": remote_port,
                        "already_present": True,
                    }
                )
            if not self.adb.has_forward(serial, local_port, remote_port):
                raise fail(
                    "execution_failure",
                    "adb forward --list does not contain this device and port",
                    details={
                        "serial": serial,
                        "local_port": local_port,
                        "remote_port": remote_port,
                        "forward_list": (self.adb.forward_list().stdout or "")[-2000:],
                    },
                )

        if inner_bypass or rename_libs:
            if not package:
                raise fail(
                    "invalid_input",
                    "package_name is required to scope library renames to the target app",
                    remediation="Pass package_name or run inspect_apk first.",
                )
            candidates = rename_libs or ["libSdkHelper_sdk.so"]
            search_dirs = self.adb.package_dirs(serial, package)
            for lib_name in candidates:
                if "/" in lib_name:
                    paths = [lib_name] if self.adb.file_exists(serial, lib_name) else []
                else:
                    paths: list[str] = []
                    for search_dir in search_dirs:
                        found = self.adb.find(serial, search_dir, lib_name)
                        if not found:
                            base_name = lib_name[:-3] if lib_name.lower().endswith(".so") else lib_name
                            found = self.adb.find(serial, search_dir, base_name + "*")
                        paths.extend(found)
                    paths = list(dict.fromkeys(paths))
                if not paths:
                    actions.append({"action": "rename_device_lib", "lib": lib_name, "result": "not_found"})
                for path in paths:
                    backup = path + ".apu.bak"
                    if self.adb.file_exists(serial, backup):
                        errors.append(
                            {
                                "action": "rename_device_lib",
                                "lib": lib_name,
                                "path": path,
                                "error": "backup already exists; refusing to overwrite",
                            }
                        )
                        continue
                    rename = self.adb.rename(serial, path, backup)
                    if rename.ok:
                        mutation = run.add_mutation(
                            {
                                "kind": "rename_device_lib",
                                "target": path,
                                "detail": {"lib": lib_name, "backup": backup},
                                "apply_command": ["adb", "-s", serial, "shell", f"mv {shlex.quote(path)} {shlex.quote(backup)}"],
                                "restore_command": ["adb", "-s", serial, "shell", f"mv {shlex.quote(backup)} {shlex.quote(path)}"],
                                "reversible": True,
                            }
                        )
                        actions.append({"action": "rename_device_lib", "path": path, "mutation_id": mutation["mutation_id"]})
                    else:
                        errors.append({"action": "rename_device_lib", "lib": lib_name, "path": path, "error": rename.stderr or rename.stdout})

        if allow_install and apk_path:
            inspection = self._inspection_for(run)
            self._check_install_compatibility(serial, inspection)
            install_paths = self._install_set(apk_path, run)
            install = self.adb.install_files(serial, install_paths)
            if not install.ok:
                raise self._install_failure(install, install_paths)
            command = [
                "adb",
                "-s",
                serial,
                "install-multiple" if len(install_paths) > 1 else "install",
                "-r",
                *[str(path) for path in install_paths],
            ]
            run.add_mutation(
                {
                    "kind": "install_apk",
                    "target": package or str(apk_path),
                    "detail": {
                        "apk_paths": [str(path) for path in install_paths],
                        "note": "install is not automatically reversed",
                    },
                    "apply_command": command,
                    "restore_command": None,
                    "reversible": False,
                }
            )
            actions.append({"action": "install_apk", "apk_paths": [str(path) for path in install_paths]})

        info = self.adb.device_info(serial, frida_server_path=frida_server_path)
        run.update_run(stage="environment_prepared", device=info, package=package, artifacts={"device": info})
        evidence = self._record(
            run,
            operation="prepare_android_environment",
            subject={"format": "device", "digest": {"serial": serial}},
            provider="adb",
            predicate_type="device.prepare",
            parameters={
                "serial": serial,
                "package": package,
                "start_frida_server": start_frida_server,
                "forward_port": local_port,
                "remote_port": remote_port,
                "frida_host": self.config.frida_host_for(serial),
                "inner_bypass": inner_bypass,
                "allow_install": allow_install,
            },
            normalized_result={"actions": actions, "errors": errors, "device": info},
            confidence="observed",
            authority="live-device",
            limitations=[] if not errors else ["Some reversible device mutations could not be applied; review errors."],
        )
        return self._result(run, evidence, actions=actions, errors=errors, device=info)

    def launch_android_target(
        self,
        run_id: str,
        *,
        serial: str | None = None,
        package_name: str | None = None,
        apk_path: str | None = None,
        activity: str | None = None,
        force_stop: bool = True,
        install: bool = False,
        poll_timeout_ms: int = 5000,
        auto_emulator_bypass: bool = True,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        serial = self._serial(serial)
        package = self._package_for(run, package_name)
        inspection = self._inspection_for(run)
        if not install:
            installed = self.adb.shell(serial, f"pm path {shlex.quote(package)} 2>/dev/null", timeout=20)
            if not installed.ok or not installed.stdout.strip():
                raise fail(
                    "not_found",
                    f"target package is not installed: {package}",
                    remediation="Pass install=true/--install or install the APK manually.",
                    details={"package": package},
                )
        if install and apk_path:
            self._check_install_compatibility(serial, inspection)
            install_paths = self._install_set(apk_path, run)
            result = self.adb.install_files(serial, install_paths)
            if not result.ok:
                raise self._install_failure(result, install_paths)
            command = [
                "adb",
                "-s",
                serial,
                "install-multiple" if len(install_paths) > 1 else "install",
                "-r",
                *[str(path) for path in install_paths],
            ]
            run.add_mutation(
                {
                    "kind": "install_apk",
                    "target": package,
                    "detail": {
                        "apk_paths": [str(path) for path in install_paths],
                        "note": "install is not automatically reversed",
                    },
                    "apply_command": command,
                    "restore_command": None,
                    "reversible": False,
                }
            )
        activity = activity or (inspection.get("package") or {}).get("launchable_activity")
        if not activity:
            activity = self.adb.resolve_activity(serial, package)
        if force_stop:
            stop = self.adb.force_stop(serial, package)
            if not stop.ok:
                run.append_event("force_stop_failed", {"package": package, "output": stop.stderr or stop.stdout})
            else:
                run.add_mutation(
                    {
                        "kind": "force_stop",
                        "target": package,
                        "detail": {"note": "force-stop is not reversible; recorded for timeline only"},
                        "apply_command": ["adb", "-s", serial, "shell", f"am force-stop {package}"],
                        "restore_command": None,
                        "reversible": False,
                        "state": "applied",
                    }
                )
        shell = (inspection.get("packing") or {}).get("primary")
        bypass_attempted = False
        pid: int | None = None
        status: dict[str, Any] | None = None
        last_error: Exception | None = None
        last_start = None
        for attempt in range(2):
            if attempt > 0 and force_stop:
                self.adb.force_stop(serial, package)
            start = self.adb.am_start(serial, package, activity)
            last_start = start
            if not start.ok:
                # Crash-looping (often Houdini/anti-emulator) apps can make
                # `am start -W` return non-zero even though a process is spawned.
                # Prefer an observable PID over the shell exit code.
                run.append_event(
                    "am_start_nonzero",
                    {
                        "package": package,
                        "activity": activity,
                        "attempt": attempt,
                        "returncode": start.returncode,
                        "output": (start.stderr or start.stdout)[-4000:],
                    },
                )
            deadline = time.monotonic() + poll_timeout_ms / 1000.0
            pid = None
            status = None
            while time.monotonic() < deadline:
                try:
                    remaining_ms = max(500, int((deadline - time.monotonic()) * 1000))
                    pid = self.process.wait_for_pid(serial, package, timeout_ms=remaining_ms)
                    status = self.process.status(serial, pid)
                    break
                except AnalysisError as exc:
                    last_error = exc
                    time.sleep(0.1)
            if pid is not None and status is not None:
                break
            if attempt == 0 and auto_emulator_bypass and shell == "ijiami":
                bypass_attempted = True
                try:
                    bypass = self.prepare_android_environment(
                        run.run_id,
                        serial=serial,
                        package_name=package,
                        start_frida_server=False,
                        rename_libs=["libijm-emulator.so", "libijmdetect-drisk.so"],
                    )
                    run.append_event(
                        "auto_emulator_bypass",
                        {"actions": bypass.get("actions"), "errors": bypass.get("errors")},
                    )
                except AnalysisError as exc:
                    run.append_event("auto_emulator_bypass_failed", {"error": exc.projection()})
                continue
        if pid is None or status is None:
            raise fail(
                "process_died",
                "am start did not yield a running process",
                retryable=True,
                captured_output=((last_start.stderr or last_start.stdout) if last_start else "")[-4000:],
                remediation="The app may be crash-looping under Houdini/anti-emulator checks; try a reversible library rename, freeze_dd, or an ARM64 device.",
                details={
                    "package": package,
                    "activity": activity,
                    "returncode": last_start.returncode if last_start else None,
                    "auto_emulator_bypass_attempted": bypass_attempted,
                    "last_error": str(last_error) if last_error else None,
                },
            )
        run.update_run(stage="launched", package=package, artifacts={"pid": pid, "activity": activity})
        evidence = self._record(
            run,
            operation="launch_android_target",
            subject={"format": "process", "digest": {"package": package}, "architecture": None},
            provider="adb",
            predicate_type="process.launch",
            parameters={"serial": serial, "package": package, "activity": activity, "force_stop": force_stop},
            normalized_result={"pid": pid, "package": package, "activity": activity, "status": status},
            confidence="observed",
            authority="live-device",
            limitations=["A launched process may exit immediately under anti-debug; check status and survival."],
            locations=[{"kind": "device-path", "path": f"/proc/{pid}"}],
        )
        if bypass_attempted:
            self._remember_launch_bypass(run, inspection, pid, evidence["evidence_id"])
        return self._result(run, evidence, pid=pid, package=package, activity=activity, status=status)

    def inspect_process_state(
        self,
        run_id: str,
        *,
        serial: str | None = None,
        pid: int | None = None,
        package_name: str | None = None,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        serial = self._serial(serial)
        package = self._package_for(run, package_name)
        if pid is not None:
            pid_selection = self._validated_pid(serial, pid, package)
        else:
            selection = self.process.find_pid_candidates(serial, package)
            if selection["main_pid"] is None:
                raise fail(
                    "process_not_running",
                    f"process not running: {package}",
                    details={"package": package, "candidates": selection["candidates"]},
                )
            pid_selection = selection
            pid = int(selection["main_pid"])
        status = self.process.status(serial, pid)
        maps = self.process.maps(serial, pid)
        inspection = self._inspection_for(run)
        shell = (inspection.get("packing") or {}).get("primary")
        ranked = self.memory.rank_regions(maps, shell=shell)
        mapped_libs = sorted(
            {
                region.path
                for region in maps
                if region.path.endswith(".so")
            }
        )
        frida_maps = [path for path in mapped_libs if "frida" in path.lower()]
        result = {
            "pid": pid,
            "package": package,
            "pid_selection": pid_selection,
            "status": status,
            "map_count": len(maps),
            "mapped_libs": mapped_libs[:200],
            "frida_maps": frida_maps,
            "candidate_regions": [region.to_dict() for region in ranked[:30]],
            "dalvik_dex_regions": [
                region.to_dict() for region in maps if "dalvik-dex" in (region.path or "").lower()
            ],
        }
        run.update_run(stage="process_inspected", artifacts={"process": result})
        evidence = self._record(
            run,
            operation="inspect_process_state",
            subject={"format": "process", "digest": {"package": package, "pid": pid}},
            provider="memory",
            predicate_type="process.inspect",
            parameters={"serial": serial, "pid": pid, "package": package},
            normalized_result=result,
            confidence="observed",
            authority="live-device",
            limitations=[
                "Region scores are heuristics derived from the knowledge base, not proof that a DEX is present.",
                "TracerPid != 0 indicates ptrace; attach may be blocked.",
            ],
            locations=[{"kind": "device-path", "path": f"/proc/{pid}/maps"}],
        )
        return self._result(run, evidence, process=result)

    # ------------------------------------------------------------------ lessons / memory
    def recall_unpack_lessons(
        self,
        *,
        query: str | None = None,
        shell: str | None = None,
        device_abi: str | None = None,
        apk_abis: list[str] | None = None,
        framework: str | None = None,
        package_name: str | None = None,
        tags: list[str] | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        return self.lessons.recall(
            query=query,
            shell=shell,
            device_abi=device_abi,
            apk_abis=apk_abis,
            framework=framework,
            package_name=package_name,
            tags=tags,
            limit=limit,
        )

    def export_unpack_lessons(self) -> dict[str, Any]:
        return self.lessons.export_document()

    def import_unpack_lessons(self, document: Any) -> dict[str, Any]:
        return self.lessons.import_document(document, source="web-import")

    def remember_unpack_lesson(
        self,
        *,
        title: str,
        scenario: str,
        solution: str,
        root_cause: str | None = None,
        shell: str | None = None,
        device_abi: str | None = None,
        apk_abis: list[str] | None = None,
        framework: str | None = None,
        package_name: str | None = None,
        winning_method: str | None = None,
        failed_methods: list[Any] | None = None,
        symptoms: list[str] | None = None,
        tags: list[str] | None = None,
        evidence_links: list[str] | None = None,
        confidence: str = "analyst",
        scope: str = "global",
    ) -> dict[str, Any]:
        if scope not in ("global", "package"):
            raise fail("invalid_input", "scope must be global or package")
        if scope == "package" and not package_name:
            raise fail("invalid_input", "package_name is required when scope=package")
        payload = {
            "title": title,
            "scenario": scenario,
            "root_cause": root_cause,
            "solution": solution,
            "shell": shell,
            "device_abi": device_abi,
            "apk_abis": apk_abis or [],
            "framework": framework,
            "package_scope": package_name if scope == "package" else "global",
            "winning_method": winning_method,
            "failed_methods": failed_methods or [],
            "symptoms": symptoms or [],
            "tags": tags or [],
            "evidence_links": evidence_links or [],
            "confidence": confidence,
        }
        lesson, status = self.lessons.record(payload, kind="manual", success=True)
        return {
            "memory_dir": str(self.lessons.root),
            "status": status,
            "lesson": lesson,
            "stats": self.lessons.stats(),
        }

    def _lesson_context(
        self,
        inspection: dict[str, Any],
        device: dict[str, Any] | None = None,
        process: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        frameworks = inspection.get("frameworks") or []
        framework = frameworks[0].get("name") if frameworks else None
        return self.lessons.recall(
            shell=(inspection.get("packing") or {}).get("primary"),
            device_abi=(device or {}).get("abi"),
            apk_abis=inspection.get("abis") or [],
            framework=framework,
            package_name=(inspection.get("package") or {}).get("name"),
            limit=8,
        )

    def _remember_dump_lesson(
        self,
        run: RunWorkspace,
        inspection: dict[str, Any],
        attempts: list[dict[str, Any]],
        winning_method: str,
        evidence_id: str,
    ) -> None:
        failures = [item for item in attempts if item.get("status") in ("failed", "incomplete")]
        if not failures:
            return
        shell = (inspection.get("packing") or {}).get("primary") or "unknown"
        device = self._device_artifact(run) or {}
        frameworks = inspection.get("frameworks") or []
        failed_methods = [
            {
                "method": item.get("method"),
                "code": (item.get("error") or {}).get("code"),
                "message": (item.get("error") or {}).get("message"),
            }
            for item in failures
        ]
        symptoms = []
        for item in failures:
            error = item.get("error") or {}
            text = f"{item.get('method')} failed: {error.get('message') or error.get('code')}"
            captured = str(error.get("captured_output") or "").strip()
            if captured:
                text += f" ({captured[:240]})"
            symptoms.append(text)
        failed_labels = " + ".join(str(item.get("method")) for item in failures)
        title = f"{shell}: {failed_labels} → {winning_method}"
        abi_class = apk_abi_class(inspection.get("abis") or [])
        payload = {
            "title": title,
            "scenario": "DEX dump automatic fallback",
            "shell": shell,
            "device_abi": device.get("abi"),
            "apk_abi_class": abi_class,
            "framework": frameworks[0].get("name") if frameworks else None,
            "package_scope": "global",
            "symptoms": symptoms,
            "root_cause": _infer_dump_root_cause(failures),
            "solution": (
                f"On this shell/device profile, {winning_method} succeeded after "
                f"{failed_labels}. Use the learned fallback order, and keep the "
                f"documented do-not-attempt rules."
            ),
            "winning_method": winning_method,
            "failed_methods": failed_methods,
            "tags": ["auto", "dump", shell, winning_method, device.get("abi") or "unknown", abi_class],
            "evidence_links": [f"run:{run.run_id}", f"ev:{evidence_id}"],
            "examples": [
                {
                    "run_id": run.run_id,
                    "package": (inspection.get("package") or {}).get("name"),
                    "evidence_id": evidence_id,
                    "timestamp": utc_now(),
                }
            ],
            "confidence": "observed",
            "limitations": [
                "Automatically recorded from one observed fallback chain; verify on another sample before treating it as a universal rule."
            ],
        }
        try:
            lesson, status = self.lessons.record(payload, kind="auto", success=True)
            run.append_event(
                "memory_recorded",
                {"lesson_id": lesson["lesson_id"], "status": status, "title": lesson["title"]},
            )
        except Exception as exc:
            run.append_event("memory_record_failed", {"error": str(exc)})

    def _remember_launch_bypass(
        self,
        run: RunWorkspace,
        inspection: dict[str, Any],
        pid: int,
        evidence_id: str,
    ) -> None:
        shell = (inspection.get("packing") or {}).get("primary") or "unknown"
        device = self._device_artifact(run) or {}
        frameworks = inspection.get("frameworks") or []
        abi_class = apk_abi_class(inspection.get("abis") or [])
        payload = {
            "title": f"{shell}: emulator-detection crash loop → auto emulator-library bypass",
            "scenario": "App crash-loops on an x86/x86_64 emulator before DEX work",
            "shell": shell,
            "device_abi": device.get("abi"),
            "apk_abi_class": abi_class,
            "framework": frameworks[0].get("name") if frameworks else None,
            "package_scope": "global",
            "symptoms": [
                "am start -W returned non-zero and no stable process was observed",
                "process died shortly after start under Houdini/native-bridge",
            ],
            "root_cause": "An anti-emulator library (for example libijm-emulator.so) terminates the process before DEX work completes.",
            "solution": "Reversibly rename libijm-emulator.so / libijmdetect-drisk.so inside the target package directory, then relaunch.",
            "winning_method": "auto_emulator_bypass",
            "failed_methods": [{"method": "launch", "code": "process_died", "message": "crash loop"}],
            "tags": ["auto", "launch", "emulator-bypass", shell, device.get("abi") or "unknown", abi_class],
            "evidence_links": [f"run:{run.run_id}", f"ev:{evidence_id}"],
            "examples": [
                {
                    "run_id": run.run_id,
                    "package": (inspection.get("package") or {}).get("name"),
                    "evidence_id": evidence_id,
                    "timestamp": utc_now(),
                }
            ],
            "confidence": "observed",
            "limitations": [
                "The bypass is scoped to the target package directory and is restored by cleanup_run."
            ],
        }
        try:
            lesson, status = self.lessons.record(payload, kind="auto", success=True)
            run.append_event(
                "memory_recorded",
                {"lesson_id": lesson["lesson_id"], "status": status, "title": lesson["title"]},
            )
        except Exception as exc:
            run.append_event("memory_record_failed", {"error": str(exc)})

    # ------------------------------------------------------------------ strategy
    def _augment_strategy_with_lessons(
        self,
        strategy: dict[str, Any],
        inspection: dict[str, Any],
        device: dict[str, Any] | None,
        process: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Apply recalled lessons to a deterministic strategy."""

        # Historical lessons are evidence, not authority: they may reorder
        # fallbacks or promote a repeatedly successful primary, but they never
        # override the documented do-not-attempt rules.
        lesson_context: dict[str, Any] = {"lessons": [], "total": 0}
        try:
            lesson_context = self._lesson_context(inspection, device, process)
        except AnalysisError as exc:
            lesson_context = {"lessons": [], "total": 0, "error": exc.projection()}
        recalled = [
            lesson
            for lesson in (lesson_context.get("lessons") or [])
            # WP-D3 marks user-imported lessons as untrusted; they must never
            # steer the deterministic strategy.
            if lesson.get("trusted") is not False
        ]
        strategy["lessons"] = [
            {
                "lesson_id": lesson.get("lesson_id"),
                "title": lesson.get("title"),
                "solution": lesson.get("solution"),
                "winning_method": lesson.get("winning_method"),
                "occurrences": lesson.get("occurrences"),
                "success_count": lesson.get("success_count"),
                "confidence": lesson.get("confidence"),
                "scope": lesson.get("package_scope"),
                "trusted": lesson.get("trusted", True),
                "score": lesson.get("score"),
                "relevance_reasons": lesson.get("relevance_reasons"),
            }
            for lesson in recalled[:8]
        ]
        strategy["lesson_stats"] = lesson_context.get("stats")
        do_not = set(strategy.get("do_not_attempt") or [])
        fallbacks = list(strategy.get("fallbacks") or [])
        current_primary = strategy.get("primary")
        learned_primary: str | None = None
        adjustments: list[dict[str, Any]] = []
        for lesson in recalled:
            method = lesson.get("winning_method")
            if method not in DUMP_METHODS or method in do_not:
                continue
            occurrences = int(lesson.get("occurrences") or 0)
            successes = int(lesson.get("success_count") or 0)
            ratio = (successes / occurrences) if occurrences else 0.0
            failed_names = {str(item.get("method")) for item in lesson.get("failed_methods") or []}
            if (
                learned_primary is None
                and method != current_primary
                and occurrences >= 3
                and ratio >= 0.8
                and current_primary in failed_names
            ):
                learned_primary = str(method)
                adjustments.append(
                    {
                        "kind": "primary",
                        "method": method,
                        "lesson_id": lesson.get("lesson_id"),
                        "occurrences": occurrences,
                        "success_rate": round(ratio, 2),
                        "reason": "repeatedly succeeded where the deterministic primary failed",
                    }
                )
                continue
            if method == current_primary or method == learned_primary:
                continue
            if occurrences >= 2 and ratio >= 0.6:
                if fallbacks and fallbacks[0] == method:
                    adjustments.append(
                        {
                            "kind": "confirmed",
                            "method": method,
                            "lesson_id": lesson.get("lesson_id"),
                            "occurrences": occurrences,
                            "success_rate": round(ratio, 2),
                            "reason": "already the first fallback; repeated observations confirm the order",
                        }
                    )
                else:
                    if method in fallbacks:
                        fallbacks.remove(method)
                    fallbacks.insert(0, str(method))
                    adjustments.append(
                        {
                            "kind": "fallback",
                            "method": method,
                            "lesson_id": lesson.get("lesson_id"),
                            "occurrences": occurrences,
                            "success_rate": round(ratio, 2),
                            "reason": "promoted ahead of the default fallback order",
                        }
                    )
        strategy["fallbacks"] = list(dict.fromkeys(fallbacks))
        strategy["learned_primary"] = learned_primary
        strategy["learned_adjustments"] = adjustments
        if learned_primary:
            strategy.setdefault("notes", []).append(
                f"Learned primary {learned_primary} from repeated observed successes; review the linked lesson before relying on it."
            )
        if lesson_context.get("error"):
            strategy.setdefault("limitations", []).append(
                "Memory recall failed; strategy used the deterministic rules only."
            )
        return strategy

    def recommend_unpack_strategy(
        self,
        run_id: str,
        *,
        inspection_evidence_id: str | None = None,
        device_evidence_id: str | None = None,
        process_evidence_id: str | None = None,
        force_dump: bool = False,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        artifacts = self._run_artifacts(run)
        inspection = artifacts.get("inspection")
        if not inspection:
            raise fail("invalid_input", "run has no APK inspection; call inspect_apk first")
        device = artifacts.get("device")
        process = artifacts.get("process")
        force_dump = force_dump or bool(run.load_run().get("runtime_dump_required"))
        if force_dump:
            run.update_run(runtime_dump_required=True)
        strategy = recommend_strategy(inspection, device, process, force_dump=force_dump)

        strategy = self._augment_strategy_with_lessons(strategy, inspection, device, process)

        links = [item for item in (inspection_evidence_id, device_evidence_id, process_evidence_id) if item]
        evidence = self._record(
            run,
            operation="recommend_unpack_strategy",
            subject=self._apk_subject(inspection),
            provider="apk",
            predicate_type="strategy.recommend",
            parameters={"inspection_evidence_id": inspection_evidence_id, "force_dump": force_dump},
            normalized_result=strategy,
            confidence=strategy.get("confidence", "derived"),
            authority="analyst-inference",
            limitations=["Strategy ranking is derived from documented case behavior and current device facts; runtime behavior remains unverified until executed."],
            evidence_links=links,
        )
        run.update_run(stage="strategy_ready", strategy=strategy)
        return self._result(run, evidence, strategy=strategy)

    # ------------------------------------------------------------------ dump acceptance
    def _assess_candidate(self, candidate: dict[str, Any], expected_package: str | None, target_packages: list[str] | None = None) -> dict[str, Any]:
        """Re-assess one dumped candidate with the shared Wave 1 DEX validator.

        Provider-reported ``complete`` flags are not trusted: a header-only
        check or a zero-filled memory hole can look valid there.  The shared
        assessment is authoritative, and a candidate is only a target result
        when it is complete and (if the package is known) contains classes from
        that package.
        """

        path = candidate.get("local_path")
        if not path or not Path(path).is_file():
            candidate.update(
                {
                    "complete": False,
                    "target": False,
                    "reasons": ["candidate_missing"],
                    "assessment": None,
                }
            )
            return candidate
        assessment = assess_dex(path, expected_package, target_packages=target_packages)
        payload = assessment.to_dict()
        forced_holes = int(candidate.get("dump_holes") or 0)
        reasons = list(assessment.reasons)
        if forced_holes:
            # Short reads are zero-filled by the dump path; the DEX content may
            # not contain a full 4 KiB zero block, so propagate the hole here
            # and keep the stored assessment consistent with the verdict.
            reasons.append(f"dump_zero_fill={forced_holes}")
            payload["complete"] = False
            payload["repairable_complete"] = False
            payload["reasons"] = reasons
            payload["dump_holes"] = forced_holes
        # A live dump may carry a stale checksum/signature while the class table
        # and code are intact.  Repair recomputes those header fields, so accept
        # repairable content here; the post-repair verification is what decides
        # whether the job may succeed.
        repairable = bool(assessment.repairable_complete and forced_holes == 0)
        target = bool(repairable and (expected_package is None or assessment.package_classes > 0))
        candidate.update(
            {
                "size": assessment.actual_size,
                "file_size": assessment.declared_size,
                "class_defs_size": assessment.class_defs,
                "classes_with_code": assessment.classes_with_code,
                "package_classes": assessment.package_classes,
                "holes": assessment.holes + (1 if forced_holes else 0),
                "truncated": assessment.truncated,
                "complete": repairable,
                "content_complete": assessment.content_complete and forced_holes == 0,
                "repairable_complete": repairable,
                "checksum_ok": assessment.checksum_ok,
                "signature_ok": assessment.signature_ok,
                "target": target,
                "accepted": target,
                "expected_package": expected_package,
                "reasons": reasons,
                "assessment": payload,
            }
        )
        notes = list(candidate.get("notes") or [])
        for reason in reasons:
            if reason not in notes:
                notes.append(reason)
        if expected_package and assessment.package_classes == 0:
            notes.append(f"no classes from target package {expected_package}")
        candidate["notes"] = notes
        return candidate

    def _accept_candidates(
        self,
        outcome: dict[str, Any],
        expected_package: str | None,
        target_packages: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for candidate in outcome.get("candidates") or []:
            self._assess_candidate(candidate, expected_package, target_packages)
            (accepted if candidate.get("target") else rejected).append(candidate)
        outcome["accepted_candidates"] = accepted
        outcome["rejected_candidates"] = rejected
        return accepted, rejected

    def _validated_pid(self, serial: str, pid: int, package: str) -> dict[str, Any]:
        validation = self.process.validate_pid(serial, pid, package)
        if validation.get("alive") is False:
            raise fail(
                "process_died", f"target pid {pid} exited before process inspection",
                retryable=True, details={"package": package, "pid": pid, "validation": validation},
                remediation="Inspect the startup/device logs or select a compatible runtime; an exited PID does not establish a package mismatch.",
            )
        if not validation.get("valid"):
            raise fail(
                "process_mismatch",
                f"pid {pid} does not belong to package {package}",
                details={"package": package, "pid": pid, "validation": validation},
            )
        return validation

    # ------------------------------------------------------------------ dump
    def dump_android_dex(
        self,
        run_id: str,
        *,
        serial: str | None = None,
        package_name: str | None = None,
        pid: int | None = None,
        method: str = "auto",
        mode: str = "auto",
        apk_path: str | None = None,
        inner_bypass: bool = False,
        freeze_poll_ms: int = 80,
        freeze_timeout_ms: int = 15000,
        frida_timeout_ms: int | None = None,
        max_region_bytes: int | None = None,
        keep_device_files: bool = False,
        cancel: threading.Event | None = None,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        serial = self._serial(serial)
        package = self._package_for(run, package_name)
        inspection = self._inspection_for(run)
        pid_validation = self._validated_pid(serial, pid, package) if pid is not None else None
        artifacts = self._run_artifacts(run)
        device = artifacts.get("device") or {}
        process_state = artifacts.get("process") or {}
        strategy = self._augment_strategy_with_lessons(
            recommend_strategy(inspection, device, process_state,
                               force_dump=bool(run.load_run().get("runtime_dump_required"))),
            inspection,
            device,
            process_state,
        )
        if method == "auto":
            methods = []
            primary = strategy.get("learned_primary") or strategy.get("primary")
            fallbacks = list(strategy.get("fallbacks") or [])
            if primary in (None, "inspect", "static_jadx", "static_wgt"):
                primary = "frida_inmemory"
                fallbacks = ["frida_inmemory_spawn", "memory_dd", "freeze_dd"]
            if primary not in ("inspect", "static_jadx", "static_wgt"):
                methods.append(primary)
            for fallback in fallbacks:
                candidate = fallback
                if fallback == "frida_mcookie_spawn_anti_kill":
                    candidate = "frida_mcookie_spawn"
                if fallback == "arm64_device_fallback":
                    candidate = "arm64_device"
                if candidate not in methods:
                    methods.append(candidate)
        else:
            methods = [method]
        if not methods:
            raise fail("unsupported_target", "no dump method is applicable to this target", details={"strategy": strategy})

        layers = {item.get("shell") for item in (inspection.get("packing") or {}).get("layers") or []}
        already_bypassed = any(
            item.get("kind") == "rename_device_lib" and item.get("state") == "applied"
            for item in run.load_mutations()
        )
        if (inner_bypass or ("360" in layers and "secneo" in layers)) and not already_bypassed:
            self.prepare_android_environment(
                run.run_id,
                serial=serial,
                package_name=package,
                start_frida_server=False,
                inner_bypass=True,
                keep_device_files=keep_device_files,
            )
        frida_methods = {
            "frida_inmemory",
            "frida_inmemory_spawn",
            "frida_mcookie",
            "frida_mcookie_spawn",
            "disk_pull",
        }
        attempts: list[dict[str, Any]] = []
        all_evidence_ids: list[str] = []
        last_error: AnalysisError | None = None
        frida_prepare_error: AnalysisError | None = None
        partial_support: dict[str, dict[str, Any]] = {}
        for attempt_index, attempt_method in enumerate(methods):
            if cancel is not None and cancel.is_set():
                raise fail("cancelled", "dump cancelled")
            if attempt_method in ("static_jadx", "inspect"):
                raise fail("unsupported_target", f"method {attempt_method} is not a DEX dump")
            if attempt_method == "arm64_device":
                last_error = fail(
                    "unsupported_target",
                    "anti-debug blocks this emulator; an ARM64 physical device is likely required",
                    remediation="Retry on an ARM64 device with root and a matching frida-server.",
                )
                attempts.append({"method": attempt_method, "status": "unsupported", "error": last_error.projection()})
                continue
            run.append_event("dump_attempt", {"run_id": run_id, "method": attempt_method, "index": attempt_index})
            try:
                # Frida setup is specific to injection attempts. A missing or
                # incompatible server must not prevent an allowed memory fallback.
                if attempt_method in frida_methods:
                    if frida_prepare_error is not None:
                        raise frida_prepare_error
                    if not self._frida_reachable(serial):
                        try:
                            self.prepare_android_environment(
                                run.run_id,
                                serial=serial,
                                package_name=package,
                                start_frida_server=True,
                                keep_device_files=keep_device_files,
                            )
                        except AnalysisError as exc:
                            frida_prepare_error = exc
                            raise
                if attempt_method == "frida_inmemory":
                    outcome = self._attempt_frida_cookie(
                        run,
                        serial,
                        package,
                        inspection,
                        pid=pid,
                        spawn=(mode == "spawn"),
                        auto_spawn=(mode == "auto"),
                        anti_kill=False,
                        timeout_ms=frida_timeout_ms,
                        keep_device_files=keep_device_files,
                        cancel=cancel,
                    )
                elif attempt_method == "frida_inmemory_spawn":
                    outcome = self._attempt_frida_cookie(
                        run,
                        serial,
                        package,
                        inspection,
                        pid=None,
                        spawn=True,
                        auto_spawn=False,
                        anti_kill=True,
                        timeout_ms=frida_timeout_ms,
                        keep_device_files=keep_device_files,
                        cancel=cancel,
                    )
                elif attempt_method == "frida_mcookie":
                    outcome = self._attempt_frida_cookie(
                        run,
                        serial,
                        package,
                        inspection,
                        pid=pid,
                        spawn=(mode == "spawn"),
                        auto_spawn=(mode == "auto"),
                        anti_kill=False,
                        timeout_ms=frida_timeout_ms,
                        keep_device_files=keep_device_files,
                        cancel=cancel,
                    )
                elif attempt_method == "frida_mcookie_spawn":
                    outcome = self._attempt_frida_cookie(
                        run,
                        serial,
                        package,
                        inspection,
                        pid=None,
                        spawn=True,
                        auto_spawn=False,
                        anti_kill=True,
                        timeout_ms=frida_timeout_ms,
                        keep_device_files=keep_device_files,
                        cancel=cancel,
                    )
                elif attempt_method == "disk_pull":
                    outcome = self._attempt_frida_disk(
                        run,
                        serial,
                        package,
                        timeout_ms=frida_timeout_ms,
                        cancel=cancel,
                    )
                elif attempt_method in ("memory_dd", "memory_dd_retry"):
                    outcome = self._attempt_memory(
                        run,
                        serial,
                        package,
                        inspection,
                        pid=pid,
                        freeze=False,
                        freeze_timeout_ms=freeze_timeout_ms,
                        freeze_poll_ms=freeze_poll_ms,
                        max_region_bytes=max_region_bytes or self.config.max_region_bytes,
                        keep_device_files=keep_device_files,
                        cancel=cancel,
                        fresh_launch=(attempt_method == "memory_dd_retry"),
                    )
                elif attempt_method == "freeze_dd":
                    outcome = self._attempt_memory(
                        run,
                        serial,
                        package,
                        inspection,
                        pid=pid,
                        freeze=True,
                        freeze_timeout_ms=freeze_timeout_ms,
                        freeze_poll_ms=freeze_poll_ms,
                        max_region_bytes=max_region_bytes or self.config.max_region_bytes,
                        keep_device_files=keep_device_files,
                        cancel=cancel,
                    )
                else:
                    raise fail("invalid_input", f"unknown dump method: {attempt_method}")
            except AnalysisError as exc:
                last_error = exc
                attempts.append({"method": attempt_method, "status": "failed", "error": exc.projection()})
                run.append_event("dump_attempt_failed", {"method": attempt_method, "error": exc.projection()})
                if method != "auto" or exc.code in ("cancelled", "cleanup_incomplete"):
                    raise
                continue
            accepted, rejected = self._accept_candidates(outcome, package, target_namespaces(inspection))
            # Keep companion libraries only from an observed anonymous DEX
            # dump that also contains recoverable target code. They help JADX
            # resolve dependencies but do not establish target recovery alone.
            if any((c.get("assessment") or {}).get("recoverable")
                   for c in outcome.get("candidates") or []):
                for candidate in outcome.get("candidates") or []:
                    path = candidate.get("local_path")
                    if not path or "dalvik-dex" not in candidate.get("memory_mapping", "").lower():
                        continue
                    if (candidate.get("assessment") or {}).get("package_classes"):
                        continue
                    support = assess_dex(path)
                    if support.recoverable:
                        partial_support[path] = {
                            **candidate, "accepted": False, "complete": False,
                            "retained": True, "role": "supporting_library",
                            "assessment": support.to_dict(), "reasons": support.reasons,
                        }
            if not accepted:
                reasons: list[str] = []
                for candidate in rejected:
                    for reason in candidate.get("reasons") or []:
                        if reason not in reasons:
                            reasons.append(reason)
                incomplete = fail(
                    "dump_incomplete",
                    f"{attempt_method} produced no complete DEX for {package}",
                    retryable=True,
                    details={
                        "method": attempt_method,
                        "package": package,
                        "candidate_count": len(outcome.get("candidates") or []),
                        "reasons": reasons,
                        "rejected": [
                            {
                                "local_path": item.get("local_path"),
                                "source": item.get("source"),
                                "truncated": item.get("truncated"),
                                "holes": item.get("holes"),
                                "package_classes": item.get("package_classes"),
                                "reasons": item.get("reasons"),
                            }
                            for item in rejected[:10]
                        ],
                    },
                )
                last_error = incomplete
                attempts.append(
                    {
                        "method": attempt_method,
                        "status": "incomplete",
                        "candidate_count": len(outcome.get("candidates") or []),
                        "rejected_count": len(rejected),
                        "reasons": reasons,
                        "error": incomplete.projection(),
                    }
                )
                run.append_event(
                    "dump_attempt_incomplete",
                    {"method": attempt_method, "reasons": reasons, "candidates": len(rejected)},
                )
                if method != "auto":
                    break
                continue
            evidence = self._record(
                run,
                operation="dump_android_dex",
                subject=self._apk_subject(inspection),
                provider="frida" if "frida" in attempt_method else "memory",
                predicate_type="dex.dump",
                parameters={
                    "method": attempt_method,
                    "mode": mode,
                    "package": package,
                    "pid": outcome.get("pid"),
                    "serial": serial,
                    "pid_validation": pid_validation,
                },
                normalized_result=outcome,
                confidence="observed",
                authority="live-device",
                limitations=outcome.get("limitations") or [],
                locations=[
                    {"kind": "artifact-path", "path": candidate["local_path"]}
                    for candidate in outcome.get("candidates") or []
                ],
            )
            all_evidence_ids.append(evidence["evidence_id"])
            attempts.append({"method": attempt_method, "status": "succeeded", "evidence_id": evidence["evidence_id"]})
            self._remember_dump_lesson(run, inspection, attempts, attempt_method, evidence["evidence_id"])
            if outcome.get("emulator_bypass"):
                self._remember_launch_bypass(
                    run, inspection, int(outcome.get("pid") or 0), evidence["evidence_id"]
                )
            run.update_run(
                stage="dumped",
                attempts=attempts,
                artifacts={
                    "raw_dir": str(run.raw_dir),
                    "last_dump": outcome,
                    "pid": outcome.get("pid"),
                },
            )
            return self._result(
                run,
                evidence,
                method=attempt_method,
                candidates=outcome.get("candidates") or [],
                accepted_candidates=accepted,
                skipped_candidates=rejected,
                attempts=attempts,
            )
        # Keep coded target DEX even when holes prevent complete validation.
        # Exhaust the permitted fallbacks first; partial recovery is never a
        # successful method observation and cannot promote a memory lesson.
        partial_candidates = []
        for path in sorted(run.raw_dir.glob("*.dex")):
            assessment = assess_dex(path, package, target_packages=target_namespaces(inspection))
            if assessment.recoverable:
                partial_candidates.append({
                    "local_path": str(path), "source": "run_raw", "accepted": False,
                    "complete": False, "retained": True, "assessment": assessment.to_dict(),
                    "reasons": assessment.reasons,
                })
        if partial_candidates:
            partial_candidates.extend(partial_support.values())
            limitations = ["Partial target bytecode retained for best-effort repair/JADX; missing bytes and methods remain unknown."]
            outcome = {"status": "partial", "complete": False, "method": "partial_recovery",
                       "candidates": partial_candidates, "attempts": attempts, "limitations": limitations}
            evidence = self._record(
                run, operation="dump_android_dex", subject=self._apk_subject(inspection),
                provider="dex", predicate_type="dex.dump.partial",
                parameters={"method": method, "serial": serial, "package": package},
                normalized_result=outcome, confidence="observed", authority="live-device",
                limitations=limitations,
                locations=[{"kind": "artifact-path", "path": c["local_path"]} for c in partial_candidates],
            )
            run.update_run(stage="dump_partial", attempts=attempts, artifacts={"raw_dir": str(run.raw_dir), "last_dump": outcome})
            return self._result(run, evidence, **outcome, accepted_candidates=[], skipped_candidates=[])
        run.update_run(stage="dump_failed", attempts=attempts)
        if last_error is not None:
            last_error.partial = {"run_id": run.run_id, "attempts": attempts}
            raise last_error
        raise fail("dump_incomplete", "all dump methods failed", details={"attempts": attempts})

    # ------------------------------------------------------------------ frida attempts
    def _attempt_frida_cookie(
        self,
        run: RunWorkspace,
        serial: str,
        package: str,
        inspection: dict[str, Any],
        *,
        pid: int | None,
        spawn: bool,
        auto_spawn: bool,
        anti_kill: bool,
        timeout_ms: int | None,
        keep_device_files: bool,
        cancel: threading.Event | None,
    ) -> dict[str, Any]:
        if not spawn and pid is None:
            try:
                pid = self.process.find_pid(serial, package)
            except AnalysisError:
                if not auto_spawn:
                    raise
                spawn = True
        if spawn and not self._frida_reachable(serial):
            self.prepare_android_environment(
                run.run_id,
                serial=serial,
                package_name=package,
                start_frida_server=True,
                keep_device_files=keep_device_files,
            )
        activity = (inspection.get("package") or {}).get("launchable_activity")
        effective_timeout = timeout_ms or self.config.frida_timeout_ms
        config = {
            "run_id": run.run_id,
            "package": package,
            "activity_class": activity,
            "anti_kill": anti_kill,
            "ready_timeout_ms": 30000,
            # Let the script report before the host deadline so its events are retained.
            "hard_timeout_ms": max(10000, effective_timeout - 5000),
        }
        frida_result = self.frida.run_script(
            "dump_cookie.js",
            config,
            pid=None if spawn else pid,
            package=package,
            spawn=spawn,
            timeout_ms=timeout_ms,
            cancel=cancel,
            host=self.config.frida_host_for(serial),
        )
        saved = [event for event in frida_result["events"] if event.get("type") == "saved"]
        ready = next((event for event in frida_result["events"] if event.get("type") == "ready" and event.get("out_dir")), None)
        device_dir = ready.get("out_dir") if ready else None
        candidates: list[dict[str, Any]] = []
        limitations: list[str] = []
        try:
            for index, event in enumerate(saved):
                device_path = event.get("path")
                size = int(event.get("size") or 0)
                if not device_path:
                    continue
                local_path = run.raw_dir / f"frida_{index:02d}_{Path(device_path).name}"
                pull = self.adb.pull(serial, device_path, local_path)
                if not pull.ok or not local_path.is_file():
                    limitations.append(f"failed to pull {device_path}: {pull.stderr or pull.stdout}")
                    continue
                actual = local_path.stat().st_size
                candidate = {
                    "label": event.get("label") or f"frida_{index}",
                    "source": "frida-cookie",
                    "local_path": str(local_path),
                    "device_path": device_path,
                    "loader": event.get("loader"),
                    "loader_id": event.get("loader_id"),
                    "loader_path": event.get("loader_path"),
                    "element_path": event.get("element_path"),
                    "dex_path": event.get("dex_path"),
                    "target_loader": event.get("target_loader"),
                    "sha256": sha256_file(local_path),
                    "notes": [] if actual == size else [f"pulled size {actual} != reported {size}"],
                }
                self._assess_candidate(candidate, package, target_namespaces(inspection))
                if event.get("target_loader") is False and not candidate.get("target"):
                    candidate["non_target_loader"] = True
                    candidate.setdefault("notes", []).append(
                        "loader is not the activity/app classloader (plugin or shell DEX)"
                    )
                    limitations.append(
                        f"{candidate['label']}: non-target loader {candidate.get('loader_id')}"
                    )
                candidates.append(candidate)
        finally:
            if device_dir and not keep_device_files:
                run_dir = str(Path(device_dir).parent)
                self.adb.remove(serial, run_dir)
        if not candidates:
            raise fail(
                "dump_incomplete",
                "Frida cookie dump produced no pulled DEX files",
                retryable=True,
                details={"events": frida_result["events"][-20:], "limitations": limitations},
            )
        return {
            "pid": frida_result["events"][0].get("pid") if frida_result["events"] else None,
            "method": "frida-cookie",
            "frida": {
                "events": frida_result["events"][-50:],
                "returncode": frida_result["returncode"],
                "duration_s": frida_result["duration_s"],
            },
            "candidates": candidates,
            "limitations": limitations,
        }

    def _attempt_frida_disk(
        self,
        run: RunWorkspace,
        serial: str,
        package: str,
        *,
        timeout_ms: int | None,
        cancel: threading.Event | None,
    ) -> dict[str, Any]:
        if not self._frida_reachable(serial):
            self.prepare_android_environment(run.run_id, serial=serial, package_name=package)
        try:
            pid = self.process.find_pid(serial, package)
        except AnalysisError:
            self.launch_android_target(run.run_id, serial=serial, package_name=package, force_stop=True)
            pid = self.process.wait_for_pid(serial, package, timeout_ms=5000)
        effective_timeout = timeout_ms or self.config.frida_timeout_ms
        config = {
            "run_id": run.run_id,
            "package": package,
            "ready_timeout_ms": 30000,
            "hard_timeout_ms": max(10000, effective_timeout - 5000),
        }
        frida_result = self.frida.run_script(
            "disk_path.js",
            config,
            pid=pid,
            package=package,
            spawn=False,
            timeout_ms=timeout_ms,
            cancel=cancel,
            host=self.config.frida_host_for(serial),
        )
        paths = [
            str(event.get("path"))
            for event in frida_result["events"]
            if event.get("type") in ("path", "saved") and str(event.get("path", "")).lower().endswith(".dex")
        ]
        if not paths:
            directories = [
                f"/data/user/0/{package}/files/prodexdir",
                f"/data/data/{package}/files/prodexdir",
                f"/data/user/0/{package}/code_cache",
            ]
            for directory in directories:
                for name in self.adb.list_dir(serial, directory):
                    if name.lower().endswith(".dex"):
                        paths.append(directory.rstrip("/") + "/" + name)
        paths = list(dict.fromkeys(paths))
        candidates: list[dict[str, Any]] = []
        limitations: list[str] = []
        for index, device_path in enumerate(paths):
            local_path = run.raw_dir / f"disk_{index:02d}_{Path(device_path).name}"
            pull = self.adb.pull(serial, device_path, local_path)
            if not pull.ok or not local_path.is_file():
                # MTP may be readable via run-as even when root pull fails.
                exec_out = self.adb.exec_out(serial, f"cat {shlex.quote(device_path)}", local_path, timeout=120)
                if not exec_out.ok or not local_path.is_file():
                    limitations.append(f"failed to pull {device_path}")
                    continue
            remote_size = self.adb.stat_size(serial, device_path)
            actual = local_path.stat().st_size
            notes: list[str] = []
            if remote_size is not None and actual != remote_size:
                notes.append(f"pulled {actual} bytes but device reports {remote_size} (short read)")
            candidate = {
                "label": Path(device_path).stem,
                "source": "disk-pull",
                "local_path": str(local_path),
                "device_path": device_path,
                "remote_size": remote_size,
                "sha256": sha256_file(local_path),
                "notes": notes,
            }
            self._assess_candidate(candidate, package, target_namespaces(self._inspection_for(run)))
            # A disk pull is success only when the bytes match the DEX header
            # file_size; the shared assessment rejects truncated/partial reads.
            if candidate.get("truncated"):
                notes.append(f"truncated: {actual} < header file_size {candidate.get('file_size')}")
            candidate["notes"] = notes
            candidates.append(candidate)
        if not candidates:
            raise fail(
                "dump_incomplete",
                "no on-disk DEX files were found for this package",
                retryable=True,
                details={"paths": paths[:50], "frida_events": frida_result["events"][-20:]},
            )
        return {
            "pid": None,
            "method": "disk-pull",
            "frida": {"events": frida_result["events"][-50:], "returncode": frida_result["returncode"]},
            "candidates": candidates,
            "limitations": limitations,
        }

    def _frida_reachable(self, serial: str | None = None) -> bool:
        return bool(self.frida.probe(host=self.config.frida_host_for(serial)).get("reachable"))

    def _last_evidence_id(self, run: RunWorkspace, operation: str) -> str | None:
        records, _ = run.read_evidence(operation=operation, limit=1_000_000)
        return records[-1]["evidence_id"] if records else None

    def _device_frida_server_version(self, serial: str, server_path: str) -> str | None:
        result = self.adb.shell(
            serial, f"{shlex.quote(server_path)} --version 2>/dev/null", timeout=10
        )
        text = (result.stdout or "").strip()
        if result.ok and text and "__APU_MISSING__" not in text:
            return text.splitlines()[-1].strip()
        return None

    def _local_frida_server_version(self, local_server: str | None) -> str | None:
        if not local_server or not Path(local_server).is_file():
            return None
        # Running the binary is the authoritative check when the host can
        # execute it; the filename of official frida-server builds also
        # carries the version (frida-server-16.1.4-android-x86_64).
        try:
            result = self.host.run([local_server, "--version"], timeout=10)
        except OSError:
            result = None
        if result is not None and result.ok and (result.stdout or "").strip():
            candidate = result.stdout.strip().splitlines()[-1].strip()
            if re.fullmatch(r"\d+\.\d+(\.\d+)?([-.+][^\s]*)?", candidate):
                return candidate
        match = re.search(r"frida-server-(\d+\.\d+(?:\.\d+)?)", Path(local_server).name)
        return match.group(1) if match else None

    def _is_frida_server_pid(self, serial: str, pid: int) -> bool:
        result = self.adb.shell(serial, "ps -A 2>/dev/null", timeout=15)
        if not result.ok:
            return False
        for line in result.stdout.splitlines():
            parts = line.split()
            if str(pid) in parts[:2] and "frida-server" in line:
                return True
        return False

    # ------------------------------------------------------------------ memory attempts
    @staticmethod
    def _annotate_dump_holes(
        candidates: list[dict[str, Any]],
        hole_regions: list[dict[str, Any]],
        base_address: int,
    ) -> None:
        """Propagate zero-filled dump ranges onto overlapping DEX candidates."""

        if not hole_regions or not candidates:
            return
        for candidate in candidates:
            vaddr = candidate.get("vaddr")
            if vaddr is None:
                continue
            start = int(vaddr)
            end = start + int(candidate.get("size") or 0)
            overlap = 0
            for hole in hole_regions:
                hole_start = int(
                    hole.get("address") or (base_address + int(hole.get("offset") or 0))
                )
                hole_end = hole_start + int(hole.get("size") or 0)
                overlap += max(0, min(end, hole_end) - max(start, hole_start))
            if overlap:
                candidate["dump_holes"] = overlap
                notes = list(candidate.get("notes") or [])
                notes.append(
                    f"{overlap} byte(s) of this candidate came from a zero-filled dump hole/short read"
                )
                candidate["notes"] = notes

    def _attempt_memory(
        self,
        run: RunWorkspace,
        serial: str,
        package: str,
        inspection: dict[str, Any],
        *,
        pid: int | None,
        freeze: bool,
        freeze_timeout_ms: int,
        freeze_poll_ms: int,
        max_region_bytes: int,
        keep_device_files: bool,
        cancel: threading.Event | None,
        fresh_launch: bool = False,
    ) -> dict[str, Any]:
        self.adb.ensure_root(serial)
        shell = (inspection.get("packing") or {}).get("primary")
        arm_only_on_x86 = _arm_only_on_x86(inspection, self._device_artifact(run) or {})
        emulator_bypass = any(
            item.get("kind") == "rename_device_lib" and item.get("state") == "applied"
            for item in run.load_mutations()
        )
        if shell == "ijiami" and arm_only_on_x86 and not emulator_bypass:
            # ARM-only ijiami on x86/x86_64 often crashes before the DEX window.
            # Apply the documented reversible rename first; cleanup restores it.
            try:
                bypass = self.prepare_android_environment(
                    run.run_id,
                    serial=serial,
                    package_name=package,
                    start_frida_server=False,
                    rename_libs=["libijm-emulator.so", "libijmdetect-drisk.so"],
                )
                emulator_bypass = any(
                    action.get("action") == "rename_device_lib" and action.get("mutation_id")
                    for action in bypass.get("actions") or []
                )
                run.append_event(
                    "proactive_emulator_bypass",
                    {"actions": bypass.get("actions"), "errors": bypass.get("errors")},
                )
            except AnalysisError as exc:
                run.append_event("proactive_emulator_bypass_failed", {"error": exc.projection()})
        pid = self._launch_if_needed(run, serial, package, inspection, pid, freeze, fresh_launch)
        remote_dir = f"/data/local/tmp/apu/{run.run_id}"
        self.adb.mkdirs(serial, remote_dir)
        self.adb.chmod(serial, "777", remote_dir)
        stopped = False
        stop_mutation: dict[str, Any] | None = None
        try:
            if freeze:
                predicate = _freeze_predicate(shell)
                started = time.monotonic()
                deadline = started + freeze_timeout_ms / 1000.0
                region = None
                refresh_count = 0
                stop_reason = "timeout"
                while time.monotonic() < deadline:
                    remaining_ms = max(300, int((deadline - time.monotonic()) * 1000))
                    region, _ = self.process.wait_for_map(
                        serial,
                        pid,
                        predicate,
                        timeout_ms=min(1500, remaining_ms),
                        interval_ms=freeze_poll_ms,
                    )
                    if region is not None:
                        break
                    if self.process.is_alive(serial, pid):
                        continue
                    # Crash-looping apps can replace the process while we poll.
                    refresh_count += 1
                    if refresh_count > 2:
                        stop_reason = "process_restart_limit"
                        break
                    try:
                        pid = self.process.wait_for_pid(
                            serial, package, timeout_ms=min(1500, remaining_ms)
                        )
                    except AnalysisError:
                        try:
                            self.launch_android_target(
                                run.run_id,
                                serial=serial,
                                package_name=package,
                                force_stop=True,
                            )
                            pid = self.process.wait_for_pid(
                                serial, package, timeout_ms=min(2000, remaining_ms)
                            )
                        except AnalysisError:
                            stop_reason = "process_unavailable"
                            break
                if region is None:
                    elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
                    message = (
                        f"no freeze target region appeared within {freeze_timeout_ms} ms"
                        if stop_reason == "timeout"
                        else f"target process kept exiting before a DEX region was observed; "
                        f"freeze capture stopped after {elapsed_ms} ms ({stop_reason}, "
                        f"configured limit {freeze_timeout_ms} ms)"
                    )
                    raise fail(
                        "dump_incomplete",
                        message,
                        retryable=stop_reason == "timeout",
                        details={"pid": pid, "shell": shell, "refresh_count": refresh_count,
                                 "stop_reason": stop_reason, "elapsed_ms": elapsed_ms,
                                 "timeout_ms": freeze_timeout_ms},
                    )
                if not self.process.signal(serial, pid, "STOP"):
                    raise fail("execution_failure", f"failed to SIGSTOP pid {pid}")
                stopped = True
                stop_mutation = run.add_mutation(
                    {
                        "kind": "kill_stop",
                        "target": f"pid:{pid}",
                        "detail": {"reason": "freeze_dd"},
                        "apply_command": ["adb", "-s", serial, "shell", f"kill -STOP {pid}"],
                        "restore_command": ["adb", "-s", serial, "shell", f"kill -CONT {pid}"],
                        "reversible": True,
                    }
                )
                status = self.process.status(serial, pid)
                if "T" not in (status.get("state") or ""):
                    raise fail("execution_failure", f"SIGSTOP did not freeze pid {pid}", details={"status": status})
            maps = self.process.maps(serial, pid)
            ranked = self.memory.rank_regions(maps, shell=shell)
            if not ranked:
                raise fail("dump_incomplete", "no candidate memory regions", details={"pid": pid})
            fast = arm_only_on_x86 or freeze or fresh_launch
            candidates: list[dict[str, Any]] = []
            region_reports: list[dict[str, Any]] = []
            limitations: list[str] = []
            skipped_regions: list[dict[str, Any]] = []
            # ijiami commonly maps several independent DEX payloads as separate
            # dalvik-DEX ashmem ranges. Scan the ranked ranges instead of
            # stopping at the first successful one. The cap is configurable so
            # real DEX regions are not silently dropped on larger maps.
            region_limit = max(1, int(self.config.dump_top_regions))
            candidate_limit = max(1, int(self.config.dump_max_candidates))
            scanned_regions = 0
            for index, region in enumerate(ranked[:region_limit]):
                if cancel is not None and cancel.is_set():
                    raise fail("cancelled", "memory dump cancelled")
                report = self._dump_region_candidates(
                    run,
                    serial,
                    pid,
                    region,
                    index,
                    remote_dir=remote_dir,
                    fast=fast,
                    max_region_bytes=max_region_bytes,
                    keep_device_files=keep_device_files,
                )
                region_reports.append(report)
                scanned_regions += 1
                candidates.extend(report.get("candidates") or [])
                if len(candidates) > candidate_limit:
                    dropped = len(candidates) - candidate_limit
                    del candidates[candidate_limit:]
                    limitations.append(
                        f"candidate cap ({candidate_limit}) reached; dropped {dropped} candidate(s)"
                    )
                if len(candidates) >= candidate_limit:
                    limitations.append(
                        f"candidate cap ({candidate_limit}) reached; remaining regions were not scanned"
                    )
                    break
            for region in ranked[scanned_regions:]:
                skipped_regions.append(
                    {
                        "start": region.start,
                        "size": region.size,
                        "path": region.path,
                        "score": region.score,
                        "reason": "region_cap" if scanned_regions >= region_limit else "candidate_cap",
                    }
                )
            spans = self._complete_memory_candidates(
                run, serial, pid, candidates, remote_dir=remote_dir,
                fast=fast, max_region_bytes=max_region_bytes, cancel=cancel,
            )
            if not candidates:
                raise fail(
                    "dump_incomplete",
                    "no DEX payload was found in the ranked memory regions",
                    retryable=True,
                    details={"pid": pid, "regions": region_reports, "skipped_regions": skipped_regions},
                )
            if skipped_regions:
                run.append_event(
                    "dump_regions_skipped",
                    {
                        "pid": pid,
                        "skipped": len(skipped_regions),
                        "reason": skipped_regions[0]["reason"],
                        "starts": [item["start"] for item in skipped_regions[:20]],
                    },
                )
            dumped_bytes = sum(
                int(((report.get("dump") or {}).get("size") or 0)) for report in region_reports
            ) + sum(int((report.get("dump") or {}).get("size") or 0) for report in spans)
            hole_bytes = sum(
                int(((report.get("dump") or {}).get("holes") or 0)) for report in region_reports
            ) + sum(int((report.get("dump") or {}).get("holes") or 0) for report in spans)
            coverage = {
                "ranked_regions": len(ranked),
                "scanned_regions": scanned_regions,
                "skipped_regions": skipped_regions,
                "candidate_cap": candidate_limit,
                "top_regions": region_limit,
                "candidate_count": len(candidates),
                "bytes_dumped": dumped_bytes,
                "hole_bytes": hole_bytes,
                "max_region_bytes": max_region_bytes,
                "candidate_span_attempts": len(spans),
                "zero_ratio_threshold": self.config.dump_zero_ratio,
            }
            return {
                "pid": pid,
                "method": "freeze_dd" if freeze else "memory_dd",
                "frozen": stopped,
                "emulator_bypass": emulator_bypass,
                "candidates": candidates,
                "regions": region_reports,
                "candidate_spans": spans,
                "coverage": coverage,
                "limitations": limitations,
            }
        finally:
            resume_error: str | None = None
            if stopped:
                try:
                    if not self.process.signal(serial, pid, "CONT"):
                        resume_error = f"failed to SIGCONT pid {pid}"
                except Exception as exc:
                    resume_error = str(exc)
                if resume_error:
                    # Android may kill a frozen app while a large dump is in
                    # progress. Only a successful device-side absence check
                    # proves no process remains to resume; an ADB failure does
                    # not. Preserve the already-read bytecode in that case.
                    try:
                        gone = self.adb.shell(
                            serial, f"if [ ! -d /proc/{int(pid)} ]; then printf apu_process_exited; fi",
                            timeout=10,
                        )
                        if gone.ok and gone.stdout.strip() == "apu_process_exited":
                            run.append_event("frozen_process_exited", {"pid": pid, "serial": serial})
                            resume_error = None
                    except Exception:
                        pass
                if stop_mutation is not None:
                    run.update_mutation(
                        stop_mutation["mutation_id"],
                        state="restore_failed" if resume_error else "restored",
                    )
                if resume_error:
                    run.append_event("process_resume_failed", {"pid": pid, "serial": serial, "error": resume_error})
            if not keep_device_files:
                self.adb.remove(serial, remote_dir)
            if resume_error:
                raise fail("cleanup_incomplete", resume_error, details={"pid": pid, "serial": serial})

    def _complete_memory_candidates(
        self, run: RunWorkspace, serial: str, pid: int,
        candidates: list[dict[str, Any]], *, remote_dir: str, fast: bool,
        max_region_bytes: int, cancel: threading.Event | None,
    ) -> list[dict[str, Any]]:
        """Complete an embedded DEX by virtual address, including mmap tails.

        A region may contain several DEX headers. Only reading by file_size at
        the region start leaves the later DEX truncated, even when its remaining
        bytes are readable in adjacent mappings. Keep the first extraction on
        disk and preserve holes when completing it.
        """
        reports: list[dict[str, Any]] = []
        for index, candidate in enumerate(list(candidates)):
            if not candidate.get("truncated") or candidate.get("vaddr") is None:
                continue
            source = Path(str(candidate.get("local_path") or ""))
            header = read_header(source)
            if header is None or header.file_size <= source.stat().st_size:
                continue
            report: dict[str, Any] = {"source_candidate": str(source),
                                     "vaddr": int(candidate["vaddr"]),
                                     "declared_size": header.file_size}
            reports.append(report)
            if header.file_size > max_region_bytes:
                report.update(status="skipped", reason="candidate_size_cap")
                continue
            if cancel is not None and cancel.is_set():
                raise fail("cancelled", "memory dump cancelled")
            label = f"span{index}_{uuid4().hex[:8]}"
            path = run.raw_dir / (label + ".bin")
            try:
                dump = self.memory.dump_virtual_range(
                    serial, pid, int(candidate["vaddr"]), header.file_size, path,
                    self.process.maps(serial, pid), remote_dir=remote_dir,
                    fast=fast, strict=False,
                )
                report["dump"] = dump
                extracted = scan_file_for_dex(
                    path, run.raw_dir, label=label, base_vaddr=int(candidate["vaddr"]),
                    max_candidates=1,
                )
                self._annotate_dump_holes(extracted, dump.get("hole_regions") or [],
                                          int(candidate["vaddr"]))
                if extracted and not extracted[0].get("truncated"):
                    if candidate.get("memory_mapping"):
                        extracted[0]["memory_mapping"] = candidate["memory_mapping"]
                    candidates[index] = extracted[0]
                    report.update(status="read", replacement=extracted[0]["local_path"])
                else:
                    report.update(status="partial", reason="virtual_read_still_truncated")
            except AnalysisError as exc:
                if exc.code == "cancelled":
                    raise
                report.update(status="failed", error=exc.projection())
        return reports

    def _dump_region_candidates(
        self,
        run: RunWorkspace,
        serial: str,
        pid: int,
        region: Any,
        index: int,
        *,
        remote_dir: str,
        fast: bool,
        max_region_bytes: int,
        keep_device_files: bool,
    ) -> dict[str, Any]:
        is_ashmem = "dalvik-dex" in (region.path or "").lower()
        dump_path = run.raw_dir / f"region_{index:02d}_{region.start:x}_{region.size}.bin"
        limitations: list[str] = []
        header_bytes = b""
        header = None
        try:
            header_bytes = self.memory.read_small(serial, pid, region.start, 0x70, run.tmp_dir)
        except AnalysisError:
            header_bytes = b""
        if is_ashmem and header_bytes[:4] != b"dex\n" and region.size > 2 * 1024 * 1024:
            # ART can split a multi-DEX allocation at protection boundaries.
            # The next DEX header may be inside this continuation mapping.
            # Scan it within the ordinary per-region cap, then complete any
            # embedded file across mappings by its own virtual address.
            limitations.append(
                f"scanned dalvik-DEX continuation segment at {region.start:#x} for embedded headers"
            )
        if is_ashmem and header_bytes[:4] == b"dex\n":
            from ..providers.dex import parse_dex_header

            header = parse_dex_header(header_bytes)
            if header is None:
                raise fail("dump_incomplete", f"DEX header at {region.start:#x} did not validate")
            dump_report = self.memory.dump_virtual_range(
                serial,
                pid,
                region.start,
                header.file_size,
                dump_path,
                self.process.maps(serial, pid),
                remote_dir=remote_dir,
                fast=fast,
                strict=False,
            )
        else:
            size = min(region.size, max_region_bytes)
            if region.size > max_region_bytes:
                limitations.append(
                    f"region {region.start:#x} truncated to {max_region_bytes} bytes by the per-region cap"
                )
            dump_report = self.memory.dump_range(
                serial,
                pid,
                region.start,
                size,
                dump_path,
                remote_dir=remote_dir,
                fast=fast,
                strict=False,
            )
        zero_ratio = self.memory.zero_ratio(dump_path)
        threshold = float(self.config.dump_zero_ratio)
        candidates: list[dict[str, Any]] = []
        if zero_ratio < threshold:
            candidates = scan_file_for_dex(
                dump_path,
                run.raw_dir,
                label=f"region{index}",
                base_vaddr=region.start,
            )
            self._annotate_dump_holes(
                candidates, (dump_report.get("hole_regions") or []), region.start
            )
            for candidate in candidates:
                candidate["memory_mapping"] = region.path or ""
        else:
            limitations.append(f"region {region.start:#x} is {zero_ratio:.1%} zero; skipped DEX scan")
        # A dalvik-DEX ashmem region can hold more than one payload after the
        # first file_size; scan the remainder so multi-DEX apps are not truncated.
        if is_ashmem and header is not None and header.file_size < region.size:
            tail_start = region.start + header.file_size
            tail_size = min(region.size - header.file_size, max_region_bytes)
            if tail_size >= 0x70:
                tail_path = run.raw_dir / f"region_{index:02d}_tail.bin"
                tail_report = self.memory.dump_range(
                    serial,
                    pid,
                    tail_start,
                    tail_size,
                    tail_path,
                    remote_dir=remote_dir,
                    fast=fast,
                    strict=False,
                )
                if self.memory.zero_ratio(tail_path) < threshold:
                    tail_candidates = scan_file_for_dex(
                        tail_path,
                        run.raw_dir,
                        label=f"region{index}_tail",
                        base_vaddr=tail_start,
                    )
                    self._annotate_dump_holes(
                        tail_candidates, (tail_report.get("hole_regions") or []), tail_start
                    )
                    for candidate in tail_candidates:
                        candidate["memory_mapping"] = region.path or ""
                    candidates.extend(tail_candidates)
                region_reports_tail = {
                    "tail_start": tail_start,
                    "tail_size": tail_size,
                    "dump": tail_report,
                }
                limitations.append(f"scanned dalvik-DEX tail at {tail_start:#x} ({tail_size} bytes)")
                return {
                    "region": region.to_dict(),
                    "dump": dump_report,
                    "tail": region_reports_tail,
                    "zero_ratio": round(zero_ratio, 4),
                    "candidates": candidates,
                    "limitations": limitations,
                    "dump_path": str(dump_path),
                }
        return {
            "region": region.to_dict(),
            "dump": dump_report,
            "zero_ratio": round(zero_ratio, 4),
            "candidates": candidates,
            "limitations": limitations,
            "dump_path": str(dump_path),
        }

    def _launch_if_needed(
        self,
        run: RunWorkspace,
        serial: str,
        package: str,
        inspection: dict[str, Any],
        pid: int | None,
        freeze: bool,
        fresh_launch: bool = False,
    ) -> int:
        if pid and not freeze and not fresh_launch:
            return pid
        if pid is None and not freeze and not fresh_launch:
            try:
                return self.process.find_pid(serial, package)
            except AnalysisError:
                pass
        self.launch_android_target(
            run.run_id,
            serial=serial,
            package_name=package,
            force_stop=freeze or fresh_launch,
        )
        return self.process.wait_for_pid(serial, package, timeout_ms=5000)

    # ------------------------------------------------------------------ repair / verify / decompile
    def repair_android_dex(
        self,
        run_id: str,
        *,
        input_paths: list[str] | None = None,
        input_dir: str | None = None,
        output_dir: str | None = None,
        allow_truncated: bool = False,
        include_stub: bool = False,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        source_dir = Path(input_dir) if input_dir else run.raw_dir
        sources = [Path(item) for item in input_paths] if input_paths else sorted(source_dir.glob("*.dex"))
        if not sources:
            raise fail("invalid_input", f"no DEX files found under {source_dir}")
        out_dir = Path(output_dir) if output_dir else run.fixed_dir
        inspection = self._inspection_for(run)
        package = (inspection.get("package") or {}).get("name")
        last_dump = self._run_artifacts(run).get('last_dump') or {}
        runtime_variants = bool(
            last_dump.get('status') == 'partial'
            and self._last_evidence_id(run, 'dump_android_dex')
            and all(p.resolve().parent == run.raw_dir.resolve() for p in sources)
        )
        result = repair_dex_set(
            sources,
            out_dir,
            allow_truncated=allow_truncated,
            include_stub=include_stub,
            package=package,
            target_packages=target_namespaces(inspection),
            runtime_variants=runtime_variants,
        )
        evidence = self._record(
            run,
            operation="repair_android_dex",
            subject=self._apk_subject(inspection),
            provider="dex",
            predicate_type="dex.repair",
            parameters={
                "input_dir": str(source_dir),
                "output_dir": str(out_dir),
                "allow_truncated": allow_truncated,
                "include_stub": include_stub,
            },
            normalized_result=result,
            confidence="observed",
            authority="shipped-artifact",
            limitations=[
                "A valid checksum proves internal consistency, not that all classes were recovered.",
                "Same-run partial runtime snapshots with identical class tables, descriptors and normalized prefixes select the most readable variant; raw snapshots remain preserved.",
            ],
            locations=[{"kind": "artifact-path", "path": item["path"]} for item in result.get("files") or []],
            evidence_links=[link] if (link := self._last_evidence_id(run, "dump_android_dex")) else [],
        )
        run.update_run(stage="repaired", artifacts={"fixed_dir": str(out_dir), "repair": result})
        return self._result(run, evidence, repair=result)

    def verify_android_dex(
        self,
        run_id: str,
        *,
        dex_paths: list[str] | None = None,
        dex_dir: str | None = None,
        package_name: str | None = None,
        run_jadx: bool = False,
        timeout_s: int | None = None,
        cancel: threading.Event | None = None,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        inspection = self._inspection_for(run)
        package = package_name or (inspection.get("package") or {}).get("name")
        canonical_dir = (
            run.fixed_dir if any(run.fixed_dir.glob("*.dex")) else run.raw_dir
        )
        source_dir = Path(dex_dir) if dex_dir else canonical_dir
        paths = [Path(item) for item in dex_paths] if dex_paths else sorted(source_dir.glob("*.dex"))
        if not paths:
            raise fail("invalid_input", f"no DEX files found under {source_dir}")
        namespaces = target_namespaces(inspection) if not package_name or package_name == (inspection.get("package") or {}).get("name") else [package_name]
        reports = [verify_dex(path, package, target_packages=namespaces) for path in paths]
        total_classes = sum(item.get("total_classes", 0) for item in reports)
        total_size = sum(item.get("size", 0) for item in reports)
        jadx_result = None
        if run_jadx:
            try:
                jadx_inputs, input_selection = self._jadx_inputs(run, inspection, paths)
                jadx_result = self.jadx.decompile(
                    jadx_inputs,
                    run.jadx_dir / ("verify-" + uuid4().hex[:8]),
                    timeout_s=timeout_s or self.config.jadx_timeout_s,
                    package=package,
                    target_packages=namespaces,
                    cancel=cancel,
                )
                if isinstance(jadx_result, dict):
                    jadx_result.setdefault("ok", True)
                    jadx_result["input_selection"] = input_selection
            except AnalysisError as exc:
                # JADX failure is reported separately; it must not downgrade a
                # DEX whose content verification passed.
                jadx_result = {"ok": False, "error": exc.projection()}
            except Exception as exc:  # pragma: no cover - defensive isolation
                jadx_result = {"ok": False, "error": {"message": str(exc)}}
        files_complete = all(
            bool(item.get("content_complete", item.get("status") == "complete"))
            for item in reports
        )
        target_complete = any(item.get("complete") for item in reports)
        result = {
            "dex_dir": str(source_dir),
            "files": reports,
            "file_count": len(reports),
            "total_classes": total_classes,
            "total_size": total_size,
            # Overall verification succeeds when every DEX is structurally
            # complete and at least one DEX contains the target package.  A
            # multi-dex app may legitimately have runtime DEX files without
            # app-package classes; those must not flip the whole job to partial.
            "complete": bool(files_complete and target_complete),
            "files_complete": files_complete,
            "target_complete": target_complete,
            "target_packages": namespaces,
            "recoverable": any((item.get("assessment") or {}).get("recoverable") for item in reports),
            "jadx": jadx_result,
        }
        previous = run.load_run().get("artifacts") or {}
        previous_paths = {str(Path(item["path"]).resolve()) for item in
                          (previous.get("verification") or {}).get("files", []) if item.get("path")}
        available_paths = {str(path.resolve()) for path in canonical_dir.glob("*.dex")}
        checked_paths = {str(path.resolve()) for path in paths}
        primary_check = checked_paths.issuperset(available_paths or previous_paths)
        result["scope"] = "whole_run" if primary_check else "subset"
        evidence = self._record(
            run,
            operation="verify_android_dex",
            subject=self._apk_subject(inspection),
            provider="dex",
            predicate_type="dex.verify",
            parameters={"dex_dir": str(source_dir), "package": package, "run_jadx": run_jadx},
            normalized_result=result,
            confidence="observed",
            authority="shipped-artifact",
            limitations=[
                "Class counts are read from class_defs/type_ids/string_ids; unresolved reflection and dynamic loading remain unknown.",
            ],
            locations=[{"kind": "artifact-path", "path": str(path)} for path in paths],
            evidence_links=[
                link
                for link in (self._last_evidence_id(run, "repair_android_dex"),)
                if link
            ],
        )
        # A diagnostic subset must not replace whole-run verification or the
        # quality record bound to the primary source directory.
        artifacts = {"verification" if primary_check else "verification_check": result}
        if jadx_result is not None:
            artifacts["verification_jadx"] = jadx_result
            if primary_check and not previous.get("decompilation"):
                artifacts["decompilation"] = jadx_result
        run.update_run(stage="verified", artifacts=artifacts)
        return self._result(run, evidence, verification=result)

    def _jadx_inputs(self, run: RunWorkspace, inspection: dict[str, Any],
                     paths: list[Path]) -> tuple[list[str | Path], dict[str, Any]]:
        """Keep APK resource context when every shipped DEX is byte-identical.

        Large generated R classes can exhaust JADX's heap when supplied as bare
        DEX. The APK container lets JADX use its resource table. Any additional
        runtime DEX remains an input; changed/packed/subset DEX stays on the DEX
        route, so original shell stubs cannot replace recovered payloads.
        """
        selection = {"kind": "dex", "dex_file_count": len(paths)}
        packing = inspection.get("packing") or {}
        if packing.get("packed") is not False or packing.get("application_class_suspicious"):
            return paths, selection
        target = (run.load_run().get("target") or {}).get("path")
        if not target or not Path(target).is_file():
            return paths, selection
        expected_hash = (inspection.get("identity") or {}).get("sha256")
        if not expected_hash or sha256_file(Path(target)) != expected_hash:
            return paths, selection
        digests = {p: sha256_file(p) for p in paths}
        shipped: set[str] = set()
        try:
            with zipfile.ZipFile(target) as archive:
                entries = [n for n in archive.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
                if not entries:
                    return paths, selection
                for name in entries:
                    digest = hashlib.sha256()
                    with archive.open(name) as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                    shipped.add(digest.hexdigest())
        except (OSError, zipfile.BadZipFile):
            return paths, selection
        if not shipped.issubset(set(digests.values())):
            return paths, selection
        extras = [p for p, digest in digests.items() if digest not in shipped]
        return [str(target), *extras], {"kind": "apk_with_runtime_extras",
            "apk_path": str(target), "apk_sha256": expected_hash,
            "shipped_dex_count": len(entries), "runtime_extra_dex_count": len(extras),
            "reason": "All shipped DEX bytes match; retain APK resource context and every additional runtime DEX."}

    def decompile_android_apk(
        self,
        run_id: str,
        *,
        source: str = "apk",
        apk_path: str | None = None,
        dex_dir: str | None = None,
        output_dir: str | None = None,
        extra_args: list[str] | None = None,
        timeout_s: int | None = None,
        cancel: threading.Event | None = None,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        inspection = self._inspection_for(run)
        package = (inspection.get("package") or {}).get("name")
        if source == "apk":
            target = apk_path or (run.load_run().get("target") or {}).get("path")
            if not target:
                raise fail("invalid_input", "no APK path for decompilation")
            inputs = [target]
        elif source == "dex":
            source_dir = Path(dex_dir) if dex_dir else (
                run.fixed_dir if any(run.fixed_dir.glob("*.dex")) else run.raw_dir
            )
            inputs = sorted(source_dir.glob("*.dex"))
            if not inputs:
                raise fail("invalid_input", f"no DEX files under {source_dir}")
        else:
            raise fail("invalid_input", f"unknown decompile source: {source}")
        previous_decompilation = (run.load_run().get("artifacts") or {}).get("decompilation")
        out_dir = Path(output_dir) if output_dir else (
            run.jadx_dir / ("decompile-" + uuid4().hex[:8]) if previous_decompilation else run.jadx_dir)
        input_selection = {"kind": "apk"}
        if source == "dex":
            inputs, input_selection = self._jadx_inputs(run, inspection, inputs)
        timeout_s = timeout_s or self.config.jadx_timeout_s
        try:
            result = self.jadx.decompile(
                inputs,
                out_dir,
                timeout_s=timeout_s,
                package=package,
                target_packages=target_namespaces(inspection),
                extra_args=extra_args,
                cancel=cancel,
            )
        except AnalysisError as exc:
            # Preserve a timeout even when Java output is empty, so the job
            # finalizer can distinguish it from DEX recovery failure.
            run.update_run(artifacts={"decompilation": {
                "ok": False, "status": "partial", "error": exc.projection(),
                "timed_out": exc.code == "timeout", "timeout_s": timeout_s,
                "output_dir": str(out_dir),
            }})
            raise
        result["input_selection"] = input_selection
        evidence = self._record(
            run,
            operation="decompile_android_apk",
            subject=self._apk_subject(inspection),
            provider="jadx",
            predicate_type="apk.decompile",
            parameters={"source": source, "output_dir": str(out_dir), "timeout_s": timeout_s},
            normalized_result=result,
            confidence="observed",
            authority="shipped-artifact",
            limitations=["Decompiled source is reconstructed, not original source."],
            locations=[{"kind": "artifact-path", "path": result["output_dir"]}],
            evidence_links=[
                link
                for link in (
                    self._last_evidence_id(run, "repair_android_dex"),
                    self._last_evidence_id(run, "dump_android_dex"),
                )
                if link
            ],
        )
        run.update_run(stage="decompiled", artifacts={"jadx_dir": result["output_dir"], "decompilation": result})
        return self._result(run, evidence, decompilation=result)

    # ------------------------------------------------------------------ evidence / run
    def get_evidence(
        self,
        run_id: str,
        *,
        evidence_id: str | None = None,
        operation: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        records, total = run.read_evidence(evidence_id=evidence_id, operation=operation, offset=offset, limit=limit)
        if evidence_id and not records:
            raise fail("not_found", f"evidence not found: {evidence_id}", details={"run_id": run_id})
        return {
            "run_id": run.run_id,
            "records": records,
            "total": total,
            "offset": offset,
            "limit": limit,
            "next_offset": offset + len(records) if offset + len(records) < total else None,
            "run_state": run.load_run(),
        }

    def inspect_run(self, run_id: str, *, include_events: bool = False, limit: int = 50) -> dict[str, Any]:
        run = self._load_run(run_id)
        state = run.load_run()
        evidence, total = run.read_evidence(offset=0, limit=limit)
        events: list[dict[str, Any]] = []
        if include_events and run.events_path.is_file():
            with open(run.events_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            events = events[-limit:]
        return {
            "run_id": run.run_id,
            "run_root": str(run.root),
            "state": state,
            "mutations": run.load_mutations(),
            "evidence_count": total,
            "evidence_summary": [
                {
                    "evidence_id": item.get("evidence_id"),
                    "operation": item.get("operation"),
                    "confidence": item.get("confidence"),
                    "authority": item.get("authority"),
                }
                for item in evidence
            ],
            "events": events,
        }

    def export_evidence_bundle(
        self,
        run_id: str,
        output_path: str | Path,
        *,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        output = Path(output_path).expanduser()
        if output.exists() and not overwrite:
            raise fail("conflict", f"output already exists: {output}")
        records, total = run.read_evidence(offset=0, limit=1_000_000)
        events: list[dict[str, Any]] = []
        if run.events_path.is_file():
            with open(run.events_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        bundle = {
            "schema_version": 1,
            "exported_at": utc_now(),
            "run": run.load_run(),
            "evidence": records,
            "events": events,
            "mutations": run.load_mutations(),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        temp = output.with_name(output.name + ".part")
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(bundle, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, output)
        digest = sha256_file(output)
        evidence = self._record(
            run,
            operation="export_evidence_bundle",
            subject={"format": "run", "digest": {"sha256": digest}},
            provider="apk",
            predicate_type="evidence.export",
            parameters={"output_path": str(output), "overwrite": overwrite},
            normalized_result={"output_path": str(output), "sha256": digest, "size": output.stat().st_size, "record_count": total},
            confidence="observed",
            authority="analyst-inference",
            limitations=["The bundle is a snapshot of this run; it is not a live device state."],
            locations=[{"kind": "artifact-path", "path": str(output)}],
        )
        return self._result(run, evidence, export={"output_path": str(output), "sha256": digest, "size": output.stat().st_size})

    def cleanup_run(
        self,
        run_id: str,
        *,
        serial: str | None = None,
        restore_mutations: bool = True,
        cont_process: bool = True,
        keep_device_files: bool = False,
        delete_run: bool = False,
        prune_raw_dumps: bool = False,
    ) -> dict[str, Any]:
        run = self._load_run(run_id)
        mutations = run.load_mutations()
        restored: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        recorded_serial = ((run.load_run().get("device") or {}).get("serial"))
        serial = serial or recorded_serial or self.config.default_serial
        if serial is None:
            try:
                serial = self.adb.resolve_serial(None)
            except AnalysisError:
                serial = None
        if restore_mutations and serial:
            for mutation in reversed(mutations):
                if mutation.get("state") not in _RETRYABLE_MUTATION_STATES:
                    continue
                kind = mutation.get("kind")
                try:
                    if kind == "kill_stop" and cont_process:
                        match = re.search(r"pid:(\d+)", str(mutation.get("target")))
                        note = None
                        if match:
                            pid = int(match.group(1))
                            if self.process.is_alive(serial, pid):
                                if not self.process.signal(serial, pid, "CONT"):
                                    raise fail(
                                        "cleanup_incomplete",
                                        f"failed to resume frozen pid {pid} (kill -CONT)",
                                        details={"pid": pid},
                                    )
                            else:
                                note = "process not running; nothing to resume"
                        else:
                            note = "no pid recorded"
                        run.update_mutation(mutation["mutation_id"], state="restored")
                        restored.append({"mutation_id": mutation["mutation_id"], "kind": kind, "note": note})
                    elif kind == "rename_device_lib":
                        backup = (mutation.get("detail") or {}).get("backup")
                        target = mutation.get("target")
                        if backup and self.adb.file_exists(serial, backup):
                            if self.adb.file_exists(serial, target):
                                raise fail(
                                    "cleanup_incomplete",
                                    f"refusing to overwrite recreated library {target}; backup remains at {backup}",
                                    details={"target": target, "backup": backup},
                                )
                            rename = self.adb.rename(serial, backup, target)
                            if rename.ok:
                                run.update_mutation(mutation["mutation_id"], state="restored")
                                restored.append({"mutation_id": mutation["mutation_id"], "kind": kind})
                            else:
                                raise fail("cleanup_incomplete", f"failed to restore {target}", captured_output=rename.stderr)
                        else:
                            run.update_mutation(mutation["mutation_id"], state="restored")
                            restored.append({"mutation_id": mutation["mutation_id"], "kind": kind, "note": "backup absent"})
                    elif kind == "frida_server_start":
                        pid = (mutation.get("detail") or {}).get("pid")
                        if pid and self._is_frida_server_pid(serial, int(pid)):
                            kill = self.adb.shell(serial, f"kill -9 {int(pid)} 2>/dev/null", timeout=15)
                            if not kill.ok:
                                raise fail(
                                    "cleanup_incomplete",
                                    f"failed to stop frida-server pid {pid}",
                                    captured_output=kill.stderr or kill.stdout,
                                    details={"pid": int(pid)},
                                )
                            note = None
                        elif pid:
                            note = "pid no longer belongs to frida-server; not killed"
                        else:
                            note = "no pid recorded"
                        run.update_mutation(mutation["mutation_id"], state="restored")
                        restored.append({"mutation_id": mutation["mutation_id"], "kind": kind, "note": note})
                    elif kind == "adb_forward":
                        local_port = (mutation.get("detail") or {}).get("local_port")
                        if local_port:
                            # Scoped to this device and this local port only; a
                            # global or other-device forward is never removed.
                            removal = self.adb.remove_forward(serial, int(local_port))
                            if not removal.ok:
                                raise fail(
                                    "cleanup_incomplete",
                                    f"failed to remove adb forward tcp:{local_port} for {serial}",
                                    captured_output=removal.stderr or removal.stdout,
                                    details={"serial": serial, "local_port": int(local_port)},
                                )
                        run.update_mutation(mutation["mutation_id"], state="restored")
                        restored.append(
                            {
                                "mutation_id": mutation["mutation_id"],
                                "kind": kind,
                                "local_port": local_port,
                                "serial": serial,
                            }
                        )
                    elif kind == "push_file":
                        created = (mutation.get("detail") or {}).get("created")
                        if created:
                            removal = self.adb.remove(serial, str(mutation.get("target")))
                            if not removal.ok:
                                raise fail(
                                    "cleanup_incomplete",
                                    f"failed to remove pushed file {mutation.get('target')}",
                                    captured_output=removal.stderr or removal.stdout,
                                )
                        run.update_mutation(mutation["mutation_id"], state="restored")
                        restored.append({"mutation_id": mutation["mutation_id"], "kind": kind})
                    elif kind == "install_apk":
                        run.update_mutation(mutation["mutation_id"], state="kept")
                        restored.append({"mutation_id": mutation["mutation_id"], "kind": kind, "note": "install retained"})
                    elif kind == "force_stop":
                        run.update_mutation(mutation["mutation_id"], state="kept")
                        restored.append({"mutation_id": mutation["mutation_id"], "kind": kind, "note": "force-stop is not reversible"})
                except AnalysisError as exc:
                    failed.append({"mutation_id": mutation["mutation_id"], "kind": kind, "error": exc.projection()})
                    run.update_mutation(mutation["mutation_id"], state="restore_failed")
                except Exception as exc:  # pragma: no cover - defensive
                    failed.append({"mutation_id": mutation["mutation_id"], "kind": kind, "error": str(exc)})
                    run.update_mutation(mutation["mutation_id"], state="restore_failed")
        device_temp_removed = False
        if serial and not keep_device_files:
            targets = [f"/data/local/tmp/apu/{run.run_id}"]
            package = run.load_run().get("package")
            if package:
                targets.extend(
                    f"{base}/{package}/files/apu/{run.run_id}" for base in ("/data/user/0", "/data/data")
                )
            removed_all = True
            for target in targets:
                removal = self.adb.remove(serial, target)
                if not removal.ok:
                    removed_all = False
                    errors.append(
                        {
                            "kind": "device_temp_remove",
                            "target": target,
                            "output": (removal.stderr or removal.stdout or "")[-1000:],
                        }
                    )
            device_temp_removed = removed_all
        import tempfile

        host_temp_removed = False
        host_temp = Path(tempfile.gettempdir()) / "apu" / re.sub(r"[^A-Za-z0-9_.-]+", "_", run.run_id)
        try:
            if host_temp.exists():
                shutil.rmtree(host_temp)
                host_temp_removed = True
        except OSError as exc:
            host_temp_removed = not host_temp.exists()
            if not host_temp_removed:
                errors.append({"kind": "host_temp_remove", "target": str(host_temp), "error": str(exc)})
        raw_dumps_pruned = 0
        if prune_raw_dumps:
            for path in list(run.raw_dir.glob("region_*.bin")) + list(run.raw_dir.glob("*.bin.part")):
                try:
                    path.unlink()
                    raw_dumps_pruned += 1
                except OSError as exc:
                    errors.append({"kind": "raw_dump_prune", "target": str(path), "error": str(exc)})
        # Any mutation not in an explicitly final state keeps cleanup incomplete.
        # This covers restore_failed, apply_failed, still-applied, and unknown
        # states written by current or older clients.
        final_mutations = run.load_mutations()
        remaining = [
            item for item in final_mutations if item.get("state") not in _TERMINAL_MUTATION_STATES
        ]
        reported_ids = {item.get("mutation_id") for item in failed + restored}
        if remaining and serial is None:
            failed.append(
                {
                    "kind": "device_unavailable",
                    "error": "no online device to restore mutations",
                    "remaining_mutations": [item.get("mutation_id") for item in remaining],
                }
            )
        elif remaining:
            for item in remaining:
                if item.get("mutation_id") in reported_ids:
                    continue
                state = item.get("state")
                failed.append(
                    {
                        "mutation_id": item.get("mutation_id"),
                        "kind": item.get("kind"),
                        "state": state,
                        "error": f"mutation state {state!r} was not finalized by cleanup",
                    }
                )
        cleanup_incomplete = bool(failed or remaining or errors)
        cleanup_status = "incomplete" if cleanup_incomplete else "complete"
        message = (
            "cleanup incomplete: " + "; ".join(
                str(item.get("error") or item.get("kind")) for item in (failed + errors)
            )
            if cleanup_incomplete
            else "all reversible device mutations restored"
        )
        # Run-level bookkeeping only. Job status is owned by the backend
        # (WP-F); this function never changes it.
        run.update_run(stage="cleaned", cleanup_status=cleanup_status)
        summary = {
            "run_id": run.run_id,
            "ok": not cleanup_incomplete,
            "cleanup_incomplete": cleanup_incomplete,
            "cleanup_status": cleanup_status,
            "message": message,
            "restored": restored,
            "failed": failed,
            "errors": errors,
            "remaining_mutations": [item.get("mutation_id") for item in remaining],
            "device_temp_removed": device_temp_removed,
            "host_temp_removed": host_temp_removed,
            "raw_dumps_pruned": raw_dumps_pruned,
        }
        if delete_run and not cleanup_incomplete:
            try:
                run.delete()
                summary["run_deleted"] = True
            except OSError as exc:
                summary["run_deleted"] = False
                summary["errors"].append({"kind": "run_delete", "error": str(exc)})
                summary["ok"] = False
                summary["cleanup_incomplete"] = True
                summary["cleanup_status"] = "incomplete"
        else:
            summary["run_deleted"] = False
            self._record(
                run,
                operation="cleanup_run",
                subject={"format": "run", "digest": {"run_id": run.run_id}},
                provider="adb",
                predicate_type="run.cleanup",
                parameters={"restore_mutations": restore_mutations, "cont_process": cont_process},
                normalized_result=summary,
                confidence="observed",
                authority="live-device",
                limitations=[] if not cleanup_incomplete else ["Some mutations or temp files could not be cleaned; inspect the mutation log and errors."],
            )
        return summary

    # ------------------------------------------------------------------ doctor
    def doctor(self, *, frida_server_path: str | None = None) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        def check(name: str, ok: bool, detail: Any = None, remediation: str = "") -> None:
            checks.append({"name": name, "ok": ok, "detail": detail, "remediation": remediation if not ok else ""})

        check("python", sys.version_info >= (3, 10), sys.version.split()[0], "Install Python 3.10 or newer.")
        adb_version = self.host.run(list(self.config.adb) + ["version"], timeout=10)
        check("adb", adb_version.ok, adb_version.stdout.splitlines()[0] if adb_version.stdout else adb_version.stderr, "Install Android platform-tools and add adb to PATH.")
        frida_version = self.frida.version()
        check("frida_cli", bool(frida_version), frida_version, "Install frida with matching host/device versions.")
        server_binary = frida_server_path or self.config.frida_server
        check("frida_server_binary", bool(server_binary), server_binary, "Set APU_FRIDA_SERVER or place frida-server in the workspace.")
        check("aapt", bool(self.config.aapt), self.config.aapt, "Set APU_AAPT or install Android build-tools.")
        check("java", bool(self.config.java), self.config.java, "Set APU_JAVA/JAVA_HOME or place jadx/jre nearby.")
        check("jadx_jar", bool(self.config.jadx_jar), self.config.jadx_jar, "Set APU_JADX_JAR or place jadx-gui-*-all.jar under jadx/lib.")
        try:
            runs_dir = self.config.ensure_runs_dir()
            probe = runs_dir / ".doctor-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            check("runs_dir_writable", True, str(runs_dir))
        except OSError as exc:
            check("runs_dir_writable", False, str(exc), "Set APU_RUNS_DIR to a writable directory.")
        try:
            self.lessons.ensure()
            probe = self.lessons.root / ".doctor-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            stats = self.lessons.stats()
            check(
                "memory_dir_writable",
                True,
                {"path": str(self.lessons.root), "lessons": stats.get("total")},
            )
        except OSError as exc:
            check("memory_dir_writable", False, str(exc), "Set APU_MEMORY_DIR to a writable directory.")
        device: dict[str, Any] | None = None
        try:
            serial = self.adb.resolve_serial(None)
            device = self.adb.device_info(serial, frida_server_path=server_binary)
            check("device", True, {"serial": serial, "abi": device.get("abi"), "sdk": device.get("sdk")})
            check("root", bool(device.get("root", {}).get("available")), device.get("root"), "Run adb root or use a root-capable emulator.")
            check("frida_server", bool(device.get("frida", {}).get("reachable")), device.get("frida"), "Push and start a matching frida-server.")
        except AnalysisError as exc:
            check("device", False, exc.projection(), "Connect an emulator/device with USB debugging.")
        return {
            "ok": all(
                item["ok"]
                for item in checks
                if item["name"] in ("python", "adb", "runs_dir_writable", "memory_dir_writable")
            ),
            "checks": checks,
            "config": self.config.platform_summary(),
            "device": device,
        }

    def _extract_static_dex(self, run_id: str, apk_path: str, *, route: str) -> dict[str, Any]:
        """Extract, repair and verify top-level classes*.dex for a static route.

        Both ``static_jadx`` and ``static_wgt`` handle unpacked APKs; the DEX is
        the native application code in both cases, so neither route may stop at
        sources/assets and report "no_target_dex" while a valid DEX exists.
        """
        run = self._load_run(run_id)
        extracted: list[dict[str, Any]] = []
        dex_error: str | None = None
        try:
            with zipfile.ZipFile(apk_path) as archive:
                names = [
                    name
                    for name in archive.namelist()
                    if re.fullmatch(r"classes(?:\d+)?\.dex", name)
                ]
                names.sort(key=_static_dex_entry_key)
                for name in names:
                    data = archive.read(name)
                    destination = run.raw_dir / Path(name).name
                    destination.write_bytes(data)
                    extracted.append(
                        {"name": name, "size": len(data), "path": str(destination)}
                    )
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            dex_error = f"{type(exc).__name__}: {exc}"
        repair: dict[str, Any] | None = None
        verification: dict[str, Any] | None = None
        if extracted:
            self._stage(run_id, "repairing", route=route, dex_files=len(extracted))
            try:
                repair_result = self.repair_android_dex(run_id)
                repair = repair_result.get("repair", repair_result)
                self._stage(run_id, "verifying", route=route)
                verify_result = self.verify_android_dex(run_id)
                verification = verify_result.get("verification", verify_result)
            except AnalysisError as exc:
                verification = {"complete": False, "error": project_error(exc)}
        return {
            "files": extracted,
            "error": dex_error,
            "repair": repair,
            "verification": verification,
        }

    # ------------------------------------------------------------------ orchestration
    def unpack(
        self,
        apk_path: str,
        *,
        serial: str | None = None,
        run_id: str | None = None,
        package_name: str | None = None,
        inner_bypass: bool = False,
        run_jadx: bool = True,
        jadx_timeout_s: int | None = None,
        cleanup: bool = True,
        install: bool = False,
        freeze_timeout_ms: int = 15000,
        freeze_poll_ms: int = 80,
        frida_timeout_ms: int | None = None,
        max_region_bytes: int | None = None,
        keep_device_files: bool = False,
        auto_emulator_bypass: bool = True,
        force_dump: bool = False,
    ) -> dict[str, Any]:
        inspection_result = self.inspect_apk(apk_path, run_id=run_id)
        run_id = inspection_result["run_id"]
        inspection = inspection_result["inspection"]
        self._stage(
            run_id,
            "inspected",
            package=(inspection.get("package") or {}).get("name"),
            shell=(inspection.get("packing") or {}).get("primary"),
            mixed=(inspection.get("packing") or {}).get("mixed"),
            packed=(inspection.get("packing") or {}).get("packed"),
        )
        strategy_result = self.recommend_unpack_strategy(run_id, force_dump=force_dump)
        strategy = strategy_result["strategy"]
        self._stage(
            run_id,
            "strategy_ready",
            primary=strategy.get("primary"),
            fallbacks=strategy.get("fallbacks"),
            learned_primary=strategy.get("learned_primary"),
        )
        primary = strategy.get("primary")
        if not force_dump and primary == "static_wgt":
            self._stage(run_id, "static_route", route="uni-app wgt")
            extraction_data: dict[str, Any] | None = None
            extraction_error: dict[str, Any] | None = None
            try:
                extraction_result = self.extract_apk_assets(apk_path, run_id=run_id)
                extraction_data = extraction_result.get("extraction", extraction_result)
            except AnalysisError as exc:
                extraction_error = project_error(exc)
            dex = self._extract_static_dex(run_id, apk_path, route="static_wgt")
            decompilation: dict[str, Any] | None = None
            if run_jadx and dex["files"]:
                try:
                    decompiled = self.decompile_android_apk(run_id, source="apk", timeout_s=jadx_timeout_s)
                    decompilation = decompiled["decompilation"]
                except AnalysisError as exc:
                    # JADX is optional for a wgt route; keep the extracted DEX.
                    decompilation = {"ok": False, "error": project_error(exc)}
            elif run_jadx:
                decompilation = {"ok": False, "skipped": True, "reason": "no dex extracted"}
            else:
                decompilation = {"ok": False, "skipped": True, "reason": "jadx disabled"}
            self._stage(
                run_id,
                "done",
                status="static_extracted",
                route="uni-app wgt",
                dex_files=len(dex["files"]),
            )
            return {
                "run_id": run_id,
                "strategy": strategy,
                "static_route": "uni-app wgt",
                "extraction": extraction_data,
                "extraction_error": extraction_error,
                "dex_extraction": {"files": dex["files"], "error": dex["error"]},
                "repair": dex["repair"],
                "verification": dex["verification"],
                "decompilation": decompilation,
                "status": "static_extracted",
            }
        if not force_dump and primary == "static_jadx":
            self._stage(run_id, "static_route", route="jadx")
            dex = self._extract_static_dex(run_id, apk_path, route="static_jadx")
            decompilation: dict[str, Any] | None = None
            if run_jadx:
                try:
                    decompiled = self.decompile_android_apk(run_id, source="apk", timeout_s=jadx_timeout_s)
                    decompilation = decompiled["decompilation"]
                except AnalysisError as exc:
                    # JADX failure must not discard a verified static DEX.
                    decompilation = {"ok": False, "error": project_error(exc)}
            else:
                decompilation = {"ok": False, "skipped": True, "reason": "jadx disabled"}
            self._stage(
                run_id,
                "done",
                status="decompiled",
                route="jadx",
                dex_files=len(dex["files"]),
            )
            return {
                "run_id": run_id,
                "strategy": strategy,
                "static_route": "jadx",
                "dex_extraction": {"files": dex["files"], "error": dex["error"]},
                "repair": dex["repair"],
                "verification": dex["verification"],
                "decompilation": decompilation,
                "status": "decompiled",
            }
        self._stage(run_id, "device_inspecting")
        device_result = self.inspect_android_device(serial=serial, run_id=run_id)
        serial = device_result["device"]["serial"]
        self._stage(
            run_id,
            "device_inspected",
            serial=serial,
            abi=(device_result.get("device") or {}).get("abi"),
            sdk=(device_result.get("device") or {}).get("sdk"),
        )
        package = package_name or (inspection.get("package") or {}).get("name")
        if package and not install:
            installed = self.adb.shell(serial, f"pm path {shlex.quote(package)} 2>/dev/null", timeout=20)
            if not installed.ok or not installed.stdout.strip():
                raise fail(
                    "not_found",
                    f"target package is not installed: {package}",
                    remediation="Pass install=true/--install, or install the APK manually.",
                    details={"package": package},
                )
        # Recompute with device facts so ABI/Houdini/TracerPid branches are current.
        strategy = self.recommend_unpack_strategy(run_id, force_dump=force_dump)["strategy"]
        frida_routes = {
            "frida_inmemory",
            "frida_inmemory_spawn",
            "frida_mcookie",
            "frida_mcookie_spawn_anti_kill",
            "frida_mcookie_spawn",
            "disk_pull",
        }
        needs_frida = strategy.get("primary") in frida_routes or any(
            item in frida_routes for item in (strategy.get("fallbacks") or [])
        )
        layers = {item.get("shell") for item in (inspection.get("packing") or {}).get("layers") or []}
        need_inner = inner_bypass or ("360" in layers and "secneo" in layers)
        cleanup_result: dict[str, Any] | None = None
        failure: Exception | None = None
        result: dict[str, Any] | None = None
        try:
            self._stage(run_id, "preparing", install=install, frida=False, frida_deferred=needs_frida)
            self.prepare_android_environment(
                run_id,
                serial=serial,
                package_name=package_name,
                start_frida_server=False,
                apk_path=apk_path,
                allow_install=install,
                keep_device_files=keep_device_files,
            )
            if need_inner:
                # Install first so the package's native libraries exist before
                # applying the recorded, reversible inner-shell preparation.
                self.prepare_android_environment(
                    run_id, serial=serial, package_name=package_name,
                    start_frida_server=False, inner_bypass=True,
                    keep_device_files=keep_device_files,
                )
            try:
                self._stage(run_id, "launching")
                launched = self.launch_android_target(
                    run_id,
                    serial=serial,
                    package_name=package_name,
                    auto_emulator_bypass=auto_emulator_bypass,
                )
                self._stage(run_id, "launched", pid=launched.get("pid"), package=launched.get("package"))
                self._stage(run_id, "process_inspecting")
                process_state = self.inspect_process_state(run_id, serial=serial, package_name=package_name)
                self._stage(
                    run_id,
                    "process_inspected",
                    tracer_pid=(process_state.get("process") or {}).get("status", {}).get("tracer_pid"),
                )
            except AnalysisError as exc:
                if exc.code not in {"process_not_running", "process_died"}:
                    raise
                # A short-lived launch is an observation, not a prerequisite
                # for spawn or freeze recovery. The dump orchestrator still
                # enforces the shell-specific routes and attempt limits.
                self._stage(run_id, "process_unavailable", error=project_error(exc))
            self._stage(run_id, "dumping")
            dump_result = self.dump_android_dex(
                run_id,
                serial=serial,
                package_name=package_name,
                method="auto",
                mode="auto",
                inner_bypass=need_inner,
                freeze_timeout_ms=freeze_timeout_ms,
                freeze_poll_ms=freeze_poll_ms,
                frida_timeout_ms=frida_timeout_ms,
                max_region_bytes=max_region_bytes,
                keep_device_files=keep_device_files,
            )
            self._stage(
                run_id,
                "dumped",
                method=dump_result.get("method"),
                candidates=len(dump_result.get("candidates") or []),
            )
            self._stage(run_id, "repairing")
            repair_result = self.repair_android_dex(run_id)
            self._stage(run_id, "repaired", files=len((repair_result.get("repair") or {}).get("files") or []))
            self._stage(run_id, "verifying", jadx=run_jadx)
            verify_result = self.verify_android_dex(run_id, run_jadx=run_jadx, timeout_s=jadx_timeout_s)
            verification = verify_result["verification"]
            self._stage(
                run_id,
                "verified",
                complete=verification.get("complete"),
                classes=verification.get("total_classes"),
                files=verification.get("file_count"),
            )
            result = {
                "run_id": run_id,
                "strategy": strategy,
                "method": dump_result["method"],
                "candidates": dump_result["candidates"],
                "repair": repair_result["repair"],
                "verification": verification,
                "status": "success" if verification.get("complete") and dump_result.get("status") != "partial" else "partial",
                "dump_quality": {"status": dump_result.get("status", "complete"), "limitations": dump_result.get("limitations") or []},
            }
        except Exception as exc:
            failure = exc
        finally:
            if cleanup:
                self._stage(run_id, "cleanup")
                try:
                    cleanup_result = self.cleanup_run(
                        run_id,
                        serial=serial,
                        keep_device_files=keep_device_files,
                        delete_run=False,
                    )
                    self._stage(run_id, "cleaned", status=cleanup_result.get("cleanup_status"))
                except Exception as exc:
                    cleanup_result = {"cleanup_status": "incomplete", "error": str(exc)}
                    self._stage(run_id, "cleanup_failed", error=str(exc))
        if failure is not None:
            if isinstance(failure, AnalysisError):
                failure.partial = {**(failure.partial or {}), "run_id": run_id, "cleanup": cleanup_result}
                self._stage(run_id, "failed", error=failure.projection())
            else:
                self._stage(run_id, "failed", error={"message": str(failure)})
            raise failure
        if result is not None:
            self._stage(run_id, "done", status=result.get("status"), method=result.get("method"))
        assert result is not None
        result["cleanup"] = cleanup_result
        return result

    # ------------------------------------------------------------------ MCP dispatch
    TOOL_METHODS = {
        "inspect_apk": "inspect_apk",
        "extract_apk_assets": "extract_apk_assets",
        "inspect_android_device": "inspect_android_device",
        "prepare_android_environment": "prepare_android_environment",
        "launch_android_target": "launch_android_target",
        "inspect_process_state": "inspect_process_state",
        "recommend_unpack_strategy": "recommend_unpack_strategy",
        "dump_android_dex": "dump_android_dex",
        "repair_android_dex": "repair_android_dex",
        "verify_android_dex": "verify_android_dex",
        "decompile_android_apk": "decompile_android_apk",
        "get_evidence": "get_evidence",
        "export_evidence_bundle": "export_evidence_bundle",
        "inspect_run": "inspect_run",
        "cleanup_run": "cleanup_run",
        "recall_unpack_lessons": "recall_unpack_lessons",
        "remember_unpack_lesson": "remember_unpack_lesson",
    }

    def call_tool(self, name: str, arguments: dict[str, Any], cancel: threading.Event | None = None) -> dict[str, Any]:
        method_name = self.TOOL_METHODS.get(name)
        if not method_name:
            raise fail("invalid_input", f"unknown tool: {name}", details={"tool": name})
        method = getattr(self, method_name)
        kwargs = dict(arguments or {})
        if name in ("dump_android_dex", "verify_android_dex", "decompile_android_apk"):
            kwargs["cancel"] = cancel
        return method(**kwargs)


def _arm_only_on_x86(inspection: dict[str, Any], device: dict[str, Any]) -> bool:
    abis = set(inspection.get("abis") or [])
    device_abi = (device.get("abi") or "")
    return bool(
        device_abi in ("x86", "x86_64")
        and abis
        and not any(abi in abis for abi in ("x86", "x86_64"))
    )


def _freeze_predicate(shell: str | None):
    if shell == "bangcle":
        return lambda region: (
            ("libc_malloc" in (region.path or "").lower() or "[heap]" in (region.path or "").lower())
            and region.size > 4 * 1024 * 1024
        )
    if shell == "ijiami":
        return lambda region: "dalvik-dex" in (region.path or "").lower() and region.size > 1024 * 1024
    return lambda region: region.size > 1024 * 1024 and region.perms.startswith("rw")


def _read_apk_package(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as archive:
            data = archive.read("AndroidManifest.xml")
        return extract_manifest(data).get("package")
    except Exception:
        return None


def _abis_compatible(apk_abis: list[str] | set[str], device_abis: list[str] | set[str]) -> bool:
    apk = {str(item).lower() for item in (apk_abis or []) if item}
    device = {str(item).lower() for item in (device_abis or []) if item}
    if not apk:
        return True
    if apk & device:
        return True
    aliases = {"arm64": "arm64-v8a", "arm": "armeabi-v7a"}
    return bool(apk & {aliases.get(item, item) for item in device})


def _infer_dump_root_cause(failures: list[dict[str, Any]]) -> str:
    texts: list[str] = []
    codes: set[str] = set()
    for item in failures:
        error = item.get("error") or {}
        codes.add(str(error.get("code") or ""))
        texts.append(str(error.get("message") or ""))
        texts.append(str(error.get("captured_output") or ""))
    text = " ".join(texts).lower()
    if "signal 9" in text or "terminated" in text:
        return ("The process exited before producing DEX; the exit cause is unconfirmed. "
                "Inspect device exit/crash logs before attributing it to anti-debug or ABI translation.")
    if "dump_incomplete" in codes:
        return "The failed method did not expose DEX in the memory regions it inspected."
    if "timeout" in codes:
        return "The failed method timed out before producing DEX."
    return "The failed methods did not produce a complete DEX on this shell/device profile."


def _arch_matches(server_arch: str, device_abi: str) -> bool:
    server = server_arch.lower()
    device = device_abi.lower()
    if server == "x86_64":
        return device == "x86_64"
    if server == "x86":
        return device in ("x86", "x86_64")
    if server == "arm64":
        return device == "arm64-v8a"
    if server == "arm":
        return device in ("armeabi", "armeabi-v7a", "arm64-v8a")
    return False
