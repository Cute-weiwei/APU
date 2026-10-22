from __future__ import annotations

import re
import json
import shutil
import tempfile
import threading
import time
from uuid import uuid4
from pathlib import Path
from typing import Iterable, Any

from ..config import default_jadx_timeout_s, default_jadx_threads, default_jadx_heap_mb
from ..domain.errors import AnalysisError, fail
from .host import CommandResult, HostRunner


class JadxProvider:
    def __init__(self, host: HostRunner, java: str | None, jar: str | None):
        self.host = host
        self.java = java
        self.jar = jar

    def available(self) -> bool:
        return bool(self.java and self.jar and Path(self.java).is_file() and Path(self.jar).is_file())

    @staticmethod
    def _java_options(heap_mb: int, low_memory: bool) -> list[str]:
        options = [f"-Xmx{heap_mb}M", "-XX:+ExitOnOutOfMemoryError"]
        if low_memory:
            # Large class graphs mostly survive collection. Reserve more of
            # the bounded heap for them instead of an oversized young generation.
            options += ["-Xms256m", "-XX:+UseSerialGC", "-XX:NewRatio=8",
                        "-XX:MinHeapFreeRatio=10", "-XX:MaxHeapFreeRatio=20"]
        return options

    def _run(self, argv: list[str], timeout_s: float, cancel: threading.Event | None) -> CommandResult:
        if cancel is None:
            return self.host.run(argv, timeout=timeout_s)
        stream = self.host.stream(argv, timeout=timeout_s, cancel=cancel)
        if stream.cancelled:
            raise fail("cancelled", "JADX cancellation requested")
        return CommandResult(argv, stream.returncode if stream.returncode is not None else -1,
            stdout=stream.text("stdout"), stderr=stream.text("stderr"),
            timed_out=stream.timed_out, duration_s=stream.duration_s)

    def _recover(self, inputs: list[str], out_dir: Path, failed: list[Path],
                 remaining_s: float, cancel: threading.Event | None, *, all_classes: bool = False,
                 heap_mb: int = 4096, threads: int = 1, low_memory: bool = False) -> dict[str, Any]:
        """Retain raw instructions for failed classes without replacing normal Java."""
        source_root = out_dir / "sources" if (out_dir / "sources").is_dir() else out_dir
        wanted = {p.relative_to(source_root).with_suffix("").as_posix() for p in failed}
        recovery = out_dir / "recovery" / ("fallback-" + uuid4().hex[:8])
        recovery.mkdir(parents=True)
        report: dict[str, Any] = {"mode": "fallback", "format": "raw_instructions",
            "scope": "all_classes_after_process_failure" if all_classes else "warning_classes",
            "output_dir": str(recovery), "requested_file_count": len(wanted),
            "limitations": ["Raw instructions are an alternate reading aid, not reconstructed or compilable Java. Primary source warnings remain unresolved."]}
        # Use one bounded process for the APK, then retain only failing classes
        # and their inner classes. Reloading a large APK per class is too costly.
        with tempfile.TemporaryDirectory(prefix="_jadx-fallback-", dir=out_dir) as scratch:
            argv = [str(self.java), *self._java_options(heap_mb, low_memory), "-cp", str(self.jar), "jadx.cli.JadxCLI",
                    "--no-debug-info", "--threads-count", str(threads),
                    "--no-res", "--decompilation-mode", "fallback",
                    "-d", scratch, *inputs]
            result = self._run(argv, remaining_s, cancel)
            fallback_root = Path(scratch) / "sources"
            covered: set[str] = set()
            files: list[str] = []
            warning_count = 0
            for path in fallback_root.rglob("*.java"):
                relative = path.relative_to(fallback_root)
                stem = relative.with_suffix("").as_posix()
                # Normal mode can inline inner classes into the outer file.
                keys = [stem, *[stem[:i] for i, char in enumerate(stem) if char == "$"]]
                matched = wanted.intersection(keys)
                if not matched and not all_classes:
                    continue
                target = recovery / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                text = path.read_text(encoding="utf-8", errors="replace")
                warning_count += int(any(marker in text for marker in ("JADX ERROR:", "Method not decompiled:", "Code decompiled incorrectly")))
                covered.update(matched)
                files.append(relative.as_posix())
            report.update({"status": "complete" if result.ok and files and covered == wanted and not warning_count else "partial",
                "java_file_count": len(files), "covered_file_count": len(covered),
                "missing_files": sorted(name + ".java" for name in wanted - covered),
                "incomplete_file_count": warning_count, "timed_out": result.timed_out,
                "duration_s": round(result.duration_s, 3), "returncode": result.returncode,
                "command": argv, "files": sorted(files),
                "stdout_tail": result.stdout[-2000:], "stderr_tail": result.stderr[-2000:]})
        (recovery / "FALLBACK_REPORT.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        (recovery / "README.txt").write_text(
            "Raw bytecode instructions for classes with JADX reconstruction errors.\n"
            "These files preserve a lower-level view for analysis; they are not original or compilable Java.\n"
            "The normal Java output and its warnings are retained separately. See FALLBACK_REPORT.json.\n", encoding="utf-8")
        return report

    def decompile(
        self,
        inputs: Iterable[str | Path],
        output_dir: str | Path,
        *,
        timeout_s: int | None = None,
        package: str | None = None,
        target_packages: Iterable[str] | None = None,
        extra_args: list[str] | None = None,
        cancel: threading.Event | None = None,
    ) -> dict[str, Any]:
        timeout_s = timeout_s or default_jadx_timeout_s()
        threads = default_jadx_threads()
        if timeout_s < 0:
            raise fail("invalid_input", "JADX timeout must be positive (or zero for the default)")
        if not self.available():
            raise fail(
                "tool_missing",
                "JADX CLI is not configured",
                remediation="Set APU_JAVA/APU_JADX_JAR or place jadx-gui-*-all.jar under jadx/lib.",
                details={"java": self.java, "jadx_jar": self.jar},
            )
        source_list = [str(Path(item)) for item in inputs]
        if not source_list:
            raise fail("invalid_input", "no DEX/APK inputs supplied to JADX")
        input_bytes = sum(Path(item).stat().st_size for item in source_list if Path(item).is_file())
        heap_mb = default_jadx_heap_mb()
        low_memory = input_bytes > 64 * 1024 * 1024
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            str(self.java),
            *self._java_options(heap_mb, low_memory),
            "-cp",
            str(self.jar),
            "jadx.cli.JadxCLI",
            "--no-debug-info",
            "--threads-count", str(threads),
            "-d",
            str(out_dir),
        ]
        if low_memory:
            # Retain explicit classes and calls instead of expanding their ASTs
            # through inlining. Every input DEX remains in the same invocation.
            argv.extend(["--no-inline-anonymous", "--no-inline-methods", "--no-inline-kotlin-lambda"])
        argv.extend(extra_args or [])
        argv.extend(source_list)
        started = time.monotonic()
        result = self._run(argv, timeout_s, cancel)
        source_root = out_dir / "sources" if (out_dir / "sources").is_dir() else out_dir
        java_files = [p for p in source_root.rglob("*.java")
                      if source_root != out_dir or p.relative_to(out_dir).parts[0] != "recovery"]
        package_files: set[Path] = set()
        namespaces = list(dict.fromkeys(str(value).strip() for value in
                          [package, *(target_packages or [])] if value))
        namespaces = [value for value in namespaces if re.fullmatch(
            r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", value)]
        for namespace in namespaces:
            package_dir = source_root / Path(namespace.replace(".", "/"))
            if package_dir.is_dir():
                package_files.update(package_dir.rglob("*.java"))
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        memory_exhausted = "OutOfMemoryError" in combined or "GC overhead limit exceeded" in combined
        process_failed = memory_exhausted or "ERROR - Process error:" in combined or result.returncode not in (0, 3)
        error_lines = [
            line
            for line in combined.splitlines()
            if re.search(r"^\s*ERROR\b", line)
        ]
        count_match = re.search(r"finished with errors, count:\s*(\d+)", combined)
        error_count = int(count_match.group(1)) if count_match else len(error_lines)
        markers = ("Method not decompiled:", "JADX ERROR:", "Code decompiled incorrectly")
        warning_files = {marker: 0 for marker in markers}
        incomplete_file_count = 0
        failed_files: list[Path] = []
        for path in java_files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                incomplete_file_count += 1
                continue
            found = [marker for marker in markers if marker in text]
            if found:
                incomplete_file_count += 1
                failed_files.append(path)
                for marker in found:
                    warning_files[marker] += 1
        if not result.ok and not java_files:
            raise fail(
                "timeout" if result.timed_out else "resource_constraint" if memory_exhausted else "execution_failure",
                f"JADX timed out after {timeout_s}s without Java output" if result.timed_out else "JADX ran out of Java heap memory" if memory_exhausted else "JADX produced no Java output",
                captured_output=result.stderr or result.stdout,
                details={"returncode": result.returncode, "inputs": source_list,
                         "output_dir": str(out_dir), "timed_out": result.timed_out,
                         "memory_exhausted": memory_exhausted,
                         "timeout_s": timeout_s, "duration_s": round(result.duration_s, 3)},
            )
        fallback = None
        if failed_files or process_failed:
            remaining = timeout_s - (time.monotonic() - started)
            if result.timed_out or remaining <= 0 or extra_args:
                fallback = {"status": "skipped", "reason": "timeout_budget_exhausted" if result.timed_out or remaining <= 0 else "custom_options"}
            else:
                try:
                    fallback = self._recover(source_list, out_dir, failed_files, remaining, cancel,
                                             all_classes=process_failed, heap_mb=heap_mb, threads=threads,
                                             low_memory=low_memory)
                except AnalysisError as exc:
                    if exc.code == "cancelled":
                        raise
                    fallback = {"status": "partial", "error": exc.projection()}
                except OSError as exc:
                    fallback = {"status": "partial", "error": str(exc)}
        return {
            "output_dir": str(out_dir),
            "inputs": source_list,
            "java_file_count": len(java_files),
            "package_java_file_count": len(package_files),
            "target_packages": namespaces,
            "error_count": error_count,
            "memory_exhausted": memory_exhausted,
            "process_failed": process_failed,
            "primary_coverage": "unknown_after_process_failure" if process_failed else "reconstruction_attempted",
            "incomplete_file_count": incomplete_file_count,
            "warning_files": warning_files,
            "fallback": fallback,
            "errors": error_lines[:50],
            "returncode": result.returncode,
            "duration_s": round(result.duration_s, 3),
            "total_duration_s": round(time.monotonic() - started, 3),
            "timeout_s": timeout_s,
            "threads": threads,
            "heap_mb": heap_mb,
            "profile": "no_inline" if low_memory else "default",
            "gc_profile": "serial" if low_memory else "default",
            "timed_out": bool(result.timed_out or (fallback or {}).get("timed_out")),
            "completion_reason": "timeout" if result.timed_out or (fallback or {}).get("timed_out") else (
                "memory_limit" if memory_exhausted else "process_failure" if process_failed else
                "complete" if result.ok and java_files and not error_count and not incomplete_file_count and not process_failed
                else "decompilation_errors"
            ),
            "command": argv,
            "sample_files": [str(item) for item in java_files[:10]],
            "stdout_tail": (result.stdout or "")[-4000:],
            "stderr_tail": (result.stderr or "")[-4000:],
            "status": "complete" if result.ok and java_files and not error_count and not incomplete_file_count and not process_failed else "partial",
        }
