from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apk_unpack.application.memory import apk_abi_class

NOT_PACKED_ROOT = "APK is not packed; runtime dumping is unnecessary."
NOT_PACKED_TITLE = "APK is not packed: static route"
NOT_PACKED_SCENARIO = "APK has no shell indicators or is already unpacked"
NOT_PACKED_SOLUTION = (
    "APK is not packed: skip runtime dumping and decompile the APK or extract "
    "classes*.dex directly. This is the fast route for unpacked/system APKs."
)
PACKED_STATIC_ROOT = (
    "APK is packed; the top-level classes*.dex is a shell loader, not the real application code."
)
PACKED_STATIC_SCENARIO = "Static classes*.dex extraction on a packed APK"
PACKED_STATIC_SOLUTION = (
    "Do not trust static classes*.dex on a packed APK: it contains only the shell "
    "loader. Use a runtime dump (or a compatible ARM/native-bridge device) and "
    "verify the class count and completeness before reporting success."
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_run_events(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "events.jsonl"
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _inspection(state: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    for container in (state.get("artifacts") or {}, state):
        if not isinstance(container, dict):
            continue
        value = container.get("inspection")
        if isinstance(value, dict) and value:
            return value
    # Fall back to the evidence ledger for older runs that did not persist
    # the inspection into run.json.
    try:
        lines = (run_dir / "evidence.jsonl").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        for key in ("inspection", "analysis", "value", "detail"):
            value = record.get(key)
            if isinstance(value, dict) and ("packing" in value or "package" in value):
                return value
    return {}


def _device(state: dict[str, Any]) -> dict[str, Any]:
    for container in (state.get("artifacts") or {}, state):
        if isinstance(container, dict) and isinstance(container.get("device"), dict):
            return container["device"]
    return {}


def _attempts(state: dict[str, Any]) -> list[dict[str, Any]]:
    for container in (state.get("artifacts") or {}, state):
        if isinstance(container, dict) and isinstance(container.get("attempts"), list):
            return [item for item in container["attempts"] if isinstance(item, dict)]
    return []


def _last_dump(state: dict[str, Any], attempts: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts = state.get("artifacts") or {}
    if isinstance(artifacts, dict) and isinstance(artifacts.get("last_dump"), dict):
        return artifacts["last_dump"]
    for attempt in reversed(attempts):
        if attempt.get("status") == "succeeded" and attempt.get("method"):
            return attempt
    return {}


def _failed_signature(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    signature: list[str] = []
    for item in value:
        if isinstance(item, dict):
            signature.append(f"{item.get('method')}:{item.get('code')}")
        elif item:
            signature.append(str(item))
    return signature


def _looks_like_antiemulator(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "sigkill",
            "sigill",
            "sigsegv",
            "killed",
            "process died",
            "process_died",
            "process terminated",
            "crash loop",
            "self-destruct",
            "self destruct",
            "anti-emulator",
            "anti emulator",
            "native.bridge",
            "native bridge",
            "native_bridge",
            "libexec",
            "houdini",
        )
    )


def _looks_like_frida_block(text: str) -> bool:
    lowered = text.lower()
    return "frida" in lowered and any(
        token in lowered for token in ("refused", "attach", "server", "not running", "unable", "blocked")
    )


def _root_cause(*, shell: str | None, packed: bool | None, success: bool, symptoms: list[str], failed: list[dict[str, Any]]) -> str:
    text = " ".join(symptoms + [str(item.get("message") or "") for item in failed])
    if packed is False and success:
        return "APK is not packed; runtime dumping is unnecessary."
    if _looks_like_antiemulator(text):
        return "The target process terminated before DEX work (anti-emulator / anti-debug / native-bridge detection)."
    if _looks_like_frida_block(text):
        return "Frida attach/server was unavailable or blocked by the shell."
    if "no dex" in text.lower() or "no dex files" in text.lower():
        return "No DEX became visible with the attempted method."
    if not success:
        return "The attempted method did not produce usable DEX on this device profile."
    if shell:
        return f"Observed a successful route for the {shell} shell on this device profile."
    return "Observed a successful route on this device profile."


def build_lesson_payload(
    *,
    job: dict[str, Any],
    result: Any,
    run_id: str,
    run_dir: Path,
) -> tuple[dict[str, Any] | None, str]:
    if result.outcome == "cancelled":
        return None, "job cancelled"
    state = _read_json(run_dir / "run.json")
    inspection = _inspection(state, run_dir)
    packing = inspection.get("packing") or {}
    shell = str(packing.get("primary") or "").strip() or None
    packed = packing.get("packed")
    if packed is None and "packed" in inspection:
        packed = inspection.get("packed")
    if packed is not None:
        packed = bool(packed)
    device = _device(state)
    device_abi = str(device.get("abi") or "").strip() or None
    frameworks = inspection.get("frameworks") or []
    framework = None
    if isinstance(frameworks, list) and frameworks:
        first = frameworks[0]
        if isinstance(first, dict):
            framework = first.get("name")
        elif first:
            framework = str(first)
    package = (inspection.get("package") or {}).get("name")
    apk_abis = inspection.get("abis")
    if not isinstance(apk_abis, list):
        apk_abis = []
    abi_class = apk_abi_class(apk_abis)
    attempts = _attempts(state)
    last_dump = _last_dump(state, attempts)
    winning_method = str(last_dump.get("method") or "").strip() or None

    sources = [path for path in run_dir.glob("dexdump/jadx/**/sources") if path.is_dir()]
    fixed = list(run_dir.glob("dexdump/fixed/*.dex"))
    has_artifacts = bool(sources or fixed)
    if not winning_method:
        if sources:
            winning_method = "static_jadx"
        elif fixed:
            winning_method = "static_dex_extract"
        elif result.outcome in ("success", "partial") and inspection and packed is False:
            winning_method = "static_route"

    failed_attempts = [item for item in attempts if str(item.get("status")) == "failed"]
    failed_methods: list[dict[str, Any]] = []
    for item in failed_attempts:
        error = item.get("error") or {}
        failed_methods.append(
            {
                "method": item.get("method"),
                "code": error.get("code") if isinstance(error, dict) else None,
                "message": error.get("message") if isinstance(error, dict) else str(error),
            }
        )
    error = result.error if isinstance(result.error, dict) else {}
    error_code = str(error.get("code") or "") if error else ""
    error_message = str(error.get("message") or "") if error else ""
    startup_pitfall = False
    if not failed_methods and error:
        # Provider/network/config failures are not APK-shell lessons. But a
        # job that dies before any dump attempt because the shell kills the
        # process is exactly the kind of pitfall worth remembering. The
        # packed-static guard is handled by the static/pitfall branch below.
        error_text = f"{error_code} {error_message}"
        if error_code == "packed_static_only":
            pass
        elif _looks_like_antiemulator(error_text) or _looks_like_frida_block(error_text):
            startup_pitfall = True
            failed_methods.append(
                {
                    "method": error_code or "startup",
                    "code": error_code or None,
                    "message": error_message[:500] or None,
                }
            )
        else:
            return None, f"job-level error without dump attempts: {error_code or 'unknown'}"

    if not winning_method and not failed_methods:
        if not inspection and not attempts:
            return None, "no inspection or dump evidence"
        return None, "no winning method or failed attempts"

    # Only a verified success may increment success_count. A partial job is
    # recorded separately as a pitfall/warning: its artifacts were incomplete
    # or unverified, so it must never be promoted to the learned route order.
    success = result.outcome == "success"
    partial = result.outcome == "partial"
    if success and not has_artifacts:
        # A lesson is only useful if it explains a route that actually produced
        # DEX/source files. Successful runs without artifacts are not actionable.
        return None, "successful job produced no DEX/JADX artifacts"
    symptoms: list[str] = []
    for item in failed_attempts:
        failure = item.get("error") or {}
        if isinstance(failure, dict):
            text = f"{item.get('method')} failed: {failure.get('message') or failure.get('code')}"
            captured = str(failure.get("captured_output") or "").strip()
            if captured:
                text += f" ({captured[:240]})"
        else:
            text = f"{item.get('method')} failed: {failure}"
        if text not in symptoms:
            symptoms.append(text)
    if error and success is False:
        message = str(error.get("message") or error.get("code") or "").strip()
        if message and f"job failed: {message}" not in symptoms:
            symptoms.append(f"job failed: {message}")
    if not success:
        for warning in (result.warnings or [])[:5]:
            text = str(warning)[:400]
            if text and text not in symptoms:
                symptoms.append(text)
        # A job-level failure without any dump attempt is only useful when it
        # identifies a concrete pitfall. Failures that did run dump methods are
        # kept as pitfall evidence (failed method + error code/message); the
        # route-key dedupe prevents the library from filling with repeats.
        # Partial jobs are always actionable warnings, so they are exempt.
        if not failed_methods and not partial:
            pitfall_text = " ".join(symptoms)
            if not (_looks_like_antiemulator(pitfall_text) or _looks_like_frida_block(pitfall_text)):
                return None, "failure has no actionable pitfall (no artifacts or known root cause)"

    failed_labels = " + ".join(str(item.get("method")) for item in failed_attempts) or (
        str(failed_methods[0].get("method")) if failed_methods else ""
    )
    display_shell = shell or "unknown"
    static_route = winning_method in ("static_jadx", "static_dex_extract", "static_route")
    packed_static = static_route and (packed is True or error_code == "packed_static_only")
    # Only a verified success may claim the "not packed" fast route.
    canonical_not_packed = static_route and packed is False and not packed_static and success
    lesson_shell = shell
    lesson_framework = framework
    lesson_device_abi = device_abi
    lesson_abi_class = abi_class
    lesson_apk_abis = apk_abis
    root_cause_override: str | None = None
    if packed_static:
        title = f"{display_shell}: packed APK, static route only returned shell classes"
        scenario = PACKED_STATIC_SCENARIO
        solution = PACKED_STATIC_SOLUTION
        winning_method = "static_shell_only"
        root_cause_override = PACKED_STATIC_ROOT
    elif canonical_not_packed:
        title = NOT_PACKED_TITLE
        scenario = NOT_PACKED_SCENARIO
        solution = NOT_PACKED_SOLUTION
        winning_method = "static_route"
        root_cause_override = NOT_PACKED_ROOT
        # One generic lesson for every unpacked/plain profile; keep the concrete
        # run in evidence/examples instead of duplicating it per shell/ABI/framework.
        lesson_shell = None
        lesson_framework = None
        lesson_device_abi = None
        lesson_abi_class = "unknown"
        lesson_apk_abis = []
    elif partial:
        # A partial job is not a verified route. Record it as a pitfall/warning
        # with no winning method so it can never be promoted into the learned
        # primary/fallback order, and so it does not merge into a later
        # verified-success lesson for the same method.
        partial_method = winning_method or (
            str(failed_methods[0].get("method")) if failed_methods else None
        )
        method_label = partial_method or failed_labels or "unknown method"
        title = f"{display_shell}: partial result via {method_label} (unverified warning)"
        scenario = "Job ended partial: the produced artifacts or route were not verified"
        root_cause_override = (
            f"Job finished partial ({error_code or 'unverified'}): "
            + (error_message[:400] or "the route did not produce verified target DEX.")
        )
        solution = (
            f"{method_label} did not produce a verified target DEX (job partial). "
            "Treat this route as a warning, not a success: review the failed attempts "
            "and evidence, then retry with another method or device. Only promote a "
            "route after a verified success."
        )
        unverified = {
            "method": partial_method or "unknown",
            "code": error_code or "partial_unverified",
            "message": error_message[:500] or "job ended partial; artifacts were not verified",
        }
        if not any(
            item.get("method") == unverified["method"] and item.get("code") == unverified["code"]
            for item in failed_methods
        ):
            failed_methods.append(unverified)
        winning_method = None
    elif static_route:
        # Unknown packing state: static output may be a shell loader. Do not
        # claim either "not packed" or success without evidence.
        return None, "static route with unknown packing state"
    elif success and winning_method:
        title = f"{display_shell}: {failed_labels + ' -> ' if failed_labels else ''}{winning_method}"
        scenario = "DEX dump automatic route"
        solution = (
            f"{winning_method} succeeded"
            + (f" after {failed_labels}" if failed_labels else "")
            + ". Prefer this fallback order for the same shell/device/ABI profile; verify on another sample."
        )
    elif startup_pitfall:
        title = f"{display_shell}: startup pitfall ({error_code or 'process_died'})"
        scenario = "target process terminated before any DEX dump attempt"
        solution = (
            "The shell killed the process before a DEX window existed. This is an "
            "anti-emulator / anti-debug / native-bridge pitfall: keep the process alive "
            "(shield or compatible native bridge) or retry on ARM64 hardware; verify the "
            "process survives startup before attempting a dump."
        )
    elif failed_methods:
        title = f"{display_shell}: no winning dump method ({failed_labels or 'job failed'})"
        scenario = "DEX dump failed on this device profile"
        solution = (
            "No method produced a usable DEX. Review the failed attempts and device logs; "
            "try another device/native bridge or inspect the evidence bundle before retrying."
        )
    else:  # pragma: no cover - guarded above
        return None, "no lesson content"

    evidence_links = [f"run:{run_id}", f"job:{job.get('id')}"]
    for item in attempts:
        evidence_id = item.get("evidence_id")
        if evidence_id:
            evidence_links.append(f"ev:{evidence_id}")
            break
    example_evidence = next(
        (str(item.get("evidence_id")) for item in attempts if item.get("evidence_id")),
        None,
    )
    tags = ["auto", "job"]
    if lesson_shell:
        tags.append(lesson_shell)
    tags.extend(
        [
            winning_method or "no-method",
            lesson_device_abi or "unknown",
            lesson_abi_class,
            str(job.get("engine") or "unknown"),
            str(result.outcome or "unknown"),
        ]
    )
    if lesson_framework:
        tags.append(str(lesson_framework))
    if static_route:
        tags.append("static")
    else:
        tags.append("dump")
    if canonical_not_packed:
        tags.append("not-packed")
    if packed_static:
        tags.extend(["packed", "pitfall"])
    if partial:
        tags.extend(["pitfall", "warning", "partial"])

    payload = {
        "title": title,
        "scenario": scenario,
        "shell": lesson_shell,
        "device_abi": lesson_device_abi,
        "apk_abis": lesson_apk_abis,
        "apk_abi_class": lesson_abi_class,
        "framework": lesson_framework,
        "package_scope": "global",
        "symptoms": symptoms,
        "root_cause": root_cause_override
        or _root_cause(
            shell=shell,
            packed=packed if isinstance(packed, bool) else None,
            success=success,
            symptoms=symptoms,
            failed=failed_methods,
        ),
        "solution": solution,
        "winning_method": winning_method,
        "failed_methods": failed_methods,
        "tags": tags,
        "evidence_links": evidence_links[:50],
        "examples": [
            {
                "run_id": run_id,
                "package": package,
                "evidence_id": example_evidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
        "confidence": "observed",
        "limitations": [
            "Automatically generated from one backend job; treat it as observed evidence, not a universal rule.",
        ]
        + (
            [
                "Recorded from a partial job: the route did not produce verified target DEX "
                "and must not be ranked as a successful primary/fallback.",
            ]
            if partial
            else []
        ),
    }
    return payload, "ok"


def record_job_lesson(
    lessons: Any,
    *,
    job: dict[str, Any],
    result: Any,
    run_id: str,
    run_dir: Path,
    emit: Any,
) -> dict[str, Any] | None:
    """Build and persist one automatic lesson for a finished job.

    This is intentionally rule-based so it works even when the LLM provider is
    unavailable. It never fails the job: recording errors are emitted instead.
    """
    try:
        payload, reason = build_lesson_payload(job=job, result=result, run_id=run_id, run_dir=run_dir)
        if payload is None:
            emit("lesson_skipped", f"lesson not recorded: {reason}", {"run_id": run_id, "reason": reason})
            return None
        # Only verified, non-pitfall success increments success_count. Partial
        # jobs are warning records (winning_method is None), so they must stay
        # at success_count=0 even when they carried artifacts.
        success = result.outcome == "success" and payload.get("winning_method") != "static_shell_only"

        # The native agent already records dump-fallback and emulator-bypass
        # lessons. If this run has an equivalent auto lesson, reuse it instead
        # of double-counting occurrences.
        for event in _read_run_events(run_dir):
            name = event.get("event") or event.get("kind")
            if name not in ("memory_recorded", "agent.memory_recorded"):
                continue
            detail = event.get("detail") or event.get("data") or {}
            if not isinstance(detail, dict):
                continue
            lesson_id = detail.get("lesson_id")
            existing = lessons.get(lesson_id) if lesson_id else None
            if not existing:
                continue
            if (
                existing.get("winning_method") == payload.get("winning_method")
                and _failed_signature(existing.get("failed_methods")) == _failed_signature(payload.get("failed_methods"))
            ):
                emit(
                    "lesson_recorded",
                    f"lesson already saved: {existing.get('title')}",
                    {
                        "lesson_id": existing.get("lesson_id"),
                        "title": existing.get("title"),
                        "status": "existing",
                        "deduped": True,
                        "source": "agent",
                        "occurrences": existing.get("occurrences"),
                        "shell": existing.get("shell"),
                        "winning_method": existing.get("winning_method"),
                        "run_id": run_id,
                    },
                )
                return existing

        lesson, status = lessons.record(payload, kind="auto", success=success)
        emit(
            "lesson_recorded",
            f"lesson {status}: {lesson.get('title')}",
            {
                "lesson_id": lesson.get("lesson_id"),
                "title": lesson.get("title"),
                "status": status,
                "deduped": status != "added",
                "source": "backend",
                "outcome": str(result.outcome or ""),
                "occurrences": lesson.get("occurrences"),
                "success_count": lesson.get("success_count"),
                "shell": lesson.get("shell"),
                "winning_method": lesson.get("winning_method"),
                "run_id": run_id,
            },
        )
        return lesson
    except Exception as exc:  # pragma: no cover - defensive
        emit(
            "lesson_record_failed",
            "automatic lesson recording failed",
            {"run_id": run_id, "error": str(exc)[:1000]},
        )
        return None
